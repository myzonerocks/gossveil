//! The operations over a session archive: start from a published bundle,
//! seal, open a whisper message, open the first message of a session. Stores
//! stay with the caller; each call takes the records it needs and leaves the
//! updated archive behind.
const std = @import("std");
const curve = @import("../keys/curve.zig");
const derive = @import("../keys/derive.zig");
const cipher = @import("../keys/cipher.zig");
const identity = @import("../keys/identity.zig");
const agree = @import("../handshake/agree.zig");
const pq_record = @import("pq/record.zig");
const state_mod = @import("state.zig");
const State = state_mod.State;
const chain_mod = @import("chain.zig");
const Archive = @import("archive.zig").Archive;
const Published = @import("../bundle/published.zig").Published;
const records = @import("../bundle/records.zig");
const Whisper = @import("../post/whisper.zig").Whisper;
const Binding = @import("../post/whisper.zig").Binding;
const Opener = @import("../post/opener.zig").Opener;
const Fault = @import("../fault.zig").Fault;
const mem = std.mem;
const Allocator = mem.Allocator;

pub const Kind = enum(u8) {
    whisper = 2,
    first = 3,
    circle = 7,
    plain = 8,
};

pub const Sealed = struct {
    kind: Kind,
    bytes: []u8,
};

fn pqLimits(us: identity.IdentityPair, them: identity.Identity) pq_record.Limits {
    const with_self = us.identity.eql(them);
    return .{
        .max_jump = if (with_self) std.math.maxInt(u32) else state_mod.max_forward_jump,
        .max_skipped = @intCast(state_mod.max_skipped_keys),
    };
}

/// Opens a session to the bundle's owner. The caller has already decided the
/// identity is trusted and saves it afterwards.
pub fn start(allocator: Allocator, archive: *Archive, us: identity.IdentityPair, our_registration_id: u32, published: Published, now_secs: u64) !void {
    try published.check();
    const base = try curve.Pair.generate();
    const params = agree.Initiator{
        .us = us,
        .our_base = base,
        .them = published.identity,
        .their_signed = published.signed,
        .their_one_time = published.one_time,
        .their_ratchet = published.signed,
        .their_pq = published.pq_key,
    };
    const opened = try agree.initiatorSecret(params);
    const pq_state = try pq_record.start(allocator, opened.keys.pq_auth, .initiator, pqLimits(us, published.identity));
    defer allocator.free(pq_state);
    var s = try agree.initiatorState(allocator, params, opened.keys, pq_state);
    errdefer s.deinit();
    s.setPending(published.one_time_id, published.signed_id, base.public, now_secs);
    try s.setPendingCapsule(published.pq_id, &opened.capsule.?.bytes);
    s.local_registration_id = our_registration_id;
    s.remote_registration_id = published.registration_id;
    try archive.promote(s);
}

pub fn seal(allocator: Allocator, archive: *Archive, plain: []const u8, now_secs: u64, binding: ?Binding) !Sealed {
    const s = archive.live() orelse return Fault.NoSession;
    if (!s.canSendAt(now_secs)) return Fault.NoSession;
    const chain = try s.sendingChain();
    const slot = chain.slot();
    const pq = try pq_record.send(allocator, s.pq_state);
    defer allocator.free(pq.packet);
    s.setPqState(pq.state);
    const keys = slot.open(pq.key);
    const pair = try s.sendingPair();
    const body = try cipher.cbcSeal(allocator, keys.cipher, keys.iv, plain);
    defer allocator.free(body);
    const version: u8 = @intCast(s.version);
    var inner = try Whisper.seal(allocator, .{
        .version = version,
        .mac_key = keys.mac,
        .binding = binding,
        .ratchet = pair.public,
        .index = chain.index,
        .previous_index = s.previous_index,
        .body = body,
        .sender = s.local,
        .recipient = s.remote,
        .pq_packet = pq.packet,
    });
    defer inner.deinit();
    s.setSendingChain(chain.advance());

    if (s.pending) |pending| {
        const capsule = s.pending_capsule orelse return Fault.BadSession;
        var wrapped = try Opener.wrap(allocator, .{
            .version = version,
            .registration_id = s.local_registration_id,
            .one_time_id = pending.one_time_id,
            .signed_id = pending.signed_id,
            .pq_id = capsule.pq_id,
            .capsule = capsule.capsule,
            .base = pending.base,
            .identity = s.local,
            .inner = inner.bytes,
        });
        const bytes = wrapped.bytes;
        wrapped.bytes = &.{};
        return .{ .kind = .first, .bytes = bytes };
    }
    const bytes = inner.bytes;
    inner.bytes = &.{};
    return .{ .kind = .whisper, .bytes = bytes };
}

pub const Consumed = struct {
    one_time_id: ?u32,
    signed_id: u32,
    pq_id: u32,
    base: curve.Public,
};

pub const Offered = struct {
    signed: ?records.SignedRecord,
    one_time: ?records.OneTimeRecord,
    pq: ?records.PqRecord,
};

pub const Opened = struct {
    plain: []u8,
    consumed: ?Consumed,
};

/// Opens the first message of a session, starting the session if its base
/// key is new. The caller checks trust on the message's identity first.
pub fn openFirst(allocator: Allocator, archive: *Archive, us: identity.IdentityPair, our_registration_id: u32, first: Opener, offered: Offered, binding: ?Binding) !Opened {
    var consumed: ?Consumed = null;
    if (!try archive.revive(first.version, &first.base.serialize())) {
        const signed = offered.signed orelse return Fault.UnknownKeyId;
        if (signed.id != first.signed_id) return Fault.UnknownKeyId;
        var one_time: ?curve.Pair = null;
        if (first.one_time_id) |id| {
            const r = offered.one_time orelse return Fault.UnknownKeyId;
            if (r.id != id) return Fault.UnknownKeyId;
            one_time = r.pair;
        }
        const pq_id = first.pq_id orelse return Fault.BadMessage;
        const pq = offered.pq orelse return Fault.UnknownKeyId;
        if (pq.id != pq_id) return Fault.UnknownKeyId;
        const them = identity.Identity{ .key = first.identity };
        const params = agree.Responder{
            .us = us,
            .our_signed = signed.pair,
            .our_one_time = one_time,
            .our_ratchet = signed.pair,
            .our_pq = pq.pair.secret,
            .them = them,
            .their_base = first.base,
            .their_capsule = first.capsule orelse return Fault.BadMessage,
        };
        const answered = try agree.responderSecret(params);
        const pq_state = try pq_record.start(allocator, answered.keys.pq_auth, .responder, pqLimits(us, them));
        defer allocator.free(pq_state);
        var s = try agree.responderState(allocator, params, answered.keys, pq_state);
        errdefer s.deinit();
        s.local_registration_id = our_registration_id;
        s.remote_registration_id = first.registration_id;
        try archive.promote(s);
        consumed = .{ .one_time_id = first.one_time_id, .signed_id = first.signed_id, .pq_id = pq_id, .base = first.base };
    }
    var inner = try Whisper.parse(allocator, first.inner);
    defer inner.deinit();
    const plain = try openWithArchive(allocator, archive, inner, binding);
    return .{ .plain = plain, .consumed = consumed };
}

pub fn openWhisper(allocator: Allocator, archive: *Archive, message: Whisper, binding: ?Binding) ![]u8 {
    return openWithArchive(allocator, archive, message, binding);
}

fn openWithArchive(allocator: Allocator, archive: *Archive, message: Whisper, binding: ?Binding) ![]u8 {
    if (archive.live()) |current| {
        var candidate = try current.clone();
        if (openWithState(allocator, &candidate, message, binding)) |plain| {
            errdefer allocator.free(plain);
            current.deinit();
            current.* = candidate;
            return plain;
        } else |e| {
            candidate.deinit();
            if (e == Fault.Replay) return e;
        }
    }
    var i: usize = 0;
    while (i < archive.shelvedCount()) : (i += 1) {
        var candidate = archive.shelved(i) catch continue;
        if (openWithState(allocator, &candidate, message, binding)) |plain| {
            errdefer allocator.free(plain);
            try archive.promoteShelved(i, candidate);
            return plain;
        } else |e| {
            candidate.deinit();
            if (e == Fault.Replay) return e;
        }
    }
    return Fault.BadMessage;
}

fn openWithState(allocator: Allocator, s: *State, message: Whisper, binding: ?Binding) ![]u8 {
    if (!s.canSend()) return Fault.BadMessage;
    if (message.version != s.version) return Fault.UnknownVersion;
    if (!message.checkBinding(binding)) return Fault.BadMessage;
    const their_ratchet = message.ratchet;
    const chain = try laneChain(s, their_ratchet);
    const slot = try slotFor(s, their_ratchet, chain, message.index);
    const pq = pq_record.receive(allocator, s.pq_state, message.pq_packet) catch return Fault.BadMessage;
    s.setPqState(pq.state);
    const keys = slot.open(pq.key);
    if (!message.checkMac(s.remote, s.local, keys.mac)) return Fault.BadMessage;
    const plain = try cipher.cbcOpen(allocator, keys.cipher, keys.iv, message.body);
    s.clearPending();
    return plain;
}

/// The receiving chain for their ratchet key, turning the ratchet when it is new.
fn laneChain(s: *State, their_ratchet: curve.Public) !chain_mod.Chain {
    if (s.receivingLane(their_ratchet)) |lane| return lane.chain;
    const ours = try s.sendingPair();
    const receiving = derive.turn(s.root, try ours.secret.agree(their_ratchet));
    const fresh = try curve.Pair.generate();
    const sending = derive.turn(receiving.root, try fresh.secret.agree(their_ratchet));
    s.root = sending.root;
    try s.addReceiving(their_ratchet, .{ .key = receiving.chain, .index = 0 });
    const index = (try s.sendingChain()).index;
    s.previous_index = if (index > 0) index - 1 else 0;
    s.setSending(fresh, .{ .key = sending.chain, .index = 0 });
    return .{ .key = receiving.chain, .index = 0 };
}

fn slotFor(s: *State, their_ratchet: curve.Public, chain: chain_mod.Chain, index: u32) !chain_mod.Slot {
    if (chain.index > index) return s.takeSkipped(their_ratchet, index) orelse Fault.Replay;
    if (index - chain.index > state_mod.max_forward_jump and !s.withSelf()) return Fault.BadMessage;
    var c = chain;
    while (c.index < index) : (c = c.advance()) try s.keepSkipped(their_ratchet, c.slot());
    s.receivingLane(their_ratchet).?.chain = c.advance();
    return c.slot();
}

test "two parties exchange messages both ways, out of order, across a reload" {
    const a = std.testing.allocator;
    const alice_id = try identity.IdentityPair.generate();
    const bob_id = try identity.IdentityPair.generate();
    const signed = try records.SignedRecord.generate(1, 1000, bob_id.secret);
    const post = try records.PqRecord.generate(1, 1000, .round_three, bob_id.secret);
    const one_time = try records.OneTimeRecord.generate(7);
    const published = try Published.init(4242, 1, 7, one_time.pair.public, 1, signed.pair.public, &signed.signature, bob_id.identity, 1, post.pair.public, &post.signature);

    var alice = Archive.init(a);
    defer alice.deinit();
    try start(a, &alice, alice_id, 1234, published, 1_700_000_000);
    var bob = Archive.init(a);
    defer bob.deinit();

    const m1 = try seal(a, &alice, "hello bob", 1_700_000_000, null);
    defer a.free(m1.bytes);
    try std.testing.expectEqual(Kind.first, m1.kind);
    var first = try Opener.parse(a, m1.bytes);
    defer first.deinit();
    const r1 = try openFirst(a, &bob, bob_id, 4242, first, .{ .signed = signed, .one_time = one_time, .pq = post }, null);
    defer a.free(r1.plain);
    try std.testing.expectEqualStrings("hello bob", r1.plain);
    try std.testing.expectEqual(@as(?u32, 7), r1.consumed.?.one_time_id);

    var i: usize = 0;
    while (i < 8) : (i += 1) {
        const reply = try seal(a, &bob, "reply", 1_700_000_000, null);
        defer a.free(reply.bytes);
        try std.testing.expectEqual(Kind.whisper, reply.kind);
        var w = try Whisper.parse(a, reply.bytes);
        defer w.deinit();
        const p = try openWhisper(a, &alice, w, null);
        defer a.free(p);
        try std.testing.expectEqualStrings("reply", p);
        const again = try seal(a, &alice, "again", 1_700_000_000, null);
        defer a.free(again.bytes);
        var w2 = try Whisper.parse(a, again.bytes);
        defer w2.deinit();
        const p2 = try openWhisper(a, &bob, w2, null);
        defer a.free(p2);
        try std.testing.expectEqualStrings("again", p2);
    }

    const s1 = try seal(a, &bob, "skip one", 1_700_000_000, null);
    defer a.free(s1.bytes);
    const s2 = try seal(a, &bob, "skip two", 1_700_000_000, null);
    defer a.free(s2.bytes);
    var w2 = try Whisper.parse(a, s2.bytes);
    defer w2.deinit();
    const p2 = try openWhisper(a, &alice, w2, null);
    defer a.free(p2);
    try std.testing.expectEqualStrings("skip two", p2);
    const bytes = try alice.serialize(a);
    defer a.free(bytes);
    var reloaded = try Archive.parse(a, bytes);
    defer reloaded.deinit();
    var w1 = try Whisper.parse(a, s1.bytes);
    defer w1.deinit();
    const p1 = try openWhisper(a, &reloaded, w1, null);
    defer a.free(p1);
    try std.testing.expectEqualStrings("skip one", p1);
    try std.testing.expectError(Fault.Replay, openWhisper(a, &reloaded, w1, null));
}

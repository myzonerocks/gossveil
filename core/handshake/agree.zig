//! The handshake: the initiator derives the shared secret from four (or five)
//! curve agreements and one post-quantum capsule; the responder derives the
//! same from its side. Both open into a root key, a chain key and the
//! post-quantum ratchet's authentication key, and each side sets up its first
//! lanes. The post-quantum ratchet state arrives from the caller as bytes.
const std = @import("std");
const curve = @import("../keys/curve.zig");
const pq = @import("../keys/pq.zig");
const derive = @import("../keys/derive.zig");
const identity = @import("../keys/identity.zig");
const State = @import("../ratchet/state.zig").State;
const state_mod = @import("../ratchet/state.zig");
const Allocator = std.mem.Allocator;

const discontinuity = [_]u8{0xFF} ** 32;

pub const Initiator = struct {
    us: identity.IdentityPair,
    our_base: curve.Pair,
    them: identity.Identity,
    their_signed: curve.Public,
    their_one_time: ?curve.Public,
    their_ratchet: curve.Public,
    their_pq: pq.Public,
};

pub const Responder = struct {
    us: identity.IdentityPair,
    our_signed: curve.Pair,
    our_one_time: ?curve.Pair,
    our_ratchet: curve.Pair,
    our_pq: pq.Secret,
    them: identity.Identity,
    their_base: curve.Public,
    their_capsule: []const u8,
};

pub const Opened = struct {
    keys: derive.Opening,
    capsule: ?pq.Capsule,
};

/// The initiator's shared secret and the capsule it must send along.
pub fn initiatorSecret(p: Initiator) !Opened {
    var material: [32 * 6]u8 = undefined;
    var n: usize = 0;
    material[n..][0..32].* = discontinuity;
    n += 32;
    material[n..][0..32].* = try p.us.secret.agree(p.their_signed);
    n += 32;
    material[n..][0..32].* = try p.our_base.secret.agree(p.them.key);
    n += 32;
    material[n..][0..32].* = try p.our_base.secret.agree(p.their_signed);
    n += 32;
    if (p.their_one_time) |one_time| {
        material[n..][0..32].* = try p.our_base.secret.agree(one_time);
        n += 32;
    }
    const capsule = try p.their_pq.encapsulate();
    material[n..][0..32].* = capsule.shared;
    n += 32;
    defer std.crypto.secureZero(u8, &material);
    return .{ .keys = derive.opening(material[0..n]), .capsule = capsule };
}

pub fn responderSecret(p: Responder) !Opened {
    var material: [32 * 6]u8 = undefined;
    var n: usize = 0;
    material[n..][0..32].* = discontinuity;
    n += 32;
    material[n..][0..32].* = try p.our_signed.secret.agree(p.them.key);
    n += 32;
    material[n..][0..32].* = try p.us.secret.agree(p.their_base);
    n += 32;
    material[n..][0..32].* = try p.our_signed.secret.agree(p.their_base);
    n += 32;
    if (p.our_one_time) |one_time| {
        material[n..][0..32].* = try one_time.secret.agree(p.their_base);
        n += 32;
    }
    material[n..][0..32].* = try p.our_pq.open(p.their_capsule);
    n += 32;
    defer std.crypto.secureZero(u8, &material);
    return .{ .keys = derive.opening(material[0..n]), .capsule = null };
}

/// The initiator's first state: a receiving lane on their ratchet key and a
/// sending lane on a fresh one, one turn ahead.
pub fn initiatorState(allocator: Allocator, p: Initiator, keys: derive.Opening, pq_state: []const u8) !State {
    const sending = try curve.Pair.generate();
    const turn = derive.turn(keys.root, try sending.secret.agree(p.their_ratchet));
    var s = try State.init(allocator, state_mod.current_version, p.us.identity.key, p.them.key, turn.root, &p.our_base.public.serialize(), pq_state);
    errdefer s.deinit();
    try s.addReceiving(p.their_ratchet, .{ .key = keys.chain, .index = 0 });
    s.setSending(sending, .{ .key = turn.chain, .index = 0 });
    return s;
}

/// The responder's first state: a sending lane on its own ratchet key.
pub fn responderState(allocator: Allocator, p: Responder, keys: derive.Opening, pq_state: []const u8) !State {
    var s = try State.init(allocator, state_mod.current_version, p.us.identity.key, p.them.key, keys.root, &p.their_base.serialize(), pq_state);
    errdefer s.deinit();
    s.setSending(p.our_ratchet, .{ .key = keys.chain, .index = 0 });
    return s;
}

test "both sides open the same keys, with and without a one-time key" {
    const a = std.testing.allocator;
    const alice = try identity.IdentityPair.generate();
    const bob = try identity.IdentityPair.generate();
    const signed = try curve.Pair.generate();
    const one_time = try curve.Pair.generate();
    const post = try pq.Pair.generate(.round_three);
    for ([_]bool{ true, false }) |with_one_time| {
        const base = try curve.Pair.generate();
        const init = Initiator{ .us = alice, .our_base = base, .them = bob.identity, .their_signed = signed.public, .their_one_time = if (with_one_time) one_time.public else null, .their_ratchet = signed.public, .their_pq = post.public };
        const opened = try initiatorSecret(init);
        const resp = Responder{ .us = bob, .our_signed = signed, .our_one_time = if (with_one_time) one_time else null, .our_ratchet = signed, .our_pq = post.secret, .them = alice.identity, .their_base = base.public, .their_capsule = &opened.capsule.?.bytes };
        const answered = try responderSecret(resp);
        try std.testing.expectEqualSlices(u8, &opened.keys.root, &answered.keys.root);
        try std.testing.expectEqualSlices(u8, &opened.keys.chain, &answered.keys.chain);
        try std.testing.expectEqualSlices(u8, &opened.keys.pq_auth, &answered.keys.pq_auth);
        var alice_state = try initiatorState(a, init, opened.keys, "pq");
        defer alice_state.deinit();
        var bob_state = try responderState(a, resp, answered.keys, "pq");
        defer bob_state.deinit();
        try std.testing.expect(alice_state.receivingLane(signed.public) != null);
        try std.testing.expectEqualSlices(u8, &(try bob_state.sendingChain()).key, &alice_state.receivingLane(signed.public).?.chain.key);
        try std.testing.expectEqualSlices(u8, alice_state.base, bob_state.base);
    }
}

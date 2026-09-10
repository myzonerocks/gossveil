//! The C ABI: every input is a pointer and a length, every byte output a
//! library-owned buffer the caller frees, every call one status. Nothing here
//! calls back into the host; the caller keeps its own stores.
const std = @import("std");
const builtin = @import("builtin");
const veil = @import("gossveil");
const mem = std.mem;
const Allocator = mem.Allocator;

const curve = veil.keys.curve;
const pq = veil.keys.pq;
const identity = veil.keys.identity;
const derive = veil.keys.derive;
const cipher = veil.keys.cipher;
const records = veil.bundle.records;
const Published = veil.bundle.Published;
const Archive = veil.ratchet.Archive;
const engine = veil.ratchet.engine;
const Whisper = veil.post.Whisper;
const Opener = veil.post.Opener;
const Binding = veil.post.whisper.Binding;
const post_content = veil.post.content;
const Report = veil.post.Report;
const Circle = veil.circle.Circle;
const circle_post = veil.circle.post;
const circle_cipher = veil.circle.cipher;
const certificate = veil.envelope.certificate;
const Content = veil.envelope.Content;
const envelope_seal = veil.envelope.seal;
const multiseal = veil.envelope.multiseal;
const safety = veil.trust.safety;
const name = veil.handle.name;
const link = veil.handle.link;
const account = veil.vault.account;
const circle_params = veil.vault.circle_params;
const chunkmac = veil.stream.chunkmac;
const ServiceId = veil.ident.ServiceId;
const Fault = veil.Fault;

const is_wasm = builtin.cpu.arch == .wasm32 and builtin.os.tag == .freestanding;
const heap: Allocator = if (is_wasm) std.heap.wasm_allocator else std.heap.smp_allocator;

pub const abi_version: u32 = 1;

pub const GvBuffer = extern struct {
    ptr: ?[*]u8,
    len: usize,
};

pub const Status = enum(i32) {
    ok = 0,
    bad_argument = 1,
    bad_state = 2,
    bad_key = 3,
    bad_signature = 4,
    bad_message = 5,
    unknown_key_id = 6,
    untrusted_identity = 7,
    no_session = 8,
    replay = 9,
    legacy_version = 10,
    unknown_version = 11,
    out_of_memory = 12,
    verify_failed = 13,
    internal = 14,
};

fn within(comptime Set: type, e: anyerror) bool {
    inline for (@typeInfo(Set).error_set.?) |f| if (e == @field(Set, f.name)) return true;
    return false;
}

fn statusFor(e: anyerror) Status {
    if (e == error.ProofVerificationFailure) return .verify_failed;
    if (within(name.NameError, e)) return .bad_argument;
    return switch (e) {
        error.OutOfMemory => .out_of_memory,
        error.BadArgument, error.BadText, error.WrongLength, error.BadEntropy => .bad_argument,
        error.BadState, error.BadSession => .bad_state,
        error.BadKey, error.UnknownKeyType, error.IdentityElement, error.NonCanonical, error.WeakPublicKey, error.EncodingError => .bad_key,
        error.BadSignature => .bad_signature,
        error.BadMessage, error.BadPadding, error.Overflow, error.Truncated, error.BadTag, error.BadLink, error.AuthenticationFailed, error.BadRecord, error.BadPacket => .bad_message,
        error.UnknownKeyId => .unknown_key_id,
        error.UntrustedIdentity => .untrusted_identity,
        error.NoSession => .no_session,
        error.Replay => .replay,
        error.LegacyVersion => .legacy_version,
        error.UnknownVersion => .unknown_version,
        error.VerifyFailed => .verify_failed,
        else => .internal,
    };
}

fn bytesIn(p: ?[*]const u8, n: usize) []const u8 {
    return if (p) |ptr| ptr[0..n] else &.{};
}

fn fixed(data: []const u8, comptime n: usize) ![n]u8 {
    if (data.len != n) return error.WrongLength;
    return data[0..n].*;
}

/// One call: an arena for everything transient, and the list of outputs
/// handed over so far, taken back if a later step fails.
const Call = struct {
    arena_state: std.heap.ArenaAllocator,
    given: [8]*GvBuffer = undefined,
    given_count: usize = 0,

    fn open() Call {
        return .{ .arena_state = std.heap.ArenaAllocator.init(heap) };
    }

    fn arena(c: *Call) Allocator {
        return c.arena_state.allocator();
    }

    fn give(c: *Call, cell: *GvBuffer, data: []const u8) !void {
        cell.* = .{ .ptr = null, .len = 0 };
        c.given[c.given_count] = cell;
        c.given_count += 1;
        if (data.len == 0) return;
        const copy = try heap.alloc(u8, data.len);
        @memcpy(copy, data);
        cell.* = .{ .ptr = copy.ptr, .len = copy.len };
    }

    fn close(c: *Call, result: anyerror!void) i32 {
        defer c.arena_state.deinit();
        result catch |e| {
            for (c.given[0..c.given_count]) |cell| {
                gv_free(cell.ptr, cell.len);
                cell.* = .{ .ptr = null, .len = 0 };
            }
            return @intFromEnum(statusFor(e));
        };
        return @intFromEnum(Status.ok);
    }
};

fn usFrom(secret: []const u8) !identity.IdentityPair {
    return identity.IdentityPair.fromPair(try curve.Pair.fromSecret(try curve.Secret.parse(secret)));
}

fn archiveFrom(arena: Allocator, data: []const u8) !Archive {
    return if (data.len == 0) Archive.init(arena) else Archive.parse(arena, data);
}

fn circleFrom(arena: Allocator, data: []const u8) !Circle {
    return if (data.len == 0) Circle.init(arena) else Circle.parse(arena, data);
}

fn bindingFrom(sender: []const u8, sender_device: u32, recipient: []const u8, recipient_device: u32) ?Binding {
    if (sender.len == 0 or recipient.len == 0) return null;
    return .{
        .sender = .{ .name = sender, .device = sender_device },
        .recipient = .{ .name = recipient, .device = recipient_device },
    };
}

fn kindIn(v: u8) !engine.Kind {
    return std.enums.fromInt(engine.Kind, v) orelse Fault.BadArgument;
}

pub export fn gv_abi_version() u32 {
    return abi_version;
}

pub export fn gv_free(ptr: ?[*]u8, len: usize) void {
    if (ptr) |p| if (len > 0) heap.free(p[0..len]);
}

pub export fn gv_alloc(len: usize) ?[*]u8 {
    const slice = heap.alloc(u8, len) catch return null;
    return slice.ptr;
}

pub export fn gv_status_text(status: i32) [*:0]const u8 {
    const s: Status = std.enums.fromInt(Status, status) orelse .internal;
    return switch (s) {
        .ok => "ok",
        .bad_argument => "bad argument",
        .bad_state => "bad state",
        .bad_key => "bad key",
        .bad_signature => "bad signature",
        .bad_message => "bad message",
        .unknown_key_id => "unknown key id",
        .untrusted_identity => "untrusted identity",
        .no_session => "no session",
        .replay => "replayed message",
        .legacy_version => "legacy message version",
        .unknown_version => "unknown message version",
        .out_of_memory => "out of memory",
        .verify_failed => "verification failed",
        .internal => "internal error",
    };
}

// Keys

fn curvePair(c: *Call, secret: *GvBuffer, public_key: *GvBuffer) !void {
    const pair = try curve.Pair.generate();
    try c.give(secret, &pair.secret.serialize());
    try c.give(public_key, &pair.public.serialize());
}

pub export fn gv_curve_pair(secret: *GvBuffer, public_key: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(curvePair(&call, secret, public_key));
}

fn curvePublic(c: *Call, secret: []const u8, public_key: *GvBuffer) !void {
    const s = try curve.Secret.parse(secret);
    try c.give(public_key, &(try s.public()).serialize());
}

pub export fn gv_curve_public(secret: ?[*]const u8, secret_len: usize, public_key: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(curvePublic(&call, bytesIn(secret, secret_len), public_key));
}

fn curveSign(c: *Call, secret: []const u8, message: []const u8, signature: *GvBuffer) !void {
    const s = try curve.Secret.parse(secret);
    try c.give(signature, &try s.sign(message));
}

pub export fn gv_curve_sign(secret: ?[*]const u8, secret_len: usize, message: ?[*]const u8, message_len: usize, signature: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(curveSign(&call, bytesIn(secret, secret_len), bytesIn(message, message_len), signature));
}

fn curveVerify(_: *Call, public_key: []const u8, message: []const u8, signature: []const u8, ok: *u8) !void {
    const p = try curve.Public.parse(public_key);
    ok.* = @intFromBool(signature.len == 64 and p.verify(message, signature[0..64].*));
}

pub export fn gv_curve_verify(public_key: ?[*]const u8, public_len: usize, message: ?[*]const u8, message_len: usize, signature: ?[*]const u8, signature_len: usize, ok: *u8) i32 {
    var call = Call.open();
    return call.close(curveVerify(&call, bytesIn(public_key, public_len), bytesIn(message, message_len), bytesIn(signature, signature_len), ok));
}

fn curveAgree(c: *Call, secret: []const u8, public_key: []const u8, shared: *GvBuffer) !void {
    const s = try curve.Secret.parse(secret);
    try c.give(shared, &try s.agree(try curve.Public.parse(public_key)));
}

pub export fn gv_curve_agree(secret: ?[*]const u8, secret_len: usize, public_key: ?[*]const u8, public_len: usize, shared: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(curveAgree(&call, bytesIn(secret, secret_len), bytesIn(public_key, public_len), shared));
}

fn curveCheck(_: *Call, public_key: []const u8) !void {
    _ = try curve.Public.parse(public_key);
}

pub export fn gv_curve_check(public_key: ?[*]const u8, public_len: usize) i32 {
    var call = Call.open();
    return call.close(curveCheck(&call, bytesIn(public_key, public_len)));
}

fn pqPair(c: *Call, scheme: u8, public_key: *GvBuffer, secret: *GvBuffer) !void {
    const pair = try pq.Pair.generate(try pq.Scheme.fromByte(scheme));
    try c.give(public_key, &pair.public.serialize());
    try c.give(secret, &pair.secret.serialize());
}

pub export fn gv_pq_pair(scheme: u8, public_key: *GvBuffer, secret: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(pqPair(&call, scheme, public_key, secret));
}

fn pqEncapsulate(c: *Call, public_key: []const u8, capsule: *GvBuffer, shared: *GvBuffer) !void {
    const p = try pq.Public.parse(public_key);
    const made = try p.encapsulate();
    try c.give(capsule, &made.bytes);
    try c.give(shared, &made.shared);
}

pub export fn gv_pq_encapsulate(public_key: ?[*]const u8, public_len: usize, capsule: *GvBuffer, shared: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(pqEncapsulate(&call, bytesIn(public_key, public_len), capsule, shared));
}

fn pqOpen(c: *Call, secret: []const u8, capsule: []const u8, shared: *GvBuffer) !void {
    const s = try pq.Secret.parse(secret);
    try c.give(shared, &try s.open(capsule));
}

pub export fn gv_pq_open(secret: ?[*]const u8, secret_len: usize, capsule: ?[*]const u8, capsule_len: usize, shared: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(pqOpen(&call, bytesIn(secret, secret_len), bytesIn(capsule, capsule_len), shared));
}

fn identityPair(c: *Call, serialized: *GvBuffer) !void {
    const pair = try identity.IdentityPair.generate();
    try c.give(serialized, try pair.serialize(c.arena()));
}

pub export fn gv_identity_pair(serialized: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(identityPair(&call, serialized));
}

fn identitySerialize(c: *Call, secret: []const u8, serialized: *GvBuffer) !void {
    const us = try usFrom(secret);
    try c.give(serialized, try us.serialize(c.arena()));
}

pub export fn gv_identity_serialize(secret: ?[*]const u8, secret_len: usize, serialized: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(identitySerialize(&call, bytesIn(secret, secret_len), serialized));
}

fn identityParse(c: *Call, serialized: []const u8, public_key: *GvBuffer, secret: *GvBuffer) !void {
    const pair = try identity.IdentityPair.parse(serialized);
    try c.give(public_key, &pair.identity.serialize());
    try c.give(secret, &pair.secret.serialize());
}

pub export fn gv_identity_parse(serialized: ?[*]const u8, len: usize, public_key: *GvBuffer, secret: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(identityParse(&call, bytesIn(serialized, len), public_key, secret));
}

fn identityVouch(c: *Call, secret: []const u8, other: []const u8, signature: *GvBuffer) !void {
    const us = try usFrom(secret);
    try c.give(signature, &try us.vouch(try identity.Identity.parse(other)));
}

pub export fn gv_identity_vouch(secret: ?[*]const u8, secret_len: usize, other: ?[*]const u8, other_len: usize, signature: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(identityVouch(&call, bytesIn(secret, secret_len), bytesIn(other, other_len), signature));
}

fn identityVouched(_: *Call, public_key: []const u8, other: []const u8, signature: []const u8, ok: *u8) !void {
    const who = try identity.Identity.parse(public_key);
    const whom = try identity.Identity.parse(other);
    ok.* = @intFromBool(signature.len == 64 and who.vouchesFor(whom, signature[0..64].*));
}

pub export fn gv_identity_vouched(public_key: ?[*]const u8, public_len: usize, other: ?[*]const u8, other_len: usize, signature: ?[*]const u8, signature_len: usize, ok: *u8) i32 {
    var call = Call.open();
    return call.close(identityVouched(&call, bytesIn(public_key, public_len), bytesIn(other, other_len), bytesIn(signature, signature_len), ok));
}

// Published key records

fn oneTimeRecord(c: *Call, id: u32, secret: []const u8, record: *GvBuffer) !void {
    const r = records.OneTimeRecord{ .id = id, .pair = try curve.Pair.fromSecret(try curve.Secret.parse(secret)) };
    try c.give(record, try r.serialize(c.arena()));
}

pub export fn gv_one_time_record(id: u32, secret: ?[*]const u8, secret_len: usize, record: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(oneTimeRecord(&call, id, bytesIn(secret, secret_len), record));
}

fn oneTimeParse(c: *Call, record: []const u8, id: *u32, public_key: *GvBuffer, secret: *GvBuffer) !void {
    const r = try records.OneTimeRecord.parse(record);
    id.* = r.id;
    try c.give(public_key, &r.pair.public.serialize());
    try c.give(secret, &r.pair.secret.serialize());
}

pub export fn gv_one_time_parse(record: ?[*]const u8, len: usize, id: *u32, public_key: *GvBuffer, secret: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(oneTimeParse(&call, bytesIn(record, len), id, public_key, secret));
}

fn signedRecord(c: *Call, id: u32, stamp: u64, secret: []const u8, signature: []const u8, record: *GvBuffer) !void {
    const r = records.SignedRecord{
        .id = id,
        .stamp = stamp,
        .pair = try curve.Pair.fromSecret(try curve.Secret.parse(secret)),
        .signature = try fixed(signature, 64),
    };
    try c.give(record, try r.serialize(c.arena()));
}

pub export fn gv_signed_record(id: u32, stamp: u64, secret: ?[*]const u8, secret_len: usize, signature: ?[*]const u8, signature_len: usize, record: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(signedRecord(&call, id, stamp, bytesIn(secret, secret_len), bytesIn(signature, signature_len), record));
}

fn signedParse(c: *Call, record: []const u8, id: *u32, stamp: *u64, public_key: *GvBuffer, secret: *GvBuffer, signature: *GvBuffer) !void {
    const r = try records.SignedRecord.parse(record);
    id.* = r.id;
    stamp.* = r.stamp;
    try c.give(public_key, &r.pair.public.serialize());
    try c.give(secret, &r.pair.secret.serialize());
    try c.give(signature, &r.signature);
}

pub export fn gv_signed_parse(record: ?[*]const u8, len: usize, id: *u32, stamp: *u64, public_key: *GvBuffer, secret: *GvBuffer, signature: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(signedParse(&call, bytesIn(record, len), id, stamp, public_key, secret, signature));
}

fn pqRecord(c: *Call, id: u32, stamp: u64, public_key: []const u8, secret: []const u8, signature: []const u8, record: *GvBuffer) !void {
    const r = records.PqRecord{
        .id = id,
        .stamp = stamp,
        .pair = .{ .public = try pq.Public.parse(public_key), .secret = try pq.Secret.parse(secret) },
        .signature = try fixed(signature, 64),
    };
    try c.give(record, try r.serialize(c.arena()));
}

pub export fn gv_pq_record(id: u32, stamp: u64, public_key: ?[*]const u8, public_len: usize, secret: ?[*]const u8, secret_len: usize, signature: ?[*]const u8, signature_len: usize, record: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(pqRecord(&call, id, stamp, bytesIn(public_key, public_len), bytesIn(secret, secret_len), bytesIn(signature, signature_len), record));
}

fn pqRecordParse(c: *Call, record: []const u8, id: *u32, stamp: *u64, public_key: *GvBuffer, secret: *GvBuffer, signature: *GvBuffer) !void {
    const r = try records.PqRecord.parse(record);
    id.* = r.id;
    stamp.* = r.stamp;
    try c.give(public_key, &r.pair.public.serialize());
    try c.give(secret, &r.pair.secret.serialize());
    try c.give(signature, &r.signature);
}

pub export fn gv_pq_record_parse(record: ?[*]const u8, len: usize, id: *u32, stamp: *u64, public_key: *GvBuffer, secret: *GvBuffer, signature: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(pqRecordParse(&call, bytesIn(record, len), id, stamp, public_key, secret, signature));
}

// Sessions

pub const GvSessionInfo = extern struct {
    has_live: u8,
    can_send: u8,
    usable: u8,
    version: u32,
    local_registration_id: u32,
    remote_registration_id: u32,
    shelved: u32,
    local_identity: [33]u8,
    remote_identity: [33]u8,
    base: [33]u8,
};

fn sessionInfo(c: *Call, record: []const u8, now_secs: u64, info: *GvSessionInfo) !void {
    var archive = try archiveFrom(c.arena(), record);
    info.* = mem.zeroes(GvSessionInfo);
    info.shelved = @intCast(archive.shelvedCount());
    if (archive.live() == null) return;
    info.has_live = 1;
    info.can_send = @intFromBool(archive.canSend());
    info.usable = @intFromBool(archive.canSendAt(now_secs));
    info.version = try archive.version();
    info.local_registration_id = try archive.localRegistrationId();
    info.remote_registration_id = try archive.remoteRegistrationId();
    info.local_identity = (try archive.localIdentity()).serialize();
    info.remote_identity = (try archive.remoteIdentity()).serialize();
    const base = try archive.base();
    if (base.len == 33) info.base = base[0..33].*;
}

pub export fn gv_session_info(record: ?[*]const u8, len: usize, now_secs: u64, info: *GvSessionInfo) i32 {
    var call = Call.open();
    return call.close(sessionInfo(&call, bytesIn(record, len), now_secs, info));
}

fn sessionShelve(c: *Call, record: []const u8, out_record: *GvBuffer) !void {
    var archive = try archiveFrom(c.arena(), record);
    try archive.shelve();
    try c.give(out_record, try archive.serialize(c.arena()));
}

pub export fn gv_session_shelve(record: ?[*]const u8, len: usize, out_record: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(sessionShelve(&call, bytesIn(record, len), out_record));
}

fn sessionRatchetIs(c: *Call, record: []const u8, key: []const u8, ok: *u8) !void {
    const archive = try archiveFrom(c.arena(), record);
    ok.* = @intFromBool(archive.sendingRatchetIs(try curve.Public.parse(key)));
}

pub export fn gv_session_ratchet_is(record: ?[*]const u8, len: usize, key: ?[*]const u8, key_len: usize, ok: *u8) i32 {
    var call = Call.open();
    return call.close(sessionRatchetIs(&call, bytesIn(record, len), bytesIn(key, key_len), ok));
}

pub const GvPublished = extern struct {
    registration_id: u32,
    device: u32,
    one_time_id: i64,
    one_time: ?[*]const u8,
    one_time_len: usize,
    signed_id: u32,
    signed_key: ?[*]const u8,
    signed_len: usize,
    signed_signature: ?[*]const u8,
    signed_signature_len: usize,
    identity: ?[*]const u8,
    identity_len: usize,
    pq_id: u32,
    pq_key: ?[*]const u8,
    pq_len: usize,
    pq_signature: ?[*]const u8,
    pq_signature_len: usize,
};

fn sessionStart(c: *Call, secret: []const u8, registration_id: u32, record: []const u8, p: *const GvPublished, now_secs: u64, out_record: *GvBuffer) !void {
    const one_time_bytes = bytesIn(p.one_time, p.one_time_len);
    const offered = p.one_time_id >= 0 and one_time_bytes.len > 0;
    const published = try Published.init(
        p.registration_id,
        p.device,
        if (offered) @intCast(p.one_time_id) else null,
        if (offered) try curve.Public.parse(one_time_bytes) else null,
        p.signed_id,
        try curve.Public.parse(bytesIn(p.signed_key, p.signed_len)),
        bytesIn(p.signed_signature, p.signed_signature_len),
        try identity.Identity.parse(bytesIn(p.identity, p.identity_len)),
        p.pq_id,
        try pq.Public.parse(bytesIn(p.pq_key, p.pq_len)),
        bytesIn(p.pq_signature, p.pq_signature_len),
    );
    var archive = try archiveFrom(c.arena(), record);
    try engine.start(c.arena(), &archive, try usFrom(secret), registration_id, published, now_secs);
    try c.give(out_record, try archive.serialize(c.arena()));
}

pub export fn gv_session_start(identity_secret: ?[*]const u8, secret_len: usize, registration_id: u32, record: ?[*]const u8, record_len: usize, published: *const GvPublished, now_secs: u64, out_record: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(sessionStart(&call, bytesIn(identity_secret, secret_len), registration_id, bytesIn(record, record_len), published, now_secs, out_record));
}

fn sessionSeal(c: *Call, record: []const u8, plain: []const u8, now_secs: u64, binding: ?Binding, kind: *u8, sealed: *GvBuffer, out_record: *GvBuffer) !void {
    var archive = try archiveFrom(c.arena(), record);
    const made = try engine.seal(c.arena(), &archive, plain, now_secs, binding);
    kind.* = @intFromEnum(made.kind);
    try c.give(sealed, made.bytes);
    try c.give(out_record, try archive.serialize(c.arena()));
}

pub export fn gv_session_seal(record: ?[*]const u8, record_len: usize, plain: ?[*]const u8, plain_len: usize, now_secs: u64, sender: ?[*]const u8, sender_len: usize, sender_device: u32, recipient: ?[*]const u8, recipient_len: usize, recipient_device: u32, kind: *u8, sealed: *GvBuffer, out_record: *GvBuffer) i32 {
    var call = Call.open();
    const binding = bindingFrom(bytesIn(sender, sender_len), sender_device, bytesIn(recipient, recipient_len), recipient_device);
    return call.close(sessionSeal(&call, bytesIn(record, record_len), bytesIn(plain, plain_len), now_secs, binding, kind, sealed, out_record));
}

fn sessionOpen(c: *Call, record: []const u8, whisper: []const u8, binding: ?Binding, plain: *GvBuffer, out_record: *GvBuffer) !void {
    var archive = try archiveFrom(c.arena(), record);
    if (archive.live() == null and archive.shelvedCount() == 0) return Fault.NoSession;
    const message = try Whisper.parse(c.arena(), whisper);
    const text = try engine.openWhisper(c.arena(), &archive, message, binding);
    try c.give(plain, text);
    try c.give(out_record, try archive.serialize(c.arena()));
}

pub export fn gv_session_open(record: ?[*]const u8, record_len: usize, whisper: ?[*]const u8, whisper_len: usize, sender: ?[*]const u8, sender_len: usize, sender_device: u32, recipient: ?[*]const u8, recipient_len: usize, recipient_device: u32, plain: *GvBuffer, out_record: *GvBuffer) i32 {
    var call = Call.open();
    const binding = bindingFrom(bytesIn(sender, sender_len), sender_device, bytesIn(recipient, recipient_len), recipient_device);
    return call.close(sessionOpen(&call, bytesIn(record, record_len), bytesIn(whisper, whisper_len), binding, plain, out_record));
}

pub const GvConsumed = extern struct {
    used: u8,
    one_time_id: i64,
    signed_id: u32,
    pq_id: u32,
    base: [33]u8,
};

const FirstInputs = struct {
    secret: []const u8,
    registration_id: u32,
    record: []const u8,
    opener: []const u8,
    signed_record: []const u8,
    one_time_record: []const u8,
    pq_record: []const u8,
    binding: ?Binding,
};

fn sessionOpenFirst(c: *Call, in: FirstInputs, plain: *GvBuffer, out_record: *GvBuffer, consumed: *GvConsumed) !void {
    var archive = try archiveFrom(c.arena(), in.record);
    const first = try Opener.parse(c.arena(), in.opener);
    const offered: engine.Offered = .{
        .signed = if (in.signed_record.len > 0) try records.SignedRecord.parse(in.signed_record) else null,
        .one_time = if (in.one_time_record.len > 0) try records.OneTimeRecord.parse(in.one_time_record) else null,
        .pq = if (in.pq_record.len > 0) try records.PqRecord.parse(in.pq_record) else null,
    };
    const opened = try engine.openFirst(c.arena(), &archive, try usFrom(in.secret), in.registration_id, first, offered, in.binding);
    consumed.* = mem.zeroes(GvConsumed);
    consumed.one_time_id = -1;
    if (opened.consumed) |u| {
        consumed.used = 1;
        consumed.one_time_id = if (u.one_time_id) |id| @intCast(id) else -1;
        consumed.signed_id = u.signed_id;
        consumed.pq_id = u.pq_id;
        consumed.base = u.base.serialize();
    }
    try c.give(plain, opened.plain);
    try c.give(out_record, try archive.serialize(c.arena()));
}

pub export fn gv_session_open_first(identity_secret: ?[*]const u8, secret_len: usize, registration_id: u32, record: ?[*]const u8, record_len: usize, opener: ?[*]const u8, opener_len: usize, signed_record: ?[*]const u8, signed_len: usize, one_time_record: ?[*]const u8, one_time_len: usize, pq_record: ?[*]const u8, pq_len: usize, sender: ?[*]const u8, sender_len: usize, sender_device: u32, recipient: ?[*]const u8, recipient_len: usize, recipient_device: u32, plain: *GvBuffer, out_record: *GvBuffer, consumed: *GvConsumed) i32 {
    var call = Call.open();
    const in: FirstInputs = .{
        .secret = bytesIn(identity_secret, secret_len),
        .registration_id = registration_id,
        .record = bytesIn(record, record_len),
        .opener = bytesIn(opener, opener_len),
        .signed_record = bytesIn(signed_record, signed_len),
        .one_time_record = bytesIn(one_time_record, one_time_len),
        .pq_record = bytesIn(pq_record, pq_len),
        .binding = bindingFrom(bytesIn(sender, sender_len), sender_device, bytesIn(recipient, recipient_len), recipient_device),
    };
    return call.close(sessionOpenFirst(&call, in, plain, out_record, consumed));
}

pub const GvOpenerInfo = extern struct {
    version: u8,
    registration_id: u32,
    one_time_id: i64,
    signed_id: u32,
    pq_id: i64,
    base: [33]u8,
    identity: [33]u8,
};

fn openerParse(c: *Call, opener: []const u8, info: *GvOpenerInfo, inner: *GvBuffer) !void {
    const o = try Opener.parse(c.arena(), opener);
    info.* = .{
        .version = o.version,
        .registration_id = o.registration_id,
        .one_time_id = if (o.one_time_id) |id| @intCast(id) else -1,
        .signed_id = o.signed_id,
        .pq_id = if (o.pq_id) |id| @intCast(id) else -1,
        .base = o.base.serialize(),
        .identity = o.identity.serialize(),
    };
    try c.give(inner, o.inner);
}

pub export fn gv_opener_parse(opener: ?[*]const u8, len: usize, info: *GvOpenerInfo, inner: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(openerParse(&call, bytesIn(opener, len), info, inner));
}

pub const GvWhisperInfo = extern struct {
    version: u8,
    index: u32,
    previous_index: u32,
    ratchet: [33]u8,
};

fn whisperParse(c: *Call, whisper: []const u8, info: *GvWhisperInfo, body: *GvBuffer) !void {
    const w = try Whisper.parse(c.arena(), whisper);
    info.* = .{ .version = w.version, .index = w.index, .previous_index = w.previous_index, .ratchet = w.ratchet.serialize() };
    try c.give(body, w.body);
}

pub export fn gv_whisper_parse(whisper: ?[*]const u8, len: usize, info: *GvWhisperInfo, body: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(whisperParse(&call, bytesIn(whisper, len), info, body));
}

// Circles

fn circleAnnounce(c: *Call, record: []const u8, circle_id: []const u8, out_record: *GvBuffer, announce: *GvBuffer) !void {
    var circle = try circleFrom(c.arena(), record);
    const a = try circle_cipher.announce(c.arena(), &circle, try fixed(circle_id, 16));
    try c.give(out_record, try circle.serialize(c.arena()));
    try c.give(announce, a.bytes);
}

pub export fn gv_circle_announce(record: ?[*]const u8, record_len: usize, circle_id: ?[*]const u8, id_len: usize, out_record: *GvBuffer, announce: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(circleAnnounce(&call, bytesIn(record, record_len), bytesIn(circle_id, id_len), out_record, announce));
}

fn circleAdmit(c: *Call, record: []const u8, announce: []const u8, out_record: *GvBuffer) !void {
    var circle = try circleFrom(c.arena(), record);
    const a = try circle_post.Announce.parse(c.arena(), announce);
    try circle_cipher.admit(&circle, a);
    try c.give(out_record, try circle.serialize(c.arena()));
}

pub export fn gv_circle_admit(record: ?[*]const u8, record_len: usize, announce: ?[*]const u8, announce_len: usize, out_record: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(circleAdmit(&call, bytesIn(record, record_len), bytesIn(announce, announce_len), out_record));
}

pub const GvAnnounceInfo = extern struct {
    version: u8,
    circle_id: [16]u8,
    chain_id: u32,
    step: u32,
    seed: [32]u8,
    signing: [33]u8,
};

fn announceParse(c: *Call, announce: []const u8, info: *GvAnnounceInfo) !void {
    const a = try circle_post.Announce.parse(c.arena(), announce);
    info.* = .{ .version = a.version, .circle_id = a.circle_id, .chain_id = a.chain_id, .step = a.step, .seed = a.seed, .signing = a.signing.serialize() };
}

pub export fn gv_announce_parse(announce: ?[*]const u8, len: usize, info: *GvAnnounceInfo) i32 {
    var call = Call.open();
    return call.close(announceParse(&call, bytesIn(announce, len), info));
}

fn circleSeal(c: *Call, record: []const u8, circle_id: []const u8, plain: []const u8, note: *GvBuffer, out_record: *GvBuffer) !void {
    var circle = try circleFrom(c.arena(), record);
    const bytes = try circle_cipher.seal(c.arena(), &circle, try fixed(circle_id, 16), plain);
    try c.give(note, bytes);
    try c.give(out_record, try circle.serialize(c.arena()));
}

pub export fn gv_circle_seal(record: ?[*]const u8, record_len: usize, circle_id: ?[*]const u8, id_len: usize, plain: ?[*]const u8, plain_len: usize, note: *GvBuffer, out_record: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(circleSeal(&call, bytesIn(record, record_len), bytesIn(circle_id, id_len), bytesIn(plain, plain_len), note, out_record));
}

fn circleOpen(c: *Call, record: []const u8, note: []const u8, plain: *GvBuffer, out_record: *GvBuffer) !void {
    var circle = try circleFrom(c.arena(), record);
    if (circle.newest() == null) return Fault.NoSession;
    const n = try circle_post.Note.parse(c.arena(), note);
    const text = try circle_cipher.open(c.arena(), &circle, n);
    try c.give(plain, text);
    try c.give(out_record, try circle.serialize(c.arena()));
}

pub export fn gv_circle_open(record: ?[*]const u8, record_len: usize, note: ?[*]const u8, note_len: usize, plain: *GvBuffer, out_record: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(circleOpen(&call, bytesIn(record, record_len), bytesIn(note, note_len), plain, out_record));
}

pub const GvNoteInfo = extern struct {
    version: u8,
    circle_id: [16]u8,
    chain_id: u32,
    step: u32,
};

fn noteParse(c: *Call, note: []const u8, info: *GvNoteInfo, body: *GvBuffer) !void {
    const n = try circle_post.Note.parse(c.arena(), note);
    info.* = .{ .version = n.version, .circle_id = n.circle_id, .chain_id = n.chain_id, .step = n.step };
    try c.give(body, n.body);
}

pub export fn gv_note_parse(note: ?[*]const u8, len: usize, info: *GvNoteInfo, body: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(noteParse(&call, bytesIn(note, len), info, body));
}

// Envelopes

fn serverCert(c: *Call, key_id: u32, key: []const u8, trust_secret: []const u8, cert: *GvBuffer) !void {
    const made = try certificate.ServerCert.make(c.arena(), key_id, try curve.Public.parse(key), try curve.Secret.parse(trust_secret));
    try c.give(cert, made.bytes);
}

pub export fn gv_server_cert(key_id: u32, key: ?[*]const u8, key_len: usize, trust_secret: ?[*]const u8, trust_len: usize, cert: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(serverCert(&call, key_id, bytesIn(key, key_len), bytesIn(trust_secret, trust_len), cert));
}

pub const GvServerCertInfo = extern struct {
    key_id: u32,
    key: [33]u8,
};

fn serverCertParse(c: *Call, cert: []const u8, info: *GvServerCertInfo, body: *GvBuffer, signature: *GvBuffer) !void {
    const parsed = try certificate.ServerCert.parse(c.arena(), cert);
    info.* = .{ .key_id = parsed.key_id, .key = parsed.key.serialize() };
    try c.give(body, parsed.body);
    try c.give(signature, &parsed.signature);
}

pub export fn gv_server_cert_parse(cert: ?[*]const u8, len: usize, info: *GvServerCertInfo, body: *GvBuffer, signature: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(serverCertParse(&call, bytesIn(cert, len), info, body, signature));
}

fn serverCertCheck(c: *Call, cert: []const u8, trust_root: []const u8, ok: *u8) !void {
    const parsed = try certificate.ServerCert.parse(c.arena(), cert);
    ok.* = @intFromBool(parsed.signedBy(try curve.Public.parse(trust_root)));
}

pub export fn gv_server_cert_check(cert: ?[*]const u8, len: usize, trust_root: ?[*]const u8, trust_len: usize, ok: *u8) i32 {
    var call = Call.open();
    return call.close(serverCertCheck(&call, bytesIn(cert, len), bytesIn(trust_root, trust_len), ok));
}

const SenderCertInputs = struct {
    sender_id: []const u8,
    phone: []const u8,
    device: u32,
    key: []const u8,
    expires_ms: u64,
    server_cert: []const u8,
    server_secret: []const u8,
};

fn senderCert(c: *Call, in: SenderCertInputs, cert: *GvBuffer) !void {
    const server = try certificate.ServerCert.parse(c.arena(), in.server_cert);
    const made = try certificate.SenderCert.make(c.arena(), .{
        .sender_id = in.sender_id,
        .sender_phone = if (in.phone.len > 0) in.phone else null,
        .sender_device = in.device,
        .sender_key = try curve.Public.parse(in.key),
        .expires_ms = in.expires_ms,
        .server = &server,
        .server_secret = try curve.Secret.parse(in.server_secret),
    });
    try c.give(cert, made.bytes);
}

pub export fn gv_sender_cert(sender_id: ?[*]const u8, id_len: usize, phone: ?[*]const u8, phone_len: usize, device: u32, key: ?[*]const u8, key_len: usize, expires_ms: u64, server_cert: ?[*]const u8, server_len: usize, server_secret: ?[*]const u8, secret_len: usize, cert: *GvBuffer) i32 {
    var call = Call.open();
    const in: SenderCertInputs = .{
        .sender_id = bytesIn(sender_id, id_len),
        .phone = bytesIn(phone, phone_len),
        .device = device,
        .key = bytesIn(key, key_len),
        .expires_ms = expires_ms,
        .server_cert = bytesIn(server_cert, server_len),
        .server_secret = bytesIn(server_secret, secret_len),
    };
    return call.close(senderCert(&call, in, cert));
}

pub const GvSenderCertInfo = extern struct {
    device: u32,
    expires_ms: u64,
    key: [33]u8,
    has_phone: u8,
};

fn senderCertParse(c: *Call, cert: []const u8, info: *GvSenderCertInfo, sender_id: *GvBuffer, phone: *GvBuffer, server_cert: *GvBuffer, body: *GvBuffer, signature: *GvBuffer) !void {
    const parsed = try certificate.SenderCert.parse(c.arena(), cert);
    info.* = .{ .device = parsed.sender_device, .expires_ms = parsed.expires_ms, .key = parsed.sender_key.serialize(), .has_phone = @intFromBool(parsed.sender_phone != null) };
    try c.give(sender_id, parsed.sender_id);
    try c.give(phone, parsed.sender_phone orelse &.{});
    try c.give(server_cert, parsed.server.bytes);
    try c.give(body, parsed.body);
    try c.give(signature, &parsed.signature);
}

pub export fn gv_sender_cert_parse(cert: ?[*]const u8, len: usize, info: *GvSenderCertInfo, sender_id: *GvBuffer, phone: *GvBuffer, server_cert: *GvBuffer, body: *GvBuffer, signature: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(senderCertParse(&call, bytesIn(cert, len), info, sender_id, phone, server_cert, body, signature));
}

fn senderCertCheck(c: *Call, cert: []const u8, trust_root: []const u8, now_ms: u64, ok: *u8) !void {
    const parsed = try certificate.SenderCert.parse(c.arena(), cert);
    ok.* = @intFromBool(parsed.valid(try curve.Public.parse(trust_root), now_ms));
}

pub export fn gv_sender_cert_check(cert: ?[*]const u8, len: usize, trust_root: ?[*]const u8, trust_len: usize, now_ms: u64, ok: *u8) i32 {
    var call = Call.open();
    return call.close(senderCertCheck(&call, bytesIn(cert, len), bytesIn(trust_root, trust_len), now_ms, ok));
}

fn contentMake(c: *Call, kind: u8, sender_cert: []const u8, body: []const u8, hint: u8, circle_id: ?[]const u8, content: *GvBuffer) !void {
    const sender = try certificate.SenderCert.parse(c.arena(), sender_cert);
    const made = try Content.make(c.arena(), try kindIn(kind), &sender, body, @enumFromInt(hint), circle_id);
    try c.give(content, made.bytes);
}

pub export fn gv_content(kind: u8, sender_cert: ?[*]const u8, cert_len: usize, body: ?[*]const u8, body_len: usize, hint: u8, circle_id: ?[*]const u8, circle_len: usize, has_circle: u8, content: *GvBuffer) i32 {
    var call = Call.open();
    const circle: ?[]const u8 = if (has_circle != 0) bytesIn(circle_id, circle_len) else null;
    return call.close(contentMake(&call, kind, bytesIn(sender_cert, cert_len), bytesIn(body, body_len), hint, circle, content));
}

pub const GvContentInfo = extern struct {
    kind: u8,
    hint: u8,
    has_circle: u8,
};

fn contentParse(c: *Call, content: []const u8, info: *GvContentInfo, body: *GvBuffer, sender_cert: *GvBuffer, circle_id: *GvBuffer) !void {
    const parsed = try Content.parse(c.arena(), content);
    info.* = .{ .kind = @intFromEnum(parsed.kind), .hint = @intFromEnum(parsed.hint), .has_circle = @intFromBool(parsed.circle_id != null) };
    try c.give(body, parsed.body);
    try c.give(sender_cert, parsed.sender.bytes);
    try c.give(circle_id, parsed.circle_id orelse &.{});
}

pub export fn gv_content_parse(content: ?[*]const u8, len: usize, info: *GvContentInfo, body: *GvBuffer, sender_cert: *GvBuffer, circle_id: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(contentParse(&call, bytesIn(content, len), info, body, sender_cert, circle_id));
}

fn envelopeSeal(c: *Call, secret: []const u8, recipient: []const u8, content: []const u8, envelope: *GvBuffer) !void {
    const parsed = try Content.parse(c.arena(), content);
    try c.give(envelope, try envelope_seal.seal(c.arena(), try usFrom(secret), try curve.Public.parse(recipient), &parsed));
}

pub export fn gv_envelope_seal(identity_secret: ?[*]const u8, secret_len: usize, recipient_identity: ?[*]const u8, recipient_len: usize, content: ?[*]const u8, content_len: usize, envelope: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(envelopeSeal(&call, bytesIn(identity_secret, secret_len), bytesIn(recipient_identity, recipient_len), bytesIn(content, content_len), envelope));
}

fn envelopeOpen(c: *Call, secret: []const u8, envelope: []const u8, content: *GvBuffer) !void {
    const opened = try envelope_seal.open(c.arena(), try usFrom(secret), envelope);
    try c.give(content, opened.bytes);
}

pub export fn gv_envelope_open(identity_secret: ?[*]const u8, secret_len: usize, envelope: ?[*]const u8, envelope_len: usize, content: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(envelopeOpen(&call, bytesIn(identity_secret, secret_len), bytesIn(envelope, envelope_len), content));
}

const Cursor = struct {
    data: []const u8,
    at: usize = 0,

    fn take(k: *Cursor, n: usize) ![]const u8 {
        if (k.at + n > k.data.len) return Fault.BadArgument;
        defer k.at += n;
        return k.data[k.at..][0..n];
    }

    fn byte(k: *Cursor) !u8 {
        return (try k.take(1))[0];
    }
};

/// Recipients arrive as one blob: a count, then per recipient a 17-byte service
/// id, a device count, (device, big-endian registration id) pairs and a 33-byte
/// identity key. Excluded ids are a count and 17 bytes each.
fn envelopeSealMany(c: *Call, secret: []const u8, recipients_blob: []const u8, excluded_blob: []const u8, content: []const u8, sent: *GvBuffer) !void {
    const arena = c.arena();
    var k = Cursor{ .data = recipients_blob };
    const recipients = try arena.alloc(multiseal.Recipient, try k.byte());
    for (recipients) |*r| {
        const service_id = try ServiceId.fromFixed((try k.take(17))[0..17].*);
        const devices = try arena.alloc(multiseal.Device, try k.byte());
        for (devices) |*d| {
            const device = try k.byte();
            d.* = .{ .device = device, .registration_id = mem.readInt(u16, (try k.take(2))[0..2], .big) };
        }
        r.* = .{ .service_id = service_id, .devices = devices, .identity = try curve.Public.parse(try k.take(33)) };
    }
    var excluded: []ServiceId = &.{};
    if (excluded_blob.len > 0) {
        var e = Cursor{ .data = excluded_blob };
        excluded = try arena.alloc(ServiceId, try e.byte());
        for (excluded) |*sid| sid.* = try ServiceId.fromFixed((try e.take(17))[0..17].*);
    }
    const parsed = try Content.parse(arena, content);
    try c.give(sent, try multiseal.sealForMany(arena, try usFrom(secret), recipients, excluded, &parsed));
}

pub export fn gv_envelope_seal_many(identity_secret: ?[*]const u8, secret_len: usize, recipients: ?[*]const u8, recipients_len: usize, excluded: ?[*]const u8, excluded_len: usize, content: ?[*]const u8, content_len: usize, sent: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(envelopeSealMany(&call, bytesIn(identity_secret, secret_len), bytesIn(recipients, recipients_len), bytesIn(excluded, excluded_len), bytesIn(content, content_len), sent));
}

fn envelopeForSingle(c: *Call, sent: []const u8, received: *GvBuffer) !void {
    try c.give(received, try multiseal.forSingle(c.arena(), sent));
}

pub export fn gv_envelope_for_single(sent: ?[*]const u8, len: usize, received: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(envelopeForSingle(&call, bytesIn(sent, len), received));
}

fn envelopeForRecipient(c: *Call, sent: []const u8, service_id: []const u8, device: u8, received: *GvBuffer) !void {
    try c.give(received, try multiseal.forRecipient(c.arena(), sent, try ServiceId.fromFixed(try fixed(service_id, 17)), device));
}

pub export fn gv_envelope_for_recipient(sent: ?[*]const u8, len: usize, service_id: ?[*]const u8, id_len: usize, device: u8, received: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(envelopeForRecipient(&call, bytesIn(sent, len), bytesIn(service_id, id_len), device, received));
}

// Safety numbers

fn safetyOf(c: *Call, version: u32, iterations: u32, local_id: []const u8, local_key: []const u8, remote_id: []const u8, remote_key: []const u8, display: *GvBuffer, scannable: *GvBuffer) !void {
    const s = try safety.Safety.of(version, iterations, local_id, try identity.Identity.parse(local_key), remote_id, try identity.Identity.parse(remote_key));
    try c.give(display, &s.display.text);
    try c.give(scannable, try s.scannable.serialize(c.arena()));
}

pub export fn gv_safety(version: u32, iterations: u32, local_id: ?[*]const u8, local_id_len: usize, local_key: ?[*]const u8, local_key_len: usize, remote_id: ?[*]const u8, remote_id_len: usize, remote_key: ?[*]const u8, remote_key_len: usize, display: *GvBuffer, scannable: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(safetyOf(&call, version, iterations, bytesIn(local_id, local_id_len), bytesIn(local_key, local_key_len), bytesIn(remote_id, remote_id_len), bytesIn(remote_key, remote_key_len), display, scannable));
}

fn safetyMatches(_: *Call, ours: []const u8, theirs: []const u8, ok: *u8) !void {
    const mine = try safety.Scannable.parse(ours);
    ok.* = @intFromBool(try mine.matches(theirs));
}

pub export fn gv_safety_matches(ours: ?[*]const u8, ours_len: usize, theirs: ?[*]const u8, theirs_len: usize, ok: *u8) i32 {
    var call = Call.open();
    return call.close(safetyMatches(&call, bytesIn(ours, ours_len), bytesIn(theirs, theirs_len), ok));
}

// Handles

fn handleHash(c: *Call, text: []const u8, hash: *GvBuffer) !void {
    try c.give(hash, &try name.hashOf(text));
}

pub export fn gv_handle_hash(handle: ?[*]const u8, len: usize, hash: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(handleHash(&call, bytesIn(handle, len), hash));
}

fn handleProof(c: *Call, text: []const u8, randomness: []const u8, proof: *GvBuffer) !void {
    var r: [32]u8 = undefined;
    if (randomness.len == 32) r = randomness[0..32].* else veil.entropy.fill(&r);
    try c.give(proof, &try name.proofOf(text, r));
}

pub export fn gv_handle_proof(handle: ?[*]const u8, len: usize, randomness: ?[*]const u8, randomness_len: usize, proof: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(handleProof(&call, bytesIn(handle, len), bytesIn(randomness, randomness_len), proof));
}

fn handleVerify(_: *Call, proof: []const u8, hash: []const u8, ok: *u8) !void {
    ok.* = if (name.Handle.verify(proof, try fixed(hash, 32))) 1 else |_| 0;
}

pub export fn gv_handle_verify(proof: ?[*]const u8, proof_len: usize, hash: ?[*]const u8, hash_len: usize, ok: *u8) i32 {
    var call = Call.open();
    return call.close(handleVerify(&call, bytesIn(proof, proof_len), bytesIn(hash, hash_len), ok));
}

fn handleCandidates(c: *Call, nickname: []const u8, min_len: u32, max_len: u32, out: *GvBuffer) !void {
    const arena = c.arena();
    const list = try name.candidates(arena, nickname, .{ .min = min_len, .max = max_len });
    var joined: std.ArrayList(u8) = .empty;
    for (list, 0..) |candidate, i| {
        if (i > 0) try joined.append(arena, '\n');
        try joined.appendSlice(arena, candidate);
    }
    try c.give(out, joined.items);
}

pub export fn gv_handle_candidates(nickname: ?[*]const u8, len: usize, min_len: u32, max_len: u32, newline_separated: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(handleCandidates(&call, bytesIn(nickname, len), min_len, max_len, newline_separated));
}

fn handleFromParts(c: *Call, nickname: []const u8, discriminator: []const u8, min_len: u32, max_len: u32, text: *GvBuffer, hash: *GvBuffer) !void {
    const h = try name.Handle.fromParts(nickname, discriminator, .{ .min = min_len, .max = max_len });
    try c.give(text, try std.fmt.allocPrint(c.arena(), "{s}.{s}", .{ nickname, discriminator }));
    try c.give(hash, &try h.hash());
}

pub export fn gv_handle_from_parts(nickname: ?[*]const u8, nickname_len: usize, discriminator: ?[*]const u8, discriminator_len: usize, min_len: u32, max_len: u32, handle: *GvBuffer, hash: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(handleFromParts(&call, bytesIn(nickname, nickname_len), bytesIn(discriminator, discriminator_len), min_len, max_len, handle, hash));
}

fn handleLink(c: *Call, text: []const u8, previous: []const u8, out_entropy: *GvBuffer, sealed: *GvBuffer) !void {
    const made = try link.create(c.arena(), text, if (previous.len == 32) previous[0..32].* else null);
    try c.give(out_entropy, &made.entropy);
    try c.give(sealed, made.sealed);
}

pub export fn gv_handle_link(handle: ?[*]const u8, len: usize, entropy: ?[*]const u8, entropy_len: usize, out_entropy: *GvBuffer, sealed: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(handleLink(&call, bytesIn(handle, len), bytesIn(entropy, entropy_len), out_entropy, sealed));
}

fn handleLinkOpen(c: *Call, entropy: []const u8, sealed: []const u8, text: *GvBuffer) !void {
    try c.give(text, try link.open(c.arena(), entropy, sealed));
}

pub export fn gv_handle_link_open(entropy: ?[*]const u8, entropy_len: usize, sealed: ?[*]const u8, sealed_len: usize, handle: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(handleLinkOpen(&call, bytesIn(entropy, entropy_len), bytesIn(sealed, sealed_len), handle));
}

// The vault

fn poolRandom(c: *Call, pool: *GvBuffer) !void {
    const p = account.EntropyPool.random();
    try c.give(pool, p.text());
}

pub export fn gv_pool_random(pool: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(poolRandom(&call, pool));
}

pub export fn gv_pool_valid(pool: ?[*]const u8, len: usize) u8 {
    return @intFromBool(account.EntropyPool.valid(bytesIn(pool, len)));
}

fn poolDerive(c: *Call, pool: []const u8, recovery_key: *GvBuffer, backup_key: *GvBuffer) !void {
    const p = try account.EntropyPool.parse(pool);
    try c.give(recovery_key, &p.recoveryKey());
    try c.give(backup_key, &p.backupKey().bytes);
}

pub export fn gv_pool_derive(pool: ?[*]const u8, len: usize, recovery_key: *GvBuffer, backup_key: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(poolDerive(&call, bytesIn(pool, len), recovery_key, backup_key));
}

fn backupKeyRandom(c: *Call, key: *GvBuffer) !void {
    try c.give(key, &account.BackupKey.random().bytes);
}

pub export fn gv_backup_key_random(key: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(backupKeyRandom(&call, key));
}

fn backupKeyIn(key: []const u8) !account.BackupKey {
    return .{ .bytes = try fixed(key, account.backup_key_length) };
}

fn backupKeyForAccount(c: *Call, key: []const u8, account_id: []const u8, backup_id: *GvBuffer, signing_key: *GvBuffer) !void {
    const k = try backupKeyIn(key);
    const who = try ServiceId.parse(account_id);
    if (who.kind != .aci) return Fault.BadArgument;
    try c.give(backup_id, &k.backupId(who));
    try c.give(signing_key, &k.signingKey(who).serialize());
}

pub export fn gv_backup_key_for_account(key: ?[*]const u8, key_len: usize, account_id: ?[*]const u8, id_len: usize, backup_id: *GvBuffer, signing_key: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(backupKeyForAccount(&call, bytesIn(key, key_len), bytesIn(account_id, id_len), backup_id, signing_key));
}

fn backupKeyLocalMetadata(c: *Call, key: []const u8, metadata_key: *GvBuffer) !void {
    try c.give(metadata_key, &(try backupKeyIn(key)).localMetadataKey());
}

pub export fn gv_backup_key_local_metadata(key: ?[*]const u8, key_len: usize, metadata_key: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(backupKeyLocalMetadata(&call, bytesIn(key, key_len), metadata_key));
}

fn backupKeyMedia(c: *Call, key: []const u8, media_name: []const u8, media_id: *GvBuffer, media_key: *GvBuffer, thumbnail_key: *GvBuffer) !void {
    const k = try backupKeyIn(key);
    const id = try k.mediaId(media_name);
    try c.give(media_id, &id);
    try c.give(media_key, &k.mediaKey(id));
    try c.give(thumbnail_key, &k.thumbnailKey(id));
}

pub export fn gv_backup_key_media(key: ?[*]const u8, key_len: usize, media_name: ?[*]const u8, name_len: usize, media_id: *GvBuffer, media_key: *GvBuffer, thumbnail_key: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(backupKeyMedia(&call, bytesIn(key, key_len), bytesIn(media_name, name_len), media_id, media_key, thumbnail_key));
}

fn backupKeyMediaKeys(c: *Call, key: []const u8, media_id: []const u8, media_key: *GvBuffer, thumbnail_key: *GvBuffer) !void {
    const k = try backupKeyIn(key);
    const id = try fixed(media_id, account.media_id_length);
    try c.give(media_key, &k.mediaKey(id));
    try c.give(thumbnail_key, &k.thumbnailKey(id));
}

pub export fn gv_backup_key_media_keys(key: ?[*]const u8, key_len: usize, media_id: ?[*]const u8, id_len: usize, media_key: *GvBuffer, thumbnail_key: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(backupKeyMediaKeys(&call, bytesIn(key, key_len), bytesIn(media_id, id_len), media_key, thumbnail_key));
}

fn circleMasterRandom(c: *Call, master: *GvBuffer) !void {
    try c.give(master, &circle_params.MasterKey.random().bytes);
}

pub export fn gv_circle_master_random(master: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(circleMasterRandom(&call, master));
}

fn circleSecretParams(c: *Call, master: []const u8, secret_params: *GvBuffer) !void {
    const params = try (try circle_params.MasterKey.parse(master)).secretParams();
    try c.give(secret_params, &params.serialize());
}

pub export fn gv_circle_secret_params(master: ?[*]const u8, len: usize, secret_params: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(circleSecretParams(&call, bytesIn(master, len), secret_params));
}

fn circleParamsInfo(c: *Call, secret_params: []const u8, master: *GvBuffer, identifier: *GvBuffer, public_params: *GvBuffer) !void {
    const params = try circle_params.SecretParams.parse(secret_params);
    try c.give(master, &params.master.bytes);
    try c.give(identifier, &params.identifier);
    try c.give(public_params, &params.publicParams());
}

pub export fn gv_circle_params_info(secret_params: ?[*]const u8, len: usize, master: *GvBuffer, identifier: *GvBuffer, public_params: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(circleParamsInfo(&call, bytesIn(secret_params, len), master, identifier, public_params));
}

// Streams, primitives, reports

fn hkdfOut(c: *Call, material: []const u8, salt: ?[]const u8, info: []const u8, out_len: u32, out: *GvBuffer) !void {
    if (out_len == 0 or out_len > 255 * 32) return Fault.BadArgument;
    const buf = try c.arena().alloc(u8, out_len);
    derive.hkdf(buf, material, salt, info);
    try c.give(out, buf);
}

pub export fn gv_hkdf(material: ?[*]const u8, material_len: usize, salt: ?[*]const u8, salt_len: usize, has_salt: u8, info: ?[*]const u8, info_len: usize, out_len: u32, out: *GvBuffer) i32 {
    var call = Call.open();
    const salt_in: ?[]const u8 = if (has_salt != 0) bytesIn(salt, salt_len) else null;
    return call.close(hkdfOut(&call, bytesIn(material, material_len), salt_in, bytesIn(info, info_len), out_len, out));
}

fn sivSeal(c: *Call, key: []const u8, nonce: []const u8, plain: []const u8, aad: []const u8, sealed: *GvBuffer) !void {
    try c.give(sealed, try cipher.sivSeal(c.arena(), try fixed(key, 32), try fixed(nonce, 12), plain, aad));
}

pub export fn gv_siv_seal(key: ?[*]const u8, key_len: usize, nonce: ?[*]const u8, nonce_len: usize, plain: ?[*]const u8, plain_len: usize, aad: ?[*]const u8, aad_len: usize, sealed: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(sivSeal(&call, bytesIn(key, key_len), bytesIn(nonce, nonce_len), bytesIn(plain, plain_len), bytesIn(aad, aad_len), sealed));
}

fn sivOpen(c: *Call, key: []const u8, nonce: []const u8, sealed: []const u8, aad: []const u8, plain: *GvBuffer) !void {
    try c.give(plain, try cipher.sivOpen(c.arena(), try fixed(key, 32), try fixed(nonce, 12), sealed, aad));
}

pub export fn gv_siv_open(key: ?[*]const u8, key_len: usize, nonce: ?[*]const u8, nonce_len: usize, sealed: ?[*]const u8, sealed_len: usize, aad: ?[*]const u8, aad_len: usize, plain: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(sivOpen(&call, bytesIn(key, key_len), bytesIn(nonce, nonce_len), bytesIn(sealed, sealed_len), bytesIn(aad, aad_len), plain));
}

fn randomOut(c: *Call, len: u32, out: *GvBuffer) !void {
    const buf = try c.arena().alloc(u8, len);
    veil.entropy.fill(buf);
    try c.give(out, buf);
}

pub export fn gv_random(len: u32, out: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(randomOut(&call, len, out));
}

fn chunkTags(c: *Call, key: []const u8, chunk: u32, data: []const u8, tags: *GvBuffer) !void {
    if (chunk == 0) return Fault.BadArgument;
    var tagger = try chunkmac.Tagger.init(c.arena(), try fixed(key, 32), chunk);
    try tagger.update(data);
    try c.give(tags, try tagger.finish());
}

pub export fn gv_chunk_tags(key: ?[*]const u8, key_len: usize, chunk: u32, data: ?[*]const u8, data_len: usize, tags: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(chunkTags(&call, bytesIn(key, key_len), chunk, bytesIn(data, data_len), tags));
}

fn chunkCheck(c: *Call, key: []const u8, chunk: u32, data: []const u8, tags: []const u8) !void {
    if (chunk == 0) return Fault.BadArgument;
    var checker = try chunkmac.Checker.init(c.arena(), try fixed(key, 32), chunk, tags);
    try checker.update(data);
    try checker.finish();
}

pub export fn gv_chunk_check(key: ?[*]const u8, key_len: usize, chunk: u32, data: ?[*]const u8, data_len: usize, tags: ?[*]const u8, tags_len: usize) i32 {
    var call = Call.open();
    return call.close(chunkCheck(&call, bytesIn(key, key_len), chunk, bytesIn(data, data_len), bytesIn(tags, tags_len)));
}

fn reportMake(c: *Call, original: []const u8, kind: u8, stamp_ms: u64, device: u32, report: *GvBuffer) !void {
    const r = try Report.forOriginal(c.arena(), original, try kindIn(kind), stamp_ms, device);
    try c.give(report, try r.serialize(c.arena()));
}

pub export fn gv_report(original: ?[*]const u8, len: usize, kind: u8, stamp_ms: u64, device: u32, report: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(reportMake(&call, bytesIn(original, len), kind, stamp_ms, device, report));
}

pub const GvReportInfo = extern struct {
    stamp_ms: u64,
    device: u32,
    has_ratchet: u8,
    ratchet: [33]u8,
};

fn reportParse(_: *Call, report: []const u8, info: *GvReportInfo) !void {
    const r = try Report.parse(report);
    info.* = .{
        .stamp_ms = r.stamp_ms,
        .device = r.device,
        .has_ratchet = @intFromBool(r.ratchet != null),
        .ratchet = if (r.ratchet) |k| k.serialize() else mem.zeroes([33]u8),
    };
}

pub export fn gv_report_parse(report: ?[*]const u8, len: usize, info: *GvReportInfo) i32 {
    var call = Call.open();
    return call.close(reportParse(&call, bytesIn(report, len), info));
}

fn reportInBody(c: *Call, body: []const u8, report: *GvBuffer) !void {
    try c.give(report, try post_content.reportIn(body));
}

pub export fn gv_report_in_body(body: ?[*]const u8, len: usize, report: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(reportInBody(&call, bytesIn(body, len), report));
}

fn plainFromReport(c: *Call, report: []const u8, plain: *GvBuffer) !void {
    try c.give(plain, try post_content.fromReport(c.arena(), report));
}

pub export fn gv_plain_from_report(report: ?[*]const u8, len: usize, plain: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(plainFromReport(&call, bytesIn(report, len), plain));
}

fn plainBody(c: *Call, plain: []const u8, body: *GvBuffer) !void {
    const p = try post_content.Plain.parse(c.arena(), plain);
    try c.give(body, p.body);
}

pub export fn gv_plain_body(plain: ?[*]const u8, len: usize, body: *GvBuffer) i32 {
    var call = Call.open();
    return call.close(plainBody(&call, bytesIn(plain, len), body));
}

//! The post-quantum ratchet as the session sees it: a serialised state in,
//! a packet and a key out on send, a key out on receive, the new state back.
const std = @import("std");
const codec = @import("../../wire/codec.zig");
const stream = @import("stream.zig");
const braid = @import("braid.zig");
const packet = @import("packet.zig");
const mem = std.mem;
const Allocator = mem.Allocator;

pub const Side = stream.Side;
pub const Limits = stream.Limits;
pub const RatchetError = error{ BadRecord, BadPacket, VersionMismatch, MinimumVersion, NoStream } || stream.StreamError || braid.BraidError;

pub const Sent = struct { state: []u8, packet: []u8, key: ?[32]u8 };
pub const Received = struct { state: []u8, key: ?[32]u8 };

const Terms = struct {
    auth_key: []const u8,
    side: Side,
    min_version: u8,
    limits: Limits,
};

const Record = struct {
    terms: ?Terms = null,
    stream: ?[]const u8 = null,
    braid: ?[]const u8 = null,
};

fn parseRecord(data: []const u8) RatchetError!Record {
    var out: Record = .{};
    var r = codec.Reader.init(data);
    while (r.next() catch return RatchetError.BadRecord) |f| switch (f.number) {
        1 => {
            var t: Terms = .{ .auth_key = &.{}, .side = .initiator, .min_version = 0, .limits = .{} };
            var inner = codec.Reader.init(f.bytes() orelse return RatchetError.BadRecord);
            while (inner.next() catch return RatchetError.BadRecord) |g| switch (g.number) {
                1 => t.auth_key = g.bytes() orelse &.{},
                2 => t.side = if ((g.uint() orelse 0) == 1) .responder else .initiator,
                3 => t.min_version = @intCast(g.uint() orelse 0),
                4 => {
                    var lim = codec.Reader.init(g.bytes() orelse return RatchetError.BadRecord);
                    while (lim.next() catch return RatchetError.BadRecord) |h| switch (h.number) {
                        1 => t.limits.max_jump = std.math.cast(u32, h.uint() orelse 0) orelse return RatchetError.BadRecord,
                        2 => t.limits.max_skipped = std.math.cast(u32, h.uint() orelse 0) orelse return RatchetError.BadRecord,
                        else => {},
                    };
                },
                else => {},
            };
            out.terms = t;
        },
        2 => out.stream = f.bytes(),
        3 => out.braid = f.bytes(),
        else => {},
    };
    return out;
}

fn writeTerms(w: *codec.Writer, t: Terms) !void {
    var inner = codec.Writer.init(w.allocator);
    defer inner.deinit();
    try inner.bytesIfSet(1, t.auth_key);
    try inner.uintIfSet(2, @intFromEnum(t.side));
    try inner.uintIfSet(3, t.min_version);
    var lim = codec.Writer.init(w.allocator);
    defer lim.deinit();
    try lim.uintIfSet(1, t.limits.max_jump);
    try lim.uintIfSet(2, t.limits.max_skipped);
    try inner.embed(4, &lim);
    try w.embed(1, &inner);
}

fn writeRecord(allocator: Allocator, terms: ?Terms, s: ?*const stream.Stream, b: *const braid.Braid) ![]u8 {
    var w = codec.Writer.init(allocator);
    defer w.deinit();
    if (terms) |t| try writeTerms(&w, t);
    if (s) |st| {
        var inner = codec.Writer.init(allocator);
        defer inner.deinit();
        try st.write(&inner);
        try w.embed(2, &inner);
    }
    var inner = codec.Writer.init(allocator);
    defer inner.deinit();
    try b.write(&inner);
    try w.embed(3, &inner);
    return w.finish();
}

/// The state before the first message: the braid's first state and the terms
/// the stream is opened from on the first send.
pub fn start(allocator: Allocator, auth_key: [32]u8, side: Side, limits: Limits) ![]u8 {
    var b = switch (side) {
        .initiator => braid.Braid.startInitiator(&auth_key),
        .responder => try braid.Braid.startResponder(&auth_key),
    };
    defer b.deinit(allocator);
    return writeRecord(allocator, .{ .auth_key = &auth_key, .side = side, .min_version = 1, .limits = limits }, null, &b);
}

fn streamOf(allocator: Allocator, rec: Record) RatchetError!stream.Stream {
    if (rec.stream) |bytes| return stream.Stream.read(allocator, bytes);
    const t = rec.terms orelse return RatchetError.NoStream;
    return stream.Stream.open(allocator, t.auth_key, t.side, t.limits);
}

fn nothing(allocator: Allocator) ![]u8 {
    return allocator.dupe(u8, &.{});
}

pub fn send(allocator: Allocator, state: []const u8) RatchetError!Sent {
    if (state.len == 0) return .{ .state = try nothing(allocator), .packet = try nothing(allocator), .key = null };
    const rec = try parseRecord(state);
    const braid_bytes = rec.braid orelse return .{ .state = try nothing(allocator), .packet = try nothing(allocator), .key = null };
    var b = try braid.Braid.read(allocator, braid_bytes);
    defer b.deinit(allocator);
    const sent = try b.send(allocator);
    var s = try streamOf(allocator, rec);
    defer s.deinit(allocator);
    if (sent.secret) |k| try s.nextEpoch(allocator, k.epoch, &k.secret);
    const produced = try s.keyToSend(allocator, sent.packet.epoch - 1);
    const bytes = try sent.packet.serialize(allocator, produced.index);
    errdefer allocator.free(bytes);
    const out = try writeRecord(allocator, rec.terms, &s, &b);
    return .{ .state = out, .packet = bytes, .key = produced.key };
}

pub fn receive(allocator: Allocator, state: []const u8, packet_bytes: []const u8) RatchetError!Received {
    if (state.len == 0) return .{ .state = try nothing(allocator), .key = null };
    const rec = try parseRecord(state);
    if (packet_bytes.len == 0) {
        if (rec.braid == null) return .{ .state = try nothing(allocator), .key = null };
        const t = rec.terms orelse return RatchetError.VersionMismatch;
        if (t.min_version > 0) return RatchetError.MinimumVersion;
        return .{ .state = try nothing(allocator), .key = null };
    }
    if (packet_bytes[0] != 1) return RatchetError.BadPacket;
    const braid_bytes = rec.braid orelse return .{ .state = try nothing(allocator), .key = null };
    const parsed = try packet.Packet.parse(packet_bytes);
    var b = try braid.Braid.read(allocator, braid_bytes);
    defer b.deinit(allocator);
    const secret = try b.receive(allocator, parsed.packet);
    var s = try streamOf(allocator, rec);
    defer s.deinit(allocator);
    if (secret) |k| try s.nextEpoch(allocator, k.epoch, &k.secret);
    const epoch = parsed.packet.epoch - 1;
    const key: ?[32]u8 = if (epoch == 0 and parsed.index == 0) null else try s.keyToReceive(allocator, epoch, parsed.index);
    const out = try writeRecord(allocator, null, &s, &b);
    return .{ .state = out, .key = key };
}

test "both sides derive the same per-message keys across a long exchange" {
    const a = std.testing.allocator;
    const auth_key = [_]u8{0x5A} ** 32;
    var alice = try start(a, auth_key, .initiator, .{});
    defer a.free(alice);
    var bob = try start(a, auth_key, .responder, .{});
    defer a.free(bob);
    var round: usize = 0;
    while (round < 120) : (round += 1) {
        const s = try send(a, alice);
        defer a.free(s.packet);
        a.free(alice);
        alice = s.state;
        const r = try receive(a, bob, s.packet);
        a.free(bob);
        bob = r.state;
        try std.testing.expectEqualSlices(u8, &s.key.?, &r.key.?);
        const s2 = try send(a, bob);
        defer a.free(s2.packet);
        a.free(bob);
        bob = s2.state;
        const r2 = try receive(a, alice, s2.packet);
        a.free(alice);
        alice = r2.state;
        try std.testing.expectEqualSlices(u8, &s2.key.?, &r2.key.?);
    }
    const rec = try parseRecord(alice);
    var s = try stream.Stream.read(a, rec.stream.?);
    defer s.deinit(a);
    try std.testing.expect(s.epoch >= 2);
}

test "a burst one way, then replies, with reordering" {
    const a = std.testing.allocator;
    const auth_key = [_]u8{0x11} ** 32;
    var alice = try start(a, auth_key, .initiator, .{});
    defer a.free(alice);
    var bob = try start(a, auth_key, .responder, .{});
    defer a.free(bob);
    var packets: [50][]u8 = undefined;
    var keys: [50]?[32]u8 = undefined;
    for (&packets, &keys) |*p, *k| {
        const s = try send(a, alice);
        a.free(alice);
        alice = s.state;
        p.* = s.packet;
        k.* = s.key;
    }
    defer for (packets) |p| a.free(p);
    var order: [50]usize = undefined;
    for (&order, 0..) |*o, i| o.* = (i * 37 + 11) % 50;
    for (order) |i| {
        const r = try receive(a, bob, packets[i]);
        a.free(bob);
        bob = r.state;
        try std.testing.expectEqualSlices(u8, &keys[i].?, &r.key.?);
    }
    var round: usize = 0;
    while (round < 60) : (round += 1) {
        const s = try send(a, bob);
        defer a.free(s.packet);
        a.free(bob);
        bob = s.state;
        const r = try receive(a, alice, s.packet);
        a.free(alice);
        alice = r.state;
        try std.testing.expectEqualSlices(u8, &s.key.?, &r.key.?);
        const s2 = try send(a, alice);
        defer a.free(s2.packet);
        a.free(alice);
        alice = s2.state;
        const r2 = try receive(a, bob, s2.packet);
        a.free(bob);
        bob = r2.state;
        try std.testing.expectEqualSlices(u8, &s2.key.?, &r2.key.?);
    }
}

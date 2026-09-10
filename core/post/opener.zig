//! The first message of a session: the handshake material wrapped around a
//! ratchet message, so the responder can open the session and the message.
const std = @import("std");
const curve = @import("../keys/curve.zig");
const codec = @import("../wire/codec.zig");
const frame = @import("../wire/frame.zig");
const Fault = @import("../fault.zig").Fault;
const mem = std.mem;
const Allocator = mem.Allocator;

pub const Opener = struct {
    version: u8,
    registration_id: u32,
    one_time_id: ?u32,
    signed_id: u32,
    pq_id: ?u32,
    capsule: ?[]const u8,
    base: curve.Public,
    identity: curve.Public,
    /// The inner ratchet message, still serialised.
    inner: []const u8,
    bytes: []u8,
    allocator: Allocator,

    pub fn deinit(o: *Opener) void {
        o.allocator.free(o.bytes);
        o.* = undefined;
    }

    pub const Wrap = struct {
        version: u8,
        registration_id: u32,
        one_time_id: ?u32,
        signed_id: u32,
        pq_id: u32,
        capsule: []const u8,
        base: curve.Public,
        identity: curve.Public,
        inner: []const u8,
    };

    pub fn wrap(allocator: Allocator, p: Wrap) !Opener {
        var w = codec.Writer.init(allocator);
        defer w.deinit();
        try w.buf.append(allocator, frame.versionByte(p.version & 0xF));
        if (p.one_time_id) |id| try w.uint(1, id);
        try w.bytes(2, &p.base.serialize());
        try w.bytes(3, &p.identity.serialize());
        try w.bytes(4, p.inner);
        try w.uint(5, p.registration_id);
        try w.uint(6, p.signed_id);
        try w.uint(7, p.pq_id);
        try w.bytes(8, p.capsule);
        const bytes = try w.finish();
        errdefer allocator.free(bytes);
        return parseOwned(allocator, bytes);
    }

    pub fn parse(allocator: Allocator, data: []const u8) !Opener {
        const copy = try allocator.dupe(u8, data);
        errdefer allocator.free(copy);
        return parseOwned(allocator, copy);
    }

    fn parseOwned(allocator: Allocator, bytes: []u8) !Opener {
        if (bytes.len < 1) return Fault.BadMessage;
        const version = try frame.messageVersion(bytes[0]);
        var o: Opener = .{ .version = version, .registration_id = 0, .one_time_id = null, .signed_id = 0, .pq_id = null, .capsule = null, .base = undefined, .identity = undefined, .inner = undefined, .bytes = bytes, .allocator = allocator };
        var base: ?curve.Public = null;
        var identity: ?curve.Public = null;
        var inner: ?[]const u8 = null;
        var signed_id: ?u32 = null;
        var r = codec.Reader.init(bytes[1..]);
        while (r.next() catch return Fault.BadMessage) |f| switch (f.number) {
            1 => o.one_time_id = std.math.cast(u32, f.uint() orelse return Fault.BadMessage) orelse return Fault.BadMessage,
            2 => base = try curve.Public.parse(f.bytes() orelse return Fault.BadMessage),
            3 => identity = try curve.Public.parse(f.bytes() orelse return Fault.BadMessage),
            4 => inner = f.bytes(),
            5 => o.registration_id = std.math.cast(u32, f.uint() orelse return Fault.BadMessage) orelse return Fault.BadMessage,
            6 => signed_id = std.math.cast(u32, f.uint() orelse return Fault.BadMessage) orelse return Fault.BadMessage,
            7 => o.pq_id = std.math.cast(u32, f.uint() orelse return Fault.BadMessage) orelse return Fault.BadMessage,
            8 => o.capsule = f.bytes(),
            else => {},
        };
        o.base = base orelse return Fault.BadMessage;
        o.identity = identity orelse return Fault.BadMessage;
        o.inner = inner orelse return Fault.BadMessage;
        o.signed_id = signed_id orelse return Fault.BadMessage;
        if ((o.pq_id == null) != (o.capsule == null)) return Fault.BadMessage;
        if (o.pq_id == null and version > frame.oldest_version) return Fault.BadMessage;
        return o;
    }
};

test "a current-version opener carries its capsule" {
    const a = std.testing.allocator;
    const base = try curve.Pair.generate();
    const id = try curve.Pair.generate();
    var o = try Opener.wrap(a, .{ .version = 4, .registration_id = 12, .one_time_id = 3, .signed_id = 1, .pq_id = 2, .capsule = "capsule", .base = base.public, .identity = id.public, .inner = "inner" });
    defer o.deinit();
    try std.testing.expectEqual(@as(u32, 12), o.registration_id);
    try std.testing.expectEqual(@as(?u32, 3), o.one_time_id);
    try std.testing.expectEqualStrings("capsule", o.capsule.?);
    try std.testing.expectEqualStrings("inner", o.inner);
    try std.testing.expectEqual(@as(u8, 0x44), o.bytes[0]);
}

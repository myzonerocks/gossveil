//! What a device keeps about one sender in a group: up to five members
//! (chains under signing keys), newest first, each with its skipped keys.
const std = @import("std");
const curve = @import("../keys/curve.zig");
const codec = @import("../wire/codec.zig");
const chain = @import("chain.zig");
const Fault = @import("../fault.zig").Fault;
const mem = std.mem;
const Allocator = mem.Allocator;

pub const max_members: usize = 5;
pub const max_skipped: usize = 2000;
pub const max_forward_jump: u32 = 25_000;
pub const current_version: u8 = 3;

pub const Member = struct {
    version: u32,
    chain_id: u32,
    link: chain.Link,
    signing: curve.Public,
    signing_secret: ?curve.Secret,
    skipped: std.ArrayList(chain.Yield) = .empty,

    pub fn deinit(m: *Member, allocator: Allocator) void {
        m.skipped.deinit(allocator);
    }

    pub fn keepSkipped(m: *Member, allocator: Allocator, y: chain.Yield) !void {
        try m.skipped.append(allocator, y);
        while (m.skipped.items.len > max_skipped) _ = m.skipped.orderedRemove(0);
    }

    pub fn takeSkipped(m: *Member, step: u32) ?chain.Yield {
        for (m.skipped.items, 0..) |y, i| if (y.step == step) return m.skipped.orderedRemove(i);
        return null;
    }

    fn write(m: Member, w: *codec.Writer) !void {
        try w.uintIfSet(1, m.chain_id);
        {
            var inner = codec.Writer.init(w.allocator);
            defer inner.deinit();
            try inner.uintIfSet(1, m.link.step);
            try inner.bytes(2, &m.link.seed);
            try w.embed(2, &inner);
        }
        {
            var inner = codec.Writer.init(w.allocator);
            defer inner.deinit();
            try inner.bytes(1, &m.signing.serialize());
            if (m.signing_secret) |s| try inner.bytes(2, &s.serialize());
            try w.embed(3, &inner);
        }
        for (m.skipped.items) |y| {
            var inner = codec.Writer.init(w.allocator);
            defer inner.deinit();
            try inner.uintIfSet(1, y.step);
            try inner.bytes(2, &y.seed);
            try w.embed(4, &inner);
        }
        try w.uintIfSet(5, m.version);
    }

    fn parse(allocator: Allocator, data: []const u8) !Member {
        var m: Member = .{ .version = 0, .chain_id = 0, .link = .{ .step = 0, .seed = mem.zeroes([32]u8) }, .signing = undefined, .signing_secret = null };
        errdefer m.deinit(allocator);
        var signing: ?curve.Public = null;
        var r = codec.Reader.init(data);
        while (r.next() catch return Fault.BadSession) |f| switch (f.number) {
            1 => m.chain_id = std.math.cast(u32, f.uint() orelse 0) orelse return Fault.BadSession,
            2 => {
                var inner = codec.Reader.init(f.bytes() orelse return Fault.BadSession);
                while (inner.next() catch return Fault.BadSession) |g| switch (g.number) {
                    1 => m.link.step = std.math.cast(u32, g.uint() orelse 0) orelse return Fault.BadSession,
                    2 => if (g.bytes()) |b| if (b.len == 32) {
                        m.link.seed = b[0..32].*;
                    },
                    else => {},
                };
            },
            3 => {
                var inner = codec.Reader.init(f.bytes() orelse return Fault.BadSession);
                while (inner.next() catch return Fault.BadSession) |g| switch (g.number) {
                    1 => signing = try curve.Public.parse(g.bytes() orelse return Fault.BadSession),
                    2 => if (g.bytes()) |b| if (b.len != 0) {
                        m.signing_secret = try curve.Secret.parse(b);
                    },
                    else => {},
                };
            },
            4 => {
                var y: chain.Yield = .{ .step = 0, .seed = mem.zeroes([32]u8) };
                var inner = codec.Reader.init(f.bytes() orelse return Fault.BadSession);
                while (inner.next() catch return Fault.BadSession) |g| switch (g.number) {
                    1 => y.step = std.math.cast(u32, g.uint() orelse 0) orelse return Fault.BadSession,
                    2 => if (g.bytes()) |b| if (b.len == 32) {
                        y.seed = b[0..32].*;
                    },
                    else => {},
                };
                try m.skipped.append(allocator, y);
            },
            5 => m.version = std.math.cast(u32, f.uint() orelse 0) orelse return Fault.BadSession,
            else => {},
        };
        m.signing = signing orelse return Fault.BadSession;
        return m;
    }
};

pub const Circle = struct {
    allocator: Allocator,
    /// Newest first.
    members: std.ArrayList(Member) = .empty,

    pub fn init(allocator: Allocator) Circle {
        return .{ .allocator = allocator };
    }

    pub fn deinit(c: *Circle) void {
        for (c.members.items) |*m| m.deinit(c.allocator);
        c.members.deinit(c.allocator);
        c.* = undefined;
    }

    pub fn newest(c: *Circle) ?*Member {
        return if (c.members.items.len == 0) null else &c.members.items[0];
    }

    pub fn byChain(c: *Circle, chain_id: u32) ?*Member {
        for (c.members.items) |*m| if (m.chain_id == chain_id) return m;
        return null;
    }

    /// A member for a chain already known keeps its keys; a chain id under a
    /// different signing key is replaced. The list holds the newest five.
    pub fn admit(c: *Circle, version: u32, chain_id: u32, step: u32, seed: [32]u8, signing: curve.Public, signing_secret: ?curve.Secret) !void {
        var kept: ?Member = null;
        var i: usize = 0;
        while (i < c.members.items.len) {
            const m = c.members.items[i];
            if (m.chain_id == chain_id) {
                if (kept == null and m.signing.eql(signing)) {
                    kept = c.members.orderedRemove(i);
                } else {
                    var dropped = c.members.orderedRemove(i);
                    dropped.deinit(c.allocator);
                }
            } else i += 1;
        }
        const member = kept orelse Member{ .version = version, .chain_id = chain_id, .link = .{ .step = step, .seed = seed }, .signing = signing, .signing_secret = signing_secret };
        while (c.members.items.len >= max_members) {
            var dropped = c.members.pop().?;
            dropped.deinit(c.allocator);
        }
        try c.members.insert(c.allocator, 0, member);
    }

    pub fn serialize(c: *const Circle, allocator: Allocator) ![]u8 {
        var w = codec.Writer.init(allocator);
        defer w.deinit();
        for (c.members.items) |m| {
            var inner = codec.Writer.init(allocator);
            defer inner.deinit();
            try m.write(&inner);
            try w.embed(1, &inner);
        }
        return w.finish();
    }

    pub fn parse(allocator: Allocator, data: []const u8) !Circle {
        var c = init(allocator);
        errdefer c.deinit();
        var r = codec.Reader.init(data);
        while (r.next() catch return Fault.BadSession) |f| {
            if (f.number != 1) continue;
            var m = try Member.parse(allocator, f.bytes() orelse return Fault.BadSession);
            errdefer m.deinit(allocator);
            try c.members.append(allocator, m);
        }
        return c;
    }
};

test "the circle keeps five members and replaces a chain under a new key" {
    const a = std.testing.allocator;
    var c = Circle.init(a);
    defer c.deinit();
    const key = try curve.Pair.generate();
    var i: u32 = 0;
    while (i < 7) : (i += 1) try c.admit(3, i, 0, [_]u8{1} ** 32, key.public, null);
    try std.testing.expectEqual(@as(usize, 5), c.members.items.len);
    try std.testing.expectEqual(@as(u32, 6), c.newest().?.chain_id);
    const other = try curve.Pair.generate();
    try c.admit(3, 6, 9, [_]u8{2} ** 32, other.public, null);
    try std.testing.expectEqual(@as(u32, 9), c.byChain(6).?.link.step);
    const bytes = try c.serialize(a);
    defer a.free(bytes);
    var back = try Circle.parse(a, bytes);
    defer back.deinit();
    try std.testing.expect(back.byChain(6).?.signing.eql(other.public));
}

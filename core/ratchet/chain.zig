//! A symmetric chain and the message keys it yields. A skipped key is kept as
//! its seed so the post-quantum ratchet key can be mixed in when the message
//! arrives; records written before that scheme carry the derived keys.
const std = @import("std");
const derive = @import("../keys/derive.zig");

pub const Chain = struct {
    key: [32]u8,
    index: u32,

    pub fn advance(c: Chain) Chain {
        return .{ .key = derive.chainNext(c.key), .index = c.index + 1 };
    }

    pub fn slot(c: Chain) Slot {
        return .{ .seed = .{ .seed = derive.chainSeed(c.key), .index = c.index } };
    }
};

pub const MessageKeys = struct {
    cipher: [32]u8,
    mac: [32]u8,
    iv: [16]u8,
    index: u32,
};

pub const Slot = union(enum) {
    seed: struct { seed: [32]u8, index: u32 },
    keys: MessageKeys,

    pub fn index(s: Slot) u32 {
        return switch (s) {
            .seed => |v| v.index,
            .keys => |k| k.index,
        };
    }

    pub fn open(s: Slot, pq_key: ?[32]u8) MessageKeys {
        switch (s) {
            .seed => |v| {
                const m = derive.messageKeys(v.seed, pq_key);
                return .{ .cipher = m.cipher, .mac = m.mac, .iv = m.iv, .index = v.index };
            },
            .keys => |k| return k,
        }
    }
};

test "advancing a chain moves its index and changes its key" {
    const c = Chain{ .key = [_]u8{1} ** 32, .index = 4 };
    const n = c.advance();
    try std.testing.expectEqual(@as(u32, 5), n.index);
    try std.testing.expect(!std.mem.eql(u8, &c.key, &n.key));
    try std.testing.expectEqual(@as(u32, 4), c.slot().index());
    try std.testing.expectEqual(@as(u32, 4), c.slot().open(null).index);
}

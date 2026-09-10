//! A member's chain in a group: a seed that steps per message and the
//! message key each step yields.
const std = @import("std");
const derive = @import("../keys/derive.zig");

pub const Link = struct {
    step: u32,
    seed: [32]u8,

    pub fn advance(l: Link) Link {
        return .{ .step = l.step + 1, .seed = derive.chainNext(l.seed) };
    }

    pub fn yield(l: Link) Yield {
        return .{ .step = l.step, .seed = derive.chainSeed(l.seed) };
    }
};

pub const Yield = struct {
    step: u32,
    seed: [32]u8,

    pub fn keys(y: Yield) derive.CircleKeys {
        return derive.circleKeys(y.seed);
    }
};

test "a link advances and yields distinct keys" {
    const l = Link{ .step = 0, .seed = [_]u8{4} ** 32 };
    const n = l.advance();
    try std.testing.expectEqual(@as(u32, 1), n.step);
    try std.testing.expect(!std.mem.eql(u8, &l.yield().keys().cipher, &n.yield().keys().cipher));
}

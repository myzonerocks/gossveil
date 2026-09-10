//! A decryption report: tells a sender which message failed to open so it
//! can resend, carrying the ratchet key of the original when it had one.
const std = @import("std");
const curve = @import("../keys/curve.zig");
const codec = @import("../wire/codec.zig");
const Kind = @import("../ratchet/engine.zig").Kind;
const Whisper = @import("whisper.zig").Whisper;
const Opener = @import("opener.zig").Opener;
const content = @import("content.zig");
const Fault = @import("../fault.zig").Fault;
const mem = std.mem;

pub const Report = struct {
    ratchet: ?curve.Public,
    stamp_ms: u64,
    device: u32,

    pub fn forOriginal(allocator: mem.Allocator, original: []const u8, kind: Kind, stamp_ms: u64, device: u32) !Report {
        var ratchet: ?curve.Public = null;
        switch (kind) {
            .whisper => {
                var w = try Whisper.parse(allocator, original);
                defer w.deinit();
                ratchet = w.ratchet;
            },
            .first => {
                var o = try Opener.parse(allocator, original);
                defer o.deinit();
                var w = try Whisper.parse(allocator, o.inner);
                defer w.deinit();
                ratchet = w.ratchet;
            },
            .circle, .plain => {},
        }
        return .{ .ratchet = ratchet, .stamp_ms = stamp_ms, .device = device };
    }

    pub fn serialize(r: Report, allocator: mem.Allocator) ![]u8 {
        var w = codec.Writer.init(allocator);
        defer w.deinit();
        if (r.ratchet) |k| try w.bytes(1, &k.serialize());
        try w.uint(2, r.stamp_ms);
        try w.uint(3, r.device);
        return w.finish();
    }

    pub fn parse(data: []const u8) !Report {
        var out: Report = .{ .ratchet = null, .stamp_ms = 0, .device = 0 };
        var r = codec.Reader.init(data);
        while (r.next() catch return Fault.BadMessage) |f| switch (f.number) {
            1 => out.ratchet = try curve.Public.parse(f.bytes() orelse return Fault.BadMessage),
            2 => out.stamp_ms = f.uint() orelse return Fault.BadMessage,
            3 => out.device = std.math.cast(u32, f.uint() orelse return Fault.BadMessage) orelse return Fault.BadMessage,
            else => {},
        };
        return out;
    }

    /// The report framed inside a content body.
    pub fn fromContentBody(body: []const u8) !Report {
        return parse(try content.reportIn(body));
    }
};

test "a report round trips with and without a ratchet key" {
    const a = std.testing.allocator;
    const pair = try curve.Pair.generate();
    const with = Report{ .ratchet = pair.public, .stamp_ms = 1_700_000_000, .device = 1 };
    const bytes = try with.serialize(a);
    defer a.free(bytes);
    const back = try Report.parse(bytes);
    try std.testing.expect(back.ratchet.?.eql(pair.public));
    try std.testing.expectEqual(@as(u64, 1_700_000_000), back.stamp_ms);
    const without = try Report.forOriginal(a, &[_]u8{ 1, 2, 3 }, .circle, 5, 2);
    try std.testing.expect(without.ratchet == null);
    const framed = try content.fromReport(a, bytes);
    defer a.free(framed);
    try std.testing.expectEqual(@as(u32, 1), (try Report.fromContentBody(framed[1..])).device);
}

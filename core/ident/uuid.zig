//! A sixteen-byte identifier with its hyphenated text form.
const std = @import("std");
const entropy = @import("../entropy.zig");
const Fault = @import("../fault.zig").Fault;

pub const text_length = 36;

pub const Uuid = struct {
    bytes: [16]u8,

    pub fn random() Uuid {
        var b = entropy.array(16);
        b[6] = (b[6] & 0x0F) | 0x40;
        b[8] = (b[8] & 0x3F) | 0x80;
        return .{ .bytes = b };
    }

    pub fn fromBytes(b: [16]u8) Uuid {
        return .{ .bytes = b };
    }

    pub fn eql(a: Uuid, b: Uuid) bool {
        return std.mem.eql(u8, &a.bytes, &b.bytes);
    }

    pub fn parse(source: []const u8) Fault!Uuid {
        if (source.len != text_length) return Fault.BadText;
        for ([_]usize{ 8, 13, 18, 23 }) |i| if (source[i] != '-') return Fault.BadText;
        var out: [16]u8 = undefined;
        var src: usize = 0;
        for (&out) |*byte| {
            if (src == 8 or src == 13 or src == 18 or src == 23) src += 1;
            const hi = std.fmt.charToDigit(source[src], 16) catch return Fault.BadText;
            const lo = std.fmt.charToDigit(source[src + 1], 16) catch return Fault.BadText;
            byte.* = (hi << 4) | lo;
            src += 2;
        }
        return .{ .bytes = out };
    }

    pub fn format(u: Uuid, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        const b = u.bytes;
        try writer.print(
            "{x:0>2}{x:0>2}{x:0>2}{x:0>2}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}",
            .{ b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15] },
        );
    }

    pub fn text(u: Uuid) [text_length]u8 {
        var out: [text_length]u8 = undefined;
        _ = std.fmt.bufPrint(&out, "{f}", .{u}) catch unreachable;
        return out;
    }
};

test "a random id is version four and round trips through text" {
    const u = Uuid.random();
    try std.testing.expectEqual(@as(u8, 0x40), u.bytes[6] & 0xF0);
    try std.testing.expect(Uuid.eql(u, try Uuid.parse(&u.text())));
    try std.testing.expectError(Fault.BadText, Uuid.parse("not-a-uuid"));
}

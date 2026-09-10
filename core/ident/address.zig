//! Where a message goes: a name (an account id for deployed clients, any text
//! for tests) and a device number. The name is borrowed from the caller.
const std = @import("std");
const mem = std.mem;

pub const Address = struct {
    name: []const u8,
    device: u32,

    pub fn eql(a: Address, b: Address) bool {
        return a.device == b.device and mem.eql(u8, a.name, b.name);
    }

    pub fn format(a: Address, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print("{s}.{d}", .{ a.name, a.device });
    }
};

test "addresses compare by name and device" {
    const a = Address{ .name = "alice", .device = 1 };
    try std.testing.expect(a.eql(.{ .name = "alice", .device = 1 }));
    try std.testing.expect(!a.eql(.{ .name = "alice", .device = 2 }));
    var buf: [16]u8 = undefined;
    try std.testing.expectEqualStrings("alice.1", try std.fmt.bufPrint(&buf, "{f}", .{a}));
}

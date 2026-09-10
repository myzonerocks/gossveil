//! Plain content: a service message that travels unencrypted inside an
//! envelope, framed by an identifier byte and a padding boundary byte.
const std = @import("std");
const codec = @import("../wire/codec.zig");
const Fault = @import("../fault.zig").Fault;
const mem = std.mem;

pub const identifier_byte: u8 = 0xC0;
pub const boundary_byte: u8 = 0x80;
const report_field: u32 = 8;

pub const Plain = struct {
    /// Everything after the identifier byte, padding included.
    body: []const u8,
    bytes: []u8,
    allocator: mem.Allocator,

    pub fn deinit(p: *Plain) void {
        p.allocator.free(p.bytes);
        p.* = undefined;
    }

    pub fn parse(allocator: mem.Allocator, data: []const u8) !Plain {
        if (data.len < 2 or data[0] != identifier_byte) return Fault.BadMessage;
        const copy = try allocator.dupe(u8, data);
        return .{ .body = copy[1..], .bytes = copy, .allocator = allocator };
    }
};

/// Frames a serialised report as content.
pub fn fromReport(allocator: mem.Allocator, report: []const u8) ![]u8 {
    var w = codec.Writer.init(allocator);
    defer w.deinit();
    try w.buf.append(allocator, identifier_byte);
    try w.bytes(report_field, report);
    try w.buf.append(allocator, boundary_byte);
    return w.finish();
}

/// The report inside a content body, padding stripped.
pub fn reportIn(body: []const u8) Fault![]const u8 {
    const boundary = mem.lastIndexOfScalar(u8, body, boundary_byte) orelse return Fault.BadMessage;
    var r = codec.Reader.init(body[0..boundary]);
    while (r.next() catch return Fault.BadMessage) |f| {
        if (f.number == report_field) if (f.bytes()) |b| return b;
    }
    return Fault.BadMessage;
}

test "content frames a report and gives it back" {
    const a = std.testing.allocator;
    const framed = try fromReport(a, "report bytes");
    defer a.free(framed);
    try std.testing.expectEqual(identifier_byte, framed[0]);
    try std.testing.expectEqual(boundary_byte, framed[framed.len - 1]);
    var plain = try Plain.parse(a, framed);
    defer plain.deinit();
    try std.testing.expectEqualStrings("report bytes", try reportIn(plain.body));
}

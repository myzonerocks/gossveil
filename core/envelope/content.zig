//! What an envelope carries: the kind of the inner message, the sender's
//! certificate, the message itself, a hint about resending, and the group it
//! belongs to when it belongs to one.
const std = @import("std");
const codec = @import("../wire/codec.zig");
const Kind = @import("../ratchet/engine.zig").Kind;
const SenderCert = @import("certificate.zig").SenderCert;
const Fault = @import("../fault.zig").Fault;
const mem = std.mem;
const Allocator = mem.Allocator;

pub const Hint = enum(u8) {
    default = 0,
    resendable = 1,
    implicit = 2,
    _,
};

/// The record numbers a first message as one; everywhere else it is three.
fn kindToRecord(k: Kind) u64 {
    return switch (k) {
        .first => 1,
        .whisper => 2,
        .circle => 7,
        .plain => 8,
    };
}

fn kindFromRecord(v: u64) Fault!Kind {
    return switch (v) {
        1 => .first,
        2 => .whisper,
        7 => .circle,
        8 => .plain,
        else => Fault.BadMessage,
    };
}

pub const Content = struct {
    kind: Kind,
    sender: SenderCert,
    body: []const u8,
    hint: Hint,
    circle_id: ?[]const u8,
    bytes: []u8,
    allocator: Allocator,

    pub fn deinit(c: *Content) void {
        c.sender.deinit();
        c.allocator.free(c.bytes);
        c.* = undefined;
    }

    pub fn make(allocator: Allocator, kind: Kind, sender: *const SenderCert, body: []const u8, hint: Hint, circle_id: ?[]const u8) !Content {
        var w = codec.Writer.init(allocator);
        defer w.deinit();
        try w.uint(1, kindToRecord(kind));
        try w.bytes(2, sender.bytes);
        try w.bytes(3, body);
        if (hint != .default) try w.uint(4, @intFromEnum(hint));
        if (circle_id) |g| try w.bytes(5, g);
        const bytes = try w.finish();
        errdefer allocator.free(bytes);
        return parseOwned(allocator, bytes);
    }

    pub fn parse(allocator: Allocator, data: []const u8) !Content {
        const copy = try allocator.dupe(u8, data);
        errdefer allocator.free(copy);
        return parseOwned(allocator, copy);
    }

    fn parseOwned(allocator: Allocator, bytes: []u8) !Content {
        var kind: ?Kind = null;
        var sender: ?[]const u8 = null;
        var body: ?[]const u8 = null;
        var hint: Hint = .default;
        var circle_id: ?[]const u8 = null;
        var r = codec.Reader.init(bytes);
        while (r.next() catch return Fault.BadMessage) |f| switch (f.number) {
            1 => kind = try kindFromRecord(f.uint() orelse return Fault.BadMessage),
            2 => sender = f.bytes(),
            3 => body = f.bytes(),
            4 => hint = @enumFromInt(@as(u8, @truncate(f.uint() orelse 0))),
            5 => circle_id = f.bytes(),
            else => {},
        };
        return .{
            .kind = kind orelse return Fault.BadMessage,
            .sender = try SenderCert.parse(allocator, sender orelse return Fault.BadMessage),
            .body = body orelse return Fault.BadMessage,
            .hint = hint,
            .circle_id = circle_id,
            .bytes = bytes,
            .allocator = allocator,
        };
    }
};

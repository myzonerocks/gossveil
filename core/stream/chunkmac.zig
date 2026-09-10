//! Chunked authentication of a stream: one MAC per fixed-size chunk, the last
//! chunk zero-padded, so a download checks as it arrives.
const std = @import("std");
const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
const Fault = @import("../fault.zig").Fault;
const mem = std.mem;

pub const mac_length = 32;
pub const default_chunk = 256 * 1024;

pub fn chunkCount(total: usize, chunk: usize) usize {
    return if (total == 0) 0 else (total + chunk - 1) / chunk;
}

pub fn macBytesFor(total: usize, chunk: usize) usize {
    return chunkCount(total, chunk) * mac_length;
}

/// The sender's side: feed data, then take every chunk's MAC.
pub const Tagger = struct {
    key: [32]u8,
    chunk: usize,
    buf: []u8,
    filled: usize,
    macs: std.ArrayList(u8),
    allocator: mem.Allocator,

    pub fn init(allocator: mem.Allocator, key: [32]u8, chunk: usize) !Tagger {
        return .{ .key = key, .chunk = chunk, .buf = try allocator.alloc(u8, chunk), .filled = 0, .macs = .empty, .allocator = allocator };
    }

    pub fn deinit(t: *Tagger) void {
        t.allocator.free(t.buf);
        t.macs.deinit(t.allocator);
    }

    pub fn update(t: *Tagger, data: []const u8) !void {
        var rest = data;
        while (rest.len > 0) {
            const take = @min(t.chunk - t.filled, rest.len);
            @memcpy(t.buf[t.filled .. t.filled + take], rest[0..take]);
            t.filled += take;
            rest = rest[take..];
            if (t.filled == t.chunk) try t.flush();
        }
    }

    /// The caller owns the returned MACs.
    pub fn finish(t: *Tagger) ![]u8 {
        if (t.filled > 0) try t.flush();
        return t.macs.toOwnedSlice(t.allocator);
    }

    fn flush(t: *Tagger) !void {
        @memset(t.buf[t.filled..], 0);
        var mac: [mac_length]u8 = undefined;
        Hmac.create(&mac, t.buf, &t.key);
        try t.macs.appendSlice(t.allocator, &mac);
        t.filled = 0;
    }
};

/// The receiver's side: feed data and fail on the first chunk that does not match.
pub const Checker = struct {
    key: [32]u8,
    chunk: usize,
    expected: []const u8,
    buf: []u8,
    filled: usize,
    index: usize,
    allocator: mem.Allocator,

    pub fn init(allocator: mem.Allocator, key: [32]u8, chunk: usize, expected: []const u8) !Checker {
        return .{ .key = key, .chunk = chunk, .expected = expected, .buf = try allocator.alloc(u8, chunk), .filled = 0, .index = 0, .allocator = allocator };
    }

    pub fn deinit(c: *Checker) void {
        c.allocator.free(c.buf);
    }

    pub fn update(c: *Checker, data: []const u8) !void {
        var rest = data;
        while (rest.len > 0) {
            const take = @min(c.chunk - c.filled, rest.len);
            @memcpy(c.buf[c.filled .. c.filled + take], rest[0..take]);
            c.filled += take;
            rest = rest[take..];
            if (c.filled == c.chunk) try c.check();
        }
    }

    pub fn finish(c: *Checker) !void {
        if (c.filled > 0) try c.check();
    }

    fn check(c: *Checker) !void {
        const at = c.index * mac_length;
        if (at + mac_length > c.expected.len) return Fault.BadMessage;
        @memset(c.buf[c.filled..], 0);
        var mac: [mac_length]u8 = undefined;
        Hmac.create(&mac, c.buf, &c.key);
        if (!std.crypto.timing_safe.eql([mac_length]u8, mac, c.expected[at..][0..mac_length].*)) return Fault.BadMessage;
        c.filled = 0;
        c.index += 1;
    }
};

test "tags round trip and a flipped byte is caught" {
    const a = std.testing.allocator;
    const key = [_]u8{0x42} ** 32;
    var tagger = try Tagger.init(a, key, 64);
    defer tagger.deinit();
    const data = [_]u8{0xAA} ** 100;
    try tagger.update(&data);
    const macs = try tagger.finish();
    defer a.free(macs);
    try std.testing.expectEqual(macBytesFor(100, 64), macs.len);
    var checker = try Checker.init(a, key, 64, macs);
    defer checker.deinit();
    try checker.update(&data);
    try checker.finish();
    var bad = data;
    bad[0] ^= 0xFF;
    var again = try Checker.init(a, key, 64, macs);
    defer again.deinit();
    try std.testing.expectError(Fault.BadMessage, again.update(&bad));
}

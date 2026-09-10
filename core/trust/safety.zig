//! Safety numbers: an iterated hash of an identity key and its stable
//! identifier, shown as sixty digits and exchanged as a scannable record.
const std = @import("std");
const identity = @import("../keys/identity.zig");
const curve = @import("../keys/curve.zig");
const codec = @import("../wire/codec.zig");
const Fault = @import("../fault.zig").Fault;
const Sha512 = std.crypto.hash.sha2.Sha512;
const mem = std.mem;

pub const display_length = 60;
const half_length = 30;

fn iterated(iterations: u32, stable_id: []const u8, key: [curve.serialized_length]u8) Fault![64]u8 {
    if (iterations <= 1 or iterations > 1_000_000) return Fault.BadArgument;
    var digest: [64]u8 = undefined;
    var h = Sha512.init(.{});
    h.update(&[_]u8{ 0, 0 });
    h.update(&key);
    h.update(stable_id);
    h.update(&key);
    h.final(&digest);
    var i: u32 = 1;
    while (i < iterations) : (i += 1) {
        var again = Sha512.init(.{});
        again.update(&digest);
        again.update(&key);
        again.final(&digest);
    }
    return digest;
}

fn digits(half: *const [half_length]u8) [half_length]u8 {
    var out: [half_length]u8 = undefined;
    var block: usize = 0;
    while (block < 6) : (block += 1) {
        var x: u64 = 0;
        for (half[block * 5 ..][0..5]) |b| x = (x << 8) | b;
        x %= 100_000;
        const slot = out[block * 5 ..][0..5];
        var d: usize = 5;
        while (d > 0) : (d -= 1) {
            slot[d - 1] = @intCast('0' + x % 10);
            x /= 10;
        }
    }
    return out;
}

pub const Display = struct {
    text: [display_length]u8,

    pub fn of(local: *const [64]u8, remote: *const [64]u8) Display {
        const l = digits(local[0..half_length]);
        const r = digits(remote[0..half_length]);
        var out: [display_length]u8 = undefined;
        if (mem.lessThan(u8, &l, &r)) {
            out[0..30].* = l;
            out[30..].* = r;
        } else {
            out[0..30].* = r;
            out[30..].* = l;
        }
        return .{ .text = out };
    }

    pub fn eql(a: Display, b: Display) bool {
        return std.crypto.timing_safe.eql([display_length]u8, a.text, b.text);
    }
};

pub const Scannable = struct {
    version: u32,
    local: [32]u8,
    remote: [32]u8,

    pub fn serialize(s: Scannable, allocator: mem.Allocator) ![]u8 {
        var w = codec.Writer.init(allocator);
        defer w.deinit();
        try w.uint(1, s.version);
        var local = codec.Writer.init(allocator);
        defer local.deinit();
        try local.bytes(1, &s.local);
        try w.embed(2, &local);
        var remote = codec.Writer.init(allocator);
        defer remote.deinit();
        try remote.bytes(1, &s.remote);
        try w.embed(3, &remote);
        return w.finish();
    }

    pub fn parse(data: []const u8) !Scannable {
        var out: Scannable = .{ .version = 0, .local = undefined, .remote = undefined };
        var have_local = false;
        var have_remote = false;
        var r = codec.Reader.init(data);
        while (r.next() catch return Fault.BadMessage) |f| switch (f.number) {
            1 => out.version = std.math.cast(u32, f.uint() orelse return Fault.BadMessage) orelse return Fault.BadMessage,
            2, 3 => {
                const half = try inner(f.bytes() orelse return Fault.BadMessage);
                if (f.number == 2) {
                    out.local = half;
                    have_local = true;
                } else {
                    out.remote = half;
                    have_remote = true;
                }
            },
            else => {},
        };
        if (!have_local or !have_remote) return Fault.BadMessage;
        return out;
    }

    fn inner(data: []const u8) Fault![32]u8 {
        var r = codec.Reader.init(data);
        while (r.next() catch return Fault.BadMessage) |f| {
            if (f.number == 1) if (f.bytes()) |b| {
                if (b.len < 32) return Fault.BadMessage;
                return b[0..32].*;
            };
        }
        return Fault.BadMessage;
    }

    /// Whether the other party's record describes the same pair of keys.
    pub fn matches(s: Scannable, theirs_bytes: []const u8) !bool {
        const theirs = try parse(theirs_bytes);
        if (theirs.version != s.version) return Fault.BadArgument;
        const a = std.crypto.timing_safe.eql([32]u8, theirs.local, s.remote);
        const b = std.crypto.timing_safe.eql([32]u8, theirs.remote, s.local);
        return a and b;
    }
};

pub const Safety = struct {
    display: Display,
    scannable: Scannable,

    pub fn of(version: u32, iterations: u32, local_id: []const u8, local: identity.Identity, remote_id: []const u8, remote: identity.Identity) Fault!Safety {
        const l = try iterated(iterations, local_id, local.serialize());
        const r = try iterated(iterations, remote_id, remote.serialize());
        return .{
            .display = Display.of(&l, &r),
            .scannable = .{ .version = version, .local = l[0..32].*, .remote = r[0..32].* },
        };
    }
};

test "both parties render the same digits and matching records" {
    const a = std.testing.allocator;
    const alice = try identity.IdentityPair.generate();
    const bob = try identity.IdentityPair.generate();
    const ours = try Safety.of(2, 1024, "+14152222222", alice.identity, "+14153333333", bob.identity);
    const theirs = try Safety.of(2, 1024, "+14153333333", bob.identity, "+14152222222", alice.identity);
    try std.testing.expect(ours.display.eql(theirs.display));
    const their_bytes = try theirs.scannable.serialize(a);
    defer a.free(their_bytes);
    try std.testing.expect(try ours.scannable.matches(their_bytes));
    try std.testing.expectError(Fault.BadArgument, Safety.of(2, 1, "a", alice.identity, "b", bob.identity));
}

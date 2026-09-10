//! The two group messages: the announcement that hands members a sender's
//! chain and signing key, and the note carrying one sealed message under
//! that sender's signature.
const std = @import("std");
const curve = @import("../keys/curve.zig");
const codec = @import("../wire/codec.zig");
const Fault = @import("../fault.zig").Fault;
const mem = std.mem;
const Allocator = mem.Allocator;

pub const version: u8 = 3;

fn versionOf(byte: u8) Fault!u8 {
    const v = byte >> 4;
    if (v < version) return Fault.LegacyVersion;
    if (v > version) return Fault.UnknownVersion;
    return v;
}

pub const Announce = struct {
    version: u8,
    circle_id: [16]u8,
    chain_id: u32,
    step: u32,
    seed: [32]u8,
    signing: curve.Public,
    bytes: []u8,
    allocator: Allocator,

    pub fn deinit(m: *Announce) void {
        m.allocator.free(m.bytes);
        m.* = undefined;
    }

    pub fn make(allocator: Allocator, v: u8, circle_id: [16]u8, chain_id: u32, step: u32, seed: [32]u8, signing: curve.Public) !Announce {
        var w = codec.Writer.init(allocator);
        defer w.deinit();
        try w.buf.append(allocator, ((v & 0xF) << 4) | version);
        try w.bytes(1, &circle_id);
        try w.uint(2, chain_id);
        try w.uint(3, step);
        try w.bytes(4, &seed);
        try w.bytes(5, &signing.serialize());
        const bytes = try w.finish();
        errdefer allocator.free(bytes);
        return parseOwned(allocator, bytes);
    }

    pub fn parse(allocator: Allocator, data: []const u8) !Announce {
        const copy = try allocator.dupe(u8, data);
        errdefer allocator.free(copy);
        return parseOwned(allocator, copy);
    }

    fn parseOwned(allocator: Allocator, bytes: []u8) !Announce {
        if (bytes.len < 1) return Fault.BadMessage;
        const v = try versionOf(bytes[0]);
        var circle_id: ?[16]u8 = null;
        var chain_id: ?u32 = null;
        var step: ?u32 = null;
        var seed: ?[32]u8 = null;
        var signing: ?curve.Public = null;
        var r = codec.Reader.init(bytes[1..]);
        while (r.next() catch return Fault.BadMessage) |f| switch (f.number) {
            1 => {
                const b = f.bytes() orelse return Fault.BadMessage;
                if (b.len != 16) return Fault.BadMessage;
                circle_id = b[0..16].*;
            },
            2 => chain_id = std.math.cast(u32, f.uint() orelse return Fault.BadMessage) orelse return Fault.BadMessage,
            3 => step = std.math.cast(u32, f.uint() orelse return Fault.BadMessage) orelse return Fault.BadMessage,
            4 => {
                const b = f.bytes() orelse return Fault.BadMessage;
                if (b.len != 32) return Fault.BadMessage;
                seed = b[0..32].*;
            },
            5 => signing = try curve.Public.parse(f.bytes() orelse return Fault.BadMessage),
            else => {},
        };
        return .{
            .version = v,
            .circle_id = circle_id orelse return Fault.BadMessage,
            .chain_id = chain_id orelse return Fault.BadMessage,
            .step = step orelse return Fault.BadMessage,
            .seed = seed orelse return Fault.BadMessage,
            .signing = signing orelse return Fault.BadMessage,
            .bytes = bytes,
            .allocator = allocator,
        };
    }
};

pub const Note = struct {
    version: u8,
    circle_id: [16]u8,
    chain_id: u32,
    step: u32,
    body: []const u8,
    bytes: []u8,
    allocator: Allocator,

    pub fn deinit(n: *Note) void {
        n.allocator.free(n.bytes);
        n.* = undefined;
    }

    pub fn make(allocator: Allocator, v: u8, circle_id: [16]u8, chain_id: u32, step: u32, body: []const u8, signer: curve.Secret) !Note {
        var w = codec.Writer.init(allocator);
        defer w.deinit();
        try w.buf.append(allocator, ((v & 0xF) << 4) | version);
        try w.bytes(1, &circle_id);
        try w.uint(2, chain_id);
        try w.uint(3, step);
        try w.bytes(4, body);
        const signature = try signer.sign(w.buf.items);
        try w.buf.appendSlice(allocator, &signature);
        const bytes = try w.finish();
        errdefer allocator.free(bytes);
        return parseOwned(allocator, bytes);
    }

    pub fn parse(allocator: Allocator, data: []const u8) !Note {
        const copy = try allocator.dupe(u8, data);
        errdefer allocator.free(copy);
        return parseOwned(allocator, copy);
    }

    fn parseOwned(allocator: Allocator, bytes: []u8) !Note {
        if (bytes.len < 1 + curve.signature_length) return Fault.BadMessage;
        const v = try versionOf(bytes[0]);
        const content = bytes[1 .. bytes.len - curve.signature_length];
        var circle_id: ?[16]u8 = null;
        var chain_id: ?u32 = null;
        var step: ?u32 = null;
        var body: ?[]const u8 = null;
        var r = codec.Reader.init(content);
        while (r.next() catch return Fault.BadMessage) |f| switch (f.number) {
            1 => {
                const b = f.bytes() orelse return Fault.BadMessage;
                if (b.len != 16) return Fault.BadMessage;
                circle_id = b[0..16].*;
            },
            2 => chain_id = std.math.cast(u32, f.uint() orelse return Fault.BadMessage) orelse return Fault.BadMessage,
            3 => step = std.math.cast(u32, f.uint() orelse return Fault.BadMessage) orelse return Fault.BadMessage,
            4 => body = f.bytes(),
            else => {},
        };
        return .{
            .version = v,
            .circle_id = circle_id orelse return Fault.BadMessage,
            .chain_id = chain_id orelse return Fault.BadMessage,
            .step = step orelse return Fault.BadMessage,
            .body = body orelse return Fault.BadMessage,
            .bytes = bytes,
            .allocator = allocator,
        };
    }

    pub fn signedBy(n: Note, signing: curve.Public) bool {
        const end = n.bytes.len - curve.signature_length;
        return signing.verify(n.bytes[0..end], n.bytes[end..][0..curve.signature_length].*);
    }
};

test "a note verifies under its signing key only and an announcement round trips" {
    const a = std.testing.allocator;
    const signer = try curve.Pair.generate();
    const other = try curve.Pair.generate();
    var n = try Note.make(a, 3, [_]u8{1} ** 16, 42, 7, "body", signer.secret);
    defer n.deinit();
    try std.testing.expect(n.signedBy(signer.public));
    try std.testing.expect(!n.signedBy(other.public));
    try std.testing.expectEqual(@as(u8, 0x33), n.bytes[0]);
    var m = try Announce.make(a, 3, [_]u8{5} ** 16, 99, 4, [_]u8{6} ** 32, signer.public);
    defer m.deinit();
    var back = try Announce.parse(a, m.bytes);
    defer back.deinit();
    try std.testing.expectEqual(@as(u32, 99), back.chain_id);
    try std.testing.expect(back.signing.eql(signer.public));
}

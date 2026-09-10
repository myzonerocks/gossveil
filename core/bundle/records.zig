//! The pre-key records a device keeps: a one-time key, a signed key and a
//! post-quantum key, each with its id and, for the signed ones, a timestamp
//! and the identity's signature over the serialised public key.
const std = @import("std");
const curve = @import("../keys/curve.zig");
const pq = @import("../keys/pq.zig");
const identity = @import("../keys/identity.zig");
const codec = @import("../wire/codec.zig");
const Fault = @import("../fault.zig").Fault;
const Allocator = std.mem.Allocator;

pub const OneTimeRecord = struct {
    id: u32,
    pair: curve.Pair,

    pub fn generate(id: u32) Fault!OneTimeRecord {
        return .{ .id = id, .pair = try curve.Pair.generate() };
    }

    pub fn serialize(r: OneTimeRecord, allocator: Allocator) ![]u8 {
        var w = codec.Writer.init(allocator);
        defer w.deinit();
        try w.uint(1, r.id);
        try w.bytes(2, &r.pair.public.serialize());
        try w.bytes(3, &r.pair.secret.serialize());
        return w.finish();
    }

    pub fn parse(data: []const u8) !OneTimeRecord {
        var id: ?u32 = null;
        var public: ?[]const u8 = null;
        var secret: ?[]const u8 = null;
        var r = codec.Reader.init(data);
        while (r.next() catch return Fault.BadMessage) |f| switch (f.number) {
            1 => id = std.math.cast(u32, f.uint() orelse 0),
            2 => public = f.bytes(),
            3 => secret = f.bytes(),
            else => {},
        };
        return .{
            .id = id orelse return Fault.BadArgument,
            .pair = .{
                .public = try curve.Public.parse(public orelse return Fault.BadArgument),
                .secret = try curve.Secret.parse(secret orelse return Fault.BadArgument),
            },
        };
    }
};

pub const SignedRecord = struct {
    id: u32,
    stamp: u64,
    pair: curve.Pair,
    signature: [curve.signature_length]u8,

    pub fn generate(id: u32, stamp: u64, signer: curve.Secret) Fault!SignedRecord {
        const pair = try curve.Pair.generate();
        return .{ .id = id, .stamp = stamp, .pair = pair, .signature = try signer.sign(&pair.public.serialize()) };
    }

    pub fn signedBy(r: SignedRecord, who: identity.Identity) bool {
        return who.key.verify(&r.pair.public.serialize(), r.signature);
    }

    pub fn serialize(r: SignedRecord, allocator: Allocator) ![]u8 {
        var w = codec.Writer.init(allocator);
        defer w.deinit();
        try w.uint(1, r.id);
        try w.bytes(2, &r.pair.public.serialize());
        try w.bytes(3, &r.pair.secret.serialize());
        try w.bytes(4, &r.signature);
        try w.word64(5, r.stamp);
        return w.finish();
    }

    pub fn parse(data: []const u8) !SignedRecord {
        var id: ?u32 = null;
        var public: ?[]const u8 = null;
        var secret: ?[]const u8 = null;
        var signature: ?[]const u8 = null;
        var stamp: u64 = 0;
        var r = codec.Reader.init(data);
        while (r.next() catch return Fault.BadMessage) |f| switch (f.number) {
            1 => id = std.math.cast(u32, f.uint() orelse 0),
            2 => public = f.bytes(),
            3 => secret = f.bytes(),
            4 => signature = f.bytes(),
            5 => stamp = f.word() orelse 0,
            else => {},
        };
        const sig = signature orelse return Fault.BadArgument;
        if (sig.len != curve.signature_length) return Fault.BadSignature;
        return .{
            .id = id orelse return Fault.BadArgument,
            .stamp = stamp,
            .pair = .{
                .public = try curve.Public.parse(public orelse return Fault.BadArgument),
                .secret = try curve.Secret.parse(secret orelse return Fault.BadArgument),
            },
            .signature = sig[0..curve.signature_length].*,
        };
    }
};

pub const PqRecord = struct {
    id: u32,
    stamp: u64,
    pair: pq.Pair,
    signature: [curve.signature_length]u8,

    pub fn generate(id: u32, stamp: u64, scheme: pq.Scheme, signer: curve.Secret) Fault!PqRecord {
        const pair = try pq.Pair.generate(scheme);
        return .{ .id = id, .stamp = stamp, .pair = pair, .signature = try signer.sign(&pair.public.serialize()) };
    }

    pub fn signedBy(r: PqRecord, who: identity.Identity) bool {
        return who.key.verify(&r.pair.public.serialize(), r.signature);
    }

    pub fn serialize(r: PqRecord, allocator: Allocator) ![]u8 {
        var w = codec.Writer.init(allocator);
        defer w.deinit();
        try w.uintIfSet(1, r.id);
        try w.bytes(2, &r.pair.public.serialize());
        try w.bytes(3, &r.pair.secret.serialize());
        try w.bytes(4, &r.signature);
        try w.word64(5, r.stamp);
        return w.finish();
    }

    pub fn parse(data: []const u8) !PqRecord {
        var id: u32 = 0;
        var public: ?pq.Public = null;
        var secret: ?pq.Secret = null;
        var signature: ?[]const u8 = null;
        var stamp: u64 = 0;
        var r = codec.Reader.init(data);
        while (r.next() catch return Fault.BadMessage) |f| switch (f.number) {
            1 => id = std.math.cast(u32, f.uint() orelse 0) orelse return Fault.BadArgument,
            2 => public = try pq.Public.parse(f.bytes() orelse return Fault.BadArgument),
            3 => secret = try pq.Secret.parse(f.bytes() orelse return Fault.BadArgument),
            4 => signature = f.bytes(),
            5 => stamp = f.word() orelse 0,
            else => {},
        };
        const p = public orelse return Fault.BadArgument;
        const s = secret orelse return Fault.BadArgument;
        if (p.scheme != s.scheme) return Fault.BadKey;
        const sig = signature orelse return Fault.BadArgument;
        if (sig.len != curve.signature_length) return Fault.BadSignature;
        return .{ .id = id, .stamp = stamp, .pair = .{ .public = p, .secret = s }, .signature = sig[0..curve.signature_length].* };
    }
};

test "every record round trips and the signed ones verify" {
    const a = std.testing.allocator;
    const me = try identity.IdentityPair.generate();
    const one = try OneTimeRecord.generate(7);
    const one_bytes = try one.serialize(a);
    defer a.free(one_bytes);
    try std.testing.expect((try OneTimeRecord.parse(one_bytes)).pair.public.eql(one.pair.public));

    const signed = try SignedRecord.generate(1, 1234, me.secret);
    const signed_bytes = try signed.serialize(a);
    defer a.free(signed_bytes);
    const signed_back = try SignedRecord.parse(signed_bytes);
    try std.testing.expectEqual(@as(u64, 1234), signed_back.stamp);
    try std.testing.expect(signed_back.signedBy(me.identity));

    const post = try PqRecord.generate(2, 99, .round_three, me.secret);
    const post_bytes = try post.serialize(a);
    defer a.free(post_bytes);
    const post_back = try PqRecord.parse(post_bytes);
    try std.testing.expect(post_back.pair.public.eql(post.pair.public));
    try std.testing.expect(post_back.signedBy(me.identity));
    try std.testing.expect(!post_back.signedBy((try identity.IdentityPair.generate()).identity));
}

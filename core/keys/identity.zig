//! A device's long-lived identity: a curve key pair, serialised as a two-field
//! record of the public and secret keys.
const std = @import("std");
const curve = @import("curve.zig");
const codec = @import("../wire/codec.zig");
const Fault = @import("../fault.zig").Fault;

pub const Identity = struct {
    key: curve.Public,

    pub fn parse(data: []const u8) Fault!Identity {
        return .{ .key = try curve.Public.parse(data) };
    }

    pub fn serialize(i: Identity) [curve.serialized_length]u8 {
        return i.key.serialize();
    }

    /// Whether this identity signed `other` as one of its own.
    pub fn vouchesFor(i: Identity, other: Identity, signature: [64]u8) bool {
        return i.key.verify(&other.serialize(), signature);
    }

    pub fn eql(a: Identity, b: Identity) bool {
        return a.key.eql(b.key);
    }
};

pub const IdentityPair = struct {
    identity: Identity,
    secret: curve.Secret,

    pub fn generate() Fault!IdentityPair {
        return fromPair(try curve.Pair.generate());
    }

    pub fn fromPair(pair: curve.Pair) IdentityPair {
        return .{ .identity = .{ .key = pair.public }, .secret = pair.secret };
    }

    pub fn parse(data: []const u8) !IdentityPair {
        var public: ?[]const u8 = null;
        var secret: ?[]const u8 = null;
        var r = codec.Reader.init(data);
        while (r.next() catch return Fault.BadMessage) |f| switch (f.number) {
            1 => public = f.bytes(),
            2 => secret = f.bytes(),
            else => {},
        };
        return .{
            .identity = try Identity.parse(public orelse return Fault.BadArgument),
            .secret = try curve.Secret.parse(secret orelse return Fault.BadArgument),
        };
    }

    pub fn serialize(p: IdentityPair, allocator: std.mem.Allocator) ![]u8 {
        var w = codec.Writer.init(allocator);
        defer w.deinit();
        try w.bytes(1, &p.identity.serialize());
        try w.bytes(2, &p.secret.serialize());
        return w.finish();
    }

    /// Signs another identity as an alternate of this one.
    pub fn vouch(p: IdentityPair, other: Identity) Fault![64]u8 {
        return p.secret.sign(&other.serialize());
    }
};

test "the pair round trips and vouches" {
    const a = std.testing.allocator;
    const pair = try IdentityPair.generate();
    const bytes = try pair.serialize(a);
    defer a.free(bytes);
    const back = try IdentityPair.parse(bytes);
    try std.testing.expect(back.identity.eql(pair.identity));
    const other = try IdentityPair.generate();
    const sig = try pair.vouch(other.identity);
    try std.testing.expect(pair.identity.vouchesFor(other.identity, sig));
    try std.testing.expect(!other.identity.vouchesFor(pair.identity, sig));
}

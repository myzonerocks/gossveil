//! Curve25519 keys. A public key travels as a tag byte and the Montgomery
//! u-coordinate; a secret is held clamped so its serialised form is canonical.
const std = @import("std");
const mem = std.mem;
const X25519 = std.crypto.dh.X25519;
const signing = @import("sign.zig");
const entropy = @import("../entropy.zig");
const frame = @import("../wire/frame.zig");
const Fault = @import("../fault.zig").Fault;

pub const secret_length = 32;
pub const public_length = 32;
pub const serialized_length = 33;
pub const signature_length = signing.length;

pub const Public = struct {
    u: [public_length]u8,

    pub fn fromRaw(u: [public_length]u8) Public {
        return .{ .u = u };
    }

    pub fn parse(data: []const u8) Fault!Public {
        if (data.len != serialized_length) return Fault.BadKey;
        if (data[0] != frame.curve_key_tag) return Fault.UnknownKeyType;
        return .{ .u = data[1..33].* };
    }

    pub fn serialize(p: Public) [serialized_length]u8 {
        var out: [serialized_length]u8 = undefined;
        out[0] = frame.curve_key_tag;
        out[1..].* = p.u;
        return out;
    }

    pub fn verify(p: Public, message: []const u8, signature: [signature_length]u8) bool {
        return signing.verify(p.u, message, signature);
    }

    pub fn eql(a: Public, b: Public) bool {
        return mem.eql(u8, &a.u, &b.u);
    }

    pub fn order(a: Public, b: Public) std.math.Order {
        return mem.order(u8, &a.u, &b.u);
    }
};

pub const Secret = struct {
    scalar: [secret_length]u8,

    pub fn fromRaw(bytes: [secret_length]u8) Secret {
        return .{ .scalar = signing.clamp(bytes) };
    }

    pub fn parse(data: []const u8) Fault!Secret {
        if (data.len != secret_length) return Fault.BadKey;
        return fromRaw(data[0..32].*);
    }

    pub fn serialize(s: Secret) [secret_length]u8 {
        return s.scalar;
    }

    pub fn public(s: Secret) Fault!Public {
        const point = X25519.Curve.basePoint.clampedMul(s.scalar) catch return Fault.BadKey;
        return .{ .u = point.toBytes() };
    }

    pub fn agree(s: Secret, their: Public) Fault![32]u8 {
        return X25519.scalarmult(s.scalar, their.u) catch Fault.BadKey;
    }

    pub fn sign(s: Secret, message: []const u8) Fault![signature_length]u8 {
        return s.signWithNonce(message, entropy.array(64));
    }

    pub fn signWithNonce(s: Secret, message: []const u8, nonce: [64]u8) Fault![signature_length]u8 {
        return signing.sign(s.scalar, message, nonce) catch Fault.BadKey;
    }
};

pub const Pair = struct {
    public: Public,
    secret: Secret,

    pub fn generate() Fault!Pair {
        return fromSeed(entropy.array(32));
    }

    pub fn fromSeed(seed: [32]u8) Fault!Pair {
        const secret = Secret.fromRaw(seed);
        return .{ .public = try secret.public(), .secret = secret };
    }

    pub fn fromSecret(secret: Secret) Fault!Pair {
        return .{ .public = try secret.public(), .secret = secret };
    }
};

test "agreement is symmetric and keys round trip" {
    const a = try Pair.generate();
    const b = try Pair.generate();
    try std.testing.expectEqualSlices(u8, &try a.secret.agree(b.public), &try b.secret.agree(a.public));
    const parsed = try Public.parse(&a.public.serialize());
    try std.testing.expect(parsed.eql(a.public));
    try std.testing.expectError(Fault.UnknownKeyType, Public.parse(&([_]u8{6} ++ a.public.u)));
}

test "a signature made by the pair verifies" {
    const p = try Pair.generate();
    const sig = try p.secret.sign("veil");
    try std.testing.expect(p.public.verify("veil", sig));
}

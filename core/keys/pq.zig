//! Post-quantum key encapsulation. Two lattice parameter sets share one wire
//! shape: a scheme byte, then the key or the capsule.
const std = @import("std");
const entropy = @import("../entropy.zig");
const Fault = @import("../fault.zig").Fault;

const RoundThree = std.crypto.kem.kyber_d00.Kyber1024;
const Standard = std.crypto.kem.ml_kem.MLKem1024;

pub const Scheme = enum(u8) {
    round_three = 0x08,
    standard = 0x0A,

    pub fn fromByte(b: u8) Fault!Scheme {
        return switch (b) {
            0x08 => .round_three,
            0x0A => .standard,
            else => Fault.UnknownKeyType,
        };
    }
};

pub const public_length = RoundThree.PublicKey.encoded_length;
pub const secret_length = RoundThree.SecretKey.encoded_length;
pub const capsule_length = RoundThree.ciphertext_length;
pub const shared_length = 32;
pub const serialized_public_length = 1 + public_length;
pub const serialized_secret_length = 1 + secret_length;
pub const serialized_capsule_length = 1 + capsule_length;

comptime {
    std.debug.assert(Standard.PublicKey.encoded_length == public_length);
    std.debug.assert(Standard.SecretKey.encoded_length == secret_length);
    std.debug.assert(Standard.ciphertext_length == capsule_length);
    std.debug.assert(RoundThree.shared_length == shared_length and Standard.shared_length == shared_length);
}

/// A capsule travels with the scheme byte in front, like the keys do.
pub const Capsule = struct {
    bytes: [serialized_capsule_length]u8,
    shared: [shared_length]u8,
};

pub const Public = struct {
    scheme: Scheme,
    key: [public_length]u8,

    pub fn parse(data: []const u8) Fault!Public {
        if (data.len == 0) return Fault.UnknownKeyType;
        const scheme = try Scheme.fromByte(data[0]);
        if (data.len != serialized_public_length) return Fault.BadKey;
        return .{ .scheme = scheme, .key = data[1..][0..public_length].* };
    }

    pub fn serialize(p: Public) [serialized_public_length]u8 {
        var out: [serialized_public_length]u8 = undefined;
        out[0] = @intFromEnum(p.scheme);
        out[1..].* = p.key;
        return out;
    }

    pub fn encapsulate(p: Public) Fault!Capsule {
        return p.encapsulateWithSeed(entropy.array(32));
    }

    pub fn encapsulateWithSeed(p: Public, seed: [32]u8) Fault!Capsule {
        var out: Capsule = undefined;
        out.bytes[0] = @intFromEnum(p.scheme);
        switch (p.scheme) {
            .round_three => {
                const pk = RoundThree.PublicKey.fromBytes(&p.key) catch return Fault.BadKey;
                const e = pk.encapsDeterministic(&seed);
                out.bytes[1..].* = e.ciphertext;
                out.shared = e.shared_secret;
            },
            .standard => {
                const pk = Standard.PublicKey.fromBytes(&p.key) catch return Fault.BadKey;
                const e = pk.encapsDeterministic(&seed);
                out.bytes[1..].* = e.ciphertext;
                out.shared = e.shared_secret;
            },
        }
        return out;
    }

    pub fn eql(a: Public, b: Public) bool {
        return a.scheme == b.scheme and std.mem.eql(u8, &a.key, &b.key);
    }
};

pub const Secret = struct {
    scheme: Scheme,
    key: [secret_length]u8,

    pub fn parse(data: []const u8) Fault!Secret {
        if (data.len == 0) return Fault.UnknownKeyType;
        const scheme = try Scheme.fromByte(data[0]);
        if (data.len != serialized_secret_length) return Fault.BadKey;
        return .{ .scheme = scheme, .key = data[1..][0..secret_length].* };
    }

    pub fn serialize(s: Secret) [serialized_secret_length]u8 {
        var out: [serialized_secret_length]u8 = undefined;
        out[0] = @intFromEnum(s.scheme);
        out[1..].* = s.key;
        return out;
    }

    /// Takes the serialised capsule, scheme byte first.
    pub fn open(s: Secret, capsule: []const u8) Fault![shared_length]u8 {
        if (capsule.len != serialized_capsule_length) return Fault.BadArgument;
        if (capsule[0] != @intFromEnum(s.scheme)) return Fault.UnknownKeyType;
        const body = capsule[1..][0..capsule_length];
        return switch (s.scheme) {
            .round_three => (RoundThree.SecretKey.fromBytes(&s.key) catch return Fault.BadKey).decaps(body) catch Fault.BadKey,
            .standard => (Standard.SecretKey.fromBytes(&s.key) catch return Fault.BadKey).decaps(body) catch Fault.BadKey,
        };
    }
};

pub const Pair = struct {
    public: Public,
    secret: Secret,

    pub fn generate(scheme: Scheme) Fault!Pair {
        return fromSeed(scheme, entropy.array(64));
    }

    pub fn fromSeed(scheme: Scheme, seed: [64]u8) Fault!Pair {
        switch (scheme) {
            .round_three => {
                const kp = RoundThree.KeyPair.generateDeterministic(seed) catch return Fault.BadKey;
                return .{ .public = .{ .scheme = scheme, .key = kp.public_key.toBytes() }, .secret = .{ .scheme = scheme, .key = kp.secret_key.toBytes() } };
            },
            .standard => {
                const kp = Standard.KeyPair.generateDeterministic(seed) catch return Fault.BadKey;
                return .{ .public = .{ .scheme = scheme, .key = kp.public_key.toBytes() }, .secret = .{ .scheme = scheme, .key = kp.secret_key.toBytes() } };
            },
        }
    }
};

test "both schemes round trip through the serialised shape" {
    inline for (.{ Scheme.round_three, Scheme.standard }) |scheme| {
        const pair = try Pair.generate(scheme);
        const public = try Public.parse(&pair.public.serialize());
        const secret = try Secret.parse(&pair.secret.serialize());
        const capsule = try public.encapsulate();
        try std.testing.expectEqualSlices(u8, &capsule.shared, &try secret.open(&capsule.bytes));
        try std.testing.expectEqual(@intFromEnum(scheme), pair.public.serialize()[0]);
    }
}

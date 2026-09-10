//! Usernames: a nickname and a discriminator, the curve-point hash a server
//! stores, the proof that a hash was made from a real name, and candidates.
const std = @import("std");
const Sponge = @import("sponge.zig").Sponge;
const entropy = @import("../entropy.zig");
const Ristretto255 = std.crypto.ecc.Ristretto255;
const scalar = std.crypto.ecc.Edwards25519.scalar;
const Sha512 = std.crypto.hash.sha2.Sha512;
const mem = std.mem;
const Allocator = mem.Allocator;

pub const hash_length = 32;
pub const proof_length = 128;
pub const max_nickname_length = 48;

const generator_label = "Signal_Username_20230130_Constant_Points_Generate";

const generators_raw = [3][32]u8{
    .{ 0x60, 0xb9, 0x93, 0x66, 0x3a, 0x3d, 0xae, 0xcc, 0x4c, 0x85, 0x2f, 0x53, 0x35, 0x47, 0xe3, 0x05, 0x38, 0x8c, 0x2a, 0x50, 0xa5, 0x83, 0x93, 0xea, 0x27, 0x7d, 0xe4, 0xab, 0xf3, 0xde, 0x54, 0x3a },
    .{ 0xf2, 0xb6, 0xf1, 0xc8, 0x26, 0xfa, 0x36, 0x40, 0x20, 0x6f, 0x3b, 0x58, 0xb2, 0x28, 0x6b, 0xde, 0xfd, 0xfd, 0xa6, 0xa5, 0x4f, 0xf9, 0x02, 0xf2, 0x04, 0xa7, 0x2d, 0xe7, 0x37, 0xd2, 0x61, 0x57 },
    .{ 0x06, 0x06, 0xbd, 0x3a, 0xbf, 0xce, 0x4e, 0x96, 0x17, 0xd4, 0x48, 0xfb, 0x2c, 0xae, 0xb6, 0xcc, 0x02, 0x8e, 0xc9, 0xa2, 0xb6, 0x2b, 0x10, 0xb3, 0xd9, 0xeb, 0x29, 0x48, 0xda, 0x6f, 0x3f, 0x53 },
};

fn generators() [3]Ristretto255 {
    var out: [3]Ristretto255 = undefined;
    for (&out, generators_raw) |*p, raw| p.* = Ristretto255.fromBytes(raw) catch unreachable;
    return out;
}

pub const NameError = error{
    MissingSeparator,
    NicknameCannotBeEmpty,
    NicknameCannotStartWithDigit,
    BadNicknameCharacter,
    NicknameTooShort,
    NicknameTooLong,
    DiscriminatorCannotBeEmpty,
    BadDiscriminatorCharacter,
    DiscriminatorCannotBeZero,
    DiscriminatorCannotBeSingleDigit,
    DiscriminatorCannotHaveLeadingZeros,
    DiscriminatorTooLarge,
    ProofVerificationFailure,
};

pub const Limits = struct {
    min: usize = 3,
    max: usize = 32,
};

fn code(c: u8) ?u8 {
    return switch (c) {
        '_' => 1,
        'a'...'z' => c - 'a' + 2,
        '0'...'9' => c - '0' + 28,
        else => null,
    };
}

fn small(v: u64) [32]u8 {
    var out = [_]u8{0} ** 32;
    mem.writeInt(u64, out[0..8], v, .little);
    return out;
}

fn nicknameScalar(nickname: []const u8) NameError![32]u8 {
    if (nickname.len == 0) return NameError.NicknameCannotBeEmpty;
    if (nickname.len > max_nickname_length) return NameError.NicknameTooLong;
    var codes: [max_nickname_length]u8 = undefined;
    for (nickname, 0..) |c, i| codes[i] = code(std.ascii.toLower(c)) orelse return NameError.BadNicknameCharacter;
    const base = small(37);
    var acc = [_]u8{0} ** 32;
    var i = nickname.len;
    while (i > 1) : (i -= 1) acc = scalar.mulAdd(acc, base, small(codes[i - 1]));
    return scalar.mulAdd(acc, small(27), small(codes[0]));
}

fn digestScalar(nickname: []const u8, discriminator: u64) [32]u8 {
    var h = Sha512.init(.{});
    h.update(nickname);
    h.update(&[_]u8{0});
    var d: [8]u8 = undefined;
    mem.writeInt(u64, &d, discriminator, .big);
    h.update(&d);
    var out: [64]u8 = undefined;
    h.final(&out);
    return scalar.reduce64(out);
}

fn discriminatorOf(text: []const u8) NameError!u64 {
    if (text.len == 0) return NameError.DiscriminatorCannotBeEmpty;
    if (!std.ascii.isDigit(text[0])) return NameError.BadDiscriminatorCharacter;
    var n: u64 = 0;
    for (text) |c| {
        if (!std.ascii.isDigit(c)) return NameError.BadDiscriminatorCharacter;
        n = std.math.mul(u64, n, 10) catch return NameError.DiscriminatorTooLarge;
        n = std.math.add(u64, n, c - '0') catch return NameError.DiscriminatorTooLarge;
    }
    if (n == 0) return NameError.DiscriminatorCannotBeZero;
    return switch (text.len) {
        1 => NameError.DiscriminatorCannotBeSingleDigit,
        2 => n,
        else => if (text[0] != '0') n else NameError.DiscriminatorCannotHaveLeadingZeros,
    };
}

pub fn checkNickname(nickname: []const u8, limits: Limits) NameError!void {
    if (nickname.len == 0) return NameError.NicknameCannotBeEmpty;
    if (std.ascii.isDigit(nickname[0])) return NameError.NicknameCannotStartWithDigit;
    for (nickname) |c| _ = code(std.ascii.toLower(c)) orelse return NameError.BadNicknameCharacter;
    if (nickname.len < limits.min) return NameError.NicknameTooShort;
    if (nickname.len > limits.max) return NameError.NicknameTooLong;
}

pub const Handle = struct {
    scalars: [3][32]u8,

    /// "nickname.discriminator", the discriminator being the digits after the last dot.
    pub fn parse(text: []const u8) NameError!Handle {
        const dot = mem.lastIndexOfScalar(u8, text, '.') orelse return NameError.MissingSeparator;
        return fromPartsUnbounded(text[0..dot], text[dot + 1 ..]);
    }

    pub fn fromParts(nickname: []const u8, discriminator: []const u8, limits: Limits) NameError!Handle {
        const h = try fromPartsUnbounded(nickname, discriminator);
        try checkNickname(nickname, limits);
        return h;
    }

    fn fromPartsUnbounded(nickname: []const u8, discriminator: []const u8) NameError!Handle {
        if (nickname.len == 0) return NameError.NicknameCannotBeEmpty;
        if (std.ascii.isDigit(nickname[0])) return NameError.NicknameCannotStartWithDigit;
        const d = try discriminatorOf(discriminator);
        return .{ .scalars = .{ digestScalar(nickname, d), try nicknameScalar(nickname), small(d) } };
    }

    fn point(h: Handle) !Ristretto255 {
        return combine(h.scalars, null, null);
    }

    pub fn hash(h: Handle) ![hash_length]u8 {
        return (try h.point()).toBytes();
    }

    pub fn proof(h: Handle, randomness: [32]u8) ![proof_length]u8 {
        const p = try h.point();
        const message = p.toBytes();
        var transcript = statement(p);
        var blinding = transcript;
        blinding.absorb(&randomness);
        for (h.scalars) |s| blinding.absorb(&s);
        blinding.ratchet();
        blinding.absorbRatchet(&message);
        var nonce_bytes: [3 * 64]u8 = undefined;
        blinding.squeeze(&nonce_bytes);
        var nonce: [3][32]u8 = undefined;
        for (&nonce, 0..) |*n, i| n.* = scalar.reduce64(nonce_bytes[i * 64 ..][0..64].*);
        const commitment = try combine(nonce, null, p);
        transcript.absorb(&commitment.toBytes());
        transcript.absorbRatchet(&message);
        const challenge = transcript.scalarValue();
        var out: [proof_length]u8 = undefined;
        out[0..32].* = challenge;
        for (nonce, h.scalars, 0..) |n, s, i| out[32 + i * 32 ..][0..32].* = scalar.mulAdd(s, challenge, n);
        try verify(&out, message);
        return out;
    }

    pub fn verify(proof_bytes: []const u8, hash_bytes: [hash_length]u8) NameError!void {
        if (proof_bytes.len != proof_length) return NameError.ProofVerificationFailure;
        const p = Ristretto255.fromBytes(hash_bytes) catch return NameError.ProofVerificationFailure;
        const challenge = proof_bytes[0..32].*;
        scalar.rejectNonCanonical(challenge) catch return NameError.ProofVerificationFailure;
        var response: [3][32]u8 = undefined;
        for (&response, 0..) |*r, i| {
            r.* = proof_bytes[32 + i * 32 ..][0..32].*;
            scalar.rejectNonCanonical(r.*) catch return NameError.ProofVerificationFailure;
        }
        var transcript = statement(p);
        const commitment = combine(response, challenge, p) catch return NameError.ProofVerificationFailure;
        transcript.absorb(&commitment.toBytes());
        transcript.absorbRatchet(&hash_bytes);
        if (!std.crypto.timing_safe.eql([32]u8, transcript.scalarValue(), challenge)) return NameError.ProofVerificationFailure;
    }

    /// The transcript prefix: the statement's byte shape, then every point in
    /// declaration order (base point, hash, the three generators).
    fn statement(p: Ristretto255) Sponge {
        var s = Sponge.init("POKSHO_Ristretto_SHOHMACSHA256");
        s.absorb(&[_]u8{ 1, 1, 3, 0, 2, 1, 3, 2, 4 });
        s.absorb(&Ristretto255.basePoint.toBytes());
        s.absorb(&p.toBytes());
        for (generators()) |g| s.absorb(&g.toBytes());
        s.ratchet();
        return s;
    }

    fn combine(coefficients: [3][32]u8, challenge: ?[32]u8, p: ?Ristretto255) !Ristretto255 {
        const g = generators();
        var acc = try g[0].mul(coefficients[0]);
        acc = acc.add(try g[1].mul(coefficients[1]));
        acc = acc.add(try g[2].mul(coefficients[2]));
        if (challenge) |c| acc = acc.sub(try p.?.mul(c));
        return acc;
    }
};

pub fn hashOf(text: []const u8) ![hash_length]u8 {
    return (try Handle.parse(text)).hash();
}

pub fn proofOf(text: []const u8, randomness: [32]u8) ![proof_length]u8 {
    return (try Handle.parse(text)).proof(randomness);
}

const ranges = [8][2]u64{
    .{ 1, 100 },
    .{ 100, 1_000 },
    .{ 1_000, 10_000 },
    .{ 10_000, 100_000 },
    .{ 100_000, 1_000_000 },
    .{ 1_000_000, 10_000_000 },
    .{ 10_000_000, 100_000_000 },
    .{ 100_000_000, 1_000_000_000 },
};
const per_range = [8]u8{ 4, 3, 3, 2, 2, 2, 2, 2 };
pub const candidate_count = 20;

fn below(bound: u64) u64 {
    const limit = std.math.maxInt(u64) - std.math.maxInt(u64) % bound;
    while (true) {
        const v = mem.readInt(u64, &entropy.array(8), .little);
        if (v < limit) return v % bound;
    }
}

/// Twenty "nickname.discriminator" candidates, denser in the short ranges.
/// The caller owns the returned strings.
pub fn candidates(allocator: Allocator, nickname: []const u8, limits: Limits) ![candidate_count][]u8 {
    try checkNickname(nickname, limits);
    var out: [candidate_count][]u8 = undefined;
    var made: usize = 0;
    errdefer for (out[0..made]) |s| allocator.free(s);
    for (ranges, per_range) |range, count| {
        var i: u8 = 0;
        while (i < count) : (i += 1) {
            const d = range[0] + below(range[1] - range[0]);
            out[made] = try std.fmt.allocPrint(allocator, "{s}.{s}{d}", .{ nickname, if (d < 10) "0" else "", d });
            made += 1;
        }
    }
    return out;
}

test "the generators are the ones the label derives" {
    var s = Sponge.init(generator_label);
    s.absorbRatchet("");
    for (generators()) |expected| try std.testing.expectEqualSlices(u8, &expected.toBytes(), &s.point().toBytes());
}

test "hash, proof and verification agree" {
    const h = try Handle.parse("plain_user.42");
    const digest = try h.hash();
    const p = try h.proof(entropy.array(32));
    try Handle.verify(&p, digest);
    var wrong = digest;
    wrong[0] ^= 1;
    try std.testing.expectError(NameError.ProofVerificationFailure, Handle.verify(&p, wrong));
}

test "discriminator rules and candidates" {
    try std.testing.expectError(NameError.DiscriminatorCannotBeSingleDigit, Handle.parse("abc.1"));
    try std.testing.expectError(NameError.DiscriminatorCannotHaveLeadingZeros, Handle.parse("abc.001"));
    try std.testing.expectError(NameError.DiscriminatorCannotBeZero, Handle.parse("abc.00"));
    try std.testing.expectError(NameError.NicknameCannotStartWithDigit, Handle.parse("1abc.01"));
    _ = try Handle.parse("abc.01");
    const a = std.testing.allocator;
    const list = try candidates(a, "plain_user", .{});
    defer for (list) |c| a.free(c);
    for (list) |c| _ = try Handle.parse(c);
    try std.testing.expect(mem.startsWith(u8, list[0], "plain_user."));
}

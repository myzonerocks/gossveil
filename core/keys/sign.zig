//! Signatures from a Montgomery key: the secret scalar signs on the Edwards
//! curve and the verifier maps the Montgomery public key to its Edwards image,
//! taking the sign bit from the signature's last byte. A random nonce goes
//! into the hash so two signatures of one message differ.
const std = @import("std");
const Ed = std.crypto.ecc.Edwards25519;
const Sha512 = std.crypto.hash.sha2.Sha512;

pub const length = 64;
const nonce_prefix = [_]u8{0xFE} ** 64;

pub fn clamp(s: [32]u8) [32]u8 {
    var c = s;
    c[0] &= 248;
    c[31] &= 127;
    c[31] |= 64;
    return c;
}

fn edwardsImage(u: [32]u8, sign_bit: u1) !Ed {
    const fe = Ed.Fe.fromBytes(u);
    const y = fe.sub(Ed.Fe.one).mul(fe.add(Ed.Fe.one).invert());
    var bytes = y.toBytes();
    bytes[31] = (bytes[31] & 0x7F) | (@as(u8, sign_bit) << 7);
    return Ed.fromBytes(bytes) catch error.BadKey;
}

pub fn sign(secret: [32]u8, message: []const u8, nonce: [64]u8) ![length]u8 {
    const a = clamp(secret);
    const public_point = try Ed.basePoint.mul(a);
    const public_bytes = public_point.toBytes();
    const sign_bit: u1 = @intCast(public_bytes[31] >> 7);

    var h = Sha512.init(.{});
    h.update(&nonce_prefix);
    h.update(&secret);
    h.update(&nonce);
    var digest: [64]u8 = undefined;
    h.final(&digest);
    const r = Ed.scalar.reduce64(digest);
    const commitment = (try Ed.basePoint.mul(r)).toBytes();

    var h2 = Sha512.init(.{});
    h2.update(&commitment);
    h2.update(&public_bytes);
    h2.update(message);
    h2.final(&digest);
    const challenge = Ed.scalar.reduce64(digest);
    const response = Ed.scalar.mulAdd(challenge, a, r);

    var out: [length]u8 = undefined;
    out[0..32].* = commitment;
    out[32..64].* = response;
    out[63] = (out[63] & 0x7F) | (@as(u8, sign_bit) << 7);
    return out;
}

pub fn verify(public: [32]u8, message: []const u8, signature: [length]u8) bool {
    var sig = signature;
    const sign_bit: u1 = @intCast(sig[63] >> 7);
    sig[63] &= 0x7F;
    const commitment = Ed.fromBytes(sig[0..32].*) catch return false;
    commitment.rejectIdentity() catch return false;
    const image = edwardsImage(public, sign_bit) catch return false;

    var h = Sha512.init(.{});
    h.update(sig[0..32]);
    h.update(&image.toBytes());
    h.update(message);
    var digest: [64]u8 = undefined;
    h.final(&digest);
    const challenge = Ed.scalar.reduce64(digest);
    const check = Ed.mulDoubleBasePublic(Ed.basePoint, sig[32..64].*, image.neg(), challenge) catch return false;
    return std.mem.eql(u8, sig[0..32], &check.toBytes());
}

test "a signature verifies and a flipped bit does not" {
    const entropy = @import("../entropy.zig");
    const secret = entropy.array(32);
    const public = (try std.crypto.dh.X25519.Curve.basePoint.clampedMul(clamp(secret))).toBytes();
    const sig = try sign(secret, "veil", entropy.array(64));
    try std.testing.expect(verify(public, "veil", sig));
    var bad = sig;
    bad[3] ^= 1;
    try std.testing.expect(!verify(public, "veil", bad));
    try std.testing.expect(!verify(public, "vail", sig));
}

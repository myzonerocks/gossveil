//! Every key derivation the handshake and the ratchets use, over HKDF and
//! HMAC with SHA-256. The labels are the protocol's; the names are ours.
const std = @import("std");
const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;

pub const Opening = struct { root: [32]u8, chain: [32]u8, pq_auth: [32]u8 };

/// The handshake secret opens into a root key, a first chain key and the
/// authentication key of the post-quantum ratchet.
pub fn opening(secret: []const u8) Opening {
    var out: [96]u8 = undefined;
    Hkdf.expand(&out, "WhisperText_X25519_SHA-256_CRYSTALS-KYBER-1024", Hkdf.extract(&.{}, secret));
    return .{ .root = out[0..32].*, .chain = out[32..64].*, .pq_auth = out[64..96].* };
}

pub const Turn = struct { root: [32]u8, chain: [32]u8 };

/// One turn of the asymmetric ratchet: the agreement is the material, the
/// previous root key is the salt.
pub fn turn(root: [32]u8, agreement: [32]u8) Turn {
    var out: [64]u8 = undefined;
    Hkdf.expand(&out, "WhisperRatchet", Hkdf.extract(&root, &agreement));
    return .{ .root = out[0..32].*, .chain = out[32..64].* };
}

pub const MessageKeys = struct { cipher: [32]u8, mac: [32]u8, iv: [16]u8 };

/// Message keys from a chain seed; the post-quantum ratchet key is the salt
/// when the session has one.
pub fn messageKeys(seed: [32]u8, salt: ?[32]u8) MessageKeys {
    const prk = if (salt) |s| Hkdf.extract(&s, &seed) else Hkdf.extract(&.{}, &seed);
    var out: [80]u8 = undefined;
    Hkdf.expand(&out, "WhisperMessageKeys", prk);
    return .{ .cipher = out[0..32].*, .mac = out[32..64].*, .iv = out[64..80].* };
}

fn tagged(key: [32]u8, tag: u8) [32]u8 {
    var out: [32]u8 = undefined;
    Hmac.create(&out, &[_]u8{tag}, &key);
    return out;
}

pub fn chainSeed(chain: [32]u8) [32]u8 {
    return tagged(chain, 0x01);
}

pub fn chainNext(chain: [32]u8) [32]u8 {
    return tagged(chain, 0x02);
}

pub const CircleKeys = struct { iv: [16]u8, cipher: [32]u8 };

pub fn circleKeys(seed: [32]u8) CircleKeys {
    var out: [48]u8 = undefined;
    Hkdf.expand(&out, "WhisperGroup", Hkdf.extract(&.{}, &seed));
    return .{ .iv = out[0..16].*, .cipher = out[16..48].* };
}

/// HKDF with SHA-256 and an optional salt, the general form the surfaces expose.
pub fn hkdf(out: []u8, material: []const u8, salt: ?[]const u8, info: []const u8) void {
    Hkdf.expand(out, info, Hkdf.extract(salt orelse &.{}, material));
}

test "the chain seed and the next chain key differ" {
    const chain = [_]u8{0x11} ** 32;
    try std.testing.expect(!std.mem.eql(u8, &chainSeed(chain), &chainNext(chain)));
    const o = opening("secret");
    try std.testing.expect(!std.mem.eql(u8, &o.root, &o.chain));
}

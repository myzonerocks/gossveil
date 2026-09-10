//! Group parameters: a master key and everything derived from it, in the
//! fixed little-endian record layout the group server and the clients share.
const std = @import("std");
const Sponge = @import("../handle/sponge.zig").Sponge;
const entropy = @import("../entropy.zig");
const Fault = @import("../fault.zig").Fault;
const Ristretto255 = std.crypto.ecc.Ristretto255;
const mem = std.mem;

pub const master_length = 32;
pub const identifier_length = 32;
pub const secret_length = 289;
pub const public_length = 97;

const id_generators_raw = [64]u8{
    0xa6, 0x32, 0x4c, 0x36, 0x8d, 0xf7, 0x34, 0x69, 0x11, 0x47, 0x98, 0x13, 0x48, 0xb6, 0xe7, 0xeb,
    0x42, 0xc3, 0x30, 0x7e, 0x71, 0x1b, 0x6c, 0x7e, 0xcc, 0xd3, 0x03, 0x2d, 0x45, 0x69, 0x3f, 0x5a,
    0x04, 0x80, 0x13, 0x52, 0x5b, 0x76, 0x12, 0x4b, 0xf2, 0x64, 0x0c, 0x5e, 0x93, 0x69, 0xc7, 0x6e,
    0xfb, 0xe8, 0x0a, 0xba, 0x2a, 0x24, 0xaa, 0x5d, 0x8e, 0x18, 0xa9, 0x8e, 0xba, 0x14, 0xf8, 0x37,
};

fn generatorsFor(label: []const u8) [2]Ristretto255 {
    var s = Sponge.init(label);
    s.absorbRatchet("");
    return .{ s.point(), s.point() };
}

/// Two scalars and the point they commit to, under a pair of generators.
const Commitment = struct {
    a1: [32]u8,
    a2: [32]u8,
    public: [32]u8,

    fn from(s: *Sponge, g: [2]Ristretto255) !Commitment {
        const a1 = s.scalarValue();
        const a2 = s.scalarValue();
        const public = (try g[0].mul(a1)).add(try g[1].mul(a2));
        return .{ .a1 = a1, .a2 = a2, .public = public.toBytes() };
    }
};

pub const MasterKey = struct {
    bytes: [master_length]u8,

    pub fn random() MasterKey {
        return fromRandomness(entropy.array(32));
    }

    pub fn fromRandomness(randomness: [32]u8) MasterKey {
        var s = Sponge.init("Signal_ZKGroup_20200424_Random_GroupSecretParams_Generate");
        s.absorbRatchet(&randomness);
        return .{ .bytes = s.squeezeArray(32) };
    }

    pub fn parse(data: []const u8) Fault!MasterKey {
        if (data.len != master_length) return Fault.BadArgument;
        return .{ .bytes = data[0..master_length].* };
    }

    pub fn secretParams(k: MasterKey) !SecretParams {
        var s = Sponge.init("Signal_ZKGroup_20200424_GroupMasterKey_GroupSecretParams_DeriveFromMasterKey");
        s.absorbRatchet(&k.bytes);
        const group_id = s.squeezeArray(32);
        const blob_key = s.squeezeArray(32);
        const id = try Commitment.from(&s, generatorsFor("Signal_ZKGroup_20200424_Constant_UidEncryption_SystemParams_Generate"));
        const profile = try Commitment.from(&s, generatorsFor("Signal_ZKGroup_20200424_Constant_ProfileKeyEncryption_SystemParams_Generate"));
        return .{ .master = k, .identifier = group_id, .blob_key = blob_key, .id = id, .profile = profile };
    }

    pub fn identifier(k: MasterKey) ![identifier_length]u8 {
        return (try k.secretParams()).identifier;
    }
};

pub const SecretParams = struct {
    master: MasterKey,
    identifier: [identifier_length]u8,
    blob_key: [32]u8,
    id: Commitment,
    profile: Commitment,

    pub fn serialize(p: SecretParams) [secret_length]u8 {
        var out: [secret_length]u8 = undefined;
        out[0] = 0;
        out[1..33].* = p.master.bytes;
        out[33..65].* = p.identifier;
        out[65..97].* = p.blob_key;
        out[97..129].* = p.id.a1;
        out[129..161].* = p.id.a2;
        out[161..193].* = p.id.public;
        out[193..225].* = p.profile.a1;
        out[225..257].* = p.profile.a2;
        out[257..289].* = p.profile.public;
        return out;
    }

    pub fn parse(data: []const u8) Fault!SecretParams {
        if (data.len != secret_length or data[0] != 0) return Fault.BadArgument;
        return .{
            .master = .{ .bytes = data[1..33].* },
            .identifier = data[33..65].*,
            .blob_key = data[65..97].*,
            .id = .{ .a1 = data[97..129].*, .a2 = data[129..161].*, .public = data[161..193].* },
            .profile = .{ .a1 = data[193..225].*, .a2 = data[225..257].*, .public = data[257..289].* },
        };
    }

    pub fn publicParams(p: SecretParams) [public_length]u8 {
        var out: [public_length]u8 = undefined;
        out[0] = 0;
        out[1..33].* = p.identifier;
        out[33..65].* = p.id.public;
        out[65..97].* = p.profile.public;
        return out;
    }
};

test "the id generators match the fixed system parameters" {
    const g = generatorsFor("Signal_ZKGroup_20200424_Constant_UidEncryption_SystemParams_Generate");
    try std.testing.expectEqualSlices(u8, id_generators_raw[0..32], &g[0].toBytes());
    try std.testing.expectEqualSlices(u8, id_generators_raw[32..64], &g[1].toBytes());
}

test "secret params round trip and carry their identifier" {
    const master = MasterKey.random();
    const params = try master.secretParams();
    const bytes = params.serialize();
    const back = try SecretParams.parse(&bytes);
    try std.testing.expectEqualSlices(u8, &bytes, &back.serialize());
    try std.testing.expectEqualSlices(u8, &params.identifier, &try master.identifier());
    try std.testing.expectEqualSlices(u8, &params.identifier, back.publicParams()[1..33]);
}

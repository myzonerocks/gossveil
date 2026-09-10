//! A stateful hash over HMAC-SHA256: absorb, ratchet, squeeze. It derives
//! the fixed generators and drives the non-interactive proofs.
const std = @import("std");
const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
const Ristretto255 = std.crypto.ecc.Ristretto255;
const scalar = std.crypto.ecc.Edwards25519.scalar;

pub const Sponge = struct {
    hasher: Hmac,
    state: [32]u8,
    absorbing: bool,

    pub fn init(label: []const u8) Sponge {
        var s: Sponge = .{ .hasher = Hmac.init(&[_]u8{0} ** 32), .state = [_]u8{0} ** 32, .absorbing = false };
        s.absorbRatchet(label);
        return s;
    }

    pub fn absorb(s: *Sponge, input: []const u8) void {
        if (!s.absorbing) {
            s.hasher = Hmac.init(&s.state);
            s.absorbing = true;
        }
        s.hasher.update(input);
    }

    pub fn ratchet(s: *Sponge) void {
        if (!s.absorbing) return;
        s.hasher.update(&[_]u8{0});
        s.hasher.final(&s.state);
        s.absorbing = false;
    }

    pub fn absorbRatchet(s: *Sponge, input: []const u8) void {
        s.absorb(input);
        s.ratchet();
    }

    pub fn squeeze(s: *Sponge, out: []u8) void {
        std.debug.assert(!s.absorbing);
        const prefix = Hmac.init(&s.state);
        var i: u64 = 0;
        var done: usize = 0;
        while (done < out.len) : (i += 1) {
            var h = prefix;
            var counter: [8]u8 = undefined;
            std.mem.writeInt(u64, &counter, i, .big);
            h.update(&counter);
            h.update(&[_]u8{1});
            var digest: [32]u8 = undefined;
            h.final(&digest);
            const n = @min(32, out.len - done);
            @memcpy(out[done .. done + n], digest[0..n]);
            done += n;
        }
        var next = prefix;
        var total: [8]u8 = undefined;
        std.mem.writeInt(u64, &total, out.len, .big);
        next.update(&total);
        next.update(&[_]u8{2});
        next.final(&s.state);
    }

    pub fn squeezeArray(s: *Sponge, comptime n: usize) [n]u8 {
        var out: [n]u8 = undefined;
        s.squeeze(&out);
        return out;
    }

    pub fn point(s: *Sponge) Ristretto255 {
        return Ristretto255.fromUniform(s.squeezeArray(64));
    }

    pub fn scalarValue(s: *Sponge) [32]u8 {
        return scalar.reduce64(s.squeezeArray(64));
    }
};

test "the squeeze matches the fixed vector" {
    var s = Sponge.init("asd");
    s.absorbRatchet("asdasd");
    const out = s.squeezeArray(64);
    const expected = [_]u8{
        0x39, 0x2c, 0xb9, 0x44, 0x93, 0x73, 0x03, 0x7f, 0xa0, 0xc1, 0x1a, 0xeb, 0xed, 0x69, 0xcc, 0xa3,
        0xb7, 0xd3, 0xbc, 0x97, 0x90, 0x87, 0x8f, 0x34, 0x17, 0x29, 0xc6, 0x5d, 0x55, 0x06, 0x44, 0x2f,
        0x04, 0x98, 0x6c, 0xb5, 0xc9, 0x09, 0x8f, 0x27, 0x7c, 0x3e, 0xa6, 0x40, 0xa4, 0xdc, 0x6e, 0x90,
        0x37, 0x2b, 0x43, 0x3a, 0x90, 0xaf, 0x9a, 0xea, 0x70, 0x72, 0xea, 0xba, 0x33, 0x98, 0xc4, 0xfe,
    };
    try std.testing.expectEqualSlices(u8, &expected, &out);
    var again = Sponge.init("asd");
    again.absorbRatchet("asdasd");
    const longer = again.squeezeArray(65);
    try std.testing.expectEqualSlices(u8, &expected, longer[0..64]);
    try std.testing.expectEqual(@as(u8, 0x7a), longer[64]);
}

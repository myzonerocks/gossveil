//! ML-KEM-768 split in two: the first capsule half needs only the public
//! seed and the key hash (the header), the second needs the full
//! encapsulation key. What is carried between the halves has a fixed byte
//! layout so a session can move between implementations mid-exchange.
//! The polynomial arithmetic follows the standard library's lattice code.
const std = @import("std");
const builtin = @import("builtin");
const sha3 = std.crypto.hash.sha3;
const math = std.math;
const entropy = @import("../../entropy.zig");

const Standard = std.crypto.kem.ml_kem.MLKem768;

const k: u8 = 3;
const eta1: u8 = 2;
const eta2: u8 = 2;
const du: u8 = 10;
const dv: u8 = 4;
const n: usize = 256;
const q: i16 = 3329;
const mont: i32 = 1 << 16;

pub const header_length: usize = 64;
pub const encap_length: usize = 1152;
pub const first_length: usize = 960;
pub const second_length: usize = 128;
pub const decap_length: usize = 2400;
/// r in the NTT domain (three polynomials of i16), e2 (i16) and the message.
pub const carry_length: usize = 3 * n * 2 + n * 2 + 32;
pub const seed_length: usize = 64;

pub const Keys = struct {
    header: [header_length]u8,
    encap: [encap_length]u8,
    decap: [decap_length]u8,
};

pub fn generate(seed: [seed_length]u8) !Keys {
    const pair = try Standard.KeyPair.generateDeterministic(seed);
    const pk = pair.public_key.toBytes();
    var out: Keys = undefined;
    out.header[0..32].* = pk[encap_length..][0..32].*;
    sha3.Sha3_256.hash(&pk, out.header[32..64], .{});
    out.encap = pk[0..encap_length].*;
    out.decap = pair.secret_key.toBytes();
    return out;
}

pub const First = struct {
    capsule: [first_length]u8,
    carry: [carry_length]u8,
    shared: [32]u8,
};

pub fn firstHalf(header: *const [header_length]u8, message: *const [32]u8) First {
    const rho = header[0..32];
    const key_hash = header[32..64];
    var kr: [64]u8 = undefined;
    var g = sha3.Sha3_512.init(.{});
    g.update(message);
    g.update(key_hash);
    g.final(&kr);
    const r_seed = kr[32..64];

    const V = Vec(k);
    const rh = V.noise(eta1, 0, r_seed).ntt().barrett().normalize();
    const e1 = V.noise(eta2, k, r_seed);
    const e2 = polyNoise(eta2, 2 * k, r_seed);
    const at = matrix(rho.*, true);
    var u: V = undefined;
    for (0..k) |i| u.ps[i] = at.rows[i].dotHat(rh);
    u = u.barrett().invNtt().add(e1).normalize();

    var out: First = undefined;
    out.capsule = u.compress(du);
    out.shared = kr[0..32].*;
    var off: usize = 0;
    for (0..k) |i| {
        for (rh.ps[i].cs) |c| {
            std.mem.writeInt(i16, out.carry[off..][0..2], c, .little);
            off += 2;
        }
    }
    for (e2.cs) |c| {
        std.mem.writeInt(i16, out.carry[off..][0..2], c, .little);
        off += 2;
    }
    out.carry[off..][0..32].* = message.*;
    return out;
}

pub fn secondHalf(encap: *const [encap_length]u8, carry: *const [carry_length]u8) [second_length]u8 {
    const V = Vec(k);
    var th: V = undefined;
    inline for (0..k) |i| th.ps[i] = polyFromBytes(encap[i * 384 ..][0..384]).normalize();
    var rh: V = undefined;
    var off: usize = 0;
    for (0..k) |i| {
        for (&rh.ps[i].cs) |*c| {
            c.* = @intCast(@mod(@as(i32, std.mem.readInt(i16, carry[off..][0..2], .little)), q));
            off += 2;
        }
    }
    var e2: Poly = undefined;
    for (&e2.cs) |*c| {
        c.* = std.mem.readInt(i16, carry[off..][0..2], .little);
        off += 2;
    }
    const message = carry[off..][0..32];
    const v = th.dotHat(rh).barrett().invNtt().add(polyDecompress(1, message)).add(e2).normalize();
    return v.compress(dv);
}

pub fn open(decap: *const [decap_length]u8, first: *const [first_length]u8, second: *const [second_length]u8) ![32]u8 {
    var capsule: [first_length + second_length]u8 = undefined;
    capsule[0..first_length].* = first.*;
    capsule[first_length..].* = second.*;
    const sk = try Standard.SecretKey.fromBytes(decap);
    return sk.decaps(&capsule);
}

pub fn keyMatchesHeader(encap: *const [encap_length]u8, header: *const [header_length]u8) bool {
    var pk: [encap_length + 32]u8 = undefined;
    pk[0..encap_length].* = encap.*;
    pk[encap_length..].* = header[0..32].*;
    var h: [32]u8 = undefined;
    sha3.Sha3_256.hash(&pk, &h, .{});
    if (!std.crypto.timing_safe.eql([32]u8, h, header[32..64].*)) return false;
    _ = Standard.PublicKey.fromBytes(&pk) catch return false;
    return true;
}

test "the split encapsulation opens like the whole" {
    const keys = try generate(entropy.array(seed_length));
    const message = entropy.array(32);
    const first = firstHalf(&keys.header, &message);
    const second = secondHalf(&keys.encap, &first.carry);
    try std.testing.expectEqualSlices(u8, &first.shared, &try open(&keys.decap, &first.capsule, &second));
    try std.testing.expect(keyMatchesHeader(&keys.encap, &keys.header));
    var bad = keys.encap;
    bad[0] ^= 1;
    try std.testing.expect(!keyMatchesHeader(&bad, &keys.header));
}

const mont_mod_q: i32 = @rem(@as(i32, mont), q);
const mont2_mod_q: i32 = @rem(mont_mod_q * mont_mod_q, q);
const mont2_over_128: i32 = @mod(invertMod(@as(i32, 128), @as(i32, q)) * mont2_mod_q, q);
const zetas = computeZetas();

const inv_ntt_reductions = [_]i16{
    -1,  -1,  16,  17,  48,  49,  80,  81,  112, 113, 144, 145, 176, 177, 208, 209, 240, 241, -1,
    0,   1,   32,  33,  34,  35,  64,  65,  96,  97,  98,  99,  128, 129, 160, 161, 162, 163, 192,
    193, 224, 225, 226, 227, -1,  2,   3,   66,  67,  68,  69,  70,  71,  130, 131, 194, 195, 196,
    197, 198, 199, -1,  4,   5,   6,   7,   132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142,
    143, -1,  -1,
};

fn invertMod(a: i32, p: i32) i32 {
    var old_r: i32 = a;
    var r: i32 = p;
    var old_s: i32 = 1;
    var s: i32 = 0;
    while (r != 0) {
        const quotient = @divTrunc(old_r, r);
        const next_r = old_r - quotient * r;
        old_r = r;
        r = next_r;
        const next_s = old_s - quotient * s;
        old_s = s;
        s = next_s;
    }
    std.debug.assert(old_r == 1);
    return old_s;
}

fn computeZetas() [128]i16 {
    @setEvalBranchQuota(10000);
    var out: [128]i16 = undefined;
    for (&out, 0..) |*z, i| {
        const exponent = @bitReverse(@as(u7, @intCast(i)));
        var base: i32 = 17;
        var result: i32 = 1;
        var e: u7 = exponent;
        while (e > 0) : (e >>= 1) {
            if (e & 1 != 0) result = @rem(result * base, q);
            base = @rem(base * base, q);
        }
        z.* = csubq(feBarrett(feToMont(@intCast(result))));
    }
    return out;
}

fn montReduce(x: i32) i16 {
    const q_inv: i32 = comptime blk: {
        var inv: u32 = 1;
        const qu: u32 = @intCast(q);
        var j: usize = 0;
        while (j < 16) : (j += 1) inv = inv *% (2 -% qu *% inv);
        break :blk @intCast(inv & 0xFFFF);
    };
    const m: i16 = @truncate(@as(i32, @truncate(x *% q_inv)));
    const y = x - @as(i32, m) * @as(i32, q);
    return @bitCast(@as(u16, @truncate(@as(u32, @bitCast(y)) >> 16)));
}

fn feToMont(x: i16) i16 {
    return montReduce(@as(i32, x) * mont2_mod_q);
}

fn feBarrett(x: i16) i16 {
    return x -% @as(i16, @intCast((@as(i32, x) * 20159) >> 26)) *% q;
}

fn csubq(x: i16) i16 {
    var r = x;
    r -= q;
    r += (r >> 15) & q;
    return r;
}

const Poly = struct {
    cs: [n]i16,

    const encoded_length = n / 2 * 3;
    const zero: Poly = .{ .cs = .{0} ** n };

    fn add(a: Poly, b: Poly) Poly {
        var out: Poly = undefined;
        for (0..n) |i| out.cs[i] = a.cs[i] + b.cs[i];
        return out;
    }

    fn ntt(a: Poly) Poly {
        var p = a;
        var zi: usize = 0;
        var l = n >> 1;
        while (l > 1) : (l >>= 1) {
            var offset: usize = 0;
            while (offset < n - l) : (offset += 2 * l) {
                zi += 1;
                const z = @as(i32, zetas[zi]);
                for (offset..offset + l) |j| {
                    const t = montReduce(z * @as(i32, p.cs[j + l]));
                    p.cs[j + l] = p.cs[j] - t;
                    p.cs[j] += t;
                }
            }
        }
        return p;
    }

    fn invNtt(a: Poly) Poly {
        var zi: usize = 127;
        var ri: usize = 0;
        var p = a;
        var l: usize = 2;
        while (l < n) : (l <<= 1) {
            var offset: usize = 0;
            while (offset < n - l) : (offset += 2 * l) {
                const minus_zeta = @as(i32, zetas[zi]);
                zi -= 1;
                for (offset..offset + l) |j| {
                    const t = p.cs[j + l] - p.cs[j];
                    p.cs[j] += p.cs[j + l];
                    p.cs[j + l] = montReduce(minus_zeta * @as(i32, t));
                }
            }
            while (true) {
                const idx = inv_ntt_reductions[ri];
                ri += 1;
                if (idx < 0) break;
                p.cs[@intCast(idx)] = feBarrett(p.cs[@intCast(idx)]);
            }
        }
        for (0..n) |j| p.cs[j] = montReduce(mont2_over_128 * @as(i32, p.cs[j]));
        return p;
    }

    fn normalize(a: Poly) Poly {
        var out: Poly = undefined;
        for (0..n) |i| out.cs[i] = csubq(feBarrett(a.cs[i]));
        return out;
    }

    fn barrett(a: Poly) Poly {
        var out: Poly = undefined;
        for (0..n) |i| out.cs[i] = feBarrett(a.cs[i]);
        return out;
    }

    fn mulHat(a: Poly, b: Poly) Poly {
        var p: Poly = undefined;
        var zi: usize = 64;
        var i: usize = 0;
        while (i < n) : (i += 4) {
            const z = @as(i32, zetas[zi]);
            zi += 1;
            const a1b1 = montReduce(@as(i32, a.cs[i + 1]) * @as(i32, b.cs[i + 1]));
            const a0b0 = montReduce(@as(i32, a.cs[i]) * @as(i32, b.cs[i]));
            const a1b0 = montReduce(@as(i32, a.cs[i + 1]) * @as(i32, b.cs[i]));
            const a0b1 = montReduce(@as(i32, a.cs[i]) * @as(i32, b.cs[i + 1]));
            p.cs[i] = montReduce(a1b1 * z) + a0b0;
            p.cs[i + 1] = a0b1 + a1b0;
            const a3b3 = montReduce(@as(i32, a.cs[i + 3]) * @as(i32, b.cs[i + 3]));
            const a2b2 = montReduce(@as(i32, a.cs[i + 2]) * @as(i32, b.cs[i + 2]));
            const a3b2 = montReduce(@as(i32, a.cs[i + 3]) * @as(i32, b.cs[i + 2]));
            const a2b3 = montReduce(@as(i32, a.cs[i + 2]) * @as(i32, b.cs[i + 3]));
            p.cs[i + 2] = a2b2 - montReduce(a3b3 * z);
            p.cs[i + 3] = a2b3 + a3b2;
        }
        return p;
    }

    fn compressedSize(comptime d: u8) usize {
        return @divTrunc(n * d, 8);
    }

    fn compress(p: Poly, comptime d: u8) [compressedSize(d)]u8 {
        @setEvalBranchQuota(10000);
        const q_over_2: u32 = comptime @divTrunc(q, 2);
        const two_d_min_1: u32 = comptime (1 << d) - 1;
        var in_off: usize = 0;
        var out_off: usize = 0;
        const batch_size: usize = comptime math.lcm(d, 8);
        const in_batch_size: usize = comptime batch_size / d;
        const out_batch_size: usize = comptime batch_size / 8;
        const out_length: usize = comptime @divTrunc(n * d, 8);
        var out = [_]u8{0} ** out_length;
        while (in_off < n) {
            var in: [in_batch_size]u16 = undefined;
            inline for (0..in_batch_size) |i| {
                const t = @as(u24, @intCast(p.cs[in_off + i])) << d;
                comptime std.debug.assert(d <= 11);
                comptime std.debug.assert(((20642679 * @as(u64, q)) >> 36) == 1);
                const u: u32 = @intCast((@as(u64, t + q_over_2) * 20642679) >> 36);
                in[i] = @intCast(u & two_d_min_1);
            }
            comptime var in_shift: usize = 0;
            comptime var j: usize = 0;
            comptime var ci: usize = 0;
            inline while (ci < in_batch_size) : (j += 1) {
                comptime var todo: usize = 8;
                inline while (todo > 0) {
                    const out_shift = comptime 8 - todo;
                    out[out_off + j] |= @as(u8, @truncate((in[ci] >> in_shift) << out_shift));
                    const done = comptime @min(@min(d, todo), d - in_shift);
                    todo -= done;
                    in_shift += done;
                    if (in_shift == d) {
                        in_shift = 0;
                        ci += 1;
                    }
                }
            }
            in_off += in_batch_size;
            out_off += out_batch_size;
        }
        return out;
    }
};

fn polyFromBytes(buf: *const [Poly.encoded_length]u8) Poly {
    var out: Poly = undefined;
    for (0..comptime n / 2) |i| {
        const b0 = @as(i16, buf[3 * i]);
        const b1 = @as(i16, buf[3 * i + 1]);
        const b2 = @as(i16, buf[3 * i + 2]);
        out.cs[2 * i] = b0 | ((b1 & 0xf) << 8);
        out.cs[2 * i + 1] = (b1 >> 4) | b2 << 4;
    }
    return out;
}

fn polyDecompress(comptime d: u8, in: *const [Poly.compressedSize(d)]u8) Poly {
    @setEvalBranchQuota(10000);
    var out: Poly = undefined;
    var in_off: usize = 0;
    var out_off: usize = 0;
    const batch_size: usize = comptime math.lcm(d, 8);
    const in_batch_size: usize = comptime batch_size / 8;
    const out_batch_size: usize = comptime batch_size / d;
    while (out_off < n) {
        comptime var in_shift: usize = 0;
        comptime var j: usize = 0;
        comptime var ci: usize = 0;
        inline while (ci < out_batch_size) : (ci += 1) {
            comptime var todo = d;
            var value: u16 = 0;
            inline while (todo > 0) {
                const out_shift = comptime d - todo;
                const m = comptime (1 << d) - 1;
                value |= (@as(u16, in[in_off + j] >> in_shift) << out_shift) & m;
                const done = comptime @min(@min(8, todo), 8 - in_shift);
                todo -= done;
                in_shift += done;
                if (in_shift == 8) {
                    in_shift = 0;
                    j += 1;
                }
            }
            const qx = @as(u32, value) * @as(u32, q);
            out.cs[out_off + ci] = @as(i16, @intCast((qx + (1 << (d - 1))) >> d));
        }
        in_off += in_batch_size;
        out_off += out_batch_size;
    }
    return out;
}

fn polyNoise(comptime eta: u8, nonce: u8, seed: *const [32]u8) Poly {
    var h = sha3.Shake256.init(.{});
    h.update(seed);
    h.update(&[1]u8{nonce});
    const buf_len = comptime 2 * eta * n / 8;
    var buf: [buf_len]u8 = undefined;
    h.squeeze(&buf);
    const T = switch (builtin.target.cpu.arch) {
        .x86_64, .x86 => u32,
        else => u64,
    };
    comptime var batch_count: usize = undefined;
    comptime var batch_bytes: usize = undefined;
    comptime var mask: T = 0;
    comptime {
        batch_count = @bitSizeOf(T) / @as(usize, 2 * eta);
        while (@rem(n, batch_count) != 0 and batch_count > 0) : (batch_count -= 1) {}
        std.debug.assert(batch_count > 0);
        std.debug.assert(@rem(2 * eta * batch_count, 8) == 0);
        batch_bytes = 2 * eta * batch_count / 8;
        for (0..2 * eta * batch_count) |_| {
            mask <<= eta;
            mask |= 1;
        }
    }
    var out: Poly = undefined;
    for (0..comptime n / batch_count) |i| {
        var t: T = 0;
        inline for (0..batch_bytes) |j| t |= @as(T, buf[batch_bytes * i + j]) << (8 * j);
        var d: T = 0;
        inline for (0..eta) |j| d += (t >> j) & mask;
        inline for (0..batch_count) |j| {
            const mask2 = comptime (1 << eta) - 1;
            const a = @as(i16, @intCast((d >> (comptime (2 * j * eta))) & mask2));
            const b = @as(i16, @intCast((d >> (comptime ((2 * j + 1) * eta))) & mask2));
            out.cs[batch_count * i + j] = a - b;
        }
    }
    return out;
}

fn polyUniform(seed: [32]u8, x: u8, y: u8) Poly {
    var h = sha3.Shake128.init(.{});
    h.update(&seed);
    h.update(&[2]u8{ x, y });
    const buf_len = sha3.Shake128.block_length;
    var buf: [buf_len]u8 = undefined;
    var out: Poly = undefined;
    var filled: usize = 0;
    outer: while (true) {
        h.squeeze(&buf);
        var j: usize = 0;
        while (j < buf_len) : (j += 3) {
            const b0 = @as(u16, buf[j]);
            const b1 = @as(u16, buf[j + 1]);
            const b2 = @as(u16, buf[j + 2]);
            const ts: [2]u16 = .{ b0 | ((b1 & 0xf) << 8), (b1 >> 4) | (b2 << 4) };
            inline for (ts) |t| {
                if (t < q) {
                    out.cs[filled] = @intCast(t);
                    filled += 1;
                    if (filled == n) break :outer;
                }
            }
        }
    }
    return out;
}

fn Vec(comptime size: u8) type {
    return struct {
        ps: [size]Poly,

        const Self = @This();

        fn compressedSize(comptime d: u8) usize {
            return Poly.compressedSize(d) * size;
        }

        fn ntt(v: Self) Self {
            var out: Self = undefined;
            inline for (0..size) |i| out.ps[i] = v.ps[i].ntt();
            return out;
        }

        fn invNtt(v: Self) Self {
            var out: Self = undefined;
            inline for (0..size) |i| out.ps[i] = v.ps[i].invNtt();
            return out;
        }

        fn normalize(v: Self) Self {
            var out: Self = undefined;
            inline for (0..size) |i| out.ps[i] = v.ps[i].normalize();
            return out;
        }

        fn barrett(v: Self) Self {
            var out: Self = undefined;
            inline for (0..size) |i| out.ps[i] = v.ps[i].barrett();
            return out;
        }

        fn add(a: Self, b: Self) Self {
            var out: Self = undefined;
            inline for (0..size) |i| out.ps[i] = a.ps[i].add(b.ps[i]);
            return out;
        }

        fn noise(comptime eta: u8, nonce: u8, seed: *const [32]u8) Self {
            var out: Self = undefined;
            for (0..size) |i| out.ps[i] = polyNoise(eta, nonce + @as(u8, @intCast(i)), seed);
            return out;
        }

        fn dotHat(a: Self, b: Self) Poly {
            var out: Poly = Poly.zero;
            for (0..size) |i| out = out.add(a.ps[i].mulHat(b.ps[i]));
            return out;
        }

        fn compress(v: Self, comptime d: u8) [compressedSize(d)]u8 {
            const cs = comptime Poly.compressedSize(d);
            var out: [compressedSize(d)]u8 = undefined;
            inline for (0..size) |i| out[i * cs .. (i + 1) * cs].* = v.ps[i].compress(d);
            return out;
        }
    };
}

const Matrix = struct { rows: [k]Vec(k) };

fn matrix(seed: [32]u8, comptime transposed: bool) Matrix {
    var out: Matrix = undefined;
    var i: u8 = 0;
    while (i < k) : (i += 1) {
        var j: u8 = 0;
        while (j < k) : (j += 1) {
            out.rows[i].ps[j] = polyUniform(seed, if (transposed) i else j, if (transposed) j else i);
        }
    }
    return out;
}

//! Arithmetic in GF(2^16), reduced by x^16 + x^12 + x^3 + x + 1.
const std = @import("std");

const modulus: u32 = 0x1100b;

pub fn add(a: u16, b: u16) u16 {
    return a ^ b;
}

pub fn mul(a: u16, b: u16) u16 {
    var product: u32 = 0;
    var bit: u5 = 0;
    while (bit < 16) : (bit += 1) {
        if ((b >> @intCast(bit)) & 1 != 0) product ^= @as(u32, a) << bit;
    }
    return reduce(product);
}

fn reduce(x: u32) u16 {
    var v = x;
    var bit: u5 = 31;
    while (true) : (bit -= 1) {
        if (v & (@as(u32, 1) << bit) != 0) v ^= modulus << (bit - 16);
        if (bit == 16) break;
    }
    return @truncate(v);
}

/// a / b as a times b to the power 2^16 - 2, fifteen squarings.
pub fn div(a: u16, b: u16) u16 {
    var power = mul(b, b);
    var out = a;
    var i: usize = 1;
    while (i < 16) : (i += 1) {
        out = mul(out, power);
        power = mul(power, power);
    }
    return out;
}

test "the field behaves" {
    try std.testing.expectEqual(@as(u16, 1), mul(1, 1));
    try std.testing.expectEqual(@as(u16, 0), mul(0x1234, 0));
    const a: u16 = 0xBEEF;
    const b: u16 = 0x1357;
    try std.testing.expectEqual(mul(a, b), mul(b, a));
    try std.testing.expectEqual(a, mul(div(a, b), b));
    try std.testing.expectEqual(@as(u16, 1), div(b, b));
    try std.testing.expectEqual(mul(a, add(b, 7)), add(mul(a, b), mul(a, 7)));
}

//! The symmetric ciphers: AES-256 in CBC with PKCS#7 padding (message
//! bodies), in CTR (envelopes), with GCM (sealed content) and with GCM-SIV
//! (the surfaces' general form).
const std = @import("std");
const mem = std.mem;
const Aes256 = std.crypto.core.aes.Aes256;
const Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
const GcmSiv = std.crypto.aead.aes_gcm_siv.Aes256GcmSiv;
const Fault = @import("../fault.zig").Fault;

pub fn cbcSeal(allocator: mem.Allocator, key: [32]u8, iv: [16]u8, plain: []const u8) ![]u8 {
    const pad: u8 = @intCast(16 - (plain.len % 16));
    const out = try allocator.alloc(u8, plain.len + pad);
    const enc = Aes256.initEnc(key);
    var prev = iv;
    var i: usize = 0;
    while (i < out.len) : (i += 16) {
        var block: [16]u8 = undefined;
        for (0..16) |j| {
            const p = i + j;
            block[j] = (if (p < plain.len) plain[p] else pad) ^ prev[j];
        }
        enc.encrypt(&prev, &block);
        out[i..][0..16].* = prev;
    }
    return out;
}

pub fn cbcOpen(allocator: mem.Allocator, key: [32]u8, iv: [16]u8, sealed: []const u8) ![]u8 {
    if (sealed.len == 0 or sealed.len % 16 != 0) return Fault.BadMessage;
    const out = try allocator.alloc(u8, sealed.len);
    errdefer allocator.free(out);
    const dec = Aes256.initDec(key);
    var prev = iv;
    var i: usize = 0;
    while (i < sealed.len) : (i += 16) {
        const block = sealed[i..][0..16].*;
        var plain: [16]u8 = undefined;
        dec.decrypt(&plain, &block);
        for (0..16) |j| out[i + j] = plain[j] ^ prev[j];
        prev = block;
    }
    const pad = out[out.len - 1];
    if (pad == 0 or pad > 16) return Fault.BadPadding;
    for (out[out.len - pad ..]) |b| if (b != pad) return Fault.BadPadding;
    return allocator.realloc(out, out.len - pad);
}

/// CTR keeps the length; the same call seals and opens.
pub fn ctr(key: [32]u8, iv: [16]u8, input: []const u8, output: []u8) void {
    const enc = Aes256.initEnc(key);
    var counter = iv;
    var i: usize = 0;
    while (i < input.len) {
        var stream: [16]u8 = undefined;
        enc.encrypt(&stream, &counter);
        var j: usize = 16;
        while (j > 0) {
            j -= 1;
            counter[j] +%= 1;
            if (counter[j] != 0) break;
        }
        const n = @min(16, input.len - i);
        for (0..n) |k| output[i + k] = input[i + k] ^ stream[k];
        i += n;
    }
}

pub fn gcmSeal(allocator: mem.Allocator, key: [32]u8, nonce: [12]u8, plain: []const u8, aad: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, plain.len + Gcm.tag_length);
    var tag: [Gcm.tag_length]u8 = undefined;
    Gcm.encrypt(out[0..plain.len], &tag, plain, aad, nonce, key);
    @memcpy(out[plain.len..], &tag);
    return out;
}

pub fn gcmOpen(allocator: mem.Allocator, key: [32]u8, nonce: [12]u8, sealed: []const u8, aad: []const u8) ![]u8 {
    if (sealed.len < Gcm.tag_length) return Fault.BadMessage;
    const body = sealed.len - Gcm.tag_length;
    const out = try allocator.alloc(u8, body);
    errdefer allocator.free(out);
    Gcm.decrypt(out, sealed[0..body], sealed[body..][0..Gcm.tag_length].*, aad, nonce, key) catch return Fault.BadMessage;
    return out;
}

pub fn sivSeal(allocator: mem.Allocator, key: [32]u8, nonce: [12]u8, plain: []const u8, aad: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, plain.len + GcmSiv.tag_length);
    var tag: [GcmSiv.tag_length]u8 = undefined;
    GcmSiv.encrypt(out[0..plain.len], &tag, plain, aad, nonce, key);
    @memcpy(out[plain.len..], &tag);
    return out;
}

pub fn sivOpen(allocator: mem.Allocator, key: [32]u8, nonce: [12]u8, sealed: []const u8, aad: []const u8) ![]u8 {
    if (sealed.len < GcmSiv.tag_length) return Fault.BadMessage;
    const body = sealed.len - GcmSiv.tag_length;
    const out = try allocator.alloc(u8, body);
    errdefer allocator.free(out);
    GcmSiv.decrypt(out, sealed[0..body], sealed[body..][0..GcmSiv.tag_length].*, aad, nonce, key) catch return Fault.BadMessage;
    return out;
}

test "cbc pads every length and refuses a bad pad" {
    const a = std.testing.allocator;
    const key = [_]u8{0x42} ** 32;
    const iv = [_]u8{0x24} ** 16;
    var len: usize = 0;
    while (len < 40) : (len += 1) {
        const msg = try a.alloc(u8, len);
        defer a.free(msg);
        for (msg, 0..) |*b, i| b.* = @intCast(i);
        const sealed = try cbcSeal(a, key, iv, msg);
        defer a.free(sealed);
        try std.testing.expectEqual((len / 16 + 1) * 16, sealed.len);
        const plain = try cbcOpen(a, key, iv, sealed);
        defer a.free(plain);
        try std.testing.expectEqualSlices(u8, msg, plain);
    }
    try std.testing.expectError(Fault.BadMessage, cbcOpen(a, key, iv, "short"));
}

test "ctr, gcm and gcm-siv round trip" {
    const a = std.testing.allocator;
    const key = [_]u8{7} ** 32;
    var out: [5]u8 = undefined;
    ctr(key, [_]u8{1} ** 16, "hello", &out);
    var back: [5]u8 = undefined;
    ctr(key, [_]u8{1} ** 16, &out, &back);
    try std.testing.expectEqualStrings("hello", &back);
    const g = try gcmSeal(a, key, [_]u8{2} ** 12, "plain", "aad");
    defer a.free(g);
    const gp = try gcmOpen(a, key, [_]u8{2} ** 12, g, "aad");
    defer a.free(gp);
    try std.testing.expectEqualStrings("plain", gp);
    try std.testing.expectError(Fault.BadMessage, gcmOpen(a, key, [_]u8{2} ** 12, g, "x"));
    const s = try sivSeal(a, key, [_]u8{3} ** 12, "plain", "");
    defer a.free(s);
    const sp = try sivOpen(a, key, [_]u8{3} ** 12, s, "");
    defer a.free(sp);
    try std.testing.expectEqualStrings("plain", sp);
}

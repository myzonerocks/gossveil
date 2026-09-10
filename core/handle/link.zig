//! A username link: the name sealed under keys derived from a random entropy
//! the user shares out of band, padded so its length says nothing.
const std = @import("std");
const derive = @import("../keys/derive.zig");
const cipher = @import("../keys/cipher.zig");
const codec = @import("../wire/codec.zig");
const entropy = @import("../entropy.zig");
const Handle = @import("name.zig").Handle;
const Fault = @import("../fault.zig").Fault;
const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
const mem = std.mem;
const Allocator = mem.Allocator;

pub const entropy_length = 32;
const iv_length = 16;
const tag_length = 32;

pub const LinkError = error{ BadEntropy, BadLink };

pub const Link = struct {
    entropy: [entropy_length]u8,
    sealed: []u8,
};

fn key(e: [entropy_length]u8, label: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    derive.hkdf(&out, &e, null, label);
    return out;
}

/// Seals a name for a link, reusing `previous` when given so an existing link keeps working.
pub fn create(allocator: Allocator, name: []const u8, previous: ?[entropy_length]u8) !Link {
    const e = previous orelse entropy.array(entropy_length);
    var w = codec.Writer.init(allocator);
    defer w.deinit();
    try w.bytesIfSet(1, name);
    const pad_len = (16 * 3) -| name.len;
    const pad = try allocator.alloc(u8, pad_len);
    defer allocator.free(pad);
    @memset(pad, 0);
    try w.bytesIfSet(2, pad);
    if (w.buf.items.len >= 16 * 4) return Fault.BadArgument;
    const iv = entropy.array(iv_length);
    const body = try cipher.cbcSeal(allocator, key(e, "Signal Username Link Encryption Key"), iv, w.buf.items);
    defer allocator.free(body);
    const out = try allocator.alloc(u8, iv_length + body.len + tag_length);
    out[0..iv_length].* = iv;
    @memcpy(out[iv_length..][0..body.len], body);
    const mac_key = key(e, "Signal Username Link Authentication Key");
    Hmac.create(out[iv_length + body.len ..][0..tag_length], out[0 .. iv_length + body.len], &mac_key);
    return .{ .entropy = e, .sealed = out };
}

pub fn open(allocator: Allocator, e_bytes: []const u8, sealed: []const u8) ![]u8 {
    if (e_bytes.len != entropy_length) return LinkError.BadEntropy;
    if (sealed.len < iv_length + 16 + tag_length) return LinkError.BadLink;
    const e = e_bytes[0..entropy_length].*;
    const authed = sealed[0 .. sealed.len - tag_length];
    const mac_key = key(e, "Signal Username Link Authentication Key");
    var expected: [tag_length]u8 = undefined;
    Hmac.create(&expected, authed, &mac_key);
    if (!std.crypto.timing_safe.eql([tag_length]u8, expected, sealed[authed.len..][0..tag_length].*)) return LinkError.BadLink;
    const plain = cipher.cbcOpen(allocator, key(e, "Signal Username Link Encryption Key"), authed[0..iv_length].*, authed[iv_length..]) catch return LinkError.BadLink;
    defer allocator.free(plain);
    var name: ?[]const u8 = null;
    var r = codec.Reader.init(plain);
    while (r.next() catch return LinkError.BadLink) |f| if (f.number == 1) {
        name = f.bytes();
    };
    const n = name orelse return LinkError.BadLink;
    _ = Handle.parse(n) catch return LinkError.BadLink;
    return allocator.dupe(u8, n);
}

test "a link round trips its name and keeps its entropy" {
    const a = std.testing.allocator;
    const link = try create(a, "plain_user.42", null);
    defer a.free(link.sealed);
    const back = try open(a, &link.entropy, link.sealed);
    defer a.free(back);
    try std.testing.expectEqualStrings("plain_user.42", back);
    const again = try create(a, "plain_user.42", link.entropy);
    defer a.free(again.sealed);
    try std.testing.expectEqualSlices(u8, &link.entropy, &again.entropy);
    try std.testing.expectError(LinkError.BadLink, open(a, &again.entropy, link.sealed[0 .. link.sealed.len - 1]));
}

//! The single-recipient envelope: an ephemeral key, the sender's identity
//! sealed under an ephemeral agreement, and the content sealed under a static
//! agreement. Opening dispatches on the version nibble to this form or the
//! many-recipient form.
const std = @import("std");
const curve = @import("../keys/curve.zig");
const derive = @import("../keys/derive.zig");
const cipher = @import("../keys/cipher.zig");
const identity = @import("../keys/identity.zig");
const codec = @import("../wire/codec.zig");
const Content = @import("content.zig").Content;
const multiseal = @import("multiseal.zig");
const Fault = @import("../fault.zig").Fault;
const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
const mem = std.mem;
const Allocator = mem.Allocator;

pub const version_byte: u8 = 0x11;
const short_tag_length = 10;

/// AES-256-CTR with a zero nonce, then the first ten bytes of an HMAC over the ciphertext.
fn ctrSeal(allocator: Allocator, plain: []const u8, key: [32]u8, mac_key: [32]u8) ![]u8 {
    const out = try allocator.alloc(u8, plain.len + short_tag_length);
    cipher.ctr(key, [_]u8{0} ** 16, plain, out[0..plain.len]);
    var tag: [32]u8 = undefined;
    Hmac.create(&tag, out[0..plain.len], &mac_key);
    @memcpy(out[plain.len..], tag[0..short_tag_length]);
    return out;
}

fn ctrOpen(allocator: Allocator, sealed: []const u8, key: [32]u8, mac_key: [32]u8) ![]u8 {
    if (sealed.len < short_tag_length) return Fault.BadMessage;
    const body = sealed[0 .. sealed.len - short_tag_length];
    var tag: [32]u8 = undefined;
    Hmac.create(&tag, body, &mac_key);
    if (!std.crypto.timing_safe.eql([short_tag_length]u8, tag[0..short_tag_length].*, sealed[body.len..][0..short_tag_length].*)) return Fault.BadMessage;
    const out = try allocator.alloc(u8, body.len);
    cipher.ctr(key, [_]u8{0} ** 16, body, out);
    return out;
}

pub const Way = enum { sending, receiving };

const EphemeralKeys = struct { chain: [32]u8, cipher: [32]u8, mac: [32]u8 };

fn ephemeralKeys(our_secret: curve.Secret, our_public: curve.Public, their_public: curve.Public, way: Way) !EphemeralKeys {
    var salt: ["UnidentifiedDelivery".len + 66]u8 = undefined;
    salt[0..20].* = "UnidentifiedDelivery".*;
    const first = if (way == .sending) their_public else our_public;
    const second = if (way == .sending) our_public else their_public;
    salt[20..53].* = first.serialize();
    salt[53..86].* = second.serialize();
    const shared = try our_secret.agree(their_public);
    var out: [96]u8 = undefined;
    derive.hkdf(&out, &shared, &salt, "");
    return .{ .chain = out[0..32].*, .cipher = out[32..64].*, .mac = out[64..96].* };
}

const StaticKeys = struct { cipher: [32]u8, mac: [32]u8 };

fn staticKeys(allocator: Allocator, our_secret: curve.Secret, their_public: curve.Public, chain: [32]u8, sealed: []const u8) !StaticKeys {
    const salt = try allocator.alloc(u8, 32 + sealed.len);
    defer allocator.free(salt);
    salt[0..32].* = chain;
    @memcpy(salt[32..], sealed);
    const shared = try our_secret.agree(their_public);
    var out: [96]u8 = undefined;
    derive.hkdf(&out, &shared, salt, "");
    return .{ .cipher = out[32..64].*, .mac = out[64..96].* };
}

/// The caller resolved the recipient's identity from its store and trusts it.
pub fn seal(allocator: Allocator, us: identity.IdentityPair, them: curve.Public, content: *const Content) ![]u8 {
    const ephemeral = try curve.Pair.generate();
    const eph = try ephemeralKeys(ephemeral.secret, ephemeral.public, them, .sending);
    const sealed_static = try ctrSeal(allocator, &us.identity.key.serialize(), eph.cipher, eph.mac);
    defer allocator.free(sealed_static);
    const statics = try staticKeys(allocator, us.secret, them, eph.chain, sealed_static);
    const sealed_content = try ctrSeal(allocator, content.bytes, statics.cipher, statics.mac);
    defer allocator.free(sealed_content);
    var w = codec.Writer.init(allocator);
    defer w.deinit();
    try w.buf.append(allocator, version_byte);
    try w.bytes(1, &ephemeral.public.serialize());
    try w.bytes(2, sealed_static);
    try w.bytes(3, sealed_content);
    return w.finish();
}

/// Opens either envelope form to its content, checked against the key that
/// sealed it. Certificate trust is the caller's.
pub fn open(allocator: Allocator, us: identity.IdentityPair, data: []const u8) !Content {
    if (data.len == 0) return Fault.BadMessage;
    return switch (data[0] >> 4) {
        0, 1 => openSingle(allocator, us, data[1..]),
        2 => multiseal.openReceived(allocator, us, data[1..]),
        else => Fault.UnknownVersion,
    };
}

fn openSingle(allocator: Allocator, us: identity.IdentityPair, body: []const u8) !Content {
    var ephemeral: ?curve.Public = null;
    var sealed_static: ?[]const u8 = null;
    var sealed_content: ?[]const u8 = null;
    var r = codec.Reader.init(body);
    while (r.next() catch return Fault.BadMessage) |f| switch (f.number) {
        1 => ephemeral = try curve.Public.parse(f.bytes() orelse return Fault.BadMessage),
        2 => sealed_static = f.bytes(),
        3 => sealed_content = f.bytes(),
        else => {},
    };
    const e = ephemeral orelse return Fault.BadMessage;
    const ss = sealed_static orelse return Fault.BadMessage;
    const sc = sealed_content orelse return Fault.BadMessage;
    const eph = try ephemeralKeys(us.secret, us.identity.key, e, .receiving);
    const static_bytes = try ctrOpen(allocator, ss, eph.cipher, eph.mac);
    defer allocator.free(static_bytes);
    const static_key = try curve.Public.parse(static_bytes);
    const statics = try staticKeys(allocator, us.secret, static_key, eph.chain, ss);
    const content_bytes = try ctrOpen(allocator, sc, statics.cipher, statics.mac);
    defer allocator.free(content_bytes);
    var content = try Content.parse(allocator, content_bytes);
    errdefer content.deinit();
    if (!content.sender.sender_key.eql(static_key)) return Fault.BadMessage;
    return content;
}

test "a sealed envelope opens for its recipient only" {
    const certificate = @import("certificate.zig");
    const a = std.testing.allocator;
    const trust = try curve.Pair.generate();
    const server = try curve.Pair.generate();
    const alice = try identity.IdentityPair.generate();
    const bob = try identity.IdentityPair.generate();
    var sc = try certificate.ServerCert.make(a, 1, server.public, trust.secret);
    defer sc.deinit();
    var cert = try certificate.SenderCert.make(a, .{ .sender_id = "9d0652a3-dcc3-4d11-975f-74d61598733f", .sender_phone = "+14155550100", .sender_device = 2, .sender_key = alice.identity.key, .expires_ms = 1000, .server = &sc, .server_secret = server.secret });
    defer cert.deinit();
    var content = try Content.make(a, .whisper, &cert, "ciphertext body", .resendable, "circle");
    defer content.deinit();
    const sealed = try seal(a, alice, bob.identity.key, &content);
    defer a.free(sealed);
    var opened = try open(a, bob, sealed);
    defer opened.deinit();
    try std.testing.expectEqualStrings("ciphertext body", opened.body);
    try std.testing.expectEqual(@import("content.zig").Hint.resendable, opened.hint);
    try std.testing.expectEqualStrings("circle", opened.circle_id.?);
    try std.testing.expectEqualStrings("+14155550100", opened.sender.sender_phone.?);
    try std.testing.expectError(Fault.BadMessage, open(a, alice, sealed));
}

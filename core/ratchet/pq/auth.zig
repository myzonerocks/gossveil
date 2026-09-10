//! Authentication of the post-quantum ratchet's headers and capsules: a root
//! key that moves with every epoch and a MAC key derived beside it.
const std = @import("std");
const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;

pub const tag_length = 32;
pub const Tag = [tag_length]u8;

const update_label = "Signal_PQCKA_V1_MLKEM768:Authenticator Update";
const header_label = "Signal_PQCKA_V1_MLKEM768:ekheader";
const capsule_label = "Signal_PQCKA_V1_MLKEM768:ciphertext";

pub const Auth = struct {
    root: [32]u8,
    mac: [32]u8,

    pub fn init(root: []const u8, epoch: u64) Auth {
        var a: Auth = .{ .root = [_]u8{0} ** 32, .mac = [_]u8{0} ** 32 };
        a.advance(epoch, root);
        return a;
    }

    /// The next root and MAC keys from the current root, a new secret and the epoch.
    pub fn advance(a: *Auth, epoch: u64, secret: []const u8) void {
        var material: [96]u8 = undefined;
        material[0..32].* = a.root;
        @memcpy(material[32 .. 32 + secret.len], secret);
        var info: [update_label.len + 8]u8 = undefined;
        info[0..update_label.len].* = update_label.*;
        std.mem.writeInt(u64, info[update_label.len..][0..8], epoch, .big);
        var out: [64]u8 = undefined;
        Hkdf.expand(&out, &info, Hkdf.extract(&([_]u8{0} ** 32), material[0 .. 32 + secret.len]));
        a.root = out[0..32].*;
        a.mac = out[32..64].*;
    }

    fn tagOf(a: *const Auth, label: []const u8, epoch: u64, data: []const u8) Tag {
        var epoch_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &epoch_bytes, epoch, .big);
        var h = Hmac.init(&a.mac);
        h.update(label);
        h.update(&epoch_bytes);
        h.update(data);
        var out: Tag = undefined;
        h.final(&out);
        return out;
    }

    pub fn tagHeader(a: *const Auth, epoch: u64, header: *const [64]u8) Tag {
        return a.tagOf(header_label, epoch, header);
    }

    pub fn tagCapsule(a: *const Auth, epoch: u64, capsule: []const u8) Tag {
        return a.tagOf(capsule_label, epoch, capsule);
    }

    pub fn checkHeader(a: *const Auth, epoch: u64, header: *const [64]u8, tag: *const Tag) bool {
        return std.crypto.timing_safe.eql(Tag, a.tagHeader(epoch, header), tag.*);
    }

    pub fn checkCapsule(a: *const Auth, epoch: u64, capsule: []const u8, tag: *const Tag) bool {
        return std.crypto.timing_safe.eql(Tag, a.tagCapsule(epoch, capsule), tag.*);
    }
};

test "two sides with the same root agree on tags" {
    var a = Auth.init("root", 1);
    var b = Auth.init("root", 1);
    const header = [_]u8{7} ** 64;
    try std.testing.expect(b.checkHeader(1, &header, &a.tagHeader(1, &header)));
    a.advance(2, "secret");
    try std.testing.expect(!b.checkHeader(1, &header, &a.tagHeader(1, &header)));
    b.advance(2, "secret");
    try std.testing.expect(b.checkCapsule(2, "capsule", &a.tagCapsule(2, "capsule")));
}

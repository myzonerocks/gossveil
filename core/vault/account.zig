//! Account-level keys: the entropy pool a user holds and every key derived
//! from it or from the backup key.
const std = @import("std");
const curve = @import("../keys/curve.zig");
const derive = @import("../keys/derive.zig");
const entropy = @import("../entropy.zig");
const ServiceId = @import("../ident/service.zig").ServiceId;
const Fault = @import("../fault.zig").Fault;

pub const pool_length = 64;
pub const backup_key_length = 32;
pub const backup_id_length = 16;
pub const media_id_length = 15;
pub const media_key_length = 64;
const alphabet = "0123456789abcdefghijklmnopqrstuvwxyz";

pub const EntropyPool = struct {
    chars: [pool_length]u8,

    pub fn random() EntropyPool {
        var out: EntropyPool = undefined;
        for (&out.chars) |*c| {
            var draw: u8 = undefined;
            // Rejection keeps every character equally likely.
            while (true) {
                draw = entropy.array(1)[0];
                if (draw < 252) break;
            }
            c.* = alphabet[draw % alphabet.len];
        }
        return out;
    }

    pub fn valid(source: []const u8) bool {
        if (source.len != pool_length) return false;
        for (source) |c| if (!std.ascii.isDigit(c) and !std.ascii.isLower(c)) return false;
        return true;
    }

    pub fn parse(source: []const u8) Fault!EntropyPool {
        if (!valid(source)) return Fault.BadArgument;
        return .{ .chars = source[0..pool_length].* };
    }

    pub fn text(p: *const EntropyPool) []const u8 {
        return &p.chars;
    }

    pub fn recoveryKey(p: *const EntropyPool) [32]u8 {
        var out: [32]u8 = undefined;
        derive.hkdf(&out, &p.chars, null, "20240801_SIGNAL_SVR_MASTER_KEY");
        return out;
    }

    pub fn backupKey(p: *const EntropyPool) BackupKey {
        var out: [backup_key_length]u8 = undefined;
        derive.hkdf(&out, &p.chars, null, "20240801_SIGNAL_BACKUP_KEY");
        return .{ .bytes = out };
    }
};

pub const BackupKey = struct {
    bytes: [backup_key_length]u8,

    pub fn random() BackupKey {
        return .{ .bytes = entropy.array(backup_key_length) };
    }

    fn expand(k: BackupKey, out: []u8, label: []const u8, suffix: []const u8) void {
        var info: [256]u8 = undefined;
        const total = label.len + suffix.len;
        std.debug.assert(total <= info.len);
        @memcpy(info[0..label.len], label);
        @memcpy(info[label.len..total], suffix);
        derive.hkdf(out, &k.bytes, null, info[0..total]);
    }

    pub fn backupId(k: BackupKey, account: ServiceId) [backup_id_length]u8 {
        var out: [backup_id_length]u8 = undefined;
        var sid: [17]u8 = undefined;
        k.expand(&out, "20241024_SIGNAL_BACKUP_ID:", account.compact(&sid));
        return out;
    }

    pub fn signingKey(k: BackupKey, account: ServiceId) curve.Secret {
        var out: [32]u8 = undefined;
        var sid: [17]u8 = undefined;
        k.expand(&out, "20241024_SIGNAL_BACKUP_ID_KEYPAIR:", account.compact(&sid));
        return curve.Secret.fromRaw(out);
    }

    pub fn localMetadataKey(k: BackupKey) [32]u8 {
        var out: [32]u8 = undefined;
        k.expand(&out, "20241011_SIGNAL_LOCAL_BACKUP_METADATA_KEY", "");
        return out;
    }

    pub fn mediaId(k: BackupKey, media_name: []const u8) Fault![media_id_length]u8 {
        if (media_name.len > 200) return Fault.BadArgument;
        var out: [media_id_length]u8 = undefined;
        k.expand(&out, "20241007_SIGNAL_BACKUP_MEDIA_ID:", media_name);
        return out;
    }

    /// An HMAC key followed by an AES-CBC key.
    pub fn mediaKey(k: BackupKey, media_id: [media_id_length]u8) [media_key_length]u8 {
        var out: [media_key_length]u8 = undefined;
        k.expand(&out, "20241007_SIGNAL_BACKUP_ENCRYPT_MEDIA:", &media_id);
        return out;
    }

    pub fn thumbnailKey(k: BackupKey, media_id: [media_id_length]u8) [media_key_length]u8 {
        var out: [media_key_length]u8 = undefined;
        k.expand(&out, "20241030_SIGNAL_BACKUP_ENCRYPT_THUMBNAIL:", &media_id);
        return out;
    }
};

test "a random pool is valid and derives stable keys" {
    const pool = EntropyPool.random();
    try std.testing.expect(EntropyPool.valid(pool.text()));
    const again = try EntropyPool.parse(pool.text());
    try std.testing.expectEqualSlices(u8, &pool.recoveryKey(), &again.recoveryKey());
    try std.testing.expectEqualSlices(u8, &pool.backupKey().bytes, &again.backupKey().bytes);
    try std.testing.expect(!EntropyPool.valid("too short"));
    const k = pool.backupKey();
    const id = try k.mediaId("photo");
    try std.testing.expect(!std.mem.eql(u8, &k.mediaKey(id), &k.thumbnailKey(id)));
}

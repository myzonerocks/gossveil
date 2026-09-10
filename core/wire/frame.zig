//! Framing bytes shared by the messages: the version byte that leads every
//! ratchet message and the type tags that lead keys and content.
const std = @import("std");
const Fault = @import("../fault.zig").Fault;

pub const current_version: u8 = 4;
pub const oldest_version: u8 = 3;
pub const curve_key_tag: u8 = 0x05;

/// The first byte of a ratchet message: the message's version in the high
/// nibble, the newest version the writer speaks in the low nibble.
pub fn versionByte(message_version: u8) u8 {
    return (message_version << 4) | current_version;
}

pub fn messageVersion(byte: u8) Fault!u8 {
    const v = byte >> 4;
    if (v < oldest_version) return Fault.LegacyVersion;
    if (v > current_version) return Fault.UnknownVersion;
    return v;
}

test "the version byte carries both nibbles" {
    try std.testing.expectEqual(@as(u8, 0x44), versionByte(4));
    try std.testing.expectEqual(@as(u8, 3), try messageVersion(0x34));
    try std.testing.expectError(Fault.LegacyVersion, messageVersion(0x24));
    try std.testing.expectError(Fault.UnknownVersion, messageVersion(0x54));
}

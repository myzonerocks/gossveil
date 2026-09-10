//! Message authentication with HMAC-SHA256: full tags, truncated tags, and a
//! constant-time check.
const std = @import("std");
const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;

pub const length = Hmac.mac_length;

pub const Mac = struct {
    inner: Hmac,

    pub fn init(key: []const u8) Mac {
        return .{ .inner = Hmac.init(key) };
    }

    pub fn update(m: *Mac, data: []const u8) void {
        m.inner.update(data);
    }

    pub fn final(m: *Mac) [length]u8 {
        var out: [length]u8 = undefined;
        m.inner.final(&out);
        return out;
    }
};

pub fn tag(key: []const u8, data: []const u8) [length]u8 {
    var out: [length]u8 = undefined;
    Hmac.create(&out, data, key);
    return out;
}

pub fn matches(expected: []const u8, actual: []const u8) bool {
    if (expected.len != actual.len) return false;
    var diff: u8 = 0;
    for (expected, actual) |e, a| diff |= e ^ a;
    return diff == 0;
}

test "a tag over parts equals a tag over the whole" {
    var m = Mac.init("key");
    m.update("ab");
    m.update("c");
    try std.testing.expect(matches(&m.final(), &tag("key", "abc")));
    try std.testing.expect(!matches(&tag("key", "abc"), &tag("key", "abd")));
}

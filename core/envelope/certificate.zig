//! The certificates behind a sealed envelope: a server certificate signed by
//! the trust root, and a sender certificate signed by that server, naming the
//! sender's id, phone number, device, key and expiry.
const std = @import("std");
const curve = @import("../keys/curve.zig");
const codec = @import("../wire/codec.zig");
const Fault = @import("../fault.zig").Fault;
const mem = std.mem;
const Allocator = mem.Allocator;

fn signature64(data: []const u8) Fault![64]u8 {
    if (data.len != 64) return Fault.BadSignature;
    return data[0..64].*;
}

fn splitSigned(data: []const u8) Fault!struct { body: []const u8, signature: [64]u8 } {
    var body: ?[]const u8 = null;
    var signature: ?[]const u8 = null;
    var r = codec.Reader.init(data);
    while (r.next() catch return Fault.BadMessage) |f| switch (f.number) {
        1 => body = f.bytes(),
        2 => signature = f.bytes(),
        else => {},
    };
    return .{ .body = body orelse return Fault.BadMessage, .signature = try signature64(signature orelse return Fault.BadMessage) };
}

fn joinSigned(allocator: Allocator, body: []const u8, signature: [64]u8) ![]u8 {
    var w = codec.Writer.init(allocator);
    defer w.deinit();
    try w.bytes(1, body);
    try w.bytes(2, &signature);
    return w.finish();
}

pub const ServerCert = struct {
    key_id: u32,
    key: curve.Public,
    body: []const u8,
    signature: [64]u8,
    bytes: []u8,
    allocator: Allocator,

    pub fn deinit(c: *ServerCert) void {
        c.allocator.free(c.bytes);
        c.* = undefined;
    }

    pub fn make(allocator: Allocator, key_id: u32, key: curve.Public, trust_root: curve.Secret) !ServerCert {
        var body = codec.Writer.init(allocator);
        defer body.deinit();
        try body.uint(1, key_id);
        try body.bytes(2, &key.serialize());
        const bytes = try joinSigned(allocator, body.buf.items, try trust_root.sign(body.buf.items));
        errdefer allocator.free(bytes);
        return parseOwned(allocator, bytes);
    }

    pub fn parse(allocator: Allocator, data: []const u8) !ServerCert {
        const copy = try allocator.dupe(u8, data);
        errdefer allocator.free(copy);
        return parseOwned(allocator, copy);
    }

    fn parseOwned(allocator: Allocator, bytes: []u8) !ServerCert {
        const signed = try splitSigned(bytes);
        var key_id: ?u32 = null;
        var key: ?curve.Public = null;
        var r = codec.Reader.init(signed.body);
        while (r.next() catch return Fault.BadMessage) |f| switch (f.number) {
            1 => key_id = std.math.cast(u32, f.uint() orelse return Fault.BadMessage) orelse return Fault.BadMessage,
            2 => key = try curve.Public.parse(f.bytes() orelse return Fault.BadMessage),
            else => {},
        };
        return .{
            .key_id = key_id orelse return Fault.BadMessage,
            .key = key orelse return Fault.BadMessage,
            .body = signed.body,
            .signature = signed.signature,
            .bytes = bytes,
            .allocator = allocator,
        };
    }

    pub fn signedBy(c: ServerCert, trust_root: curve.Public) bool {
        return trust_root.verify(c.body, c.signature);
    }
};

pub const SenderCert = struct {
    sender_id: []const u8,
    sender_phone: ?[]const u8,
    sender_device: u32,
    sender_key: curve.Public,
    expires_ms: u64,
    server: ServerCert,
    body: []const u8,
    signature: [64]u8,
    bytes: []u8,
    allocator: Allocator,

    pub fn deinit(c: *SenderCert) void {
        c.server.deinit();
        c.allocator.free(c.bytes);
        c.* = undefined;
    }

    pub const Make = struct {
        sender_id: []const u8,
        sender_phone: ?[]const u8,
        sender_device: u32,
        sender_key: curve.Public,
        expires_ms: u64,
        server: *const ServerCert,
        server_secret: curve.Secret,
    };

    pub fn make(allocator: Allocator, m: Make) !SenderCert {
        var body = codec.Writer.init(allocator);
        defer body.deinit();
        if (m.sender_phone) |p| try body.bytes(1, p);
        try body.uint(2, m.sender_device);
        try body.word64(3, m.expires_ms);
        try body.bytes(4, &m.sender_key.serialize());
        try body.bytes(5, m.server.bytes);
        try body.bytes(6, m.sender_id);
        const bytes = try joinSigned(allocator, body.buf.items, try m.server_secret.sign(body.buf.items));
        errdefer allocator.free(bytes);
        return parseOwned(allocator, bytes);
    }

    pub fn parse(allocator: Allocator, data: []const u8) !SenderCert {
        const copy = try allocator.dupe(u8, data);
        errdefer allocator.free(copy);
        return parseOwned(allocator, copy);
    }

    fn parseOwned(allocator: Allocator, bytes: []u8) !SenderCert {
        const signed = try splitSigned(bytes);
        var phone: ?[]const u8 = null;
        var device: ?u32 = null;
        var expires: ?u64 = null;
        var key: ?curve.Public = null;
        var server: ?[]const u8 = null;
        var id: ?[]const u8 = null;
        var r = codec.Reader.init(signed.body);
        while (r.next() catch return Fault.BadMessage) |f| switch (f.number) {
            1 => phone = f.bytes(),
            2 => device = std.math.cast(u32, f.uint() orelse return Fault.BadMessage) orelse return Fault.BadMessage,
            3 => expires = f.word(),
            4 => key = try curve.Public.parse(f.bytes() orelse return Fault.BadMessage),
            5 => server = f.bytes(),
            6 => id = f.bytes(),
            else => {},
        };
        return .{
            .sender_id = id orelse return Fault.BadMessage,
            .sender_phone = phone,
            .sender_device = device orelse return Fault.BadMessage,
            .sender_key = key orelse return Fault.BadMessage,
            .expires_ms = expires orelse return Fault.BadMessage,
            .server = try ServerCert.parse(allocator, server orelse return Fault.BadMessage),
            .body = signed.body,
            .signature = signed.signature,
            .bytes = bytes,
            .allocator = allocator,
        };
    }

    /// Valid when the chain leads to the trust root and the certificate has not expired.
    pub fn valid(c: SenderCert, trust_root: curve.Public, now_ms: u64) bool {
        if (!c.server.signedBy(trust_root)) return false;
        if (!c.server.key.verify(c.body, c.signature)) return false;
        return now_ms <= c.expires_ms;
    }
};

test "certificates chain and expire" {
    const a = std.testing.allocator;
    const trust = try curve.Pair.generate();
    const server = try curve.Pair.generate();
    const sender = try curve.Pair.generate();
    var sc = try ServerCert.make(a, 1, server.public, trust.secret);
    defer sc.deinit();
    var cert = try SenderCert.make(a, .{ .sender_id = "9d0652a3-dcc3-4d11-975f-74d61598733f", .sender_phone = null, .sender_device = 1, .sender_key = sender.public, .expires_ms = 1000, .server = &sc, .server_secret = server.secret });
    defer cert.deinit();
    try std.testing.expect(cert.valid(trust.public, 999));
    try std.testing.expect(!cert.valid(trust.public, 1001));
    try std.testing.expect(!cert.valid(server.public, 999));
    var parsed = try SenderCert.parse(a, cert.bytes);
    defer parsed.deinit();
    try std.testing.expectEqualStrings(cert.sender_id, parsed.sender_id);
    try std.testing.expect(parsed.sender_phone == null);
}

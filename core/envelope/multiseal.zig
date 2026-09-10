//! The many-recipient envelope: one sealed content, one wrapped key and tag
//! per recipient, every device of a recipient listed with its registration
//! id. A server splits it into the received form each device opens.
const std = @import("std");
const curve = @import("../keys/curve.zig");
const derive = @import("../keys/derive.zig");
const cipher = @import("../keys/cipher.zig");
const identity = @import("../keys/identity.zig");
const entropy = @import("../entropy.zig");
const ServiceId = @import("../ident/service.zig").ServiceId;
const Uuid = @import("../ident/uuid.zig").Uuid;
const Content = @import("content.zig").Content;
const Way = @import("seal.zig").Way;
const Fault = @import("../fault.zig").Fault;
const mem = std.mem;
const Allocator = mem.Allocator;

pub const received_byte: u8 = 0x22;
pub const sent_byte: u8 = 0x23;
pub const registration_mask: u16 = 0x3FFF;
const wrapped_key_length = 32;
const tag_length = 16;

const Session = struct {
    ephemeral: curve.Pair,
    key: [32]u8,

    fn from(m: [32]u8) !Session {
        var r: [32]u8 = undefined;
        derive.hkdf(&r, &m, null, "Sealed Sender v2: r (2023-08)");
        var k: [32]u8 = undefined;
        derive.hkdf(&k, &m, null, "Sealed Sender v2: K");
        return .{ .ephemeral = try curve.Pair.fromSecret(curve.Secret.fromRaw(r)), .key = k };
    }
};

fn wrap(ours: curve.Pair, theirs: curve.Public, way: Way, input: [32]u8) ![32]u8 {
    var material: [32 + 66]u8 = undefined;
    material[0..32].* = try ours.secret.agree(theirs);
    const first = if (way == .sending) ours.public else theirs;
    const second = if (way == .sending) theirs else ours.public;
    material[32..65].* = first.serialize();
    material[65..98].* = second.serialize();
    var out: [32]u8 = undefined;
    derive.hkdf(&out, &material, null, "Sealed Sender v2: DH");
    for (&out, input) |*o, i| o.* ^= i;
    return out;
}

fn tag(us: identity.IdentityPair, them: curve.Public, way: Way, ephemeral: curve.Public, wrapped: [32]u8) ![tag_length]u8 {
    var material: [32 + 33 + 32 + 66]u8 = undefined;
    material[0..32].* = try us.secret.agree(them);
    material[32..65].* = ephemeral.serialize();
    material[65..97].* = wrapped;
    const ours = us.identity.key;
    const first = if (way == .sending) ours else them;
    const second = if (way == .sending) them else ours;
    material[97..130].* = first.serialize();
    material[130..163].* = second.serialize();
    var out: [tag_length]u8 = undefined;
    derive.hkdf(&out, &material, null, "Sealed Sender v2: DH-sender");
    return out;
}

pub fn openReceived(allocator: Allocator, us: identity.IdentityPair, body: []const u8) !Content {
    if (body.len < wrapped_key_length + tag_length + 32 + tag_length) return Fault.BadMessage;
    const wrapped = body[0..wrapped_key_length].*;
    const their_tag = body[wrapped_key_length..][0..tag_length].*;
    const ephemeral = curve.Public.fromRaw(body[wrapped_key_length + tag_length ..][0..32].*);
    const sealed = body[wrapped_key_length + tag_length + 32 ..];
    const ours: curve.Pair = .{ .public = us.identity.key, .secret = us.secret };
    const m = try wrap(ours, ephemeral, .receiving, wrapped);
    const session = try Session.from(m);
    if (!session.ephemeral.public.eql(ephemeral)) return Fault.BadMessage;
    const content_bytes = try cipher.sivOpen(allocator, session.key, [_]u8{0} ** 12, sealed, &.{});
    defer allocator.free(content_bytes);
    var content = try Content.parse(allocator, content_bytes);
    errdefer content.deinit();
    const expected = try tag(us, content.sender.sender_key, .receiving, ephemeral, wrapped);
    if (!std.crypto.timing_safe.eql([tag_length]u8, expected, their_tag)) return Fault.BadMessage;
    return content;
}

pub const Device = struct { device: u8, registration_id: u16 };

pub const Recipient = struct {
    service_id: ServiceId,
    devices: []const Device,
    identity: curve.Public,
};

fn putVarint(out: *std.ArrayList(u8), allocator: Allocator, value: u64) !void {
    var v = value;
    while (true) {
        const byte: u8 = @truncate(v & 0x7F);
        if (v < 0x80) return out.append(allocator, byte);
        try out.append(allocator, byte | 0x80);
        v >>= 7;
    }
}

pub fn sealForMany(allocator: Allocator, us: identity.IdentityPair, recipients: []const Recipient, excluded: []const ServiceId, content: *const Content) ![]u8 {
    const m = entropy.array(32);
    const session = try Session.from(m);
    const sealed = try cipher.sivSeal(allocator, session.key, [_]u8{0} ** 12, content.bytes, &.{});
    defer allocator.free(sealed);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.append(allocator, sent_byte);
    try putVarint(&out, allocator, recipients.len + excluded.len);
    for (recipients) |r| {
        if (r.devices.len == 0) return Fault.BadArgument;
        try out.appendSlice(allocator, &r.service_id.fixed());
        for (r.devices, 0..) |d, i| {
            if (d.registration_id & registration_mask != d.registration_id or d.device == 0) return Fault.BadArgument;
            const reg: u16 = if (i + 1 < r.devices.len) d.registration_id | 0x8000 else d.registration_id;
            try out.append(allocator, d.device);
            var reg_bytes: [2]u8 = undefined;
            mem.writeInt(u16, &reg_bytes, reg, .big);
            try out.appendSlice(allocator, &reg_bytes);
        }
        const wrapped = try wrap(session.ephemeral, r.identity, .sending, m);
        try out.appendSlice(allocator, &wrapped);
        try out.appendSlice(allocator, &try tag(us, r.identity, .sending, session.ephemeral.public, wrapped));
    }
    for (excluded) |sid| {
        try out.appendSlice(allocator, &sid.fixed());
        try out.append(allocator, 0);
    }
    try out.appendSlice(allocator, &session.ephemeral.public.u);
    try out.appendSlice(allocator, sealed);
    return out.toOwnedSlice(allocator);
}

pub const SentRecipient = struct {
    service_id: ServiceId,
    devices: []const Device,
    wrapped_and_tag: []const u8,
};

pub const Sent = struct {
    recipients: []SentRecipient,
    device_storage: []Device,
    shared: []const u8,
    allocator: Allocator,

    pub fn deinit(s: *Sent) void {
        s.allocator.free(s.recipients);
        s.allocator.free(s.device_storage);
        s.* = undefined;
    }

    /// The per-device form the server hands to one recipient.
    pub fn receivedFor(s: *const Sent, allocator: Allocator, recipient: *const SentRecipient) ![]u8 {
        const out = try allocator.alloc(u8, 1 + recipient.wrapped_and_tag.len + s.shared.len);
        out[0] = received_byte;
        @memcpy(out[1 .. 1 + recipient.wrapped_and_tag.len], recipient.wrapped_and_tag);
        @memcpy(out[1 + recipient.wrapped_and_tag.len ..], s.shared);
        return out;
    }
};

fn getVarint(data: []const u8, at: *usize) Fault!u64 {
    var out: u64 = 0;
    var i: usize = 0;
    while (i < 10 and at.* + i < data.len) : (i += 1) {
        const byte = data[at.* + i];
        out |= @as(u64, byte & 0x7F) << @intCast(7 * i);
        if (byte & 0x80 == 0) {
            at.* += i + 1;
            return out;
        }
    }
    return Fault.BadMessage;
}

pub fn parseSent(allocator: Allocator, data: []const u8) !Sent {
    if (data.len == 0) return Fault.BadMessage;
    if (data[0] != sent_byte and data[0] != received_byte) return Fault.UnknownVersion;
    const ids_only = data[0] == received_byte;
    var at: usize = 1;
    const count = std.math.cast(usize, try getVarint(data, &at)) orelse return Fault.BadMessage;
    var recipients: std.ArrayList(SentRecipient) = .empty;
    errdefer recipients.deinit(allocator);
    var devices: std.ArrayList(Device) = .empty;
    errdefer devices.deinit(allocator);
    var ranges: std.ArrayList([2]usize) = .empty;
    defer ranges.deinit(allocator);
    var i: usize = 0;
    while (i < count) : (i += 1) {
        var sid: ServiceId = undefined;
        if (ids_only) {
            if (at + 16 > data.len) return Fault.BadMessage;
            sid = ServiceId.aci(Uuid.fromBytes(data[at..][0..16].*));
            at += 16;
        } else {
            if (at + 17 > data.len) return Fault.BadMessage;
            sid = try ServiceId.fromFixed(data[at..][0..17].*);
            at += 17;
        }
        const first = devices.items.len;
        while (true) {
            if (at >= data.len) return Fault.BadMessage;
            const device = data[at];
            at += 1;
            if (device == 0) {
                if (devices.items.len != first) return Fault.BadMessage;
                break;
            }
            if (at + 2 > data.len) return Fault.BadMessage;
            const raw = mem.readInt(u16, data[at..][0..2], .big);
            at += 2;
            try devices.append(allocator, .{ .device = device, .registration_id = raw & registration_mask });
            if (raw & 0x8000 == 0) break;
        }
        var wrapped_and_tag: []const u8 = &.{};
        if (devices.items.len != first) {
            if (at + wrapped_key_length + tag_length > data.len) return Fault.BadMessage;
            wrapped_and_tag = data[at..][0 .. wrapped_key_length + tag_length];
            at += wrapped_key_length + tag_length;
        }
        try recipients.append(allocator, .{ .service_id = sid, .devices = &.{}, .wrapped_and_tag = wrapped_and_tag });
        try ranges.append(allocator, .{ first, devices.items.len });
    }
    if (at + 32 > data.len) return Fault.BadMessage;
    const device_storage = try devices.toOwnedSlice(allocator);
    errdefer allocator.free(device_storage);
    for (recipients.items, ranges.items) |*r, range| r.devices = device_storage[range[0]..range[1]];
    return .{ .recipients = try recipients.toOwnedSlice(allocator), .device_storage = device_storage, .shared = data[at..], .allocator = allocator };
}

/// A message sent to exactly one recipient, rewritten as that recipient receives it.
pub fn forSingle(allocator: Allocator, data: []const u8) ![]u8 {
    var sent = try parseSent(allocator, data);
    defer sent.deinit();
    var only: ?*const SentRecipient = null;
    for (sent.recipients) |*r| {
        if (r.devices.len == 0) continue;
        if (only != null) return Fault.BadArgument;
        only = r;
    }
    return sent.receivedFor(allocator, only orelse return Fault.BadArgument);
}

/// The server's split: the received form for one device of one recipient.
pub fn forRecipient(allocator: Allocator, data: []const u8, service_id: ServiceId, device: u8) ![]u8 {
    var sent = try parseSent(allocator, data);
    defer sent.deinit();
    for (sent.recipients) |*r| {
        if (!r.service_id.eql(service_id)) continue;
        for (r.devices) |d| if (d.device == device) return sent.receivedFor(allocator, r);
    }
    return Fault.BadArgument;
}

test "the many-recipient form splits and opens" {
    const certificate = @import("certificate.zig");
    const seal = @import("seal.zig");
    const a = std.testing.allocator;
    const trust = try curve.Pair.generate();
    const server = try curve.Pair.generate();
    const alice = try identity.IdentityPair.generate();
    const bob = try identity.IdentityPair.generate();
    var sc = try certificate.ServerCert.make(a, 1, server.public, trust.secret);
    defer sc.deinit();
    var cert = try certificate.SenderCert.make(a, .{ .sender_id = "9d0652a3-dcc3-4d11-975f-74d61598733f", .sender_phone = null, .sender_device = 2, .sender_key = alice.identity.key, .expires_ms = 1000, .server = &sc, .server_secret = server.secret });
    defer cert.deinit();
    var content = try Content.make(a, .whisper, &cert, "ciphertext body", .default, null);
    defer content.deinit();
    const bob_sid = ServiceId.aci(try Uuid.parse("e80f7bbe-5b94-471e-bd8c-2173654ea3d1"));
    const devices = [_]Device{ .{ .device = 1, .registration_id = 4242 }, .{ .device = 2, .registration_id = 7 } };
    const sent = try sealForMany(a, alice, &.{.{ .service_id = bob_sid, .devices = &devices, .identity = bob.identity.key }}, &.{}, &content);
    defer a.free(sent);
    const received = try forSingle(a, sent);
    defer a.free(received);
    try std.testing.expectEqual(received_byte, received[0]);
    var opened = try seal.open(a, bob, received);
    defer opened.deinit();
    try std.testing.expectEqualStrings("ciphertext body", opened.body);
    const by_device = try forRecipient(a, sent, bob_sid, 2);
    defer a.free(by_device);
    try std.testing.expectEqualSlices(u8, received, by_device);
    try std.testing.expectError(Fault.BadMessage, seal.open(a, alice, received));
}

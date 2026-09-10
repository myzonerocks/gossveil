//! The ratchet message: a version byte, the fields, and an eight-byte MAC over
//! both identities and everything before it. It may bind the sender and
//! recipient addresses when both are account identifiers.
const std = @import("std");
const curve = @import("../keys/curve.zig");
const codec = @import("../wire/codec.zig");
const frame = @import("../wire/frame.zig");
const Address = @import("../ident/address.zig").Address;
const ServiceId = @import("../ident/service.zig").ServiceId;
const Fault = @import("../fault.zig").Fault;
const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
const mem = std.mem;
const Allocator = mem.Allocator;

pub const mac_length: usize = 8;
pub const binding_length: usize = 36;

pub const Binding = struct { sender: Address, recipient: Address };

/// Both names have to be account identifiers for a binding to exist at all.
pub fn encodeBinding(b: Binding) ?[binding_length]u8 {
    const sender = ServiceId.parse(b.sender.name) catch return null;
    const recipient = ServiceId.parse(b.recipient.name) catch return null;
    var out: [binding_length]u8 = undefined;
    out[0..17].* = sender.fixed();
    out[17] = @truncate(b.sender.device);
    out[18..35].* = recipient.fixed();
    out[35] = @truncate(b.recipient.device);
    return out;
}

pub const Whisper = struct {
    version: u8,
    ratchet: curve.Public,
    index: u32,
    previous_index: u32,
    body: []const u8,
    pq_packet: []const u8,
    binding: ?[binding_length]u8,
    /// The complete wire bytes; every slice above borrows from them.
    bytes: []u8,
    allocator: Allocator,

    pub fn deinit(w: *Whisper) void {
        w.allocator.free(w.bytes);
        w.* = undefined;
    }

    pub const Seal = struct {
        version: u8,
        mac_key: [32]u8,
        binding: ?Binding,
        ratchet: curve.Public,
        index: u32,
        previous_index: u32,
        body: []const u8,
        sender: curve.Public,
        recipient: curve.Public,
        pq_packet: []const u8,
    };

    pub fn seal(allocator: Allocator, s: Seal) !Whisper {
        const bound = if (s.binding) |b| encodeBinding(b) else null;
        var w = codec.Writer.init(allocator);
        defer w.deinit();
        try w.buf.append(allocator, frame.versionByte(s.version & 0xF));
        try w.bytes(1, &s.ratchet.serialize());
        try w.uint(2, s.index);
        try w.uint(3, s.previous_index);
        try w.bytes(4, s.body);
        try w.bytesIfSet(5, s.pq_packet);
        if (bound) |b| try w.bytes(6, &b);
        const tag = mac(s.sender, s.recipient, s.mac_key, w.buf.items);
        try w.buf.appendSlice(allocator, tag[0..mac_length]);
        const bytes = try w.finish();
        errdefer allocator.free(bytes);
        return parseOwned(allocator, bytes);
    }

    pub fn parse(allocator: Allocator, data: []const u8) !Whisper {
        const copy = try allocator.dupe(u8, data);
        errdefer allocator.free(copy);
        return parseOwned(allocator, copy);
    }

    fn parseOwned(allocator: Allocator, bytes: []u8) !Whisper {
        if (bytes.len < 1 + mac_length) return Fault.BadMessage;
        const version = try frame.messageVersion(bytes[0]);
        const content = bytes[1 .. bytes.len - mac_length];
        var ratchet: ?curve.Public = null;
        var index: ?u32 = null;
        var previous_index: u32 = 0;
        var body: ?[]const u8 = null;
        var pq_packet: []const u8 = &.{};
        var binding: ?[binding_length]u8 = null;
        var r = codec.Reader.init(content);
        while (r.next() catch return Fault.BadMessage) |f| switch (f.number) {
            1 => ratchet = try curve.Public.parse(f.bytes() orelse return Fault.BadMessage),
            2 => index = std.math.cast(u32, f.uint() orelse return Fault.BadMessage) orelse return Fault.BadMessage,
            3 => previous_index = std.math.cast(u32, f.uint() orelse return Fault.BadMessage) orelse return Fault.BadMessage,
            4 => body = f.bytes(),
            5 => pq_packet = f.bytes() orelse &.{},
            6 => {
                const b = f.bytes() orelse return Fault.BadMessage;
                if (b.len != binding_length) return Fault.BadMessage;
                binding = b[0..binding_length].*;
            },
            else => {},
        };
        return .{
            .version = version,
            .ratchet = ratchet orelse return Fault.BadMessage,
            .index = index orelse return Fault.BadMessage,
            .previous_index = previous_index,
            .body = body orelse return Fault.BadMessage,
            .pq_packet = pq_packet,
            .binding = binding,
            .bytes = bytes,
            .allocator = allocator,
        };
    }

    fn mac(sender: curve.Public, recipient: curve.Public, key: [32]u8, content: []const u8) [32]u8 {
        var h = Hmac.init(&key);
        h.update(&sender.serialize());
        h.update(&recipient.serialize());
        h.update(content);
        var out: [32]u8 = undefined;
        h.final(&out);
        return out;
    }

    pub fn checkMac(w: Whisper, sender: curve.Public, recipient: curve.Public, key: [32]u8) bool {
        const end = w.bytes.len - mac_length;
        const ours = mac(sender, recipient, key, w.bytes[0..end]);
        return std.crypto.timing_safe.eql([mac_length]u8, ours[0..mac_length].*, w.bytes[end..][0..mac_length].*);
    }

    /// A message that binds addresses has to name ours; one that binds none is accepted as is.
    pub fn checkBinding(w: Whisper, local: ?Binding) bool {
        const bound = w.binding orelse return true;
        const ours = local orelse return true;
        const expected = encodeBinding(ours) orelse return false;
        return std.crypto.timing_safe.eql([binding_length]u8, bound, expected);
    }
};

test "a sealed message parses back and its mac checks" {
    const a = std.testing.allocator;
    const sender = try curve.Pair.generate();
    const recipient = try curve.Pair.generate();
    const ratchet = try curve.Pair.generate();
    const key = [_]u8{9} ** 32;
    var w = try Whisper.seal(a, .{ .version = 4, .mac_key = key, .binding = null, .ratchet = ratchet.public, .index = 7, .previous_index = 3, .body = "body", .sender = sender.public, .recipient = recipient.public, .pq_packet = "pq" });
    defer w.deinit();
    try std.testing.expect(w.checkMac(sender.public, recipient.public, key));
    try std.testing.expect(!w.checkMac(recipient.public, sender.public, key));
    try std.testing.expectEqual(@as(u32, 7), w.index);
    try std.testing.expectEqualStrings("pq", w.pq_packet);
    try std.testing.expectEqual(@as(u8, 0x44), w.bytes[0]);
    try std.testing.expect(w.checkBinding(null));
}

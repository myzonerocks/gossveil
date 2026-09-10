//! The post-quantum ratchet's packet, one per session message: a version
//! byte, the epoch, the key index, a payload kind and, for most kinds, one
//! piece of the erasure-coded payload.
const std = @import("std");
const code = @import("code.zig");
const mem = std.mem;
const Allocator = mem.Allocator;

pub const Piece = code.Piece;

pub const PacketError = error{BadPacket} || Allocator.Error;

pub const Kind = enum(u8) { empty = 0, header = 1, encap = 2, encap_and_ack = 3, ack = 4, first = 5, second = 6 };

pub const Payload = union(Kind) {
    empty: void,
    header: Piece,
    encap: Piece,
    encap_and_ack: Piece,
    ack: bool,
    first: Piece,
    second: Piece,

    pub fn piece(p: Payload) ?Piece {
        return switch (p) {
            .header, .encap, .encap_and_ack, .first, .second => |c| c,
            else => null,
        };
    }
};

pub const Packet = struct {
    epoch: u64,
    payload: Payload,

    pub fn serialize(p: Packet, allocator: Allocator, index: u32) ![]u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);
        try out.append(allocator, 1);
        try putVarint(&out, allocator, p.epoch);
        try putVarint(&out, allocator, index);
        try out.append(allocator, @intFromEnum(p.payload));
        if (p.payload.piece()) |c| {
            try putVarint(&out, allocator, c.index);
            try out.appendSlice(allocator, &c.data);
        }
        return out.toOwnedSlice(allocator);
    }

    pub const Parsed = struct { packet: Packet, index: u32 };

    pub fn parse(data: []const u8) PacketError!Parsed {
        if (data.len == 0 or data[0] != 1) return PacketError.BadPacket;
        var at: usize = 1;
        const epoch = try getVarint(data, &at);
        if (epoch == 0) return PacketError.BadPacket;
        const index = std.math.cast(u32, try getVarint(data, &at)) orelse return PacketError.BadPacket;
        if (at >= data.len) return PacketError.BadPacket;
        const kind: Kind = switch (data[at]) {
            0 => .empty,
            1 => .header,
            2 => .encap,
            3 => .encap_and_ack,
            4 => .ack,
            5 => .first,
            6 => .second,
            else => return PacketError.BadPacket,
        };
        at += 1;
        const payload: Payload = switch (kind) {
            .empty => .{ .empty = {} },
            .ack => .{ .ack = true },
            .header => .{ .header = try getPiece(data, &at) },
            .encap => .{ .encap = try getPiece(data, &at) },
            .encap_and_ack => .{ .encap_and_ack = try getPiece(data, &at) },
            .first => .{ .first = try getPiece(data, &at) },
            .second => .{ .second = try getPiece(data, &at) },
        };
        return .{ .packet = .{ .epoch = epoch, .payload = payload }, .index = index };
    }
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

fn getVarint(data: []const u8, at: *usize) PacketError!u64 {
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
    return PacketError.BadPacket;
}

fn getPiece(data: []const u8, at: *usize) PacketError!Piece {
    const index = try getVarint(data, at);
    if (index > 65535 or at.* + code.piece_size > data.len) return PacketError.BadPacket;
    const p: Piece = .{ .index = @intCast(index), .data = data[at.*..][0..code.piece_size].* };
    at.* += code.piece_size;
    return p;
}

test "a packet round trips its bytes" {
    const a = std.testing.allocator;
    const p: Packet = .{ .epoch = 300, .payload = .{ .first = .{ .index = 7, .data = [_]u8{0xAB} ** 32 } } };
    const bytes = try p.serialize(a, 5);
    defer a.free(bytes);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 0xAC, 0x02, 5, 5, 7 }, bytes[0..6]);
    const parsed = try Packet.parse(bytes);
    try std.testing.expectEqual(@as(u64, 300), parsed.packet.epoch);
    try std.testing.expectEqual(@as(u32, 5), parsed.index);
    try std.testing.expectEqual(@as(u16, 7), parsed.packet.payload.first.index);
}

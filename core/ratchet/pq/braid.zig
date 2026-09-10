//! The braid: eleven states that carry a header, an encapsulation key and
//! two capsule halves across the pieces of ordinary messages, one epoch at a
//! time, the two sides swapping roles every epoch.
const std = @import("std");
const codec = @import("../../wire/codec.zig");
const entropy = @import("../../entropy.zig");
const code = @import("code.zig");
const kem = @import("kem.zig");
const authm = @import("auth.zig");
const packet = @import("packet.zig");
const mem = std.mem;
const Allocator = mem.Allocator;
const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;

const Auth = authm.Auth;
const tag_length = authm.tag_length;
pub const Packet = packet.Packet;
pub const Payload = packet.Payload;

pub const BraidError = error{ BadRecord, BadPacket, BadTag, EpochOutOfRange, BadData } || code.CodeError || Allocator.Error;

pub const EpochSecret = struct { epoch: u64, secret: [32]u8 };

fn epochSecret(shared: [32]u8, epoch: u64) [32]u8 {
    const label = "Signal_PQCKA_V1_MLKEM768:SCKA Key";
    var info: [label.len + 8]u8 = undefined;
    info[0..label.len].* = label.*;
    mem.writeInt(u64, info[label.len..], epoch, .big);
    var out: [32]u8 = undefined;
    Hkdf.expand(&out, &info, Hkdf.extract(&[_]u8{0} ** 32, &shared));
    return out;
}

const header_message = kem.header_length + tag_length;
const second_message = kem.second_length + tag_length;

// The side that samples keys and sends the header and the encapsulation key.
const Unsampled = struct { epoch: u64, auth: Auth };
const Sampled = struct { epoch: u64, auth: Auth, encap: [kem.encap_length]u8, decap: [kem.decap_length]u8, out_header: code.Spread };
const HeaderOut = struct { epoch: u64, auth: Auth, decap: [kem.decap_length]u8, out_encap: code.Spread, in_first: code.Gather };
const FirstIn = struct { epoch: u64, auth: Auth, decap: [kem.decap_length]u8, first: [kem.first_length]u8, out_encap: code.Spread };
const EncapOutFirstIn = struct { epoch: u64, auth: Auth, decap: [kem.decap_length]u8, first: [kem.first_length]u8, in_second: code.Gather };
// The side that encapsulates and sends the two capsule halves.
const Waiting = struct { epoch: u64, auth: Auth, in_header: code.Gather };
const HeaderIn = struct { epoch: u64, auth: Auth, header: [kem.header_length]u8, in_encap: code.Gather };
const FirstOut = struct { epoch: u64, auth: Auth, header: [kem.header_length]u8, carry: [kem.carry_length]u8, first: [kem.first_length]u8, out_first: code.Spread, in_encap: code.Gather };
const EncapInFirstOut = struct { epoch: u64, auth: Auth, carry: [kem.carry_length]u8, encap: [kem.encap_length]u8, first: [kem.first_length]u8, out_first: code.Spread };
const FirstAcked = struct { epoch: u64, auth: Auth, header: [kem.header_length]u8, carry: [kem.carry_length]u8, first: [kem.first_length]u8, in_encap: code.Gather };
const SecondOut = struct { epoch: u64, auth: Auth, out_second: code.Spread };

pub const Braid = union(enum) {
    unsampled: Unsampled,
    sampled: Sampled,
    header_out: HeaderOut,
    first_in: FirstIn,
    encap_out_first_in: EncapOutFirstIn,
    waiting: Waiting,
    header_in: HeaderIn,
    first_out: FirstOut,
    encap_in_first_out: EncapInFirstOut,
    first_acked: FirstAcked,
    second_out: SecondOut,

    pub fn startInitiator(auth_key: []const u8) Braid {
        return .{ .unsampled = .{ .epoch = 1, .auth = Auth.init(auth_key, 1) } };
    }

    pub fn startResponder(auth_key: []const u8) BraidError!Braid {
        return .{ .waiting = .{ .epoch = 1, .auth = Auth.init(auth_key, 1), .in_header = try code.Gather.forLength(header_message) } };
    }

    pub fn deinit(b: *Braid, allocator: Allocator) void {
        switch (b.*) {
            .unsampled => {},
            .sampled => |*s| s.out_header.deinit(allocator),
            .header_out => |*s| {
                s.out_encap.deinit(allocator);
                s.in_first.deinit(allocator);
            },
            .first_in => |*s| s.out_encap.deinit(allocator),
            .encap_out_first_in => |*s| s.in_second.deinit(allocator),
            .waiting => |*s| s.in_header.deinit(allocator),
            .header_in => |*s| s.in_encap.deinit(allocator),
            .first_out => |*s| {
                s.out_first.deinit(allocator);
                s.in_encap.deinit(allocator);
            },
            .encap_in_first_out => |*s| s.out_first.deinit(allocator),
            .first_acked => |*s| s.in_encap.deinit(allocator),
            .second_out => |*s| s.out_second.deinit(allocator),
        }
        b.* = undefined;
    }

    pub fn epoch(b: *const Braid) u64 {
        return switch (b.*) {
            inline else => |s| s.epoch,
        };
    }

    pub const Sent = struct { packet: Packet, secret: ?EpochSecret };

    /// Produces the next packet and moves the braid forward.
    pub fn send(b: *Braid, allocator: Allocator) BraidError!Sent {
        const ep = b.epoch();
        switch (b.*) {
            .unsampled => |s| {
                const keys = kem.generate(entropy.array(kem.seed_length)) catch return BraidError.BadData;
                var message: [header_message]u8 = undefined;
                message[0..kem.header_length].* = keys.header;
                message[kem.header_length..].* = s.auth.tagHeader(ep, &keys.header);
                var out = try code.Spread.of(allocator, &message);
                errdefer out.deinit(allocator);
                const piece = try out.nextPiece(allocator);
                b.* = .{ .sampled = .{ .epoch = ep, .auth = s.auth, .encap = keys.encap, .decap = keys.decap, .out_header = out } };
                return .{ .packet = .{ .epoch = ep, .payload = .{ .header = piece } }, .secret = null };
            },
            .sampled => |*s| return .{ .packet = .{ .epoch = ep, .payload = .{ .header = try s.out_header.nextPiece(allocator) } }, .secret = null },
            .header_out => |*s| return .{ .packet = .{ .epoch = ep, .payload = .{ .encap = try s.out_encap.nextPiece(allocator) } }, .secret = null },
            .first_in => |*s| return .{ .packet = .{ .epoch = ep, .payload = .{ .encap_and_ack = try s.out_encap.nextPiece(allocator) } }, .secret = null },
            .encap_out_first_in => return .{ .packet = .{ .epoch = ep, .payload = .{ .ack = true } }, .secret = null },
            .waiting => return .{ .packet = .{ .epoch = ep, .payload = .{ .empty = {} } }, .secret = null },
            .header_in => |s| {
                const first = kem.firstHalf(&s.header, &entropy.array(32));
                const secret = epochSecret(first.shared, ep);
                var auth = s.auth;
                auth.advance(ep, &secret);
                var out = try code.Spread.of(allocator, &first.capsule);
                errdefer out.deinit(allocator);
                const piece = try out.nextPiece(allocator);
                b.* = .{ .first_out = .{ .epoch = ep, .auth = auth, .header = s.header, .carry = first.carry, .first = first.capsule, .out_first = out, .in_encap = s.in_encap } };
                return .{ .packet = .{ .epoch = ep, .payload = .{ .first = piece } }, .secret = .{ .epoch = ep, .secret = secret } };
            },
            .first_out => |*s| return .{ .packet = .{ .epoch = ep, .payload = .{ .first = try s.out_first.nextPiece(allocator) } }, .secret = null },
            .encap_in_first_out => |*s| return .{ .packet = .{ .epoch = ep, .payload = .{ .first = try s.out_first.nextPiece(allocator) } }, .secret = null },
            .first_acked => return .{ .packet = .{ .epoch = ep, .payload = .{ .empty = {} } }, .secret = null },
            .second_out => |*s| return .{ .packet = .{ .epoch = ep, .payload = .{ .second = try s.out_second.nextPiece(allocator) } }, .secret = null },
        }
    }

    fn secondSpread(allocator: Allocator, auth: *const Auth, ep: u64, encap: *const [kem.encap_length]u8, carry: *const [kem.carry_length]u8, first: *const [kem.first_length]u8) !code.Spread {
        const second = kem.secondHalf(encap, carry);
        var whole: [kem.first_length + kem.second_length]u8 = undefined;
        whole[0..kem.first_length].* = first.*;
        whole[kem.first_length..].* = second;
        var message: [second_message]u8 = undefined;
        message[0..kem.second_length].* = second;
        message[kem.second_length..].* = auth.tagCapsule(ep, &whole);
        return code.Spread.of(allocator, &message);
    }

    /// Feeds one packet in; the returned secret, when present, opens the next epoch.
    pub fn receive(b: *Braid, allocator: Allocator, p: Packet) BraidError!?EpochSecret {
        const ep = b.epoch();
        if (p.epoch > ep) {
            if (b.* == .second_out and p.epoch == ep + 1) {
                const s = &b.second_out;
                const auth = s.auth;
                s.out_second.deinit(allocator);
                b.* = .{ .unsampled = .{ .epoch = ep + 1, .auth = auth } };
                return null;
            }
            return BraidError.EpochOutOfRange;
        }
        if (p.epoch < ep) return null;
        switch (b.*) {
            .unsampled, .header_in => return null,
            .sampled => |*s| {
                const piece = if (p.payload == .first) p.payload.first else return null;
                var in = try code.Gather.forLength(kem.first_length);
                errdefer in.deinit(allocator);
                try in.add(allocator, &piece);
                var out = try code.Spread.of(allocator, &s.encap);
                errdefer out.deinit(allocator);
                s.out_header.deinit(allocator);
                const old = s.*;
                b.* = .{ .header_out = .{ .epoch = ep, .auth = old.auth, .decap = old.decap, .out_encap = out, .in_first = in } };
                return null;
            },
            .header_out => |*s| {
                const piece = if (p.payload == .first) p.payload.first else return null;
                try s.in_first.add(allocator, &piece);
                const whole = (try s.in_first.message(allocator)) orelse return null;
                defer allocator.free(whole);
                s.in_first.deinit(allocator);
                const old = s.*;
                b.* = .{ .first_in = .{ .epoch = ep, .auth = old.auth, .decap = old.decap, .first = whole[0..kem.first_length].*, .out_encap = old.out_encap } };
                return null;
            },
            .first_in => |*s| {
                const piece = if (p.payload == .second) p.payload.second else return null;
                var in = try code.Gather.forLength(second_message);
                errdefer in.deinit(allocator);
                try in.add(allocator, &piece);
                s.out_encap.deinit(allocator);
                const old = s.*;
                b.* = .{ .encap_out_first_in = .{ .epoch = ep, .auth = old.auth, .decap = old.decap, .first = old.first, .in_second = in } };
                return null;
            },
            .encap_out_first_in => |*s| {
                const piece = if (p.payload == .second) p.payload.second else return null;
                try s.in_second.add(allocator, &piece);
                const whole = (try s.in_second.message(allocator)) orelse return null;
                defer allocator.free(whole);
                const second = whole[0..kem.second_length];
                const tag = whole[kem.second_length..][0..tag_length];
                const shared = kem.open(&s.decap, &s.first, second) catch return BraidError.BadData;
                const secret = epochSecret(shared, ep);
                var auth = s.auth;
                auth.advance(ep, &secret);
                var capsule: [kem.first_length + kem.second_length]u8 = undefined;
                capsule[0..kem.first_length].* = s.first;
                capsule[kem.first_length..].* = second.*;
                if (!auth.checkCapsule(ep, &capsule, tag)) return BraidError.BadTag;
                var in = try code.Gather.forLength(header_message);
                errdefer in.deinit(allocator);
                s.in_second.deinit(allocator);
                b.* = .{ .waiting = .{ .epoch = ep + 1, .auth = auth, .in_header = in } };
                return .{ .epoch = ep, .secret = secret };
            },
            .waiting => |*s| {
                const piece = if (p.payload == .header) p.payload.header else return null;
                try s.in_header.add(allocator, &piece);
                const whole = (try s.in_header.message(allocator)) orelse return null;
                defer allocator.free(whole);
                const header = whole[0..kem.header_length];
                if (!s.auth.checkHeader(ep, header, whole[kem.header_length..][0..tag_length])) return BraidError.BadTag;
                var in = try code.Gather.forLength(kem.encap_length);
                errdefer in.deinit(allocator);
                s.in_header.deinit(allocator);
                const old = s.*;
                b.* = .{ .header_in = .{ .epoch = ep, .auth = old.auth, .header = header.*, .in_encap = in } };
                return null;
            },
            .first_out => |*s| {
                const acked = p.payload == .encap_and_ack;
                const piece = switch (p.payload) {
                    .encap, .encap_and_ack => |c| c,
                    else => return null,
                };
                try s.in_encap.add(allocator, &piece);
                if (try s.in_encap.message(allocator)) |whole| {
                    defer allocator.free(whole);
                    const encap = whole[0..kem.encap_length];
                    if (!kem.keyMatchesHeader(encap, &s.header)) return BraidError.BadData;
                    if (acked) {
                        var out = try secondSpread(allocator, &s.auth, ep, encap, &s.carry, &s.first);
                        errdefer out.deinit(allocator);
                        s.out_first.deinit(allocator);
                        s.in_encap.deinit(allocator);
                        const old = s.*;
                        b.* = .{ .second_out = .{ .epoch = ep, .auth = old.auth, .out_second = out } };
                    } else {
                        s.in_encap.deinit(allocator);
                        const old = s.*;
                        b.* = .{ .encap_in_first_out = .{ .epoch = ep, .auth = old.auth, .carry = old.carry, .encap = encap.*, .first = old.first, .out_first = old.out_first } };
                    }
                } else if (acked) {
                    s.out_first.deinit(allocator);
                    const old = s.*;
                    b.* = .{ .first_acked = .{ .epoch = ep, .auth = old.auth, .header = old.header, .carry = old.carry, .first = old.first, .in_encap = old.in_encap } };
                }
                return null;
            },
            .encap_in_first_out => |*s| {
                const acked = switch (p.payload) {
                    .ack => |v| v,
                    .encap_and_ack => true,
                    else => false,
                };
                if (!acked) return null;
                var out = try secondSpread(allocator, &s.auth, ep, &s.encap, &s.carry, &s.first);
                errdefer out.deinit(allocator);
                s.out_first.deinit(allocator);
                const old = s.*;
                b.* = .{ .second_out = .{ .epoch = ep, .auth = old.auth, .out_second = out } };
                return null;
            },
            .first_acked => |*s| {
                const piece = switch (p.payload) {
                    .encap, .encap_and_ack => |c| c,
                    else => return null,
                };
                try s.in_encap.add(allocator, &piece);
                const whole = (try s.in_encap.message(allocator)) orelse return null;
                defer allocator.free(whole);
                const encap = whole[0..kem.encap_length];
                if (!kem.keyMatchesHeader(encap, &s.header)) return BraidError.BadData;
                var out = try secondSpread(allocator, &s.auth, ep, encap, &s.carry, &s.first);
                errdefer out.deinit(allocator);
                s.in_encap.deinit(allocator);
                const old = s.*;
                b.* = .{ .second_out = .{ .epoch = ep, .auth = old.auth, .out_second = out } };
                return null;
            },
            .second_out => return null,
        }
    }

    fn writeAuth(w: *codec.Writer, auth: *const Auth) !void {
        var inner = codec.Writer.init(w.allocator);
        defer inner.deinit();
        try inner.bytes(1, &auth.root);
        try inner.bytes(2, &auth.mac);
        try w.embed(2, &inner);
    }

    fn writeFixed(w: *codec.Writer, ep: u64, auth: *const Auth, fields: anytype) !void {
        var inner = codec.Writer.init(w.allocator);
        defer inner.deinit();
        try inner.uintIfSet(1, ep);
        try writeAuth(&inner, auth);
        inline for (fields, 3..) |f, number| try inner.bytes(number, f);
        try w.embed(1, &inner);
    }

    fn writeCoder(w: *codec.Writer, number: u32, coder: anytype) !void {
        var inner = codec.Writer.init(w.allocator);
        defer inner.deinit();
        try coder.write(&inner);
        try w.embed(number, &inner);
    }

    /// One inner state, numbered as the record declares.
    pub fn write(b: *const Braid, w: *codec.Writer) !void {
        var inner = codec.Writer.init(w.allocator);
        defer inner.deinit();
        const number: u32 = switch (b.*) {
            .unsampled => |s| blk: {
                try writeFixed(&inner, s.epoch, &s.auth, .{});
                break :blk 1;
            },
            .sampled => |*s| blk: {
                try writeFixed(&inner, s.epoch, &s.auth, .{ &s.encap, &s.decap });
                try writeCoder(&inner, 2, &s.out_header);
                break :blk 2;
            },
            .header_out => |*s| blk: {
                try writeFixed(&inner, s.epoch, &s.auth, .{&s.decap});
                try writeCoder(&inner, 2, &s.out_encap);
                try writeCoder(&inner, 3, &s.in_first);
                break :blk 3;
            },
            .first_in => |*s| blk: {
                try writeFixed(&inner, s.epoch, &s.auth, .{ &s.decap, &s.first });
                try writeCoder(&inner, 2, &s.out_encap);
                break :blk 4;
            },
            .encap_out_first_in => |*s| blk: {
                try writeFixed(&inner, s.epoch, &s.auth, .{ &s.decap, &s.first });
                try writeCoder(&inner, 3, &s.in_second);
                break :blk 5;
            },
            .waiting => |*s| blk: {
                try writeFixed(&inner, s.epoch, &s.auth, .{});
                try writeCoder(&inner, 2, &s.in_header);
                break :blk 6;
            },
            .header_in => |*s| blk: {
                try writeFixed(&inner, s.epoch, &s.auth, .{&s.header});
                try writeCoder(&inner, 2, &s.in_encap);
                break :blk 7;
            },
            .first_out => |*s| blk: {
                try writeFixed(&inner, s.epoch, &s.auth, .{ &s.header, &s.carry, &s.first });
                try writeCoder(&inner, 2, &s.out_first);
                try writeCoder(&inner, 3, &s.in_encap);
                break :blk 8;
            },
            .encap_in_first_out => |*s| blk: {
                try writeFixed(&inner, s.epoch, &s.auth, .{ &s.carry, &s.encap, &s.first });
                try writeCoder(&inner, 2, &s.out_first);
                break :blk 9;
            },
            .first_acked => |*s| blk: {
                try writeFixed(&inner, s.epoch, &s.auth, .{ &s.header, &s.carry, &s.first });
                try writeCoder(&inner, 2, &s.in_encap);
                break :blk 10;
            },
            .second_out => |*s| blk: {
                try writeFixed(&inner, s.epoch, &s.auth, .{});
                try writeCoder(&inner, 2, &s.out_second);
                break :blk 11;
            },
        };
        try w.embed(number, &inner);
    }

    const Fixed = struct {
        epoch: u64 = 0,
        auth: ?Auth = null,
        f3: []const u8 = &.{},
        f4: []const u8 = &.{},
        f5: []const u8 = &.{},

        fn array(x: Fixed, comptime field: u8, comptime len: usize) BraidError![len]u8 {
            const bytes = switch (field) {
                3 => x.f3,
                4 => x.f4,
                5 => x.f5,
                else => unreachable,
            };
            if (bytes.len != len) return BraidError.BadRecord;
            return bytes[0..len].*;
        }
    };

    fn readAuth(data: []const u8) BraidError!Auth {
        var auth: Auth = .{ .root = mem.zeroes([32]u8), .mac = mem.zeroes([32]u8) };
        var r = codec.Reader.init(data);
        while (r.next() catch return BraidError.BadRecord) |f| switch (f.number) {
            1 => if (f.bytes()) |b| if (b.len == 32) {
                auth.root = b[0..32].*;
            },
            2 => if (f.bytes()) |b| if (b.len == 32) {
                auth.mac = b[0..32].*;
            },
            else => {},
        };
        return auth;
    }

    fn readFixed(data: []const u8) BraidError!Fixed {
        var out: Fixed = .{};
        var r = codec.Reader.init(data);
        while (r.next() catch return BraidError.BadRecord) |f| switch (f.number) {
            1 => out.epoch = f.uint() orelse 0,
            2 => out.auth = try readAuth(f.bytes() orelse return BraidError.BadRecord),
            3 => out.f3 = f.bytes() orelse return BraidError.BadRecord,
            4 => out.f4 = f.bytes() orelse return BraidError.BadRecord,
            5 => out.f5 = f.bytes() orelse return BraidError.BadRecord,
            else => {},
        };
        if (out.auth == null) return BraidError.BadRecord;
        return out;
    }

    const Parts = struct { fixed: ?Fixed = null, coder2: ?[]const u8 = null, coder3: ?[]const u8 = null };

    fn readParts(data: []const u8) BraidError!Parts {
        var parts: Parts = .{};
        var r = codec.Reader.init(data);
        while (r.next() catch return BraidError.BadRecord) |f| switch (f.number) {
            1 => parts.fixed = try readFixed(f.bytes() orelse return BraidError.BadRecord),
            2 => parts.coder2 = f.bytes(),
            3 => parts.coder3 = f.bytes(),
            else => {},
        };
        if (parts.fixed == null) return BraidError.BadRecord;
        return parts;
    }

    fn spread(allocator: Allocator, bytes: ?[]const u8) BraidError!code.Spread {
        return code.Spread.read(allocator, bytes orelse return BraidError.BadRecord);
    }

    fn gather(allocator: Allocator, bytes: ?[]const u8, expected: usize) BraidError!code.Gather {
        var g = try code.Gather.read(allocator, bytes orelse return BraidError.BadRecord);
        if (g.needed != expected / 2) {
            g.deinit(allocator);
            return BraidError.BadRecord;
        }
        return g;
    }

    pub fn read(allocator: Allocator, data: []const u8) BraidError!Braid {
        var r = codec.Reader.init(data);
        while (r.next() catch return BraidError.BadRecord) |f| {
            if (f.kind != .bytes or f.number < 1 or f.number > 11) continue;
            const parts = try readParts(f.byte_value);
            const x = parts.fixed.?;
            const ep = x.epoch;
            const auth = x.auth.?;
            switch (f.number) {
                1 => return .{ .unsampled = .{ .epoch = ep, .auth = auth } },
                2 => return .{ .sampled = .{ .epoch = ep, .auth = auth, .encap = try x.array(3, kem.encap_length), .decap = try x.array(4, kem.decap_length), .out_header = try spread(allocator, parts.coder2) } },
                3 => {
                    var out = try spread(allocator, parts.coder2);
                    errdefer out.deinit(allocator);
                    return .{ .header_out = .{ .epoch = ep, .auth = auth, .decap = try x.array(3, kem.decap_length), .out_encap = out, .in_first = try gather(allocator, parts.coder3, kem.first_length) } };
                },
                4 => return .{ .first_in = .{ .epoch = ep, .auth = auth, .decap = try x.array(3, kem.decap_length), .first = try x.array(4, kem.first_length), .out_encap = try spread(allocator, parts.coder2) } },
                5 => return .{ .encap_out_first_in = .{ .epoch = ep, .auth = auth, .decap = try x.array(3, kem.decap_length), .first = try x.array(4, kem.first_length), .in_second = try gather(allocator, parts.coder3, second_message) } },
                6 => return .{ .waiting = .{ .epoch = ep, .auth = auth, .in_header = try gather(allocator, parts.coder2, header_message) } },
                7 => return .{ .header_in = .{ .epoch = ep, .auth = auth, .header = try x.array(3, kem.header_length), .in_encap = try gather(allocator, parts.coder2, kem.encap_length) } },
                8 => {
                    var out = try spread(allocator, parts.coder2);
                    errdefer out.deinit(allocator);
                    return .{ .first_out = .{ .epoch = ep, .auth = auth, .header = try x.array(3, kem.header_length), .carry = try x.array(4, kem.carry_length), .first = try x.array(5, kem.first_length), .out_first = out, .in_encap = try gather(allocator, parts.coder3, kem.encap_length) } };
                },
                9 => return .{ .encap_in_first_out = .{ .epoch = ep, .auth = auth, .carry = try x.array(3, kem.carry_length), .encap = try x.array(4, kem.encap_length), .first = try x.array(5, kem.first_length), .out_first = try spread(allocator, parts.coder2) } },
                10 => return .{ .first_acked = .{ .epoch = ep, .auth = auth, .header = try x.array(3, kem.header_length), .carry = try x.array(4, kem.carry_length), .first = try x.array(5, kem.first_length), .in_encap = try gather(allocator, parts.coder2, kem.encap_length) } },
                11 => return .{ .second_out = .{ .epoch = ep, .auth = auth, .out_second = try spread(allocator, parts.coder2) } },
                else => unreachable,
            }
        }
        return BraidError.BadRecord;
    }
};

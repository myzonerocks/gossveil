//! One ratchet state: the root key, the sending chain, the receiving chains
//! with their skipped keys, the pending handshake material, and the record
//! encoding the stores persist.
const std = @import("std");
const curve = @import("../keys/curve.zig");
const codec = @import("../wire/codec.zig");
const chain = @import("chain.zig");
const Chain = chain.Chain;
const Slot = chain.Slot;
const Fault = @import("../fault.zig").Fault;
const mem = std.mem;
const Allocator = mem.Allocator;

pub const max_forward_jump: u32 = 25_000;
pub const max_skipped_keys: usize = 2000;
pub const max_receiving_lanes: usize = 5;
pub const unacknowledged_lifetime_secs: u64 = 30 * 24 * 60 * 60;
pub const current_version: u32 = 4;

/// One direction's ratchet key with its chain and skipped keys.
pub const Lane = struct {
    ratchet: curve.Public,
    ratchet_secret: ?curve.Secret,
    chain: Chain,
    skipped: std.ArrayList(Slot) = .empty,

    pub fn deinit(l: *Lane, allocator: Allocator) void {
        l.skipped.deinit(allocator);
    }

    fn clone(l: Lane, allocator: Allocator) !Lane {
        var out = l;
        out.skipped = try l.skipped.clone(allocator);
        return out;
    }
};

pub const PendingHandshake = struct {
    one_time_id: ?u32,
    signed_id: u32,
    base: curve.Public,
    stamp_secs: u64,
};

pub const PendingCapsule = struct {
    pq_id: u32,
    capsule: []u8,
};

pub const State = struct {
    allocator: Allocator,
    version: u32,
    local: curve.Public,
    remote: curve.Public,
    root: [32]u8,
    previous_index: u32 = 0,
    sending: ?Lane = null,
    receiving: std.ArrayList(Lane) = .empty,
    pending: ?PendingHandshake = null,
    pending_capsule: ?PendingCapsule = null,
    remote_registration_id: u32 = 0,
    local_registration_id: u32 = 0,
    base: []u8,
    pq_state: []u8,

    pub fn init(allocator: Allocator, version: u32, local: curve.Public, remote: curve.Public, root: [32]u8, base: []const u8, pq_state: []const u8) !State {
        const base_copy = try allocator.dupe(u8, base);
        errdefer allocator.free(base_copy);
        const pq_copy = try allocator.dupe(u8, pq_state);
        return .{ .allocator = allocator, .version = version, .local = local, .remote = remote, .root = root, .base = base_copy, .pq_state = pq_copy };
    }

    pub fn deinit(s: *State) void {
        if (s.sending) |*l| l.deinit(s.allocator);
        for (s.receiving.items) |*l| l.deinit(s.allocator);
        s.receiving.deinit(s.allocator);
        if (s.pending_capsule) |p| s.allocator.free(p.capsule);
        s.allocator.free(s.base);
        s.allocator.free(s.pq_state);
        s.* = undefined;
    }

    pub fn clone(s: State) !State {
        const a = s.allocator;
        var out = s;
        out.sending = null;
        out.receiving = .empty;
        out.pending_capsule = null;
        out.base = try a.dupe(u8, s.base);
        errdefer a.free(out.base);
        out.pq_state = try a.dupe(u8, s.pq_state);
        errdefer a.free(out.pq_state);
        errdefer {
            for (out.receiving.items) |*l| l.deinit(a);
            out.receiving.deinit(a);
        }
        if (s.sending) |l| out.sending = try l.clone(a);
        errdefer if (out.sending) |*l| l.deinit(a);
        try out.receiving.ensureTotalCapacity(a, s.receiving.items.len);
        for (s.receiving.items) |l| out.receiving.appendAssumeCapacity(try l.clone(a));
        if (s.pending_capsule) |p| out.pending_capsule = .{ .pq_id = p.pq_id, .capsule = try a.dupe(u8, p.capsule) };
        return out;
    }

    pub fn withSelf(s: State) bool {
        return s.local.eql(s.remote);
    }

    pub fn canSend(s: State) bool {
        return s.sending != null;
    }

    /// A session whose first message was never acknowledged goes stale after
    /// thirty days; the caller then opens a fresh one from a new bundle.
    pub fn canSendAt(s: State, now_secs: u64) bool {
        if (s.sending == null) return false;
        if (s.pending) |p| if (p.stamp_secs + unacknowledged_lifetime_secs < now_secs) return false;
        return true;
    }

    pub fn setSending(s: *State, pair: curve.Pair, c: Chain) void {
        if (s.sending) |*l| l.deinit(s.allocator);
        s.sending = .{ .ratchet = pair.public, .ratchet_secret = pair.secret, .chain = c };
    }

    pub fn sendingChain(s: State) Fault!Chain {
        const l = s.sending orelse return Fault.BadSession;
        return l.chain;
    }

    pub fn setSendingChain(s: *State, c: Chain) void {
        s.sending.?.chain = c;
    }

    pub fn sendingPair(s: State) Fault!curve.Pair {
        const l = s.sending orelse return Fault.BadSession;
        return .{ .public = l.ratchet, .secret = l.ratchet_secret orelse return Fault.BadSession };
    }

    pub fn addReceiving(s: *State, their_ratchet: curve.Public, c: Chain) !void {
        try s.receiving.append(s.allocator, .{ .ratchet = their_ratchet, .ratchet_secret = null, .chain = c });
        if (s.receiving.items.len > max_receiving_lanes) {
            var old = s.receiving.orderedRemove(0);
            old.deinit(s.allocator);
        }
    }

    pub fn receivingLane(s: *State, their_ratchet: curve.Public) ?*Lane {
        for (s.receiving.items) |*l| if (l.ratchet.eql(their_ratchet)) return l;
        return null;
    }

    /// Takes a skipped key for `index` out of the lane, if one was kept.
    pub fn takeSkipped(s: *State, their_ratchet: curve.Public, index: u32) ?Slot {
        const lane = s.receivingLane(their_ratchet) orelse return null;
        for (lane.skipped.items, 0..) |slot, i| if (slot.index() == index) return lane.skipped.orderedRemove(i);
        return null;
    }

    pub fn keepSkipped(s: *State, their_ratchet: curve.Public, slot: Slot) !void {
        const lane = s.receivingLane(their_ratchet) orelse return Fault.BadSession;
        try lane.skipped.insert(s.allocator, 0, slot);
        if (lane.skipped.items.len > max_skipped_keys) _ = lane.skipped.pop();
    }

    pub fn setPending(s: *State, one_time_id: ?u32, signed_id: u32, base: curve.Public, now_secs: u64) void {
        s.pending = .{ .one_time_id = one_time_id, .signed_id = signed_id, .base = base, .stamp_secs = now_secs };
    }

    pub fn setPendingCapsule(s: *State, pq_id: u32, capsule: []const u8) !void {
        const copy = try s.allocator.dupe(u8, capsule);
        if (s.pending_capsule) |p| s.allocator.free(p.capsule);
        s.pending_capsule = .{ .pq_id = pq_id, .capsule = copy };
    }

    pub fn clearPending(s: *State) void {
        s.pending = null;
        if (s.pending_capsule) |p| s.allocator.free(p.capsule);
        s.pending_capsule = null;
    }

    /// Takes ownership of `bytes`.
    pub fn setPqState(s: *State, bytes: []u8) void {
        s.allocator.free(s.pq_state);
        s.pq_state = bytes;
    }

    pub fn serialize(s: State, allocator: Allocator) ![]u8 {
        var w = codec.Writer.init(allocator);
        defer w.deinit();
        try w.uintIfSet(1, s.version);
        try w.bytes(2, &s.local.serialize());
        try w.bytes(3, &s.remote.serialize());
        try w.bytes(4, &s.root);
        try w.uintIfSet(5, s.previous_index);
        if (s.sending) |l| {
            var inner = try laneWriter(allocator, l);
            defer inner.deinit();
            try w.embed(6, &inner);
        }
        for (s.receiving.items) |l| {
            var inner = try laneWriter(allocator, l);
            defer inner.deinit();
            try w.embed(7, &inner);
        }
        if (s.pending) |p| {
            var inner = codec.Writer.init(allocator);
            defer inner.deinit();
            if (p.one_time_id) |id| try inner.uint(1, id);
            try inner.bytes(2, &p.base.serialize());
            try inner.uintIfSet(3, p.signed_id);
            try inner.uintIfSet(4, p.stamp_secs);
            try w.embed(9, &inner);
        }
        try w.uintIfSet(10, s.remote_registration_id);
        try w.uintIfSet(11, s.local_registration_id);
        try w.bytesIfSet(13, s.base);
        if (s.pending_capsule) |p| {
            var inner = codec.Writer.init(allocator);
            defer inner.deinit();
            try inner.uintIfSet(1, p.pq_id);
            try inner.bytesIfSet(2, p.capsule);
            try w.embed(14, &inner);
        }
        try w.bytesIfSet(15, s.pq_state);
        return w.finish();
    }

    fn laneWriter(allocator: Allocator, l: Lane) !codec.Writer {
        var w = codec.Writer.init(allocator);
        errdefer w.deinit();
        try w.bytes(1, &l.ratchet.serialize());
        if (l.ratchet_secret) |sec| try w.bytes(2, &sec.serialize());
        {
            var inner = codec.Writer.init(allocator);
            defer inner.deinit();
            try inner.uintIfSet(1, l.chain.index);
            try inner.bytes(2, &l.chain.key);
            try w.embed(3, &inner);
        }
        for (l.skipped.items) |slot| {
            var inner = codec.Writer.init(allocator);
            defer inner.deinit();
            switch (slot) {
                .seed => |v| {
                    try inner.uintIfSet(1, v.index);
                    try inner.bytes(5, &v.seed);
                },
                .keys => |k| {
                    try inner.uintIfSet(1, k.index);
                    try inner.bytes(2, &k.cipher);
                    try inner.bytes(3, &k.mac);
                    try inner.bytes(4, &k.iv);
                },
            }
            try w.embed(4, &inner);
        }
        return w;
    }

    pub fn parse(allocator: Allocator, data: []const u8) !State {
        var local: ?curve.Public = null;
        var remote: ?curve.Public = null;
        var s = try init(allocator, 0, undefined, undefined, mem.zeroes([32]u8), &.{}, &.{});
        errdefer s.deinit();
        var r = codec.Reader.init(data);
        while (r.next() catch return Fault.BadSession) |f| switch (f.number) {
            1 => s.version = std.math.cast(u32, f.uint() orelse 0) orelse return Fault.BadSession,
            2 => local = try curve.Public.parse(f.bytes() orelse return Fault.BadSession),
            3 => remote = try curve.Public.parse(f.bytes() orelse return Fault.BadSession),
            4 => {
                const b = f.bytes() orelse return Fault.BadSession;
                if (b.len != 32) return Fault.BadSession;
                s.root = b[0..32].*;
            },
            5 => s.previous_index = std.math.cast(u32, f.uint() orelse 0) orelse return Fault.BadSession,
            6 => {
                var lane = try parseLane(allocator, f.bytes() orelse return Fault.BadSession);
                errdefer lane.deinit(allocator);
                if (lane.ratchet_secret == null) return Fault.BadSession;
                if (s.sending) |*old| old.deinit(allocator);
                s.sending = lane;
            },
            7 => {
                var lane = try parseLane(allocator, f.bytes() orelse return Fault.BadSession);
                errdefer lane.deinit(allocator);
                try s.receiving.append(allocator, lane);
            },
            9 => s.pending = try parsePending(f.bytes() orelse return Fault.BadSession),
            10 => s.remote_registration_id = std.math.cast(u32, f.uint() orelse 0) orelse return Fault.BadSession,
            11 => s.local_registration_id = std.math.cast(u32, f.uint() orelse 0) orelse return Fault.BadSession,
            13 => {
                const copy = try allocator.dupe(u8, f.bytes() orelse return Fault.BadSession);
                allocator.free(s.base);
                s.base = copy;
            },
            14 => {
                var id: u32 = 0;
                var capsule: []const u8 = &.{};
                var inner = codec.Reader.init(f.bytes() orelse return Fault.BadSession);
                while (inner.next() catch return Fault.BadSession) |g| switch (g.number) {
                    1 => id = std.math.cast(u32, g.uint() orelse 0) orelse return Fault.BadSession,
                    2 => capsule = g.bytes() orelse &.{},
                    else => {},
                };
                try s.setPendingCapsule(id, capsule);
            },
            15 => {
                const copy = try allocator.dupe(u8, f.bytes() orelse return Fault.BadSession);
                allocator.free(s.pq_state);
                s.pq_state = copy;
            },
            else => {},
        };
        s.local = local orelse return Fault.BadSession;
        s.remote = remote orelse return Fault.BadSession;
        return s;
    }

    fn parseLane(allocator: Allocator, data: []const u8) !Lane {
        var ratchet: ?curve.Public = null;
        var secret: ?curve.Secret = null;
        var c: Chain = .{ .key = mem.zeroes([32]u8), .index = 0 };
        var skipped: std.ArrayList(Slot) = .empty;
        errdefer skipped.deinit(allocator);
        var r = codec.Reader.init(data);
        while (r.next() catch return Fault.BadSession) |f| switch (f.number) {
            1 => ratchet = try curve.Public.parse(f.bytes() orelse return Fault.BadSession),
            2 => secret = try curve.Secret.parse(f.bytes() orelse return Fault.BadSession),
            3 => {
                var inner = codec.Reader.init(f.bytes() orelse return Fault.BadSession);
                while (inner.next() catch return Fault.BadSession) |g| switch (g.number) {
                    1 => c.index = std.math.cast(u32, g.uint() orelse 0) orelse return Fault.BadSession,
                    2 => {
                        const b = g.bytes() orelse return Fault.BadSession;
                        if (b.len != 32) return Fault.BadSession;
                        c.key = b[0..32].*;
                    },
                    else => {},
                };
            },
            4 => try skipped.append(allocator, try parseSlot(f.bytes() orelse return Fault.BadSession)),
            else => {},
        };
        return .{ .ratchet = ratchet orelse return Fault.BadSession, .ratchet_secret = secret, .chain = c, .skipped = skipped };
    }

    fn parseSlot(data: []const u8) !Slot {
        var index: u32 = 0;
        var cipher: ?[32]u8 = null;
        var mac: ?[32]u8 = null;
        var iv: ?[16]u8 = null;
        var seed: ?[32]u8 = null;
        var r = codec.Reader.init(data);
        while (r.next() catch return Fault.BadSession) |f| switch (f.number) {
            1 => index = std.math.cast(u32, f.uint() orelse 0) orelse return Fault.BadSession,
            2 => if (f.bytes()) |b| if (b.len == 32) {
                cipher = b[0..32].*;
            },
            3 => if (f.bytes()) |b| if (b.len == 32) {
                mac = b[0..32].*;
            },
            4 => if (f.bytes()) |b| if (b.len == 16) {
                iv = b[0..16].*;
            },
            5 => if (f.bytes()) |b| if (b.len == 32) {
                seed = b[0..32].*;
            },
            else => {},
        };
        if (seed) |v| return .{ .seed = .{ .seed = v, .index = index } };
        return .{ .keys = .{
            .cipher = cipher orelse return Fault.BadSession,
            .mac = mac orelse return Fault.BadSession,
            .iv = iv orelse return Fault.BadSession,
            .index = index,
        } };
    }

    fn parsePending(data: []const u8) !PendingHandshake {
        var out: PendingHandshake = .{ .one_time_id = null, .signed_id = 0, .base = undefined, .stamp_secs = 0 };
        var base: ?curve.Public = null;
        var r = codec.Reader.init(data);
        while (r.next() catch return Fault.BadSession) |f| switch (f.number) {
            1 => out.one_time_id = std.math.cast(u32, f.uint() orelse 0) orelse return Fault.BadSession,
            2 => base = try curve.Public.parse(f.bytes() orelse return Fault.BadSession),
            3 => out.signed_id = @truncate(f.uint() orelse 0),
            4 => out.stamp_secs = f.uint() orelse 0,
            else => {},
        };
        out.base = base orelse return Fault.BadSession;
        return out;
    }
};

test "a state survives its record with skipped keys and pending material" {
    const a = std.testing.allocator;
    const us = try curve.Pair.generate();
    const them = try curve.Pair.generate();
    var s = try State.init(a, 4, us.public, them.public, [_]u8{7} ** 32, &us.public.serialize(), "pq");
    defer s.deinit();
    s.setSending(try curve.Pair.generate(), .{ .key = [_]u8{1} ** 32, .index = 3 });
    try s.addReceiving(them.public, .{ .key = [_]u8{2} ** 32, .index = 5 });
    try s.keepSkipped(them.public, Chain.slot(.{ .key = [_]u8{3} ** 32, .index = 1 }));
    s.setPending(9, 1, us.public, 1_700_000_000);
    try s.setPendingCapsule(1, "capsule");
    s.local_registration_id = 4242;
    s.remote_registration_id = 1;
    const bytes = try s.serialize(a);
    defer a.free(bytes);
    var back = try State.parse(a, bytes);
    defer back.deinit();
    try std.testing.expectEqual(@as(u32, 3), (try back.sendingChain()).index);
    const again = try back.serialize(a);
    defer a.free(again);
    try std.testing.expectEqualSlices(u8, bytes, again);
    try std.testing.expect(back.takeSkipped(them.public, 1) != null);
    try std.testing.expect(back.takeSkipped(them.public, 1) == null);
    try std.testing.expectEqual(@as(u64, 1_700_000_000), back.pending.?.stamp_secs);
    try std.testing.expectEqualStrings("capsule", back.pending_capsule.?.capsule);
    try std.testing.expectEqualStrings("pq", back.pq_state);
    try std.testing.expect(back.canSendAt(1_700_000_001));
    try std.testing.expect(!back.canSendAt(1_700_000_000 + unacknowledged_lifetime_secs + 1));
    var copy = try back.clone();
    defer copy.deinit();
    try std.testing.expectEqual(@as(u32, 4242), copy.local_registration_id);
}

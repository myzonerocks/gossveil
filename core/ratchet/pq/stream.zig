//! The post-quantum key stream: one flow per side per epoch, a bounded set of
//! keys held for out-of-order messages, and the record encoding of all of it.
const std = @import("std");
const codec = @import("../../wire/codec.zig");
const mem = std.mem;
const Allocator = mem.Allocator;
const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;

pub const Side = enum(u8) {
    initiator = 0,
    responder = 1,
};

pub const StreamError = error{ EpochOutOfRange, KeyJump, KeyTrimmed, KeyAlreadyTaken, SendEpochWentBack, BadRecord } || Allocator.Error;

/// Zero means the compiled-in default, in the record as well.
pub const Limits = struct {
    max_jump: u32 = 0,
    max_skipped: u32 = 0,

    pub const default_max_jump: u32 = 25_000;
    pub const default_max_skipped: u32 = 2_000;

    fn jump(l: Limits) u32 {
        return if (l.max_jump > 0) l.max_jump else default_max_jump;
    }

    fn skipped(l: Limits) u32 {
        return if (l.max_skipped > 0) l.max_skipped else default_max_skipped;
    }

    fn trimAt(l: Limits) usize {
        return @as(usize, l.skipped()) * 11 / 10 + 1;
    }

    pub fn of(max_jump: u32, max_skipped: u32) Limits {
        return .{
            .max_jump = if (max_jump == default_max_jump) 0 else max_jump,
            .max_skipped = if (max_skipped == default_max_skipped) 0 else max_skipped,
        };
    }
};

const held_entry = 4 + 32;

const Held = struct {
    data: std.ArrayList(u8) = .empty,

    fn add(h: *Held, allocator: Allocator, index: u32, key: [32]u8) !void {
        var idx: [4]u8 = undefined;
        mem.writeInt(u32, &idx, index, .big);
        try h.data.appendSlice(allocator, &idx);
        try h.data.appendSlice(allocator, &key);
    }

    fn remove(h: *Held, at: usize) void {
        var end = at;
        if (at + held_entry < h.data.items.len) {
            const last = h.data.items.len - held_entry;
            mem.copyForwards(u8, h.data.items[at .. at + held_entry], h.data.items[last..]);
            end = last;
        }
        h.data.shrinkRetainingCapacity(end);
    }

    fn trim(h: *Held, current: u32, limits: Limits) void {
        if (h.data.items.len < limits.trimAt() * held_entry) return;
        const horizon = current - limits.skipped();
        var i: usize = 0;
        while (i < h.data.items.len) {
            if (mem.readInt(u32, h.data.items[i..][0..4], .big) < horizon) h.remove(i) else i += held_entry;
        }
    }

    fn take(h: *Held, at: u32, current: u32, limits: Limits) StreamError![32]u8 {
        if (at + limits.skipped() < current) return StreamError.KeyTrimmed;
        var i: usize = 0;
        while (i < h.data.items.len) : (i += held_entry) {
            if (mem.readInt(u32, h.data.items[i..][0..4], .big) == at) {
                const key = h.data.items[i + 4 ..][0..32].*;
                h.remove(i);
                return key;
            }
        }
        return StreamError.KeyAlreadyTaken;
    }
};

const Flow = struct {
    counter: u32 = 0,
    next: ?[32]u8,
    held: Held = .{},

    fn step(next: *[32]u8, counter: *u32) [32]u8 {
        counter.* += 1;
        var info: [4 + 31]u8 = undefined;
        mem.writeInt(u32, info[0..4], counter.*, .big);
        info[4..].* = "Signal PQ Ratchet V1 Chain Next".*;
        var out: [64]u8 = undefined;
        Hkdf.expand(&out, &info, Hkdf.extract(&[_]u8{0} ** 32, next));
        next.* = out[0..32].*;
        return out[32..64].*;
    }

    fn produce(f: *Flow) struct { index: u32, key: [32]u8 } {
        const key = step(&f.next.?, &f.counter);
        return .{ .index = f.counter, .key = key };
    }

    fn keyAt(f: *Flow, allocator: Allocator, at: u32, limits: Limits) StreamError![32]u8 {
        if (at > f.counter) {
            if (at - f.counter > limits.jump()) return StreamError.KeyJump;
        } else if (at < f.counter) {
            return f.held.take(at, f.counter, limits);
        } else return StreamError.KeyAlreadyTaken;
        const keep = limits.skipped();
        if (at > f.counter + keep) f.held.data.clearRetainingCapacity();
        while (at > f.counter + 1) {
            const key = step(&f.next.?, &f.counter);
            if (f.counter + keep >= at) try f.held.add(allocator, f.counter, key);
        }
        f.held.trim(f.counter, limits);
        return step(&f.next.?, &f.counter);
    }
};

const Epoch = struct { send: Flow, recv: Flow };

const epochs_kept_before_send: usize = 1;

pub const Stream = struct {
    side: Side,
    epoch: u64,
    send_epoch: u64,
    epochs: std.ArrayList(Epoch),
    next_root: [32]u8,
    limits: Limits,

    fn expand(salt: []const u8, material: []const u8, info: []const u8) [96]u8 {
        var out: [96]u8 = undefined;
        Hkdf.expand(&out, info, Hkdf.extract(salt, material));
        return out;
    }

    fn epochFrom(g: *const [96]u8, side: Side) Epoch {
        const a: [32]u8 = g[32..64].*;
        const b: [32]u8 = g[64..96].*;
        return .{
            .send = .{ .next = if (side == .initiator) a else b },
            .recv = .{ .next = if (side == .initiator) b else a },
        };
    }

    pub fn open(allocator: Allocator, initial: []const u8, side: Side, limits: Limits) !Stream {
        const g = expand(&[_]u8{0} ** 32, initial, "Signal PQ Ratchet V1 Chain  Start");
        var epochs: std.ArrayList(Epoch) = .empty;
        try epochs.append(allocator, epochFrom(&g, side));
        return .{ .side = side, .epoch = 0, .send_epoch = 0, .epochs = epochs, .next_root = g[0..32].*, .limits = limits };
    }

    pub fn deinit(s: *Stream, allocator: Allocator) void {
        for (s.epochs.items) |*e| {
            e.send.held.data.deinit(allocator);
            e.recv.held.data.deinit(allocator);
        }
        s.epochs.deinit(allocator);
    }

    pub fn nextEpoch(s: *Stream, allocator: Allocator, epoch: u64, secret: []const u8) !void {
        std.debug.assert(epoch == s.epoch + 1);
        const g = expand(&s.next_root, secret, "Signal PQ Ratchet V1 Chain Add Epoch");
        s.epoch = epoch;
        s.next_root = g[0..32].*;
        try s.epochs.append(allocator, epochFrom(&g, s.side));
    }

    fn slotOf(s: *const Stream, epoch: u64) StreamError!usize {
        if (epoch > s.epoch) return StreamError.EpochOutOfRange;
        const back: usize = @intCast(s.epoch - epoch);
        if (back >= s.epochs.items.len) return StreamError.EpochOutOfRange;
        return s.epochs.items.len - 1 - back;
    }

    pub const Produced = struct { index: u32, key: [32]u8 };

    pub fn keyToSend(s: *Stream, allocator: Allocator, epoch: u64) StreamError!Produced {
        if (epoch < s.send_epoch) return StreamError.SendEpochWentBack;
        var slot = try s.slotOf(epoch);
        if (s.send_epoch != epoch) {
            s.send_epoch = epoch;
            while (slot > epochs_kept_before_send) : (slot -= 1) {
                var old = s.epochs.orderedRemove(0);
                old.send.held.data.deinit(allocator);
                old.recv.held.data.deinit(allocator);
            }
            for (s.epochs.items[0..slot]) |*e| e.send.next = null;
        }
        if (s.epochs.items[slot].send.next == null) return StreamError.EpochOutOfRange;
        const p = s.epochs.items[slot].send.produce();
        return .{ .index = p.index, .key = p.key };
    }

    pub fn keyToReceive(s: *Stream, allocator: Allocator, epoch: u64, index: u32) StreamError![32]u8 {
        const slot = try s.slotOf(epoch);
        if (s.epochs.items[slot].recv.next == null) return StreamError.EpochOutOfRange;
        return s.epochs.items[slot].recv.keyAt(allocator, index, s.limits);
    }

    pub fn write(s: *const Stream, w: *codec.Writer) !void {
        try w.uintIfSet(1, @intFromEnum(s.side));
        try w.uintIfSet(2, s.epoch);
        for (s.epochs.items) |*e| {
            var pair = codec.Writer.init(w.allocator);
            defer pair.deinit();
            inline for (.{ &e.send, &e.recv }, 1..) |flow, number| {
                var inner = codec.Writer.init(w.allocator);
                defer inner.deinit();
                try inner.uintIfSet(1, flow.counter);
                if (flow.next) |next| try inner.bytes(2, &next);
                try inner.bytesIfSet(3, flow.held.data.items);
                try pair.embed(number, &inner);
            }
            try w.embed(3, &pair);
        }
        try w.bytes(4, &s.next_root);
        try w.uintIfSet(5, s.send_epoch);
        var limits = codec.Writer.init(w.allocator);
        defer limits.deinit();
        try limits.uintIfSet(1, s.limits.max_jump);
        try limits.uintIfSet(2, s.limits.max_skipped);
        try w.embed(6, &limits);
    }

    fn readFlow(allocator: Allocator, data: []const u8) StreamError!Flow {
        var f: Flow = .{ .next = null };
        errdefer f.held.data.deinit(allocator);
        var r = codec.Reader.init(data);
        while (r.next() catch return StreamError.BadRecord) |field| switch (field.number) {
            1 => f.counter = std.math.cast(u32, field.uint() orelse 0) orelse return StreamError.BadRecord,
            2 => {
                const b = field.bytes() orelse return StreamError.BadRecord;
                if (b.len == 32) f.next = b[0..32].* else if (b.len != 0) return StreamError.BadRecord;
            },
            3 => {
                const b = field.bytes() orelse return StreamError.BadRecord;
                if (b.len % held_entry != 0) return StreamError.BadRecord;
                try f.held.data.appendSlice(allocator, b);
            },
            else => {},
        };
        return f;
    }

    pub fn read(allocator: Allocator, data: []const u8) StreamError!Stream {
        var s: Stream = .{ .side = .initiator, .epoch = 0, .send_epoch = 0, .epochs = .empty, .next_root = mem.zeroes([32]u8), .limits = .{} };
        errdefer s.deinit(allocator);
        var has_limits = false;
        var r = codec.Reader.init(data);
        while (r.next() catch return StreamError.BadRecord) |field| switch (field.number) {
            1 => s.side = switch (field.uint() orelse 0) {
                0 => .initiator,
                1 => .responder,
                else => return StreamError.BadRecord,
            },
            2 => s.epoch = field.uint() orelse 0,
            3 => {
                var e: Epoch = .{ .send = .{ .next = null }, .recv = .{ .next = null } };
                var have: u2 = 0;
                var inner = codec.Reader.init(field.bytes() orelse return StreamError.BadRecord);
                while (inner.next() catch return StreamError.BadRecord) |g| switch (g.number) {
                    1 => {
                        e.send = try readFlow(allocator, g.bytes() orelse return StreamError.BadRecord);
                        have |= 1;
                    },
                    2 => {
                        e.recv = try readFlow(allocator, g.bytes() orelse return StreamError.BadRecord);
                        have |= 2;
                    },
                    else => {},
                };
                if (have != 3) {
                    e.send.held.data.deinit(allocator);
                    e.recv.held.data.deinit(allocator);
                    return StreamError.BadRecord;
                }
                try s.epochs.append(allocator, e);
            },
            4 => {
                const b = field.bytes() orelse return StreamError.BadRecord;
                if (b.len != 32) return StreamError.BadRecord;
                s.next_root = b[0..32].*;
            },
            5 => s.send_epoch = field.uint() orelse 0,
            6 => {
                has_limits = true;
                var inner = codec.Reader.init(field.bytes() orelse return StreamError.BadRecord);
                while (inner.next() catch return StreamError.BadRecord) |g| switch (g.number) {
                    1 => s.limits.max_jump = std.math.cast(u32, g.uint() orelse 0) orelse return StreamError.BadRecord,
                    2 => s.limits.max_skipped = std.math.cast(u32, g.uint() orelse 0) orelse return StreamError.BadRecord,
                    else => {},
                };
            },
            else => {},
        };
        if (!has_limits) return StreamError.BadRecord;
        return s;
    }
};

test "both sides agree and out-of-order keys are kept" {
    const a = std.testing.allocator;
    var alice = try Stream.open(a, "1", .initiator, .{});
    defer alice.deinit(a);
    var bob = try Stream.open(a, "1", .responder, .{});
    defer bob.deinit(a);
    const k1 = try alice.keyToSend(a, 0);
    const k2 = try alice.keyToSend(a, 0);
    const k3 = try alice.keyToSend(a, 0);
    try std.testing.expectEqualSlices(u8, &k3.key, &try bob.keyToReceive(a, 0, k3.index));
    try std.testing.expectEqualSlices(u8, &k1.key, &try bob.keyToReceive(a, 0, k1.index));
    try std.testing.expectEqualSlices(u8, &k2.key, &try bob.keyToReceive(a, 0, k2.index));
    try std.testing.expectError(StreamError.KeyAlreadyTaken, bob.keyToReceive(a, 0, k2.index));
    try alice.nextEpoch(a, 1, "secret");
    try bob.nextEpoch(a, 1, "secret");
    const k4 = try bob.keyToSend(a, 1);
    try std.testing.expectEqualSlices(u8, &k4.key, &try alice.keyToReceive(a, 1, k4.index));
    var w = codec.Writer.init(a);
    defer w.deinit();
    try bob.write(&w);
    var back = try Stream.read(a, w.buf.items);
    defer back.deinit(a);
    try std.testing.expectEqualSlices(u8, &(try bob.keyToSend(a, 1)).key, &(try back.keyToSend(a, 1)).key);
}

//! A session record: the live state plus up to forty earlier states, newest
//! first, that still open late messages.
const std = @import("std");
const State = @import("state.zig").State;
const curve = @import("../keys/curve.zig");
const codec = @import("../wire/codec.zig");
const Fault = @import("../fault.zig").Fault;
const mem = std.mem;
const Allocator = mem.Allocator;

pub const max_previous: usize = 40;

pub const Archive = struct {
    allocator: Allocator,
    current: ?State = null,
    previous: std.ArrayList([]u8) = .empty,

    pub fn init(allocator: Allocator) Archive {
        return .{ .allocator = allocator };
    }

    pub fn deinit(ar: *Archive) void {
        if (ar.current) |*c| c.deinit();
        for (ar.previous.items) |p| ar.allocator.free(p);
        ar.previous.deinit(ar.allocator);
        ar.* = undefined;
    }

    pub fn live(ar: *Archive) ?*State {
        return if (ar.current) |*c| c else null;
    }

    pub fn canSendAt(ar: *const Archive, now_secs: u64) bool {
        const c = ar.current orelse return false;
        return c.canSendAt(now_secs);
    }

    pub fn shelve(ar: *Archive) !void {
        var c = ar.current orelse return;
        ar.current = null;
        defer c.deinit();
        const bytes = try c.serialize(ar.allocator);
        errdefer ar.allocator.free(bytes);
        if (ar.previous.items.len >= max_previous) ar.allocator.free(ar.previous.pop().?);
        try ar.previous.insert(ar.allocator, 0, bytes);
    }

    /// Takes ownership of `state`; the previous live state is shelved.
    pub fn promote(ar: *Archive, state: State) !void {
        var owned = state;
        errdefer owned.deinit();
        try ar.shelve();
        ar.current = owned;
    }

    pub fn promoteShelved(ar: *Archive, index: usize, state: State) !void {
        var owned = state;
        errdefer owned.deinit();
        ar.allocator.free(ar.previous.orderedRemove(index));
        try ar.promote(owned);
    }

    /// Whether a session for `base` already exists, live or shelved; a shelved
    /// match becomes live again.
    pub fn revive(ar: *Archive, wanted_version: u32, wanted_base: []const u8) !bool {
        if (ar.current) |c| if (c.version == wanted_version and mem.eql(u8, c.base, wanted_base)) return true;
        for (ar.previous.items, 0..) |bytes, i| {
            var state = State.parse(ar.allocator, bytes) catch continue;
            if (state.version == wanted_version and mem.eql(u8, state.base, wanted_base)) {
                try ar.promoteShelved(i, state);
                return true;
            }
            state.deinit();
        }
        return false;
    }

    pub fn shelved(ar: *const Archive, index: usize) !State {
        return State.parse(ar.allocator, ar.previous.items[index]);
    }

    pub fn shelvedCount(ar: *const Archive) usize {
        return ar.previous.items.len;
    }

    fn liveOrFault(ar: *const Archive) Fault!State {
        return ar.current orelse Fault.BadState;
    }

    pub fn version(ar: *const Archive) Fault!u32 {
        return (try ar.liveOrFault()).version;
    }

    pub fn localRegistrationId(ar: *const Archive) Fault!u32 {
        return (try ar.liveOrFault()).local_registration_id;
    }

    pub fn remoteRegistrationId(ar: *const Archive) Fault!u32 {
        return (try ar.liveOrFault()).remote_registration_id;
    }

    pub fn remoteIdentity(ar: *const Archive) Fault!curve.Public {
        return (try ar.liveOrFault()).remote;
    }

    pub fn localIdentity(ar: *const Archive) Fault!curve.Public {
        return (try ar.liveOrFault()).local;
    }

    pub fn base(ar: *const Archive) Fault![]const u8 {
        return (try ar.liveOrFault()).base;
    }

    pub fn sendingRatchetIs(ar: *const Archive, key: curve.Public) bool {
        const c = ar.current orelse return false;
        const lane = c.sending orelse return false;
        return lane.ratchet.eql(key);
    }

    pub fn canSend(ar: *const Archive) bool {
        const c = ar.current orelse return false;
        return c.canSend();
    }

    pub fn serialize(ar: *const Archive, allocator: Allocator) ![]u8 {
        var w = codec.Writer.init(allocator);
        defer w.deinit();
        if (ar.current) |c| {
            const bytes = try c.serialize(allocator);
            defer allocator.free(bytes);
            try w.bytes(1, bytes);
        }
        for (ar.previous.items) |p| try w.bytes(2, p);
        return w.finish();
    }

    pub fn parse(allocator: Allocator, data: []const u8) !Archive {
        var ar = init(allocator);
        errdefer ar.deinit();
        var r = codec.Reader.init(data);
        while (r.next() catch return Fault.BadSession) |f| switch (f.number) {
            1 => {
                var state = try State.parse(allocator, f.bytes() orelse return Fault.BadSession);
                errdefer state.deinit();
                if (ar.current) |*old| old.deinit();
                ar.current = state;
            },
            2 => {
                const copy = try allocator.dupe(u8, f.bytes() orelse return Fault.BadSession);
                errdefer allocator.free(copy);
                try ar.previous.append(allocator, copy);
            },
            else => {},
        };
        return ar;
    }
};

test "shelving keeps the newest forty states, newest first, and revives by base key" {
    const a = std.testing.allocator;
    var ar = Archive.init(a);
    defer ar.deinit();
    const us = try curve.Pair.generate();
    var i: u32 = 0;
    while (i < 45) : (i += 1) {
        var state = try State.init(a, 4, us.public, us.public, [_]u8{0} ** 32, &[_]u8{@intCast(i)}, &.{});
        state.local_registration_id = i;
        try ar.promote(state);
    }
    try std.testing.expectEqual(@as(usize, 40), ar.shelvedCount());
    var newest = try ar.shelved(0);
    defer newest.deinit();
    try std.testing.expectEqual(@as(u32, 43), newest.local_registration_id);
    const bytes = try ar.serialize(a);
    defer a.free(bytes);
    var back = try Archive.parse(a, bytes);
    defer back.deinit();
    try std.testing.expectEqual(@as(u32, 44), try back.localRegistrationId());
    try std.testing.expect(try back.revive(4, &[_]u8{30}));
    try std.testing.expectEqual(@as(u32, 30), try back.localRegistrationId());
    try std.testing.expect(!try back.revive(4, &[_]u8{2}));
}

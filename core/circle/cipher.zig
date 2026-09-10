//! Group operations over a circle: announce our chain, admit another's, seal
//! a note, open one.
const std = @import("std");
const curve = @import("../keys/curve.zig");
const cipher = @import("../keys/cipher.zig");
const entropy = @import("../entropy.zig");
const chain = @import("chain.zig");
const record = @import("record.zig");
const post = @import("post.zig");
const Circle = record.Circle;
const Fault = @import("../fault.zig").Fault;
const mem = std.mem;
const Allocator = mem.Allocator;

/// The announcement for our own chain, creating the chain on first use.
pub fn announce(allocator: Allocator, circle: *Circle, circle_id: [16]u8) !post.Announce {
    if (circle.newest() == null) {
        const chain_id = mem.readInt(u32, &entropy.array(4), .little);
        const signing = try curve.Pair.generate();
        try circle.admit(record.current_version, chain_id, 0, entropy.array(32), signing.public, signing.secret);
    }
    const m = circle.newest().?;
    return post.Announce.make(allocator, @intCast(m.version), circle_id, m.chain_id, m.link.step, m.link.seed, m.signing);
}

pub fn admit(circle: *Circle, a: post.Announce) !void {
    try circle.admit(a.version, a.chain_id, a.step, a.seed, a.signing, null);
}

pub fn seal(allocator: Allocator, circle: *Circle, circle_id: [16]u8, plain: []const u8) ![]u8 {
    const m = circle.newest() orelse return Fault.NoSession;
    const signer = m.signing_secret orelse return Fault.BadSession;
    const link = m.link;
    const y = link.yield();
    const keys = y.keys();
    const body = try cipher.cbcSeal(allocator, keys.cipher, keys.iv, plain);
    defer allocator.free(body);
    var note = try post.Note.make(allocator, @intCast(m.version), circle_id, m.chain_id, y.step, body, signer);
    m.link = link.advance();
    const bytes = note.bytes;
    note.bytes = &.{};
    return bytes;
}

pub fn open(allocator: Allocator, circle: *Circle, note: post.Note) ![]u8 {
    const m = circle.byChain(note.chain_id) orelse return Fault.NoSession;
    if (note.version != m.version) return Fault.UnknownVersion;
    if (!note.signedBy(m.signing)) return Fault.BadSignature;
    const y = try yieldFor(allocator, m, note.step);
    const keys = y.keys();
    return cipher.cbcOpen(allocator, keys.cipher, keys.iv, note.body);
}

fn yieldFor(allocator: Allocator, m: *record.Member, step: u32) !chain.Yield {
    var link = m.link;
    if (link.step > step) return m.takeSkipped(step) orelse Fault.Replay;
    if (step - link.step > record.max_forward_jump) return Fault.BadMessage;
    while (link.step < step) : (link = link.advance()) try m.keepSkipped(allocator, link.yield());
    m.link = link.advance();
    return link.yield();
}

test "a group round trip with a skipped note and a record reload" {
    const a = std.testing.allocator;
    const circle_id = [_]u8{0xAB} ** 16;
    var sender = Circle.init(a);
    defer sender.deinit();
    var announcement = try announce(a, &sender, circle_id);
    defer announcement.deinit();

    var receiver = Circle.init(a);
    defer receiver.deinit();
    var parsed = try post.Announce.parse(a, announcement.bytes);
    defer parsed.deinit();
    try admit(&receiver, parsed);

    const c1 = try seal(a, &sender, circle_id, "one");
    defer a.free(c1);
    const c2 = try seal(a, &sender, circle_id, "two");
    defer a.free(c2);

    const bytes = try receiver.serialize(a);
    defer a.free(bytes);
    var reloaded = try Circle.parse(a, bytes);
    defer reloaded.deinit();

    var n2 = try post.Note.parse(a, c2);
    defer n2.deinit();
    const p2 = try open(a, &reloaded, n2);
    defer a.free(p2);
    try std.testing.expectEqualStrings("two", p2);
    var n1 = try post.Note.parse(a, c1);
    defer n1.deinit();
    const p1 = try open(a, &reloaded, n1);
    defer a.free(p1);
    try std.testing.expectEqualStrings("one", p1);
    try std.testing.expectError(Fault.Replay, open(a, &reloaded, n1));
}

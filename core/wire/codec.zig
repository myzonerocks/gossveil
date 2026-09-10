//! The length-delimited field codec every record and message uses: a tag
//! (field number and kind), then a varint, a fixed word or a byte string.
//! Fields are written in ascending number order and a default is omitted.
const std = @import("std");
const mem = std.mem;

pub const Kind = enum(u3) {
    uint = 0,
    word64 = 1,
    bytes = 2,
    word32 = 5,
};

pub const Field = struct {
    number: u32,
    kind: Kind,
    uint_value: u64 = 0,
    byte_value: []const u8 = &.{},

    pub fn uint(f: Field) ?u64 {
        return if (f.kind == .uint) f.uint_value else null;
    }

    pub fn bytes(f: Field) ?[]const u8 {
        return if (f.kind == .bytes) f.byte_value else null;
    }

    pub fn word(f: Field) ?u64 {
        return if (f.kind == .word64 or f.kind == .word32) f.uint_value else null;
    }
};

pub const ReadError = error{ Truncated, BadTag, Overflow };

/// Walks the fields of one message; byte fields borrow from the input.
pub const Reader = struct {
    data: []const u8,
    at: usize = 0,

    pub fn init(data: []const u8) Reader {
        return .{ .data = data };
    }

    pub fn next(r: *Reader) ReadError!?Field {
        if (r.at >= r.data.len) return null;
        const tag = try r.varint();
        const number: u32 = @truncate(tag >> 3);
        if (number == 0) return ReadError.BadTag;
        const kind: Kind = switch (@as(u3, @truncate(tag & 7))) {
            0 => .uint,
            1 => .word64,
            2 => .bytes,
            5 => .word32,
            else => return ReadError.BadTag,
        };
        switch (kind) {
            .uint => return .{ .number = number, .kind = kind, .uint_value = try r.varint() },
            .word64 => {
                if (r.at + 8 > r.data.len) return ReadError.Truncated;
                const v = mem.readInt(u64, r.data[r.at..][0..8], .little);
                r.at += 8;
                return .{ .number = number, .kind = kind, .uint_value = v };
            },
            .word32 => {
                if (r.at + 4 > r.data.len) return ReadError.Truncated;
                const v = mem.readInt(u32, r.data[r.at..][0..4], .little);
                r.at += 4;
                return .{ .number = number, .kind = kind, .uint_value = v };
            },
            .bytes => {
                const len: usize = @intCast(try r.varint());
                if (r.at + len > r.data.len) return ReadError.Truncated;
                const slice = r.data[r.at .. r.at + len];
                r.at += len;
                return .{ .number = number, .kind = kind, .byte_value = slice };
            },
        }
    }

    fn varint(r: *Reader) ReadError!u64 {
        var value: u64 = 0;
        var shift: u6 = 0;
        while (r.at < r.data.len) {
            const b = r.data[r.at];
            r.at += 1;
            value |= @as(u64, b & 0x7F) << shift;
            if (b & 0x80 == 0) return value;
            if (shift >= 63) return ReadError.Overflow;
            shift += 7;
        }
        return ReadError.Truncated;
    }
};

pub fn putVarint(value: u64, out: []u8) usize {
    var v = value;
    var n: usize = 0;
    while (true) : (n += 1) {
        const low: u8 = @truncate(v & 0x7F);
        v >>= 7;
        out[n] = if (v == 0) low else low | 0x80;
        if (v == 0) return n + 1;
    }
}

/// Builds one message; `finish` hands the bytes to the caller.
pub const Writer = struct {
    buf: std.ArrayList(u8) = .empty,
    allocator: mem.Allocator,

    pub fn init(allocator: mem.Allocator) Writer {
        return .{ .allocator = allocator };
    }

    pub fn deinit(w: *Writer) void {
        w.buf.deinit(w.allocator);
    }

    pub fn finish(w: *Writer) ![]u8 {
        return w.buf.toOwnedSlice(w.allocator);
    }

    fn tag(w: *Writer, number: u32, kind: Kind) !void {
        var scratch: [10]u8 = undefined;
        const n = putVarint((@as(u64, number) << 3) | @intFromEnum(kind), &scratch);
        try w.buf.appendSlice(w.allocator, scratch[0..n]);
    }

    pub fn uint(w: *Writer, number: u32, value: u64) !void {
        try w.tag(number, .uint);
        var scratch: [10]u8 = undefined;
        const n = putVarint(value, &scratch);
        try w.buf.appendSlice(w.allocator, scratch[0..n]);
    }

    pub fn bytes(w: *Writer, number: u32, data: []const u8) !void {
        try w.tag(number, .bytes);
        var scratch: [10]u8 = undefined;
        const n = putVarint(data.len, &scratch);
        try w.buf.appendSlice(w.allocator, scratch[0..n]);
        try w.buf.appendSlice(w.allocator, data);
    }

    pub fn word64(w: *Writer, number: u32, value: u64) !void {
        try w.tag(number, .word64);
        var scratch: [8]u8 = undefined;
        mem.writeInt(u64, &scratch, value, .little);
        try w.buf.appendSlice(w.allocator, &scratch);
    }

    pub fn flag(w: *Writer, number: u32, value: bool) !void {
        try w.uint(number, if (value) 1 else 0);
    }

    /// A zero is the default and is not written.
    pub fn uintIfSet(w: *Writer, number: u32, value: u64) !void {
        if (value != 0) try w.uint(number, value);
    }

    pub fn bytesIfSet(w: *Writer, number: u32, data: []const u8) !void {
        if (data.len != 0) try w.bytes(number, data);
    }

    /// Nested messages carry their own encoded bytes as a byte field.
    pub fn embed(w: *Writer, number: u32, inner: *Writer) !void {
        try w.bytes(number, inner.buf.items);
    }
};

test "fields round trip through the codec" {
    const a = std.testing.allocator;
    var w = Writer.init(a);
    defer w.deinit();
    try w.uint(1, 300);
    try w.bytes(2, "veil");
    try w.word64(3, 0x0102030405060708);
    try w.uintIfSet(4, 0);
    const out = try w.finish();
    defer a.free(out);
    var r = Reader.init(out);
    const f1 = (try r.next()).?;
    try std.testing.expectEqual(@as(u64, 300), f1.uint().?);
    const f2 = (try r.next()).?;
    try std.testing.expectEqualStrings("veil", f2.bytes().?);
    const f3 = (try r.next()).?;
    try std.testing.expectEqual(@as(u64, 0x0102030405060708), f3.word().?);
    try std.testing.expect((try r.next()) == null);
}

test "a truncated byte field is refused" {
    var r = Reader.init(&[_]u8{ 0x12, 0x05, 'a' });
    try std.testing.expectError(ReadError.Truncated, r.next());
}

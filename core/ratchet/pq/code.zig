//! A systematic erasure code over sixteen interleaved polynomials. A message
//! of 2n bytes becomes n points per polynomial; piece i carries the point at
//! x = i of every polynomial, and any n pieces rebuild the message.
const std = @import("std");
const field = @import("field.zig");
const codec = @import("../../wire/codec.zig");
const mem = std.mem;
const Allocator = mem.Allocator;

pub const piece_size = 32;
pub const polynomials = 16;

pub const Piece = struct {
    index: u16,
    data: [piece_size]u8,
};

pub const CodeError = error{ OddLength, TooLong, BadRecord } || Allocator.Error;

const Point = struct { x: u16, y: u16 };

/// Coefficients low to high; n points give exactly n coefficients.
fn fit(allocator: Allocator, points: []const Point) ![]u16 {
    const n = points.len;
    const out = try allocator.alloc(u16, n);
    @memset(out, 0);
    const term = try allocator.alloc(u16, n);
    defer allocator.free(term);
    for (points, 0..) |pi, i| {
        @memset(term, 0);
        term[0] = 1;
        var degree: usize = 0;
        var denominator: u16 = 1;
        for (points, 0..) |pj, j| {
            if (i == j) continue;
            var k = degree + 1;
            while (k > 0) : (k -= 1) term[k] = field.add(term[k - 1], field.mul(term[k], pj.x));
            term[0] = field.mul(term[0], pj.x);
            degree += 1;
            denominator = field.mul(denominator, field.add(pi.x, pj.x));
        }
        const scale = field.div(pi.y, denominator);
        for (out, term) |*o, t| o.* = field.add(o.*, field.mul(t, scale));
    }
    return out;
}

fn at(coefficients: []const u16, x: u16) u16 {
    var acc: u16 = 0;
    var i = coefficients.len;
    while (i > 0) : (i -= 1) acc = field.add(field.mul(acc, x), coefficients[i - 1]);
    return acc;
}

/// Spreads a message over pieces. Before the first parity piece the columns
/// hold message points; afterwards they hold fitted coefficients.
pub const Spread = struct {
    next: u32,
    columns: [polynomials]std.ArrayList(u16),
    fitted: bool,

    pub fn of(allocator: Allocator, message: []const u8) CodeError!Spread {
        if (message.len % 2 != 0) return CodeError.OddLength;
        if (message.len > (1 << 16) * polynomials) return CodeError.TooLong;
        var s: Spread = .{ .next = 0, .columns = undefined, .fitted = false };
        for (&s.columns) |*c| c.* = .empty;
        errdefer s.deinit(allocator);
        var i: usize = 0;
        while (i + 1 < message.len) : (i += 2) {
            try s.columns[(i / 2) % polynomials].append(allocator, (@as(u16, message[i]) << 8) | message[i + 1]);
        }
        return s;
    }

    pub fn deinit(s: *Spread, allocator: Allocator) void {
        for (&s.columns) |*c| c.deinit(allocator);
    }

    fn point(s: *Spread, allocator: Allocator, column: usize, x: usize) !u16 {
        if (!s.fitted) {
            if (x < s.columns[column].items.len) return s.columns[column].items[x];
            for (&s.columns) |*c| {
                const points = try allocator.alloc(Point, c.items.len);
                defer allocator.free(points);
                for (points, c.items, 0..) |*p, y, i| p.* = .{ .x = @intCast(i), .y = y };
                const coefficients = try fit(allocator, points);
                defer allocator.free(coefficients);
                c.clearRetainingCapacity();
                try c.appendSlice(allocator, coefficients);
            }
            s.fitted = true;
        }
        return at(s.columns[column].items, @intCast(x));
    }

    pub fn pieceAt(s: *Spread, allocator: Allocator, index: u16) !Piece {
        var out: Piece = .{ .index = index, .data = undefined };
        for (0..polynomials) |i| {
            const y = try s.point(allocator, i, index);
            out.data[i * 2] = @intCast(y >> 8);
            out.data[i * 2 + 1] = @truncate(y);
        }
        return out;
    }

    pub fn nextPiece(s: *Spread, allocator: Allocator) !Piece {
        const out = try s.pieceAt(allocator, @truncate(s.next));
        s.next +%= 1;
        return out;
    }

    pub fn write(s: *const Spread, w: *codec.Writer) !void {
        try w.uintIfSet(1, s.next);
        for (s.columns) |c| {
            const bytes = try w.allocator.alloc(u8, c.items.len * 2);
            defer w.allocator.free(bytes);
            for (c.items, 0..) |v, i| mem.writeInt(u16, bytes[i * 2 ..][0..2], v, .big);
            try w.bytes(if (s.fitted) 3 else 2, bytes);
        }
    }

    pub fn read(allocator: Allocator, data: []const u8) CodeError!Spread {
        var s: Spread = .{ .next = 0, .columns = undefined, .fitted = false };
        for (&s.columns) |*c| c.* = .empty;
        errdefer s.deinit(allocator);
        var raw_columns: usize = 0;
        var fitted_columns: usize = 0;
        var r = codec.Reader.init(data);
        while (r.next() catch return CodeError.BadRecord) |f| switch (f.number) {
            1 => s.next = std.math.cast(u32, f.uint() orelse 0) orelse return CodeError.BadRecord,
            2, 3 => {
                const b = f.bytes() orelse return CodeError.BadRecord;
                const count = if (f.number == 2) &raw_columns else &fitted_columns;
                if (count.* >= polynomials or b.len % 2 != 0) return CodeError.BadRecord;
                const c = &s.columns[count.*];
                count.* += 1;
                var i: usize = 0;
                while (i < b.len) : (i += 2) try c.append(allocator, mem.readInt(u16, b[i..][0..2], .big));
            },
            else => {},
        };
        if (raw_columns != 0) {
            if (fitted_columns != 0 or raw_columns != polynomials) return CodeError.BadRecord;
        } else if (fitted_columns == polynomials) {
            for (s.columns) |c| if (c.items.len == 0) return CodeError.BadRecord;
            s.fitted = true;
        } else return CodeError.BadRecord;
        return s;
    }
};

/// Gathers pieces until every polynomial has enough points.
pub const Gather = struct {
    needed: usize,
    points: [polynomials]std.ArrayList(Point),
    done: bool,

    pub fn forLength(len: usize) CodeError!Gather {
        if (len % 2 != 0) return CodeError.OddLength;
        var g: Gather = .{ .needed = len / 2, .points = undefined, .done = false };
        for (&g.points) |*p| p.* = .empty;
        return g;
    }

    pub fn deinit(g: *Gather, allocator: Allocator) void {
        for (&g.points) |*p| p.deinit(allocator);
    }

    fn needFor(g: *const Gather, column: usize) usize {
        const per = g.needed / polynomials;
        const extra = g.needed % polynomials;
        return if (column < extra) per + 1 else per;
    }

    fn insert(allocator: Allocator, column: *std.ArrayList(Point), p: Point) !void {
        var lo: usize = 0;
        var hi: usize = column.items.len;
        while (lo < hi) {
            const mid = (lo + hi) / 2;
            if (column.items[mid].x < p.x) lo = mid + 1 else hi = mid;
        }
        if (lo < column.items.len and column.items[lo].x == p.x) return;
        try column.insert(allocator, lo, p);
    }

    fn lookup(column: []const Point, x: u16) ?u16 {
        var lo: usize = 0;
        var hi: usize = column.len;
        while (lo < hi) {
            const mid = (lo + hi) / 2;
            if (column[mid].x < x) lo = mid + 1 else hi = mid;
        }
        return if (lo < column.len and column[lo].x == x) column[lo].y else null;
    }

    pub fn add(g: *Gather, allocator: Allocator, piece: *const Piece) !void {
        for (0..polynomials) |i| {
            const need = g.needFor(i);
            const y = (@as(u16, piece.data[i * 2]) << 8) | piece.data[i * 2 + 1];
            if (piece.index < need or g.points[i].items.len < need) try insert(allocator, &g.points[i], .{ .x = piece.index, .y = y });
        }
    }

    /// The message once every polynomial has enough points; null until then.
    pub fn message(g: *const Gather, allocator: Allocator) !?[]u8 {
        if (g.done) return null;
        for (0..polynomials) |i| if (g.points[i].items.len < g.needFor(i)) return null;
        var fits: [polynomials]?[]u16 = .{null} ** polynomials;
        defer for (fits) |f| if (f) |c| allocator.free(c);
        const out = try allocator.alloc(u8, g.needed * 2);
        errdefer allocator.free(out);
        for (0..g.needed) |i| {
            const column = i % polynomials;
            const x: u16 = @intCast(i / polynomials);
            const y = lookup(g.points[column].items, x) orelse blk: {
                if (fits[column] == null) fits[column] = try fit(allocator, g.points[column].items[0..g.needFor(column)]);
                break :blk at(fits[column].?, x);
            };
            out[i * 2] = @intCast(y >> 8);
            out[i * 2 + 1] = @truncate(y);
        }
        return out;
    }

    pub fn write(g: *const Gather, w: *codec.Writer) !void {
        try w.uintIfSet(1, g.needed);
        try w.uint(2, polynomials);
        for (g.points) |column| {
            const bytes = try w.allocator.alloc(u8, column.items.len * 4);
            defer w.allocator.free(bytes);
            for (column.items, 0..) |p, i| {
                mem.writeInt(u16, bytes[i * 4 ..][0..2], p.x, .big);
                mem.writeInt(u16, bytes[i * 4 + 2 ..][0..2], p.y, .big);
            }
            try w.bytes(3, bytes);
        }
        if (g.done) try w.uint(4, 1);
    }

    pub fn read(allocator: Allocator, data: []const u8) CodeError!Gather {
        var g: Gather = .{ .needed = 0, .points = undefined, .done = false };
        for (&g.points) |*p| p.* = .empty;
        errdefer g.deinit(allocator);
        var columns: usize = 0;
        var r = codec.Reader.init(data);
        while (r.next() catch return CodeError.BadRecord) |f| switch (f.number) {
            1 => g.needed = std.math.cast(usize, f.uint() orelse 0) orelse return CodeError.BadRecord,
            3 => {
                const b = f.bytes() orelse return CodeError.BadRecord;
                if (columns >= polynomials or b.len % 4 != 0) return CodeError.BadRecord;
                const column = &g.points[columns];
                columns += 1;
                var i: usize = 0;
                while (i < b.len) : (i += 4) try column.append(allocator, .{ .x = mem.readInt(u16, b[i..][0..2], .big), .y = mem.readInt(u16, b[i + 2 ..][0..2], .big) });
            },
            4 => g.done = (f.uint() orelse 0) != 0,
            else => {},
        };
        if (columns != polynomials) return CodeError.BadRecord;
        return g;
    }
};

test "any n pieces rebuild the message" {
    const a = std.testing.allocator;
    var message: [1152]u8 = undefined;
    for (&message, 0..) |*b, i| b.* = @truncate(i * 7 + 3);
    var spread = try Spread.of(a, &message);
    defer spread.deinit(a);
    var gather = try Gather.forLength(message.len);
    defer gather.deinit(a);
    var index: u16 = 36;
    while (index < 76) : (index += 1) {
        const piece = try spread.pieceAt(a, index);
        try gather.add(a, &piece);
        if (try gather.message(a)) |rebuilt| {
            defer a.free(rebuilt);
            try std.testing.expectEqualSlices(u8, &message, rebuilt);
            return;
        }
    }
    return error.TestUnexpectedResult;
}

test "a systematic piece and a parity piece mix, and the spread round trips its record" {
    const a = std.testing.allocator;
    const message = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ!!";
    var spread = try Spread.of(a, message);
    defer spread.deinit(a);
    var gather = try Gather.forLength(message.len);
    defer gather.deinit(a);
    const p2 = try spread.pieceAt(a, 2);
    const p0 = try spread.pieceAt(a, 0);
    try gather.add(a, &p2);
    try std.testing.expect((try gather.message(a)) == null);
    try gather.add(a, &p0);
    const rebuilt = (try gather.message(a)).?;
    defer a.free(rebuilt);
    try std.testing.expectEqualStrings(message, rebuilt);
    var w = codec.Writer.init(a);
    defer w.deinit();
    try spread.write(&w);
    var back = try Spread.read(a, w.buf.items);
    defer back.deinit(a);
    try std.testing.expectEqualSlices(u8, &(try spread.pieceAt(a, 5)).data, &(try back.pieceAt(a, 5)).data);
}

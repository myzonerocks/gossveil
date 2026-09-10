//! Account identifiers: an id typed as an account (ACI) or a phone-number
//! identity (PNI), in the three encodings the protocol uses.
const std = @import("std");
const mem = std.mem;
const Uuid = @import("uuid.zig").Uuid;
const Fault = @import("../fault.zig").Fault;

pub const text_max_length = 4 + 36;

pub const Kind = enum(u8) { aci = 0, pni = 1 };

pub const ServiceId = struct {
    kind: Kind,
    id: Uuid,

    pub fn aci(id: Uuid) ServiceId {
        return .{ .kind = .aci, .id = id };
    }

    pub fn pni(id: Uuid) ServiceId {
        return .{ .kind = .pni, .id = id };
    }

    /// Seventeen bytes: the kind, then the id.
    pub fn fixed(s: ServiceId) [17]u8 {
        var out: [17]u8 = undefined;
        out[0] = @intFromEnum(s.kind);
        out[1..].* = s.id.bytes;
        return out;
    }

    pub fn fromFixed(b: [17]u8) Fault!ServiceId {
        const kind: Kind = switch (b[0]) {
            0 => .aci,
            1 => .pni,
            else => return Fault.BadArgument,
        };
        return .{ .kind = kind, .id = Uuid.fromBytes(b[1..].*) };
    }

    /// Sixteen bytes for an account, seventeen with a leading one for a phone identity.
    pub fn compact(s: ServiceId, buf: *[17]u8) []u8 {
        switch (s.kind) {
            .aci => {
                buf[0..16].* = s.id.bytes;
                return buf[0..16];
            },
            .pni => {
                buf.* = s.fixed();
                return buf[0..17];
            },
        }
    }

    pub fn fromCompact(b: []const u8) Fault!ServiceId {
        if (b.len == 16) return aci(Uuid.fromBytes(b[0..16].*));
        if (b.len == 17 and b[0] == 1) return pni(Uuid.fromBytes(b[1..17].*));
        return Fault.BadArgument;
    }

    pub fn parse(source: []const u8) Fault!ServiceId {
        if (mem.startsWith(u8, source, "PNI:")) return pni(try Uuid.parse(source[4..]));
        return aci(try Uuid.parse(source));
    }

    pub fn text(s: ServiceId, buf: []u8) []const u8 {
        return switch (s.kind) {
            .aci => std.fmt.bufPrint(buf, "{f}", .{s.id}) catch unreachable,
            .pni => std.fmt.bufPrint(buf, "PNI:{f}", .{s.id}) catch unreachable,
        };
    }

    pub fn eql(a: ServiceId, b: ServiceId) bool {
        return a.kind == b.kind and Uuid.eql(a.id, b.id);
    }
};

test "both kinds round trip through every encoding" {
    inline for (.{ Kind.aci, Kind.pni }) |kind| {
        const s = ServiceId{ .kind = kind, .id = Uuid.random() };
        try std.testing.expect(s.eql(try ServiceId.fromFixed(s.fixed())));
        var buf: [17]u8 = undefined;
        try std.testing.expect(s.eql(try ServiceId.fromCompact(s.compact(&buf))));
        var tb: [text_max_length]u8 = undefined;
        try std.testing.expect(s.eql(try ServiceId.parse(s.text(&tb))));
    }
}

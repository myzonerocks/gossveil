//! gossveil: end-to-end encryption for messaging. This root re-exports every
//! area of the core; each area is one directory with its own tests.
const std = @import("std");

pub const version = "0.1.0-alpha.1";

pub const Fault = @import("fault.zig").Fault;
pub const entropy = @import("entropy.zig");

pub const wire = struct {
    pub const codec = @import("wire/codec.zig");
    pub const frame = @import("wire/frame.zig");
};

pub const keys = struct {
    pub const curve = @import("keys/curve.zig");
    pub const sign = @import("keys/sign.zig");
    pub const pq = @import("keys/pq.zig");
    pub const identity = @import("keys/identity.zig");
    pub const derive = @import("keys/derive.zig");
    pub const cipher = @import("keys/cipher.zig");
    pub const mac = @import("keys/mac.zig");
};

pub const bundle = struct {
    pub const records = @import("bundle/records.zig");
    pub const Published = @import("bundle/published.zig").Published;
};

pub const ratchet = struct {
    pub const chain = @import("ratchet/chain.zig");
    pub const state = @import("ratchet/state.zig");
    pub const State = state.State;
    pub const Archive = @import("ratchet/archive.zig").Archive;
};

pub const handshake = struct {
    pub const agree = @import("handshake/agree.zig");
};

pub const ident = struct {
    pub const Uuid = @import("ident/uuid.zig").Uuid;
    pub const service = @import("ident/service.zig");
    pub const ServiceId = service.ServiceId;
    pub const Address = @import("ident/address.zig").Address;
};

test {
    std.testing.refAllDecls(@This());
    std.testing.refAllDecls(wire);
    std.testing.refAllDecls(keys);
    std.testing.refAllDecls(ident);
    std.testing.refAllDecls(bundle);
    std.testing.refAllDecls(ratchet);
    std.testing.refAllDecls(handshake);
}

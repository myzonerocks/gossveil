//! What a device publishes so a peer can open a session with it: its identity,
//! a signed key, an optional one-time key and a post-quantum key, with the
//! identity's signatures over both signed keys.
const curve = @import("../keys/curve.zig");
const pq = @import("../keys/pq.zig");
const identity = @import("../keys/identity.zig");
const Fault = @import("../fault.zig").Fault;

pub const Published = struct {
    registration_id: u32,
    device: u32,
    one_time_id: ?u32,
    one_time: ?curve.Public,
    signed_id: u32,
    signed: curve.Public,
    signed_signature: [curve.signature_length]u8,
    identity: identity.Identity,
    pq_id: u32,
    pq_key: pq.Public,
    pq_signature: [curve.signature_length]u8,

    pub fn init(
        registration_id: u32,
        device: u32,
        one_time_id: ?u32,
        one_time: ?curve.Public,
        signed_id: u32,
        signed: curve.Public,
        signed_signature: []const u8,
        who: identity.Identity,
        pq_id: u32,
        pq_key: pq.Public,
        pq_signature: []const u8,
    ) Fault!Published {
        if ((one_time_id == null) != (one_time == null)) return Fault.BadArgument;
        if (signed_signature.len != curve.signature_length or pq_signature.len != curve.signature_length) return Fault.BadSignature;
        return .{
            .registration_id = registration_id,
            .device = device,
            .one_time_id = one_time_id,
            .one_time = one_time,
            .signed_id = signed_id,
            .signed = signed,
            .signed_signature = signed_signature[0..curve.signature_length].*,
            .identity = who,
            .pq_id = pq_id,
            .pq_key = pq_key,
            .pq_signature = pq_signature[0..curve.signature_length].*,
        };
    }

    /// Both signatures are over the serialised key, tag byte included.
    pub fn check(p: Published) Fault!void {
        if (!p.identity.key.verify(&p.signed.serialize(), p.signed_signature)) return Fault.BadSignature;
        if (!p.identity.key.verify(&p.pq_key.serialize(), p.pq_signature)) return Fault.BadSignature;
    }
};

test "a bundle checks its signatures and refuses a mismatched one-time pair" {
    const records = @import("records.zig");
    const me = try identity.IdentityPair.generate();
    const signed = try records.SignedRecord.generate(1, 1, me.secret);
    const post = try records.PqRecord.generate(1, 1, .round_three, me.secret);
    const bundle = try Published.init(1, 1, null, null, 1, signed.pair.public, &signed.signature, me.identity, 1, post.pair.public, &post.signature);
    try bundle.check();
    try @import("std").testing.expectError(Fault.BadArgument, Published.init(1, 1, 7, null, 1, signed.pair.public, &signed.signature, me.identity, 1, post.pair.public, &post.signature));
    var forged = bundle;
    forged.signed_signature[0] ^= 1;
    try @import("std").testing.expectError(Fault.BadSignature, forged.check());
}

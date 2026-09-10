//! Answers one JSON operation on stdin with one JSON object on stdout, or
//! replays a directory of recorded operations and compares every stable
//! field. Byte fields are base64. Nothing persists between runs.
const std = @import("std");
const veil = @import("gossveil");
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const b64 = std.base64.standard;

const curve = veil.keys.curve;
const pq = veil.keys.pq;
const identity = veil.keys.identity;
const derive = veil.keys.derive;
const cipher = veil.keys.cipher;
const records = veil.bundle.records;
const Published = veil.bundle.Published;
const Archive = veil.ratchet.Archive;
const engine = veil.ratchet.engine;
const pq_record = veil.ratchet.pq.record;
const Whisper = veil.post.Whisper;
const Opener = veil.post.Opener;
const Binding = veil.post.whisper.Binding;
const post_content = veil.post.content;
const Report = veil.post.Report;
const Circle = veil.circle.Circle;
const circle_post = veil.circle.post;
const circle_cipher = veil.circle.cipher;
const certificate = veil.envelope.certificate;
const Content = veil.envelope.Content;
const envelope_seal = veil.envelope.seal;
const multiseal = veil.envelope.multiseal;
const safety = veil.trust.safety;
const name = veil.handle.name;
const link = veil.handle.link;
const account = veil.vault.account;
const circle_params = veil.vault.circle_params;
const ServiceId = veil.ident.ServiceId;
const Uuid = veil.ident.Uuid;

const default_now: u64 = 1_700_000_000;

const Input = struct {
    arena: Allocator,
    obj: std.json.ObjectMap,

    fn str(in: Input, key: []const u8) ![]const u8 {
        const v = in.obj.get(key) orelse return error.MissingField;
        return if (v == .string) v.string else error.WrongType;
    }

    fn optStr(in: Input, key: []const u8) ?[]const u8 {
        const v = in.obj.get(key) orelse return null;
        return if (v == .string) v.string else null;
    }

    fn blob(in: Input, key: []const u8) ![]u8 {
        return decode(in.arena, try in.str(key));
    }

    fn optBlob(in: Input, key: []const u8) !?[]u8 {
        const s = in.optStr(key) orelse return null;
        return try decode(in.arena, s);
    }

    fn fixed(in: Input, key: []const u8, comptime n: usize) ![n]u8 {
        const b = try in.blob(key);
        if (b.len != n) return error.WrongLength;
        return b[0..n].*;
    }

    fn number(in: Input, key: []const u8) !u64 {
        const v = in.obj.get(key) orelse return error.MissingField;
        return if (v == .integer) @intCast(v.integer) else error.WrongType;
    }

    fn optNumber(in: Input, key: []const u8) !?u64 {
        const v = in.obj.get(key) orelse return null;
        return switch (v) {
            .integer => |i| @intCast(i),
            .null => null,
            else => error.WrongType,
        };
    }

    fn word32(in: Input, key: []const u8) !u32 {
        return @intCast(try in.number(key));
    }

    fn nested(in: Input, key: []const u8) !Input {
        const v = in.obj.get(key) orelse return error.MissingField;
        return if (v == .object) .{ .arena = in.arena, .obj = v.object } else error.WrongType;
    }

    fn optNested(in: Input, key: []const u8) !?Input {
        const v = in.obj.get(key) orelse return null;
        return switch (v) {
            .object => |o| .{ .arena = in.arena, .obj = o },
            .null => null,
            else => error.WrongType,
        };
    }

    fn items(in: Input, key: []const u8) ![]Value {
        const v = in.obj.get(key) orelse return &.{};
        return if (v == .array) v.array.items else error.WrongType;
    }
};

fn decode(arena: Allocator, s: []const u8) ![]u8 {
    const out = try arena.alloc(u8, try b64.Decoder.calcSizeForSlice(s));
    try b64.Decoder.decode(out, s);
    return out;
}

const Answer = struct {
    arena: Allocator,
    buf: std.ArrayList(u8) = .empty,
    first: bool = true,

    fn key(a: *Answer, field: []const u8) !void {
        try a.buf.append(a.arena, if (a.first) '{' else ',');
        a.first = false;
        try a.buf.append(a.arena, '"');
        try a.buf.appendSlice(a.arena, field);
        try a.buf.appendSlice(a.arena, "\":");
    }

    fn blob(a: *Answer, field: []const u8, data: []const u8) !void {
        try a.key(field);
        try a.buf.append(a.arena, '"');
        const start = a.buf.items.len;
        try a.buf.resize(a.arena, start + b64.Encoder.calcSize(data.len));
        _ = b64.Encoder.encode(a.buf.items[start..], data);
        try a.buf.append(a.arena, '"');
    }

    fn number(a: *Answer, field: []const u8, v: u64) !void {
        try a.key(field);
        try a.buf.print(a.arena, "{d}", .{v});
    }

    fn optNumber(a: *Answer, field: []const u8, v: ?u64) !void {
        try a.key(field);
        if (v) |x| try a.buf.print(a.arena, "{d}", .{x}) else try a.buf.appendSlice(a.arena, "null");
    }

    fn flag(a: *Answer, field: []const u8, v: bool) !void {
        try a.key(field);
        try a.buf.appendSlice(a.arena, if (v) "true" else "false");
    }

    fn text(a: *Answer, field: []const u8, s: []const u8) !void {
        try a.key(field);
        try a.buf.append(a.arena, '"');
        for (s) |ch| switch (ch) {
            '"' => try a.buf.appendSlice(a.arena, "\\\""),
            '\\' => try a.buf.appendSlice(a.arena, "\\\\"),
            '\n' => try a.buf.appendSlice(a.arena, "\\n"),
            else => try a.buf.append(a.arena, ch),
        };
        try a.buf.append(a.arena, '"');
    }

    fn finish(a: *Answer) ![]const u8 {
        if (a.first) try a.buf.append(a.arena, '{');
        try a.buf.appendSlice(a.arena, "}\n");
        return a.buf.items;
    }
};

const Handler = *const fn (Allocator, Input, *Answer) anyerror!void;

const handlers = std.StaticStringMap(Handler).initComptime(.{
    .{ "ping", opPing },
    .{ "ec_keypair", opCurvePair },
    .{ "ec_public", opCurvePublic },
    .{ "ec_sign", opCurveSign },
    .{ "ec_verify", opCurveVerify },
    .{ "ec_agree", opCurveAgree },
    .{ "kem_keypair", opPqPair },
    .{ "kem_encaps", opPqEncapsulate },
    .{ "kem_decaps", opPqOpen },
    .{ "identity_keypair", opIdentityPair },
    .{ "identity_keypair_parse", opIdentityParse },
    .{ "identity_keypair_serialize", opIdentitySerialize },
    .{ "prekey_record", opOneTimeRecord },
    .{ "prekey_record_parse", opOneTimeParse },
    .{ "signed_prekey_record", opSignedRecord },
    .{ "signed_prekey_record_parse", opSignedParse },
    .{ "kyber_prekey_record", opPqRecord },
    .{ "kyber_prekey_record_parse", opPqRecordParse },
    .{ "session_process_bundle", opSessionStart },
    .{ "session_encrypt", opSessionSeal },
    .{ "session_decrypt", opSessionOpen },
    .{ "session_decrypt_prekey", opSessionOpenFirst },
    .{ "prekey_message_parse", opOpenerParse },
    .{ "whisper_parse", opWhisperParse },
    .{ "session_record_info", opSessionInfo },
    .{ "session_archive", opSessionShelve },
    .{ "sender_key_create", opCircleAnnounce },
    .{ "sender_key_process", opCircleAdmit },
    .{ "group_encrypt", opCircleSeal },
    .{ "group_decrypt", opCircleOpen },
    .{ "fingerprint", opSafety },
    .{ "fingerprint_compare", opSafetyMatches },
    .{ "username_hash", opHandleHash },
    .{ "username_proof", opHandleProof },
    .{ "username_verify", opHandleVerify },
    .{ "username_link_create", opHandleLink },
    .{ "username_link_decrypt", opHandleLinkOpen },
    .{ "aep_derive", opPoolDerive },
    .{ "aep_valid", opPoolValid },
    .{ "backup_key_derive", opBackupKeyDerive },
    .{ "hkdf", opHkdf },
    .{ "aes_gcm_siv_encrypt", opSivSeal },
    .{ "aes_gcm_siv_decrypt", opSivOpen },
    .{ "decryption_error_message", opReport },
    .{ "decryption_error_for_original", opReportForOriginal },
    .{ "decryption_error_message_parse", opReportParse },
    .{ "plaintext_content_from_dem", opPlainFromReport },
    .{ "plaintext_content_extract_dem", opPlainExtractReport },
    .{ "server_cert_new", opServerCert },
    .{ "server_cert_parse", opServerCertParse },
    .{ "sender_cert_new", opSenderCert },
    .{ "sender_cert_parse", opSenderCertParse },
    .{ "usmc_new", opContent },
    .{ "usmc_parse", opContentParse },
    .{ "sealed_sender_encrypt", opEnvelopeSeal },
    .{ "sealed_sender_decrypt_to_usmc", opEnvelopeOpen },
    .{ "sealed_sender_v2_encrypt", opEnvelopeSealMany },
    .{ "sealed_sender_v2_single", opEnvelopeSplit },
    .{ "group_master_key", opCircleMaster },
    .{ "group_secret_params_parse", opCircleParamsParse },
    .{ "spqr_init", opBraidStart },
    .{ "spqr_send", opBraidSend },
    .{ "spqr_recv", opBraidReceive },
});

fn usFrom(in: Input, key: []const u8) !identity.IdentityPair {
    return identity.IdentityPair.fromPair(try curve.Pair.fromSecret(try curve.Secret.parse(try in.blob(key))));
}

fn bindingFrom(in: Input) !?Binding {
    const both = (try in.optNested("addresses")) orelse return null;
    const sender = try both.nested("sender");
    const recipient = try both.nested("recipient");
    return .{
        .sender = .{ .name = try sender.str("name"), .device = try sender.word32("device_id") },
        .recipient = .{ .name = try recipient.str("name"), .device = try recipient.word32("device_id") },
    };
}

fn archiveFrom(arena: Allocator, in: Input, key: []const u8) !Archive {
    const bytes = (try in.optBlob(key)) orelse return Archive.init(arena);
    return if (bytes.len == 0) Archive.init(arena) else Archive.parse(arena, bytes);
}

fn circleFrom(arena: Allocator, in: Input, key: []const u8) !Circle {
    const bytes = (try in.optBlob(key)) orelse return Circle.init(arena);
    return if (bytes.len == 0) Circle.init(arena) else Circle.parse(arena, bytes);
}

fn kindFrom(v: u64) !engine.Kind {
    const byte = std.math.cast(u8, v) orelse return error.BadArgument;
    return std.enums.fromInt(engine.Kind, byte) orelse error.BadArgument;
}

fn nowFrom(in: Input) !u64 {
    return (try in.optNumber("now_secs")) orelse default_now;
}

fn opPing(_: Allocator, _: Input, out: *Answer) !void {
    try out.text("pong", "ok");
}

fn opCurvePair(_: Allocator, _: Input, out: *Answer) !void {
    const pair = try curve.Pair.generate();
    try out.blob("priv", &pair.secret.serialize());
    try out.blob("pub", &pair.public.serialize());
}

fn opCurvePublic(_: Allocator, in: Input, out: *Answer) !void {
    const secret = try curve.Secret.parse(try in.blob("priv"));
    try out.blob("pub", &(try secret.public()).serialize());
}

fn opCurveSign(_: Allocator, in: Input, out: *Answer) !void {
    const secret = try curve.Secret.parse(try in.blob("priv"));
    try out.blob("sig", &try secret.sign(try in.blob("msg")));
}

fn opCurveVerify(_: Allocator, in: Input, out: *Answer) !void {
    const public = try curve.Public.parse(try in.blob("pub"));
    try out.flag("ok", public.verify(try in.blob("msg"), try in.fixed("sig", 64)));
}

fn opCurveAgree(_: Allocator, in: Input, out: *Answer) !void {
    const secret = try curve.Secret.parse(try in.blob("priv"));
    try out.blob("shared", &try secret.agree(try curve.Public.parse(try in.blob("pub"))));
}

fn opPqPair(_: Allocator, in: Input, out: *Answer) !void {
    const scheme = try pq.Scheme.fromByte(@intCast((try in.optNumber("type")) orelse 0x08));
    const pair = try pq.Pair.generate(scheme);
    try out.blob("pub", &pair.public.serialize());
    try out.blob("secret", &pair.secret.serialize());
}

fn opPqEncapsulate(_: Allocator, in: Input, out: *Answer) !void {
    const public = try pq.Public.parse(try in.blob("pub"));
    const capsule = try public.encapsulate();
    try out.blob("ct", &capsule.bytes);
    try out.blob("ss", &capsule.shared);
}

fn opPqOpen(_: Allocator, in: Input, out: *Answer) !void {
    const secret = try pq.Secret.parse(try in.blob("secret"));
    try out.blob("ss", &try secret.open(try in.blob("ct")));
}

fn opIdentityPair(arena: Allocator, _: Input, out: *Answer) !void {
    const pair = try identity.IdentityPair.generate();
    try out.blob("serialized", try pair.serialize(arena));
    try out.blob("pub", &pair.identity.serialize());
    try out.blob("priv", &pair.secret.serialize());
}

fn opIdentityParse(_: Allocator, in: Input, out: *Answer) !void {
    const pair = try identity.IdentityPair.parse(try in.blob("serialized"));
    try out.blob("pub", &pair.identity.serialize());
    try out.blob("priv", &pair.secret.serialize());
}

fn opIdentitySerialize(arena: Allocator, in: Input, out: *Answer) !void {
    try out.blob("serialized", try (try usFrom(in, "priv")).serialize(arena));
}

fn pairFrom(in: Input, key: []const u8) !curve.Pair {
    return curve.Pair.fromSecret(try curve.Secret.parse(try in.blob(key)));
}

fn opOneTimeRecord(arena: Allocator, in: Input, out: *Answer) !void {
    const record = records.OneTimeRecord{ .id = try in.word32("id"), .pair = try pairFrom(in, "priv") };
    try out.blob("serialized", try record.serialize(arena));
}

fn opOneTimeParse(_: Allocator, in: Input, out: *Answer) !void {
    const record = try records.OneTimeRecord.parse(try in.blob("serialized"));
    try out.number("id", record.id);
    try out.blob("pub", &record.pair.public.serialize());
    try out.blob("priv", &record.pair.secret.serialize());
}

fn opSignedRecord(arena: Allocator, in: Input, out: *Answer) !void {
    const record = records.SignedRecord{
        .id = try in.word32("id"),
        .stamp = try in.number("timestamp"),
        .pair = try pairFrom(in, "priv"),
        .signature = try in.fixed("sig", 64),
    };
    try out.blob("serialized", try record.serialize(arena));
}

fn opSignedParse(_: Allocator, in: Input, out: *Answer) !void {
    const record = try records.SignedRecord.parse(try in.blob("serialized"));
    try out.number("id", record.id);
    try out.number("timestamp", record.stamp);
    try out.blob("pub", &record.pair.public.serialize());
    try out.blob("priv", &record.pair.secret.serialize());
    try out.blob("sig", &record.signature);
}

fn opPqRecord(arena: Allocator, in: Input, out: *Answer) !void {
    const record = records.PqRecord{
        .id = try in.word32("id"),
        .stamp = try in.number("timestamp"),
        .pair = .{ .public = try pq.Public.parse(try in.blob("pub")), .secret = try pq.Secret.parse(try in.blob("secret")) },
        .signature = try in.fixed("sig", 64),
    };
    try out.blob("serialized", try record.serialize(arena));
}

fn opPqRecordParse(_: Allocator, in: Input, out: *Answer) !void {
    const record = try records.PqRecord.parse(try in.blob("serialized"));
    try out.number("id", record.id);
    try out.number("timestamp", record.stamp);
    try out.blob("pub", &record.pair.public.serialize());
    try out.blob("secret", &record.pair.secret.serialize());
    try out.blob("sig", &record.signature);
}

fn opSessionStart(arena: Allocator, in: Input, out: *Answer) !void {
    const b = try in.nested("bundle");
    const one_time_id = try b.optNumber("pre_key_id");
    const one_time: ?curve.Public = if (try b.optBlob("pre_key")) |raw| try curve.Public.parse(raw) else null;
    const published = try Published.init(
        try b.word32("registration_id"),
        try b.word32("device_id"),
        if (one_time_id) |id| @intCast(id) else null,
        one_time,
        try b.word32("signed_pre_key_id"),
        try curve.Public.parse(try b.blob("signed_pre_key")),
        try b.blob("signed_pre_key_sig"),
        try identity.Identity.parse(try b.blob("identity_key")),
        try b.word32("kyber_pre_key_id"),
        try pq.Public.parse(try b.blob("kyber_pre_key")),
        try b.blob("kyber_pre_key_sig"),
    );
    var archive = try archiveFrom(arena, in, "session_record");
    try engine.start(arena, &archive, try usFrom(in, "identity_priv"), try in.word32("registration_id"), published, try nowFrom(in));
    try out.blob("session_record", try archive.serialize(arena));
}

fn opSessionSeal(arena: Allocator, in: Input, out: *Answer) !void {
    var archive = try archiveFrom(arena, in, "session_record");
    const sealed = try engine.seal(arena, &archive, try in.blob("plaintext"), try nowFrom(in), try bindingFrom(in));
    try out.number("type", @intFromEnum(sealed.kind));
    try out.blob("ciphertext", sealed.bytes);
    try out.blob("session_record", try archive.serialize(arena));
}

fn opSessionOpen(arena: Allocator, in: Input, out: *Answer) !void {
    var archive = try archiveFrom(arena, in, "session_record");
    const message = try Whisper.parse(arena, try in.blob("ciphertext"));
    const plain = try engine.openWhisper(arena, &archive, message, try bindingFrom(in));
    try out.blob("plaintext", plain);
    try out.blob("session_record", try archive.serialize(arena));
    try out.blob("remote_identity", &(try archive.remoteIdentity()).serialize());
}

fn opSessionOpenFirst(arena: Allocator, in: Input, out: *Answer) !void {
    var archive = try archiveFrom(arena, in, "session_record");
    const first = try Opener.parse(arena, try in.blob("ciphertext"));
    var offered: engine.Offered = .{ .signed = null, .one_time = null, .pq = null };
    for (try in.items("signed_prekeys")) |v| {
        const r = try records.SignedRecord.parse(try decode(arena, v.string));
        if (r.id == first.signed_id) offered.signed = r;
    }
    for (try in.items("prekeys")) |v| {
        const r = try records.OneTimeRecord.parse(try decode(arena, v.string));
        if (first.one_time_id != null and r.id == first.one_time_id.?) offered.one_time = r;
    }
    for (try in.items("kyber_prekeys")) |v| {
        const r = try records.PqRecord.parse(try decode(arena, v.string));
        if (first.pq_id != null and r.id == first.pq_id.?) offered.pq = r;
    }
    const opened = try engine.openFirst(arena, &archive, try usFrom(in, "identity_priv"), try in.word32("registration_id"), first, offered, try bindingFrom(in));
    try out.blob("plaintext", opened.plain);
    try out.blob("session_record", try archive.serialize(arena));
    try out.blob("remote_identity", &first.identity.serialize());
    if (opened.consumed) |used| {
        try out.optNumber("used_pre_key_id", if (used.one_time_id) |id| id else null);
        try out.number("used_signed_pre_key_id", used.signed_id);
        try out.number("used_kyber_pre_key_id", used.pq_id);
    }
}

fn opOpenerParse(arena: Allocator, in: Input, out: *Answer) !void {
    const o = try Opener.parse(arena, try in.blob("ciphertext"));
    try out.number("version", o.version);
    try out.number("registration_id", o.registration_id);
    try out.optNumber("pre_key_id", if (o.one_time_id) |id| id else null);
    try out.number("signed_pre_key_id", o.signed_id);
    try out.optNumber("kyber_pre_key_id", if (o.pq_id) |id| id else null);
    try out.blob("base_key", &o.base.serialize());
    try out.blob("identity_key", &o.identity.serialize());
    try out.blob("message", o.inner);
}

fn opWhisperParse(arena: Allocator, in: Input, out: *Answer) !void {
    const w = try Whisper.parse(arena, try in.blob("ciphertext"));
    try out.number("version", w.version);
    try out.number("counter", w.index);
    try out.number("previous_counter", w.previous_index);
    try out.blob("ratchet_key", &w.ratchet.serialize());
    try out.blob("body", w.body);
    try out.blob("pq_ratchet", w.pq_packet);
}

fn opSessionInfo(arena: Allocator, in: Input, out: *Answer) !void {
    var archive = try archiveFrom(arena, in, "session_record");
    const has_live = archive.live() != null;
    try out.flag("has_current", has_live);
    try out.number("archived", archive.shelvedCount());
    if (!has_live) return;
    try out.number("version", try archive.version());
    try out.number("local_registration_id", try archive.localRegistrationId());
    try out.number("remote_registration_id", try archive.remoteRegistrationId());
    try out.blob("local_identity", &(try archive.localIdentity()).serialize());
    try out.blob("remote_identity", &(try archive.remoteIdentity()).serialize());
    try out.blob("alice_base_key", try archive.base());
    try out.flag("has_sender_chain", archive.canSend());
    try out.flag("usable", archive.canSendAt(try nowFrom(in)));
}

fn opSessionShelve(arena: Allocator, in: Input, out: *Answer) !void {
    var archive = try archiveFrom(arena, in, "session_record");
    try archive.shelve();
    try out.blob("session_record", try archive.serialize(arena));
}

fn opCircleAnnounce(arena: Allocator, in: Input, out: *Answer) !void {
    var circle = try circleFrom(arena, in, "sender_key_record");
    const announce = try circle_cipher.announce(arena, &circle, try in.fixed("distribution_id", 16));
    try out.blob("distribution_message", announce.bytes);
    try out.blob("sender_key_record", try circle.serialize(arena));
}

fn opCircleAdmit(arena: Allocator, in: Input, out: *Answer) !void {
    var circle = try circleFrom(arena, in, "sender_key_record");
    try circle_cipher.admit(&circle, try circle_post.Announce.parse(arena, try in.blob("distribution_message")));
    try out.blob("sender_key_record", try circle.serialize(arena));
}

fn opCircleSeal(arena: Allocator, in: Input, out: *Answer) !void {
    var circle = try circleFrom(arena, in, "sender_key_record");
    const note = try circle_cipher.seal(arena, &circle, try in.fixed("distribution_id", 16), try in.blob("plaintext"));
    try out.blob("ciphertext", note);
    try out.blob("sender_key_record", try circle.serialize(arena));
}

fn opCircleOpen(arena: Allocator, in: Input, out: *Answer) !void {
    var circle = try circleFrom(arena, in, "sender_key_record");
    const note = try circle_post.Note.parse(arena, try in.blob("ciphertext"));
    try out.blob("plaintext", try circle_cipher.open(arena, &circle, note));
    try out.blob("sender_key_record", try circle.serialize(arena));
}

fn opSafety(arena: Allocator, in: Input, out: *Answer) !void {
    const s = try safety.Safety.of(
        try in.word32("version"),
        try in.word32("iterations"),
        try in.blob("local_id"),
        try identity.Identity.parse(try in.blob("local_key")),
        try in.blob("remote_id"),
        try identity.Identity.parse(try in.blob("remote_key")),
    );
    try out.text("display", &s.display.text);
    try out.blob("scannable", try s.scannable.serialize(arena));
}

fn opSafetyMatches(_: Allocator, in: Input, out: *Answer) !void {
    const ours = try safety.Scannable.parse(try in.blob("ours"));
    try out.flag("ok", try ours.matches(try in.blob("theirs")));
}

fn opHandleHash(_: Allocator, in: Input, out: *Answer) !void {
    try out.blob("hash", &try name.hashOf(try in.str("username")));
}

fn opHandleProof(_: Allocator, in: Input, out: *Answer) !void {
    try out.blob("proof", &try name.proofOf(try in.str("username"), try in.fixed("random", 32)));
}

fn opHandleVerify(_: Allocator, in: Input, out: *Answer) !void {
    const ok = if (name.Handle.verify(try in.blob("proof"), try in.fixed("hash", 32))) true else |_| false;
    try out.flag("ok", ok);
}

fn opHandleLink(arena: Allocator, in: Input, out: *Answer) !void {
    const previous: ?[32]u8 = if (try in.optBlob("entropy")) |e| e[0..32].* else null;
    const made = try link.create(arena, try in.str("username"), previous);
    try out.blob("entropy", &made.entropy);
    try out.blob("encrypted", made.sealed);
}

fn opHandleLinkOpen(arena: Allocator, in: Input, out: *Answer) !void {
    try out.text("username", try link.open(arena, try in.blob("entropy"), try in.blob("encrypted")));
}

fn opPoolDerive(_: Allocator, in: Input, out: *Answer) !void {
    const pool = try account.EntropyPool.parse(try in.str("aep"));
    try out.blob("svr_key", &pool.recoveryKey());
    try out.blob("backup_key", &pool.backupKey().bytes);
}

fn opPoolValid(_: Allocator, in: Input, out: *Answer) !void {
    try out.flag("ok", account.EntropyPool.valid(try in.str("aep")));
}

fn opBackupKeyDerive(_: Allocator, in: Input, out: *Answer) !void {
    const key = account.BackupKey{ .bytes = try in.fixed("backup_key", 32) };
    const who = ServiceId.aci(try Uuid.parse(try in.str("aci")));
    try out.blob("backup_id", &key.backupId(who));
    try out.blob("ec_priv", &key.signingKey(who).serialize());
    try out.blob("local_metadata_key", &key.localMetadataKey());
    const media_id = try key.mediaId(try in.str("media_name"));
    try out.blob("media_id", &media_id);
    try out.blob("media_key", &key.mediaKey(media_id));
    try out.blob("thumbnail_key", &key.thumbnailKey(media_id));
}

fn opHkdf(arena: Allocator, in: Input, out: *Answer) !void {
    const output = try arena.alloc(u8, @intCast(try in.number("len")));
    derive.hkdf(output, try in.blob("ikm"), try in.optBlob("salt"), try in.blob("info"));
    try out.blob("out", output);
}

fn opSivSeal(arena: Allocator, in: Input, out: *Answer) !void {
    try out.blob("ciphertext", try cipher.sivSeal(arena, try in.fixed("key", 32), try in.fixed("nonce", 12), try in.blob("plaintext"), try in.blob("ad")));
}

fn opSivOpen(arena: Allocator, in: Input, out: *Answer) !void {
    try out.blob("plaintext", try cipher.sivOpen(arena, try in.fixed("key", 32), try in.fixed("nonce", 12), try in.blob("ciphertext"), try in.blob("ad")));
}

fn opReport(arena: Allocator, in: Input, out: *Answer) !void {
    const ratchet: ?curve.Public = if (try in.optBlob("ratchet_key")) |raw| try curve.Public.parse(raw) else null;
    const report = Report{ .ratchet = ratchet, .stamp_ms = try in.number("timestamp"), .device = try in.word32("device_id") };
    try out.blob("serialized", try report.serialize(arena));
}

fn opReportForOriginal(arena: Allocator, in: Input, out: *Answer) !void {
    const report = try Report.forOriginal(arena, try in.blob("original"), try kindFrom(try in.number("type")), try in.number("timestamp"), try in.word32("device_id"));
    try out.blob("serialized", try report.serialize(arena));
}

fn opReportParse(_: Allocator, in: Input, out: *Answer) !void {
    const report = try Report.parse(try in.blob("serialized"));
    if (report.ratchet) |k| try out.blob("ratchet_key", &k.serialize());
    try out.number("timestamp", report.stamp_ms);
    try out.number("device_id", report.device);
}

fn opPlainFromReport(arena: Allocator, in: Input, out: *Answer) !void {
    try out.blob("serialized", try post_content.fromReport(arena, try in.blob("dem")));
}

fn opPlainExtractReport(arena: Allocator, in: Input, out: *Answer) !void {
    const plain = try post_content.Plain.parse(arena, try in.blob("serialized"));
    try out.blob("dem", try post_content.reportIn(plain.body));
}

fn opServerCert(arena: Allocator, in: Input, out: *Answer) !void {
    const cert = try certificate.ServerCert.make(arena, try in.word32("key_id"), try curve.Public.parse(try in.blob("key")), try curve.Secret.parse(try in.blob("trust_root_priv")));
    try out.blob("serialized", cert.bytes);
}

fn opServerCertParse(arena: Allocator, in: Input, out: *Answer) !void {
    const cert = try certificate.ServerCert.parse(arena, try in.blob("serialized"));
    try out.number("key_id", cert.key_id);
    try out.blob("key", &cert.key.serialize());
    try out.blob("certificate", cert.body);
    try out.blob("signature", &cert.signature);
    if (try in.optBlob("trust_root")) |root| try out.flag("valid", cert.signedBy(try curve.Public.parse(root)));
}

fn opSenderCert(arena: Allocator, in: Input, out: *Answer) !void {
    const server = try certificate.ServerCert.parse(arena, try in.blob("server_cert"));
    const cert = try certificate.SenderCert.make(arena, .{
        .sender_id = try in.str("uuid"),
        .sender_phone = in.optStr("e164"),
        .sender_device = try in.word32("device_id"),
        .sender_key = try curve.Public.parse(try in.blob("sender_key")),
        .expires_ms = try in.number("expiration"),
        .server = &server,
        .server_secret = try curve.Secret.parse(try in.blob("server_priv")),
    });
    try out.blob("serialized", cert.bytes);
}

fn opSenderCertParse(arena: Allocator, in: Input, out: *Answer) !void {
    const cert = try certificate.SenderCert.parse(arena, try in.blob("serialized"));
    try out.text("uuid", cert.sender_id);
    if (cert.sender_phone) |phone| try out.text("e164", phone);
    try out.number("device_id", cert.sender_device);
    try out.blob("sender_key", &cert.sender_key.serialize());
    try out.number("expiration", cert.expires_ms);
    try out.blob("server_cert", cert.server.bytes);
    if (try in.optBlob("trust_root")) |root| try out.flag("valid", cert.valid(try curve.Public.parse(root), try in.number("time")));
}

fn opContent(arena: Allocator, in: Input, out: *Answer) !void {
    const sender = try certificate.SenderCert.parse(arena, try in.blob("sender_cert"));
    const hint: veil.envelope.content.Hint = @enumFromInt(try in.word32("hint"));
    const content = try Content.make(arena, try kindFrom(try in.number("type")), &sender, try in.blob("content"), hint, try in.optBlob("group_id"));
    try out.blob("serialized", content.bytes);
}

fn opContentParse(arena: Allocator, in: Input, out: *Answer) !void {
    const content = try Content.parse(arena, try in.blob("serialized"));
    try out.number("type", @intFromEnum(content.kind));
    try out.number("hint", @intFromEnum(content.hint));
    try out.blob("content", content.body);
    try out.blob("sender_cert", content.sender.bytes);
    if (content.circle_id) |g| try out.blob("group_id", g);
}

fn opEnvelopeSeal(arena: Allocator, in: Input, out: *Answer) !void {
    const content = try Content.parse(arena, try in.blob("usmc"));
    try out.blob("message", try envelope_seal.seal(arena, try usFrom(in, "identity_priv"), try curve.Public.parse(try in.blob("recipient_identity")), &content));
}

fn opEnvelopeOpen(arena: Allocator, in: Input, out: *Answer) !void {
    const content = try envelope_seal.open(arena, try usFrom(in, "identity_priv"), try in.blob("message"));
    try out.blob("usmc", content.bytes);
    try out.number("type", @intFromEnum(content.kind));
    try out.blob("content", content.body);
    try out.text("sender_uuid", content.sender.sender_id);
    try out.number("sender_device_id", content.sender.sender_device);
    try out.blob("sender_cert", content.sender.bytes);
}

fn opEnvelopeSealMany(arena: Allocator, in: Input, out: *Answer) !void {
    const entries = try in.items("recipients");
    const recipients = try arena.alloc(multiseal.Recipient, entries.len);
    for (entries, recipients) |entry, *r| {
        const one: Input = .{ .arena = arena, .obj = entry.object };
        const device_entries = try one.items("devices");
        const devices = try arena.alloc(multiseal.Device, device_entries.len);
        for (device_entries, devices) |d, *dev| {
            const ds: Input = .{ .arena = arena, .obj = d.object };
            dev.* = .{ .device = @intCast(try ds.number("device_id")), .registration_id = @intCast(try ds.number("registration_id")) };
        }
        r.* = .{
            .service_id = try ServiceId.parse(try one.str("service_id")),
            .devices = devices,
            .identity = try curve.Public.parse(try one.blob("identity_key")),
        };
    }
    const content = try Content.parse(arena, try in.blob("usmc"));
    try out.blob("sent", try multiseal.sealForMany(arena, try usFrom(in, "identity_priv"), recipients, &.{}, &content));
}

fn opEnvelopeSplit(arena: Allocator, in: Input, out: *Answer) !void {
    const sent = try in.blob("sent");
    if (in.optStr("service_id")) |text| {
        try out.blob("received", try multiseal.forRecipient(arena, sent, try ServiceId.parse(text), @intCast(try in.number("device_id"))));
    } else {
        try out.blob("received", try multiseal.forSingle(arena, sent));
    }
}

fn opCircleMaster(_: Allocator, in: Input, out: *Answer) !void {
    const master = if (try in.optBlob("master_key")) |raw| try circle_params.MasterKey.parse(raw) else circle_params.MasterKey.random();
    const params = try master.secretParams();
    try out.blob("master_key", &master.bytes);
    try out.blob("group_id", &params.identifier);
    try out.blob("secret_params", &params.serialize());
    try out.blob("public_params", &params.publicParams());
}

fn opCircleParamsParse(_: Allocator, in: Input, out: *Answer) !void {
    const params = try circle_params.SecretParams.parse(try in.blob("secret_params"));
    try out.blob("master_key", &params.master.bytes);
    try out.blob("group_id", &params.identifier);
    try out.blob("public_params", &params.publicParams());
}

fn opBraidStart(arena: Allocator, in: Input, out: *Answer) !void {
    const side: pq_record.Side = if (std.mem.eql(u8, try in.str("dir"), "a2b")) .initiator else .responder;
    try out.blob("state", try pq_record.start(arena, try in.fixed("auth_key", 32), side, .{}));
}

fn opBraidSend(arena: Allocator, in: Input, out: *Answer) !void {
    const sent = try pq_record.send(arena, try in.blob("state"));
    try out.blob("state", sent.state);
    try out.blob("msg", sent.packet);
    if (sent.key) |k| try out.blob("key", &k) else try out.optNumber("key", null);
}

fn opBraidReceive(arena: Allocator, in: Input, out: *Answer) !void {
    const received = try pq_record.receive(arena, try in.blob("state"), try in.blob("msg"));
    try out.blob("state", received.state);
    if (received.key) |k| try out.blob("key", &k) else try out.optNumber("key", null);
}

fn answer(arena: Allocator, op: []const u8, in: Input, out: *Answer) !void {
    const handler = handlers.get(op) orelse return error.UnknownOp;
    try handler(arena, in, out);
}

/// Fields that carry fresh randomness on every run and never compare equal.
const unstable_fields = [_][]const u8{"session_record"};

fn sameValue(a: Value, b: Value) bool {
    return switch (a) {
        .string => |x| b == .string and std.mem.eql(u8, x, b.string),
        .integer => |x| b == .integer and x == b.integer,
        .bool => |x| b == .bool and x == b.bool,
        .null => b == .null,
        else => false,
    };
}

const Replay = struct {
    files: usize = 0,
    checked: usize = 0,
    failed: usize = 0,

    fn file(r: *Replay, arena: Allocator, file_name: []const u8, text: []const u8) !void {
        r.files += 1;
        const parsed = try std.json.parseFromSliceLeaky(Value, arena, text, .{});
        for (parsed.array.items, 0..) |item, index| {
            const check = item.object.get("check") orelse continue;
            if (check != .bool or !check.bool) continue;
            r.checked += 1;
            const op = item.object.get("op").?.string;
            const in: Input = .{ .arena = arena, .obj = item.object.get("args").?.object };
            const expected = item.object.get("result").?.object;
            var out: Answer = .{ .arena = arena };
            answer(arena, op, in, &out) catch |e| {
                r.failed += 1;
                std.debug.print("conformance: {s}#{d} {s}: {t}\n", .{ file_name, index, op, e });
                continue;
            };
            const produced = try std.json.parseFromSliceLeaky(Value, arena, try out.finish(), .{});
            var fields = expected.iterator();
            while (fields.next()) |kv| {
                var unstable = false;
                for (unstable_fields) |f| unstable = unstable or std.mem.eql(u8, f, kv.key_ptr.*);
                if (unstable) continue;
                const got = produced.object.get(kv.key_ptr.*) orelse Value{ .null = {} };
                if (!sameValue(kv.value_ptr.*, got)) {
                    r.failed += 1;
                    std.debug.print("conformance: {s}#{d} {s}: field '{s}' differs\n", .{ file_name, index, op, kv.key_ptr.* });
                    break;
                }
            }
        }
    }
};

fn replayDir(init: std.process.Init, dir_path: []const u8) !u8 {
    const arena = init.arena.allocator();
    var dir = try std.Io.Dir.cwd().openDir(init.io, dir_path, .{ .iterate = true });
    defer dir.close(init.io);
    var it = dir.iterate();
    var replay: Replay = .{};
    while (try it.next(init.io)) |entry| {
        if (entry.kind != .file or !std.mem.endsWith(u8, entry.name, ".json")) continue;
        const text = try dir.readFileAlloc(init.io, entry.name, arena, .limited(1 << 28));
        try replay.file(arena, entry.name, text);
    }
    std.debug.print("conformance: {d} files, {d} operations replayed, {d} failed\n", .{ replay.files, replay.checked, replay.failed });
    return if (replay.failed == 0 and replay.files > 0) 0 else 1;
}

fn emit(init: std.process.Init, text: []const u8) !void {
    var out_buf: [1 << 12]u8 = undefined;
    var w = std.Io.File.stdout().writer(init.io, &out_buf);
    try w.interface.writeAll(text);
    try w.interface.flush();
}

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();
    var argv = try std.process.Args.Iterator.initAllocator(init.minimal.args, arena);
    _ = argv.next();
    if (argv.next()) |mode| {
        if (std.mem.eql(u8, mode, "--replay")) return replayDir(init, argv.next() orelse "conformance/vectors");
        std.debug.print("conform: usage: conform [--replay <dir>]\n", .{});
        return 2;
    }
    var in_buf: [1 << 16]u8 = undefined;
    var reader = std.Io.File.stdin().reader(init.io, &in_buf);
    const input = try reader.interface.allocRemaining(arena, .unlimited);
    const parsed = try std.json.parseFromSliceLeaky(Value, arena, input, .{});
    if (parsed != .object) return error.WrongType;
    const in: Input = .{ .arena = arena, .obj = parsed.object };
    const op = try in.str("op");
    var out: Answer = .{ .arena = arena };
    answer(arena, op, in, &out) catch |e| {
        var failure: Answer = .{ .arena = arena };
        try failure.text("error", @errorName(e));
        try failure.text("op", op);
        try emit(init, try failure.finish());
        return 1;
    };
    try emit(init, try out.finish());
    return 0;
}

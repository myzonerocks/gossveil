//! One JNI entry, `Native.call(op, args, nums)` in the Kotlin package: byte
//! arrays and integers in, a length-prefixed run of outputs back, and a typed
//! Java exception on any error. The typing lives in Kotlin.
const std = @import("std");
const abi = @import("gossveil.zig");
const c = @cImport(@cInclude("jni.h"));

const Env = [*c]c.JNIEnv;
const Buffer = abi.GvBuffer;

pub const Op = enum(i32) {
    abi_version = 0,
    curve_pair = 1,
    curve_public = 2,
    curve_sign = 3,
    curve_verify = 4,
    curve_agree = 5,
    curve_check = 6,
    pq_pair = 7,
    pq_encapsulate = 8,
    pq_open = 9,
    identity_pair = 10,
    identity_serialize = 11,
    identity_parse = 12,
    identity_vouch = 13,
    identity_vouched = 14,
    one_time_record = 15,
    one_time_parse = 16,
    signed_record = 17,
    signed_parse = 18,
    pq_record = 19,
    pq_record_parse = 20,
    session_info = 21,
    session_shelve = 22,
    session_ratchet_is = 23,
    session_start = 24,
    session_seal = 25,
    session_open = 26,
    session_open_first = 27,
    opener_parse = 28,
    whisper_parse = 29,
    circle_announce = 30,
    circle_admit = 31,
    announce_parse = 32,
    circle_seal = 33,
    circle_open = 34,
    note_parse = 35,
    server_cert = 36,
    server_cert_parse = 37,
    server_cert_check = 38,
    sender_cert = 39,
    sender_cert_parse = 40,
    sender_cert_check = 41,
    content = 42,
    content_parse = 43,
    envelope_seal = 44,
    envelope_open = 45,
    envelope_seal_many = 46,
    envelope_for_single = 47,
    envelope_for_recipient = 48,
    safety = 49,
    safety_matches = 50,
    handle_hash = 51,
    handle_proof = 52,
    handle_verify = 53,
    handle_candidates = 54,
    handle_from_parts = 55,
    handle_link = 56,
    handle_link_open = 57,
    pool_random = 58,
    pool_valid = 59,
    pool_derive = 60,
    backup_key_random = 61,
    backup_key_for_account = 62,
    backup_key_local_metadata = 63,
    backup_key_media = 64,
    backup_key_media_keys = 65,
    circle_master_random = 66,
    circle_secret_params = 67,
    circle_params_info = 68,
    hkdf = 69,
    siv_seal = 70,
    siv_open = 71,
    random = 72,
    chunk_tags = 73,
    chunk_check = 74,
    report = 75,
    report_parse = 76,
    report_in_body = 77,
    plain_from_report = 78,
    plain_body = 79,
};

fn empty() Buffer {
    return .{ .ptr = null, .len = 0 };
}

const Call = struct {
    arena: std.mem.Allocator,
    args: [][]u8,
    nums: []i64,
    parts: std.ArrayList([]const u8) = .empty,

    fn bytes(x: *Call, i: usize) []const u8 {
        return if (i < x.args.len) x.args[i] else &.{};
    }

    fn p(x: *Call, i: usize) ?[*]const u8 {
        const s = x.bytes(i);
        return if (s.len == 0) null else s.ptr;
    }

    fn l(x: *Call, i: usize) usize {
        return x.bytes(i).len;
    }

    fn n(x: *Call, i: usize) i64 {
        return if (i < x.nums.len) x.nums[i] else 0;
    }

    fn u64n(x: *Call, i: usize) u64 {
        return @bitCast(x.n(i));
    }

    fn u32n(x: *Call, i: usize) u32 {
        return @truncate(x.u64n(i));
    }

    fn u8n(x: *Call, i: usize) u8 {
        return @truncate(x.u64n(i));
    }

    fn put(x: *Call, data: []const u8) !void {
        try x.parts.append(x.arena, try x.arena.dupe(u8, data));
    }

    fn putU32(x: *Call, v: u32) !void {
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, v, .little);
        try x.put(&b);
    }

    fn putU64(x: *Call, v: u64) !void {
        var b: [8]u8 = undefined;
        std.mem.writeInt(u64, &b, v, .little);
        try x.put(&b);
    }

    fn putFlag(x: *Call, v: u8) !void {
        try x.put(&[_]u8{v});
    }

    fn putStruct(x: *Call, value: anytype) !void {
        try x.put(std.mem.asBytes(value));
    }

    /// Copies a library buffer into the reply and releases it.
    fn take(x: *Call, cell: *Buffer) !void {
        try x.put(if (cell.ptr) |ptr| ptr[0..cell.len] else &.{});
        abi.gv_free(cell.ptr, cell.len);
        cell.* = empty();
    }

    /// Takes every output cell in order and passes the status through.
    fn done(x: *Call, status: i32, cells: []const *Buffer) !i32 {
        for (cells) |cell| try x.take(cell);
        return status;
    }
};

fn dispatch(x: *Call, op: Op) !i32 {
    var o = [_]Buffer{empty()} ** 6;
    var flag: u8 = 0;
    // `take` empties what it copied, so this only releases what an early
    // error left behind.
    defer for (&o) |*cell| abi.gv_free(cell.ptr, cell.len);
    switch (op) {
        .abi_version => {
            try x.putU32(abi.gv_abi_version());
            return 0;
        },
        .curve_pair => return x.done(abi.gv_curve_pair(&o[0], &o[1]), &.{ &o[0], &o[1] }),
        .curve_public => return x.done(abi.gv_curve_public(x.p(0), x.l(0), &o[0]), &.{&o[0]}),
        .curve_sign => return x.done(abi.gv_curve_sign(x.p(0), x.l(0), x.p(1), x.l(1), &o[0]), &.{&o[0]}),
        .curve_verify => {
            const s = abi.gv_curve_verify(x.p(0), x.l(0), x.p(1), x.l(1), x.p(2), x.l(2), &flag);
            try x.putFlag(flag);
            return s;
        },
        .curve_agree => return x.done(abi.gv_curve_agree(x.p(0), x.l(0), x.p(1), x.l(1), &o[0]), &.{&o[0]}),
        .curve_check => return abi.gv_curve_check(x.p(0), x.l(0)),
        .pq_pair => return x.done(abi.gv_pq_pair(x.u8n(0), &o[0], &o[1]), &.{ &o[0], &o[1] }),
        .pq_encapsulate => return x.done(abi.gv_pq_encapsulate(x.p(0), x.l(0), &o[0], &o[1]), &.{ &o[0], &o[1] }),
        .pq_open => return x.done(abi.gv_pq_open(x.p(0), x.l(0), x.p(1), x.l(1), &o[0]), &.{&o[0]}),
        .identity_pair => return x.done(abi.gv_identity_pair(&o[0]), &.{&o[0]}),
        .identity_serialize => return x.done(abi.gv_identity_serialize(x.p(0), x.l(0), &o[0]), &.{&o[0]}),
        .identity_parse => return x.done(abi.gv_identity_parse(x.p(0), x.l(0), &o[0], &o[1]), &.{ &o[0], &o[1] }),
        .identity_vouch => return x.done(abi.gv_identity_vouch(x.p(0), x.l(0), x.p(1), x.l(1), &o[0]), &.{&o[0]}),
        .identity_vouched => {
            const s = abi.gv_identity_vouched(x.p(0), x.l(0), x.p(1), x.l(1), x.p(2), x.l(2), &flag);
            try x.putFlag(flag);
            return s;
        },
        .one_time_record => return x.done(abi.gv_one_time_record(x.u32n(0), x.p(0), x.l(0), &o[0]), &.{&o[0]}),
        .one_time_parse => {
            var id: u32 = 0;
            const s = abi.gv_one_time_parse(x.p(0), x.l(0), &id, &o[0], &o[1]);
            try x.putU32(id);
            return x.done(s, &.{ &o[0], &o[1] });
        },
        .signed_record => return x.done(abi.gv_signed_record(x.u32n(0), x.u64n(1), x.p(0), x.l(0), x.p(1), x.l(1), &o[0]), &.{&o[0]}),
        .signed_parse => {
            var id: u32 = 0;
            var stamp: u64 = 0;
            const s = abi.gv_signed_parse(x.p(0), x.l(0), &id, &stamp, &o[0], &o[1], &o[2]);
            try x.putU32(id);
            try x.putU64(stamp);
            return x.done(s, &.{ &o[0], &o[1], &o[2] });
        },
        .pq_record => return x.done(abi.gv_pq_record(x.u32n(0), x.u64n(1), x.p(0), x.l(0), x.p(1), x.l(1), x.p(2), x.l(2), &o[0]), &.{&o[0]}),
        .pq_record_parse => {
            var id: u32 = 0;
            var stamp: u64 = 0;
            const s = abi.gv_pq_record_parse(x.p(0), x.l(0), &id, &stamp, &o[0], &o[1], &o[2]);
            try x.putU32(id);
            try x.putU64(stamp);
            return x.done(s, &.{ &o[0], &o[1], &o[2] });
        },
        .session_info => {
            var info = std.mem.zeroes(abi.GvSessionInfo);
            const s = abi.gv_session_info(x.p(0), x.l(0), x.u64n(0), &info);
            try x.putStruct(&info);
            return s;
        },
        .session_shelve => return x.done(abi.gv_session_shelve(x.p(0), x.l(0), &o[0]), &.{&o[0]}),
        .session_ratchet_is => {
            const s = abi.gv_session_ratchet_is(x.p(0), x.l(0), x.p(1), x.l(1), &flag);
            try x.putFlag(flag);
            return s;
        },
        .session_start => {
            const published = abi.GvPublished{
                .registration_id = x.u32n(1),
                .device = x.u32n(2),
                .one_time_id = x.n(3),
                .one_time = x.p(2),
                .one_time_len = x.l(2),
                .signed_id = x.u32n(4),
                .signed_key = x.p(3),
                .signed_len = x.l(3),
                .signed_signature = x.p(4),
                .signed_signature_len = x.l(4),
                .identity = x.p(5),
                .identity_len = x.l(5),
                .pq_id = x.u32n(5),
                .pq_key = x.p(6),
                .pq_len = x.l(6),
                .pq_signature = x.p(7),
                .pq_signature_len = x.l(7),
            };
            return x.done(abi.gv_session_start(x.p(0), x.l(0), x.u32n(0), x.p(1), x.l(1), &published, x.u64n(6), &o[0]), &.{&o[0]});
        },
        .session_seal => {
            var kind: u8 = 0;
            const s = abi.gv_session_seal(x.p(0), x.l(0), x.p(1), x.l(1), x.u64n(0), x.p(2), x.l(2), x.u32n(1), x.p(3), x.l(3), x.u32n(2), &kind, &o[0], &o[1]);
            try x.putFlag(kind);
            return x.done(s, &.{ &o[0], &o[1] });
        },
        .session_open => return x.done(abi.gv_session_open(x.p(0), x.l(0), x.p(1), x.l(1), x.p(2), x.l(2), x.u32n(0), x.p(3), x.l(3), x.u32n(1), &o[0], &o[1]), &.{ &o[0], &o[1] }),
        .session_open_first => {
            var consumed = std.mem.zeroes(abi.GvConsumed);
            const s = abi.gv_session_open_first(x.p(0), x.l(0), x.u32n(0), x.p(1), x.l(1), x.p(2), x.l(2), x.p(3), x.l(3), x.p(4), x.l(4), x.p(5), x.l(5), x.p(6), x.l(6), x.u32n(1), x.p(7), x.l(7), x.u32n(2), &o[0], &o[1], &consumed);
            try x.take(&o[0]);
            try x.take(&o[1]);
            try x.putStruct(&consumed);
            return s;
        },
        .opener_parse => {
            var info = std.mem.zeroes(abi.GvOpenerInfo);
            const s = abi.gv_opener_parse(x.p(0), x.l(0), &info, &o[0]);
            try x.putStruct(&info);
            return x.done(s, &.{&o[0]});
        },
        .whisper_parse => {
            var info = std.mem.zeroes(abi.GvWhisperInfo);
            const s = abi.gv_whisper_parse(x.p(0), x.l(0), &info, &o[0]);
            try x.putStruct(&info);
            return x.done(s, &.{&o[0]});
        },
        .circle_announce => return x.done(abi.gv_circle_announce(x.p(0), x.l(0), x.p(1), x.l(1), &o[0], &o[1]), &.{ &o[0], &o[1] }),
        .circle_admit => return x.done(abi.gv_circle_admit(x.p(0), x.l(0), x.p(1), x.l(1), &o[0]), &.{&o[0]}),
        .announce_parse => {
            var info = std.mem.zeroes(abi.GvAnnounceInfo);
            const s = abi.gv_announce_parse(x.p(0), x.l(0), &info);
            try x.putStruct(&info);
            return s;
        },
        .circle_seal => return x.done(abi.gv_circle_seal(x.p(0), x.l(0), x.p(1), x.l(1), x.p(2), x.l(2), &o[0], &o[1]), &.{ &o[0], &o[1] }),
        .circle_open => return x.done(abi.gv_circle_open(x.p(0), x.l(0), x.p(1), x.l(1), &o[0], &o[1]), &.{ &o[0], &o[1] }),
        .note_parse => {
            var info = std.mem.zeroes(abi.GvNoteInfo);
            const s = abi.gv_note_parse(x.p(0), x.l(0), &info, &o[0]);
            try x.putStruct(&info);
            return x.done(s, &.{&o[0]});
        },
        .server_cert => return x.done(abi.gv_server_cert(x.u32n(0), x.p(0), x.l(0), x.p(1), x.l(1), &o[0]), &.{&o[0]}),
        .server_cert_parse => {
            var info = std.mem.zeroes(abi.GvServerCertInfo);
            const s = abi.gv_server_cert_parse(x.p(0), x.l(0), &info, &o[0], &o[1]);
            try x.putStruct(&info);
            return x.done(s, &.{ &o[0], &o[1] });
        },
        .server_cert_check => {
            const s = abi.gv_server_cert_check(x.p(0), x.l(0), x.p(1), x.l(1), &flag);
            try x.putFlag(flag);
            return s;
        },
        .sender_cert => return x.done(abi.gv_sender_cert(x.p(0), x.l(0), x.p(1), x.l(1), x.u32n(0), x.p(2), x.l(2), x.u64n(1), x.p(3), x.l(3), x.p(4), x.l(4), &o[0]), &.{&o[0]}),
        .sender_cert_parse => {
            var info = std.mem.zeroes(abi.GvSenderCertInfo);
            const s = abi.gv_sender_cert_parse(x.p(0), x.l(0), &info, &o[0], &o[1], &o[2], &o[3], &o[4]);
            try x.putStruct(&info);
            return x.done(s, &.{ &o[0], &o[1], &o[2], &o[3], &o[4] });
        },
        .sender_cert_check => {
            const s = abi.gv_sender_cert_check(x.p(0), x.l(0), x.p(1), x.l(1), x.u64n(0), &flag);
            try x.putFlag(flag);
            return s;
        },
        .content => return x.done(abi.gv_content(x.u8n(0), x.p(0), x.l(0), x.p(1), x.l(1), x.u8n(1), x.p(2), x.l(2), x.u8n(2), &o[0]), &.{&o[0]}),
        .content_parse => {
            var info = std.mem.zeroes(abi.GvContentInfo);
            const s = abi.gv_content_parse(x.p(0), x.l(0), &info, &o[0], &o[1], &o[2]);
            try x.putStruct(&info);
            return x.done(s, &.{ &o[0], &o[1], &o[2] });
        },
        .envelope_seal => return x.done(abi.gv_envelope_seal(x.p(0), x.l(0), x.p(1), x.l(1), x.p(2), x.l(2), &o[0]), &.{&o[0]}),
        .envelope_open => return x.done(abi.gv_envelope_open(x.p(0), x.l(0), x.p(1), x.l(1), &o[0]), &.{&o[0]}),
        .envelope_seal_many => return x.done(abi.gv_envelope_seal_many(x.p(0), x.l(0), x.p(1), x.l(1), x.p(2), x.l(2), x.p(3), x.l(3), &o[0]), &.{&o[0]}),
        .envelope_for_single => return x.done(abi.gv_envelope_for_single(x.p(0), x.l(0), &o[0]), &.{&o[0]}),
        .envelope_for_recipient => return x.done(abi.gv_envelope_for_recipient(x.p(0), x.l(0), x.p(1), x.l(1), x.u8n(0), &o[0]), &.{&o[0]}),
        .safety => return x.done(abi.gv_safety(x.u32n(0), x.u32n(1), x.p(0), x.l(0), x.p(1), x.l(1), x.p(2), x.l(2), x.p(3), x.l(3), &o[0], &o[1]), &.{ &o[0], &o[1] }),
        .safety_matches => {
            const s = abi.gv_safety_matches(x.p(0), x.l(0), x.p(1), x.l(1), &flag);
            try x.putFlag(flag);
            return s;
        },
        .handle_hash => return x.done(abi.gv_handle_hash(x.p(0), x.l(0), &o[0]), &.{&o[0]}),
        .handle_proof => return x.done(abi.gv_handle_proof(x.p(0), x.l(0), x.p(1), x.l(1), &o[0]), &.{&o[0]}),
        .handle_verify => {
            const s = abi.gv_handle_verify(x.p(0), x.l(0), x.p(1), x.l(1), &flag);
            try x.putFlag(flag);
            return s;
        },
        .handle_candidates => return x.done(abi.gv_handle_candidates(x.p(0), x.l(0), x.u32n(0), x.u32n(1), &o[0]), &.{&o[0]}),
        .handle_from_parts => return x.done(abi.gv_handle_from_parts(x.p(0), x.l(0), x.p(1), x.l(1), x.u32n(0), x.u32n(1), &o[0], &o[1]), &.{ &o[0], &o[1] }),
        .handle_link => return x.done(abi.gv_handle_link(x.p(0), x.l(0), x.p(1), x.l(1), &o[0], &o[1]), &.{ &o[0], &o[1] }),
        .handle_link_open => return x.done(abi.gv_handle_link_open(x.p(0), x.l(0), x.p(1), x.l(1), &o[0]), &.{&o[0]}),
        .pool_random => return x.done(abi.gv_pool_random(&o[0]), &.{&o[0]}),
        .pool_valid => {
            try x.putFlag(abi.gv_pool_valid(x.p(0), x.l(0)));
            return 0;
        },
        .pool_derive => return x.done(abi.gv_pool_derive(x.p(0), x.l(0), &o[0], &o[1]), &.{ &o[0], &o[1] }),
        .backup_key_random => return x.done(abi.gv_backup_key_random(&o[0]), &.{&o[0]}),
        .backup_key_for_account => return x.done(abi.gv_backup_key_for_account(x.p(0), x.l(0), x.p(1), x.l(1), &o[0], &o[1]), &.{ &o[0], &o[1] }),
        .backup_key_local_metadata => return x.done(abi.gv_backup_key_local_metadata(x.p(0), x.l(0), &o[0]), &.{&o[0]}),
        .backup_key_media => return x.done(abi.gv_backup_key_media(x.p(0), x.l(0), x.p(1), x.l(1), &o[0], &o[1], &o[2]), &.{ &o[0], &o[1], &o[2] }),
        .backup_key_media_keys => return x.done(abi.gv_backup_key_media_keys(x.p(0), x.l(0), x.p(1), x.l(1), &o[0], &o[1]), &.{ &o[0], &o[1] }),
        .circle_master_random => return x.done(abi.gv_circle_master_random(&o[0]), &.{&o[0]}),
        .circle_secret_params => return x.done(abi.gv_circle_secret_params(x.p(0), x.l(0), &o[0]), &.{&o[0]}),
        .circle_params_info => return x.done(abi.gv_circle_params_info(x.p(0), x.l(0), &o[0], &o[1], &o[2]), &.{ &o[0], &o[1], &o[2] }),
        .hkdf => return x.done(abi.gv_hkdf(x.p(0), x.l(0), x.p(1), x.l(1), x.u8n(0), x.p(2), x.l(2), x.u32n(1), &o[0]), &.{&o[0]}),
        .siv_seal => return x.done(abi.gv_siv_seal(x.p(0), x.l(0), x.p(1), x.l(1), x.p(2), x.l(2), x.p(3), x.l(3), &o[0]), &.{&o[0]}),
        .siv_open => return x.done(abi.gv_siv_open(x.p(0), x.l(0), x.p(1), x.l(1), x.p(2), x.l(2), x.p(3), x.l(3), &o[0]), &.{&o[0]}),
        .random => return x.done(abi.gv_random(x.u32n(0), &o[0]), &.{&o[0]}),
        .chunk_tags => return x.done(abi.gv_chunk_tags(x.p(0), x.l(0), x.u32n(0), x.p(1), x.l(1), &o[0]), &.{&o[0]}),
        .chunk_check => return abi.gv_chunk_check(x.p(0), x.l(0), x.u32n(0), x.p(1), x.l(1), x.p(2), x.l(2)),
        .report => return x.done(abi.gv_report(x.p(0), x.l(0), x.u8n(0), x.u64n(1), x.u32n(2), &o[0]), &.{&o[0]}),
        .report_parse => {
            var info = std.mem.zeroes(abi.GvReportInfo);
            const s = abi.gv_report_parse(x.p(0), x.l(0), &info);
            try x.putStruct(&info);
            return s;
        },
        .report_in_body => return x.done(abi.gv_report_in_body(x.p(0), x.l(0), &o[0]), &.{&o[0]}),
        .plain_from_report => return x.done(abi.gv_plain_from_report(x.p(0), x.l(0), &o[0]), &.{&o[0]}),
        .plain_body => return x.done(abi.gv_plain_body(x.p(0), x.l(0), &o[0]), &.{&o[0]}),
    }
}

fn readArgs(arena: std.mem.Allocator, env: Env, args: c.jobjectArray) ![][]u8 {
    if (args == null) return &.{};
    const count: usize = @intCast(env.*.*.GetArrayLength.?(env, args));
    const out = try arena.alloc([]u8, count);
    for (out, 0..) |*slot, i| {
        const element = env.*.*.GetObjectArrayElement.?(env, args, @intCast(i));
        if (element == null) {
            slot.* = &.{};
            continue;
        }
        const len: usize = @intCast(env.*.*.GetArrayLength.?(env, element));
        const buf = try arena.alloc(u8, len);
        if (len > 0) env.*.*.GetByteArrayRegion.?(env, element, 0, @intCast(len), @ptrCast(buf.ptr));
        env.*.*.DeleteLocalRef.?(env, element);
        slot.* = buf;
    }
    return out;
}

fn readNums(arena: std.mem.Allocator, env: Env, nums: c.jlongArray) ![]i64 {
    if (nums == null) return &.{};
    const count: usize = @intCast(env.*.*.GetArrayLength.?(env, nums));
    const out = try arena.alloc(i64, count);
    if (count > 0) env.*.*.GetLongArrayRegion.?(env, nums, 0, @intCast(count), @ptrCast(out.ptr));
    return out;
}

/// Every part as a little-endian length then its bytes, in one array.
fn reply(env: Env, parts: []const []const u8) c.jbyteArray {
    var total: usize = 0;
    for (parts) |part| total += 4 + part.len;
    const arr = env.*.*.NewByteArray.?(env, @intCast(total));
    if (arr == null) return null;
    var at: c.jsize = 0;
    for (parts) |part| {
        var header: [4]u8 = undefined;
        std.mem.writeInt(u32, &header, @intCast(part.len), .little);
        env.*.*.SetByteArrayRegion.?(env, arr, at, 4, @ptrCast(&header));
        at += 4;
        if (part.len > 0) env.*.*.SetByteArrayRegion.?(env, arr, at, @intCast(part.len), @ptrCast(part.ptr));
        at += @intCast(part.len);
    }
    return arr;
}

fn exceptionFor(status: i32) [*:0]const u8 {
    return switch (status) {
        1 => "java/lang/IllegalArgumentException",
        3, 4 => "com/gossveil/InvalidKeyException",
        5 => "com/gossveil/InvalidMessageException",
        6 => "com/gossveil/InvalidKeyIdException",
        7 => "com/gossveil/UntrustedIdentityException",
        8 => "com/gossveil/NoSessionException",
        9 => "com/gossveil/DuplicateMessageException",
        10 => "com/gossveil/LegacyMessageException",
        11 => "com/gossveil/InvalidVersionException",
        13 => "com/gossveil/VerificationFailedException",
        else => "java/lang/IllegalStateException",
    };
}

fn throw(env: Env, status: i32) c.jbyteArray {
    const cls = env.*.*.FindClass.?(env, exceptionFor(status));
    if (cls == null) return null;
    _ = env.*.*.ThrowNew.?(env, cls, abi.gv_status_text(status));
    return null;
}

export fn Java_com_gossveil_Native_call(env: Env, cls: c.jclass, op: c.jint, args: c.jobjectArray, nums: c.jlongArray) c.jbyteArray {
    _ = cls;
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const parsed = std.enums.fromInt(Op, op) orelse return throw(env, 1);
    var x = Call{
        .arena = arena,
        .args = readArgs(arena, env, args) catch return throw(env, 12),
        .nums = readNums(arena, env, nums) catch return throw(env, 12),
    };
    const status = dispatch(&x, parsed) catch return throw(env, 12);
    if (status != 0) return throw(env, status);
    return reply(env, x.parts.items);
}

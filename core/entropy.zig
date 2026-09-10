//! Randomness: the kernel on Linux and Android, the libc generator on Apple
//! platforms, and a host-supplied import on the web.
const std = @import("std");
const builtin = @import("builtin");

pub const on_web = builtin.cpu.arch == .wasm32 and builtin.os.tag == .freestanding;

extern fn arc4random_buf(ptr: [*]u8, nbytes: usize) void;
extern "env" fn gv_random_bytes(ptr: [*]u8, nbytes: usize) void;

pub fn fill(buf: []u8) void {
    if (buf.len == 0) return;
    if (on_web) {
        gv_random_bytes(buf.ptr, buf.len);
    } else if (builtin.os.tag == .linux) {
        var done: usize = 0;
        while (done < buf.len) {
            const n = std.os.linux.getrandom(buf.ptr + done, buf.len - done, 0);
            if (n > 0) done += n;
        }
    } else {
        arc4random_buf(buf.ptr, buf.len);
    }
}

pub fn array(comptime n: usize) [n]u8 {
    var out: [n]u8 = undefined;
    fill(&out);
    return out;
}

test "two draws differ" {
    const a = array(32);
    const b = array(32);
    try std.testing.expect(!std.mem.eql(u8, &a, &b));
}

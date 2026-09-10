//! The wasm32 root: the C ABI reached through linear memory by the web
//! package. The host supplies randomness through the `gv_random_bytes` import.
comptime {
    _ = @import("gossveil.zig");
}

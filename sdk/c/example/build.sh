#!/usr/bin/env bash
# Stages the C SDK, links the example against the shared library and runs it.
set -euo pipefail
cd "$(dirname "$0")/../../.."
export PATH="$PWD/.local/zig/current:$PATH"
zig build c
cc sdk/c/example/main.c \
    -I zig-out/c/include \
    -L zig-out/c/lib -lgossveil \
    -Wl,-rpath,"$PWD/zig-out/c/lib" \
    -o zig-out/c/example
exec zig-out/c/example

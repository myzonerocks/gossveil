# Architecture

Four layers, each a thin seam over the one below. The core owns every byte format; the packages
own persistence and the host language's idioms. The design behind each choice is in
[DESIGN.md](DESIGN.md).

```
Swift (sdk/swift)   Kotlin (sdk/kotlin)   TypeScript (sdk/ts)
        │                   │                     │
   XCFramework           JNI .so/.dylib        wasm32 module
   (abi/gossveil.zig)    (abi/jni.zig)         (abi/wasm.zig)
        └──────────── C ABI, include/gossveil.h ─────────────┘
                                 │
                        the core, core/*
```

## The core

`core/veil.zig` re-exports every area. Each area is one directory with its own tests; the areas
and their files are listed in the design document. Every public function takes an allocator, and
tests run under the testing allocator, so a leak is a failing test. Nothing in the per-message
path allocates beyond its outputs.

## The C ABI

`abi/gossveil.zig` exports `gv_*`. Inputs are `(pointer, length)`; outputs are `GvBuffer` cells the
caller passes in and the library fills; one `int32_t` status per call; `gv_free` for every
buffer; on any non-zero status every output cell is empty. Structs returned by value contain no
pointers, so their layout is the same on every target the packages run on. No callbacks: stores
stay in the host language and the core sees records only.

## The packages

- **Swift** links the XCFramework built by `tools/build-xcframework.sh`. One file is the seam:
  status to thrown error, buffer to `Data` with the free.
- **Kotlin** loads `libgossveil_jni` and calls one JNI entry, `Native.call(op, args, nums)`,
  which `abi/jni.zig` dispatches over the C ABI. Outputs come back length-prefixed; errors as the
  package's typed exceptions.
- **TypeScript** instantiates the wasm32 build. The runtime copies inputs into linear memory and
  outputs out per call; two API shapes sit on top, the in-memory store shape the browser client
  uses and the record shape over host stores.

## Conformance

`conformance/conform.zig` answers one JSON operation per run so an external driver can compare
its answers with another implementation's. The answers are frozen under `conformance/vectors/`
and `zig build conformance` replays them, so a change that moves a byte fails the build.

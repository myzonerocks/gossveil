# Contributing

The design the code follows is [docs/DESIGN.md](docs/DESIGN.md); the surface each package exposes
is [docs/API.md](docs/API.md). A feature is not complete because it compiles.

## Start here

Use the project toolchain, never a global Zig. `tools/toolchain-sync` installs the pinned compiler
into `.local/zig` and wires the git hooks; `.zigversion` is the pin and `build.zig` rejects any
other version.

```sh
tools/toolchain-sync
export PATH="$PWD/.local/zig/current:$PATH"
zig build ci                 # unit tests, the source gate, the gate's own tests
zig build conformance        # replay the frozen wire vectors
```

`nix/ensure.sh develop` opens a shell with bun, a JDK and the rest of what the gates run on.

## The one rule

A change lands in the core and in all three packages together, with the docs that describe it,
or it does not land. Swift, Kotlin and TypeScript stay at parity.

## Before a pull request

```sh
zig build ci conformance c-example
tools/build-xcframework.sh && swift test
zig build wasm -Doptimize=ReleaseFast && (cd sdk/ts && bun run build && bun run typecheck && bun test)
zig build jni android -Doptimize=ReleaseFast && (cd sdk/kotlin && ./gradlew :lib:testDebugUnitTest :lib:assembleRelease)
```

A wire change re-freezes `conformance/vectors/` and says so in the pull request.

## Writing

- More code than comments. A comment block is four lines at most and says what the code does.
- Plain words. No long dashes, no figurative phrasing, in code, commits or pull requests.
- A pull request body says what changed and the one thing a reader would not guess from the
  diff. No headers, no checklists, no tool names.
- Nothing in the tree names another implementation, its authors or its licence; the gate
  enforces it. Interoperability is a fact about bytes.
- No absolute paths, account ids, hosts or tool attribution anywhere in the tree.

## Layout

```text
build.zig  build.zig.zon    one build for every target
.zigversion                 the pinned Zig
core/                       the protocol core, one directory per area
abi/                        the C ABI, the wasm root, the JNI entry
include/gossveil.h          the C header
sdk/                        swift, kotlin, ts
conformance/                the conformance command and the frozen vectors
tools/                      toolchain bootstrap, the source gate, release scripts
```

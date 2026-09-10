# Changelog

Every change that reaches a user lands under **Unreleased** in the pull request that makes it.
A release moves that section under its tag with the date, and the release notes are that section.

## Unreleased

- The C ABI ships as a package of its own: `zig build c` stages the header beside a shared
  library and a static archive, with a guide, a CMake import and the example beside them.

- Each package carries its own guide: install, the store contract, a session end to end,
  groups, sealed envelopes and safety numbers, in that package's own language.

- The web package names its repository, which the registry's provenance check requires before
  it will accept a signed publish.

- A local publish of the Android package names the released version, so a sibling checkout and a
  client that asks for it agree on the coordinate.
- The Android and JNI lanes find the JDK and the SDK where a machine keeps them, so the
  documented build line runs with nothing exported.

## v0.1.0-alpha.2 (2026-09-10)

- The Apple framework names its executable in its property list, so a device installs it; a
  simulator never checked, so only a phone could catch this.
- The Android package publishes unsigned when no signing key is given, so a fork or a source
  build gets an artifact instead of a failure.

## v0.1.0-alpha.1 (2026-09-10)

- The core protocol: keys, published records, the ratchet with its post-quantum braid, circles,
  sealed envelopes, safety numbers, handles, the vault and chunked stream authentication.
- The C ABI (`gv_*`), the wasm root, the JNI entry, the C example and the conformance command
  with the frozen vectors.
- The three packages: Swift `Gossveil` over the `GossveilKit` XCFramework, Kotlin `com.gossveil`
  as `io.github.avosa:gossveil`, and `@myzonerocks/gossveil` for the browser and Node. Every
  type and function carries this project's own name; nothing is aliased to another project's.
- The conformance harness names every operation in this project's own vocabulary; the frozen
  vectors carry the same names.
- The web package ships unbundled ES modules built by the TypeScript compiler, so a consumer
  imports what the sources declare; a test imports the built package and exercises it.
- The web package's Node-only file read is named at run time, so a browser bundler never pulls
  `node:fs/promises` or `node:url` into an application's graph.

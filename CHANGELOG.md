# Changelog

Every change that reaches a user lands under **Unreleased** in the pull request that makes it.
A release moves that section under its tag with the date, and the release notes are that section.

## Unreleased

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

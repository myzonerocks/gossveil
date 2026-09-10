<div align="center">

# Gossveil

**End-to-end encryption for messaging apps: forward-secret sessions with a post-quantum
handshake, groups, sealed envelopes and safety numbers, on iOS, Android and the web from one
core.**

[![gates](https://github.com/myzonerocks/gossveil/actions/workflows/gates.yml/badge.svg)](https://github.com/myzonerocks/gossveil/actions/workflows/gates.yml)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE.md)
[![platforms](https://img.shields.io/badge/platforms-iOS%20%7C%20Android%20%7C%20Web-informational.svg)](#sdks)

[Install](#install) &nbsp;&middot;&nbsp;
[What you get](#what-you-get) &nbsp;&middot;&nbsp;
[SDKs](#sdks) &nbsp;&middot;&nbsp;
[Documentation](#documentation) &nbsp;&middot;&nbsp;
[Provenance](PROVENANCE.md) &nbsp;&middot;&nbsp;
[Contributing](CONTRIBUTING.md)

</div>

One core in Zig with no runtime dependencies, a C ABI over it, and three thin packages: Swift,
Kotlin and TypeScript over a WebAssembly build. Storage stays in your app, in your language.

## Install

iOS and Android carry the compiled core inside the package, an XCFramework and a `.so`, so you
add a coordinate and never run a build step. On the web the package carries the wasm.

**iOS, Swift.** In Xcode, File, Add Package Dependencies, paste the repository URL. In a
`Package.swift`:

```swift
.package(url: "https://github.com/myzonerocks/gossveil", from: "0.1.0-alpha.2")
```

**Android, Kotlin.**

```kotlin
implementation("io.github.avosa:gossveil:0.1.0-alpha.2")
```

**Web, TypeScript.**

```sh
bun add @myzonerocks/gossveil@0.1.0-alpha.2
```

Then write the first session with the guide for your platform:
[iOS](sdk/swift/README.md), [Android](sdk/kotlin/README.md), [Web](sdk/ts/README.md).

## What you get

| Area | What is in the box |
|---|---|
| Sessions | Published key bundles with signed, one-time and post-quantum keys; the handshake; the forward-secret ratchet with skipped-key recovery; session records with archived states; replay rejection |
| Post-quantum ratchet | A sparse post-quantum ratchet inside every session, so long-lived sessions stay ahead of a quantum adversary |
| Groups | Sender-key distribution, group encrypt and decrypt with out-of-order delivery |
| Sealed envelopes | Server and sender certificates, envelopes for one recipient and for many, the server-side split |
| Identity | Curve25519 keys and signatures, identity key pairs, alternate-identity proofs |
| Safety numbers | The iterated fingerprint, the sixty-digit display form and the scannable form |
| Usernames | Hashing, zero-knowledge proofs of ownership, links, candidates |
| Account keys | Entropy pool, backup key, backup id, media ids and media keys |
| Primitives | HKDF, AES-256-GCM-SIV, chunked MACs, random bytes, content framing |

## SDKs

| SDK | For | Package | Guide |
|---|---|---|---|
| **Swift** | iOS, macOS | SwiftPM, a checksummed XCFramework | [sdk/swift](sdk/swift/README.md) |
| **Kotlin** | Android | Maven Central `io.github.avosa:gossveil` | [sdk/kotlin](sdk/kotlin/README.md) |
| **TypeScript** | Browser, Node | npm `@myzonerocks/gossveil` | [sdk/ts](sdk/ts/README.md) |
| **C** | any language with a C FFI | `zig build c`, a header, static and shared | [sdk/c](sdk/c/README.md) |

The three packages are thin wrappers over the same C ABI and share one operation contract, so the
same concept carries the same name everywhere and a record written by one opens in another.

## One wire, every platform

Key encodings, record layouts, message framing and key schedules are checked against frozen wire
vectors recorded by this project's own tooling and replayed on every build. A session started with
Gossveil on one platform can continue on another without changing the cryptographic core or the
wire representation.

## Not included

Anything that talks to a particular service: registration, contact discovery, key backup
enclaves, key transparency, backup-file validation and credential issuance belong to the
application and its own backend.

## Documentation

- [Swift SDK](sdk/swift/README.md), [Kotlin SDK](sdk/kotlin/README.md), [TypeScript SDK](sdk/ts/README.md), [C SDK](sdk/c/README.md)
- [API](docs/API.md), the surface each package exposes, name for name
- [Architecture](docs/ARCHITECTURE.md), how the layers fit
- [Design](docs/DESIGN.md), the design the implementation follows
- [Changelog](CHANGELOG.md)
- [Contributing](CONTRIBUTING.md), which is also how to build from source
- [Provenance](PROVENANCE.md)
- [License](LICENSE.md), [Third-party notices](NOTICE.md)

## License

Gossveil is licensed under the Apache License, Version 2.0.

See [LICENSE.md](LICENSE.md), [NOTICE.md](NOTICE.md) and
[PROVENANCE.md](PROVENANCE.md).

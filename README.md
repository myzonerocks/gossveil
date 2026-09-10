<div align="center">

# Gossveil

**End-to-end encryption for messaging apps: forward-secret sessions with a post-quantum
handshake, groups, sealed envelopes and safety numbers, on iOS, Android and the web from one
core.**

[![gates](https://github.com/myzonerocks/gossveil/actions/workflows/gates.yml/badge.svg)](https://github.com/myzonerocks/gossveil/actions/workflows/gates.yml)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE.md)
[![platforms](https://img.shields.io/badge/platforms-iOS%20%7C%20Android%20%7C%20Web-informational.svg)](#install)

[Install](#install) &nbsp;&middot;&nbsp; [What you get](#what-you-get) &nbsp;&middot;&nbsp; [Use](#use) &nbsp;&middot;&nbsp; [Contributing](CONTRIBUTING.md)

</div>

One core in Zig with no runtime dependencies, a C ABI over it, and three thin packages: Swift,
Kotlin and TypeScript over a WebAssembly build. Every message, record and key follows the
published protocol specifications byte for byte, so a session started on one platform continues
on another and a record exported by one implementation opens in the next. Frozen wire vectors
replay on every build to keep it that way.

Inspired by the Signal protocol specifications.

## Install

iOS and Android carry the compiled core inside the package, an XCFramework and a `.so`, so you
add a coordinate and never run a build step. On the web the package carries the wasm.

**iOS, Swift.** In Xcode, File, Add Package Dependencies, paste the repository URL. In a
`Package.swift`:

```swift
.package(url: "https://github.com/myzonerocks/gossveil", from: "0.1.0-alpha.1")
```

**Android, Kotlin.**

```kotlin
implementation("io.github.avosa:gossveil:0.1.0-alpha.1")
```

**Web, TypeScript.**

```sh
bun add @myzonerocks/gossveil@0.1.0-alpha.1
```

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

## Use

Stores live in your app, in your language. Every operation loads what it needs, calls the core
with records, and hands records back.

```swift
import Gossveil
try processPreKeyBundle(bundle, for: peer, ourAddress: me, sessionStore: store, identityStore: store, context: NullContext())
let sealed = try signalEncrypt(message: plaintext, for: peer, localAddress: me, sessionStore: store, identityStore: store, context: NullContext())
```

```kotlin
import com.gossveil.*
SessionBuilder(store, store, store, store, peer).process(bundle)
val message = SessionCipher(store, store, store, store, store, peer).encrypt(plaintext)
```

```ts
import init, { init as ready, encryptMessage } from '@myzonerocks/gossveil'
await init(); ready()
const ct = await encryptMessage(plaintext, peer, me, sessions, identities)
```

The full surface per language is in [docs/API.md](docs/API.md); how the layers fit is in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md); the design the implementation follows is in
[docs/DESIGN.md](docs/DESIGN.md).

## Build from source

Requires the pinned Zig, installed by `tools/toolchain-sync` into `.local/zig`.

```sh
tools/toolchain-sync
zig build ci                                  # unit tests, the source gate
zig build conformance                         # replay the frozen wire vectors
tools/build-xcframework.sh && swift test      # the Swift package
zig build wasm -Doptimize=ReleaseFast && (cd sdk/ts && bun run build && bun test)
zig build jni android -Doptimize=ReleaseFast && (cd sdk/kotlin && ./gradlew :lib:test :lib:assembleRelease)
```

## Not included

Anything that talks to a particular service: registration, contact discovery, key backup
enclaves, key transparency, backup-file validation and credential issuance belong to the
application and its own backend.

Apache-2.0. See [LICENSE.md](LICENSE.md), [NOTICE.md](NOTICE.md) and
[PROVENANCE.md](PROVENANCE.md).

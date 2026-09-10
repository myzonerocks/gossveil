# Design

This is the document the implementation follows. It is written from the published protocol
specifications (the extended triple Diffie-Hellman handshake and its post-quantum extension,
the double ratchet, the sesame multi-device rules) and from the byte formats deployed clients
already exchange, and it decides everything the specifications leave open: the layout of the
core, the vocabulary, the ownership of memory, and the shape of the surfaces.

## Goals

1. **Bytes first.** A key, a record, a message or an envelope produced here is read by any
   other correct implementation of the same formats, and the reverse. Frozen vectors under
   `conformance/` are the contract and replay on every build.
2. **Records in, records out.** The core never calls back into the host. Every operation takes
   the records it needs and returns the records it changed. Stores are the host's.
3. **One primitive per operation.** The core exposes each protocol operation once; the C ABI,
   the wasm root, the JNI entry and the three packages marshal and nothing more.
4. **Bounded work per message.** Every lookup is bounded by a protocol constant, never by the
   length of a conversation.
5. **No hidden allocation.** Every core function takes an allocator; tests run under the
   testing allocator, so a leak is a failing test.

## Layout

```
core/
  veil.zig            root: re-exports and the version
  fault.zig           the error set every area shares
  entropy.zig         randomness: the system on native targets, a host import on wasm
  wire/               codec.zig (the length-delimited field codec), frame.zig (type-byte framing)
  keys/               curve.zig, sign.zig, pq.zig, identity.zig, derive.zig, cipher.zig, mac.zig
  bundle/             published.zig (the bundle and its checks), records.zig (pre-key records)
  handshake/          agree.zig (initiator and responder key agreement)
  ratchet/            chain.zig, state.zig, archive.zig (the session record), engine.zig
  ratchet/pq/         field.zig, code.zig, kem.zig, braid.zig, packet.zig, record.zig
  post/               whisper.zig, opener.zig (pre-key message), content.zig, report.zig
  circle/             chain.zig, state.zig, record.zig, cipher.zig (sender keys)
  envelope/           certificate.zig, seal.zig, multiseal.zig
  trust/              safety.zig (safety numbers)
  handle/             name.zig, proof.zig, link.zig (usernames)
  vault/              account.zig (entropy pool, backup key), circle_params.zig (group parameters)
  stream/             chunkmac.zig (incremental authentication)
abi/
  gossveil.zig        the C ABI, prefix gv_
  wasm.zig            the wasm32 root
  jni.zig             the JNI entry
include/gossveil.h
sdk/swift sdk/kotlin sdk/ts
conformance/          the command that answers one operation, and the frozen vectors
```

Each directory is one area with one responsibility; a file inside it is one concept. Nothing in
one area reaches into the private parts of another; areas talk through the types their root
exports.

## Vocabulary

The protocol's names are used for the protocol's things: root key, chain key, message key,
pre-key, signed pre-key, post-quantum pre-key, sender key, distribution id, registration id,
device id, base key, ratchet key, skipped key. Everything that is ours is named for what it does
here:

| Ours | What it is |
|---|---|
| `Published` | the bundle a device publishes: identity, signed pre-key, optional one-time key, post-quantum pre-key, signatures |
| `Agreement` | the shared secret and the keys the handshake derives from it |
| `Chain` | a symmetric chain: a key, an index, and the message keys it yields |
| `State` | one ratchet state: root, sending chain, receiving chains, skipped keys, the pending handshake |
| `Archive` | a session record: the current state and up to forty previous ones |
| `Engine` | the operations over an archive: start, seal, open, open with a pre-key message |
| `Braid` | the sparse post-quantum ratchet's eleven-state machine |
| `Circle` | a group's sender-key material and operations |
| `Envelope` | a sealed message that hides its sender from the server |
| `Safety` | a safety number in its display and scannable forms |
| `Handle` | a username, its hash, proof and link |
| `Vault` | account-level key derivation |

## Memory

Every public function takes an allocator. Slices borrowed from an input are documented as
borrowed; everything returned is owned by the caller. Records are opaque byte slices at the
surfaces and parsed structs inside; parsing borrows from the input and re-serialising produces
the same bytes.

The C ABI runs each call in an arena that is freed on return. Outputs are copied to the base
allocator before that and handed back as `GvBuffer` cells the caller frees with `gv_free`. On
any error every output cell is empty. `gv_alloc` gives a host input memory when it cannot pass a
pointer of its own (wasm).

## Formats, in one place

- **Keys.** A curve public key is 33 bytes: type byte `0x05` then the Montgomery u-coordinate.
  A private key is 32 clamped bytes. A post-quantum public key is a type byte (`0x08` for the
  round-three lattice scheme, `0x0A` for the standardised one) then the key; its secret and its
  ciphertext carry the same type byte.
- **Signatures.** Sixty-four bytes from the Edwards form of a Montgomery key, with a random
  nonce folded into the hash so two signatures of one message differ.
- **Records.** Length-delimited fields, as the protocol's record schemas define them; the codec
  in `wire/codec.zig` writes fields in ascending number order and omits defaults.
- **Messages.** A version byte (high nibble the message version, low nibble the current
  version), the fields, and for whisper messages an eight-byte MAC over the sender and receiver
  identities and the message.
- **Envelopes.** The single-recipient form is a version byte, an ephemeral key, a static-key
  ciphertext and a message ciphertext; the multi-recipient form carries one wrapped key per
  device and one shared message, which a server splits per recipient.
- **Safety numbers.** An iterated hash over version, identity key and identifier, thirty digits
  per side, and a scannable form with the version and both hashes.

## Surfaces

The three packages present the same operations with the same names the applications call
today; `docs/API.md` lists them per language. Store protocols are the host's: sessions,
identities, one-time pre-keys, signed pre-keys, post-quantum pre-keys and sender keys. An
in-memory implementation ships with every package as the reference.

## Proof

- `zig build test`: every unit test under the leak-detecting allocator.
- `zig build conformance`: every frozen vector replayed byte for byte.
- `zig build gate`: no other implementation named, no absolute path, no tool provenance, plain
  prose.
- Per package: the host tests, and a client of each platform built against the package with a
  diff of dependency and import lines only.

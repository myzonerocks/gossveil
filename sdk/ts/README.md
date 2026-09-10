# Gossveil, TypeScript SDK

Browser and Node package for [Gossveil](https://github.com/myzonerocks/gossveil), end-to-end
encryption for messaging apps: forward-secret sessions with a post-quantum handshake, groups,
sealed envelopes and safety numbers. The core is compiled to WebAssembly and ships inside the
package, so there is no toolchain and nothing to build.

The same concepts carry the same names in the
[Swift](https://github.com/myzonerocks/gossveil/blob/main/sdk/swift/README.md) and
[Kotlin](https://github.com/myzonerocks/gossveil/blob/main/sdk/kotlin/README.md) packages, and the
byte-for-byte behaviour is the same, so a session started on one platform continues on another.
The full cross-language name table is
[docs/API.md](https://github.com/myzonerocks/gossveil/blob/main/docs/API.md).

## Install

```sh
bun add @myzonerocks/gossveil        # or npm install @myzonerocks/gossveil
```

Pre-releases publish under the `next` tag:

```sh
bun add @myzonerocks/gossveil@next
```

ES modules, types included. Nothing is imported from Node at load time, so the same build serves a
browser and a server.

### Loading the core

Every call needs the wasm loaded once:

```ts
import init from '@myzonerocks/gossveil'

await init()
```

With no argument the package resolves `wasm/gossveil.wasm` next to its own module, which is what a
bundler and Node both follow. Hand it a URL, a `Response`, bytes or a compiled module when you host
the file yourself:

```ts
import wasmUrl from '@myzonerocks/gossveil/wasm?url'

await init(wasmUrl)                       // a URL your bundler emitted
await init(fetch('/gossveil.wasm'))       // a Response, streamed
initSync(compiledModule)                  // a WebAssembly.Module you already have
```

`isReady()` says whether the core is loaded. Calling `init()` twice is free; the second call
returns the instance the first one made.

### Building from source

```sh
tools/toolchain-sync
zig build wasm -Doptimize=ReleaseFast
(cd sdk/ts && bun run build)
```

`bun run build` rebuilds the wasm and then compiles the TypeScript to `dist/`. To point an app at
a checkout, link the package the way your package manager links a local path.

## Two shapes over one core

| Shape | Stores | Use it when |
|---|---|---|
| Records, `processBundle`, `sessionEncrypt` | your own, an abstract class per store | the app has a database and wants the protocol to call into it |
| Handles, `processPreKeyBundle`, `encryptMessage` | in memory, exported and imported as bytes | the app already keeps records itself and hands them over per call |

Both are exported from the package root, both drive the same core, and records written by one open
in the other. The rest of this guide uses the record shape; the handle shape is the section at the
end.

## Stores

Storage is yours. Every operation loads what it needs, calls the core with records, and stores what
came back, in one order: trust check, core call, identity save, record store, one-time key removal,
post-quantum key marked used.

```ts
export abstract class SessionStore {
  abstract saveSession(name: ProtocolAddress, record: SessionRecord): Promise<void>
  abstract getSession(name: ProtocolAddress): Promise<SessionRecord | null>
  abstract getExistingSessions(addresses: ProtocolAddress[]): Promise<SessionRecord[]>
}

export abstract class IdentityKeyStore {
  abstract getIdentityKey(): Promise<PrivateKey>
  abstract getLocalRegistrationId(): Promise<number>
  abstract saveIdentity(name: ProtocolAddress, key: PublicKey): Promise<IdentityChange>
  abstract isTrustedIdentity(name: ProtocolAddress, key: PublicKey, direction: Direction): Promise<boolean>
  abstract getIdentity(name: ProtocolAddress): Promise<PublicKey | null>
}
```

`PreKeyStore`, `SignedPreKeyStore`, `KyberPreKeyStore` and `SenderKeyStore` take the same shape.
Every method is async, so an IndexedDB or a network-backed store fits with nothing wrapped. A
record is bytes: `serialize()` to persist, `Class.deserialize(bytes)` to reopen.

`InMemoryProtocolStore` implements all six and is what tests and a first integration use.

## A session, end to end

The recipient publishes a bundle: an identity key, a signed pre-key, a post-quantum pre-key, and
optionally a one-time pre-key. The sender processes it and the session exists.

```ts
import init, {
  InMemoryProtocolStore, KEMKeyPair, KyberPreKeyRecord, PreKeyBundle, PrivateKey,
  ProtocolAddress, SignedPreKeyRecord, processBundle,
} from '@myzonerocks/gossveil'

await init()

const mine = new InMemoryProtocolStore()
const theirs = new InMemoryProtocolStore()
const me = ProtocolAddress.new('alice', 1)
const peer = ProtocolAddress.new('bob', 1)

// On the recipient: mint the keys it publishes and keep the records.
const identity = await theirs.getIdentityKey()
const signed = PrivateKey.generate()
const pq = KEMKeyPair.generate()
const signedSignature = identity.sign(signed.getPublicKey().serialize())
const kyberSignature = identity.sign(pq.getPublicKey().serialize())
await theirs.saveSignedPreKey(1, SignedPreKeyRecord.new(1, Date.now(), signed.getPublicKey(), signed, signedSignature))
await theirs.saveKyberPreKey(1, KyberPreKeyRecord.new(1, Date.now(), pq, kyberSignature))

// On the sender: the bundle as it arrived from your service.
const bundle = PreKeyBundle.new(
  await theirs.getLocalRegistrationId(), 1,
  null, null,
  1, signed.getPublicKey(), signedSignature,
  identity.getPublicKey(),
  1, pq.getPublicKey(), kyberSignature,
)
await processBundle(bundle, peer, mine, mine)
```

Pass a one-time key id and its public key in place of the two `null`s to spend one. The first
message names it and the recipient's store drops it as it opens.

## Sending and receiving

```ts
const message = await sessionEncrypt(new TextEncoder().encode('hello'), peer, mine, mine)
message.type()   // CiphertextMessageType.PreKey first, then Whisper
```

A message is a type and a body. What goes on your wire is up to you; one type byte in front of the
body is enough, and is what the clients do:

```ts
const body = message.serialize()
const wire = new Uint8Array(body.length + 1)
wire[0] = message.type()
wire.set(body, 1)
```

Opening it picks the call by that type:

```ts
// On the recipient, opening what the sender above sent.
const type = wire[0]
const body = wire.subarray(1)
const plaintext = type === CiphertextMessageType.PreKey
  ? await sessionDecryptPreKey(PreKeyMessage.deserialize(body), me, theirs, theirs, theirs, theirs, theirs)
  : await sessionDecrypt(WhisperMessage.deserialize(body), me, theirs, theirs)
```

Out-of-order messages open. A message opened twice rejects with `kind: 'DuplicatedMessage'`.

## Groups

One sender key per member, distributed once, then every message is one ciphertext for the whole
group.

```ts
const distributionId = uuid_to_string(generate_uuid())
const distribution = await SenderKeyDistributionMessage.create(me, distributionId, mine)
// Send distribution.serialize() to each member over their own session, then on each member:
await processSenderKeyDistributionMessage(me, SenderKeyDistributionMessage.deserialize(received), theirs)

const message = await groupEncrypt(me, distributionId, mine, new TextEncoder().encode('first'))
const plaintext = await groupDecrypt(me, theirs, message.serialize())
```

## Sealed envelopes

The server carries the envelope without learning who sent it. A server certificate signs sender
certificates; a sender certificate rides inside the envelope and is checked against the trust root
when it is opened.

```ts
const serverCertificate = ServerCertificate.new(1, serverKey.getPublicKey(), trustRoot)
const certificate = SenderCertificate.new(myUuid, null, 1, myIdentityKey, expiry, serverCertificate, serverKey)

const envelope = await sealedSenderEncryptMessage(plaintext, peer, certificate, mine, mine)

const opened = await sealedSenderDecryptMessage(
  envelope, trustRoot.getPublicKey(), now, null, theirUuid, 1, theirs, theirs, theirs, theirs, theirs,
)
```

For a group, seal once for many recipients and let the server hand each device its own slice:

```ts
const content = UnidentifiedSenderMessageContent.new(message, certificate, ContentHint.Resendable, groupId)
const many = await sealedSenderMultiRecipientEncrypt(content, addresses, mine, mine)
const forOneDevice = sealedSenderMultiRecipientMessageForRecipient(many, serviceId, 1)
```

`sealedSenderDecryptToUsmc` opens the envelope without opening the message inside it, which is what
a client does when it needs the content hint or the group id first.

## Safety numbers

```ts
const utf8 = (s: string) => new TextEncoder().encode(s)
const fingerprint = Fingerprint.new(5200, 2, utf8(myUuid), myIdentityKey, utf8(theirUuid), theirIdentityKey)
fingerprint.displayableFingerprint().toString()          // the sixty digits to read out
fingerprint.scannableFingerprint().compare(scanned)      // what a scan checks
```

Both sides must pass the same version and iteration count, and each passes its own side first.

## The rest

| Area | Entry points |
|---|---|
| Identity | `IdentityKeyPair.generate()`, `PrivateKey.generate()`, `PublicKey.verify(message, signature)`, `PrivateKey.agree(other)` |
| Post-quantum | `KEMKeyPair.generate()`, `KEMPublicKey`, `KEMSecretKey` |
| Usernames | `usernames.hash`, `.generateProof`, `.verifyProof`, `.createUsernameLink`, `.decryptUsernameLink`, `.generateCandidates`, `.fromParts` |
| Account keys | `AccountEntropyPool.generate()`, `.deriveBackupKey(pool)`, `BackupKey.deriveBackupId(aci)`, `.deriveMediaId(name)` |
| Group parameters | `GroupMasterKey.generate()`, `GroupSecretParams.deriveFromMasterKey(key)`, `.getGroupIdentifier()`, `.getPublicParams()` |
| Primitives | `hkdf(length, keyMaterial, label, salt)`, `Aes256GcmSiv`, `IncrementalMac`, `randomBytes(n)` |
| Framing | `PlaintextContent`, `DecryptionErrorMessage.extractFromSerializedContent(body)` |
| Ids | `generate_uuid()`, `uuid_to_string(bytes)`, `uuid_from_string(s)`, `generateRegistrationId()` |
| Version | `abiVersion()` |

## Errors

Every failure is a `GossveilError` with a `kind` naming the fault and a numeric `status` from the
C ABI:

```ts
try {
  await sessionDecrypt(WhisperMessage.deserialize(body), peer, mine, mine)
} catch (error) {
  if (error instanceof GossveilError) {
    switch (error.kind) {
      case 'DuplicatedMessage': break        // already seen; drop it
      case 'UntrustedIdentity': break        // the key changed; ask the user
      case 'SessionNotFound': break          // fetch a bundle and start one
    }
  }
}
```

## The handle shape

The handle shape keeps records in small in-memory stores you fill before a call and read after it,
which suits an app that already owns its storage and wants to hand over exactly what one operation
needs:

```ts
const sessions = new WasmInMemSessionStore()
if (saved) await sessions.import_session(peer, saved)
const identities = new WasmInMemIdentityKeyStore(identityKeyPair, registrationId)

const ciphertext = await encryptMessage(plaintext, peer, me, sessions, identities)
await persist(await sessions.export_session(peer))
```

`processPreKeyBundle` takes the bundle as fourteen arguments rather than a record.
`decryptMessage(bytes, type, sender, local, sessions, identities, preKeys, signedPreKeys, kyberPreKeys)`
picks the right open by the type byte you pass. `generatePreKeys`, `generateSignedPreKey` and
`generateKyberPreKey` mint keys straight into these stores, and
`generateSafetyNumber` and `verifySafetyNumber` take the uuid strings a client already holds.

## Notes

- Calls that touch a store are async because your store is. The core itself is synchronous and
  runs on the calling thread.
- Records are bytes and nothing else. Persist `serialize()`, reopen with `deserialize(bytes)`, and
  a record written by any Gossveil package opens in any other.
- Randomness comes from the host through `crypto.getRandomValues`, so a context without WebCrypto
  cannot load the core.
- Timestamps are milliseconds since the epoch.
- A `ProtocolAddress` is a name and a device id. What the name means is yours; the clients use a
  service id or an account id and never a phone number.

## Tests

```sh
bun test
```

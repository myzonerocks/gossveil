# Gossveil, Swift SDK

Swift package for [Gossveil](../../README.md), end-to-end encryption for messaging apps:
forward-secret sessions with a post-quantum handshake, groups, sealed envelopes and safety
numbers. The compiled core ships inside the package as an XCFramework, so there is no toolchain
to install and nothing to build.

The same concepts carry the same names in the [Kotlin](../kotlin/README.md) and
[TypeScript](../ts/README.md) packages, and the byte-for-byte behaviour is the same, so a session
started on one platform continues on another. The full cross-language name table is
[docs/API.md](../../docs/API.md).

## Install

In Xcode, File, Add Package Dependencies, and paste the repository URL:

```
https://github.com/myzonerocks/gossveil
```

In a `Package.swift`, name the version you want:

```swift
.package(url: "https://github.com/myzonerocks/gossveil", from: "0.1.0-alpha.2")
```

Two products come with it. `Gossveil` is the one every app wants. Add `GossveilKit` as well only
where your own code imports the C module, `import GossveilKit`, since a binary target is not
visible to a client on its own:

```swift
.product(name: "Gossveil", package: "gossveil")
.product(name: "GossveilKit", package: "gossveil")
```

iOS 16 and macOS 13 and up. Every published version is on the
[releases page](https://github.com/myzonerocks/gossveil/releases).

> [!TIP]
> The XCFramework carries the static core and the C ABI module, and each release pins its
> checksum, so SwiftPM verifies the download. Nothing to link by hand, no search paths.

### Building from source

The same manifest serves a checkout. Build the slices and assemble the XCFramework into
`zig-out/`; the manifest resolves that one instead of the release whenever it is there, so the
app's dependency line never changes between the two:

```sh
tools/toolchain-sync
tools/build-xcframework.sh
```

Then depend on the checkout by path, with the same products as above:

```swift
.package(path: "../gossveil")
```

Remove `zig-out/GossveilKit.xcframework` to go back to the release.

## Stores

Storage is yours, in your language and your database. Every operation loads what it needs, calls
the core with records, and hands records back, in one order: trust check, core call, identity
save, record store, one-time key removal, post-quantum key marked used.

```swift
public protocol IdentityKeyStore: AnyObject {
    func identityKeyPair(context: StoreContext) throws -> IdentityKeyPair
    func localRegistrationId(context: StoreContext) throws -> UInt32
    func saveIdentity(_ identity: IdentityKey, for address: ProtocolAddress, context: StoreContext) throws -> IdentityChange
    func isTrustedIdentity(_ identity: IdentityKey, for address: ProtocolAddress, direction: Direction, context: StoreContext) throws -> Bool
    func identity(for address: ProtocolAddress, context: StoreContext) throws -> IdentityKey?
}
```

`SessionStore`, `PreKeyStore`, `SignedPreKeyStore`, `KyberPreKeyStore` and `SenderKeyStore` take
the same shape. A record is bytes: `serialize()` to persist, `init(bytes:)` to reopen. `StoreContext`
is your own type, handed back to your store on every call, so a store can join the transaction the
app is already in. `NullContext` is there when you have nothing to pass.

`InMemoryProtocolStore` implements all six and is what tests and a first integration use.

## A session, end to end

The recipient publishes a bundle: an identity key, a signed pre-key, a post-quantum pre-key, and
optionally a one-time pre-key. The sender processes it and the session exists.

```swift
import Gossveil

let mine = InMemoryProtocolStore()
let theirs = InMemoryProtocolStore()
let me = try ProtocolAddress(name: "alice", deviceId: 1)
let peer = try ProtocolAddress(name: "bob", deviceId: 1)

// On the recipient: mint the keys it publishes and keep the records.
let identity = try theirs.identityKeyPair(context: NullContext())
let signedPreKey = PrivateKey.generate()
let kyberPreKey = KEMKeyPair.generate()
let signedSignature = identity.privateKey.generateSignature(message: signedPreKey.publicKey.serialize())
let kyberSignature = identity.privateKey.generateSignature(message: kyberPreKey.publicKey.serialize())
try theirs.storeSignedPreKey(
    SignedPreKeyRecord(id: 1, timestamp: 42_000, privateKey: signedPreKey, signature: signedSignature),
    id: 1, context: NullContext()
)
try theirs.storeKyberPreKey(
    KyberPreKeyRecord(id: 1, timestamp: 42_000, keyPair: kyberPreKey, signature: kyberSignature),
    id: 1, context: NullContext()
)

// On the sender: the bundle as it arrived from your service.
let bundle = try PreKeyBundle(
    registrationId: theirs.localRegistrationId(context: NullContext()), deviceId: 1,
    signedPrekeyId: 1, signedPrekey: signedPreKey.publicKey, signedPrekeySignature: signedSignature,
    identity: identity.identityKey,
    kyberPrekeyId: 1, kyberPrekey: kyberPreKey.publicKey, kyberPrekeySignature: kyberSignature
)
try processPreKeyBundle(bundle, for: peer, ourAddress: me, sessionStore: mine, identityStore: mine, context: NullContext())
```

Add `prekeyId:prekey:` to the bundle to spend a one-time key. The first message names it and the
recipient's store drops it as it opens.

## Sending and receiving

```swift
let sealed = try sessionEncrypt(
    message: Data("hello".utf8), for: peer, localAddress: me,
    sessionStore: mine, identityStore: mine, context: NullContext()
)
sealed.messageType  // .preKey for the first message, .whisper after that
```

A message is a type and a body. What goes on your wire is up to you; one type byte in front of
the body is enough, and is what the clients do:

```swift
var wire = Data([sealed.messageType.rawValue])
wire.append(sealed.serialize())
```

Opening it picks the call by that type:

```swift
// On the recipient, opening what the sender above sent.
let body = wire.dropFirst()
let plaintext: Data
switch CiphertextMessage.MessageType(rawValue: wire[0]) {
case .preKey:
    plaintext = try sessionDecryptPreKey(
        message: PreKeyMessage(bytes: body), from: me, localAddress: peer,
        sessionStore: theirs, identityStore: theirs, preKeyStore: theirs,
        signedPreKeyStore: theirs, kyberPreKeyStore: theirs, context: NullContext()
    )
default:
    plaintext = try sessionDecrypt(
        message: WhisperMessage(bytes: body), from: me, to: peer,
        sessionStore: theirs, identityStore: theirs, context: NullContext()
    )
}
```

Out-of-order messages open. A message opened twice throws `GossveilError.duplicatedMessage`.

## Groups

One sender key per member, distributed once, then every message is one ciphertext for the whole
group.

```swift
let distributionId = UUID()
let distribution = try SenderKeyDistributionMessage(
    from: me, distributionId: distributionId, store: mine, context: NullContext()
)
// Send distribution.serialize() to each member over their own session, then on each member:
try processSenderKeyDistributionMessage(
    SenderKeyDistributionMessage(bytes: received), from: me, store: theirs, context: NullContext()
)

let message = try groupEncrypt(
    Data("first".utf8), from: me, distributionId: distributionId, store: mine, context: NullContext()
)
let plaintext = try groupDecrypt(message.serialize(), from: me, store: theirs, context: NullContext())
```

## Sealed envelopes

The server carries the envelope without learning who sent it. A server certificate signs sender
certificates; a sender certificate rides inside the envelope and is checked against the trust root
when it is opened.

```swift
let serverCertificate = try ServerCertificate(keyId: 1, publicKey: serverKey.publicKey, trustRoot: trustRoot)
let certificate = try SenderCertificate(
    sender: SealedSenderAddress(e164: nil, uuidString: myUuid, deviceId: 1),
    publicKey: identity.publicKey, expiration: expiry,
    signerCertificate: serverCertificate, signerKey: serverKey
)

let envelope = try sealedSenderEncrypt(
    message: Data("sealed".utf8), for: peer, from: certificate,
    sessionStore: mine, identityStore: mine, context: NullContext()
)

let opened = try sealedSenderDecrypt(
    message: envelope, from: theirSealedAddress, trustRoot: trustRoot.publicKey, timestamp: now,
    sessionStore: theirs, identityStore: theirs, preKeyStore: theirs,
    signedPreKeyStore: theirs, kyberPreKeyStore: theirs, context: NullContext()
)
opened.message
opened.sender
```

For a group, seal once for many recipients and let the server hand each device its own slice:

```swift
let content = try UnidentifiedSenderMessageContent(sealed, from: certificate, contentHint: .resendable, groupId: groupId)
let many = try sealedSenderMultiRecipientEncrypt(
    content, for: addresses, identityStore: mine, sessionStore: mine, context: NullContext()
)
let forOneDevice = try sealedSenderMultiRecipientMessage(many, for: serviceId, deviceId: 1)
```

`sealedSenderDecryptToUsmc` opens the envelope without opening the message inside it, which is what
a client does when it needs the content hint or the group id first.

## Safety numbers

```swift
let fingerprint = try NumericFingerprintGenerator(iterations: 5200).create(
    version: 2,
    localIdentifier: Data(myUuid.utf8), localKey: myIdentity.publicKey,
    remoteIdentifier: Data(theirUuid.utf8), remoteKey: theirIdentity.publicKey
)
fingerprint.displayable.formatted                       // the sixty digits to read out
try fingerprint.scannable.compare(againstEncoding: scanned)  // what a scan checks
```

Both sides must pass the same version and iteration count, and each passes its own side first.

## The rest

| Area | Entry points |
|---|---|
| Identity | `IdentityKeyPair.generate()`, `IdentityKey.verifyAlternateIdentity(_:signature:)`, `PrivateKey.generate()`, `keyAgreement(with:)` |
| Post-quantum | `KEMKeyPair.generate()`, `KEM.encapsulate(_:)`, `KEM.decapsulate(_:ciphertext:)` |
| Usernames | `Username(_:)`, `.hash`, `.generateProof()`, `Username.verify(proof:forHash:)`, `.createLink(previousEntropy:)`, `Username(fromLink:withRandomness:)`, `Username.candidates(from:)` |
| Account keys | `AccountEntropyPool.generate()`, `.deriveBackupKey(_:)`, `BackupKey.deriveBackupId(aci:)`, `.deriveMediaId(mediaName:)`, `.deriveMediaEncryptionKey(mediaId:)` |
| Group parameters | `GroupMasterKey.generate()`, `GroupSecretParams.derive(from:)`, `.groupIdentifier`, `.publicParams` |
| Primitives | `hkdf(outputLength:inputKeyMaterial:salt:info:)`, `Aes256GcmSiv`, `IncrementalMac.calculate/validate`, `randomBytes(_:)` |
| Framing | `PlaintextContent`, `DecryptionErrorMessage.extractFromSerializedContent(_:)` |
| Version | `Gossveil.abiVersion` |

## Errors

Every call throws `GossveilError`, one case per protocol fault, each carrying a message:

```swift
do {
    _ = try sessionDecrypt(message: message, from: peer, sessionStore: mine, identityStore: mine, context: NullContext())
} catch GossveilError.duplicatedMessage {
    // already seen; drop it
} catch GossveilError.untrustedIdentity {
    // the peer's identity key changed; ask the user before continuing
} catch GossveilError.sessionNotFound {
    // fetch a bundle and start one
}
```

## Notes

- Calls are synchronous and run on the calling thread. Nothing is shared between calls except the
  stores you pass, so give one conversation one queue and the records stay consistent.
- Records are bytes and nothing else. Persist `serialize()`, reopen with `init(bytes:)`, and a
  record written by any Gossveil package opens in any other.
- Timestamps are milliseconds since the epoch in records, and `Date` in the calls that take one.
- A `ProtocolAddress` is a name and a device id. What the name means is yours; the clients use a
  service id or an account id and never a phone number.

## Tests

```sh
tools/build-xcframework.sh && swift test
```

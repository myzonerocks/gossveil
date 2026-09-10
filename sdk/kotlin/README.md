# Gossveil, Kotlin SDK

Android library for [Gossveil](../../README.md), end-to-end encryption for messaging apps:
forward-secret sessions with a post-quantum handshake, groups, sealed envelopes and safety
numbers. The compiled core rides inside the AAR as a `.so` per ABI, so you add a coordinate and
never run a build step.

The same concepts carry the same names in the [Swift](../swift/README.md) and
[TypeScript](../ts/README.md) packages, and the byte-for-byte behaviour is the same, so a session
started on one platform continues on another. The full cross-language name table is
[docs/API.md](../../docs/API.md).

## Install

```kotlin
// build.gradle.kts
implementation("io.github.avosa:gossveil:0.1.0-alpha.2")
```

From Maven Central, which needs no repository entry beyond the one an Android project already has:

```kotlin
repositories { mavenCentral() }
```

`minSdk` 26, JVM target 17. The AAR carries `arm64-v8a` and `x86_64`, and the package loads the
core itself on first use, so there is no `System.loadLibrary` to call and no ABI splits to
configure. Every published version is on the
[releases page](https://github.com/myzonerocks/gossveil/releases).

### JitPack

Any tag also builds over JitPack, which takes the native libraries from that tag's release and
assembles the AAR around them. Central is the recommended route; this one is here for a tag that
was never published, or a fork:

```kotlin
// settings.gradle.kts
repositories { maven { url = uri("https://jitpack.io") } }

// build.gradle.kts
implementation("com.github.myzonerocks:gossveil:v0.1.0-alpha.2")
```

### Building from source

The native core is built by the repository's own toolchain, and Gradle picks it up from
`zig-out/`:

```sh
tools/toolchain-sync
zig build jni android -Doptimize=ReleaseFast
(cd sdk/kotlin && ./gradlew :lib:assembleRelease)
```

`jni` builds the host library the JVM unit tests load; `android` builds the two Android ABIs the
AAR ships. To point an app at a checkout instead of the registry, publish it locally and add that
repository:

```sh
(cd sdk/kotlin && ./gradlew publishToMavenLocal -PVERSION_NAME=0.1.0-alpha.2)
```

```kotlin
// settings.gradle.kts
repositories { maven { url = uri("../gossveil/sdk/kotlin/lib/build/repo") } }
```

## Stores

Storage is yours, in your language and your database. Every operation loads what it needs, calls
the core with records, and hands records back, in one order: trust check, core call, identity
save, record store, one-time key removal, post-quantum key marked used.

```java
public interface IdentityKeyStore {
    enum Direction { SENDING, RECEIVING }
    enum IdentityChange { NEW_OR_UNCHANGED, REPLACED_EXISTING }
    IdentityKeyPair getIdentityKeyPair();
    int getLocalRegistrationId();
    IdentityChange saveIdentity(ProtocolAddress address, IdentityKey identityKey);
    boolean isTrustedIdentity(ProtocolAddress address, IdentityKey identityKey, Direction direction);
    IdentityKey getIdentity(ProtocolAddress address);
}
```

`SessionStore`, `PreKeyStore`, `SignedPreKeyStore`, `KyberPreKeyStore` and `SenderKeyStore` take
the same shape, and `ProtocolStore` is all six in one interface, which is what the ciphers take in
their short constructors. A record is bytes: `serialize()` to persist, the class constructor to
reopen.

`InMemoryProtocolStore` implements all six and is what tests and a first integration use.

## A session, end to end

The recipient publishes a bundle: an identity key, a signed pre-key, a post-quantum pre-key, and
optionally a one-time pre-key. The sender processes it and the session exists.

```kotlin
import com.gossveil.*

val mine = InMemoryProtocolStore()
val theirs = InMemoryProtocolStore()
val me = ProtocolAddress("alice", 1)
val peer = ProtocolAddress("bob", 1)

// On the recipient: mint the keys it publishes and keep the records.
val identity = theirs.getIdentityKeyPair()
val signed = ECKeyPair.generate()
val pq = KEMKeyPair.generate(KEMKeyType.KYBER_1024)
val now = System.currentTimeMillis()
val signedSig = identity.privateKey.calculateSignature(signed.publicKey.serialize())
val pqSig = identity.privateKey.calculateSignature(pq.publicKey.serialize())
theirs.storeSignedPreKey(1, SignedPreKeyRecord(1, now, signed, signedSig))
theirs.storeKyberPreKey(1, KyberPreKeyRecord(1, now, pq, pqSig))

// On the sender: the bundle as it arrived from your service.
val bundle = PreKeyBundle(
    theirs.getLocalRegistrationId(), 1,
    PreKeyBundle.NULL_PRE_KEY_ID, null,
    1, signed.publicKey, signedSig,
    identity.publicKey,
    1, pq.publicKey, pqSig,
)
SessionBuilder(mine, peer).process(bundle)
```

Pass a one-time key id and its public key in place of `NULL_PRE_KEY_ID` and `null` to spend one.
The first message names it and the recipient's store drops it as it opens.

## Sending and receiving

```kotlin
val ciphertext = SessionCipher(mine, peer).encrypt("hello".toByteArray())
ciphertext.type  // CiphertextMessage.PREKEY_TYPE first, then WHISPER_TYPE
```

A message is a type and a body. What goes on your wire is up to you; one type byte in front of the
body is enough, and is what the clients do:

```kotlin
val body = ciphertext.serialize()
val wire = ByteArray(body.size + 1)
wire[0] = ciphertext.type.toByte()
System.arraycopy(body, 0, wire, 1, body.size)
```

Opening it picks the call by that type:

```kotlin
// On the recipient, opening what the sender above sent.
val type = wire[0].toInt() and 0xff
val body = wire.copyOfRange(1, wire.size)
val cipher = SessionCipher(theirs, me)
val plaintext = if (type == CiphertextMessage.PREKEY_TYPE) {
    cipher.decrypt(PreKeyMessage(body))
} else {
    cipher.decrypt(WhisperMessage(body))
}
```

Out-of-order messages open. A message opened twice throws `DuplicateMessageException`.

## Groups

One sender key per member, distributed once, then every message is one ciphertext for the whole
group.

```kotlin
val distributionId = UUID.randomUUID()
val distribution = GroupSessionBuilder(mine).create(me, distributionId)
// Send distribution.serialize() to each member over their own session, then on each member:
GroupSessionBuilder(theirs).process(me, SenderKeyDistributionMessage(received))

val message = GroupCipher(mine, me).encrypt(distributionId, "first".toByteArray())
val plaintext = GroupCipher(theirs, me).decrypt(message.serialize())
```

## Sealed envelopes

The server carries the envelope without learning who sent it. A server certificate signs sender
certificates; a sender certificate rides inside the envelope and is checked against the trust root
when it is opened.

```kotlin
val serverCertificate = ServerCertificate(1, serverKey.publicKey, trustRoot.privateKey)
val certificate = SenderCertificate(
    myUuid, null, 1, mine.getIdentityKeyPair().publicKey.publicKey,
    expiry, serverCertificate, serverKey.privateKey,
)

val cipher = SealedSessionCipher(mine, myUuid, null, 1)
val envelope = cipher.encrypt(peer, certificate, "sealed".toByteArray())

val opened = SealedSessionCipher(theirs, theirUuid, null, 1).decrypt(trustRoot.publicKey, envelope, now)
opened.paddedMessage
opened.senderUuid
```

For a group, seal once for many recipients and let the server hand each device its own slice:

```kotlin
val content = UnidentifiedSenderMessageContent(
    message, certificate, UnidentifiedSenderMessageContent.ContentHint.RESENDABLE, groupId,
)
val many = cipher.multiRecipientEncrypt(listOf(peer), content)
val forOneDevice = SealedSessionCipher.multiRecipientMessageForRecipient(many, serviceId, 1)
```

`decryptToUsmc` opens the envelope without opening the message inside it, which is what a client
does when it needs the content hint or the group id first.

## Safety numbers

```kotlin
val fingerprint = NumericFingerprintGenerator(5200).createFor(
    2,
    myUuid.toByteArray(), myIdentityKey,
    theirUuid.toByteArray(), theirIdentityKey,
)
fingerprint.displayableFingerprint.displayText          // the sixty digits to read out
fingerprint.scannableFingerprint.compareTo(scanned)     // what a scan checks
```

Both sides must pass the same version and iteration count, and each passes its own side first.

## The rest

| Area | Entry points |
|---|---|
| Identity | `IdentityKeyPair.generate()`, `IdentityKey.verifyAlternateIdentity(other, signature)`, `ECPrivateKey.generate()`, `calculateAgreement(other)` |
| Post-quantum | `KEMKeyPair.generate(type)`, `KEMPublicKey.encapsulate()`, `KEMSecretKey.decapsulate(ciphertext)` |
| Usernames | `Username(name)`, `.hash`, `.generateProof()`, `Username.verifyProof(proof, hash)`, `.generateLink()`, `Username.fromLink(encrypted, entropy)`, `Username.candidatesFrom(nickname)` |
| Account keys | `AccountEntropyPool.generate()`, `.deriveBackupKey(pool)`, `BackupKey.deriveBackupId(aci)`, `.deriveMediaId(name)`, `.deriveMediaEncryptionKey(mediaId)` |
| Group parameters | `GroupMasterKey.generate()`, `GroupSecretParams.deriveFromMasterKey(key)`, `.groupIdentifier`, `.publicParams` |
| Primitives | `HKDF.deriveSecrets(...)`, `Aes256GcmSiv`, `IncrementalMac`, `randomBytes(n)` |
| Framing | `PlaintextContent`, `DecryptionErrorMessage.extractFromSerializedContent(body)` |
| Version | `abiVersion()` |

## Errors

Each protocol fault is its own exception, so a `catch` says what happened:

```kotlin
try {
    SessionCipher(mine, peer).decrypt(WhisperMessage(body))
} catch (e: DuplicateMessageException) {
    // already seen; drop it
} catch (e: UntrustedIdentityException) {
    // the peer's identity key changed; ask the user before continuing
} catch (e: NoSessionException) {
    // fetch a bundle and start one
}
```

`InvalidKeyException`, `InvalidMessageException`, `InvalidKeyIdException`, `InvalidVersionException`,
`LegacyMessageException`, `VerificationFailedException`, `InvalidRegistrationIdException` and
`SelfSendException` cover the rest.

## Notes

- Calls are synchronous and run on the calling thread. Nothing is shared between calls except the
  stores you pass, so give one conversation one queue and the records stay consistent.
- Records are bytes and nothing else. Persist `serialize()`, reopen with the class constructor,
  and a record written by any Gossveil package opens in any other.
- Timestamps are milliseconds since the epoch.
- A `ProtocolAddress` is a name and a device id. What the name means is yours; the clients use a
  service id or an account id and never a phone number.
- The package keeps no state of its own between calls, so nothing needs to be released or closed.

## Tests

```sh
zig build jni -Doptimize=ReleaseFast
(cd sdk/kotlin && ./gradlew :lib:testDebugUnitTest)
```

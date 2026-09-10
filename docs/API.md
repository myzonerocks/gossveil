# API

One surface, three languages. Each row names the type or function as each package spells
it. Types marked "record" serialise to bytes a host persists and any package re-opens.

## Keys and identity

| Concept | Swift | Kotlin | TypeScript (record shape / store shape) |
|---|---|---|---|
| Curve public key (33 bytes, tag byte first) | `PublicKey` | `ECPublicKey` | `PublicKey` / `WasmPublicKey` |
| Curve private key (32 bytes) | `PrivateKey` (`generate`, `publicKey`, `generateSignature`, `keyAgreement`) | `ECPrivateKey` (`generate`, `publicKey`, `calculateSignature`, `calculateAgreement`) | `PrivateKey` / `WasmPrivateKey` |
| Key pair | `IdentityKeyPair`, `KEMKeyPair` | `ECKeyPair`, `IdentityKeyPair`, `KEMKeyPair.generate(KEMKeyType)` | `IdentityKeyPair`, `KEMKeyPair` / `WasmIdentityKeyPair` |
| Identity key | `IdentityKey` (`verifyAlternateIdentity`) | `IdentityKey` | `PublicKey` |
| Post-quantum keys (1569-byte public, 3169-byte secret, tag byte first) | `KEMPublicKey`, `KEMSecretKey` | `KEMPublicKey`, `KEMSecretKey` | `KEMPublicKey`, `KEMSecretKey` |
| Address | `ProtocolAddress(name:deviceId:)` | `ProtocolAddress(name, deviceId)` | `ProtocolAddress` / `WasmProtocolAddress` |
| Service id | `ServiceId`, `Aci`, `Pni` | `ServiceId.Aci`, `ServiceId.Pni` | `ServiceId`, `Aci`, `Pni` |

## Records

| Record | Swift | Kotlin | TypeScript |
|---|---|---|---|
| One-time pre-key | `PreKeyRecord(id:privateKey:)` | `PreKeyRecord(id, keyPair)` | `PreKeyRecord.new` / `generatePreKeys` |
| Signed pre-key | `SignedPreKeyRecord(id:timestamp:privateKey:signature:)` | `SignedPreKeyRecord(id, timestamp, keyPair, signature)` | `SignedPreKeyRecord.new` / `generateSignedPreKey` |
| Post-quantum pre-key | `KyberPreKeyRecord(id:timestamp:keyPair:signature:)` | `KyberPreKeyRecord(id, timestamp, keyPair, signature)` | `KyberPreKeyRecord.new` / `generateKyberPreKey` |
| Session | `SessionRecord` (`hasCurrentState`, `archiveCurrentState`, `remoteRegistrationId`, `remoteIdentityKey`) | `SessionRecord` (`hasSenderChain`, `archiveCurrentState`, `remoteRegistrationId`, `remoteIdentityKey`) | `SessionRecord` / `WasmInMemSessionStore.export_session` |
| Sender key | `SenderKeyRecord` | `SenderKeyRecord` | `SenderKeyRecord` / `WasmInMemSenderKeyStore.export_sender_key` |
| Bundle | `PreKeyBundle(registrationId:deviceId:[prekeyId:prekey:]signedPrekeyId:signedPrekey:signedPrekeySignature:identity:kyberPrekeyId:kyberPrekey:kyberPrekeySignature:)` | `PreKeyBundle(registrationId, deviceId, preKeyId or NULL_PRE_KEY_ID, preKey?, signedPreKeyId, signedPreKey, signature, identityKey, kyberPreKeyId, kyberPreKey, kyberSignature)` | `PreKeyBundle.new(...)` / the fourteen arguments of `processPreKeyBundle` |

Timestamps are milliseconds since the epoch.

## Stores

Stores live in the host. Every protocol operation loads what it needs, calls the core with
records, and stores what came back, in this order: trust check, core call, identity save,
record store, pre-key removal, post-quantum pre-key marked used.

| Store | Swift protocol | Kotlin interface | TypeScript abstract class / in-memory class |
|---|---|---|---|
| Sessions | `SessionStore` | `SessionStore` (with `containsSession`, `deleteSession`, `deleteAllSessions`) | `SessionStore` / `WasmInMemSessionStore` |
| Identities | `IdentityKeyStore` (`Direction`, `IdentityChange`) | `IdentityKeyStore` (`Direction`, `IdentityChange`) | `IdentityKeyStore` / `WasmInMemIdentityKeyStore` (with `export_identity`, `import_identity`) |
| One-time pre-keys | `PreKeyStore` | `PreKeyStore` (with `containsPreKey`) | `PreKeyStore` / `WasmInMemPreKeyStore` |
| Signed pre-keys | `SignedPreKeyStore` | `SignedPreKeyStore` | `SignedPreKeyStore` / `WasmInMemSignedPreKeyStore` |
| Post-quantum pre-keys | `KyberPreKeyStore` (`markKyberPreKeyUsed(id:signedPreKeyId:baseKey:context:)`) | `KyberPreKeyStore` | `KyberPreKeyStore` / `WasmInMemKyberPreKeyStore` |
| Sender keys | `SenderKeyStore` | `SenderKeyStore` | `SenderKeyStore` / `WasmInMemSenderKeyStore` |
| All of them | `InMemoryProtocolStore` | `InMemoryProtocolStore` (`ProtocolStore`) | `InMemoryProtocolStore` |

## Sessions

| Operation | Swift | Kotlin | TypeScript |
|---|---|---|---|
| Start from a bundle | `processPreKeyBundle(_:for:ourAddress:sessionStore:identityStore:now:context:)` | `SessionBuilder(sessions, prekeys, signed, identities, address).process(bundle)` | `processBundle(bundle, address, sessions, identities)` / `processPreKeyBundle(...)` |
| Encrypt | `sessionEncrypt(message:for:localAddress:sessionStore:identityStore:now:context:) -> CiphertextMessage` | `SessionCipher(sessions, prekeys, signed, kyber, identities, address).encrypt(bytes)` | `sessionEncrypt(...)` / `encryptMessage(...) -> WasmCiphertext` |
| Decrypt a whisper | `sessionDecrypt(message:from:to:sessionStore:identityStore:context:) -> Data` | `SessionCipher.decrypt(WhisperMessage)` | `sessionDecrypt(...)` / `decryptMessage(bytes, type, ...)` |
| Decrypt a first message | `sessionDecryptPreKey(message:from:localAddress:sessionStore:identityStore:preKeyStore:signedPreKeyStore:kyberPreKeyStore:context:) -> Data` | `SessionCipher.decrypt(PreKeyMessage)` | `sessionDecryptPreKey(...)` / `decryptMessage(bytes, type, ...)` |
| Message kinds | `CiphertextMessage.MessageType.{whisper, preKey, senderKey, plaintext}` (2, 3, 7, 8) | `CiphertextMessage.{WHISPER_TYPE, PREKEY_TYPE, SENDERKEY_TYPE, PLAINTEXT_CONTENT_TYPE}` | `CiphertextMessageType` / `message_type_whisper()`, `message_type_pre_key()`, `message_type_sender_key()` |
| Parse a message | `WhisperMessage(bytes:)`, `PreKeyMessage(bytes:)` | `WhisperMessage(bytes)`, `PreKeyMessage(bytes)` | `WhisperMessage.deserialize`, `PreKeyMessage.deserialize` |

Errors: `GossveilError` (Swift enum), the typed exceptions in the Kotlin package
(`InvalidKeyException`, `InvalidMessageException`, `InvalidKeyIdException`,
`UntrustedIdentityException`, `NoSessionException`, `DuplicateMessageException`,
`LegacyMessageException`, `InvalidVersionException`, `VerificationFailedException`), and
`GossveilError` with a `kind` string in TypeScript.

## Groups

| Operation | Swift | Kotlin | TypeScript |
|---|---|---|---|
| Create a distribution | `SenderKeyDistributionMessage(from:distributionId:store:context:)` | `GroupSessionBuilder(store).create(sender, distributionId)` | `SenderKeyDistributionMessage.create` / `createSenderKeyDistribution` |
| Process one | `processSenderKeyDistributionMessage(_:from:store:context:)` | `GroupSessionBuilder(store).process(sender, message)` | `processSenderKeyDistributionMessage` / `processSenderKeyDistribution` |
| Encrypt | `groupEncrypt(_:from:distributionId:store:context:)` | `GroupCipher(store, sender).encrypt(distributionId, bytes)` | `groupEncrypt` / `encryptGroupMessage` |
| Decrypt | `groupDecrypt(_:from:store:context:)` | `GroupCipher(store, sender).decrypt(bytes)` | `groupDecrypt` / `decryptGroupMessage` |

## Sealed sender

| Operation | Swift | Kotlin | TypeScript |
|---|---|---|---|
| Certificates | `ServerCertificate(keyId:publicKey:trustRoot:)`, `SenderCertificate(sender:publicKey:expiration:signerCertificate:signerKey:)`, `.validate(trustRoot:time:)` | `ServerCertificate(keyId, key, trustRoot)`, `SenderCertificate(uuid, e164, deviceId, key, expiration, signer, signerKey)`, `.validate(trustRoot, timestamp)` | `ServerCertificate.new`, `SenderCertificate.new`, `.validate` |
| Content | `UnidentifiedSenderMessageContent(_:from:contentHint:groupId:)` | `UnidentifiedSenderMessageContent(message, sender, hint, groupId)` | `UnidentifiedSenderMessageContent.new` |
| Seal for one | `sealedSenderEncrypt(message:for:from:sessionStore:identityStore:context:)` and `sealedSenderEncrypt(_:for:identityStore:context:)` | `SealedSessionCipher.encrypt(destination, certificate, bytes)` and `.encrypt(destination, content)` | `sealedSenderEncryptMessage`, `sealedSenderEncrypt` |
| Seal for many | `sealedSenderMultiRecipientEncrypt(_:for:excludedRecipients:identityStore:sessionStore:context:)` | `SealedSessionCipher.multiRecipientEncrypt(addresses, content, excluded)` | `sealedSenderMultiRecipientEncrypt` |
| Server split | `sealedSenderMultiRecipientMessageForSingleRecipient`, `sealedSenderMultiRecipientMessage(_:for:deviceId:)` | `SealedSessionCipher.multiRecipientMessageForSingleRecipient`, `.multiRecipientMessageForRecipient` | `sealedSenderMultiRecipientMessageForSingleRecipient`, `sealedSenderMultiRecipientMessageForRecipient` |
| Open | `sealedSenderDecrypt(message:from:trustRoot:timestamp:...)`, `sealedSenderDecryptToUsmc` | `SealedSessionCipher.decrypt(trustRoot, bytes, timestamp)`, `.decryptToUsmc` | `sealedSenderDecryptMessage`, `sealedSenderDecryptToUsmc` |

## Safety numbers, usernames, account keys, group parameters

| Area | Swift | Kotlin | TypeScript |
|---|---|---|---|
| Safety numbers | `NumericFingerprintGenerator(iterations:).create(version:localIdentifier:localKey:remoteIdentifier:remoteKey:)`, `Fingerprint.displayable.formatted`, `.scannable.compare(againstEncoding:)` | `NumericFingerprintGenerator(iterations).createFor(version, localId, localKey, remoteId, remoteKey)` | `Fingerprint.new(iterations, version, ...)` / `generateSafetyNumber`, `verifySafetyNumber` (version 2, 5200 iterations, uuid strings) |
| Usernames | `Username(_:)`, `.hash`, `.generateProof`, `Username.verify(proof:forHash:)`, `.createLink`, `Username(fromLink:withRandomness:)`, `Username.candidates(from:)`, `Username(fromParts:discriminator:)` | `Username(name)`, `.hash`, `.generateProof`, `Username.verifyProof`, `.generateLink`, `Username.fromLink`, `Username.candidatesFrom`, `Username.fromParts` | `usernames.hash`, `.generateProof`, `.verifyProof`, `.createUsernameLink`, `.decryptUsernameLink`, `.generateCandidates`, `.fromParts` |
| Account keys | `AccountEntropyPool.generate/isValid/deriveSvrKey/deriveBackupKey`, `BackupKey` derivations | same names | same names |
| Group parameters | `GroupMasterKey`, `GroupSecretParams` | `GroupMasterKey`, `GroupSecretParams` | `GroupMasterKey`, `GroupSecretParams` / `WasmGroupMasterKey`, `WasmGroupSecretParams`, `WasmGroupIdentifier` |
| Primitives | `hkdf`, `Aes256GcmSiv`, `IncrementalMac`, `randomBytes`, `KEM.encapsulate/decapsulate` | `HKDF`, `Aes256GcmSiv`, `IncrementalMac`, `randomBytes`, `KEMPublicKey.encapsulate`, `KEMSecretKey.decapsulate` | `hkdf`, `Aes256GcmSiv`, `IncrementalMac`, `randomBytes` / `generate_random_bytes`, `generate_attachment_key`, `generate_uuid`, `uuid_from_string`, `uuid_to_string`, `generateRegistrationId` |
| Content framing | `DecryptionErrorMessage`, `PlaintextContent` | `DecryptionErrorMessage`, `PlaintextContent` | `DecryptionErrorMessage`, `PlaintextContent` |

## Names kept for the clients

Each package keeps the names the clients called before the rename. They are the gossveil
types under a second name, not a second implementation.

| Kept name | Gossveil name |
|---|---|
| `SignalError` (Swift, TypeScript) | `GossveilError` |
| `SignalMessage` | `WhisperMessage` |
| `PreKeySignalMessage` | `PreKeyMessage` |
| `InMemorySignalProtocolStore` | `InMemoryProtocolStore` |
| `SignalProtocolAddress`, `SignalProtocolStore` (Kotlin) | `ProtocolAddress`, `ProtocolStore` |
| `signalEncrypt`, `signalDecrypt`, `signalDecryptPreKey` (Swift, TypeScript) | `sessionEncrypt`, `sessionDecrypt`, `sessionDecryptPreKey` |
| `LibSignal.abiVersion` (Swift) | `Gossveil.abiVersion` |
| `message_type_signal()` (TypeScript) | `message_type_whisper()` |

## The C ABI

`include/gossveil.h`. Every function returns `int32_t` (`GV_OK` is 0); byte inputs are
`(const uint8_t *, size_t)`; outputs are `GvBuffer` cells freed with `gv_free`; every output
is empty on error. `gv_alloc` gives a host input memory when it cannot pass a pointer of its
own. `gv_status_text` names a status.

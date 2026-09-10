import Foundation
@testable import Gossveil
import XCTest

final class GossveilTests: XCTestCase {
    static let signedPreKeyId: UInt32 = 1
    static let kyberPreKeyId: UInt32 = 1

    /// The iOS client's own round trip, call for call: bundle, session, first message, decrypt.
    func testSelfRoundTripAsTheClientCallsIt() throws {
        let senderStore = InMemoryProtocolStore()
        let recipientStore = InMemoryProtocolStore()
        let senderAddress = try ProtocolAddress(name: "sender", deviceId: 1)
        let recipientAddress = try ProtocolAddress(name: "recipient", deviceId: 1)

        let signedPreKey = PrivateKey.generate()
        let kyberPreKey = KEMKeyPair.generate()
        let recipientIdentity = try recipientStore.identityKeyPair(context: NullContext())
        let signedPreKeySignature = recipientIdentity.privateKey.generateSignature(message: signedPreKey.publicKey.serialize())
        let kyberPreKeySignature = recipientIdentity.privateKey.generateSignature(message: kyberPreKey.publicKey.serialize())

        try recipientStore.storeSignedPreKey(
            SignedPreKeyRecord(id: Self.signedPreKeyId, timestamp: 42000, privateKey: signedPreKey, signature: signedPreKeySignature),
            id: Self.signedPreKeyId, context: NullContext()
        )
        try recipientStore.storeKyberPreKey(
            KyberPreKeyRecord(id: Self.kyberPreKeyId, timestamp: 42000, keyPair: kyberPreKey, signature: kyberPreKeySignature),
            id: Self.kyberPreKeyId, context: NullContext()
        )

        let bundle = try PreKeyBundle(
            registrationId: recipientStore.localRegistrationId(context: NullContext()),
            deviceId: 1,
            signedPrekeyId: Self.signedPreKeyId,
            signedPrekey: signedPreKey.publicKey,
            signedPrekeySignature: signedPreKeySignature,
            identity: recipientIdentity.identityKey,
            kyberPrekeyId: Self.kyberPreKeyId,
            kyberPrekey: kyberPreKey.publicKey,
            kyberPrekeySignature: kyberPreKeySignature
        )
        try processPreKeyBundle(bundle, for: recipientAddress, ourAddress: senderAddress, sessionStore: senderStore, identityStore: senderStore, context: NullContext())

        let plaintext = Array("hello from here".utf8)
        let ciphertext = try sessionEncrypt(message: plaintext, for: recipientAddress, localAddress: senderAddress, sessionStore: senderStore, identityStore: senderStore, context: NullContext())
        XCTAssertEqual(ciphertext.messageType, .preKey)

        let first = try PreKeyMessage(bytes: ciphertext.serialize())
        let decrypted = try sessionDecryptPreKey(
            message: first, from: senderAddress, localAddress: recipientAddress,
            sessionStore: recipientStore, identityStore: recipientStore, preKeyStore: recipientStore,
            signedPreKeyStore: recipientStore, kyberPreKeyStore: recipientStore, context: NullContext()
        )
        XCTAssertEqual(Array(decrypted), plaintext)
        XCTAssertTrue(recipientStore.hasKyberPreKeyBeenUsed(id: Self.kyberPreKeyId))

        // The reply rides the session both ways, with a wire type byte the way the client frames it.
        let reply = try sessionEncrypt(message: Data("and back".utf8), for: senderAddress, localAddress: recipientAddress, sessionStore: recipientStore, identityStore: recipientStore, context: NullContext())
        XCTAssertEqual(reply.messageType, .whisper)
        var wire = Data([reply.messageType.rawValue])
        wire.append(reply.serialize())
        let body = wire.dropFirst()
        let opened = try sessionDecrypt(message: WhisperMessage(bytes: body), from: recipientAddress, to: senderAddress, sessionStore: senderStore, identityStore: senderStore, context: NullContext())
        XCTAssertEqual(opened, Data("and back".utf8))

        // A replay is refused, later messages still open.
        XCTAssertThrowsError(try sessionDecrypt(message: WhisperMessage(bytes: body), from: recipientAddress, to: senderAddress, sessionStore: senderStore, identityStore: senderStore, context: NullContext())) { error in
            guard case GossveilError.duplicatedMessage = error else { return XCTFail("\(error)") }
        }
        let later = try sessionEncrypt(message: Data("later".utf8), for: senderAddress, sessionStore: recipientStore, identityStore: recipientStore, context: NullContext())
        XCTAssertEqual(try sessionDecrypt(message: WhisperMessage(bytes: later.serialize()), from: recipientAddress, sessionStore: senderStore, identityStore: senderStore, context: NullContext()), Data("later".utf8))

        let session = try XCTUnwrap(try senderStore.loadSession(for: recipientAddress, context: NullContext()))
        XCTAssertTrue(session.hasCurrentState())
        XCTAssertEqual(try session.remoteRegistrationId(), try recipientStore.localRegistrationId(context: NullContext()))
        XCTAssertEqual(try session.remoteIdentityKey(), recipientIdentity.identityKey)
        let archived = try session.archiveCurrentState()
        XCTAssertFalse(archived.hasCurrentState())
        XCTAssertEqual(try SessionRecord(bytes: session.serialize()).serialize(), session.serialize())
    }

    func testOneTimePreKeyIsConsumedAndIdentityChangeIsRefused() throws {
        let alice = InMemoryProtocolStore()
        let bob = InMemoryProtocolStore()
        let aliceAddress = try ProtocolAddress(name: "alice", deviceId: 1)
        let bobAddress = try ProtocolAddress(name: "bob", deviceId: 1)
        let bobIdentity = try bob.identityKeyPair(context: NullContext())
        let oneTime = PrivateKey.generate()
        let signed = PrivateKey.generate()
        let kyber = KEMKeyPair.generate()
        try bob.storePreKey(PreKeyRecord(id: 7, privateKey: oneTime), id: 7, context: NullContext())
        try bob.storeSignedPreKey(SignedPreKeyRecord(id: 2, timestamp: 1, privateKey: signed, signature: bobIdentity.privateKey.generateSignature(message: signed.publicKey.serialize())), id: 2, context: NullContext())
        try bob.storeKyberPreKey(KyberPreKeyRecord(id: 3, timestamp: 1, keyPair: kyber, signature: bobIdentity.privateKey.generateSignature(message: kyber.publicKey.serialize())), id: 3, context: NullContext())
        let bundle = try PreKeyBundle(
            registrationId: bob.localRegistrationId(context: NullContext()), deviceId: 1,
            prekeyId: 7, prekey: oneTime.publicKey,
            signedPrekeyId: 2, signedPrekey: signed.publicKey, signedPrekeySignature: bobIdentity.privateKey.generateSignature(message: signed.publicKey.serialize()),
            identity: bobIdentity.identityKey,
            kyberPrekeyId: 3, kyberPrekey: kyber.publicKey, kyberPrekeySignature: bobIdentity.privateKey.generateSignature(message: kyber.publicKey.serialize())
        )
        try processPreKeyBundle(bundle, for: bobAddress, sessionStore: alice, identityStore: alice, context: NullContext())
        let message = try sessionEncrypt(message: Data("one".utf8), for: bobAddress, sessionStore: alice, identityStore: alice, context: NullContext())
        let parsed = try PreKeyMessage(bytes: message.serialize())
        XCTAssertEqual(parsed.preKeyId, 7)
        XCTAssertEqual(parsed.kyberPreKeyId, 3)
        XCTAssertEqual(parsed.identityKey, try alice.identityKeyPair(context: NullContext()).identityKey)
        _ = try sessionDecryptPreKey(message: parsed, from: aliceAddress, sessionStore: bob, identityStore: bob, preKeyStore: bob, signedPreKeyStore: bob, kyberPreKeyStore: bob, context: NullContext())
        XCTAssertThrowsError(try bob.loadPreKey(id: 7, context: NullContext()))

        // A second sender under alice's name with a different identity is untrusted at bob's.
        let impostor = InMemoryProtocolStore()
        let bundle2 = try PreKeyBundle(
            registrationId: bob.localRegistrationId(context: NullContext()), deviceId: 1,
            signedPrekeyId: 2, signedPrekey: signed.publicKey, signedPrekeySignature: bobIdentity.privateKey.generateSignature(message: signed.publicKey.serialize()),
            identity: bobIdentity.identityKey,
            kyberPrekeyId: 3, kyberPrekey: kyber.publicKey, kyberPrekeySignature: bobIdentity.privateKey.generateSignature(message: kyber.publicKey.serialize())
        )
        try processPreKeyBundle(bundle2, for: bobAddress, sessionStore: impostor, identityStore: impostor, context: NullContext())
        let forged = try sessionEncrypt(message: Data("two".utf8), for: bobAddress, sessionStore: impostor, identityStore: impostor, context: NullContext())
        XCTAssertThrowsError(try sessionDecryptPreKey(message: PreKeyMessage(bytes: forged.serialize()), from: aliceAddress, sessionStore: bob, identityStore: bob, preKeyStore: bob, signedPreKeyStore: bob, kyberPreKeyStore: bob, context: NullContext())) { error in
            guard case GossveilError.untrustedIdentity = error else { return XCTFail("\(error)") }
        }
    }

    func testGroupSenderKeys() throws {
        let alice = InMemoryProtocolStore()
        let bob = InMemoryProtocolStore()
        let aliceAddress = try ProtocolAddress(name: "alice", deviceId: 2)
        let distributionId = UUID()
        let distribution = try SenderKeyDistributionMessage(from: aliceAddress, distributionId: distributionId, store: alice, context: NullContext())
        XCTAssertEqual(distribution.distributionId, distributionId)
        let received = try SenderKeyDistributionMessage(bytes: distribution.serialize())
        try processSenderKeyDistributionMessage(received, from: aliceAddress, store: bob, context: NullContext())

        let first = try groupEncrypt(Data("first".utf8), from: aliceAddress, distributionId: distributionId, store: alice, context: NullContext())
        let second = try groupEncrypt(Data("second".utf8), from: aliceAddress, distributionId: distributionId, store: alice, context: NullContext())
        XCTAssertEqual(first.messageType, .senderKey)
        XCTAssertEqual(try SenderKeyMessage(bytes: second.serialize()).iteration, 1)
        XCTAssertEqual(try groupDecrypt(second.serialize(), from: aliceAddress, store: bob, context: NullContext()), Data("second".utf8))
        XCTAssertEqual(try groupDecrypt(first.serialize(), from: aliceAddress, store: bob, context: NullContext()), Data("first".utf8))
        XCTAssertThrowsError(try groupDecrypt(first.serialize(), from: aliceAddress, store: bob, context: NullContext()))
    }

    func testSealedSenderBothForms() throws {
        let trustRoot = PrivateKey.generate()
        let serverKey = PrivateKey.generate()
        let serverCertificate = try ServerCertificate(keyId: 1, publicKey: serverKey.publicKey, trustRoot: trustRoot)
        let aliceUuid = UUID()
        let bobUuid = UUID()
        let alice = InMemoryProtocolStore()
        let bob = InMemoryProtocolStore()
        let aliceAddress = ProtocolAddress(ServiceId(kind: .aci, uuid: aliceUuid), deviceId: 1)
        let bobAddress = ProtocolAddress(ServiceId(kind: .aci, uuid: bobUuid), deviceId: 1)
        let aliceIdentity = try alice.identityKeyPair(context: NullContext())
        let bobIdentity = try bob.identityKeyPair(context: NullContext())
        let sender = try SealedSenderAddress(e164: "+14151111111", uuidString: aliceUuid.uuidString.lowercased(), deviceId: 1)
        let certificate = try SenderCertificate(sender: sender, publicKey: aliceIdentity.publicKey, expiration: 31_337, signerCertificate: serverCertificate, signerKey: serverKey)
        XCTAssertTrue(try certificate.validate(trustRoot: trustRoot.publicKey, time: 31_336))
        XCTAssertFalse(try certificate.validate(trustRoot: trustRoot.publicKey, time: 31_338))
        XCTAssertEqual(try certificate.sender, sender)

        let signed = PrivateKey.generate()
        let kyber = KEMKeyPair.generate()
        try bob.storeSignedPreKey(SignedPreKeyRecord(id: 1, timestamp: 1, privateKey: signed, signature: bobIdentity.privateKey.generateSignature(message: signed.publicKey.serialize())), id: 1, context: NullContext())
        try bob.storeKyberPreKey(KyberPreKeyRecord(id: 1, timestamp: 1, keyPair: kyber, signature: bobIdentity.privateKey.generateSignature(message: kyber.publicKey.serialize())), id: 1, context: NullContext())
        let bundle = try PreKeyBundle(
            registrationId: bob.localRegistrationId(context: NullContext()), deviceId: 1,
            signedPrekeyId: 1, signedPrekey: signed.publicKey, signedPrekeySignature: bobIdentity.privateKey.generateSignature(message: signed.publicKey.serialize()),
            identity: bobIdentity.identityKey,
            kyberPrekeyId: 1, kyberPrekey: kyber.publicKey, kyberPrekeySignature: bobIdentity.privateKey.generateSignature(message: kyber.publicKey.serialize())
        )
        try processPreKeyBundle(bundle, for: bobAddress, sessionStore: alice, identityStore: alice, context: NullContext())

        let envelope = try sealedSenderEncrypt(message: Data("sealed".utf8), for: bobAddress, from: certificate, sessionStore: alice, identityStore: alice, context: NullContext())
        let opened = try sealedSenderDecrypt(message: envelope, from: SealedSenderAddress(e164: nil, uuidString: bobUuid.uuidString.lowercased(), deviceId: 1), trustRoot: trustRoot.publicKey, timestamp: 31_335, sessionStore: bob, identityStore: bob, preKeyStore: bob, signedPreKeyStore: bob, kyberPreKeyStore: bob, context: NullContext())
        XCTAssertEqual(opened.message, Data("sealed".utf8))
        XCTAssertEqual(opened.sender, sender)

        // Bob answers; the many-recipient form is split by the server into a received envelope.
        let reply = try sessionEncrypt(message: Data("reply".utf8), for: aliceAddress, sessionStore: bob, identityStore: bob, context: NullContext())
        XCTAssertEqual(reply.messageType, .whisper)
        let bobCertificate = try SenderCertificate(sender: SealedSenderAddress(e164: nil, uuidString: bobUuid.uuidString.lowercased(), deviceId: 1), publicKey: bobIdentity.publicKey, expiration: 31_337, signerCertificate: serverCertificate, signerKey: serverKey)
        let content = try UnidentifiedSenderMessageContent(reply, from: bobCertificate, contentHint: .resendable, groupId: Data([1, 2, 3]))
        let sent = try sealedSenderMultiRecipientEncrypt(content, for: [aliceAddress], identityStore: bob, sessionStore: bob, context: NullContext())
        let receivedEnvelope = try sealedSenderMultiRecipientMessageForSingleRecipient(sent)
        let addressed = try sealedSenderMultiRecipientMessage(sent, for: ServiceId(kind: .aci, uuid: aliceUuid), deviceId: 1)
        XCTAssertEqual(receivedEnvelope, addressed)
        let inner = try sealedSenderDecryptToUsmc(message: receivedEnvelope, identityStore: alice, context: NullContext())
        XCTAssertEqual(inner.contentHint, .resendable)
        XCTAssertEqual(inner.groupId, Data([1, 2, 3]))
        XCTAssertEqual(inner.messageType, .whisper)
        let plain = try sealedSenderDecrypt(message: receivedEnvelope, from: sender, trustRoot: trustRoot.publicKey, timestamp: 31_335, sessionStore: alice, identityStore: alice, preKeyStore: alice, signedPreKeyStore: alice, kyberPreKeyStore: alice, context: NullContext())
        XCTAssertEqual(plain.message, Data("reply".utf8))
        XCTAssertThrowsError(try sealedSenderDecrypt(message: receivedEnvelope, from: SealedSenderAddress(e164: nil, uuidString: bobUuid.uuidString.lowercased(), deviceId: 1), trustRoot: trustRoot.publicKey, timestamp: 31_335, sessionStore: bob, identityStore: bob, preKeyStore: bob, signedPreKeyStore: bob, kyberPreKeyStore: bob, context: NullContext()))
    }

    func testKeysRecordsAndHelpers() throws {
        let pair = IdentityKeyPair.generate()
        let round = try IdentityKeyPair(bytes: pair.serialize())
        XCTAssertEqual(round.publicKey, pair.publicKey)
        XCTAssertEqual(round.privateKey.serialize(), pair.privateKey.serialize())
        let signature = pair.privateKey.generateSignature(message: Data("m".utf8))
        XCTAssertTrue(try pair.publicKey.verifySignature(message: Data("m".utf8), signature: signature))
        XCTAssertFalse(try pair.publicKey.verifySignature(message: Data("x".utf8), signature: signature))
        XCTAssertThrowsError(try PublicKey(Data([0x05, 1, 2])))
        let other = IdentityKeyPair.generate()
        XCTAssertEqual(pair.privateKey.keyAgreement(with: other.publicKey), other.privateKey.keyAgreement(with: pair.publicKey))
        let alternate = pair.signAlternateIdentity(other.identityKey)
        XCTAssertTrue(try pair.identityKey.verifyAlternateIdentity(other.identityKey, signature: alternate))

        let kem = KEMKeyPair.generate()
        let (secret, ciphertext) = try KEM.encapsulate(kem.publicKey)
        XCTAssertEqual(try KEM.decapsulate(kem.secretKey, ciphertext: ciphertext), secret)
        XCTAssertEqual(try KEMPublicKey(kem.publicKey.serialize()), kem.publicKey)

        let record = try PreKeyRecord(id: 9, privateKey: pair.privateKey)
        XCTAssertEqual(try PreKeyRecord(bytes: record.serialize()).id, 9)
        XCTAssertEqual(try record.publicKey(), pair.publicKey)
        let signed = try SignedPreKeyRecord(id: 4, timestamp: 1234, privateKey: pair.privateKey, signature: signature)
        XCTAssertEqual(try SignedPreKeyRecord(bytes: signed.serialize()).timestamp, 1234)
        XCTAssertEqual(signed.signature, signature)
        let kyberRecord = try KyberPreKeyRecord(id: 5, timestamp: 99, keyPair: kem, signature: signature)
        XCTAssertEqual(try kyberRecord.keyPair().publicKey, kem.publicKey)

        let fingerprint = try NumericFingerprintGenerator(iterations: 5200).create(version: 2, localIdentifier: Data("alice".utf8), localKey: pair.publicKey, remoteIdentifier: Data("bob".utf8), remoteKey: other.publicKey)
        let theirs = try NumericFingerprintGenerator(iterations: 5200).create(version: 2, localIdentifier: Data("bob".utf8), localKey: other.publicKey, remoteIdentifier: Data("alice".utf8), remoteKey: pair.publicKey)
        XCTAssertEqual(fingerprint.displayable.formatted, theirs.displayable.formatted)
        XCTAssertEqual(fingerprint.displayable.formatted.count, 60)
        XCTAssertTrue(try fingerprint.scannable.compare(againstEncoding: theirs.scannable.encoding))

        let username = try Username("jimio.01")
        let proof = try username.generateProof()
        try Username.verify(proof: proof, forHash: username.hash)
        let link = try username.createLink()
        XCTAssertEqual(try Username(fromLink: link.encrypted, withRandomness: link.entropy), username)
        XCTAssertFalse(try Username.candidates(from: "jimio").isEmpty)
        XCTAssertThrowsError(try Username("1bad.01"))

        let pool = AccountEntropyPool.generate()
        XCTAssertTrue(AccountEntropyPool.isValid(pool))
        let backupKey = try AccountEntropyPool.deriveBackupKey(pool)
        let aci = Aci(fromUUID: UUID())
        XCTAssertEqual(backupKey.deriveBackupId(aci: aci).count, 16)
        XCTAssertEqual(backupKey.deriveEcKey(aci: aci).serialize().count, 32)
        let mediaId = backupKey.deriveMediaId(mediaName: "photo")
        XCTAssertEqual(try backupKey.deriveMediaEncryptionKey(mediaId: mediaId).count, 64)

        let params = try GroupSecretParams.generate()
        XCTAssertEqual(try GroupSecretParams.derive(from: params.masterKey).serialize(), params.serialize())
        XCTAssertEqual(params.groupIdentifier.count, 32)

        let key = randomBytes(32)
        let siv = try Aes256GcmSiv(key: key)
        let sealed = try siv.encrypt(Data("plain".utf8), nonce: randomBytes(12), associatedData: Data())
        XCTAssertNotEqual(sealed, Data("plain".utf8))
        XCTAssertEqual(try hkdf(outputLength: 42, inputKeyMaterial: key, info: Data("info".utf8)).count, 42)
        let macs = try IncrementalMac.calculate(key: key, chunkSize: 8, data: Data(repeating: 7, count: 20))
        try IncrementalMac.validate(key: key, chunkSize: 8, data: Data(repeating: 7, count: 20), digest: macs)
        XCTAssertThrowsError(try IncrementalMac.validate(key: key, chunkSize: 8, data: Data(repeating: 8, count: 20), digest: macs))

        let report = try DecryptionErrorMessage(originalMessageBytes: Data([1, 2, 3]), type: .senderKey, timestamp: 5, originalSenderDeviceId: 2)
        XCTAssertNil(report.ratchetKey)
        XCTAssertThrowsError(try DecryptionErrorMessage(originalMessageBytes: Data([1, 2, 3]), type: .whisper, timestamp: 5, originalSenderDeviceId: 2))
        XCTAssertEqual(report.timestamp, 5)
        let content = PlaintextContent(report)
        XCTAssertEqual(try DecryptionErrorMessage.extractFromSerializedContent(content.body).deviceId, 2)

        let serviceId = try ServiceId.parseFrom(serviceIdString: "PNI:" + UUID().uuidString.lowercased())
        XCTAssertEqual(serviceId.kind, .pni)
        XCTAssertEqual(try ServiceId.parseFrom(serviceIdFixedWidthBinary: serviceId.serviceIdFixedWidthBinary), serviceId)
        XCTAssertEqual(try ServiceId.parseFrom(serviceIdBinary: serviceId.serviceIdBinary), serviceId)
        XCTAssertThrowsError(try ProtocolAddress(name: "x", deviceId: 0))
        XCTAssertEqual(Gossveil.abiVersion, 1)
    }

    /// The names the client called before the rename still resolve and behave the same.
    func testCompatibilityNames() throws {
        let alice = InMemorySignalProtocolStore()
        let bob = InMemorySignalProtocolStore()
        let bobAddress = try ProtocolAddress(name: "bob", deviceId: 1)
        let aliceAddress = try ProtocolAddress(name: "alice", deviceId: 1)
        let bobIdentity = try bob.identityKeyPair(context: NullContext())
        let signed = PrivateKey.generate()
        let kyber = KEMKeyPair.generate()
        try bob.storeSignedPreKey(SignedPreKeyRecord(id: 1, timestamp: 1, privateKey: signed, signature: bobIdentity.privateKey.generateSignature(message: signed.publicKey.serialize())), id: 1, context: NullContext())
        try bob.storeKyberPreKey(KyberPreKeyRecord(id: 1, timestamp: 1, keyPair: kyber, signature: bobIdentity.privateKey.generateSignature(message: kyber.publicKey.serialize())), id: 1, context: NullContext())
        let bundle = try PreKeyBundle(
            registrationId: bob.localRegistrationId(context: NullContext()), deviceId: 1,
            signedPrekeyId: 1, signedPrekey: signed.publicKey, signedPrekeySignature: bobIdentity.privateKey.generateSignature(message: signed.publicKey.serialize()),
            identity: bobIdentity.identityKey,
            kyberPrekeyId: 1, kyberPrekey: kyber.publicKey, kyberPrekeySignature: bobIdentity.privateKey.generateSignature(message: kyber.publicKey.serialize())
        )
        try processPreKeyBundle(bundle, for: bobAddress, sessionStore: alice, identityStore: alice, context: NullContext())
        let first = try signalEncrypt(message: Data("hi".utf8), for: bobAddress, sessionStore: alice, identityStore: alice, context: NullContext())
        XCTAssertEqual(try signalDecryptPreKey(message: PreKeySignalMessage(bytes: first.serialize()), from: aliceAddress, sessionStore: bob, identityStore: bob, preKeyStore: bob, signedPreKeyStore: bob, kyberPreKeyStore: bob, context: NullContext()), Data("hi".utf8))
        let reply = try signalEncrypt(message: Data("yo".utf8), for: aliceAddress, sessionStore: bob, identityStore: bob, context: NullContext())
        XCTAssertEqual(try signalDecrypt(message: SignalMessage(bytes: reply.serialize()), from: bobAddress, sessionStore: alice, identityStore: alice, context: NullContext()), Data("yo".utf8))
        XCTAssertThrowsError(try signalDecrypt(message: SignalMessage(bytes: reply.serialize()), from: bobAddress, sessionStore: alice, identityStore: alice, context: NullContext())) { error in
            guard case SignalError.duplicatedMessage = error else { return XCTFail("\(error)") }
        }
        XCTAssertEqual(LibSignal.abiVersion, 1)
    }
}

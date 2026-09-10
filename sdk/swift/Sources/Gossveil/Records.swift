import Foundation
import GossveilKit

public final class PreKeyRecord: Sendable {
    let bytes: [UInt8]
    public let id: UInt32
    let publicKeyBytes: [UInt8]
    let privateKeyBytes: [UInt8]

    public init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        let raw = Core.octets(bytes)
        var id: UInt32 = 0
        var publicCell = Core.cell()
        var secretCell = Core.cell()
        try Core.check(gv_one_time_parse(raw, raw.count, &id, &publicCell, &secretCell))
        self.bytes = raw
        self.id = id
        publicKeyBytes = Core.take(&publicCell).octets
        privateKeyBytes = Core.take(&secretCell).octets
    }

    public convenience init(id: UInt32, publicKey: PublicKey, privateKey: PrivateKey) throws {
        try self.init(id: id, privateKey: privateKey)
    }

    public convenience init(id: UInt32, privateKey: PrivateKey) throws {
        var out = Core.cell()
        try Core.check(gv_one_time_record(id, privateKey.bytes, privateKey.bytes.count, &out))
        try self.init(bytes: Core.take(&out))
    }

    public func serialize() -> Data { Data(bytes) }
    public func publicKey() throws -> PublicKey { PublicKey(unchecked: publicKeyBytes) }
    public func privateKey() throws -> PrivateKey { PrivateKey(unchecked: privateKeyBytes) }
}

public final class SignedPreKeyRecord: Sendable {
    let bytes: [UInt8]
    public let id: UInt32
    public let timestamp: UInt64
    public let signature: Data
    let publicKeyBytes: [UInt8]
    let privateKeyBytes: [UInt8]

    public init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        let raw = Core.octets(bytes)
        var id: UInt32 = 0
        var stamp: UInt64 = 0
        var publicCell = Core.cell()
        var secretCell = Core.cell()
        var signatureCell = Core.cell()
        try Core.check(gv_signed_parse(raw, raw.count, &id, &stamp, &publicCell, &secretCell, &signatureCell))
        self.bytes = raw
        self.id = id
        timestamp = stamp
        publicKeyBytes = Core.take(&publicCell).octets
        privateKeyBytes = Core.take(&secretCell).octets
        signature = Core.take(&signatureCell)
    }

    public convenience init<Bytes: ContiguousBytes>(id: UInt32, timestamp: UInt64, privateKey: PrivateKey, signature: Bytes) throws {
        let s = Core.octets(signature)
        var out = Core.cell()
        try Core.check(gv_signed_record(id, timestamp, privateKey.bytes, privateKey.bytes.count, s, s.count, &out))
        try self.init(bytes: Core.take(&out))
    }

    public func serialize() -> Data { Data(bytes) }
    public func publicKey() throws -> PublicKey { PublicKey(unchecked: publicKeyBytes) }
    public func privateKey() throws -> PrivateKey { PrivateKey(unchecked: privateKeyBytes) }
}

public final class KyberPreKeyRecord: Sendable {
    let bytes: [UInt8]
    public let id: UInt32
    public let timestamp: UInt64
    public let signature: Data
    let publicKeyBytes: [UInt8]
    let secretKeyBytes: [UInt8]

    public init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        let raw = Core.octets(bytes)
        var id: UInt32 = 0
        var stamp: UInt64 = 0
        var publicCell = Core.cell()
        var secretCell = Core.cell()
        var signatureCell = Core.cell()
        try Core.check(gv_pq_record_parse(raw, raw.count, &id, &stamp, &publicCell, &secretCell, &signatureCell))
        self.bytes = raw
        self.id = id
        timestamp = stamp
        publicKeyBytes = Core.take(&publicCell).octets
        secretKeyBytes = Core.take(&secretCell).octets
        signature = Core.take(&signatureCell)
    }

    public convenience init<Bytes: ContiguousBytes>(id: UInt32, timestamp: UInt64, keyPair: KEMKeyPair, signature: Bytes) throws {
        let s = Core.octets(signature)
        var out = Core.cell()
        try Core.check(gv_pq_record(id, timestamp, keyPair.publicKey.bytes, keyPair.publicKey.bytes.count, keyPair.secretKey.bytes, keyPair.secretKey.bytes.count, s, s.count, &out))
        try self.init(bytes: Core.take(&out))
    }

    public func serialize() -> Data { Data(bytes) }
    public func keyPair() throws -> KEMKeyPair { KEMKeyPair(publicKey: KEMPublicKey(unchecked: publicKeyBytes), secretKey: KEMSecretKey(unchecked: secretKeyBytes)) }
    public func publicKey() throws -> KEMPublicKey { KEMPublicKey(unchecked: publicKeyBytes) }
    public func secretKey() throws -> KEMSecretKey { KEMSecretKey(unchecked: secretKeyBytes) }
}

/// A session with one device, as the bytes the store persists. Every
/// protocol operation returns a fresh record; this one never mutates.
public final class SessionRecord: Sendable {
    let bytes: [UInt8]

    public init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        let raw = Core.octets(bytes)
        var info = GvSessionInfo()
        try Core.check(gv_session_info(raw, raw.count, 0, &info))
        self.bytes = raw
    }

    init(unchecked bytes: [UInt8]) {
        self.bytes = bytes
    }

    public func serialize() -> Data { Data(bytes) }

    private func info(now: Date = Date()) -> GvSessionInfo {
        var info = GvSessionInfo()
        _ = gv_session_info(bytes, bytes.count, UInt64(max(0, now.timeIntervalSince1970)), &info)
        return info
    }

    private func live() throws -> GvSessionInfo {
        let i = info()
        guard i.has_live == 1 else { throw GossveilError.invalidState("no current session") }
        return i
    }

    public func hasCurrentState(now: Date = Date()) -> Bool {
        info(now: now).usable == 1
    }

    public var hasCurrentSession: Bool {
        info().has_live == 1
    }

    public func archiveCurrentState() throws -> SessionRecord {
        var out = Core.cell()
        try Core.check(gv_session_shelve(bytes, bytes.count, &out))
        return SessionRecord(unchecked: Core.take(&out).octets)
    }

    public func remoteRegistrationId() throws -> UInt32 {
        try live().remote_registration_id
    }

    public func localRegistrationId() throws -> UInt32 {
        try live().local_registration_id
    }

    public func sessionVersion() throws -> UInt32 {
        try live().version
    }

    public func remoteIdentityKey() throws -> IdentityKey {
        IdentityKey(publicKey: PublicKey(unchecked: Core.fixed(try live().remote_identity)))
    }

    public func currentRatchetKeyMatches(_ key: PublicKey) throws -> Bool {
        var ok: UInt8 = 0
        try Core.check(gv_session_ratchet_is(bytes, bytes.count, key.bytes, key.bytes.count, &ok))
        return ok == 1
    }
}

public final class PreKeyBundle: Sendable {
    public let registrationId: UInt32
    public let deviceId: UInt32
    public let preKeyId: UInt32?
    public let preKeyPublic: PublicKey?
    public let signedPreKeyId: UInt32
    public let signedPreKeyPublic: PublicKey
    public let signedPreKeySignature: Data
    public let identityKey: IdentityKey
    public let kyberPreKeyId: UInt32
    public let kyberPreKeyPublic: KEMPublicKey
    public let kyberPreKeySignature: Data

    public convenience init<ECBytes: ContiguousBytes, KEMBytes: ContiguousBytes>(
        registrationId: UInt32,
        deviceId: UInt32,
        prekeyId: UInt32,
        prekey: PublicKey,
        signedPrekeyId: UInt32,
        signedPrekey: PublicKey,
        signedPrekeySignature: ECBytes,
        identity identityKey: IdentityKey,
        kyberPrekeyId: UInt32,
        kyberPrekey: KEMPublicKey,
        kyberPrekeySignature: KEMBytes
    ) throws {
        try self.init(registrationId: registrationId, deviceId: deviceId, preKeyId: prekeyId, preKey: prekey, signedPrekeyId: signedPrekeyId, signedPrekey: signedPrekey, signedPrekeySignature: Data(Core.octets(signedPrekeySignature)), identity: identityKey, kyberPrekeyId: kyberPrekeyId, kyberPrekey: kyberPrekey, kyberPrekeySignature: Data(Core.octets(kyberPrekeySignature)))
    }

    public convenience init<ECBytes: ContiguousBytes, KEMBytes: ContiguousBytes>(
        registrationId: UInt32,
        deviceId: UInt32,
        signedPrekeyId: UInt32,
        signedPrekey: PublicKey,
        signedPrekeySignature: ECBytes,
        identity identityKey: IdentityKey,
        kyberPrekeyId: UInt32,
        kyberPrekey: KEMPublicKey,
        kyberPrekeySignature: KEMBytes
    ) throws {
        try self.init(registrationId: registrationId, deviceId: deviceId, preKeyId: nil, preKey: nil, signedPrekeyId: signedPrekeyId, signedPrekey: signedPrekey, signedPrekeySignature: Data(Core.octets(signedPrekeySignature)), identity: identityKey, kyberPrekeyId: kyberPrekeyId, kyberPrekey: kyberPrekey, kyberPrekeySignature: Data(Core.octets(kyberPrekeySignature)))
    }

    init(registrationId: UInt32, deviceId: UInt32, preKeyId: UInt32?, preKey: PublicKey?, signedPrekeyId: UInt32, signedPrekey: PublicKey, signedPrekeySignature: Data, identity: IdentityKey, kyberPrekeyId: UInt32, kyberPrekey: KEMPublicKey, kyberPrekeySignature: Data) throws {
        guard signedPrekeySignature.count == 64, kyberPrekeySignature.count == 64 else { throw GossveilError.invalidSignature("signatures must be 64 bytes") }
        self.registrationId = registrationId
        self.deviceId = deviceId
        self.preKeyId = preKeyId
        preKeyPublic = preKey
        signedPreKeyId = signedPrekeyId
        signedPreKeyPublic = signedPrekey
        self.signedPreKeySignature = signedPrekeySignature
        identityKey = identity
        kyberPreKeyId = kyberPrekeyId
        kyberPreKeyPublic = kyberPrekey
        self.kyberPreKeySignature = kyberPrekeySignature
    }
}

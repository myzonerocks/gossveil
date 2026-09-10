import Foundation
import GossveilKit

public final class PublicKey: Sendable, Hashable {
    let bytes: [UInt8]

    public init<Bytes: ContiguousBytes>(_ bytes: Bytes) throws {
        let raw = Core.octets(bytes)
        try Core.check(gv_curve_check(raw, raw.count))
        self.bytes = raw
    }

    init(unchecked bytes: [UInt8]) {
        self.bytes = bytes
    }

    public func serialize() -> Data {
        Data(bytes)
    }

    public var keyBytes: Data {
        Data(bytes.dropFirst())
    }

    public func verifySignature<MessageBytes: ContiguousBytes, SignatureBytes: ContiguousBytes>(message: MessageBytes, signature: SignatureBytes) throws -> Bool {
        let m = Core.octets(message)
        let s = Core.octets(signature)
        var ok: UInt8 = 0
        try Core.check(gv_curve_verify(bytes, bytes.count, m, m.count, s, s.count, &ok))
        return ok == 1
    }

    public static func == (lhs: PublicKey, rhs: PublicKey) -> Bool {
        lhs.bytes == rhs.bytes
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(bytes)
    }
}

public final class PrivateKey: Sendable {
    let bytes: [UInt8]

    public init<Bytes: ContiguousBytes>(_ bytes: Bytes) throws {
        let raw = Core.octets(bytes)
        guard raw.count == 32 else { throw GossveilError.invalidKey("private key must be 32 bytes") }
        self.bytes = raw
    }

    init(unchecked bytes: [UInt8]) {
        self.bytes = bytes
    }

    public static func generate() -> PrivateKey {
        var secret = Core.cell()
        var publicKey = Core.cell()
        _ = gv_curve_pair(&secret, &publicKey)
        _ = Core.take(&publicKey)
        return PrivateKey(unchecked: Core.take(&secret).octets)
    }

    public func serialize() -> Data {
        Data(bytes)
    }

    public var publicKey: PublicKey {
        var out = Core.cell()
        _ = gv_curve_public(bytes, bytes.count, &out)
        return PublicKey(unchecked: Core.take(&out).octets)
    }

    public func generateSignature<Bytes: ContiguousBytes>(message: Bytes) -> Data {
        let m = Core.octets(message)
        var out = Core.cell()
        _ = gv_curve_sign(bytes, bytes.count, m, m.count, &out)
        return Core.take(&out)
    }

    public func keyAgreement(with other: PublicKey) -> Data {
        var out = Core.cell()
        _ = gv_curve_agree(bytes, bytes.count, other.bytes, other.bytes.count, &out)
        return Core.take(&out)
    }
}

public struct IdentityKey: Equatable, Sendable {
    public let publicKey: PublicKey

    public init(publicKey: PublicKey) {
        self.publicKey = publicKey
    }

    public init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        publicKey = try PublicKey(bytes)
    }

    public func serialize() -> Data {
        publicKey.serialize()
    }

    public func verifyAlternateIdentity<Bytes: ContiguousBytes>(_ other: IdentityKey, signature: Bytes) throws -> Bool {
        let s = Core.octets(signature)
        var ok: UInt8 = 0
        try Core.check(gv_identity_vouched(publicKey.bytes, publicKey.bytes.count, other.publicKey.bytes, other.publicKey.bytes.count, s, s.count, &ok))
        return ok == 1
    }
}

public struct IdentityKeyPair: Sendable {
    public let publicKey: PublicKey
    public let privateKey: PrivateKey

    public init(publicKey: PublicKey, privateKey: PrivateKey) {
        self.publicKey = publicKey
        self.privateKey = privateKey
    }

    public init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        let raw = Core.octets(bytes)
        var publicCell = Core.cell()
        var secretCell = Core.cell()
        try Core.check(gv_identity_parse(raw, raw.count, &publicCell, &secretCell))
        publicKey = PublicKey(unchecked: Core.take(&publicCell).octets)
        privateKey = PrivateKey(unchecked: Core.take(&secretCell).octets)
    }

    public static func generate() -> IdentityKeyPair {
        let privateKey = PrivateKey.generate()
        return IdentityKeyPair(publicKey: privateKey.publicKey, privateKey: privateKey)
    }

    public var identityKey: IdentityKey {
        IdentityKey(publicKey: publicKey)
    }

    public func serialize() -> Data {
        var out = Core.cell()
        _ = gv_identity_serialize(privateKey.bytes, privateKey.bytes.count, &out)
        return Core.take(&out)
    }

    public func signAlternateIdentity(_ other: IdentityKey) -> Data {
        var out = Core.cell()
        _ = gv_identity_vouch(privateKey.bytes, privateKey.bytes.count, other.publicKey.bytes, other.publicKey.bytes.count, &out)
        return Core.take(&out)
    }
}

enum PqLayout {
    static let publicLength = 1569
    static let secretLength = 3169

    static func tagged(_ raw: [UInt8], length: Int) -> Bool {
        raw.count == length && (raw.first == UInt8(GV_PQ_ROUND_THREE) || raw.first == UInt8(GV_PQ_STANDARD))
    }
}

public final class KEMPublicKey: Sendable, Hashable {
    let bytes: [UInt8]

    public init<Bytes: ContiguousBytes>(_ bytes: Bytes) throws {
        let raw = Core.octets(bytes)
        guard PqLayout.tagged(raw, length: PqLayout.publicLength) else { throw GossveilError.invalidKey("unrecognized key encapsulation key") }
        self.bytes = raw
    }

    init(unchecked bytes: [UInt8]) {
        self.bytes = bytes
    }

    public func serialize() -> Data {
        Data(bytes)
    }

    public static func == (lhs: KEMPublicKey, rhs: KEMPublicKey) -> Bool {
        lhs.bytes == rhs.bytes
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(bytes)
    }
}

public final class KEMSecretKey: Sendable {
    let bytes: [UInt8]

    public init<Bytes: ContiguousBytes>(_ bytes: Bytes) throws {
        let raw = Core.octets(bytes)
        guard PqLayout.tagged(raw, length: PqLayout.secretLength) else { throw GossveilError.invalidKey("unrecognized key encapsulation secret") }
        self.bytes = raw
    }

    init(unchecked bytes: [UInt8]) {
        self.bytes = bytes
    }

    public func serialize() -> Data {
        Data(bytes)
    }
}

public final class KEMKeyPair: Sendable {
    public let publicKey: KEMPublicKey
    public let secretKey: KEMSecretKey

    public init(publicKey: KEMPublicKey, secretKey: KEMSecretKey) {
        self.publicKey = publicKey
        self.secretKey = secretKey
    }

    public static func generate() -> KEMKeyPair {
        var publicCell = Core.cell()
        var secretCell = Core.cell()
        _ = gv_pq_pair(UInt8(GV_PQ_ROUND_THREE), &publicCell, &secretCell)
        return KEMKeyPair(publicKey: KEMPublicKey(unchecked: Core.take(&publicCell).octets), secretKey: KEMSecretKey(unchecked: Core.take(&secretCell).octets))
    }
}

public enum KEM {
    /// Encapsulates to a public key: the shared secret and the capsule that
    /// yields it for the secret key holder.
    public static func encapsulate(_ publicKey: KEMPublicKey) throws -> (sharedSecret: Data, ciphertext: Data) {
        var capsule = Core.cell()
        var shared = Core.cell()
        try Core.check(gv_pq_encapsulate(publicKey.bytes, publicKey.bytes.count, &capsule, &shared))
        return (Core.take(&shared), Core.take(&capsule))
    }

    public static func decapsulate<Bytes: ContiguousBytes>(_ secretKey: KEMSecretKey, ciphertext: Bytes) throws -> Data {
        let capsule = Core.octets(ciphertext)
        var shared = Core.cell()
        try Core.check(gv_pq_open(secretKey.bytes, secretKey.bytes.count, capsule, capsule.count, &shared))
        return Core.take(&shared)
    }
}

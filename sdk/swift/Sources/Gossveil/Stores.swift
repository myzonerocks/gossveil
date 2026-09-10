import Foundation

public protocol StoreContext {}

public struct NullContext: StoreContext, Sendable {
    public init() {}
}

public enum Direction: Sendable {
    case sending
    case receiving
}

public enum IdentityChange: Sendable {
    case newOrUnchanged
    case replacedExisting
}

public protocol IdentityKeyStore: AnyObject {
    func identityKeyPair(context: StoreContext) throws -> IdentityKeyPair
    func localRegistrationId(context: StoreContext) throws -> UInt32
    func saveIdentity(_ identity: IdentityKey, for address: ProtocolAddress, context: StoreContext) throws -> IdentityChange
    func isTrustedIdentity(_ identity: IdentityKey, for address: ProtocolAddress, direction: Direction, context: StoreContext) throws -> Bool
    func identity(for address: ProtocolAddress, context: StoreContext) throws -> IdentityKey?
}

public protocol PreKeyStore: AnyObject {
    func loadPreKey(id: UInt32, context: StoreContext) throws -> PreKeyRecord
    func storePreKey(_ record: PreKeyRecord, id: UInt32, context: StoreContext) throws
    func removePreKey(id: UInt32, context: StoreContext) throws
}

public protocol SignedPreKeyStore: AnyObject {
    func loadSignedPreKey(id: UInt32, context: StoreContext) throws -> SignedPreKeyRecord
    func storeSignedPreKey(_ record: SignedPreKeyRecord, id: UInt32, context: StoreContext) throws
}

public protocol KyberPreKeyStore: AnyObject {
    func loadKyberPreKey(id: UInt32, context: StoreContext) throws -> KyberPreKeyRecord
    func storeKyberPreKey(_ record: KyberPreKeyRecord, id: UInt32, context: StoreContext) throws
    func markKyberPreKeyUsed(id: UInt32, signedPreKeyId: UInt32, baseKey: PublicKey, context: StoreContext) throws
}

public protocol SessionStore: AnyObject {
    func loadSession(for address: ProtocolAddress, context: StoreContext) throws -> SessionRecord?
    func loadExistingSessions(for addresses: [ProtocolAddress], context: StoreContext) throws -> [SessionRecord]
    func storeSession(_ record: SessionRecord, for address: ProtocolAddress, context: StoreContext) throws
}

public protocol SenderKeyStore: AnyObject {
    func storeSenderKey(from sender: ProtocolAddress, distributionId: UUID, record: SenderKeyRecord, context: StoreContext) throws
    func loadSenderKey(from sender: ProtocolAddress, distributionId: UUID, context: StoreContext) throws -> SenderKeyRecord?
}

/// Every store in one object, held in memory. Trust is on first use: an
/// unseen peer is trusted, a changed key is not.
public final class InMemoryProtocolStore: IdentityKeyStore, PreKeyStore, SignedPreKeyStore, KyberPreKeyStore, SessionStore, SenderKeyStore {
    private struct SenderKeyName: Hashable {
        let sender: ProtocolAddress
        let distributionId: UUID
    }

    private let identity: IdentityKeyPair
    private let registrationId: UInt32
    private var identities: [ProtocolAddress: IdentityKey] = [:]
    private var preKeys: [UInt32: PreKeyRecord] = [:]
    private var signedPreKeys: [UInt32: SignedPreKeyRecord] = [:]
    private var kyberPreKeys: [UInt32: KyberPreKeyRecord] = [:]
    private var kyberUsed: Set<UInt32> = []
    private var sessions: [ProtocolAddress: SessionRecord] = [:]
    private var senderKeys: [SenderKeyName: SenderKeyRecord] = [:]

    public init() {
        identity = IdentityKeyPair.generate()
        registrationId = UInt32.random(in: 1 ... 0x3FFF)
    }

    public init(identity: IdentityKeyPair, registrationId: UInt32) {
        self.identity = identity
        self.registrationId = registrationId
    }

    public func identityKeyPair(context _: StoreContext) throws -> IdentityKeyPair {
        identity
    }

    public func localRegistrationId(context _: StoreContext) throws -> UInt32 {
        registrationId
    }

    public func saveIdentity(_ identity: IdentityKey, for address: ProtocolAddress, context _: StoreContext) throws -> IdentityChange {
        let previous = identities.updateValue(identity, forKey: address)
        if let previous, previous != identity { return .replacedExisting }
        return .newOrUnchanged
    }

    public func isTrustedIdentity(_ identity: IdentityKey, for address: ProtocolAddress, direction _: Direction, context _: StoreContext) throws -> Bool {
        guard let known = identities[address] else { return true }
        return known == identity
    }

    public func identity(for address: ProtocolAddress, context _: StoreContext) throws -> IdentityKey? {
        identities[address]
    }

    public func loadPreKey(id: UInt32, context _: StoreContext) throws -> PreKeyRecord {
        guard let record = preKeys[id] else { throw GossveilError.invalidKeyIdentifier("no prekey with this identifier") }
        return record
    }

    public func storePreKey(_ record: PreKeyRecord, id: UInt32, context _: StoreContext) throws {
        preKeys[id] = record
    }

    public func removePreKey(id: UInt32, context _: StoreContext) throws {
        preKeys.removeValue(forKey: id)
    }

    public func loadSignedPreKey(id: UInt32, context _: StoreContext) throws -> SignedPreKeyRecord {
        guard let record = signedPreKeys[id] else { throw GossveilError.invalidKeyIdentifier("no signed prekey with this identifier") }
        return record
    }

    public func storeSignedPreKey(_ record: SignedPreKeyRecord, id: UInt32, context _: StoreContext) throws {
        signedPreKeys[id] = record
    }

    public func loadKyberPreKey(id: UInt32, context _: StoreContext) throws -> KyberPreKeyRecord {
        guard let record = kyberPreKeys[id] else { throw GossveilError.invalidKeyIdentifier("no kyber prekey with this identifier") }
        return record
    }

    public func storeKyberPreKey(_ record: KyberPreKeyRecord, id: UInt32, context _: StoreContext) throws {
        kyberPreKeys[id] = record
    }

    public func markKyberPreKeyUsed(id: UInt32, signedPreKeyId _: UInt32, baseKey _: PublicKey, context _: StoreContext) throws {
        kyberUsed.insert(id)
    }

    public func hasKyberPreKeyBeenUsed(id: UInt32) -> Bool {
        kyberUsed.contains(id)
    }

    public func loadSession(for address: ProtocolAddress, context _: StoreContext) throws -> SessionRecord? {
        sessions[address]
    }

    public func loadExistingSessions(for addresses: [ProtocolAddress], context _: StoreContext) throws -> [SessionRecord] {
        try addresses.map { address in
            guard let session = sessions[address] else { throw GossveilError.sessionNotFound("no session for \(address)") }
            return session
        }
    }

    public func storeSession(_ record: SessionRecord, for address: ProtocolAddress, context _: StoreContext) throws {
        sessions[address] = record
    }

    public func storeSenderKey(from sender: ProtocolAddress, distributionId: UUID, record: SenderKeyRecord, context _: StoreContext) throws {
        senderKeys[SenderKeyName(sender: sender, distributionId: distributionId)] = record
    }

    public func loadSenderKey(from sender: ProtocolAddress, distributionId: UUID, context _: StoreContext) throws -> SenderKeyRecord? {
        senderKeys[SenderKeyName(sender: sender, distributionId: distributionId)]
    }
}

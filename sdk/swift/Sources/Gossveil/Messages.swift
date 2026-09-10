import Foundation
import GossveilKit

public final class CiphertextMessage: Sendable {
    public struct MessageType: RawRepresentable, Hashable, Sendable {
        public let rawValue: UInt8

        public init(rawValue: UInt8) {
            self.rawValue = rawValue
        }

        public static let whisper = MessageType(rawValue: UInt8(GV_KIND_WHISPER))
        public static let preKey = MessageType(rawValue: UInt8(GV_KIND_FIRST))
        public static let senderKey = MessageType(rawValue: UInt8(GV_KIND_CIRCLE))
        public static let plaintext = MessageType(rawValue: UInt8(GV_KIND_PLAIN))
    }

    public let messageType: MessageType
    let bytes: [UInt8]

    init(type: MessageType, bytes: [UInt8]) {
        messageType = type
        self.bytes = bytes
    }

    public convenience init(_ message: WhisperMessage) {
        self.init(type: .whisper, bytes: message.bytes)
    }

    public convenience init(_ message: PreKeyMessage) {
        self.init(type: .preKey, bytes: message.bytes)
    }

    public convenience init(_ message: SenderKeyMessage) {
        self.init(type: .senderKey, bytes: message.bytes)
    }

    public convenience init(_ content: PlaintextContent) {
        self.init(type: .plaintext, bytes: content.bytes)
    }

    public func serialize() -> Data {
        Data(bytes)
    }
}

/// A ratchet message: the sender's current ratchet key, its place in the
/// chain and the sealed body.
public final class WhisperMessage: Sendable {
    let bytes: [UInt8]
    public let messageVersion: UInt32
    public let counter: UInt32
    public let previousCounter: UInt32
    public let senderRatchetKey: PublicKey
    public let body: Data

    public init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        let raw = Core.octets(bytes)
        var info = GvWhisperInfo()
        var bodyCell = Core.cell()
        try Core.check(gv_whisper_parse(raw, raw.count, &info, &bodyCell))
        self.bytes = raw
        messageVersion = UInt32(info.version)
        counter = info.index
        previousCounter = info.previous_index
        senderRatchetKey = PublicKey(unchecked: Core.fixed(info.ratchet))
        body = Core.take(&bodyCell)
    }

    public func serialize() -> Data {
        Data(bytes)
    }
}

/// The first message of a session: the handshake material around a whisper.
public final class PreKeyMessage: Sendable {
    let bytes: [UInt8]
    public let version: UInt32
    public let registrationId: UInt32
    public let preKeyId: UInt32?
    public let signedPreKeyId: UInt32
    public let kyberPreKeyId: UInt32?
    public let baseKey: PublicKey
    public let identityKey: IdentityKey
    public let whisperMessage: WhisperMessage

    public init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        let raw = Core.octets(bytes)
        var info = GvOpenerInfo()
        var inner = Core.cell()
        try Core.check(gv_opener_parse(raw, raw.count, &info, &inner))
        self.bytes = raw
        version = UInt32(info.version)
        registrationId = info.registration_id
        preKeyId = info.one_time_id < 0 ? nil : UInt32(info.one_time_id)
        signedPreKeyId = info.signed_id
        kyberPreKeyId = info.pq_id < 0 ? nil : UInt32(info.pq_id)
        baseKey = PublicKey(unchecked: Core.fixed(info.base))
        identityKey = IdentityKey(publicKey: PublicKey(unchecked: Core.fixed(info.identity)))
        whisperMessage = try WhisperMessage(bytes: Core.take(&inner))
    }

    public var signalMessage: WhisperMessage { whisperMessage }

    public func serialize() -> Data {
        Data(bytes)
    }
}

public final class SenderKeyMessage: Sendable {
    let bytes: [UInt8]
    public let messageVersion: UInt32
    public let distributionId: UUID
    public let chainId: UInt32
    public let iteration: UInt32
    public let ciphertext: Data

    public init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        let raw = Core.octets(bytes)
        var info = GvNoteInfo()
        var bodyCell = Core.cell()
        try Core.check(gv_note_parse(raw, raw.count, &info, &bodyCell))
        self.bytes = raw
        messageVersion = UInt32(info.version)
        distributionId = UUID(bytes: Core.fixed(info.circle_id))
        chainId = info.chain_id
        iteration = info.step
        ciphertext = Core.take(&bodyCell)
    }

    public func serialize() -> Data {
        Data(bytes)
    }
}

public final class SenderKeyDistributionMessage: Sendable {
    let bytes: [UInt8]
    public let messageVersion: UInt32
    public let distributionId: UUID
    public let chainId: UInt32
    public let iteration: UInt32
    public let chainKey: Data
    public let signatureKey: PublicKey

    public init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        let raw = Core.octets(bytes)
        var info = GvAnnounceInfo()
        try Core.check(gv_announce_parse(raw, raw.count, &info))
        self.bytes = raw
        messageVersion = UInt32(info.version)
        distributionId = UUID(bytes: Core.fixed(info.circle_id))
        chainId = info.chain_id
        iteration = info.step
        chainKey = Data(Core.fixed(info.seed))
        signatureKey = PublicKey(unchecked: Core.fixed(info.signing))
    }

    /// Starts a sender key for `distributionId` in `store` and returns the
    /// message the rest of the group needs.
    public convenience init(from sender: ProtocolAddress, distributionId: UUID, store: SenderKeyStore, context: StoreContext) throws {
        let existing = try store.loadSenderKey(from: sender, distributionId: distributionId, context: context)?.bytes ?? []
        let id = distributionId.data.octets
        var record = Core.cell()
        var announce = Core.cell()
        try Core.check(gv_circle_announce(existing, existing.count, id, id.count, &record, &announce))
        try store.storeSenderKey(from: sender, distributionId: distributionId, record: SenderKeyRecord(unchecked: Core.take(&record).octets), context: context)
        try self.init(bytes: Core.take(&announce))
    }

    public func serialize() -> Data {
        Data(bytes)
    }
}

public final class SenderKeyRecord: Sendable {
    let bytes: [UInt8]

    public init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        self.bytes = Core.octets(bytes)
    }

    init(unchecked bytes: [UInt8]) {
        self.bytes = bytes
    }

    public func serialize() -> Data {
        Data(bytes)
    }
}

public final class PlaintextContent: Sendable {
    let bytes: [UInt8]
    public let body: Data

    public init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        let raw = Core.octets(bytes)
        var bodyCell = Core.cell()
        try Core.check(gv_plain_body(raw, raw.count, &bodyCell))
        self.bytes = raw
        body = Core.take(&bodyCell)
    }

    public convenience init(_ message: DecryptionErrorMessage) {
        var out = Core.cell()
        _ = gv_plain_from_report(message.bytes, message.bytes.count, &out)
        try! self.init(bytes: Core.take(&out))
    }

    public func serialize() -> Data {
        Data(bytes)
    }
}

public final class DecryptionErrorMessage: Sendable {
    let bytes: [UInt8]
    public let timestamp: UInt64
    public let deviceId: UInt32
    public let ratchetKey: PublicKey?

    public init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        let raw = Core.octets(bytes)
        var info = GvReportInfo()
        try Core.check(gv_report_parse(raw, raw.count, &info))
        self.bytes = raw
        timestamp = info.stamp_ms
        deviceId = info.device
        ratchetKey = info.has_ratchet == 1 ? PublicKey(unchecked: Core.fixed(info.ratchet)) : nil
    }

    public convenience init<Bytes: ContiguousBytes>(originalMessageBytes: Bytes, type: CiphertextMessage.MessageType, timestamp: UInt64, originalSenderDeviceId: UInt32) throws {
        let original = Core.octets(originalMessageBytes)
        var out = Core.cell()
        try Core.check(gv_report(original, original.count, type.rawValue, timestamp, originalSenderDeviceId, &out))
        try self.init(bytes: Core.take(&out))
    }

    public static func extractFromSerializedContent<Bytes: ContiguousBytes>(_ content: Bytes) throws -> DecryptionErrorMessage {
        let raw = Core.octets(content)
        var out = Core.cell()
        try Core.check(gv_report_in_body(raw, raw.count, &out))
        return try DecryptionErrorMessage(bytes: Core.take(&out))
    }

    public func serialize() -> Data {
        Data(bytes)
    }
}

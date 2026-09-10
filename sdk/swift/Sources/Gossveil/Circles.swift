import Foundation
import GossveilKit

public func processSenderKeyDistributionMessage(_ message: SenderKeyDistributionMessage, from sender: ProtocolAddress, store: SenderKeyStore, context: StoreContext) throws {
    let existing = try store.loadSenderKey(from: sender, distributionId: message.distributionId, context: context)?.bytes ?? []
    var out = Core.cell()
    try Core.check(gv_circle_admit(existing, existing.count, message.bytes, message.bytes.count, &out))
    try store.storeSenderKey(from: sender, distributionId: message.distributionId, record: SenderKeyRecord(unchecked: Core.take(&out).octets), context: context)
}

public func groupEncrypt<Bytes: ContiguousBytes>(_ message: Bytes, from sender: ProtocolAddress, distributionId: UUID, store: SenderKeyStore, context: StoreContext) throws -> CiphertextMessage {
    guard let record = try store.loadSenderKey(from: sender, distributionId: distributionId, context: context) else {
        throw GossveilError.invalidSenderKeySession(distributionId: distributionId, message: "no sender key for \(sender)")
    }
    let plain = Core.octets(message)
    let id = distributionId.data.octets
    var note = Core.cell()
    var out = Core.cell()
    let status = gv_circle_seal(record.bytes, record.bytes.count, id, id.count, plain, plain.count, &note, &out)
    let updated = SenderKeyRecord(unchecked: Core.take(&out).octets)
    let bytes = Core.take(&note)
    try Core.check(status)
    try store.storeSenderKey(from: sender, distributionId: distributionId, record: updated, context: context)
    return CiphertextMessage(type: .senderKey, bytes: bytes.octets)
}

public func groupDecrypt<Bytes: ContiguousBytes>(_ message: Bytes, from sender: ProtocolAddress, store: SenderKeyStore, context: StoreContext) throws -> Data {
    let note = Core.octets(message)
    let parsed = try SenderKeyMessage(bytes: note)
    guard let record = try store.loadSenderKey(from: sender, distributionId: parsed.distributionId, context: context) else {
        throw GossveilError.invalidSenderKeySession(distributionId: parsed.distributionId, message: "no sender key for \(sender)")
    }
    var plain = Core.cell()
    var out = Core.cell()
    let status = gv_circle_open(record.bytes, record.bytes.count, note, note.count, &plain, &out)
    let updated = SenderKeyRecord(unchecked: Core.take(&out).octets)
    let body = Core.take(&plain)
    try Core.check(status)
    try store.storeSenderKey(from: sender, distributionId: parsed.distributionId, record: updated, context: context)
    return body
}

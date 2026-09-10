import Foundation
import GossveilKit

public enum UsePQRatchet: Sendable {
    case yes
    case no
}

func seconds(_ date: Date) -> UInt64 {
    UInt64(max(0, date.timeIntervalSince1970))
}

func untrusted(_ address: ProtocolAddress) -> GossveilError {
    .untrustedIdentity("untrusted identity for \(address)")
}

/// Starts a session with `address` from its published bundle. The bundle's
/// identity must pass the store's trust check for sending.
public func processPreKeyBundle(
    _ bundle: PreKeyBundle,
    for address: ProtocolAddress,
    ourAddress: ProtocolAddress? = nil,
    sessionStore: SessionStore,
    identityStore: IdentityKeyStore,
    now: Date = Date(),
    context: StoreContext,
    usePqRatchet _: UsePQRatchet = .no
) throws {
    _ = ourAddress
    guard try identityStore.isTrustedIdentity(bundle.identityKey, for: address, direction: .sending, context: context) else { throw untrusted(address) }
    let us = try identityStore.identityKeyPair(context: context)
    let registrationId = try identityStore.localRegistrationId(context: context)
    let existing = try sessionStore.loadSession(for: address, context: context)?.bytes ?? []
    let pinned: [[UInt8]] = [
        bundle.preKeyPublic?.bytes ?? [],
        bundle.signedPreKeyPublic.bytes,
        bundle.signedPreKeySignature.octets,
        bundle.identityKey.publicKey.bytes,
        bundle.kyberPreKeyPublic.bytes,
        bundle.kyberPreKeySignature.octets,
    ]
    var out = Core.cell()
    let status = try Core.pinned(pinned) { p in
        var published = GvPublished(
            registration_id: bundle.registrationId,
            device: bundle.deviceId,
            one_time_id: bundle.preKeyId.map { Int64($0) } ?? -1,
            one_time: p[0], one_time_len: pinned[0].count,
            signed_id: bundle.signedPreKeyId,
            signed_key: p[1], signed_len: pinned[1].count,
            signed_signature: p[2], signed_signature_len: pinned[2].count,
            identity: p[3], identity_len: pinned[3].count,
            pq_id: bundle.kyberPreKeyId,
            pq_key: p[4], pq_len: pinned[4].count,
            pq_signature: p[5], pq_signature_len: pinned[5].count
        )
        return gv_session_start(us.privateKey.bytes, us.privateKey.bytes.count, registrationId, existing, existing.count, &published, seconds(now), &out)
    }
    try Core.check(status)
    let record = SessionRecord(unchecked: Core.take(&out).octets)
    _ = try identityStore.saveIdentity(bundle.identityKey, for: address, context: context)
    try sessionStore.storeSession(record, for: address, context: context)
}

public func sessionEncrypt<Bytes: ContiguousBytes>(
    message: Bytes,
    for address: ProtocolAddress,
    localAddress: ProtocolAddress? = nil,
    sessionStore: SessionStore,
    identityStore: IdentityKeyStore,
    now: Date = Date(),
    context: StoreContext
) throws -> CiphertextMessage {
    guard let session = try sessionStore.loadSession(for: address, context: context) else {
        throw GossveilError.sessionNotFound("no session for \(address)")
    }
    let plain = Core.octets(message)
    let sender = localAddress?.name.octets ?? []
    let recipient = address.name.octets
    var kind: UInt8 = 0
    var sealed = Core.cell()
    var out = Core.cell()
    let status = gv_session_seal(session.bytes, session.bytes.count, plain, plain.count, seconds(now), sender, sender.count, localAddress?.deviceId ?? 0, recipient, recipient.count, address.deviceId, &kind, &sealed, &out)
    let record = SessionRecord(unchecked: Core.take(&out).octets)
    let bytes = Core.take(&sealed)
    try Core.check(status)
    let theirIdentity = try session.remoteIdentityKey()
    guard try identityStore.isTrustedIdentity(theirIdentity, for: address, direction: .sending, context: context) else { throw untrusted(address) }
    try sessionStore.storeSession(record, for: address, context: context)
    return CiphertextMessage(type: CiphertextMessage.MessageType(rawValue: kind), bytes: bytes.octets)
}

public func sessionDecrypt(
    message: WhisperMessage,
    from address: ProtocolAddress,
    to localAddress: ProtocolAddress? = nil,
    sessionStore: SessionStore,
    identityStore: IdentityKeyStore,
    context: StoreContext
) throws -> Data {
    guard let session = try sessionStore.loadSession(for: address, context: context) else {
        throw GossveilError.sessionNotFound("no session for \(address)")
    }
    let sender = address.name.octets
    let recipient = localAddress?.name.octets ?? []
    var plain = Core.cell()
    var out = Core.cell()
    let status = gv_session_open(session.bytes, session.bytes.count, message.bytes, message.bytes.count, sender, sender.count, address.deviceId, recipient, recipient.count, localAddress?.deviceId ?? 0, &plain, &out)
    let record = SessionRecord(unchecked: Core.take(&out).octets)
    let body = Core.take(&plain)
    try Core.check(status)
    try commit(record, for: address, sessionStore: sessionStore, identityStore: identityStore, context: context)
    return body
}

public func sessionDecryptPreKey(
    message: PreKeyMessage,
    from address: ProtocolAddress,
    localAddress: ProtocolAddress? = nil,
    sessionStore: SessionStore,
    identityStore: IdentityKeyStore,
    preKeyStore: PreKeyStore,
    signedPreKeyStore: SignedPreKeyStore,
    kyberPreKeyStore: KyberPreKeyStore,
    context: StoreContext,
    usePqRatchet _: UsePQRatchet = .no
) throws -> Data {
    guard try identityStore.isTrustedIdentity(message.identityKey, for: address, direction: .receiving, context: context) else { throw untrusted(address) }
    let us = try identityStore.identityKeyPair(context: context)
    let registrationId = try identityStore.localRegistrationId(context: context)
    let existing = try sessionStore.loadSession(for: address, context: context)?.bytes ?? []
    let signed = try signedPreKeyStore.loadSignedPreKey(id: message.signedPreKeyId, context: context).bytes
    let oneTime = try message.preKeyId.map { try preKeyStore.loadPreKey(id: $0, context: context).bytes } ?? []
    let pq = try message.kyberPreKeyId.map { try kyberPreKeyStore.loadKyberPreKey(id: $0, context: context).bytes } ?? []
    let sender = address.name.octets
    let recipient = localAddress?.name.octets ?? []
    var plain = Core.cell()
    var out = Core.cell()
    var consumed = GvConsumed()
    let status = gv_session_open_first(us.privateKey.bytes, us.privateKey.bytes.count, registrationId, existing, existing.count, message.bytes, message.bytes.count, signed, signed.count, oneTime, oneTime.count, pq, pq.count, sender, sender.count, address.deviceId, recipient, recipient.count, localAddress?.deviceId ?? 0, &plain, &out, &consumed)
    let record = SessionRecord(unchecked: Core.take(&out).octets)
    let body = Core.take(&plain)
    try Core.check(status)
    try commit(record, for: address, sessionStore: sessionStore, identityStore: identityStore, context: context)
    if consumed.used == 1 {
        if consumed.one_time_id >= 0 {
            try preKeyStore.removePreKey(id: UInt32(consumed.one_time_id), context: context)
        }
        if let kyberId = message.kyberPreKeyId {
            try kyberPreKeyStore.markKyberPreKeyUsed(id: kyberId, signedPreKeyId: consumed.signed_id, baseKey: PublicKey(unchecked: Core.fixed(consumed.base)), context: context)
        }
    }
    return body
}

/// The identity a fresh record names must still be trusted; then both the
/// identity and the record are saved.
private func commit(_ record: SessionRecord, for address: ProtocolAddress, sessionStore: SessionStore, identityStore: IdentityKeyStore, context: StoreContext) throws {
    let theirIdentity = try record.remoteIdentityKey()
    guard try identityStore.isTrustedIdentity(theirIdentity, for: address, direction: .receiving, context: context) else { throw untrusted(address) }
    _ = try identityStore.saveIdentity(theirIdentity, for: address, context: context)
    try sessionStore.storeSession(record, for: address, context: context)
}

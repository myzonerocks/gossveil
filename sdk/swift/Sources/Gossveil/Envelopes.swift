import Foundation
import GossveilKit

public final class ServerCertificate: Sendable {
    let bytes: [UInt8]
    public let keyId: UInt32
    public let publicKey: PublicKey
    public let certificateBytes: Data
    public let signatureBytes: Data

    public init<Bytes: ContiguousBytes>(_ bytes: Bytes) throws {
        let raw = Core.octets(bytes)
        var info = GvServerCertInfo()
        var body = Core.cell()
        var signature = Core.cell()
        try Core.check(gv_server_cert_parse(raw, raw.count, &info, &body, &signature))
        self.bytes = raw
        keyId = info.key_id
        publicKey = PublicKey(unchecked: Core.fixed(info.key))
        certificateBytes = Core.take(&body)
        signatureBytes = Core.take(&signature)
    }

    public convenience init(keyId: UInt32, publicKey: PublicKey, trustRoot: PrivateKey) throws {
        var out = Core.cell()
        try Core.check(gv_server_cert(keyId, publicKey.bytes, publicKey.bytes.count, trustRoot.bytes, trustRoot.bytes.count, &out))
        try self.init(Core.take(&out))
    }

    public func serialize() -> Data { Data(bytes) }
}

public final class SenderCertificate: Sendable {
    let bytes: [UInt8]
    public let senderUuid: String
    public let senderE164: String?
    public let deviceId: UInt32
    public let expiration: UInt64
    public let publicKey: PublicKey
    public let serverCertificate: ServerCertificate
    public let certificateBytes: Data
    public let signatureBytes: Data

    public init<Bytes: ContiguousBytes>(_ bytes: Bytes) throws {
        let raw = Core.octets(bytes)
        var info = GvSenderCertInfo()
        var senderId = Core.cell()
        var phone = Core.cell()
        var server = Core.cell()
        var body = Core.cell()
        var signature = Core.cell()
        try Core.check(gv_sender_cert_parse(raw, raw.count, &info, &senderId, &phone, &server, &body, &signature))
        self.bytes = raw
        senderUuid = String(decoding: Core.take(&senderId), as: UTF8.self)
        let phoneBytes = Core.take(&phone)
        senderE164 = info.has_phone == 1 ? String(decoding: phoneBytes, as: UTF8.self) : nil
        deviceId = info.device
        expiration = info.expires_ms
        publicKey = PublicKey(unchecked: Core.fixed(info.key))
        serverCertificate = try ServerCertificate(Core.take(&server))
        certificateBytes = Core.take(&body)
        signatureBytes = Core.take(&signature)
    }

    public convenience init(sender: SealedSenderAddress, publicKey: PublicKey, expiration: UInt64, signerCertificate: ServerCertificate, signerKey: PrivateKey) throws {
        let senderId = sender.uuidString.octets
        let phone = sender.e164?.octets ?? []
        var out = Core.cell()
        try Core.check(gv_sender_cert(senderId, senderId.count, phone, phone.count, sender.deviceId, publicKey.bytes, publicKey.bytes.count, expiration, signerCertificate.bytes, signerCertificate.bytes.count, signerKey.bytes, signerKey.bytes.count, &out))
        try self.init(Core.take(&out))
    }

    public var sender: SealedSenderAddress {
        get throws { try SealedSenderAddress(e164: senderE164, uuidString: senderUuid, deviceId: deviceId) }
    }

    public func validate(trustRoot: PublicKey, time: UInt64) throws -> Bool {
        var ok: UInt8 = 0
        try Core.check(gv_sender_cert_check(bytes, bytes.count, trustRoot.bytes, trustRoot.bytes.count, time, &ok))
        return ok == 1
    }

    public func serialize() -> Data { Data(bytes) }
}

public struct SealedSenderAddress: Hashable, Sendable {
    public var e164: String?
    public var uuidString: String
    public var deviceId: UInt32

    public init(e164: String?, uuidString: String, deviceId: UInt32) throws {
        guard !uuidString.isEmpty else { throw GossveilError.invalidArgument("empty sender uuid") }
        self.e164 = e164
        self.uuidString = uuidString
        self.deviceId = deviceId
    }
}

public final class UnidentifiedSenderMessageContent: Sendable {
    public enum ContentHint: UInt8, Sendable {
        case `default` = 0
        case resendable = 1
        case implicit = 2
    }

    let bytes: [UInt8]
    public let messageType: CiphertextMessage.MessageType
    public let contentHint: ContentHint
    public let groupId: Data?
    public let contents: Data
    public let senderCertificate: SenderCertificate

    public init<Bytes: ContiguousBytes>(message bytes: Bytes) throws {
        let raw = Core.octets(bytes)
        var info = GvContentInfo()
        var body = Core.cell()
        var certificate = Core.cell()
        var circle = Core.cell()
        try Core.check(gv_content_parse(raw, raw.count, &info, &body, &certificate, &circle))
        self.bytes = raw
        messageType = CiphertextMessage.MessageType(rawValue: info.kind)
        contentHint = ContentHint(rawValue: info.hint) ?? .default
        contents = Core.take(&body)
        senderCertificate = try SenderCertificate(Core.take(&certificate))
        let circleBytes = Core.take(&circle)
        groupId = info.has_circle == 1 ? circleBytes : nil
    }

    public convenience init<Bytes: ContiguousBytes>(_ message: CiphertextMessage, from sender: SenderCertificate, contentHint: ContentHint, groupId: Bytes) throws {
        try self.init(type: message.messageType, from: sender, contents: message.bytes, contentHint: contentHint, groupId: Core.octets(groupId))
    }

    public convenience init(_ message: CiphertextMessage, from sender: SenderCertificate, contentHint: ContentHint) throws {
        try self.init(type: message.messageType, from: sender, contents: message.bytes, contentHint: contentHint, groupId: nil)
    }

    convenience init(type: CiphertextMessage.MessageType, from sender: SenderCertificate, contents: [UInt8], contentHint: ContentHint, groupId: [UInt8]?) throws {
        let circle = groupId ?? []
        var out = Core.cell()
        try Core.check(gv_content(type.rawValue, sender.bytes, sender.bytes.count, contents, contents.count, contentHint.rawValue, circle, circle.count, groupId == nil ? 0 : 1, &out))
        try self.init(message: Core.take(&out))
    }

    public func serialize() -> Data { Data(bytes) }
}

public func sealedSenderEncrypt<Bytes: ContiguousBytes>(
    message: Bytes,
    for address: ProtocolAddress,
    from senderCert: SenderCertificate,
    sessionStore: SessionStore,
    identityStore: IdentityKeyStore,
    context: StoreContext
) throws -> Data {
    let ciphertext = try sessionEncrypt(message: message, for: address, sessionStore: sessionStore, identityStore: identityStore, context: context)
    let content = try UnidentifiedSenderMessageContent(ciphertext, from: senderCert, contentHint: .default)
    return try sealedSenderEncrypt(content, for: address, identityStore: identityStore, context: context)
}

public func sealedSenderEncrypt(
    _ content: UnidentifiedSenderMessageContent,
    for address: ProtocolAddress,
    identityStore: IdentityKeyStore,
    context: StoreContext
) throws -> Data {
    guard let theirIdentity = try identityStore.identity(for: address, context: context) else {
        throw GossveilError.sessionNotFound("no identity for \(address)")
    }
    let us = try identityStore.identityKeyPair(context: context)
    var out = Core.cell()
    try Core.check(gv_envelope_seal(us.privateKey.bytes, us.privateKey.bytes.count, theirIdentity.publicKey.bytes, theirIdentity.publicKey.bytes.count, content.bytes, content.bytes.count, &out))
    return Core.take(&out)
}

public struct SealedSenderRecipient: Sendable {
    public let serviceId: ServiceId
    public let devices: [(deviceId: UInt8, registrationId: UInt16)]
    public let identityKey: IdentityKey

    public init(serviceId: ServiceId, devices: [(deviceId: UInt8, registrationId: UInt16)], identityKey: IdentityKey) {
        self.serviceId = serviceId
        self.devices = devices
        self.identityKey = identityKey
    }
}

/// One envelope for every device of every recipient, sealed once per
/// recipient by their identity and session registration ids.
public func sealedSenderMultiRecipientEncrypt(
    _ content: UnidentifiedSenderMessageContent,
    for recipients: [ProtocolAddress],
    excludedRecipients: [ServiceId] = [],
    identityStore: IdentityKeyStore,
    sessionStore: SessionStore,
    context: StoreContext
) throws -> Data {
    var byService: [ServiceId: SealedSenderRecipient] = [:]
    var order: [ServiceId] = []
    let sessions = try sessionStore.loadExistingSessions(for: recipients, context: context)
    for (address, session) in zip(recipients, sessions) {
        guard let serviceId = address.serviceId else { throw GossveilError.invalidArgument("recipient \(address) is not a service id") }
        guard let identity = try identityStore.identity(for: address, context: context) else { throw GossveilError.sessionNotFound("no identity for \(address)") }
        let registrationId = try session.remoteRegistrationId()
        guard address.deviceId <= UInt8.max, registrationId <= UInt16.max else {
            throw GossveilError.invalidRegistrationId(address: address, message: "registration id does not fit the envelope")
        }
        let device = (deviceId: UInt8(address.deviceId), registrationId: UInt16(registrationId))
        if let existing = byService[serviceId] {
            byService[serviceId] = SealedSenderRecipient(serviceId: serviceId, devices: existing.devices + [device], identityKey: existing.identityKey)
        } else {
            byService[serviceId] = SealedSenderRecipient(serviceId: serviceId, devices: [device], identityKey: identity)
            order.append(serviceId)
        }
    }
    return try sealedSenderMultiRecipientEncrypt(content, for: order.map { byService[$0]! }, excludedRecipients: excludedRecipients, identityStore: identityStore, context: context)
}

public func sealedSenderMultiRecipientEncrypt(
    _ content: UnidentifiedSenderMessageContent,
    for recipients: [SealedSenderRecipient],
    excludedRecipients: [ServiceId] = [],
    identityStore: IdentityKeyStore,
    context: StoreContext
) throws -> Data {
    guard recipients.count <= UInt8.max, excludedRecipients.count <= UInt8.max else { throw GossveilError.invalidArgument("too many recipients") }
    var listing: [UInt8] = [UInt8(recipients.count)]
    for recipient in recipients {
        guard recipient.devices.count <= UInt8.max else { throw GossveilError.invalidArgument("too many devices") }
        listing += recipient.serviceId.serviceIdFixedWidthBinary
        listing.append(UInt8(recipient.devices.count))
        for device in recipient.devices {
            listing.append(device.deviceId)
            listing.append(UInt8(device.registrationId >> 8))
            listing.append(UInt8(device.registrationId & 0xFF))
        }
        listing += recipient.identityKey.publicKey.bytes
    }
    var excluded: [UInt8] = [UInt8(excludedRecipients.count)]
    for serviceId in excludedRecipients {
        excluded += serviceId.serviceIdFixedWidthBinary
    }
    let us = try identityStore.identityKeyPair(context: context)
    var out = Core.cell()
    try Core.check(gv_envelope_seal_many(us.privateKey.bytes, us.privateKey.bytes.count, listing, listing.count, excluded, excluded.count, content.bytes, content.bytes.count, &out))
    return Core.take(&out)
}

public func sealedSenderMultiRecipientMessageForSingleRecipient<Bytes: ContiguousBytes>(_ message: Bytes) throws -> Data {
    let raw = Core.octets(message)
    var out = Core.cell()
    try Core.check(gv_envelope_for_single(raw, raw.count, &out))
    return Core.take(&out)
}

public func sealedSenderMultiRecipientMessage<Bytes: ContiguousBytes>(_ message: Bytes, for serviceId: ServiceId, deviceId: UInt8) throws -> Data {
    let raw = Core.octets(message)
    let sid = serviceId.serviceIdFixedWidthBinary.octets
    var out = Core.cell()
    try Core.check(gv_envelope_for_recipient(raw, raw.count, sid, sid.count, deviceId, &out))
    return Core.take(&out)
}

public func sealedSenderDecryptToUsmc<Bytes: ContiguousBytes>(
    message: Bytes,
    identityStore: IdentityKeyStore,
    context: StoreContext
) throws -> UnidentifiedSenderMessageContent {
    let raw = Core.octets(message)
    let us = try identityStore.identityKeyPair(context: context)
    var out = Core.cell()
    try Core.check(gv_envelope_open(us.privateKey.bytes, us.privateKey.bytes.count, raw, raw.count, &out))
    return try UnidentifiedSenderMessageContent(message: Core.take(&out))
}

public struct SealedSenderResult: Sendable {
    public var message: Data
    public var sender: SealedSenderAddress
}

/// Opens an envelope, checks the sender certificate against the trust root
/// at `timestamp`, and decrypts the inner message with the matching stores.
public func sealedSenderDecrypt<Bytes: ContiguousBytes>(
    message: Bytes,
    from localAddress: SealedSenderAddress,
    trustRoot: PublicKey,
    timestamp: UInt64,
    sessionStore: SessionStore,
    identityStore: IdentityKeyStore,
    preKeyStore: PreKeyStore,
    signedPreKeyStore: SignedPreKeyStore,
    kyberPreKeyStore: KyberPreKeyStore,
    senderKeyStore: SenderKeyStore? = nil,
    context: StoreContext
) throws -> SealedSenderResult {
    let content = try sealedSenderDecryptToUsmc(message: message, identityStore: identityStore, context: context)
    let certificate = content.senderCertificate
    guard try certificate.validate(trustRoot: trustRoot, time: timestamp) else {
        throw GossveilError.invalidSignature("sender certificate failed validation")
    }
    let sender = try certificate.sender
    let sameAccount = sender.uuidString == localAddress.uuidString || (sender.e164 != nil && sender.e164 == localAddress.e164)
    if sameAccount, sender.deviceId == localAddress.deviceId {
        throw GossveilError.sealedSenderSelfSend("message sealed by this device")
    }
    let senderAddress = try ProtocolAddress(name: sender.uuidString, deviceId: sender.deviceId)
    let localProtocolAddress = try ProtocolAddress(name: localAddress.uuidString, deviceId: localAddress.deviceId)
    let plain: Data
    switch content.messageType {
    case .whisper:
        plain = try sessionDecrypt(message: WhisperMessage(bytes: content.contents), from: senderAddress, to: localProtocolAddress, sessionStore: sessionStore, identityStore: identityStore, context: context)
    case .preKey:
        plain = try sessionDecryptPreKey(message: PreKeyMessage(bytes: content.contents), from: senderAddress, localAddress: localProtocolAddress, sessionStore: sessionStore, identityStore: identityStore, preKeyStore: preKeyStore, signedPreKeyStore: signedPreKeyStore, kyberPreKeyStore: kyberPreKeyStore, context: context)
    case .senderKey:
        guard let senderKeyStore else { throw GossveilError.invalidArgument("a sender key message needs a sender key store") }
        plain = try groupDecrypt(content.contents, from: senderAddress, store: senderKeyStore, context: context)
    case .plaintext:
        plain = try PlaintextContent(bytes: content.contents).body
    default:
        throw GossveilError.invalidMessage("unknown sealed message type")
    }
    return SealedSenderResult(message: plain, sender: sender)
}

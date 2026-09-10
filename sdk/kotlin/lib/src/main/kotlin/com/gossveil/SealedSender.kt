package com.gossveil

import java.io.ByteArrayOutputStream

class ServerCertificate private constructor(private val bytes: ByteArray, reply: Reply) {
    private val info = reply.fields()
    val certificate: ByteArray = reply.bytes()
    val signature: ByteArray = reply.bytes()

    @Throws(InvalidMessageException::class)
    constructor(serialized: ByteArray) : this(serialized.copyOf(), Native.run(Native.SERVER_CERT_PARSE, Native.args(serialized)))

    constructor(keyId: Int, serverKey: ECPublicKey, trustRoot: ECPrivateKey) :
        this(Native.run(Native.SERVER_CERT, Native.args(serverKey.bytes, trustRoot.bytes), Native.nums(keyId.toLong())).bytes())

    val keyId: Int get() = info.u32(0)
    val key: ECPublicKey get() = ECPublicKey(info.bytes(4, 33), true)

    fun serialize(): ByteArray = bytes.copyOf()
}

class SenderCertificate private constructor(private val bytes: ByteArray, reply: Reply) {
    private val info = reply.fields()
    val senderUuid: String = reply.string()
    private val phoneBytes = reply.bytes()
    private val serverCertificateBytes = reply.bytes()
    val certificate: ByteArray = reply.bytes()
    val signature: ByteArray = reply.bytes()

    @Throws(InvalidMessageException::class)
    constructor(serialized: ByteArray) : this(serialized.copyOf(), Native.run(Native.SENDER_CERT_PARSE, Native.args(serialized)))

    constructor(senderUuid: String, senderE164: String?, senderDeviceId: Int, senderKey: ECPublicKey, expiration: Long, signerCertificate: ServerCertificate, signerKey: ECPrivateKey) :
        this(
            Native.run(
                Native.SENDER_CERT,
                Native.args(senderUuid.utf8(), senderE164?.utf8(), senderKey.bytes, signerCertificate.serialize(), signerKey.bytes),
                Native.nums(senderDeviceId.toLong(), expiration),
            ).bytes(),
        )

    val senderDeviceId: Int get() = info.u32(0)
    val expiration: Long get() = info.i64(8)
    val key: ECPublicKey get() = ECPublicKey(info.bytes(16, 33), true)
    val senderE164: String? get() = if (info.flag(49)) String(phoneBytes, Charsets.UTF_8) else null
    val senderAci: ServiceId.Aci? get() = runCatching { ServiceId.Aci.parseFromString(senderUuid) }.getOrNull()
    val serverCertificate: ServerCertificate get() = ServerCertificate(serverCertificateBytes)

    fun validate(trustRoot: ECPublicKey, timestamp: Long): Boolean =
        Native.run(Native.SENDER_CERT_CHECK, Native.args(bytes, trustRoot.bytes), Native.nums(timestamp)).flag()

    fun serialize(): ByteArray = bytes.copyOf()
}

class UnidentifiedSenderMessageContent private constructor(private val bytes: ByteArray, reply: Reply) {
    enum class ContentHint(val code: Int) {
        DEFAULT(0),
        RESENDABLE(1),
        IMPLICIT(2);

        companion object {
            fun of(code: Int): ContentHint = entries.firstOrNull { it.code == code } ?: DEFAULT
        }
    }

    private val info = reply.fields()
    val content: ByteArray = reply.bytes()
    private val senderCertificateBytes = reply.bytes()
    private val groupIdBytes = reply.bytes()

    @Throws(InvalidMessageException::class)
    constructor(serialized: ByteArray) : this(serialized.copyOf(), Native.run(Native.CONTENT_PARSE, Native.args(serialized)))

    constructor(message: CiphertextMessage, sender: SenderCertificate, contentHint: ContentHint, groupId: ByteArray? = null) :
        this(
            Native.run(
                Native.CONTENT,
                Native.args(sender.serialize(), message.serialize(), groupId),
                Native.nums(message.type.toLong(), contentHint.code.toLong(), if (groupId == null) 0L else 1L),
            ).bytes(),
        )

    val type: Int get() = info.u8(0)
    val contentHint: ContentHint get() = ContentHint.of(info.u8(1))
    val groupId: ByteArray? get() = if (info.flag(2)) groupIdBytes.copyOf() else null
    val senderCertificate: SenderCertificate get() = SenderCertificate(senderCertificateBytes)

    fun serialize(): ByteArray = bytes.copyOf()
}

class SealedSessionCipher(
    private val store: ProtocolStore,
    private val localUuid: String,
    private val localE164: String?,
    private val localDeviceId: Int,
) {
    class DecryptionResult(val senderUuid: String, val senderE164: String?, val deviceId: Int, val paddedMessage: ByteArray)

    class Recipient(val serviceId: ServiceId, val devices: List<Pair<Int, Int>>, val identityKey: IdentityKey)

    fun encrypt(destination: ProtocolAddress, senderCertificate: SenderCertificate, paddedPlaintext: ByteArray): ByteArray {
        val message = SessionCipher(store, destination).encrypt(paddedPlaintext)
        val content = UnidentifiedSenderMessageContent(message, senderCertificate, UnidentifiedSenderMessageContent.ContentHint.DEFAULT)
        return encrypt(destination, content)
    }

    fun encrypt(destination: ProtocolAddress, content: UnidentifiedSenderMessageContent): ByteArray {
        val theirIdentity = store.getIdentity(destination) ?: throw NoSessionException(destination, "no identity")
        return Native.run(Native.ENVELOPE_SEAL, Native.args(store.getIdentityKeyPair().privateKey.bytes, theirIdentity.publicKey.bytes, content.serialize())).bytes()
    }

    /** One envelope for every device of every recipient; the server splits it per recipient. */
    fun multiRecipientEncrypt(recipients: List<ProtocolAddress>, content: UnidentifiedSenderMessageContent, excluded: List<ServiceId> = emptyList()): ByteArray {
        val sessions = store.loadExistingSessions(recipients)
        val byService = LinkedHashMap<ServiceId, Recipient>()
        recipients.forEachIndexed { i, address ->
            val serviceId = address.serviceId ?: throw IllegalArgumentException("$address is not a service id")
            val identity = store.getIdentity(address) ?: throw NoSessionException(address, "no identity")
            val device = address.deviceId to sessions[i].remoteRegistrationId
            val existing = byService[serviceId]
            byService[serviceId] = if (existing == null) Recipient(serviceId, listOf(device), identity) else Recipient(serviceId, existing.devices + device, existing.identityKey)
        }
        return multiRecipientEncryptFor(byService.values.toList(), content, excluded)
    }

    fun multiRecipientEncryptFor(recipients: List<Recipient>, content: UnidentifiedSenderMessageContent, excluded: List<ServiceId> = emptyList()): ByteArray {
        val listing = ByteArrayOutputStream()
        listing.write(recipients.size)
        for (r in recipients) {
            listing.write(r.serviceId.toServiceIdFixedWidthBinary())
            listing.write(r.devices.size)
            for ((deviceId, registrationId) in r.devices) {
                if (deviceId > 255 || registrationId > 0xffff) throw InvalidRegistrationIdException(ProtocolAddress(r.serviceId, deviceId), "registration id does not fit the envelope")
                listing.write(deviceId)
                listing.write(registrationId shr 8)
                listing.write(registrationId and 0xff)
            }
            listing.write(r.identityKey.publicKey.bytes)
        }
        val left = ByteArrayOutputStream()
        left.write(excluded.size)
        for (s in excluded) left.write(s.toServiceIdFixedWidthBinary())
        return Native.run(Native.ENVELOPE_SEAL_MANY, Native.args(store.getIdentityKeyPair().privateKey.bytes, listing.toByteArray(), left.toByteArray(), content.serialize())).bytes()
    }

    fun decryptToUsmc(ciphertext: ByteArray): UnidentifiedSenderMessageContent =
        UnidentifiedSenderMessageContent(Native.run(Native.ENVELOPE_OPEN, Native.args(store.getIdentityKeyPair().privateKey.bytes, ciphertext)).bytes())

    @Throws(InvalidMessageException::class, SelfSendException::class)
    fun decrypt(trustRoot: ECPublicKey, ciphertext: ByteArray, timestamp: Long): DecryptionResult {
        val content = decryptToUsmc(ciphertext)
        val certificate = content.senderCertificate
        if (!certificate.validate(trustRoot, timestamp)) throw InvalidMessageException("sender certificate failed validation")
        val senderUuid = certificate.senderUuid
        val senderE164 = certificate.senderE164
        val sameAccount = senderUuid == localUuid || (senderE164 != null && senderE164 == localE164)
        if (sameAccount && certificate.senderDeviceId == localDeviceId) throw SelfSendException("message sealed by this device")
        val sender = ProtocolAddress(senderUuid, certificate.senderDeviceId)
        val local = ProtocolAddress(localUuid, localDeviceId)
        val cipher = SessionCipher(store, sender).apply { localAddress = local }
        val plain = when (content.type) {
            CiphertextMessage.WHISPER_TYPE -> cipher.decrypt(WhisperMessage(content.content))
            CiphertextMessage.PREKEY_TYPE -> cipher.decrypt(PreKeyMessage(content.content))
            CiphertextMessage.SENDERKEY_TYPE -> GroupCipher(store, sender).decrypt(content.content)
            CiphertextMessage.PLAINTEXT_CONTENT_TYPE -> PlaintextContent(content.content).body
            else -> throw InvalidMessageException("unknown sealed message type ${content.type}")
        }
        return DecryptionResult(senderUuid, senderE164, certificate.senderDeviceId, plain)
    }

    companion object {
        @JvmStatic
        fun multiRecipientMessageForSingleRecipient(message: ByteArray): ByteArray =
            Native.run(Native.ENVELOPE_FOR_SINGLE, Native.args(message)).bytes()

        @JvmStatic
        fun multiRecipientMessageForRecipient(message: ByteArray, serviceId: ServiceId, deviceId: Int): ByteArray =
            Native.run(Native.ENVELOPE_FOR_RECIPIENT, Native.args(message, serviceId.toServiceIdFixedWidthBinary()), Native.nums(deviceId.toLong())).bytes()
    }
}

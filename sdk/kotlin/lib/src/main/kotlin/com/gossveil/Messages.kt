package com.gossveil

import java.util.UUID

interface CiphertextMessage {
    val type: Int

    fun serialize(): ByteArray

    companion object {
        const val CURRENT_VERSION = 4
        const val WHISPER_TYPE = 2
        const val PREKEY_TYPE = 3
        const val SENDERKEY_TYPE = 7
        const val PLAINTEXT_CONTENT_TYPE = 8
    }
}

/** A ratchet message: the sender's ratchet key, its place in the chain and the sealed body. */
class WhisperMessage private constructor(private val bytes: ByteArray, reply: Reply) : CiphertextMessage {
    private val info = reply.fields()
    val body: ByteArray = reply.bytes()

    @Throws(InvalidMessageException::class, InvalidVersionException::class, LegacyMessageException::class)
    constructor(serialized: ByteArray) : this(serialized.copyOf(), Native.run(Native.WHISPER_PARSE, Native.args(serialized)))

    val messageVersion: Int get() = info.u8(0)
    val counter: Int get() = info.u32(4)
    val previousCounter: Int get() = info.u32(8)
    val senderRatchetKey: ECPublicKey get() = ECPublicKey(info.bytes(12, 33), true)

    override val type: Int get() = CiphertextMessage.WHISPER_TYPE

    override fun serialize(): ByteArray = bytes.copyOf()
}

/** The first message of a session: the handshake material around a whisper. */
class PreKeyMessage private constructor(private val bytes: ByteArray, reply: Reply) : CiphertextMessage {
    private val info = reply.fields()
    private val inner = reply.bytes()

    @Throws(InvalidMessageException::class, InvalidVersionException::class, LegacyMessageException::class)
    constructor(serialized: ByteArray) : this(serialized.copyOf(), Native.run(Native.OPENER_PARSE, Native.args(serialized)))

    val messageVersion: Int get() = info.u8(0)
    val registrationId: Int get() = info.u32(4)
    val preKeyId: Int? get() = info.i64(8).let { if (it < 0) null else it.toInt() }
    val signedPreKeyId: Int get() = info.u32(16)
    val kyberPreKeyId: Int? get() = info.i64(24).let { if (it < 0) null else it.toInt() }
    val baseKey: ECPublicKey get() = ECPublicKey(info.bytes(32, 33), true)
    val identityKey: IdentityKey get() = IdentityKey(ECPublicKey(info.bytes(65, 33), true))
    val whisperMessage: WhisperMessage get() = WhisperMessage(inner)
    val signalMessage: WhisperMessage get() = whisperMessage

    override val type: Int get() = CiphertextMessage.PREKEY_TYPE

    override fun serialize(): ByteArray = bytes.copyOf()
}

class SenderKeyMessage private constructor(private val bytes: ByteArray, reply: Reply) : CiphertextMessage {
    private val info = reply.fields()
    val ciphertext: ByteArray = reply.bytes()

    @Throws(InvalidMessageException::class, InvalidVersionException::class, LegacyMessageException::class)
    constructor(serialized: ByteArray) : this(serialized.copyOf(), Native.run(Native.NOTE_PARSE, Native.args(serialized)))

    val messageVersion: Int get() = info.u8(0)
    val distributionId: UUID get() = ServiceId.uuidOf(info.bytes(1, 16))
    val chainId: Int get() = info.u32(20)
    val iteration: Int get() = info.u32(24)

    override val type: Int get() = CiphertextMessage.SENDERKEY_TYPE

    override fun serialize(): ByteArray = bytes.copyOf()
}

class SenderKeyDistributionMessage private constructor(private val bytes: ByteArray, reply: Reply) {
    private val info = reply.fields()

    @Throws(InvalidMessageException::class, InvalidVersionException::class, LegacyMessageException::class)
    constructor(serialized: ByteArray) : this(serialized.copyOf(), Native.run(Native.ANNOUNCE_PARSE, Native.args(serialized)))

    val messageVersion: Int get() = info.u8(0)
    val distributionId: UUID get() = ServiceId.uuidOf(info.bytes(1, 16))
    val chainId: Int get() = info.u32(20)
    val iteration: Int get() = info.u32(24)
    val chainKey: ByteArray get() = info.bytes(28, 32)
    val signatureKey: ECPublicKey get() = ECPublicKey(info.bytes(60, 33), true)

    fun serialize(): ByteArray = bytes.copyOf()
}

class DecryptionErrorMessage private constructor(private val bytes: ByteArray, reply: Reply) {
    private val info = reply.fields()

    @Throws(InvalidMessageException::class)
    constructor(serialized: ByteArray) : this(serialized.copyOf(), Native.run(Native.REPORT_PARSE, Native.args(serialized)))

    val timestamp: Long get() = info.i64(0)
    val deviceId: Int get() = info.u32(8)
    val ratchetKey: ECPublicKey? get() = if (info.flag(12)) ECPublicKey(info.bytes(13, 33), true) else null

    fun serialize(): ByteArray = bytes.copyOf()

    companion object {
        @JvmStatic
        fun forOriginalMessage(originalBytes: ByteArray, originalType: Int, timestamp: Long, originalSenderDeviceId: Int): DecryptionErrorMessage =
            DecryptionErrorMessage(Native.run(Native.REPORT, Native.args(originalBytes), Native.nums(originalType.toLong(), timestamp, originalSenderDeviceId.toLong())).bytes())

        @JvmStatic
        fun extractFromSerializedContent(serializedContentBody: ByteArray): DecryptionErrorMessage =
            DecryptionErrorMessage(Native.run(Native.REPORT_IN_BODY, Native.args(serializedContentBody)).bytes())
    }
}

class PlaintextContent private constructor(private val bytes: ByteArray, val body: ByteArray) : CiphertextMessage {
    @Throws(InvalidMessageException::class)
    constructor(serialized: ByteArray) : this(serialized.copyOf(), Native.run(Native.PLAIN_BODY, Native.args(serialized)).bytes())

    constructor(message: DecryptionErrorMessage) : this(Native.run(Native.PLAIN_FROM_REPORT, Native.args(message.serialize())).bytes())

    override val type: Int get() = CiphertextMessage.PLAINTEXT_CONTENT_TYPE

    override fun serialize(): ByteArray = bytes.copyOf()
}

internal class RawCiphertextMessage(override val type: Int, private val bytes: ByteArray) : CiphertextMessage {
    override fun serialize(): ByteArray = bytes.copyOf()
}

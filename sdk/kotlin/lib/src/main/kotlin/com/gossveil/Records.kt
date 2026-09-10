package com.gossveil

class PreKeyRecord private constructor(internal val bytes: ByteArray, reply: Reply) {
    val id: Int = reply.u32()
    private val publicKeyBytes = reply.bytes()
    private val privateKeyBytes = reply.bytes()

    @Throws(InvalidMessageException::class)
    constructor(serialized: ByteArray) : this(serialized.copyOf(), Native.run(Native.ONE_TIME_PARSE, Native.args(serialized)))

    constructor(id: Int, keyPair: ECKeyPair) : this(Native.run(Native.ONE_TIME_RECORD, Native.args(keyPair.privateKey.bytes), Native.nums(id.toLong())).bytes())

    val keyPair: ECKeyPair get() = ECKeyPair(ECPublicKey(publicKeyBytes, true), ECPrivateKey(privateKeyBytes, true))

    fun serialize(): ByteArray = bytes.copyOf()
}

class SignedPreKeyRecord private constructor(internal val bytes: ByteArray, reply: Reply) {
    val id: Int = reply.u32()
    val timestamp: Long = reply.u64()
    private val publicKeyBytes = reply.bytes()
    private val privateKeyBytes = reply.bytes()
    val signature: ByteArray = reply.bytes()

    @Throws(InvalidMessageException::class)
    constructor(serialized: ByteArray) : this(serialized.copyOf(), Native.run(Native.SIGNED_PARSE, Native.args(serialized)))

    constructor(id: Int, timestamp: Long, keyPair: ECKeyPair, signature: ByteArray) :
        this(Native.run(Native.SIGNED_RECORD, Native.args(keyPair.privateKey.bytes, signature), Native.nums(id.toLong(), timestamp)).bytes())

    val keyPair: ECKeyPair get() = ECKeyPair(ECPublicKey(publicKeyBytes, true), ECPrivateKey(privateKeyBytes, true))

    fun serialize(): ByteArray = bytes.copyOf()
}

class KyberPreKeyRecord private constructor(internal val bytes: ByteArray, reply: Reply) {
    val id: Int = reply.u32()
    val timestamp: Long = reply.u64()
    private val publicKeyBytes = reply.bytes()
    private val secretKeyBytes = reply.bytes()
    val signature: ByteArray = reply.bytes()

    @Throws(InvalidMessageException::class)
    constructor(serialized: ByteArray) : this(serialized.copyOf(), Native.run(Native.PQ_RECORD_PARSE, Native.args(serialized)))

    constructor(id: Int, timestamp: Long, keyPair: KEMKeyPair, signature: ByteArray) :
        this(Native.run(Native.PQ_RECORD, Native.args(keyPair.publicKey.bytes, keyPair.secretKey.bytes, signature), Native.nums(id.toLong(), timestamp)).bytes())

    val keyPair: KEMKeyPair get() = KEMKeyPair(KEMPublicKey(publicKeyBytes, true), KEMSecretKey(secretKeyBytes, true))

    fun serialize(): ByteArray = bytes.copyOf()
}

/** A session with one device. Protocol operations replace the bytes in place. */
class SessionRecord internal constructor(internal var bytes: ByteArray, @Suppress("UNUSED_PARAMETER") checked: Boolean) {
    @Throws(InvalidMessageException::class)
    constructor(serialized: ByteArray) : this(check(serialized), true)

    companion object {
        private fun check(serialized: ByteArray): ByteArray {
            Native.run(Native.SESSION_INFO, Native.args(serialized), Native.nums(0))
            return serialized.copyOf()
        }
    }

    private fun info(nowSecs: Long = System.currentTimeMillis() / 1000): Fields =
        Native.run(Native.SESSION_INFO, Native.args(bytes), Native.nums(nowSecs)).fields()

    private fun live(): Fields {
        val info = info()
        if (!info.flag(0)) throw IllegalStateException("no current session")
        return info
    }

    fun serialize(): ByteArray = bytes.copyOf()

    fun hasSenderChain(): Boolean = info().flag(1)

    fun hasSenderChain(now: java.time.Instant): Boolean = info(now.epochSecond).flag(2)

    fun archiveCurrentState() {
        bytes = Native.run(Native.SESSION_SHELVE, Native.args(bytes)).bytes()
    }

    val sessionVersion: Int get() = live().u32(4)

    val localRegistrationId: Int get() = live().u32(8)

    val remoteRegistrationId: Int get() = live().u32(12)

    val localIdentityKey: IdentityKey get() = IdentityKey(ECPublicKey(live().bytes(20, 33), true))

    val remoteIdentityKey: IdentityKey get() = IdentityKey(ECPublicKey(live().bytes(53, 33), true))

    fun currentRatchetKeyMatches(key: ECPublicKey): Boolean =
        Native.run(Native.SESSION_RATCHET_IS, Native.args(bytes, key.bytes)).flag()
}

class SenderKeyRecord internal constructor(internal var bytes: ByteArray) {
    fun serialize(): ByteArray = bytes.copyOf()

    companion object {
        @JvmStatic
        fun deserialize(serialized: ByteArray): SenderKeyRecord = SenderKeyRecord(serialized.copyOf())
    }
}

class PreKeyBundle(
    val registrationId: Int,
    val deviceId: Int,
    val preKeyId: Int,
    val preKey: ECPublicKey?,
    val signedPreKeyId: Int,
    val signedPreKey: ECPublicKey,
    val signedPreKeySignature: ByteArray,
    val identityKey: IdentityKey,
    val kyberPreKeyId: Int,
    val kyberPreKey: KEMPublicKey,
    val kyberPreKeySignature: ByteArray,
) {
    companion object {
        const val NULL_PRE_KEY_ID = -1
    }

    init {
        require(signedPreKeySignature.size == 64 && kyberPreKeySignature.size == 64) { "signatures are 64 bytes" }
    }
}

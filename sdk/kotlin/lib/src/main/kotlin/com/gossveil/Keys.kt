package com.gossveil

class ECPublicKey internal constructor(internal val bytes: ByteArray, @Suppress("UNUSED_PARAMETER") checked: Boolean) : Comparable<ECPublicKey> {
    @Throws(InvalidKeyException::class)
    constructor(serialized: ByteArray) : this(check(serialized), true)

    companion object {
        const val KEY_SIZE = 33

        private fun check(serialized: ByteArray): ByteArray {
            Native.run(Native.CURVE_CHECK, Native.args(serialized))
            return serialized.copyOf()
        }
    }

    fun serialize(): ByteArray = bytes.copyOf()

    val publicKeyBytes: ByteArray get() = bytes.copyOfRange(1, bytes.size)

    fun verifySignature(message: ByteArray, signature: ByteArray): Boolean =
        Native.run(Native.CURVE_VERIFY, Native.args(bytes, message, signature)).flag()

    override fun equals(other: Any?): Boolean = other is ECPublicKey && bytes.contentEquals(other.bytes)

    override fun hashCode(): Int = bytes.contentHashCode()

    override fun compareTo(other: ECPublicKey): Int {
        for (i in 0 until minOf(bytes.size, other.bytes.size)) {
            val a = bytes[i].toInt() and 0xff
            val b = other.bytes[i].toInt() and 0xff
            if (a != b) return a - b
        }
        return bytes.size - other.bytes.size
    }
}

class ECPrivateKey internal constructor(internal val bytes: ByteArray, @Suppress("UNUSED_PARAMETER") checked: Boolean) {
    @Throws(InvalidKeyException::class)
    constructor(serialized: ByteArray) : this(check(serialized), true)

    companion object {
        private fun check(serialized: ByteArray): ByteArray {
            if (serialized.size != 32) throw InvalidKeyException("a private key is 32 bytes")
            return serialized.copyOf()
        }

        @JvmStatic
        fun generate(): ECPrivateKey = ECPrivateKey(Native.run(Native.CURVE_PAIR).bytes(), true)
    }

    fun serialize(): ByteArray = bytes.copyOf()

    val publicKey: ECPublicKey get() = ECPublicKey(Native.run(Native.CURVE_PUBLIC, Native.args(bytes)).bytes(), true)

    fun calculateSignature(message: ByteArray): ByteArray = Native.run(Native.CURVE_SIGN, Native.args(bytes, message)).bytes()

    fun calculateAgreement(other: ECPublicKey): ByteArray = Native.run(Native.CURVE_AGREE, Native.args(bytes, other.bytes)).bytes()
}

class ECKeyPair(val publicKey: ECPublicKey, val privateKey: ECPrivateKey) {
    companion object {
        @JvmStatic
        fun generate(): ECKeyPair {
            val privateKey = ECPrivateKey.generate()
            return ECKeyPair(privateKey.publicKey, privateKey)
        }
    }
}

class IdentityKey(val publicKey: ECPublicKey) {
    @Throws(InvalidKeyException::class)
    constructor(bytes: ByteArray) : this(ECPublicKey(bytes))

    @Throws(InvalidKeyException::class)
    constructor(bytes: ByteArray, offset: Int) : this(ECPublicKey(bytes.copyOfRange(offset, bytes.size)))

    fun serialize(): ByteArray = publicKey.serialize()

    fun verifyAlternateIdentity(other: IdentityKey, signature: ByteArray): Boolean =
        Native.run(Native.IDENTITY_VOUCHED, Native.args(publicKey.bytes, other.publicKey.bytes, signature)).flag()

    override fun equals(other: Any?): Boolean = other is IdentityKey && publicKey == other.publicKey

    override fun hashCode(): Int = publicKey.hashCode()
}

class IdentityKeyPair(val publicKey: IdentityKey, val privateKey: ECPrivateKey) {
    @Throws(InvalidKeyException::class)
    constructor(serialized: ByteArray) : this(parse(serialized))

    private constructor(pair: Pair<IdentityKey, ECPrivateKey>) : this(pair.first, pair.second)

    companion object {
        private fun parse(serialized: ByteArray): Pair<IdentityKey, ECPrivateKey> {
            val reply = Native.run(Native.IDENTITY_PARSE, Native.args(serialized))
            return IdentityKey(ECPublicKey(reply.bytes(), true)) to ECPrivateKey(reply.bytes(), true)
        }

        @JvmStatic
        fun generate(): IdentityKeyPair {
            val privateKey = ECPrivateKey.generate()
            return IdentityKeyPair(IdentityKey(privateKey.publicKey), privateKey)
        }
    }

    fun serialize(): ByteArray = Native.run(Native.IDENTITY_SERIALIZE, Native.args(privateKey.bytes)).bytes()

    fun signAlternateIdentity(other: IdentityKey): ByteArray =
        Native.run(Native.IDENTITY_VOUCH, Native.args(privateKey.bytes, other.publicKey.bytes)).bytes()
}

enum class KEMKeyType(internal val code: Int) {
    KYBER_1024(0x08),
    ML_KEM_1024(0x0A),
}

private const val PQ_PUBLIC_LENGTH = 1569
private const val PQ_SECRET_LENGTH = 3169

private fun pqTagged(serialized: ByteArray, length: Int): Boolean =
    serialized.size == length && (serialized[0].toInt() == 0x08 || serialized[0].toInt() == 0x0A)

class KEMPublicKey internal constructor(internal val bytes: ByteArray, @Suppress("UNUSED_PARAMETER") checked: Boolean) {
    @Throws(InvalidKeyException::class)
    constructor(serialized: ByteArray) : this(check(serialized), true)

    companion object {
        private fun check(serialized: ByteArray): ByteArray {
            if (!pqTagged(serialized, PQ_PUBLIC_LENGTH)) throw InvalidKeyException("unrecognized key encapsulation key")
            return serialized.copyOf()
        }
    }

    fun serialize(): ByteArray = bytes.copyOf()

    /** A shared secret and the capsule that yields it for the secret key holder. */
    fun encapsulate(): Pair<ByteArray, ByteArray> {
        val reply = Native.run(Native.PQ_ENCAPSULATE, Native.args(bytes))
        val capsule = reply.bytes()
        val secret = reply.bytes()
        return secret to capsule
    }

    override fun equals(other: Any?): Boolean = other is KEMPublicKey && bytes.contentEquals(other.bytes)

    override fun hashCode(): Int = bytes.contentHashCode()
}

class KEMSecretKey internal constructor(internal val bytes: ByteArray, @Suppress("UNUSED_PARAMETER") checked: Boolean) {
    @Throws(InvalidKeyException::class)
    constructor(serialized: ByteArray) : this(check(serialized), true)

    companion object {
        private fun check(serialized: ByteArray): ByteArray {
            if (!pqTagged(serialized, PQ_SECRET_LENGTH)) throw InvalidKeyException("unrecognized key encapsulation secret")
            return serialized.copyOf()
        }
    }

    fun serialize(): ByteArray = bytes.copyOf()

    fun decapsulate(ciphertext: ByteArray): ByteArray = Native.run(Native.PQ_OPEN, Native.args(bytes, ciphertext)).bytes()
}

class KEMKeyPair(val publicKey: KEMPublicKey, val secretKey: KEMSecretKey) {
    companion object {
        @JvmStatic
        fun generate(type: KEMKeyType = KEMKeyType.KYBER_1024): KEMKeyPair {
            val reply = Native.run(Native.PQ_PAIR, nums = Native.nums(type.code.toLong()))
            return KEMKeyPair(KEMPublicKey(reply.bytes(), true), KEMSecretKey(reply.bytes(), true))
        }
    }
}

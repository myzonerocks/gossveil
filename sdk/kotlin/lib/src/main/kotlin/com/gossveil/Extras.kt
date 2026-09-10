package com.gossveil

class DisplayableFingerprint internal constructor(val displayText: String)

class ScannableFingerprint internal constructor(private val encoding: ByteArray) {
    fun serialize(): ByteArray = encoding.copyOf()

    fun compareTo(other: ByteArray): Boolean = Native.run(Native.SAFETY_MATCHES, Native.args(encoding, other)).flag()
}

class Fingerprint internal constructor(val displayableFingerprint: DisplayableFingerprint, val scannableFingerprint: ScannableFingerprint)

class NumericFingerprintGenerator(private val iterations: Int) {
    fun createFor(version: Int, localStableIdentifier: ByteArray, localIdentityKey: IdentityKey, remoteStableIdentifier: ByteArray, remoteIdentityKey: IdentityKey): Fingerprint {
        val reply = Native.run(
            Native.SAFETY,
            Native.args(localStableIdentifier, localIdentityKey.publicKey.bytes, remoteStableIdentifier, remoteIdentityKey.publicKey.bytes),
            Native.nums(version.toLong(), iterations.toLong()),
        )
        return Fingerprint(DisplayableFingerprint(reply.string()), ScannableFingerprint(reply.bytes()))
    }
}

class Username(val username: String) {
    val hash: ByteArray = Native.run(Native.HANDLE_HASH, Native.args(username.utf8())).bytes()

    fun generateProof(randomness: ByteArray = randomBytes(32)): ByteArray =
        Native.run(Native.HANDLE_PROOF, Native.args(username.utf8(), randomness)).bytes()

    /** A fresh link, or one re-keyed with the previous entropy so old links keep resolving. */
    fun generateLink(previousEntropy: ByteArray? = null): UsernameLink {
        val reply = Native.run(Native.HANDLE_LINK, Native.args(username.utf8(), previousEntropy))
        return UsernameLink(reply.bytes(), reply.bytes())
    }

    override fun toString(): String = username

    override fun equals(other: Any?): Boolean = other is Username && username == other.username

    override fun hashCode(): Int = username.hashCode()

    class UsernameLink(val entropy: ByteArray, val encryptedUsername: ByteArray)

    companion object {
        @JvmStatic
        @Throws(VerificationFailedException::class)
        fun verifyProof(proof: ByteArray, hash: ByteArray) {
            if (!Native.run(Native.HANDLE_VERIFY, Native.args(proof, hash)).flag()) throw VerificationFailedException("username proof does not match hash")
        }

        @JvmStatic
        fun candidatesFrom(nickname: String, minNicknameLength: Int = 3, maxNicknameLength: Int = 32): List<Username> {
            val joined = Native.run(Native.HANDLE_CANDIDATES, Native.args(nickname.utf8()), Native.nums(minNicknameLength.toLong(), maxNicknameLength.toLong())).string()
            return if (joined.isEmpty()) emptyList() else joined.split('\n').map { Username(it) }
        }

        @JvmStatic
        fun fromParts(nickname: String, discriminator: String, minNicknameLength: Int = 3, maxNicknameLength: Int = 32): Username {
            val reply = Native.run(Native.HANDLE_FROM_PARTS, Native.args(nickname.utf8(), discriminator.utf8()), Native.nums(minNicknameLength.toLong(), maxNicknameLength.toLong()))
            return Username(reply.string())
        }

        @JvmStatic
        fun fromLink(encryptedUsername: ByteArray, entropy: ByteArray): Username =
            Username(Native.run(Native.HANDLE_LINK_OPEN, Native.args(entropy, encryptedUsername)).string())
    }
}

object AccountEntropyPool {
    @JvmStatic
    fun generate(): String = Native.run(Native.POOL_RANDOM).string()

    @JvmStatic
    fun isValid(pool: String): Boolean = Native.run(Native.POOL_VALID, Native.args(pool.utf8())).flag()

    @JvmStatic
    fun deriveSvrKey(pool: String): ByteArray = Native.run(Native.POOL_DERIVE, Native.args(pool.utf8())).bytes()

    @JvmStatic
    fun deriveBackupKey(pool: String): BackupKey {
        val reply = Native.run(Native.POOL_DERIVE, Native.args(pool.utf8()))
        reply.bytes()
        return BackupKey(reply.bytes())
    }
}

class BackupKey(contents: ByteArray) {
    val bytes: ByteArray = contents.copyOf()

    init {
        require(bytes.size == SIZE) { "a backup key is 32 bytes" }
    }

    fun serialize(): ByteArray = bytes.copyOf()

    fun deriveBackupId(aci: ServiceId.Aci): ByteArray = Native.run(Native.BACKUP_KEY_FOR_ACCOUNT, Native.args(bytes, aci.toServiceIdString().utf8())).bytes()

    fun deriveEcKey(aci: ServiceId.Aci): ECPrivateKey {
        val reply = Native.run(Native.BACKUP_KEY_FOR_ACCOUNT, Native.args(bytes, aci.toServiceIdString().utf8()))
        reply.bytes()
        return ECPrivateKey(reply.bytes(), true)
    }

    fun deriveLocalBackupMetadataKey(): ByteArray = Native.run(Native.BACKUP_KEY_LOCAL_METADATA, Native.args(bytes)).bytes()

    fun deriveMediaId(mediaName: String): ByteArray = Native.run(Native.BACKUP_KEY_MEDIA, Native.args(bytes, mediaName.utf8())).bytes()

    fun deriveMediaEncryptionKey(mediaId: ByteArray): ByteArray = Native.run(Native.BACKUP_KEY_MEDIA_KEYS, Native.args(bytes, mediaId)).bytes()

    fun deriveThumbnailTransitEncryptionKey(mediaId: ByteArray): ByteArray {
        val reply = Native.run(Native.BACKUP_KEY_MEDIA_KEYS, Native.args(bytes, mediaId))
        reply.bytes()
        return reply.bytes()
    }

    companion object {
        const val SIZE = 32

        @JvmStatic
        fun generateRandom(): BackupKey = BackupKey(Native.run(Native.BACKUP_KEY_RANDOM).bytes())
    }
}

class GroupMasterKey(contents: ByteArray) {
    val bytes: ByteArray = contents.copyOf()

    init {
        require(bytes.size == SIZE) { "a group master key is 32 bytes" }
    }

    fun serialize(): ByteArray = bytes.copyOf()

    override fun equals(other: Any?): Boolean = other is GroupMasterKey && bytes.contentEquals(other.bytes)

    override fun hashCode(): Int = bytes.contentHashCode()

    companion object {
        const val SIZE = 32

        @JvmStatic
        fun generate(): GroupMasterKey = GroupMasterKey(Native.run(Native.CIRCLE_MASTER_RANDOM).bytes())
    }
}

class GroupSecretParams(contents: ByteArray) {
    val bytes: ByteArray = contents.copyOf()

    init {
        Native.run(Native.CIRCLE_PARAMS_INFO, Native.args(bytes))
    }

    fun serialize(): ByteArray = bytes.copyOf()

    private fun info(): Reply = Native.run(Native.CIRCLE_PARAMS_INFO, Native.args(bytes))

    val masterKey: GroupMasterKey get() = GroupMasterKey(info().bytes())

    val groupIdentifier: ByteArray
        get() {
            val reply = info()
            reply.bytes()
            return reply.bytes()
        }

    val publicParams: ByteArray
        get() {
            val reply = info()
            reply.bytes()
            reply.bytes()
            return reply.bytes()
        }

    companion object {
        @JvmStatic
        fun deriveFromMasterKey(masterKey: GroupMasterKey): GroupSecretParams =
            GroupSecretParams(Native.run(Native.CIRCLE_SECRET_PARAMS, Native.args(masterKey.bytes)).bytes())

        @JvmStatic
        fun generate(): GroupSecretParams = deriveFromMasterKey(GroupMasterKey.generate())
    }
}

object HKDF {
    @JvmStatic
    fun deriveSecrets(inputKeyMaterial: ByteArray, info: ByteArray, outputLength: Int): ByteArray =
        Native.run(Native.HKDF, Native.args(inputKeyMaterial, null, info), Native.nums(0, outputLength.toLong())).bytes()

    @JvmStatic
    fun deriveSecrets(inputKeyMaterial: ByteArray, salt: ByteArray, info: ByteArray, outputLength: Int): ByteArray =
        Native.run(Native.HKDF, Native.args(inputKeyMaterial, salt, info), Native.nums(1, outputLength.toLong())).bytes()
}

class Aes256GcmSiv(key: ByteArray) {
    private val key: ByteArray = key.copyOf()

    init {
        if (key.size != 32) throw InvalidKeyException("a key is 32 bytes")
    }

    fun encrypt(plaintext: ByteArray, nonce: ByteArray, associatedData: ByteArray = ByteArray(0)): ByteArray =
        Native.run(Native.SIV_SEAL, Native.args(key, nonce, plaintext, associatedData)).bytes()

    @Throws(InvalidMessageException::class)
    fun decrypt(ciphertext: ByteArray, nonce: ByteArray, associatedData: ByteArray = ByteArray(0)): ByteArray =
        Native.run(Native.SIV_OPEN, Native.args(key, nonce, ciphertext, associatedData)).bytes()
}

object IncrementalMac {
    @JvmStatic
    fun calculate(key: ByteArray, chunkSize: Int, data: ByteArray): ByteArray =
        Native.run(Native.CHUNK_TAGS, Native.args(key, data), Native.nums(chunkSize.toLong())).bytes()

    @JvmStatic
    @Throws(InvalidMessageException::class)
    fun validate(key: ByteArray, chunkSize: Int, data: ByteArray, digest: ByteArray) {
        Native.run(Native.CHUNK_CHECK, Native.args(key, data, digest), Native.nums(chunkSize.toLong()))
    }
}

fun randomBytes(length: Int): ByteArray = Native.run(Native.RANDOM, nums = Native.nums(length.toLong())).bytes()

fun abiVersion(): Int = Native.run(Native.ABI_VERSION).u32()

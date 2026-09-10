package com.gossveil

import java.time.Instant
import java.util.UUID

private fun nowSecs(now: Instant = Instant.now()): Long = maxOf(0L, now.epochSecond)

private fun untrusted(address: ProtocolAddress, identity: IdentityKey) = UntrustedIdentityException(address.name, identity)

/** Starts a session with a remote device from its published bundle. */
class SessionBuilder(
    private val sessionStore: SessionStore,
    @Suppress("UNUSED_PARAMETER") preKeyStore: PreKeyStore,
    @Suppress("UNUSED_PARAMETER") signedPreKeyStore: SignedPreKeyStore,
    private val identityKeyStore: IdentityKeyStore,
    private val remoteAddress: ProtocolAddress,
) {
    constructor(store: ProtocolStore, remoteAddress: ProtocolAddress) : this(store, store, store, store, remoteAddress)

    @Throws(InvalidKeyException::class, UntrustedIdentityException::class)
    fun process(bundle: PreKeyBundle, now: Instant = Instant.now(), localAddress: ProtocolAddress? = null) {
        if (!identityKeyStore.isTrustedIdentity(remoteAddress, bundle.identityKey, IdentityKeyStore.Direction.SENDING)) {
            throw untrusted(remoteAddress, bundle.identityKey)
        }
        val us = identityKeyStore.getIdentityKeyPair()
        val existing = sessionStore.loadSession(remoteAddress)?.bytes
        val offered = bundle.preKey != null && bundle.preKeyId != PreKeyBundle.NULL_PRE_KEY_ID
        val record = Native.run(
            Native.SESSION_START,
            Native.args(us.privateKey.bytes, existing, bundle.preKey?.bytes, bundle.signedPreKey.bytes, bundle.signedPreKeySignature, bundle.identityKey.publicKey.bytes, bundle.kyberPreKey.bytes, bundle.kyberPreKeySignature),
            Native.nums(
                identityKeyStore.getLocalRegistrationId().toLong(),
                bundle.registrationId.toLong(),
                bundle.deviceId.toLong(),
                if (offered) bundle.preKeyId.toLong() else -1L,
                bundle.signedPreKeyId.toLong(),
                bundle.kyberPreKeyId.toLong(),
                nowSecs(now),
            ),
        ).bytes()
        identityKeyStore.saveIdentity(remoteAddress, bundle.identityKey)
        sessionStore.storeSession(remoteAddress, SessionRecord(record, true))
    }
}

/** Encrypts and decrypts over the session with one remote device. */
class SessionCipher(
    private val sessionStore: SessionStore,
    private val preKeyStore: PreKeyStore,
    private val signedPreKeyStore: SignedPreKeyStore,
    private val kyberPreKeyStore: KyberPreKeyStore,
    private val identityKeyStore: IdentityKeyStore,
    private val remoteAddress: ProtocolAddress,
) {
    constructor(store: ProtocolStore, remoteAddress: ProtocolAddress) : this(store, store, store, store, store, remoteAddress)

    var localAddress: ProtocolAddress? = null

    private fun localDevice(): Long = (localAddress?.deviceId ?: 0).toLong()

    @Throws(NoSessionException::class, UntrustedIdentityException::class)
    fun encrypt(paddedMessage: ByteArray, now: Instant = Instant.now()): CiphertextMessage {
        val session = sessionStore.loadSession(remoteAddress) ?: throw NoSessionException(remoteAddress, "no session")
        val reply = Native.run(
            Native.SESSION_SEAL,
            Native.args(session.bytes, paddedMessage, localAddress?.name?.utf8(), remoteAddress.name.utf8()),
            Native.nums(nowSecs(now), localDevice(), remoteAddress.deviceId.toLong()),
        )
        val kind = reply.u8()
        val sealed = reply.bytes()
        val record = SessionRecord(reply.bytes(), true)
        val theirIdentity = record.remoteIdentityKey
        if (!identityKeyStore.isTrustedIdentity(remoteAddress, theirIdentity, IdentityKeyStore.Direction.SENDING)) {
            throw untrusted(remoteAddress, theirIdentity)
        }
        sessionStore.storeSession(remoteAddress, record)
        return RawCiphertextMessage(kind, sealed)
    }

    @Throws(InvalidMessageException::class, DuplicateMessageException::class, NoSessionException::class, UntrustedIdentityException::class)
    fun decrypt(message: WhisperMessage): ByteArray {
        val session = sessionStore.loadSession(remoteAddress) ?: throw NoSessionException(remoteAddress, "no session")
        val reply = Native.run(
            Native.SESSION_OPEN,
            Native.args(session.bytes, message.serialize(), remoteAddress.name.utf8(), localAddress?.name?.utf8()),
            Native.nums(remoteAddress.deviceId.toLong(), localDevice()),
        )
        val plain = reply.bytes()
        commit(SessionRecord(reply.bytes(), true))
        return plain
    }

    @Throws(InvalidMessageException::class, DuplicateMessageException::class, InvalidKeyIdException::class, InvalidKeyException::class, UntrustedIdentityException::class)
    fun decrypt(message: PreKeyMessage): ByteArray {
        if (!identityKeyStore.isTrustedIdentity(remoteAddress, message.identityKey, IdentityKeyStore.Direction.RECEIVING)) {
            throw untrusted(remoteAddress, message.identityKey)
        }
        val us = identityKeyStore.getIdentityKeyPair()
        val existing = sessionStore.loadSession(remoteAddress)?.bytes
        val signed = signedPreKeyStore.loadSignedPreKey(message.signedPreKeyId).bytes
        val oneTime = message.preKeyId?.let { preKeyStore.loadPreKey(it).bytes }
        val pqId = message.kyberPreKeyId
        val pq = pqId?.let { kyberPreKeyStore.loadKyberPreKey(it).bytes }
        val reply = Native.run(
            Native.SESSION_OPEN_FIRST,
            Native.args(us.privateKey.bytes, existing, message.serialize(), signed, oneTime, pq, remoteAddress.name.utf8(), localAddress?.name?.utf8()),
            Native.nums(identityKeyStore.getLocalRegistrationId().toLong(), remoteAddress.deviceId.toLong(), localDevice()),
        )
        val plain = reply.bytes()
        val record = SessionRecord(reply.bytes(), true)
        val consumed = reply.fields()
        commit(record)
        if (consumed.flag(0)) {
            val oneTimeId = consumed.i64(8)
            if (oneTimeId >= 0) preKeyStore.removePreKey(oneTimeId.toInt())
            if (pqId != null) kyberPreKeyStore.markKyberPreKeyUsed(pqId, consumed.u32(16), ECPublicKey(consumed.bytes(24, 33), true))
        }
        return plain
    }

    fun getRemoteRegistrationId(): Int = (sessionStore.loadSession(remoteAddress) ?: throw IllegalStateException("no session")).remoteRegistrationId

    fun getSessionVersion(): Int = (sessionStore.loadSession(remoteAddress) ?: throw IllegalStateException("no session")).sessionVersion

    private fun commit(record: SessionRecord) {
        val theirIdentity = record.remoteIdentityKey
        if (!identityKeyStore.isTrustedIdentity(remoteAddress, theirIdentity, IdentityKeyStore.Direction.RECEIVING)) {
            throw untrusted(remoteAddress, theirIdentity)
        }
        identityKeyStore.saveIdentity(remoteAddress, theirIdentity)
        sessionStore.storeSession(remoteAddress, record)
    }
}

/** Sender keys: one distribution per group, processed by every member. */
class GroupSessionBuilder(private val senderKeyStore: SenderKeyStore) {
    @Throws(InvalidMessageException::class)
    fun process(sender: ProtocolAddress, message: SenderKeyDistributionMessage) {
        val existing = senderKeyStore.loadSenderKey(sender, message.distributionId)?.bytes
        val record = Native.run(Native.CIRCLE_ADMIT, Native.args(existing, message.serialize())).bytes()
        senderKeyStore.storeSenderKey(sender, message.distributionId, SenderKeyRecord(record))
    }

    fun create(sender: ProtocolAddress, distributionId: UUID): SenderKeyDistributionMessage {
        val existing = senderKeyStore.loadSenderKey(sender, distributionId)?.bytes
        val reply = Native.run(Native.CIRCLE_ANNOUNCE, Native.args(existing, ServiceId.uuidBytes(distributionId)))
        senderKeyStore.storeSenderKey(sender, distributionId, SenderKeyRecord(reply.bytes()))
        return SenderKeyDistributionMessage(reply.bytes())
    }
}

class GroupCipher(private val senderKeyStore: SenderKeyStore, private val sender: ProtocolAddress) {
    @Throws(NoSessionException::class)
    fun encrypt(distributionId: UUID, paddedPlaintext: ByteArray): CiphertextMessage {
        val record = senderKeyStore.loadSenderKey(sender, distributionId) ?: throw NoSessionException(sender, "no sender key for $distributionId")
        val reply = Native.run(Native.CIRCLE_SEAL, Native.args(record.bytes, ServiceId.uuidBytes(distributionId), paddedPlaintext))
        val note = reply.bytes()
        senderKeyStore.storeSenderKey(sender, distributionId, SenderKeyRecord(reply.bytes()))
        return RawCiphertextMessage(CiphertextMessage.SENDERKEY_TYPE, note)
    }

    @Throws(InvalidMessageException::class, DuplicateMessageException::class, NoSessionException::class)
    fun decrypt(senderKeyMessageBytes: ByteArray): ByteArray {
        val distributionId = SenderKeyMessage(senderKeyMessageBytes).distributionId
        val record = senderKeyStore.loadSenderKey(sender, distributionId) ?: throw NoSessionException(sender, "no sender key for $distributionId")
        val reply = Native.run(Native.CIRCLE_OPEN, Native.args(record.bytes, senderKeyMessageBytes))
        val plain = reply.bytes()
        senderKeyStore.storeSenderKey(sender, distributionId, SenderKeyRecord(reply.bytes()))
        return plain
    }
}

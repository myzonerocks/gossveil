package com.gossveil

import java.util.UUID

/** Every store in one object, in memory. Trust is on first use. */
class InMemoryProtocolStore(
    private val identityKeyPair: IdentityKeyPair = IdentityKeyPair.generate(),
    private val registrationId: Int = (1..16380).random(),
) : ProtocolStore {
    private val identities = HashMap<ProtocolAddress, IdentityKey>()
    private val preKeys = HashMap<Int, PreKeyRecord>()
    private val signedPreKeys = HashMap<Int, SignedPreKeyRecord>()
    private val kyberPreKeys = HashMap<Int, KyberPreKeyRecord>()
    private val kyberUsed = HashSet<Int>()
    private val sessions = HashMap<ProtocolAddress, SessionRecord>()
    private val senderKeys = HashMap<Pair<ProtocolAddress, UUID>, SenderKeyRecord>()

    override fun getIdentityKeyPair(): IdentityKeyPair = identityKeyPair

    override fun getLocalRegistrationId(): Int = registrationId

    override fun saveIdentity(address: ProtocolAddress, identityKey: IdentityKey): IdentityKeyStore.IdentityChange {
        val previous = identities.put(address, identityKey)
        return if (previous != null && previous != identityKey) IdentityKeyStore.IdentityChange.REPLACED_EXISTING else IdentityKeyStore.IdentityChange.NEW_OR_UNCHANGED
    }

    override fun isTrustedIdentity(address: ProtocolAddress, identityKey: IdentityKey, direction: IdentityKeyStore.Direction): Boolean {
        val known = identities[address] ?: return true
        return known == identityKey
    }

    override fun getIdentity(address: ProtocolAddress): IdentityKey? = identities[address]

    override fun loadPreKey(preKeyId: Int): PreKeyRecord = preKeys[preKeyId] ?: throw InvalidKeyIdException("no prekey $preKeyId")

    override fun storePreKey(preKeyId: Int, record: PreKeyRecord) {
        preKeys[preKeyId] = record
    }

    override fun containsPreKey(preKeyId: Int): Boolean = preKeys.containsKey(preKeyId)

    override fun removePreKey(preKeyId: Int) {
        preKeys.remove(preKeyId)
    }

    override fun loadSignedPreKey(signedPreKeyId: Int): SignedPreKeyRecord = signedPreKeys[signedPreKeyId] ?: throw InvalidKeyIdException("no signed prekey $signedPreKeyId")

    override fun loadSignedPreKeys(): List<SignedPreKeyRecord> = signedPreKeys.values.toList()

    override fun storeSignedPreKey(signedPreKeyId: Int, record: SignedPreKeyRecord) {
        signedPreKeys[signedPreKeyId] = record
    }

    override fun containsSignedPreKey(signedPreKeyId: Int): Boolean = signedPreKeys.containsKey(signedPreKeyId)

    override fun removeSignedPreKey(signedPreKeyId: Int) {
        signedPreKeys.remove(signedPreKeyId)
    }

    override fun loadKyberPreKey(kyberPreKeyId: Int): KyberPreKeyRecord = kyberPreKeys[kyberPreKeyId] ?: throw InvalidKeyIdException("no kyber prekey $kyberPreKeyId")

    override fun loadKyberPreKeys(): List<KyberPreKeyRecord> = kyberPreKeys.values.toList()

    override fun storeKyberPreKey(kyberPreKeyId: Int, record: KyberPreKeyRecord) {
        kyberPreKeys[kyberPreKeyId] = record
    }

    override fun containsKyberPreKey(kyberPreKeyId: Int): Boolean = kyberPreKeys.containsKey(kyberPreKeyId)

    override fun markKyberPreKeyUsed(kyberPreKeyId: Int, signedPreKeyId: Int, baseKey: ECPublicKey) {
        kyberUsed.add(kyberPreKeyId)
    }

    fun hasKyberPreKeyBeenUsed(kyberPreKeyId: Int): Boolean = kyberUsed.contains(kyberPreKeyId)

    override fun loadSession(address: ProtocolAddress): SessionRecord? = sessions[address]

    override fun loadExistingSessions(addresses: List<ProtocolAddress>): List<SessionRecord> =
        addresses.map { sessions[it] ?: throw NoSessionException(it, "no session") }

    override fun getSubDeviceSessions(name: String): List<Int> =
        sessions.keys.filter { it.name == name && it.deviceId != 1 }.map { it.deviceId }

    override fun storeSession(address: ProtocolAddress, record: SessionRecord) {
        sessions[address] = record
    }

    override fun containsSession(address: ProtocolAddress): Boolean = sessions.containsKey(address)

    override fun deleteSession(address: ProtocolAddress) {
        sessions.remove(address)
    }

    override fun deleteAllSessions(name: String) {
        sessions.keys.filter { it.name == name }.forEach { sessions.remove(it) }
    }

    override fun storeSenderKey(sender: ProtocolAddress, distributionId: UUID, record: SenderKeyRecord) {
        senderKeys[sender to distributionId] = record
    }

    override fun loadSenderKey(sender: ProtocolAddress, distributionId: UUID): SenderKeyRecord? = senderKeys[sender to distributionId]
}

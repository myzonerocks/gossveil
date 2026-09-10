package com.gossveil

import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class GossveilTest {
    private fun publish(store: InMemoryProtocolStore, oneTimeId: Int?): PreKeyBundle {
        val identity = store.getIdentityKeyPair()
        val signed = ECKeyPair.generate()
        val pq = KEMKeyPair.generate(KEMKeyType.KYBER_1024)
        val now = System.currentTimeMillis()
        val signedSig = identity.privateKey.calculateSignature(signed.publicKey.serialize())
        val pqSig = identity.privateKey.calculateSignature(pq.publicKey.serialize())
        store.storeSignedPreKey(1, SignedPreKeyRecord(1, now, signed, signedSig))
        store.storeKyberPreKey(1, KyberPreKeyRecord(1, now, pq, pqSig))
        var oneTime: ECKeyPair? = null
        if (oneTimeId != null) {
            oneTime = ECKeyPair.generate()
            store.storePreKey(oneTimeId, PreKeyRecord(oneTimeId, oneTime))
        }
        return PreKeyBundle(
            store.getLocalRegistrationId(), 1,
            oneTimeId ?: PreKeyBundle.NULL_PRE_KEY_ID, oneTime?.publicKey,
            1, signed.publicKey, signedSig,
            identity.publicKey,
            1, pq.publicKey, pqSig,
        )
    }

    /** The Android client's wire framing: one type byte and the body. */
    private fun encrypt(plaintext: ByteArray, peer: ProtocolAddress, store: ProtocolStore): ByteArray {
        val ciphertext = SessionCipher(store, store, store, store, store, peer).encrypt(plaintext)
        val body = ciphertext.serialize()
        val wire = ByteArray(body.size + 1)
        wire[0] = ciphertext.type.toByte()
        System.arraycopy(body, 0, wire, 1, body.size)
        return wire
    }

    private fun decrypt(wire: ByteArray, peer: ProtocolAddress, store: ProtocolStore): ByteArray {
        val type = wire[0].toInt() and 0xff
        val body = wire.copyOfRange(1, wire.size)
        val cipher = SessionCipher(store, store, store, store, store, peer)
        return if (type == CiphertextMessage.PREKEY_TYPE) cipher.decrypt(PreKeyMessage(body)) else cipher.decrypt(WhisperMessage(body))
    }

    @Test
    fun sessionsAsTheClientCallsThem() {
        val alice = InMemoryProtocolStore()
        val bob = InMemoryProtocolStore()
        val aliceAddress = ProtocolAddress("alice::device-1", 1)
        val bobAddress = ProtocolAddress("bob::device-2", 1)
        SessionBuilder(alice, alice, alice, alice, bobAddress).process(publish(bob, null))
        assertTrue(alice.containsSession(bobAddress))

        val first = encrypt("hello bob".toByteArray(), bobAddress, alice)
        assertEquals(CiphertextMessage.PREKEY_TYPE, first[0].toInt())
        assertContentEquals("hello bob".toByteArray(), decrypt(first, aliceAddress, bob))
        assertTrue(bob.hasKyberPreKeyBeenUsed(1))

        val reply = encrypt("hi alice".toByteArray(), aliceAddress, bob)
        assertEquals(CiphertextMessage.WHISPER_TYPE, reply[0].toInt())
        assertContentEquals("hi alice".toByteArray(), decrypt(reply, bobAddress, alice))
        assertFailsWith<DuplicateMessageException> { decrypt(reply, bobAddress, alice) }

        val later = encrypt("later".toByteArray(), bobAddress, alice)
        assertEquals(CiphertextMessage.WHISPER_TYPE, later[0].toInt())
        assertContentEquals("later".toByteArray(), decrypt(later, aliceAddress, bob))

        val record = assertNotNull(alice.loadSession(bobAddress))
        val reloaded = SessionRecord(record.serialize())
        assertTrue(reloaded.hasSenderChain())
        assertEquals(bob.getLocalRegistrationId(), reloaded.remoteRegistrationId)
        assertEquals(bob.getIdentityKeyPair().publicKey, reloaded.remoteIdentityKey)
        assertEquals(bob.getLocalRegistrationId(), SessionCipher(alice, bobAddress).getRemoteRegistrationId())
        reloaded.archiveCurrentState()
        assertFalse(reloaded.hasSenderChain())
    }

    @Test
    fun oneTimeKeyConsumedAndChangedIdentityRefused() {
        val alice = InMemoryProtocolStore()
        val bob = InMemoryProtocolStore()
        val aliceAddress = ProtocolAddress("alice", 1)
        val bobAddress = ProtocolAddress("bob", 1)
        SessionBuilder(alice, bobAddress).process(publish(bob, 7))
        val message = SessionCipher(alice, bobAddress).encrypt("one".toByteArray())
        val parsed = PreKeyMessage(message.serialize())
        assertEquals(7, parsed.preKeyId)
        assertEquals(1, parsed.kyberPreKeyId)
        assertEquals(alice.getIdentityKeyPair().publicKey, parsed.identityKey)
        assertContentEquals("one".toByteArray(), SessionCipher(bob, aliceAddress).decrypt(parsed))
        assertFalse(bob.containsPreKey(7))
        assertFailsWith<InvalidKeyIdException> { bob.loadPreKey(7) }

        val impostor = InMemoryProtocolStore()
        SessionBuilder(impostor, bobAddress).process(publish(bob, null))
        val forged = SessionCipher(impostor, bobAddress).encrypt("forged".toByteArray())
        assertFailsWith<UntrustedIdentityException> { SessionCipher(bob, aliceAddress).decrypt(PreKeyMessage(forged.serialize())) }
    }

    @Test
    fun groupsOverSenderKeys() {
        val alice = InMemoryProtocolStore()
        val bob = InMemoryProtocolStore()
        val aliceAddress = ProtocolAddress("alice", 2)
        val distributionId = UUID.randomUUID()
        val distribution = GroupSessionBuilder(alice).create(aliceAddress, distributionId)
        assertEquals(distributionId, distribution.distributionId)
        GroupSessionBuilder(bob).process(aliceAddress, SenderKeyDistributionMessage(distribution.serialize()))
        val one = GroupCipher(alice, aliceAddress).encrypt(distributionId, "one".toByteArray())
        val two = GroupCipher(alice, aliceAddress).encrypt(distributionId, "two".toByteArray())
        assertEquals(CiphertextMessage.SENDERKEY_TYPE, one.type)
        assertEquals(1, SenderKeyMessage(two.serialize()).iteration)
        assertContentEquals("two".toByteArray(), GroupCipher(bob, aliceAddress).decrypt(two.serialize()))
        assertContentEquals("one".toByteArray(), GroupCipher(bob, aliceAddress).decrypt(one.serialize()))
        assertFailsWith<DuplicateMessageException> { GroupCipher(bob, aliceAddress).decrypt(one.serialize()) }
    }

    @Test
    fun sealedSenderBothForms() {
        val trustRoot = ECKeyPair.generate()
        val serverKey = ECKeyPair.generate()
        val serverCertificate = ServerCertificate(1, serverKey.publicKey, trustRoot.privateKey)
        val aliceUuid = UUID.randomUUID().toString()
        val bobUuid = UUID.randomUUID().toString()
        val alice = InMemoryProtocolStore()
        val bob = InMemoryProtocolStore()
        val aliceAddress = ProtocolAddress(aliceUuid, 1)
        val bobAddress = ProtocolAddress(bobUuid, 1)
        val aliceCert = SenderCertificate(aliceUuid, "+14151111111", 1, alice.getIdentityKeyPair().publicKey.publicKey, 31337, serverCertificate, serverKey.privateKey)
        assertTrue(aliceCert.validate(trustRoot.publicKey, 31336))
        assertFalse(aliceCert.validate(trustRoot.publicKey, 31338))
        assertEquals("+14151111111", aliceCert.senderE164)
        assertEquals(1, aliceCert.serverCertificate.keyId)

        SessionBuilder(alice, bobAddress).process(publish(bob, null))
        val aliceCipher = SealedSessionCipher(alice, aliceUuid, null, 1)
        val bobCipher = SealedSessionCipher(bob, bobUuid, null, 1)
        val envelope = aliceCipher.encrypt(bobAddress, aliceCert, "sealed".toByteArray())
        val opened = bobCipher.decrypt(trustRoot.publicKey, envelope, 31335)
        assertContentEquals("sealed".toByteArray(), opened.paddedMessage)
        assertEquals(aliceUuid, opened.senderUuid)

        val reply = SessionCipher(bob, aliceAddress).encrypt("reply".toByteArray())
        val bobCert = SenderCertificate(bobUuid, null, 1, bob.getIdentityKeyPair().publicKey.publicKey, 31337, serverCertificate, serverKey.privateKey)
        val content = UnidentifiedSenderMessageContent(reply, bobCert, UnidentifiedSenderMessageContent.ContentHint.RESENDABLE, byteArrayOf(1, 2, 3))
        val sent = bobCipher.multiRecipientEncrypt(listOf(aliceAddress), content)
        val single = SealedSessionCipher.multiRecipientMessageForSingleRecipient(sent)
        assertContentEquals(single, SealedSessionCipher.multiRecipientMessageForRecipient(sent, ServiceId.parseFromString(aliceUuid), 1))
        val inner = aliceCipher.decryptToUsmc(single)
        assertEquals(UnidentifiedSenderMessageContent.ContentHint.RESENDABLE, inner.contentHint)
        assertContentEquals(byteArrayOf(1, 2, 3), inner.groupId)
        assertEquals(CiphertextMessage.WHISPER_TYPE, inner.type)
        assertContentEquals("reply".toByteArray(), aliceCipher.decrypt(trustRoot.publicKey, single, 31335).paddedMessage)
        assertFailsWith<InvalidMessageException> { bobCipher.decrypt(trustRoot.publicKey, single, 31335) }
    }

    @Test
    fun keysRecordsAndHelpers() {
        val pair = IdentityKeyPair.generate()
        val round = IdentityKeyPair(pair.serialize())
        assertEquals(pair.publicKey, round.publicKey)
        assertContentEquals(pair.privateKey.serialize(), round.privateKey.serialize())
        val signature = pair.privateKey.calculateSignature("m".toByteArray())
        assertTrue(pair.publicKey.publicKey.verifySignature("m".toByteArray(), signature))
        assertFalse(pair.publicKey.publicKey.verifySignature("x".toByteArray(), signature))
        assertFailsWith<InvalidKeyException> { ECPublicKey(byteArrayOf(5, 1, 2)) }
        val other = IdentityKeyPair.generate()
        assertContentEquals(pair.privateKey.calculateAgreement(other.publicKey.publicKey), other.privateKey.calculateAgreement(pair.publicKey.publicKey))
        assertTrue(other.publicKey.verifyAlternateIdentity(pair.publicKey, other.signAlternateIdentity(pair.publicKey)))
        assertFalse(pair.publicKey.verifyAlternateIdentity(other.publicKey, other.signAlternateIdentity(pair.publicKey)))

        val pq = KEMKeyPair.generate()
        val (secret, capsule) = pq.publicKey.encapsulate()
        assertContentEquals(secret, pq.secretKey.decapsulate(capsule))
        assertEquals(pq.publicKey, KEMPublicKey(pq.publicKey.serialize()))

        val record = PreKeyRecord(9, ECKeyPair(pair.publicKey.publicKey, pair.privateKey))
        assertEquals(9, PreKeyRecord(record.serialize()).id)
        assertEquals(pair.publicKey.publicKey, record.keyPair.publicKey)
        val signed = SignedPreKeyRecord(4, 1234, ECKeyPair(pair.publicKey.publicKey, pair.privateKey), signature)
        assertEquals(1234, SignedPreKeyRecord(signed.serialize()).timestamp)
        assertContentEquals(signature, signed.signature)
        val pqRecord = KyberPreKeyRecord(5, 99, pq, signature)
        assertEquals(pq.publicKey, KyberPreKeyRecord(pqRecord.serialize()).keyPair.publicKey)

        val ours = NumericFingerprintGenerator(5200).createFor(2, "alice".toByteArray(), pair.publicKey, "bob".toByteArray(), other.publicKey)
        val theirs = NumericFingerprintGenerator(5200).createFor(2, "bob".toByteArray(), other.publicKey, "alice".toByteArray(), pair.publicKey)
        assertEquals(ours.displayableFingerprint.displayText, theirs.displayableFingerprint.displayText)
        assertEquals(60, ours.displayableFingerprint.displayText.length)
        assertTrue(ours.scannableFingerprint.compareTo(theirs.scannableFingerprint.serialize()))

        val username = Username("jimio.01")
        Username.verifyProof(username.generateProof(), username.hash)
        assertFailsWith<VerificationFailedException> { Username.verifyProof(Username("jimio.02").generateProof(), username.hash) }
        val link = username.generateLink()
        assertEquals(username, Username.fromLink(link.encryptedUsername, link.entropy))
        assertTrue(Username.candidatesFrom("jimio").isNotEmpty())
        assertEquals("jimio.01", Username.fromParts("jimio", "01").username)
        assertFailsWith<Exception> { Username("1bad.01") }

        val pool = AccountEntropyPool.generate()
        assertTrue(AccountEntropyPool.isValid(pool))
        val backupKey = AccountEntropyPool.deriveBackupKey(pool)
        val aci = ServiceId.Aci(UUID.randomUUID())
        assertEquals(16, backupKey.deriveBackupId(aci).size)
        assertEquals(32, backupKey.deriveEcKey(aci).serialize().size)
        val mediaId = backupKey.deriveMediaId("photo")
        assertEquals(64, backupKey.deriveMediaEncryptionKey(mediaId).size)

        val params = GroupSecretParams.generate()
        assertContentEquals(params.serialize(), GroupSecretParams.deriveFromMasterKey(params.masterKey).serialize())
        assertEquals(32, params.groupIdentifier.size)

        val key = randomBytes(32)
        val siv = Aes256GcmSiv(key)
        val nonce = randomBytes(12)
        assertContentEquals("plain".toByteArray(), siv.decrypt(siv.encrypt("plain".toByteArray(), nonce, "ad".toByteArray()), nonce, "ad".toByteArray()))
        assertFailsWith<InvalidMessageException> { siv.decrypt(siv.encrypt("plain".toByteArray(), nonce), nonce, "x".toByteArray()) }
        assertEquals(42, HKDF.deriveSecrets(key, "info".toByteArray(), 42).size)
        val macs = IncrementalMac.calculate(key, 8, ByteArray(20) { 7 })
        IncrementalMac.validate(key, 8, ByteArray(20) { 7 }, macs)
        assertFailsWith<InvalidMessageException> { IncrementalMac.validate(key, 8, ByteArray(20) { 8 }, macs) }

        val report = DecryptionErrorMessage.forOriginalMessage(byteArrayOf(1, 2, 3), CiphertextMessage.SENDERKEY_TYPE, 5, 2)
        assertEquals(5, report.timestamp)
        assertNull(report.ratchetKey)
        val content = PlaintextContent(report)
        assertEquals(2, DecryptionErrorMessage.extractFromSerializedContent(content.body).deviceId)

        val pni = ServiceId.parseFromString("PNI:" + UUID.randomUUID())
        assertEquals(pni, ServiceId.parseFromFixedWidthBinary(pni.toServiceIdFixedWidthBinary()))
        assertEquals(pni, ServiceId.parseFromBinary(pni.toServiceIdBinary()))
        assertEquals(1, abiVersion())
    }

    /** The names the client called before the rename still resolve to the same types. */
    @Test
    fun compatibilityNames() {
        val alice = InMemorySignalProtocolStore()
        val bob = InMemorySignalProtocolStore()
        val aliceAddress = SignalProtocolAddress("alice", 1)
        val bobAddress = SignalProtocolAddress("bob", 1)
        val store: SignalProtocolStore = alice
        SessionBuilder(store, bobAddress).process(publish(bob, null))
        val first = SessionCipher(alice, bobAddress).encrypt("hi".toByteArray())
        assertContentEquals("hi".toByteArray(), SessionCipher(bob, aliceAddress).decrypt(PreKeySignalMessage(first.serialize())))
        val reply = SessionCipher(bob, aliceAddress).encrypt("yo".toByteArray())
        assertContentEquals("yo".toByteArray(), SessionCipher(alice, bobAddress).decrypt(SignalMessage(reply.serialize())))
    }
}

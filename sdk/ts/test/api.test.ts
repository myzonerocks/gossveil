// The record-shaped API over host stores: sessions, groups, sealed envelopes
// in both forms, safety numbers, usernames, account keys, group parameters
// and the primitives.
import { describe, expect, test, beforeAll } from 'bun:test'
import init, {
  Aci,
  AccountEntropyPool,
  Aes256GcmSiv,
  BackupKey,
  CiphertextMessageType,
  ContentHint,
  DecryptionErrorMessage,
  Fingerprint,
  GossveilError,
  GroupMasterKey,
  GroupSecretParams,
  IdentityKeyPair,
  InMemoryProtocolStore,
  IncrementalMac,
  KEMKeyPair,
  KyberPreKeyRecord,
  PlaintextContent,
  PreKeyBundle,
  PreKeyMessage,
  PreKeyRecord,
  PrivateKey,
  ProtocolAddress,
  SenderCertificate,
  SenderKeyDistributionMessage,
  ServerCertificate,
  ServiceId,
  SessionRecord,
  SignedPreKeyRecord,
  UnidentifiedSenderMessageContent,
  WhisperMessage,
  groupDecrypt,
  groupEncrypt,
  hkdf,
  processBundle,
  processSenderKeyDistributionMessage,
  randomBytes,
  sealedSenderDecryptMessage,
  sealedSenderDecryptToUsmc,
  sealedSenderEncryptMessage,
  sealedSenderMultiRecipientEncrypt,
  sealedSenderMultiRecipientMessageForRecipient,
  sealedSenderMultiRecipientMessageForSingleRecipient,
  sessionDecrypt,
  sessionDecryptPreKey,
  sessionEncrypt,
  usernames,
  uuid_to_string,
  generate_uuid,
  abiVersion,
  InMemorySignalProtocolStore,
  PreKeySignalMessage,
  SignalError,
  SignalMessage,
  signalDecrypt,
  signalDecryptPreKey,
  signalEncrypt,
} from '../src/index'

const text = (s: string) => new TextEncoder().encode(s)
const read = (b: Uint8Array) => new TextDecoder().decode(b)

async function publish(store: InMemoryProtocolStore, oneTimeId: number | null) {
  const identity = await store.getIdentityKey()
  const signed = PrivateKey.generate()
  const pq = KEMKeyPair.generate()
  await store.saveSignedPreKey(1, SignedPreKeyRecord.new(1, Date.now(), signed.getPublicKey(), signed, identity.sign(signed.getPublicKey().serialize())))
  await store.saveKyberPreKey(1, KyberPreKeyRecord.new(1, Date.now(), pq, identity.sign(pq.getPublicKey().serialize())))
  let oneTime: PrivateKey | null = null
  if (oneTimeId !== null) {
    oneTime = PrivateKey.generate()
    await store.savePreKey(oneTimeId, PreKeyRecord.new(oneTimeId, oneTime.getPublicKey(), oneTime))
  }
  return PreKeyBundle.new(
    await store.getLocalRegistrationId(), 1,
    oneTimeId, oneTime?.getPublicKey() ?? null,
    1, signed.getPublicKey(), identity.sign(signed.getPublicKey().serialize()),
    identity.getPublicKey(),
    1, pq.getPublicKey(), identity.sign(pq.getPublicKey().serialize()),
  )
}

beforeAll(async () => {
  await init()
})

describe('sessions over host stores', () => {
  test('a conversation both ways with a one-time key, replays refused, records reloaded', async () => {
    const alice = new InMemoryProtocolStore()
    const bob = new InMemoryProtocolStore()
    const aliceAddress = ProtocolAddress.new('alice', 1)
    const bobAddress = ProtocolAddress.new('bob', 1)
    await processBundle(await publish(bob, 7), bobAddress, alice, alice)
    const first = await sessionEncrypt(text('one'), bobAddress, alice, alice)
    expect(first.type()).toBe(CiphertextMessageType.PreKey)
    const parsed = PreKeyMessage.deserialize(first.serialize())
    expect(parsed.preKeyId()).toBe(7)
    expect(parsed.kyberPreKeyId()).toBe(1)
    expect(read(await sessionDecryptPreKey(parsed, aliceAddress, bob, bob, bob, bob, bob))).toBe('one')
    await expect(bob.getPreKey(7)).rejects.toBeInstanceOf(GossveilError)
    expect(bob.hasKyberPreKeyBeenUsed(1)).toBe(true)
    const reply = await sessionEncrypt(text('two'), aliceAddress, bob, bob)
    expect(reply.type()).toBe(CiphertextMessageType.Whisper)
    const whisper = WhisperMessage.deserialize(reply.serialize())
    expect(read(await sessionDecrypt(whisper, bobAddress, alice, alice))).toBe('two')
    await expect(sessionDecrypt(whisper, bobAddress, alice, alice)).rejects.toMatchObject({ kind: 'DuplicatedMessage' })
    const record = (await alice.getSession(bobAddress))!
    const reloaded = SessionRecord.deserialize(record.serialize())
    expect(reloaded.hasCurrentState()).toBe(true)
    expect(reloaded.remoteRegistrationId()).toBe(await bob.getLocalRegistrationId())
    expect(reloaded.remoteIdentityKey().equals((await bob.getIdentityKey()).getPublicKey())).toBe(true)
    // The check is against our own sending ratchet key, so bob's key does not match and alice's next one does.
    expect(reloaded.currentRatchetKeyMatches(whisper.senderRatchetKey())).toBe(false)
    const next = await sessionEncrypt(text('three'), bobAddress, alice, alice)
    expect((await alice.getSession(bobAddress))!.currentRatchetKeyMatches(WhisperMessage.deserialize(next.serialize()).senderRatchetKey())).toBe(true)
    reloaded.archiveCurrentState()
    expect(reloaded.hasCurrentState()).toBe(false)
  })

  test('a changed identity is refused', async () => {
    const alice = new InMemoryProtocolStore()
    const bob = new InMemoryProtocolStore()
    const aliceAddress = ProtocolAddress.new('alice', 1)
    const bobAddress = ProtocolAddress.new('bob', 1)
    await processBundle(await publish(bob, null), bobAddress, alice, alice)
    const msg = await sessionEncrypt(text('hi'), bobAddress, alice, alice)
    await sessionDecryptPreKey(PreKeyMessage.deserialize(msg.serialize()), aliceAddress, bob, bob, bob, bob, bob)
    const impostor = new InMemoryProtocolStore()
    await processBundle(await publish(bob, null), bobAddress, impostor, impostor)
    const forged = await sessionEncrypt(text('forged'), bobAddress, impostor, impostor)
    await expect(sessionDecryptPreKey(PreKeyMessage.deserialize(forged.serialize()), aliceAddress, bob, bob, bob, bob, bob)).rejects.toMatchObject({ kind: 'UntrustedIdentity' })
  })

  test('the names the client called before the rename still work', async () => {
    const alice = new InMemorySignalProtocolStore()
    const bob = new InMemorySignalProtocolStore()
    const aliceAddress = ProtocolAddress.new('alice', 1)
    const bobAddress = ProtocolAddress.new('bob', 1)
    await processBundle(await publish(bob, null), bobAddress, alice, alice)
    const first = await signalEncrypt(text('hi'), bobAddress, alice, alice)
    expect(read(await signalDecryptPreKey(PreKeySignalMessage.deserialize(first.serialize()), aliceAddress, bob, bob, bob, bob, bob))).toBe('hi')
    const reply = await signalEncrypt(text('yo'), aliceAddress, bob, bob)
    expect(read(await signalDecrypt(SignalMessage.deserialize(reply.serialize()), bobAddress, alice, alice))).toBe('yo')
    await expect(signalDecrypt(SignalMessage.deserialize(reply.serialize()), bobAddress, alice, alice)).rejects.toBeInstanceOf(SignalError)
    expect(SignalError).toBe(GossveilError)
  })
})

describe('groups, envelopes and the rest', () => {
  test('sender keys', async () => {
    const alice = new InMemoryProtocolStore()
    const bob = new InMemoryProtocolStore()
    const aliceAddress = ProtocolAddress.new('alice', 2)
    const distributionId = uuid_to_string(generate_uuid())
    const distribution = await SenderKeyDistributionMessage.create(aliceAddress, distributionId, alice)
    expect(distribution.distributionId()).toBe(distributionId)
    await processSenderKeyDistributionMessage(aliceAddress, SenderKeyDistributionMessage.deserialize(distribution.serialize()), bob)
    const one = await groupEncrypt(aliceAddress, distributionId, alice, text('one'))
    const two = await groupEncrypt(aliceAddress, distributionId, alice, text('two'))
    expect(one.type()).toBe(CiphertextMessageType.SenderKey)
    expect(read(await groupDecrypt(aliceAddress, bob, two.serialize()))).toBe('two')
    expect(read(await groupDecrypt(aliceAddress, bob, one.serialize()))).toBe('one')
    await expect(groupDecrypt(aliceAddress, bob, one.serialize())).rejects.toBeInstanceOf(GossveilError)
  })

  test('sealed sender, single and multi-recipient', async () => {
    const trustRoot = PrivateKey.generate()
    const serverKey = PrivateKey.generate()
    const serverCertificate = ServerCertificate.new(1, serverKey.getPublicKey(), trustRoot)
    const aliceUuid = uuid_to_string(generate_uuid())
    const bobUuid = uuid_to_string(generate_uuid())
    const alice = new InMemoryProtocolStore()
    const bob = new InMemoryProtocolStore()
    const aliceAddress = ProtocolAddress.new(aliceUuid, 1)
    const bobAddress = ProtocolAddress.new(bobUuid, 1)
    const aliceCert = SenderCertificate.new(aliceUuid, '+14151111111', 1, (await alice.getIdentityKey()).getPublicKey(), 31337, serverCertificate, serverKey)
    expect(aliceCert.validate(trustRoot.getPublicKey(), 31336)).toBe(true)
    expect(aliceCert.validate(trustRoot.getPublicKey(), 31338)).toBe(false)
    expect(aliceCert.senderE164()).toBe('+14151111111')
    expect(aliceCert.serverCertificate().keyId()).toBe(1)

    await processBundle(await publish(bob, null), bobAddress, alice, alice)
    const envelope = await sealedSenderEncryptMessage(text('sealed'), bobAddress, aliceCert, alice, alice)
    const opened = await sealedSenderDecryptMessage(envelope, trustRoot.getPublicKey(), 31335, null, bobUuid, 1, bob, bob, bob, bob, bob)
    expect(read(opened.message)).toBe('sealed')
    expect(opened.senderUuid).toBe(aliceUuid)
    expect(opened.deviceId).toBe(1)

    const reply = await sessionEncrypt(text('reply'), aliceAddress, bob, bob)
    const bobCert = SenderCertificate.new(bobUuid, null, 1, (await bob.getIdentityKey()).getPublicKey(), 31337, serverCertificate, serverKey)
    const content = UnidentifiedSenderMessageContent.new(reply, bobCert, ContentHint.Resendable, new Uint8Array([1, 2, 3]))
    const sent = await sealedSenderMultiRecipientEncrypt(content, [aliceAddress], bob, bob)
    const single = sealedSenderMultiRecipientMessageForSingleRecipient(sent)
    expect(sealedSenderMultiRecipientMessageForRecipient(sent, ServiceId.parseFromServiceIdString(aliceUuid), 1)).toEqual(single)
    const inner = await sealedSenderDecryptToUsmc(single, alice)
    expect(inner.contentHint()).toBe(ContentHint.Resendable)
    expect(inner.groupId()).toEqual(new Uint8Array([1, 2, 3]))
    expect(inner.msgType()).toBe(CiphertextMessageType.Whisper)
    const plain = await sealedSenderDecryptMessage(single, trustRoot.getPublicKey(), 31335, null, aliceUuid, 1, alice, alice, alice, alice, alice)
    expect(read(plain.message)).toBe('reply')
    await expect(sealedSenderDecryptMessage(single, trustRoot.getPublicKey(), 31335, null, bobUuid, 1, bob, bob, bob, bob, bob)).rejects.toBeInstanceOf(GossveilError)
  })

  test('safety numbers, usernames, account keys, group parameters, primitives', () => {
    const a = IdentityKeyPair.generate()
    const b = IdentityKeyPair.generate()
    expect(IdentityKeyPair.deserialize(a.serialize()).publicKey.equals(a.publicKey)).toBe(true)
    expect(b.publicKey.verifyAlternateIdentity(a.publicKey, b.signAlternateIdentity(a.publicKey))).toBe(true)
    const ours = Fingerprint.new(5200, 2, text('alice'), a.publicKey, text('bob'), b.publicKey)
    const theirs = Fingerprint.new(5200, 2, text('bob'), b.publicKey, text('alice'), a.publicKey)
    expect(ours.displayableFingerprint().toString()).toBe(theirs.displayableFingerprint().toString())
    expect(ours.scannableFingerprint().compare(theirs.scannableFingerprint().toBuffer())).toBe(true)

    const hash = usernames.hash('jimio.01')
    usernames.verifyProof(usernames.generateProof('jimio.01'), hash)
    expect(() => usernames.verifyProof(usernames.generateProof('jimio.02'), hash)).toThrow(GossveilError)
    const link = usernames.createUsernameLink('jimio.01')
    expect(usernames.decryptUsernameLink(link.entropy, link.encryptedUsername)).toBe('jimio.01')
    expect(usernames.generateCandidates('jimio').length).toBeGreaterThan(0)
    expect(usernames.fromParts('jimio', '01').username).toBe('jimio.01')
    expect(() => usernames.hash('1bad.01')).toThrow(GossveilError)

    const pool = AccountEntropyPool.generate()
    expect(AccountEntropyPool.isValid(pool)).toBe(true)
    expect(AccountEntropyPool.deriveSvrKey(pool).length).toBe(32)
    const backupKey = AccountEntropyPool.deriveBackupKey(pool)
    const aci = Aci.fromUuid(uuid_to_string(generate_uuid()))
    expect(backupKey.deriveBackupId(aci).length).toBe(16)
    expect(backupKey.deriveEcKey(aci).serialize().length).toBe(32)
    const mediaId = backupKey.deriveMediaId('photo')
    expect(backupKey.deriveMediaEncryptionKey(mediaId).length).toBe(64)
    expect(BackupKey.generateRandom().serialize().length).toBe(32)

    const params = GroupSecretParams.generate()
    expect(GroupSecretParams.deriveFromMasterKey(params.getMasterKey()).serialize()).toEqual(params.serialize())
    expect(params.getGroupIdentifier().length).toBe(32)
    expect(new GroupMasterKey(params.getMasterKey().serialize()).serialize()).toEqual(params.getMasterKey().serialize())

    const key = randomBytes(32)
    const siv = new Aes256GcmSiv(key)
    const nonce = randomBytes(12)
    expect(read(siv.decrypt(siv.encrypt(text('plain'), nonce, text('ad')), nonce, text('ad')))).toBe('plain')
    expect(() => siv.decrypt(siv.encrypt(text('plain'), nonce, text('ad')), nonce, text('xx'))).toThrow(GossveilError)
    expect(hkdf(42, key, text('info')).length).toBe(42)
    const macs = IncrementalMac.calculate(key, 8, new Uint8Array(20).fill(7))
    IncrementalMac.validate(key, 8, new Uint8Array(20).fill(7), macs)
    expect(() => IncrementalMac.validate(key, 8, new Uint8Array(20).fill(8), macs)).toThrow(GossveilError)

    const report = DecryptionErrorMessage.forOriginal(new Uint8Array([1, 2, 3]), CiphertextMessageType.SenderKey, 5, 2)
    expect(report.timestamp()).toBe(5)
    expect(report.ratchetKey()).toBeUndefined()
    const content = PlaintextContent.from(report)
    expect(DecryptionErrorMessage.extractFromSerializedBody(content.body()).deviceId()).toBe(2)
    expect(PlaintextContent.deserialize(content.serialize()).body()).toEqual(content.body())

    const pni = ServiceId.parseFromServiceIdString(`PNI:${uuid_to_string(generate_uuid())}`)
    expect(ServiceId.parseFromServiceIdFixedWidthBinary(pni.getServiceIdFixedWidthBinary()).equals(pni)).toBe(true)
    expect(ServiceId.parseFromServiceIdBinary(pni.getServiceIdBinary()).equals(pni)).toBe(true)
    expect(() => ProtocolAddress.new('x', 0)).toThrow(GossveilError)
    expect(abiVersion()).toBe(1)
  })
})

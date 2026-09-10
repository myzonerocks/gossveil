// The web client's flow, call for call: keys generated into stores, records
// exported and re-imported, a bundle processed with no one-time key, and the
// wire framing of one type byte and a body.
import { describe, expect, test, beforeAll } from 'bun:test'
import init, {
  init as initRuntime,
  WasmPrivateKey,
  WasmPublicKey,
  WasmIdentityKeyPair,
  WasmProtocolAddress,
  WasmInMemIdentityKeyStore,
  WasmInMemSessionStore,
  WasmInMemPreKeyStore,
  WasmInMemSignedPreKeyStore,
  WasmInMemKyberPreKeyStore,
  WasmInMemSenderKeyStore,
  WasmGroupMasterKey,
  WasmGroupSecretParams,
  encryptMessage,
  decryptMessage,
  processPreKeyBundle,
  generatePreKeys,
  generateSignedPreKey,
  generateKyberPreKey,
  generateRegistrationId,
  generateSafetyNumber,
  verifySafetyNumber,
  createSenderKeyDistribution,
  processSenderKeyDistribution,
  encryptGroupMessage,
  decryptGroupMessage,
  generate_uuid,
  uuid_to_string,
  uuid_from_string,
  generate_random_bytes,
  generate_attachment_key,
  message_type_pre_key,
  message_type_signal,
  message_type_whisper,
  message_type_sender_key,
  GossveilError,
} from '../src/index'
import { core } from '../src/bridge'

const SPK_ID = 1
const KYBER_ID = 1

interface Device {
  uid: string
  did: string
  identity: WasmIdentityKeyPair
  registrationId: number
  stored: Map<string, Uint8Array>
  pkIds: number[]
}

function toAddress(uid: string, did: string): WasmProtocolAddress {
  return new WasmProtocolAddress(`${uid}::${did}`, 1)
}

async function provision(uid: string, did: string): Promise<Device> {
  const privateKey = WasmPrivateKey.generate()
  const privKeyBytes = privateKey.serialize()
  const identity = new WasmIdentityKeyPair(privateKey.getPublicKey(), privateKey)
  expect(WasmPrivateKey.deserialize(privKeyBytes).getPublicKey().serialize()).toEqual(identity.public_key.serialize())
  const stored = new Map<string, Uint8Array>()
  const pkStore = new WasmInMemPreKeyStore()
  const prekeys = await generatePreKeys(1, 5, pkStore)
  const pkIds: number[] = []
  for (const pk of prekeys) {
    stored.set(`pk:${pk.id}`, pk.record)
    pkIds.push(pk.id)
  }
  const spk = await generateSignedPreKey(SPK_ID, identity, new WasmInMemSignedPreKeyStore())
  stored.set(`spk`, spk.record)
  const kpk = await generateKyberPreKey(KYBER_ID, identity, new WasmInMemKyberPreKeyStore())
  stored.set(`kpk`, kpk.record)
  expect(spk.signature.length).toBe(64)
  expect(kpk.public_key.length).toBe(1569)
  expect(typeof kpk.timestamp).toBe('bigint')
  expect(identity.public_key.verify(spk.public_key, spk.signature)).toBe(true)
  return { uid, did, identity, registrationId: generateRegistrationId(), stored, pkIds }
}

// The identity store is rebuilt per call the way the client does it; pinned
// peer identities ride along through export_identity and import_identity.
async function identityStore(d: Device): Promise<WasmInMemIdentityKeyStore> {
  const priv = WasmPrivateKey.deserialize(d.identity.private_key.serialize())
  const store = new WasmInMemIdentityKeyStore(new WasmIdentityKeyPair(priv.getPublicKey(), priv), d.registrationId)
  for (const [key, bytes] of d.stored) {
    if (!key.startsWith('idk:')) continue
    const [name, deviceId] = key.slice(4).split('#')
    await store.import_identity(new WasmProtocolAddress(name, Number(deviceId)), bytes)
  }
  return store
}

async function pinIdentity(d: Device, peer: WasmProtocolAddress, store: WasmInMemIdentityKeyStore): Promise<void> {
  const identity = await store.export_identity(peer)
  if (identity) d.stored.set(`idk:${peer.name}#${peer.deviceId}`, identity)
}

async function sessionStore(d: Device, peer: WasmProtocolAddress): Promise<WasmInMemSessionStore> {
  const store = new WasmInMemSessionStore()
  const record = d.stored.get(`sess:${peer.name}.${peer.deviceId}`)
  if (record && record.length > 0) await store.import_session(peer, record)
  return store
}

async function persist(d: Device, peer: WasmProtocolAddress, store: WasmInMemSessionStore): Promise<void> {
  const bytes = await store.export_session(peer)
  if (!bytes || bytes.length === 0) throw new Error('empty session export')
  d.stored.set(`sess:${peer.name}.${peer.deviceId}`, bytes)
}

async function preKeyStores(d: Device) {
  const pkStore = new WasmInMemPreKeyStore()
  for (const id of d.pkIds) {
    const raw = d.stored.get(`pk:${id}`)
    if (raw) await pkStore.import_pre_key(id, raw)
  }
  const spkStore = new WasmInMemSignedPreKeyStore()
  await spkStore.import_signed_pre_key(SPK_ID, d.stored.get('spk')!)
  const kpkStore = new WasmInMemKyberPreKeyStore()
  await kpkStore.import_kyber_pre_key(KYBER_ID, d.stored.get('kpk')!)
  return { pkStore, spkStore, kpkStore }
}

async function bundleOf(d: Device) {
  const { spkStore, kpkStore } = await preKeyStores(d)
  const signed = core.signedParse((await spkStore.export_signed_pre_key(SPK_ID))!)
  const pq = core.pqRecordParse((await kpkStore.export_kyber_pre_key(KYBER_ID))!)
  return {
    registration_id: d.registrationId,
    identity_key: d.identity.public_key.serialize(),
    signed_prekey: { id: SPK_ID, key: signed.publicKey, sig: signed.signature },
    kyber_prekey: { id: KYBER_ID, key: pq.publicKey, sig: pq.signature },
  }
}

async function setupOutgoing(local: Device, peer: Device) {
  const localAddr = toAddress(local.uid, local.did)
  const peerAddr = toAddress(peer.uid, peer.did)
  const bundle = await bundleOf(peer)
  const sessions = new WasmInMemSessionStore()
  const identities = await identityStore(local)
  await processPreKeyBundle(
    peerAddr, localAddr, bundle.registration_id,
    WasmPublicKey.deserialize(bundle.identity_key),
    bundle.signed_prekey.id, WasmPublicKey.deserialize(bundle.signed_prekey.key), bundle.signed_prekey.sig,
    null, null,
    bundle.kyber_prekey.id, bundle.kyber_prekey.key, bundle.kyber_prekey.sig,
    sessions, identities,
  )
  await persist(local, peerAddr, sessions)
  await pinIdentity(local, peerAddr, identities)
  expect(await sessions.has_session(peerAddr)).toBe(true)
  return { sessions, identities }
}

async function encrypt(local: Device, peer: Device, text: string, stores?: { sessions: WasmInMemSessionStore; identities: WasmInMemIdentityKeyStore }): Promise<Uint8Array> {
  const localAddr = toAddress(local.uid, local.did)
  const peerAddr = toAddress(peer.uid, peer.did)
  const sessions = stores?.sessions ?? (await sessionStore(local, peerAddr))
  const identities = stores?.identities ?? (await identityStore(local))
  const ct = await encryptMessage(new TextEncoder().encode(text), peerAddr, localAddr, sessions, identities)
  await persist(local, peerAddr, sessions)
  const wire = new Uint8Array(1 + ct.body.length)
  wire[0] = ct.message_type
  wire.set(ct.body, 1)
  return wire
}

async function decrypt(local: Device, peer: Device, wire: Uint8Array): Promise<string> {
  const localAddr = toAddress(local.uid, local.did)
  const peerAddr = toAddress(peer.uid, peer.did)
  const sessions = await sessionStore(local, peerAddr)
  const identities = await identityStore(local)
  const { pkStore, spkStore, kpkStore } = await preKeyStores(local)
  const plain = await decryptMessage(wire.slice(1), wire[0], peerAddr, localAddr, sessions, identities, pkStore, spkStore, kpkStore)
  await persist(local, peerAddr, sessions)
  await pinIdentity(local, peerAddr, identities)
  for (const id of local.pkIds) if ((await pkStore.export_pre_key(id)) === undefined) local.stored.delete(`pk:${id}`)
  return new TextDecoder().decode(plain)
}

beforeAll(async () => {
  await init()
  initRuntime()
})

describe('the web client flow', () => {
  test('sessions both ways over exported and re-imported records', async () => {
    const alice = await provision('alice', 'browser-1')
    const bob = await provision('bob', 'browser-2')
    const stores = await setupOutgoing(alice, bob)
    const first = await encrypt(alice, bob, 'hello bob', stores)
    expect(first[0]).toBe(message_type_pre_key())
    expect(await decrypt(bob, alice, first)).toBe('hello bob')
    const second = await encrypt(alice, bob, 'again')
    expect(second[0]).toBe(message_type_pre_key())
    expect(await decrypt(bob, alice, second)).toBe('again')
    const reply = await encrypt(bob, alice, 'hi alice')
    expect(reply[0]).toBe(message_type_whisper())
    expect(message_type_signal()).toBe(message_type_whisper())
    expect(await decrypt(alice, bob, reply)).toBe('hi alice')
    const third = await encrypt(alice, bob, 'ratcheted')
    expect(third[0]).toBe(message_type_whisper())
    expect(await decrypt(bob, alice, third)).toBe('ratcheted')
    await expect(decrypt(bob, alice, third)).rejects.toBeInstanceOf(GossveilError)
    expect(bob.pkIds.every(id => bob.stored.has(`pk:${id}`))).toBe(true)
  })

  test('a one-time prekey is consumed and vanishes from the store', async () => {
    const alice = await provision('alice', 'b1')
    const bob = await provision('bob', 'b2')
    const bundle = await bundleOf(bob)
    const pkStore = new WasmInMemPreKeyStore()
    const oneTimeId = bob.pkIds[0]
    await pkStore.import_pre_key(oneTimeId, bob.stored.get(`pk:${oneTimeId}`)!)
    const oneTime = core.oneTimeParse((await pkStore.export_pre_key(oneTimeId))!).publicKey
    const sessions = new WasmInMemSessionStore()
    const identities = await identityStore(alice)
    await processPreKeyBundle(toAddress('bob', 'b2'), toAddress('alice', 'b1'), bundle.registration_id, WasmPublicKey.deserialize(bundle.identity_key), SPK_ID, WasmPublicKey.deserialize(bundle.signed_prekey.key), bundle.signed_prekey.sig, oneTimeId, oneTime, KYBER_ID, bundle.kyber_prekey.key, bundle.kyber_prekey.sig, sessions, identities)
    const ct = await encryptMessage(new TextEncoder().encode('one time'), toAddress('bob', 'b2'), toAddress('alice', 'b1'), sessions, identities)
    const wire = new Uint8Array([ct.message_type, ...ct.body])
    expect(await decrypt(bob, alice, wire)).toBe('one time')
    expect(bob.stored.has(`pk:${oneTimeId}`)).toBe(false)
    await expect(decrypt(bob, alice, wire)).rejects.toThrow()
  })

  test('a changed identity is refused', async () => {
    const alice = await provision('alice', 'b1')
    const bob = await provision('bob', 'b2')
    const stores = await setupOutgoing(alice, bob)
    expect(await decrypt(bob, alice, await encrypt(alice, bob, 'first', stores))).toBe('first')
    const impostor = await provision('alice', 'b1')
    const forged = await encrypt(impostor, bob, 'forged', await setupOutgoing(impostor, bob))
    await expect(decrypt(bob, impostor, forged)).rejects.toMatchObject({ kind: 'UntrustedIdentity' })
  })

  test('archive_session leaves a record that cannot encrypt', async () => {
    const alice = await provision('alice', 'b1')
    const bob = await provision('bob', 'b2')
    const { sessions, identities } = await setupOutgoing(alice, bob)
    const peer = toAddress('bob', 'b2')
    await sessions.archive_session(peer)
    expect(await sessions.has_session(peer)).toBe(false)
    await expect(encryptMessage(new Uint8Array([1]), peer, toAddress('alice', 'b1'), sessions, identities)).rejects.toThrow()
  })
})

describe('the rest of the surface', () => {
  test('groups over sender keys', async () => {
    const alice = toAddress('alice', 'b1')
    const distributionId = uuid_to_string(generate_uuid())
    const aliceStore = new WasmInMemSenderKeyStore()
    const bobStore = new WasmInMemSenderKeyStore()
    const distribution = await createSenderKeyDistribution(alice, distributionId, aliceStore)
    await processSenderKeyDistribution(alice, distribution, bobStore)
    const exported = await bobStore.export_sender_key(alice, distributionId)
    expect(exported).toBeDefined()
    const reloaded = new WasmInMemSenderKeyStore()
    await reloaded.import_sender_key(alice, distributionId, exported!)
    const one = await encryptGroupMessage(alice, distributionId, new TextEncoder().encode('one'), aliceStore)
    const two = await encryptGroupMessage(alice, distributionId, new TextEncoder().encode('two'), aliceStore)
    expect(new TextDecoder().decode(await decryptGroupMessage(alice, two, reloaded))).toBe('two')
    expect(new TextDecoder().decode(await decryptGroupMessage(alice, one, reloaded))).toBe('one')
    expect(message_type_sender_key()).toBe(7)
  })

  test('safety numbers agree from both sides', () => {
    const a = WasmPrivateKey.generate().getPublicKey()
    const b = WasmPrivateKey.generate().getPublicKey()
    const aUuid = uuid_to_string(generate_uuid())
    const bUuid = uuid_to_string(generate_uuid())
    const ours = generateSafetyNumber(aUuid, a, bUuid, b)
    const theirs = generateSafetyNumber(bUuid, b, aUuid, a)
    expect(ours.displayable).toBe(theirs.displayable)
    expect(ours.displayable.length).toBe(60)
    expect(verifySafetyNumber(theirs.scannable, aUuid, a, bUuid, b)).toBe(true)
    expect(verifySafetyNumber(theirs.scannable, aUuid, a, bUuid, a)).toBe(false)
  })

  test('group parameters, uuids and random helpers', () => {
    const master = WasmGroupMasterKey.generate()
    const params = master.derive_secret_params()
    expect(WasmGroupSecretParams.from_bytes(params.serialize).get_identifier().serialize).toEqual(master.derive_identifier().serialize)
    expect(WasmGroupMasterKey.from_bytes(master.serialize).serialize).toEqual(master.serialize)
    expect(params.get_master_key().serialize).toEqual(master.serialize)
    expect(master.derive_identifier().serialize.length).toBe(32)
    const id = generate_uuid()
    expect(uuid_from_string(uuid_to_string(id))).toEqual(id)
    expect(id[6] >> 4).toBe(4)
    expect(generate_random_bytes(7).length).toBe(7)
    expect(generate_attachment_key().length).toBe(64)
    const regId = generateRegistrationId()
    expect(regId).toBeGreaterThanOrEqual(1)
    expect(regId).toBeLessThanOrEqual(16380)
    const pair = WasmIdentityKeyPair.generate()
    expect(WasmIdentityKeyPair.deserialize(pair.serialize()).public_key.serialize()).toEqual(pair.public_key.serialize())
    expect(() => WasmPublicKey.deserialize(new Uint8Array([5, 1, 2]))).toThrow(GossveilError)
  })
})

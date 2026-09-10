// The surface the web client calls: keys, in-memory stores that import and
// export records, session and group operations, safety numbers, group
// parameters and the small helpers. Objects hold plain bytes, so `free()`
// only drops references and nothing dangles after a constructor.
import { core, MessageType, PQ_ROUND_THREE } from './bridge.js'
import { GossveilError, bytesEqual, fault, isReady, utf8 } from './core.js'
import { uuidToBytes, bytesToUuid } from './uuid.js'

// Older runtimes lack Symbol.dispose; the same well-known name keeps `using` working.
;(Symbol as { dispose?: symbol }).dispose ??= Symbol.for('Symbol.dispose')

function nowSecs(): bigint {
  return BigInt(Math.floor(Date.now() / 1000))
}

abstract class Handle {
  free(): void {}
  [Symbol.dispose](): void {
    this.free()
  }
}

export class WasmProtocolAddress extends Handle {
  readonly #name: string
  readonly #deviceId: number

  constructor(name: string, device_id: number) {
    super()
    if (name.length === 0) throw fault('invalidArgument', 'empty address name')
    this.#name = name
    this.#deviceId = device_id >>> 0
  }

  get name(): string {
    return this.#name
  }

  get deviceId(): number {
    return this.#deviceId
  }

  toString(): string {
    return `${this.#name}.${this.#deviceId}`
  }
}

export class WasmPublicKey extends Handle {
  readonly bytes: Uint8Array

  private constructor(bytes: Uint8Array) {
    super()
    this.bytes = bytes
  }

  static deserialize(data: Uint8Array): WasmPublicKey {
    core.curveCheck(data)
    return new WasmPublicKey(new Uint8Array(data))
  }

  /** @internal */
  static unchecked(bytes: Uint8Array): WasmPublicKey {
    return new WasmPublicKey(bytes)
  }

  serialize(): Uint8Array {
    return new Uint8Array(this.bytes)
  }

  verify(message: Uint8Array, signature: Uint8Array): boolean {
    return core.curveVerify(this.bytes, message, signature)
  }
}

export class WasmPrivateKey extends Handle {
  readonly bytes: Uint8Array

  private constructor(bytes: Uint8Array) {
    super()
    this.bytes = bytes
  }

  static deserialize(data: Uint8Array): WasmPrivateKey {
    if (data.length !== 32) throw fault('invalidKey', 'a private key is 32 bytes')
    return new WasmPrivateKey(new Uint8Array(data))
  }

  static generate(): WasmPrivateKey {
    return new WasmPrivateKey(core.curvePair().secret)
  }

  /** @internal */
  static unchecked(bytes: Uint8Array): WasmPrivateKey {
    return new WasmPrivateKey(bytes)
  }

  getPublicKey(): WasmPublicKey {
    return WasmPublicKey.unchecked(core.curvePublic(this.bytes))
  }

  serialize(): Uint8Array {
    return new Uint8Array(this.bytes)
  }

  sign(message: Uint8Array): Uint8Array {
    return core.curveSign(this.bytes, message)
  }

  agree(other: WasmPublicKey): Uint8Array {
    return core.curveAgree(this.bytes, other.bytes)
  }
}

export class WasmIdentityKeyPair extends Handle {
  readonly #publicKey: WasmPublicKey
  readonly #privateKey: WasmPrivateKey

  constructor(public_key: WasmPublicKey, private_key: WasmPrivateKey) {
    super()
    this.#publicKey = WasmPublicKey.unchecked(public_key.serialize())
    this.#privateKey = WasmPrivateKey.unchecked(private_key.serialize())
  }

  static deserialize(data: Uint8Array): WasmIdentityKeyPair {
    const { publicKey, secret } = core.identityParse(data)
    return new WasmIdentityKeyPair(WasmPublicKey.unchecked(publicKey), WasmPrivateKey.unchecked(secret))
  }

  static generate(): WasmIdentityKeyPair {
    const secret = WasmPrivateKey.generate()
    return new WasmIdentityKeyPair(secret.getPublicKey(), secret)
  }

  serialize(): Uint8Array {
    return core.identitySerialize(this.#privateKey.bytes)
  }

  get public_key(): WasmPublicKey {
    return this.#publicKey
  }

  get private_key(): WasmPrivateKey {
    return this.#privateKey
  }
}

export class WasmInMemIdentityKeyStore extends Handle {
  readonly #identity: WasmIdentityKeyPair
  readonly #registrationId: number
  readonly #known = new Map<string, Uint8Array>()

  constructor(identity_key_pair: WasmIdentityKeyPair, registration_id: number) {
    super()
    this.#identity = identity_key_pair
    this.#registrationId = registration_id >>> 0
  }

  get identity_key_pair(): WasmIdentityKeyPair {
    return this.#identity
  }

  get registration_id(): number {
    return this.#registrationId
  }

  /** The identity pinned for an address, or undefined before first contact. */
  async export_identity(address: WasmProtocolAddress): Promise<Uint8Array | undefined> {
    const known = this.#known.get(address.toString())
    return known ? new Uint8Array(known) : undefined
  }

  async import_identity(address: WasmProtocolAddress, identity_bytes: Uint8Array): Promise<void> {
    core.curveCheck(identity_bytes)
    this.#known.set(address.toString(), new Uint8Array(identity_bytes))
  }

  /** @internal Trust on first use: unknown is trusted, a changed key is not. */
  isTrusted(address: WasmProtocolAddress, identity: Uint8Array): boolean {
    const known = this.#known.get(address.toString())
    return known === undefined || bytesEqual(known, identity)
  }

  /** @internal */
  save(address: WasmProtocolAddress, identity: Uint8Array): boolean {
    const known = this.#known.get(address.toString())
    this.#known.set(address.toString(), new Uint8Array(identity))
    return known !== undefined && !bytesEqual(known, identity)
  }
}

class RecordStore extends Handle {
  protected readonly records = new Map<number, Uint8Array>()

  protected get(id: number): Uint8Array | undefined {
    const r = this.records.get(id >>> 0)
    return r ? new Uint8Array(r) : undefined
  }

  protected put(id: number, bytes: Uint8Array): void {
    this.records.set(id >>> 0, new Uint8Array(bytes))
  }

  protected drop(id: number): void {
    this.records.delete(id >>> 0)
  }

  ids(): number[] {
    return [...this.records.keys()]
  }
}

export class WasmInMemPreKeyStore extends RecordStore {
  async export_pre_key(id: number): Promise<Uint8Array | undefined> {
    return this.get(id)
  }

  async import_pre_key(id: number, record_bytes: Uint8Array): Promise<void> {
    core.oneTimeParse(record_bytes)
    this.put(id, record_bytes)
  }

  async remove_pre_key(id: number): Promise<void> {
    this.drop(id)
  }
}

export class WasmInMemSignedPreKeyStore extends RecordStore {
  async export_signed_pre_key(id: number): Promise<Uint8Array | undefined> {
    return this.get(id)
  }

  async import_signed_pre_key(id: number, record_bytes: Uint8Array): Promise<void> {
    core.signedParse(record_bytes)
    this.put(id, record_bytes)
  }

  async remove_signed_pre_key(id: number): Promise<void> {
    this.drop(id)
  }
}

export class WasmInMemKyberPreKeyStore extends RecordStore {
  readonly #used = new Set<number>()

  async export_kyber_pre_key(id: number): Promise<Uint8Array | undefined> {
    return this.get(id)
  }

  async import_kyber_pre_key(id: number, record_bytes: Uint8Array): Promise<void> {
    core.pqRecordParse(record_bytes)
    this.put(id, record_bytes)
  }

  async remove_kyber_pre_key(id: number): Promise<void> {
    this.drop(id)
    this.#used.delete(id >>> 0)
  }

  /** @internal */
  markUsed(id: number): void {
    this.#used.add(id >>> 0)
  }

  async has_kyber_pre_key_been_used(id: number): Promise<boolean> {
    return this.#used.has(id >>> 0)
  }
}

export class WasmInMemSessionStore extends Handle {
  readonly #sessions = new Map<string, Uint8Array>()

  async has_session(address: WasmProtocolAddress): Promise<boolean> {
    const record = this.#sessions.get(address.toString())
    return record !== undefined && core.sessionInfo(record, nowSecs()).usable
  }

  async export_session(address: WasmProtocolAddress): Promise<Uint8Array | undefined> {
    const record = this.#sessions.get(address.toString())
    return record ? new Uint8Array(record) : undefined
  }

  async import_session(address: WasmProtocolAddress, session_bytes: Uint8Array): Promise<void> {
    core.sessionInfo(session_bytes, 0n)
    this.#sessions.set(address.toString(), new Uint8Array(session_bytes))
  }

  async archive_session(address: WasmProtocolAddress): Promise<void> {
    const record = this.#sessions.get(address.toString())
    if (record) this.#sessions.set(address.toString(), core.sessionShelve(record))
  }

  async remove_session(address: WasmProtocolAddress): Promise<void> {
    this.#sessions.delete(address.toString())
  }

  /** @internal */
  load(address: WasmProtocolAddress): Uint8Array {
    return this.#sessions.get(address.toString()) ?? new Uint8Array(0)
  }

  /** @internal */
  store(address: WasmProtocolAddress, record: Uint8Array): void {
    this.#sessions.set(address.toString(), record)
  }
}

export class WasmInMemSenderKeyStore extends Handle {
  readonly #keys = new Map<string, Uint8Array>()

  static key(address: WasmProtocolAddress, distributionId: string): string {
    return `${address.toString()}|${distributionId.toLowerCase()}`
  }

  async export_sender_key(address: WasmProtocolAddress, distribution_id: string): Promise<Uint8Array | undefined> {
    const record = this.#keys.get(WasmInMemSenderKeyStore.key(address, distribution_id))
    return record ? new Uint8Array(record) : undefined
  }

  async import_sender_key(address: WasmProtocolAddress, distribution_id: string, record_bytes: Uint8Array): Promise<void> {
    this.#keys.set(WasmInMemSenderKeyStore.key(address, distribution_id), new Uint8Array(record_bytes))
  }

  /** @internal */
  load(address: WasmProtocolAddress, distributionId: string): Uint8Array {
    return this.#keys.get(WasmInMemSenderKeyStore.key(address, distributionId)) ?? new Uint8Array(0)
  }

  /** @internal */
  store(address: WasmProtocolAddress, distributionId: string, record: Uint8Array): void {
    this.#keys.set(WasmInMemSenderKeyStore.key(address, distributionId), record)
  }
}

/** A published record as the client keeps it: the id, the public half and the bytes to persist. */
abstract class PublishedKey extends Handle {
  readonly #id: number
  readonly #publicKey: Uint8Array
  readonly #record: Uint8Array

  protected constructor(id: number, publicKey: Uint8Array, record: Uint8Array) {
    super()
    this.#id = id
    this.#publicKey = publicKey
    this.#record = record
  }

  get id(): number {
    return this.#id
  }

  get public_key(): Uint8Array {
    return new Uint8Array(this.#publicKey)
  }

  get record(): Uint8Array {
    return new Uint8Array(this.#record)
  }
}

export class WasmPreKey extends PublishedKey {
  /** @internal */
  static fromRecord(record: Uint8Array): WasmPreKey {
    const parsed = core.oneTimeParse(record)
    return new WasmPreKey(parsed.id, parsed.publicKey, record)
  }
}

abstract class SignedPublishedKey extends PublishedKey {
  readonly #signature: Uint8Array
  readonly #timestamp: bigint

  protected constructor(id: number, publicKey: Uint8Array, record: Uint8Array, signature: Uint8Array, timestamp: bigint) {
    super(id, publicKey, record)
    this.#signature = signature
    this.#timestamp = timestamp
  }

  get signature(): Uint8Array {
    return new Uint8Array(this.#signature)
  }

  get timestamp(): bigint {
    return this.#timestamp
  }
}

export class WasmSignedPreKey extends SignedPublishedKey {
  /** @internal */
  static fromRecord(record: Uint8Array): WasmSignedPreKey {
    const parsed = core.signedParse(record)
    return new WasmSignedPreKey(parsed.id, parsed.publicKey, record, parsed.signature, parsed.stamp)
  }
}

export class WasmKyberPreKey extends SignedPublishedKey {
  /** @internal */
  static fromRecord(record: Uint8Array): WasmKyberPreKey {
    const parsed = core.pqRecordParse(record)
    return new WasmKyberPreKey(parsed.id, parsed.publicKey, record, parsed.signature, parsed.stamp)
  }
}

export class WasmCiphertext extends Handle {
  readonly #type: number
  readonly #body: Uint8Array

  private constructor(type: number, body: Uint8Array) {
    super()
    this.#type = type
    this.#body = body
  }

  /** @internal */
  static of(type: number, body: Uint8Array): WasmCiphertext {
    return new WasmCiphertext(type, body)
  }

  get message_type(): number {
    return this.#type
  }

  get body(): Uint8Array {
    return new Uint8Array(this.#body)
  }
}

export class WasmSafetyNumber extends Handle {
  readonly #displayable: string
  readonly #scannable: Uint8Array

  private constructor(displayable: string, scannable: Uint8Array) {
    super()
    this.#displayable = displayable
    this.#scannable = scannable
  }

  /** @internal */
  static of(displayable: string, scannable: Uint8Array): WasmSafetyNumber {
    return new WasmSafetyNumber(displayable, scannable)
  }

  get displayable(): string {
    return this.#displayable
  }

  get scannable(): Uint8Array {
    return new Uint8Array(this.#scannable)
  }
}

export class WasmGroupIdentifier extends Handle {
  readonly #bytes: Uint8Array

  private constructor(bytes: Uint8Array) {
    super()
    this.#bytes = bytes
  }

  /** @internal */
  static of(bytes: Uint8Array): WasmGroupIdentifier {
    return new WasmGroupIdentifier(bytes)
  }

  get serialize(): Uint8Array {
    return new Uint8Array(this.#bytes)
  }
}

export class WasmGroupSecretParams extends Handle {
  readonly #bytes: Uint8Array
  readonly #identifier: Uint8Array

  private constructor(bytes: Uint8Array, identifier: Uint8Array) {
    super()
    this.#bytes = bytes
    this.#identifier = identifier
  }

  static from_bytes(bytes: Uint8Array): WasmGroupSecretParams {
    const info = core.circleParamsInfo(bytes)
    return new WasmGroupSecretParams(new Uint8Array(bytes), info.identifier)
  }

  get_identifier(): WasmGroupIdentifier {
    return WasmGroupIdentifier.of(this.#identifier)
  }

  get_master_key(): WasmGroupMasterKey {
    return WasmGroupMasterKey.from_bytes(core.circleParamsInfo(this.#bytes).master)
  }

  get_public_params(): Uint8Array {
    return core.circleParamsInfo(this.#bytes).publicParams
  }

  get serialize(): Uint8Array {
    return new Uint8Array(this.#bytes)
  }
}

export class WasmGroupMasterKey extends Handle {
  readonly #bytes: Uint8Array

  private constructor(bytes: Uint8Array) {
    super()
    this.#bytes = bytes
  }

  static from_bytes(bytes: Uint8Array): WasmGroupMasterKey {
    if (bytes.length !== 32) throw fault('invalidArgument', 'a group master key is 32 bytes')
    return new WasmGroupMasterKey(new Uint8Array(bytes))
  }

  static generate(): WasmGroupMasterKey {
    return new WasmGroupMasterKey(core.circleMasterRandom())
  }

  derive_secret_params(): WasmGroupSecretParams {
    return WasmGroupSecretParams.from_bytes(core.circleSecretParams(this.#bytes))
  }

  derive_identifier(): WasmGroupIdentifier {
    return this.derive_secret_params().get_identifier()
  }

  get serialize(): Uint8Array {
    return new Uint8Array(this.#bytes)
  }
}

// Sessions

function binding(sender: WasmProtocolAddress, recipient: WasmProtocolAddress) {
  return { sender: sender.name, senderDevice: sender.deviceId, recipient: recipient.name, recipientDevice: recipient.deviceId }
}

function untrusted(address: WasmProtocolAddress): GossveilError {
  return fault('untrustedIdentity', `untrusted identity for ${address.toString()}`)
}

function commit(record: Uint8Array, sender: WasmProtocolAddress, sessions: WasmInMemSessionStore, identities: WasmInMemIdentityKeyStore): void {
  const theirIdentity = core.sessionInfo(record, nowSecs()).remoteIdentity
  if (!identities.isTrusted(sender, theirIdentity)) throw untrusted(sender)
  identities.save(sender, theirIdentity)
  sessions.store(sender, record)
}

/** Starts a session with `recipient` from its published bundle; `prekey_id` and `prekey` may be null. */
export async function processPreKeyBundle(
  recipient: WasmProtocolAddress,
  local_address: WasmProtocolAddress,
  registration_id: number,
  identity_key: WasmPublicKey,
  signed_prekey_id: number,
  signed_prekey: WasmPublicKey,
  signed_prekey_signature: Uint8Array,
  prekey_id: number | null | undefined,
  prekey: Uint8Array | null | undefined,
  kyber_prekey_id: number,
  kyber_prekey: Uint8Array,
  kyber_prekey_signature: Uint8Array,
  session_store: WasmInMemSessionStore,
  identity_store: WasmInMemIdentityKeyStore,
): Promise<void> {
  void local_address
  const identity = identity_key.serialize()
  if (!identity_store.isTrusted(recipient, identity)) throw untrusted(recipient)
  const record = core.sessionStart(identity_store.identity_key_pair.private_key.bytes, identity_store.registration_id, session_store.load(recipient), {
    registrationId: registration_id,
    device: recipient.deviceId,
    oneTimeId: prekey_id ?? null,
    oneTime: prekey ?? null,
    signedId: signed_prekey_id,
    signedKey: signed_prekey.serialize(),
    signedSignature: signed_prekey_signature,
    identity,
    pqId: kyber_prekey_id,
    pqKey: kyber_prekey,
    pqSignature: kyber_prekey_signature,
  }, nowSecs())
  identity_store.save(recipient, identity)
  session_store.store(recipient, record)
}

export async function encryptMessage(
  plaintext: Uint8Array,
  recipient: WasmProtocolAddress,
  local_address: WasmProtocolAddress,
  session_store: WasmInMemSessionStore,
  identity_store: WasmInMemIdentityKeyStore,
): Promise<WasmCiphertext> {
  const existing = session_store.load(recipient)
  if (existing.length === 0) throw fault('sessionNotFound', `no session for ${recipient.toString()}`)
  const { kind, sealed, record } = core.sessionSeal(existing, plaintext, nowSecs(), binding(local_address, recipient))
  const theirIdentity = core.sessionInfo(record, nowSecs()).remoteIdentity
  if (!identity_store.isTrusted(recipient, theirIdentity)) throw untrusted(recipient)
  session_store.store(recipient, record)
  return WasmCiphertext.of(kind, sealed)
}

/** Opens a message of `message_type`; a first message consumes the one-time prekey it names. */
export async function decryptMessage(
  ciphertext: Uint8Array,
  message_type: number,
  sender: WasmProtocolAddress,
  local_address: WasmProtocolAddress,
  session_store: WasmInMemSessionStore,
  identity_store: WasmInMemIdentityKeyStore,
  prekey_store: WasmInMemPreKeyStore,
  signed_prekey_store: WasmInMemSignedPreKeyStore,
  kyber_prekey_store: WasmInMemKyberPreKeyStore,
): Promise<Uint8Array> {
  const existing = session_store.load(sender)
  const b = binding(sender, local_address)
  if (message_type === MessageType.preKey) {
    const { info } = core.openerParse(ciphertext)
    if (!identity_store.isTrusted(sender, info.identity)) throw untrusted(sender)
    const signed = await signed_prekey_store.export_signed_pre_key(info.signedId)
    if (!signed) throw fault('invalidKeyId', `no signed prekey ${info.signedId}`)
    let oneTime: Uint8Array = new Uint8Array(0)
    if (info.oneTimeId !== null) {
      const record = await prekey_store.export_pre_key(info.oneTimeId)
      if (!record) throw fault('invalidKeyId', `no prekey ${info.oneTimeId}`)
      oneTime = record
    }
    let pq: Uint8Array = new Uint8Array(0)
    if (info.pqId !== null) {
      const record = await kyber_prekey_store.export_kyber_pre_key(info.pqId)
      if (!record) throw fault('invalidKeyId', `no kyber prekey ${info.pqId}`)
      pq = record
    }
    const { plain, record, consumed } = core.sessionOpenFirst(identity_store.identity_key_pair.private_key.bytes, identity_store.registration_id, existing, ciphertext, signed, oneTime, pq, b)
    commit(record, sender, session_store, identity_store)
    if (consumed.used) {
      if (consumed.oneTimeId !== null) await prekey_store.remove_pre_key(consumed.oneTimeId)
      if (info.pqId !== null) kyber_prekey_store.markUsed(info.pqId)
    }
    return plain
  }
  if (message_type === MessageType.whisper) {
    if (existing.length === 0) throw fault('sessionNotFound', `no session for ${sender.toString()}`)
    const { plain, record } = core.sessionOpen(existing, ciphertext, b)
    commit(record, sender, session_store, identity_store)
    return plain
  }
  throw fault('invalidMessage', `unknown message type ${message_type}`)
}

// Key generation

export async function generatePreKeys(start_id: number, count: number, prekey_store: WasmInMemPreKeyStore): Promise<WasmPreKey[]> {
  const out: WasmPreKey[] = []
  for (let i = 0; i < count; i++) {
    const id = (start_id + i) >>> 0
    const record = core.oneTimeRecord(id, core.curvePair().secret)
    await prekey_store.import_pre_key(id, record)
    out.push(WasmPreKey.fromRecord(record))
  }
  return out
}

export async function generateSignedPreKey(key_id: number, identity_key_pair: WasmIdentityKeyPair, signed_prekey_store: WasmInMemSignedPreKeyStore): Promise<WasmSignedPreKey> {
  const pair = core.curvePair()
  const signature = core.curveSign(identity_key_pair.private_key.bytes, pair.publicKey)
  const record = core.signedRecord(key_id >>> 0, BigInt(Date.now()), pair.secret, signature)
  await signed_prekey_store.import_signed_pre_key(key_id, record)
  return WasmSignedPreKey.fromRecord(record)
}

export async function generateKyberPreKey(key_id: number, identity_key_pair: WasmIdentityKeyPair, kyber_prekey_store: WasmInMemKyberPreKeyStore): Promise<WasmKyberPreKey> {
  const pair = core.pqPair(PQ_ROUND_THREE)
  const signature = core.curveSign(identity_key_pair.private_key.bytes, pair.publicKey)
  const record = core.pqRecord(key_id >>> 0, BigInt(Date.now()), pair.publicKey, pair.secret, signature)
  await kyber_prekey_store.import_kyber_pre_key(key_id, record)
  return WasmKyberPreKey.fromRecord(record)
}

const MAX_REGISTRATION_ID = 16380

/** Unbiased in 1..=16380 by rejection sampling. */
export function generateRegistrationId(): number {
  const buf = new Uint16Array(1)
  for (;;) {
    crypto.getRandomValues(buf)
    const candidate = buf[0] & 0x3fff
    if (candidate >= 1 && candidate <= MAX_REGISTRATION_ID) return candidate
  }
}

// Safety numbers

const SAFETY_NUMBER_VERSION = 2
const SAFETY_NUMBER_ITERATIONS = 5200

export function generateSafetyNumber(local_uuid: string, local_identity_key: WasmPublicKey, contact_uuid: string, contact_identity_key: WasmPublicKey): WasmSafetyNumber {
  const enc = new TextEncoder()
  const { display, scannable } = core.safety(SAFETY_NUMBER_VERSION, SAFETY_NUMBER_ITERATIONS, enc.encode(local_uuid), local_identity_key.bytes, enc.encode(contact_uuid), contact_identity_key.bytes)
  return WasmSafetyNumber.of(display, scannable)
}

export function verifySafetyNumber(scanned: Uint8Array, local_uuid: string, local_identity_key: WasmPublicKey, contact_uuid: string, contact_identity_key: WasmPublicKey): boolean {
  const ours = generateSafetyNumber(local_uuid, local_identity_key, contact_uuid, contact_identity_key)
  return core.safetyMatches(ours.scannable, scanned)
}

// Groups

export async function createSenderKeyDistribution(local_address: WasmProtocolAddress, distribution_id: string, sender_key_store: WasmInMemSenderKeyStore): Promise<Uint8Array> {
  const { record, announce } = core.circleAnnounce(sender_key_store.load(local_address, distribution_id), uuidToBytes(distribution_id))
  sender_key_store.store(local_address, distribution_id, record)
  return announce
}

export async function processSenderKeyDistribution(sender_address: WasmProtocolAddress, distribution_message: Uint8Array, sender_key_store: WasmInMemSenderKeyStore): Promise<void> {
  const distributionId = bytesToUuid(core.announceParse(distribution_message).circleId)
  const record = core.circleAdmit(sender_key_store.load(sender_address, distributionId), distribution_message)
  sender_key_store.store(sender_address, distributionId, record)
}

export async function encryptGroupMessage(local_address: WasmProtocolAddress, distribution_id: string, plaintext: Uint8Array, sender_key_store: WasmInMemSenderKeyStore): Promise<Uint8Array> {
  const existing = sender_key_store.load(local_address, distribution_id)
  if (existing.length === 0) throw fault('sessionNotFound', `no sender key for ${local_address.toString()} in ${distribution_id}`)
  const { note, record } = core.circleSeal(existing, uuidToBytes(distribution_id), plaintext)
  sender_key_store.store(local_address, distribution_id, record)
  return note
}

export async function decryptGroupMessage(sender_address: WasmProtocolAddress, ciphertext: Uint8Array, sender_key_store: WasmInMemSenderKeyStore): Promise<Uint8Array> {
  const distributionId = bytesToUuid(core.noteParse(ciphertext).circleId)
  const existing = sender_key_store.load(sender_address, distributionId)
  if (existing.length === 0) throw fault('sessionNotFound', `no sender key for ${sender_address.toString()} in ${distributionId}`)
  const { plain, record } = core.circleOpen(existing, ciphertext)
  sender_key_store.store(sender_address, distributionId, record)
  return plain
}

// Helpers

export function generate_attachment_key(): Uint8Array {
  return core.random(64)
}

export function generate_random_bytes(length: number): Uint8Array {
  return core.random(length >>> 0)
}

export function generate_uuid(): Uint8Array {
  const bytes = core.random(16)
  bytes[6] = (bytes[6] & 0x0f) | 0x40
  bytes[8] = (bytes[8] & 0x3f) | 0x80
  return bytes
}

export function uuid_from_string(s: string): Uint8Array {
  return uuidToBytes(s)
}

export function uuid_to_string(bytes: Uint8Array): string {
  return bytesToUuid(bytes)
}

/** Confirms the core is loaded; call after the default export resolves. */
export function init(): void {
  if (!isReady()) throw fault('invalidState', 'the core is not loaded: await the default export first')
}

export function log_to_console(message: string): void {
  console.log(message)
}

export function message_type_pre_key(): number {
  return MessageType.preKey
}

export function message_type_sender_key(): number {
  return MessageType.senderKey
}

export function message_type_whisper(): number {
  return MessageType.whisper
}

export { utf8 }

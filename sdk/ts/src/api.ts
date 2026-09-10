// The record-shaped API: keys, records, store interfaces a host implements,
// and the protocol operations over them. Every object holds plain bytes.
import { core, MessageType, PQ_ROUND_THREE } from './bridge'
import type { Binding } from './bridge'
import { GossveilError, bytesEqual, fault, utf8 } from './core'
import { uuidToBytes, bytesToUuid } from './uuid'

function nowSecs(date: Date = new Date()): bigint {
  return BigInt(Math.max(0, Math.floor(date.getTime() / 1000)))
}

function untrusted(address: ProtocolAddress): GossveilError {
  return fault('untrustedIdentity', `untrusted identity for ${address.toString()}`)
}

// Keys

export class PublicKey {
  readonly bytes: Uint8Array

  private constructor(bytes: Uint8Array) {
    this.bytes = bytes
  }

  static deserialize(data: Uint8Array): PublicKey {
    core.curveCheck(data)
    return new PublicKey(new Uint8Array(data))
  }

  /** @internal */
  static unchecked(bytes: Uint8Array): PublicKey {
    return new PublicKey(bytes)
  }

  serialize(): Uint8Array {
    return new Uint8Array(this.bytes)
  }

  getPublicKeyBytes(): Uint8Array {
    return this.bytes.slice(1)
  }

  verify(message: Uint8Array, signature: Uint8Array): boolean {
    return core.curveVerify(this.bytes, message, signature)
  }

  verifyAlternateIdentity(other: PublicKey, signature: Uint8Array): boolean {
    return core.identityVouched(this.bytes, other.bytes, signature)
  }

  equals(other: PublicKey): boolean {
    return bytesEqual(this.bytes, other.bytes)
  }

  compare(other: PublicKey): number {
    const n = Math.min(this.bytes.length, other.bytes.length)
    for (let i = 0; i < n; i++) if (this.bytes[i] !== other.bytes[i]) return this.bytes[i] < other.bytes[i] ? -1 : 1
    return this.bytes.length - other.bytes.length
  }
}

export class PrivateKey {
  readonly bytes: Uint8Array

  private constructor(bytes: Uint8Array) {
    this.bytes = bytes
  }

  static generate(): PrivateKey {
    return new PrivateKey(core.curvePair().secret)
  }

  static deserialize(data: Uint8Array): PrivateKey {
    if (data.length !== 32) throw fault('invalidKey', 'a private key is 32 bytes')
    return new PrivateKey(new Uint8Array(data))
  }

  /** @internal */
  static unchecked(bytes: Uint8Array): PrivateKey {
    return new PrivateKey(bytes)
  }

  serialize(): Uint8Array {
    return new Uint8Array(this.bytes)
  }

  getPublicKey(): PublicKey {
    return PublicKey.unchecked(core.curvePublic(this.bytes))
  }

  sign(message: Uint8Array): Uint8Array {
    return core.curveSign(this.bytes, message)
  }

  agree(other: PublicKey): Uint8Array {
    return core.curveAgree(this.bytes, other.bytes)
  }
}

export class IdentityKeyPair {
  readonly publicKey: PublicKey
  readonly privateKey: PrivateKey

  constructor(publicKey: PublicKey, privateKey: PrivateKey) {
    this.publicKey = publicKey
    this.privateKey = privateKey
  }

  static new(publicKey: PublicKey, privateKey: PrivateKey): IdentityKeyPair {
    return new IdentityKeyPair(publicKey, privateKey)
  }

  static generate(): IdentityKeyPair {
    const secret = PrivateKey.generate()
    return new IdentityKeyPair(secret.getPublicKey(), secret)
  }

  static deserialize(data: Uint8Array): IdentityKeyPair {
    const { publicKey, secret } = core.identityParse(data)
    return new IdentityKeyPair(PublicKey.unchecked(publicKey), PrivateKey.unchecked(secret))
  }

  serialize(): Uint8Array {
    return core.identitySerialize(this.privateKey.bytes)
  }

  signAlternateIdentity(other: PublicKey): Uint8Array {
    return core.identityVouch(this.privateKey.bytes, other.bytes)
  }
}

const PQ_PUBLIC_LENGTH = 1569
const PQ_SECRET_LENGTH = 3169

function pqTagged(data: Uint8Array, length: number): boolean {
  return data.length === length && (data[0] === PQ_ROUND_THREE || data[0] === 0x0a)
}

export class KEMPublicKey {
  readonly bytes: Uint8Array

  private constructor(bytes: Uint8Array) {
    this.bytes = bytes
  }

  static deserialize(data: Uint8Array): KEMPublicKey {
    if (!pqTagged(data, PQ_PUBLIC_LENGTH)) throw fault('invalidKey', 'unrecognized key encapsulation key')
    return new KEMPublicKey(new Uint8Array(data))
  }

  /** @internal */
  static unchecked(bytes: Uint8Array): KEMPublicKey {
    return new KEMPublicKey(bytes)
  }

  serialize(): Uint8Array {
    return new Uint8Array(this.bytes)
  }

  encapsulate(): { sharedSecret: Uint8Array; ciphertext: Uint8Array } {
    const { capsule, shared } = core.pqEncapsulate(this.bytes)
    return { sharedSecret: shared, ciphertext: capsule }
  }
}

export class KEMSecretKey {
  readonly bytes: Uint8Array

  private constructor(bytes: Uint8Array) {
    this.bytes = bytes
  }

  static deserialize(data: Uint8Array): KEMSecretKey {
    if (!pqTagged(data, PQ_SECRET_LENGTH)) throw fault('invalidKey', 'unrecognized key encapsulation secret')
    return new KEMSecretKey(new Uint8Array(data))
  }

  /** @internal */
  static unchecked(bytes: Uint8Array): KEMSecretKey {
    return new KEMSecretKey(bytes)
  }

  serialize(): Uint8Array {
    return new Uint8Array(this.bytes)
  }

  decapsulate(ciphertext: Uint8Array): Uint8Array {
    return core.pqOpen(this.bytes, ciphertext)
  }
}

export class KEMKeyPair {
  readonly publicKey: KEMPublicKey
  readonly secretKey: KEMSecretKey

  constructor(publicKey: KEMPublicKey, secretKey: KEMSecretKey) {
    this.publicKey = publicKey
    this.secretKey = secretKey
  }

  static generate(): KEMKeyPair {
    const { publicKey, secret } = core.pqPair(PQ_ROUND_THREE)
    return new KEMKeyPair(KEMPublicKey.unchecked(publicKey), KEMSecretKey.unchecked(secret))
  }

  getPublicKey(): KEMPublicKey {
    return this.publicKey
  }

  getSecretKey(): KEMSecretKey {
    return this.secretKey
  }
}

// Addresses

export class ProtocolAddress {
  readonly name: string
  readonly deviceId: number

  constructor(name: string, deviceId: number) {
    if (name.length === 0) throw fault('invalidArgument', 'empty address name')
    if (deviceId === 0) throw fault('invalidArgument', 'device id must not be zero')
    this.name = name
    this.deviceId = deviceId >>> 0
  }

  static new(name: string, deviceId: number): ProtocolAddress {
    return new ProtocolAddress(name, deviceId)
  }

  toString(): string {
    return `${this.name}.${this.deviceId}`
  }

  serviceId(): ServiceId | null {
    try {
      return ServiceId.parseFromServiceIdString(this.name)
    } catch {
      return null
    }
  }
}

export enum ServiceIdKind {
  Aci = 0,
  Pni = 1,
}

export class ServiceId {
  readonly kind: ServiceIdKind
  readonly rawUuid: Uint8Array

  constructor(kind: ServiceIdKind, rawUuid: Uint8Array) {
    if (rawUuid.length !== 16) throw fault('invalidArgument', 'a uuid is 16 bytes')
    this.kind = kind
    this.rawUuid = new Uint8Array(rawUuid)
  }

  static parseFromServiceIdString(s: string): ServiceId {
    if (s.startsWith('PNI:')) return new ServiceId(ServiceIdKind.Pni, uuidToBytes(s.slice(4)))
    return new ServiceId(ServiceIdKind.Aci, uuidToBytes(s))
  }

  static parseFromServiceIdFixedWidthBinary(bytes: Uint8Array): ServiceId {
    if (bytes.length !== 17 || bytes[0] > 1) throw fault('invalidArgument', 'bad service id')
    return new ServiceId(bytes[0] as ServiceIdKind, bytes.slice(1))
  }

  static parseFromServiceIdBinary(bytes: Uint8Array): ServiceId {
    if (bytes.length === 16) return new ServiceId(ServiceIdKind.Aci, bytes)
    if (bytes.length === 17 && bytes[0] === 1) return new ServiceId(ServiceIdKind.Pni, bytes.slice(1))
    throw fault('invalidArgument', 'bad service id')
  }

  getServiceIdString(): string {
    const uuid = bytesToUuid(this.rawUuid)
    return this.kind === ServiceIdKind.Pni ? `PNI:${uuid}` : uuid
  }

  getServiceIdFixedWidthBinary(): Uint8Array {
    const out = new Uint8Array(17)
    out[0] = this.kind
    out.set(this.rawUuid, 1)
    return out
  }

  getServiceIdBinary(): Uint8Array {
    return this.kind === ServiceIdKind.Aci ? new Uint8Array(this.rawUuid) : this.getServiceIdFixedWidthBinary()
  }

  toString(): string {
    return this.getServiceIdString()
  }

  equals(other: ServiceId): boolean {
    return this.kind === other.kind && bytesEqual(this.rawUuid, other.rawUuid)
  }
}

export class Aci extends ServiceId {
  constructor(rawUuid: Uint8Array) {
    super(ServiceIdKind.Aci, rawUuid)
  }

  static fromUuid(uuid: string): Aci {
    return new Aci(uuidToBytes(uuid))
  }
}

export class Pni extends ServiceId {
  constructor(rawUuid: Uint8Array) {
    super(ServiceIdKind.Pni, rawUuid)
  }

  static fromUuid(uuid: string): Pni {
    return new Pni(uuidToBytes(uuid))
  }
}

// Records

export class PreKeyRecord {
  readonly bytes: Uint8Array
  readonly #id: number
  readonly #publicKey: Uint8Array
  readonly #secret: Uint8Array

  private constructor(bytes: Uint8Array) {
    const parsed = core.oneTimeParse(bytes)
    this.bytes = bytes
    this.#id = parsed.id
    this.#publicKey = parsed.publicKey
    this.#secret = parsed.secret
  }

  static new(id: number, _publicKey: PublicKey, privateKey: PrivateKey): PreKeyRecord {
    return new PreKeyRecord(core.oneTimeRecord(id >>> 0, privateKey.bytes))
  }

  static deserialize(data: Uint8Array): PreKeyRecord {
    return new PreKeyRecord(new Uint8Array(data))
  }

  serialize(): Uint8Array {
    return new Uint8Array(this.bytes)
  }

  id(): number {
    return this.#id
  }

  publicKey(): PublicKey {
    return PublicKey.unchecked(this.#publicKey)
  }

  privateKey(): PrivateKey {
    return PrivateKey.unchecked(this.#secret)
  }
}

export class SignedPreKeyRecord {
  readonly bytes: Uint8Array
  readonly #id: number
  readonly #stamp: bigint
  readonly #publicKey: Uint8Array
  readonly #secret: Uint8Array
  readonly #signature: Uint8Array

  private constructor(bytes: Uint8Array) {
    const parsed = core.signedParse(bytes)
    this.bytes = bytes
    this.#id = parsed.id
    this.#stamp = parsed.stamp
    this.#publicKey = parsed.publicKey
    this.#secret = parsed.secret
    this.#signature = parsed.signature
  }

  static new(id: number, timestamp: number | bigint, _publicKey: PublicKey, privateKey: PrivateKey, signature: Uint8Array): SignedPreKeyRecord {
    return new SignedPreKeyRecord(core.signedRecord(id >>> 0, BigInt(timestamp), privateKey.bytes, signature))
  }

  static deserialize(data: Uint8Array): SignedPreKeyRecord {
    return new SignedPreKeyRecord(new Uint8Array(data))
  }

  serialize(): Uint8Array {
    return new Uint8Array(this.bytes)
  }

  id(): number {
    return this.#id
  }

  timestamp(): number {
    return Number(this.#stamp)
  }

  publicKey(): PublicKey {
    return PublicKey.unchecked(this.#publicKey)
  }

  privateKey(): PrivateKey {
    return PrivateKey.unchecked(this.#secret)
  }

  signature(): Uint8Array {
    return new Uint8Array(this.#signature)
  }
}

export class KyberPreKeyRecord {
  readonly bytes: Uint8Array
  readonly #id: number
  readonly #stamp: bigint
  readonly #publicKey: Uint8Array
  readonly #secret: Uint8Array
  readonly #signature: Uint8Array

  private constructor(bytes: Uint8Array) {
    const parsed = core.pqRecordParse(bytes)
    this.bytes = bytes
    this.#id = parsed.id
    this.#stamp = parsed.stamp
    this.#publicKey = parsed.publicKey
    this.#secret = parsed.secret
    this.#signature = parsed.signature
  }

  static new(id: number, timestamp: number | bigint, keyPair: KEMKeyPair, signature: Uint8Array): KyberPreKeyRecord {
    return new KyberPreKeyRecord(core.pqRecord(id >>> 0, BigInt(timestamp), keyPair.publicKey.bytes, keyPair.secretKey.bytes, signature))
  }

  static deserialize(data: Uint8Array): KyberPreKeyRecord {
    return new KyberPreKeyRecord(new Uint8Array(data))
  }

  serialize(): Uint8Array {
    return new Uint8Array(this.bytes)
  }

  id(): number {
    return this.#id
  }

  timestamp(): number {
    return Number(this.#stamp)
  }

  keyPair(): KEMKeyPair {
    return new KEMKeyPair(KEMPublicKey.unchecked(this.#publicKey), KEMSecretKey.unchecked(this.#secret))
  }

  publicKey(): KEMPublicKey {
    return KEMPublicKey.unchecked(this.#publicKey)
  }

  secretKey(): KEMSecretKey {
    return KEMSecretKey.unchecked(this.#secret)
  }

  signature(): Uint8Array {
    return new Uint8Array(this.#signature)
  }
}

/** A session with one device. Protocol operations replace the bytes in place. */
export class SessionRecord {
  bytes: Uint8Array

  private constructor(bytes: Uint8Array) {
    this.bytes = bytes
  }

  static deserialize(data: Uint8Array): SessionRecord {
    core.sessionInfo(data, 0n)
    return new SessionRecord(new Uint8Array(data))
  }

  /** @internal */
  static unchecked(bytes: Uint8Array): SessionRecord {
    return new SessionRecord(bytes)
  }

  serialize(): Uint8Array {
    return new Uint8Array(this.bytes)
  }

  archiveCurrentState(): void {
    this.bytes = core.sessionShelve(this.bytes)
  }

  hasCurrentState(now: Date = new Date()): boolean {
    return core.sessionInfo(this.bytes, nowSecs(now)).usable
  }

  currentRatchetKeyMatches(key: PublicKey): boolean {
    return core.sessionRatchetIs(this.bytes, key.bytes)
  }

  private live() {
    const info = core.sessionInfo(this.bytes, nowSecs())
    if (!info.hasLive) throw fault('invalidState', 'no current session')
    return info
  }

  remoteRegistrationId(): number {
    return this.live().remoteRegistrationId
  }

  localRegistrationId(): number {
    return this.live().localRegistrationId
  }

  sessionVersion(): number {
    return this.live().version
  }

  remoteIdentityKey(): PublicKey {
    return PublicKey.unchecked(this.live().remoteIdentity)
  }

  localIdentityKey(): PublicKey {
    return PublicKey.unchecked(this.live().localIdentity)
  }
}

export class SenderKeyRecord {
  bytes: Uint8Array

  private constructor(bytes: Uint8Array) {
    this.bytes = bytes
  }

  static deserialize(data: Uint8Array): SenderKeyRecord {
    return new SenderKeyRecord(new Uint8Array(data))
  }

  /** @internal */
  static unchecked(bytes: Uint8Array): SenderKeyRecord {
    return new SenderKeyRecord(bytes)
  }

  serialize(): Uint8Array {
    return new Uint8Array(this.bytes)
  }
}

export class PreKeyBundle {
  constructor(
    readonly registrationId: number,
    readonly deviceId: number,
    readonly preKeyId: number | null,
    readonly preKey: PublicKey | null,
    readonly signedPreKeyId: number,
    readonly signedPreKey: PublicKey,
    readonly signedPreKeySignature: Uint8Array,
    readonly identityKey: PublicKey,
    readonly kyberPreKeyId: number,
    readonly kyberPreKey: KEMPublicKey,
    readonly kyberPreKeySignature: Uint8Array,
  ) {}

  static new(
    registrationId: number,
    deviceId: number,
    prekeyId: number | null,
    prekey: PublicKey | null,
    signedPrekeyId: number,
    signedPrekey: PublicKey,
    signedPrekeySignature: Uint8Array,
    identityKey: PublicKey,
    kyberPrekeyId: number,
    kyberPrekey: KEMPublicKey,
    kyberPrekeySignature: Uint8Array,
  ): PreKeyBundle {
    return new PreKeyBundle(registrationId, deviceId, prekeyId, prekey, signedPrekeyId, signedPrekey, signedPrekeySignature, identityKey, kyberPrekeyId, kyberPrekey, kyberPrekeySignature)
  }
}

// Messages

export enum CiphertextMessageType {
  Whisper = 2,
  PreKey = 3,
  SenderKey = 7,
  Plaintext = 8,
}

export class CiphertextMessage {
  readonly #type: CiphertextMessageType
  readonly bytes: Uint8Array

  /** @internal */
  constructor(type: CiphertextMessageType, bytes: Uint8Array) {
    this.#type = type
    this.bytes = bytes
  }

  static from(message: WhisperMessage | PreKeyMessage | SenderKeyMessage | PlaintextContent): CiphertextMessage {
    if (message instanceof WhisperMessage) return new CiphertextMessage(CiphertextMessageType.Whisper, message.bytes)
    if (message instanceof PreKeyMessage) return new CiphertextMessage(CiphertextMessageType.PreKey, message.bytes)
    if (message instanceof SenderKeyMessage) return new CiphertextMessage(CiphertextMessageType.SenderKey, message.bytes)
    return new CiphertextMessage(CiphertextMessageType.Plaintext, message.bytes)
  }

  serialize(): Uint8Array {
    return new Uint8Array(this.bytes)
  }

  type(): CiphertextMessageType {
    return this.#type
  }
}

/** A ratchet message: the sender's ratchet key, its place in the chain and the sealed body. */
export class WhisperMessage {
  readonly bytes: Uint8Array
  readonly #version: number
  readonly #index: number
  readonly #previousIndex: number
  readonly #ratchet: Uint8Array
  readonly #body: Uint8Array

  private constructor(bytes: Uint8Array) {
    const { info, body } = core.whisperParse(bytes)
    this.bytes = bytes
    this.#version = info.version
    this.#index = info.index
    this.#previousIndex = info.previousIndex
    this.#ratchet = info.ratchet
    this.#body = body
  }

  static deserialize(data: Uint8Array): WhisperMessage {
    return new WhisperMessage(new Uint8Array(data))
  }

  serialize(): Uint8Array {
    return new Uint8Array(this.bytes)
  }

  messageVersion(): number {
    return this.#version
  }

  counter(): number {
    return this.#index
  }

  previousCounter(): number {
    return this.#previousIndex
  }

  senderRatchetKey(): PublicKey {
    return PublicKey.unchecked(this.#ratchet)
  }

  body(): Uint8Array {
    return new Uint8Array(this.#body)
  }
}

/** The first message of a session: the handshake material around a whisper. */
export class PreKeyMessage {
  readonly bytes: Uint8Array
  readonly #version: number
  readonly #registrationId: number
  readonly #oneTimeId: number | null
  readonly #signedId: number
  readonly #pqId: number | null
  readonly #base: Uint8Array
  readonly #identity: Uint8Array
  readonly #inner: Uint8Array

  private constructor(bytes: Uint8Array) {
    const { info, inner } = core.openerParse(bytes)
    this.bytes = bytes
    this.#version = info.version
    this.#registrationId = info.registrationId
    this.#oneTimeId = info.oneTimeId
    this.#signedId = info.signedId
    this.#pqId = info.pqId
    this.#base = info.base
    this.#identity = info.identity
    this.#inner = inner
  }

  static deserialize(data: Uint8Array): PreKeyMessage {
    return new PreKeyMessage(new Uint8Array(data))
  }

  serialize(): Uint8Array {
    return new Uint8Array(this.bytes)
  }

  version(): number {
    return this.#version
  }

  registrationId(): number {
    return this.#registrationId
  }

  preKeyId(): number | null {
    return this.#oneTimeId
  }

  signedPreKeyId(): number {
    return this.#signedId
  }

  kyberPreKeyId(): number | null {
    return this.#pqId
  }

  baseKey(): PublicKey {
    return PublicKey.unchecked(this.#base)
  }

  identityKey(): PublicKey {
    return PublicKey.unchecked(this.#identity)
  }

  whisperMessage(): WhisperMessage {
    return WhisperMessage.deserialize(this.#inner)
  }

  signalMessage(): WhisperMessage {
    return this.whisperMessage()
  }
}

export class SenderKeyMessage {
  readonly bytes: Uint8Array
  readonly #version: number
  readonly #distributionId: string
  readonly #chainId: number
  readonly #step: number
  readonly #body: Uint8Array

  private constructor(bytes: Uint8Array) {
    const parsed = core.noteParse(bytes)
    this.bytes = bytes
    this.#version = parsed.version
    this.#distributionId = bytesToUuid(parsed.circleId)
    this.#chainId = parsed.chainId
    this.#step = parsed.step
    this.#body = parsed.body
  }

  static deserialize(data: Uint8Array): SenderKeyMessage {
    return new SenderKeyMessage(new Uint8Array(data))
  }

  serialize(): Uint8Array {
    return new Uint8Array(this.bytes)
  }

  messageVersion(): number {
    return this.#version
  }

  distributionId(): string {
    return this.#distributionId
  }

  chainId(): number {
    return this.#chainId
  }

  iteration(): number {
    return this.#step
  }

  ciphertext(): Uint8Array {
    return new Uint8Array(this.#body)
  }
}

export class SenderKeyDistributionMessage {
  readonly bytes: Uint8Array
  readonly #version: number
  readonly #distributionId: string
  readonly #chainId: number
  readonly #step: number
  readonly #seed: Uint8Array
  readonly #signing: Uint8Array

  private constructor(bytes: Uint8Array) {
    const parsed = core.announceParse(bytes)
    this.bytes = bytes
    this.#version = parsed.version
    this.#distributionId = bytesToUuid(parsed.circleId)
    this.#chainId = parsed.chainId
    this.#step = parsed.step
    this.#seed = parsed.seed
    this.#signing = parsed.signing
  }

  static deserialize(data: Uint8Array): SenderKeyDistributionMessage {
    return new SenderKeyDistributionMessage(new Uint8Array(data))
  }

  /** Starts a sender key for `distributionId` in `store` and returns the message the group needs. */
  static async create(sender: ProtocolAddress, distributionId: string, store: SenderKeyStore): Promise<SenderKeyDistributionMessage> {
    const existing = (await store.getSenderKey(sender, distributionId))?.bytes ?? new Uint8Array(0)
    const { record, announce } = core.circleAnnounce(existing, uuidToBytes(distributionId))
    await store.saveSenderKey(sender, distributionId, SenderKeyRecord.unchecked(record))
    return new SenderKeyDistributionMessage(announce)
  }

  serialize(): Uint8Array {
    return new Uint8Array(this.bytes)
  }

  messageVersion(): number {
    return this.#version
  }

  distributionId(): string {
    return this.#distributionId
  }

  chainId(): number {
    return this.#chainId
  }

  iteration(): number {
    return this.#step
  }

  chainKey(): Uint8Array {
    return new Uint8Array(this.#seed)
  }

  signatureKey(): PublicKey {
    return PublicKey.unchecked(this.#signing)
  }
}

export class DecryptionErrorMessage {
  readonly bytes: Uint8Array
  readonly #stampMs: bigint
  readonly #device: number
  readonly #ratchet: Uint8Array | null

  private constructor(bytes: Uint8Array) {
    const parsed = core.reportParse(bytes)
    this.bytes = bytes
    this.#stampMs = parsed.stampMs
    this.#device = parsed.device
    this.#ratchet = parsed.ratchet
  }

  static forOriginal(bytes: Uint8Array, type: CiphertextMessageType, timestamp: number | bigint, originalSenderDeviceId: number): DecryptionErrorMessage {
    return new DecryptionErrorMessage(core.report(bytes, type, BigInt(timestamp), originalSenderDeviceId >>> 0))
  }

  static deserialize(data: Uint8Array): DecryptionErrorMessage {
    return new DecryptionErrorMessage(new Uint8Array(data))
  }

  static extractFromSerializedBody(body: Uint8Array): DecryptionErrorMessage {
    return new DecryptionErrorMessage(core.reportInBody(body))
  }

  serialize(): Uint8Array {
    return new Uint8Array(this.bytes)
  }

  timestamp(): number {
    return Number(this.#stampMs)
  }

  deviceId(): number {
    return this.#device
  }

  ratchetKey(): PublicKey | undefined {
    return this.#ratchet ? PublicKey.unchecked(this.#ratchet) : undefined
  }
}

export class PlaintextContent {
  readonly bytes: Uint8Array
  readonly #body: Uint8Array

  private constructor(bytes: Uint8Array) {
    this.bytes = bytes
    this.#body = core.plainBody(bytes)
  }

  static from(message: DecryptionErrorMessage): PlaintextContent {
    return new PlaintextContent(core.plainFromReport(message.bytes))
  }

  static deserialize(data: Uint8Array): PlaintextContent {
    return new PlaintextContent(new Uint8Array(data))
  }

  serialize(): Uint8Array {
    return new Uint8Array(this.bytes)
  }

  body(): Uint8Array {
    return new Uint8Array(this.#body)
  }
}

// Stores

export enum Direction {
  Sending = 0,
  Receiving = 1,
}

export enum IdentityChange {
  NewOrUnchanged = 0,
  ReplacedExisting = 1,
}

export abstract class SessionStore {
  abstract saveSession(name: ProtocolAddress, record: SessionRecord): Promise<void>
  abstract getSession(name: ProtocolAddress): Promise<SessionRecord | null>
  abstract getExistingSessions(addresses: ProtocolAddress[]): Promise<SessionRecord[]>
}

export abstract class IdentityKeyStore {
  abstract getIdentityKey(): Promise<PrivateKey>
  abstract getLocalRegistrationId(): Promise<number>
  abstract saveIdentity(name: ProtocolAddress, key: PublicKey): Promise<IdentityChange>
  abstract isTrustedIdentity(name: ProtocolAddress, key: PublicKey, direction: Direction): Promise<boolean>
  abstract getIdentity(name: ProtocolAddress): Promise<PublicKey | null>
}

export abstract class PreKeyStore {
  abstract savePreKey(id: number, record: PreKeyRecord): Promise<void>
  abstract getPreKey(id: number): Promise<PreKeyRecord>
  abstract removePreKey(id: number): Promise<void>
}

export abstract class SignedPreKeyStore {
  abstract saveSignedPreKey(id: number, record: SignedPreKeyRecord): Promise<void>
  abstract getSignedPreKey(id: number): Promise<SignedPreKeyRecord>
}

export abstract class KyberPreKeyStore {
  abstract saveKyberPreKey(id: number, record: KyberPreKeyRecord): Promise<void>
  abstract getKyberPreKey(id: number): Promise<KyberPreKeyRecord>
  abstract markKyberPreKeyUsed(id: number, signedPreKeyId: number, baseKey: PublicKey): Promise<void>
}

export abstract class SenderKeyStore {
  abstract saveSenderKey(sender: ProtocolAddress, distributionId: string, record: SenderKeyRecord): Promise<void>
  abstract getSenderKey(sender: ProtocolAddress, distributionId: string): Promise<SenderKeyRecord | null>
}

function senderKeyName(sender: ProtocolAddress, distributionId: string): string {
  return `${sender.toString()}|${distributionId.toLowerCase()}`
}

/** Every store in one object, in memory. Trust is on first use. */
export class InMemoryProtocolStore extends SessionStore implements IdentityKeyStore, PreKeyStore, SignedPreKeyStore, KyberPreKeyStore, SenderKeyStore {
  readonly #identity: IdentityKeyPair
  readonly #registrationId: number
  readonly #identities = new Map<string, PublicKey>()
  readonly #sessions = new Map<string, SessionRecord>()
  readonly #preKeys = new Map<number, PreKeyRecord>()
  readonly #signedPreKeys = new Map<number, SignedPreKeyRecord>()
  readonly #kyberPreKeys = new Map<number, KyberPreKeyRecord>()
  readonly #kyberUsed = new Set<number>()
  readonly #senderKeys = new Map<string, SenderKeyRecord>()

  constructor(identity: IdentityKeyPair = IdentityKeyPair.generate(), registrationId: number = 1 + Math.floor(Math.random() * 16380)) {
    super()
    this.#identity = identity
    this.#registrationId = registrationId
  }

  async saveSession(name: ProtocolAddress, record: SessionRecord): Promise<void> {
    this.#sessions.set(name.toString(), record)
  }

  async getSession(name: ProtocolAddress): Promise<SessionRecord | null> {
    return this.#sessions.get(name.toString()) ?? null
  }

  async getExistingSessions(addresses: ProtocolAddress[]): Promise<SessionRecord[]> {
    return addresses.map(a => {
      const s = this.#sessions.get(a.toString())
      if (!s) throw fault('sessionNotFound', `no session for ${a.toString()}`)
      return s
    })
  }

  async getIdentityKey(): Promise<PrivateKey> {
    return this.#identity.privateKey
  }

  async getLocalRegistrationId(): Promise<number> {
    return this.#registrationId
  }

  async saveIdentity(name: ProtocolAddress, key: PublicKey): Promise<IdentityChange> {
    const previous = this.#identities.get(name.toString())
    this.#identities.set(name.toString(), key)
    return previous && !previous.equals(key) ? IdentityChange.ReplacedExisting : IdentityChange.NewOrUnchanged
  }

  async isTrustedIdentity(name: ProtocolAddress, key: PublicKey, _direction: Direction): Promise<boolean> {
    const known = this.#identities.get(name.toString())
    return known === undefined || known.equals(key)
  }

  async getIdentity(name: ProtocolAddress): Promise<PublicKey | null> {
    return this.#identities.get(name.toString()) ?? null
  }

  async savePreKey(id: number, record: PreKeyRecord): Promise<void> {
    this.#preKeys.set(id, record)
  }

  async getPreKey(id: number): Promise<PreKeyRecord> {
    const r = this.#preKeys.get(id)
    if (!r) throw fault('invalidKeyId', `no prekey ${id}`)
    return r
  }

  async removePreKey(id: number): Promise<void> {
    this.#preKeys.delete(id)
  }

  async saveSignedPreKey(id: number, record: SignedPreKeyRecord): Promise<void> {
    this.#signedPreKeys.set(id, record)
  }

  async getSignedPreKey(id: number): Promise<SignedPreKeyRecord> {
    const r = this.#signedPreKeys.get(id)
    if (!r) throw fault('invalidKeyId', `no signed prekey ${id}`)
    return r
  }

  async saveKyberPreKey(id: number, record: KyberPreKeyRecord): Promise<void> {
    this.#kyberPreKeys.set(id, record)
  }

  async getKyberPreKey(id: number): Promise<KyberPreKeyRecord> {
    const r = this.#kyberPreKeys.get(id)
    if (!r) throw fault('invalidKeyId', `no kyber prekey ${id}`)
    return r
  }

  async markKyberPreKeyUsed(id: number, _signedPreKeyId: number, _baseKey: PublicKey): Promise<void> {
    this.#kyberUsed.add(id)
  }

  hasKyberPreKeyBeenUsed(id: number): boolean {
    return this.#kyberUsed.has(id)
  }

  async saveSenderKey(sender: ProtocolAddress, distributionId: string, record: SenderKeyRecord): Promise<void> {
    this.#senderKeys.set(senderKeyName(sender, distributionId), record)
  }

  async getSenderKey(sender: ProtocolAddress, distributionId: string): Promise<SenderKeyRecord | null> {
    return this.#senderKeys.get(senderKeyName(sender, distributionId)) ?? null
  }
}

// Sessions

function binding(sender: ProtocolAddress | null, recipient: ProtocolAddress | null): Binding {
  return { sender: sender?.name ?? null, senderDevice: sender?.deviceId ?? 0, recipient: recipient?.name ?? null, recipientDevice: recipient?.deviceId ?? 0 }
}

export async function processBundle(bundle: PreKeyBundle, address: ProtocolAddress, sessionStore: SessionStore, identityStore: IdentityKeyStore, now: Date = new Date(), localAddress: ProtocolAddress | null = null): Promise<void> {
  void localAddress
  if (!(await identityStore.isTrustedIdentity(address, bundle.identityKey, Direction.Sending))) throw untrusted(address)
  const identity = await identityStore.getIdentityKey()
  const registrationId = await identityStore.getLocalRegistrationId()
  const existing = (await sessionStore.getSession(address))?.bytes ?? new Uint8Array(0)
  const record = core.sessionStart(identity.bytes, registrationId, existing, {
    registrationId: bundle.registrationId,
    device: bundle.deviceId,
    oneTimeId: bundle.preKeyId,
    oneTime: bundle.preKey?.bytes ?? null,
    signedId: bundle.signedPreKeyId,
    signedKey: bundle.signedPreKey.bytes,
    signedSignature: bundle.signedPreKeySignature,
    identity: bundle.identityKey.bytes,
    pqId: bundle.kyberPreKeyId,
    pqKey: bundle.kyberPreKey.bytes,
    pqSignature: bundle.kyberPreKeySignature,
  }, nowSecs(now))
  await identityStore.saveIdentity(address, bundle.identityKey)
  await sessionStore.saveSession(address, SessionRecord.unchecked(record))
}

export async function sessionEncrypt(message: Uint8Array, address: ProtocolAddress, sessionStore: SessionStore, identityStore: IdentityKeyStore, now: Date = new Date(), localAddress: ProtocolAddress | null = null): Promise<CiphertextMessage> {
  const session = await sessionStore.getSession(address)
  if (!session) throw fault('sessionNotFound', `no session for ${address.toString()}`)
  const { kind, sealed, record } = core.sessionSeal(session.bytes, message, nowSecs(now), binding(localAddress, address))
  const theirIdentity = PublicKey.unchecked(core.sessionInfo(record, nowSecs(now)).remoteIdentity)
  if (!(await identityStore.isTrustedIdentity(address, theirIdentity, Direction.Sending))) throw untrusted(address)
  await sessionStore.saveSession(address, SessionRecord.unchecked(record))
  return new CiphertextMessage(kind as CiphertextMessageType, sealed)
}

async function commit(record: Uint8Array, address: ProtocolAddress, sessionStore: SessionStore, identityStore: IdentityKeyStore): Promise<void> {
  const theirIdentity = PublicKey.unchecked(core.sessionInfo(record, nowSecs()).remoteIdentity)
  if (!(await identityStore.isTrustedIdentity(address, theirIdentity, Direction.Receiving))) throw untrusted(address)
  await identityStore.saveIdentity(address, theirIdentity)
  await sessionStore.saveSession(address, SessionRecord.unchecked(record))
}

export async function sessionDecrypt(message: WhisperMessage, address: ProtocolAddress, sessionStore: SessionStore, identityStore: IdentityKeyStore, localAddress: ProtocolAddress | null = null): Promise<Uint8Array> {
  const session = await sessionStore.getSession(address)
  if (!session) throw fault('sessionNotFound', `no session for ${address.toString()}`)
  const { plain, record } = core.sessionOpen(session.bytes, message.bytes, binding(address, localAddress))
  await commit(record, address, sessionStore, identityStore)
  return plain
}

export async function sessionDecryptPreKey(message: PreKeyMessage, address: ProtocolAddress, sessionStore: SessionStore, identityStore: IdentityKeyStore, prekeyStore: PreKeyStore, signedPrekeyStore: SignedPreKeyStore, kyberPrekeyStore: KyberPreKeyStore, localAddress: ProtocolAddress | null = null): Promise<Uint8Array> {
  if (!(await identityStore.isTrustedIdentity(address, message.identityKey(), Direction.Receiving))) throw untrusted(address)
  const identity = await identityStore.getIdentityKey()
  const registrationId = await identityStore.getLocalRegistrationId()
  const existing = (await sessionStore.getSession(address))?.bytes ?? new Uint8Array(0)
  const signed = (await signedPrekeyStore.getSignedPreKey(message.signedPreKeyId())).bytes
  const oneTimeId = message.preKeyId()
  const oneTime = oneTimeId === null ? new Uint8Array(0) : (await prekeyStore.getPreKey(oneTimeId)).bytes
  const pqId = message.kyberPreKeyId()
  const pq = pqId === null ? new Uint8Array(0) : (await kyberPrekeyStore.getKyberPreKey(pqId)).bytes
  const { plain, record, consumed } = core.sessionOpenFirst(identity.bytes, registrationId, existing, message.bytes, signed, oneTime, pq, binding(address, localAddress))
  await commit(record, address, sessionStore, identityStore)
  if (consumed.used) {
    if (consumed.oneTimeId !== null) await prekeyStore.removePreKey(consumed.oneTimeId)
    if (pqId !== null) await kyberPrekeyStore.markKyberPreKeyUsed(pqId, consumed.signedId, PublicKey.unchecked(consumed.base))
  }
  return plain
}

// Groups

export async function processSenderKeyDistributionMessage(sender: ProtocolAddress, message: SenderKeyDistributionMessage, store: SenderKeyStore): Promise<void> {
  const existing = (await store.getSenderKey(sender, message.distributionId()))?.bytes ?? new Uint8Array(0)
  await store.saveSenderKey(sender, message.distributionId(), SenderKeyRecord.unchecked(core.circleAdmit(existing, message.bytes)))
}

export async function groupEncrypt(sender: ProtocolAddress, distributionId: string, store: SenderKeyStore, message: Uint8Array): Promise<CiphertextMessage> {
  const record = await store.getSenderKey(sender, distributionId)
  if (!record) throw fault('sessionNotFound', `no sender key for ${sender.toString()} in ${distributionId}`)
  const { note, record: updated } = core.circleSeal(record.bytes, uuidToBytes(distributionId), message)
  await store.saveSenderKey(sender, distributionId, SenderKeyRecord.unchecked(updated))
  return new CiphertextMessage(CiphertextMessageType.SenderKey, note)
}

export async function groupDecrypt(sender: ProtocolAddress, store: SenderKeyStore, message: Uint8Array): Promise<Uint8Array> {
  const distributionId = bytesToUuid(core.noteParse(message).circleId)
  const record = await store.getSenderKey(sender, distributionId)
  if (!record) throw fault('sessionNotFound', `no sender key for ${sender.toString()} in ${distributionId}`)
  const { plain, record: updated } = core.circleOpen(record.bytes, message)
  await store.saveSenderKey(sender, distributionId, SenderKeyRecord.unchecked(updated))
  return plain
}

// Sealed sender

export class ServerCertificate {
  readonly bytes: Uint8Array
  readonly #keyId: number
  readonly #key: Uint8Array
  readonly #body: Uint8Array
  readonly #signature: Uint8Array

  private constructor(bytes: Uint8Array) {
    const parsed = core.serverCertParse(bytes)
    this.bytes = bytes
    this.#keyId = parsed.keyId
    this.#key = parsed.key
    this.#body = parsed.body
    this.#signature = parsed.signature
  }

  static new(keyId: number, serverKey: PublicKey, trustRoot: PrivateKey): ServerCertificate {
    return new ServerCertificate(core.serverCert(keyId >>> 0, serverKey.bytes, trustRoot.bytes))
  }

  static deserialize(data: Uint8Array): ServerCertificate {
    return new ServerCertificate(new Uint8Array(data))
  }

  serialize(): Uint8Array {
    return new Uint8Array(this.bytes)
  }

  keyId(): number {
    return this.#keyId
  }

  key(): PublicKey {
    return PublicKey.unchecked(this.#key)
  }

  certificate(): Uint8Array {
    return new Uint8Array(this.#body)
  }

  signature(): Uint8Array {
    return new Uint8Array(this.#signature)
  }
}

export class SenderCertificate {
  readonly bytes: Uint8Array
  readonly #device: number
  readonly #expiresMs: bigint
  readonly #key: Uint8Array
  readonly #senderId: string
  readonly #phone: string | null
  readonly #serverCert: Uint8Array
  readonly #body: Uint8Array
  readonly #signature: Uint8Array

  private constructor(bytes: Uint8Array) {
    const parsed = core.senderCertParse(bytes)
    this.bytes = bytes
    this.#device = parsed.device
    this.#expiresMs = parsed.expiresMs
    this.#key = parsed.key
    this.#senderId = utf8(parsed.senderId)
    this.#phone = parsed.phone ? utf8(parsed.phone) : null
    this.#serverCert = parsed.serverCert
    this.#body = parsed.body
    this.#signature = parsed.signature
  }

  static new(senderUuid: string, senderE164: string | null, senderDeviceId: number, senderKey: PublicKey, expiration: number | bigint, signerCert: ServerCertificate, signerKey: PrivateKey): SenderCertificate {
    return new SenderCertificate(core.senderCert(senderUuid, senderE164, senderDeviceId >>> 0, senderKey.bytes, BigInt(expiration), signerCert.bytes, signerKey.bytes))
  }

  static deserialize(data: Uint8Array): SenderCertificate {
    return new SenderCertificate(new Uint8Array(data))
  }

  serialize(): Uint8Array {
    return new Uint8Array(this.bytes)
  }

  validate(trustRoot: PublicKey, time: number | bigint): boolean {
    return core.senderCertCheck(this.bytes, trustRoot.bytes, BigInt(time))
  }

  senderUuid(): string {
    return this.#senderId
  }

  senderAci(): Aci | null {
    try {
      return Aci.fromUuid(this.#senderId)
    } catch {
      return null
    }
  }

  senderE164(): string | null {
    return this.#phone
  }

  senderDeviceId(): number {
    return this.#device
  }

  expiration(): number {
    return Number(this.#expiresMs)
  }

  key(): PublicKey {
    return PublicKey.unchecked(this.#key)
  }

  serverCertificate(): ServerCertificate {
    return ServerCertificate.deserialize(this.#serverCert)
  }

  certificate(): Uint8Array {
    return new Uint8Array(this.#body)
  }

  signature(): Uint8Array {
    return new Uint8Array(this.#signature)
  }
}

export enum ContentHint {
  Default = 0,
  Resendable = 1,
  Implicit = 2,
}

export class UnidentifiedSenderMessageContent {
  readonly bytes: Uint8Array
  readonly #kind: number
  readonly #hint: number
  readonly #body: Uint8Array
  readonly #senderCert: Uint8Array
  readonly #circleId: Uint8Array | null

  private constructor(bytes: Uint8Array) {
    const parsed = core.contentParse(bytes)
    this.bytes = bytes
    this.#kind = parsed.kind
    this.#hint = parsed.hint
    this.#body = parsed.body
    this.#senderCert = parsed.senderCert
    this.#circleId = parsed.circleId
  }

  static new(message: CiphertextMessage, sender: SenderCertificate, contentHint: ContentHint, groupId: Uint8Array | null = null): UnidentifiedSenderMessageContent {
    return new UnidentifiedSenderMessageContent(core.content(message.type(), sender.bytes, message.bytes, contentHint, groupId))
  }

  static deserialize(data: Uint8Array): UnidentifiedSenderMessageContent {
    return new UnidentifiedSenderMessageContent(new Uint8Array(data))
  }

  serialize(): Uint8Array {
    return new Uint8Array(this.bytes)
  }

  msgType(): CiphertextMessageType {
    return this.#kind as CiphertextMessageType
  }

  contentHint(): ContentHint {
    return this.#hint as ContentHint
  }

  groupId(): Uint8Array | null {
    return this.#circleId ? new Uint8Array(this.#circleId) : null
  }

  contents(): Uint8Array {
    return new Uint8Array(this.#body)
  }

  senderCertificate(): SenderCertificate {
    return SenderCertificate.deserialize(this.#senderCert)
  }
}

export async function sealedSenderEncryptMessage(message: Uint8Array, address: ProtocolAddress, senderCert: SenderCertificate, sessionStore: SessionStore, identityStore: IdentityKeyStore): Promise<Uint8Array> {
  const ciphertext = await sessionEncrypt(message, address, sessionStore, identityStore)
  const content = UnidentifiedSenderMessageContent.new(ciphertext, senderCert, ContentHint.Default)
  return sealedSenderEncrypt(content, address, identityStore)
}

export async function sealedSenderEncrypt(content: UnidentifiedSenderMessageContent, address: ProtocolAddress, identityStore: IdentityKeyStore): Promise<Uint8Array> {
  const theirIdentity = await identityStore.getIdentity(address)
  if (!theirIdentity) throw fault('sessionNotFound', `no identity for ${address.toString()}`)
  const identity = await identityStore.getIdentityKey()
  return core.envelopeSeal(identity.bytes, theirIdentity.bytes, content.bytes)
}

export interface SealedSenderRecipient {
  serviceId: ServiceId
  devices: Array<{ deviceId: number; registrationId: number }>
  identityKey: PublicKey
}

async function recipientsOf(addresses: ProtocolAddress[], identityStore: IdentityKeyStore, sessionStore: SessionStore): Promise<SealedSenderRecipient[]> {
  const sessions = await sessionStore.getExistingSessions(addresses)
  const byService = new Map<string, SealedSenderRecipient>()
  for (let i = 0; i < addresses.length; i++) {
    const address = addresses[i]
    const serviceId = address.serviceId()
    if (!serviceId) throw fault('invalidArgument', `${address.toString()} is not a service id`)
    const identity = await identityStore.getIdentity(address)
    if (!identity) throw fault('sessionNotFound', `no identity for ${address.toString()}`)
    const device = { deviceId: address.deviceId, registrationId: sessions[i].remoteRegistrationId() }
    const key = serviceId.getServiceIdString()
    const entry = byService.get(key)
    if (entry) entry.devices.push(device)
    else byService.set(key, { serviceId, devices: [device], identityKey: identity })
  }
  return [...byService.values()]
}

/** One envelope for every device of every recipient in `recipients`. */
export async function sealedSenderMultiRecipientEncrypt(content: UnidentifiedSenderMessageContent, recipients: ProtocolAddress[] | SealedSenderRecipient[], identityStore: IdentityKeyStore, sessionStore: SessionStore | null = null, excludedRecipients: ServiceId[] = []): Promise<Uint8Array> {
  let list: SealedSenderRecipient[]
  if (recipients.length > 0 && recipients[0] instanceof ProtocolAddress) {
    if (!sessionStore) throw fault('invalidArgument', 'addresses need a session store for registration ids')
    list = await recipientsOf(recipients as ProtocolAddress[], identityStore, sessionStore)
  } else {
    list = recipients as SealedSenderRecipient[]
  }
  const listing: number[] = [list.length]
  for (const r of list) {
    listing.push(...r.serviceId.getServiceIdFixedWidthBinary(), r.devices.length)
    for (const d of r.devices) {
      if (d.deviceId > 255 || d.registrationId > 0xffff) throw fault('invalidArgument', 'device or registration id does not fit the envelope')
      listing.push(d.deviceId, d.registrationId >> 8, d.registrationId & 0xff)
    }
    listing.push(...r.identityKey.bytes)
  }
  const excluded: number[] = [excludedRecipients.length]
  for (const s of excludedRecipients) excluded.push(...s.getServiceIdFixedWidthBinary())
  const identity = await identityStore.getIdentityKey()
  return core.envelopeSealMany(identity.bytes, Uint8Array.from(listing), Uint8Array.from(excluded), content.bytes)
}

export function sealedSenderMultiRecipientMessageForSingleRecipient(message: Uint8Array): Uint8Array {
  return core.envelopeForSingle(message)
}

export function sealedSenderMultiRecipientMessageForRecipient(message: Uint8Array, serviceId: ServiceId, deviceId: number): Uint8Array {
  return core.envelopeForRecipient(message, serviceId.getServiceIdFixedWidthBinary(), deviceId)
}

export async function sealedSenderDecryptToUsmc(message: Uint8Array, identityStore: IdentityKeyStore): Promise<UnidentifiedSenderMessageContent> {
  const identity = await identityStore.getIdentityKey()
  return UnidentifiedSenderMessageContent.deserialize(core.envelopeOpen(identity.bytes, message))
}

export interface SealedSenderDecryptionResult {
  message: Uint8Array
  senderUuid: string
  senderE164: string | null
  deviceId: number
}

export async function sealedSenderDecryptMessage(
  message: Uint8Array,
  trustRoot: PublicKey,
  timestamp: number | bigint,
  localE164: string | null,
  localUuid: string,
  localDeviceId: number,
  sessionStore: SessionStore,
  identityStore: IdentityKeyStore,
  prekeyStore: PreKeyStore,
  signedPrekeyStore: SignedPreKeyStore,
  kyberPrekeyStore: KyberPreKeyStore,
  senderKeyStore: SenderKeyStore | null = null,
): Promise<SealedSenderDecryptionResult> {
  const content = await sealedSenderDecryptToUsmc(message, identityStore)
  const certificate = content.senderCertificate()
  if (!certificate.validate(trustRoot, timestamp)) throw fault('invalidSignature', 'sender certificate failed validation')
  const senderUuid = certificate.senderUuid()
  const senderE164 = certificate.senderE164()
  const sameAccount = senderUuid === localUuid || (senderE164 !== null && senderE164 === localE164)
  if (sameAccount && certificate.senderDeviceId() === localDeviceId) throw fault('invalidMessage', 'message sealed by this device')
  const sender = new ProtocolAddress(senderUuid, certificate.senderDeviceId())
  const local = new ProtocolAddress(localUuid, localDeviceId)
  let plain: Uint8Array
  switch (content.msgType()) {
    case CiphertextMessageType.Whisper:
      plain = await sessionDecrypt(WhisperMessage.deserialize(content.contents()), sender, sessionStore, identityStore, local)
      break
    case CiphertextMessageType.PreKey:
      plain = await sessionDecryptPreKey(PreKeyMessage.deserialize(content.contents()), sender, sessionStore, identityStore, prekeyStore, signedPrekeyStore, kyberPrekeyStore, local)
      break
    case CiphertextMessageType.SenderKey:
      if (!senderKeyStore) throw fault('invalidArgument', 'a sender key message needs a sender key store')
      plain = await groupDecrypt(sender, senderKeyStore, content.contents())
      break
    case CiphertextMessageType.Plaintext:
      plain = PlaintextContent.deserialize(content.contents()).body()
      break
    default:
      throw fault('invalidMessage', 'unknown sealed message type')
  }
  return { message: plain, senderUuid, senderE164, deviceId: certificate.senderDeviceId() }
}

// Safety numbers

export class DisplayableFingerprint {
  constructor(private readonly formatted: string) {}

  toString(): string {
    return this.formatted
  }
}

export class ScannableFingerprint {
  constructor(private readonly encoding: Uint8Array) {}

  toBuffer(): Uint8Array {
    return new Uint8Array(this.encoding)
  }

  compare(other: Uint8Array | ScannableFingerprint): boolean {
    return core.safetyMatches(this.encoding, other instanceof ScannableFingerprint ? other.encoding : other)
  }
}

export class Fingerprint {
  private constructor(private readonly display: DisplayableFingerprint, private readonly scan: ScannableFingerprint) {}

  static new(iterations: number, version: number, localIdentifier: Uint8Array, localKey: PublicKey, remoteIdentifier: Uint8Array, remoteKey: PublicKey): Fingerprint {
    const { display, scannable } = core.safety(version >>> 0, iterations >>> 0, localIdentifier, localKey.bytes, remoteIdentifier, remoteKey.bytes)
    return new Fingerprint(new DisplayableFingerprint(display), new ScannableFingerprint(scannable))
  }

  displayableFingerprint(): DisplayableFingerprint {
    return this.display
  }

  scannableFingerprint(): ScannableFingerprint {
    return this.scan
  }
}

// Usernames

export const usernames = {
  hash(username: string): Uint8Array {
    return core.handleHash(username)
  },
  generateProof(username: string, randomness: Uint8Array = core.random(32)): Uint8Array {
    return core.handleProof(username, randomness)
  },
  verifyProof(proof: Uint8Array, hash: Uint8Array): void {
    if (!core.handleVerify(proof, hash)) throw fault('verificationFailed', 'username proof does not match hash')
  },
  generateCandidates(nickname: string, minNicknameLength: number = 3, maxNicknameLength: number = 32): string[] {
    return core.handleCandidates(nickname, minNicknameLength, maxNicknameLength)
  },
  fromParts(nickname: string, discriminator: string, minNicknameLength: number = 3, maxNicknameLength: number = 32): { username: string; hash: Uint8Array } {
    const { handle, hash } = core.handleFromParts(nickname, discriminator, minNicknameLength, maxNicknameLength)
    return { username: handle, hash }
  },
  createUsernameLink(username: string, previousEntropy: Uint8Array | null = null): { entropy: Uint8Array; encryptedUsername: Uint8Array } {
    const { entropy, sealed } = core.handleLink(username, previousEntropy)
    return { entropy, encryptedUsername: sealed }
  },
  decryptUsernameLink(entropy: Uint8Array, encryptedUsername: Uint8Array): string {
    return core.handleLinkOpen(entropy, encryptedUsername)
  },
}

// Account keys

export class BackupKey {
  static readonly SIZE = 32
  readonly bytes: Uint8Array

  constructor(contents: Uint8Array) {
    if (contents.length !== BackupKey.SIZE) throw fault('invalidArgument', 'a backup key is 32 bytes')
    this.bytes = new Uint8Array(contents)
  }

  static generateRandom(): BackupKey {
    return new BackupKey(core.backupKeyRandom())
  }

  serialize(): Uint8Array {
    return new Uint8Array(this.bytes)
  }

  deriveBackupId(aci: Aci): Uint8Array {
    return core.backupKeyForAccount(this.bytes, aci.getServiceIdString()).backupId
  }

  deriveEcKey(aci: Aci): PrivateKey {
    return PrivateKey.unchecked(core.backupKeyForAccount(this.bytes, aci.getServiceIdString()).signingKey)
  }

  deriveLocalBackupMetadataKey(): Uint8Array {
    return core.backupKeyLocalMetadata(this.bytes)
  }

  deriveMediaId(mediaName: string): Uint8Array {
    return core.backupKeyMedia(this.bytes, mediaName).mediaId
  }

  deriveMediaEncryptionKey(mediaId: Uint8Array): Uint8Array {
    return core.backupKeyMediaKeys(this.bytes, mediaId).mediaKey
  }

  deriveThumbnailTransitEncryptionKey(mediaId: Uint8Array): Uint8Array {
    return core.backupKeyMediaKeys(this.bytes, mediaId).thumbnailKey
  }
}

export const AccountEntropyPool = {
  generate(): string {
    return core.poolRandom()
  },
  isValid(pool: string): boolean {
    return core.poolValid(pool)
  },
  deriveSvrKey(pool: string): Uint8Array {
    return core.poolDerive(pool).recoveryKey
  },
  deriveBackupKey(pool: string): BackupKey {
    return new BackupKey(core.poolDerive(pool).backupKey)
  },
}

// Group parameters

export class GroupMasterKey {
  static readonly SIZE = 32
  readonly bytes: Uint8Array

  constructor(contents: Uint8Array) {
    if (contents.length !== GroupMasterKey.SIZE) throw fault('invalidArgument', 'a group master key is 32 bytes')
    this.bytes = new Uint8Array(contents)
  }

  static generate(): GroupMasterKey {
    return new GroupMasterKey(core.circleMasterRandom())
  }

  serialize(): Uint8Array {
    return new Uint8Array(this.bytes)
  }
}

export class GroupSecretParams {
  readonly bytes: Uint8Array

  constructor(contents: Uint8Array) {
    core.circleParamsInfo(contents)
    this.bytes = new Uint8Array(contents)
  }

  static generate(): GroupSecretParams {
    return GroupSecretParams.deriveFromMasterKey(GroupMasterKey.generate())
  }

  static deriveFromMasterKey(masterKey: GroupMasterKey): GroupSecretParams {
    return new GroupSecretParams(core.circleSecretParams(masterKey.bytes))
  }

  serialize(): Uint8Array {
    return new Uint8Array(this.bytes)
  }

  getMasterKey(): GroupMasterKey {
    return new GroupMasterKey(core.circleParamsInfo(this.bytes).master)
  }

  getGroupIdentifier(): Uint8Array {
    return core.circleParamsInfo(this.bytes).identifier
  }

  getPublicParams(): Uint8Array {
    return core.circleParamsInfo(this.bytes).publicParams
  }
}

// Primitives

export function hkdf(outputLength: number, keyMaterial: Uint8Array, label: Uint8Array, salt: Uint8Array | null = null): Uint8Array {
  return core.hkdf(keyMaterial, salt, label, outputLength >>> 0)
}

export class Aes256GcmSiv {
  readonly #key: Uint8Array

  constructor(key: Uint8Array) {
    if (key.length !== 32) throw fault('invalidKey', 'a key is 32 bytes')
    this.#key = new Uint8Array(key)
  }

  static new(key: Uint8Array): Aes256GcmSiv {
    return new Aes256GcmSiv(key)
  }

  encrypt(message: Uint8Array, nonce: Uint8Array, associatedData: Uint8Array = new Uint8Array(0)): Uint8Array {
    return core.sivSeal(this.#key, nonce, message, associatedData)
  }

  decrypt(message: Uint8Array, nonce: Uint8Array, associatedData: Uint8Array = new Uint8Array(0)): Uint8Array {
    return core.sivOpen(this.#key, nonce, message, associatedData)
  }
}

export const IncrementalMac = {
  calculate(key: Uint8Array, chunkSize: number, data: Uint8Array): Uint8Array {
    return core.chunkTags(key, chunkSize >>> 0, data)
  },
  validate(key: Uint8Array, chunkSize: number, data: Uint8Array, digest: Uint8Array): void {
    core.chunkCheck(key, chunkSize >>> 0, data, digest)
  },
}

export function randomBytes(length: number): Uint8Array {
  return core.random(length >>> 0)
}

export function abiVersion(): number {
  return core.abiVersion()
}

export { MessageType }

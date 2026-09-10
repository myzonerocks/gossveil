// Typed calls into the core. A Call gathers inputs, scalars, output cells and
// pads in argument order, runs one export, copies every output out and frees
// everything before returning.
import { In, Out, Pad, check, invoke, textDecoder } from './core.js'
import type { Arg } from './core.js'

class Call {
  readonly #name: string
  readonly #args: Arg[] = []
  readonly #ins: In[] = []
  readonly #outs: Out[] = []
  readonly #pads: Pad[] = []

  private constructor(name: string) {
    this.#name = name
  }

  static to(name: string): Call {
    return new Call(name)
  }

  bytes(value: Uint8Array | string): this {
    const input = new In(value)
    this.#ins.push(input)
    this.#args.push(input.ptr, input.len)
    return this
  }

  num(value: Arg): this {
    this.#args.push(value)
    return this
  }

  out(): this {
    const cell = new Out()
    this.#outs.push(cell)
    this.#args.push(cell.cell)
    return this
  }

  pad(len: number): this {
    const pad = new Pad(len)
    this.#pads.push(pad)
    this.#args.push(pad.ptr)
    return this
  }

  /** Runs the export and hands the outputs and pads to `read`; every allocation is freed afterwards. */
  finish<T>(read: (outs: Uint8Array[], pads: Pad[]) => T): T {
    let status = 0
    let outs: Uint8Array[] = []
    try {
      status = invoke(this.#name, ...this.#args)
      outs = this.#outs.map(o => o.take())
      check(status)
      return read(outs, this.#pads)
    } finally {
      for (const i of this.#ins) i.free()
      for (const p of this.#pads) p.free()
    }
  }

  run(): Uint8Array[] {
    return this.finish(outs => outs)
  }

  first(): Uint8Array {
    return this.finish(outs => outs[0])
  }

  /** The status only; a non-zero status throws. */
  status(): void {
    this.finish(() => undefined)
  }

  /** A one-byte answer written through the last pointer argument. */
  flag(): boolean {
    return this.pad(1).finish((_, pads) => pads[0].view().getUint8(0) === 1)
  }
}

export const PQ_ROUND_THREE = 0x08
export const PQ_STANDARD = 0x0a
// The names the clients used before the rename, each its own value so a bundler
// never has to alias one export to another.
export const KEM_KYBER1024 = 0x08
export const KEM_MLKEM1024 = 0x0a

export const MessageType = { whisper: 2, preKey: 3, senderKey: 7, plaintext: 8 } as const

export interface SessionInfo {
  hasLive: boolean
  canSend: boolean
  usable: boolean
  version: number
  localRegistrationId: number
  remoteRegistrationId: number
  shelved: number
  localIdentity: Uint8Array
  remoteIdentity: Uint8Array
  base: Uint8Array
}

export interface Published {
  registrationId: number
  device: number
  oneTimeId: number | null
  oneTime: Uint8Array | null
  signedId: number
  signedKey: Uint8Array
  signedSignature: Uint8Array
  identity: Uint8Array
  pqId: number
  pqKey: Uint8Array
  pqSignature: Uint8Array
}

export interface Consumed {
  used: boolean
  oneTimeId: number | null
  signedId: number
  pqId: number
  base: Uint8Array
}

export interface OpenerInfo {
  version: number
  registrationId: number
  oneTimeId: number | null
  signedId: number
  pqId: number | null
  base: Uint8Array
  identity: Uint8Array
}

export interface WhisperInfo {
  version: number
  index: number
  previousIndex: number
  ratchet: Uint8Array
}

export interface Binding {
  sender: string | null
  senderDevice: number
  recipient: string | null
  recipientDevice: number
}

function bound(call: Call, b: Binding): Call {
  return call.bytes(b.sender ?? '').num(b.senderDevice).bytes(b.recipient ?? '').num(b.recipientDevice)
}

function signedId(view: DataView, at: number): number | null {
  const v = view.getBigInt64(at, true)
  return v < 0n ? null : Number(v)
}

export const core = {
  abiVersion(): number {
    return invoke('gv_abi_version')
  },

  // Keys
  curvePair(): { secret: Uint8Array; publicKey: Uint8Array } {
    const [secret, publicKey] = Call.to('gv_curve_pair').out().out().run()
    return { secret, publicKey }
  },
  curvePublic(secret: Uint8Array): Uint8Array {
    return Call.to('gv_curve_public').bytes(secret).out().first()
  },
  curveSign(secret: Uint8Array, message: Uint8Array): Uint8Array {
    return Call.to('gv_curve_sign').bytes(secret).bytes(message).out().first()
  },
  curveVerify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
    return Call.to('gv_curve_verify').bytes(publicKey).bytes(message).bytes(signature).flag()
  },
  curveAgree(secret: Uint8Array, publicKey: Uint8Array): Uint8Array {
    return Call.to('gv_curve_agree').bytes(secret).bytes(publicKey).out().first()
  },
  curveCheck(publicKey: Uint8Array): void {
    Call.to('gv_curve_check').bytes(publicKey).status()
  },
  pqPair(scheme: number = PQ_ROUND_THREE): { publicKey: Uint8Array; secret: Uint8Array } {
    const [publicKey, secret] = Call.to('gv_pq_pair').num(scheme).out().out().run()
    return { publicKey, secret }
  },
  pqEncapsulate(publicKey: Uint8Array): { capsule: Uint8Array; shared: Uint8Array } {
    const [capsule, shared] = Call.to('gv_pq_encapsulate').bytes(publicKey).out().out().run()
    return { capsule, shared }
  },
  pqOpen(secret: Uint8Array, capsule: Uint8Array): Uint8Array {
    return Call.to('gv_pq_open').bytes(secret).bytes(capsule).out().first()
  },
  identitySerialize(secret: Uint8Array): Uint8Array {
    return Call.to('gv_identity_serialize').bytes(secret).out().first()
  },
  identityParse(serialized: Uint8Array): { publicKey: Uint8Array; secret: Uint8Array } {
    const [publicKey, secret] = Call.to('gv_identity_parse').bytes(serialized).out().out().run()
    return { publicKey, secret }
  },
  identityVouch(secret: Uint8Array, other: Uint8Array): Uint8Array {
    return Call.to('gv_identity_vouch').bytes(secret).bytes(other).out().first()
  },
  identityVouched(publicKey: Uint8Array, other: Uint8Array, signature: Uint8Array): boolean {
    return Call.to('gv_identity_vouched').bytes(publicKey).bytes(other).bytes(signature).flag()
  },

  // Published key records
  oneTimeRecord(id: number, secret: Uint8Array): Uint8Array {
    return Call.to('gv_one_time_record').num(id).bytes(secret).out().first()
  },
  oneTimeParse(record: Uint8Array): { id: number; publicKey: Uint8Array; secret: Uint8Array } {
    return Call.to('gv_one_time_parse').bytes(record).pad(4).out().out().finish(([publicKey, secret], [pad]) => ({ id: pad.view().getUint32(0, true), publicKey, secret }))
  },
  signedRecord(id: number, stamp: bigint, secret: Uint8Array, signature: Uint8Array): Uint8Array {
    return Call.to('gv_signed_record').num(id).num(stamp).bytes(secret).bytes(signature).out().first()
  },
  signedParse(record: Uint8Array): { id: number; stamp: bigint; publicKey: Uint8Array; secret: Uint8Array; signature: Uint8Array } {
    return Call.to('gv_signed_parse').bytes(record).pad(4).pad(8).out().out().out().finish(([publicKey, secret, signature], [id, stamp]) => ({
      id: id.view().getUint32(0, true),
      stamp: stamp.view().getBigUint64(0, true),
      publicKey,
      secret,
      signature,
    }))
  },
  pqRecord(id: number, stamp: bigint, publicKey: Uint8Array, secret: Uint8Array, signature: Uint8Array): Uint8Array {
    return Call.to('gv_pq_record').num(id).num(stamp).bytes(publicKey).bytes(secret).bytes(signature).out().first()
  },
  pqRecordParse(record: Uint8Array): { id: number; stamp: bigint; publicKey: Uint8Array; secret: Uint8Array; signature: Uint8Array } {
    return Call.to('gv_pq_record_parse').bytes(record).pad(4).pad(8).out().out().out().finish(([publicKey, secret, signature], [id, stamp]) => ({
      id: id.view().getUint32(0, true),
      stamp: stamp.view().getBigUint64(0, true),
      publicKey,
      secret,
      signature,
    }))
  },

  // Sessions
  sessionInfo(record: Uint8Array, nowSecs: bigint): SessionInfo {
    return Call.to('gv_session_info').bytes(record).num(nowSecs).pad(120).finish((_, [info]) => {
      const v = info.view()
      return {
        hasLive: v.getUint8(0) === 1,
        canSend: v.getUint8(1) === 1,
        usable: v.getUint8(2) === 1,
        version: v.getUint32(4, true),
        localRegistrationId: v.getUint32(8, true),
        remoteRegistrationId: v.getUint32(12, true),
        shelved: v.getUint32(16, true),
        localIdentity: info.bytes(20, 33),
        remoteIdentity: info.bytes(53, 33),
        base: info.bytes(86, 33),
      }
    })
  },
  sessionShelve(record: Uint8Array): Uint8Array {
    return Call.to('gv_session_shelve').bytes(record).out().first()
  },
  sessionRatchetIs(record: Uint8Array, key: Uint8Array): boolean {
    return Call.to('gv_session_ratchet_is').bytes(record).bytes(key).flag()
  },
  /** The bundle struct carries pointers to its own inputs, so it is laid out by hand. */
  sessionStart(identitySecret: Uint8Array, registrationId: number, record: Uint8Array, p: Published, nowSecs: bigint): Uint8Array {
    const ins = [identitySecret, record, p.oneTime ?? new Uint8Array(0), p.signedKey, p.signedSignature, p.identity, p.pqKey, p.pqSignature].map(b => new In(b))
    const published = new Pad(72)
    const out = new Out()
    try {
      const v = published.view()
      v.setUint32(0, p.registrationId, true)
      v.setUint32(4, p.device, true)
      v.setBigInt64(8, p.oneTimeId === null ? -1n : BigInt(p.oneTimeId), true)
      const slots = [16, 28, 36, 44, 56, 64]
      slots.forEach((at, i) => {
        v.setUint32(at, ins[i + 2].ptr, true)
        v.setUint32(at + 4, ins[i + 2].len, true)
      })
      v.setUint32(24, p.signedId, true)
      v.setUint32(52, p.pqId, true)
      const status = invoke('gv_session_start', ins[0].ptr, ins[0].len, registrationId, ins[1].ptr, ins[1].len, published.ptr, nowSecs, out.cell)
      const result = out.take()
      check(status)
      return result
    } finally {
      for (const i of ins) i.free()
      published.free()
    }
  },
  sessionSeal(record: Uint8Array, plain: Uint8Array, nowSecs: bigint, b: Binding): { kind: number; sealed: Uint8Array; record: Uint8Array } {
    return bound(Call.to('gv_session_seal').bytes(record).bytes(plain).num(nowSecs), b).pad(1).out().out().finish(([sealed, out], [kind]) => ({ kind: kind.view().getUint8(0), sealed, record: out }))
  },
  sessionOpen(record: Uint8Array, whisper: Uint8Array, b: Binding): { plain: Uint8Array; record: Uint8Array } {
    const [plain, out] = bound(Call.to('gv_session_open').bytes(record).bytes(whisper), b).out().out().run()
    return { plain, record: out }
  },
  sessionOpenFirst(identitySecret: Uint8Array, registrationId: number, record: Uint8Array, opener: Uint8Array, signedRecord: Uint8Array, oneTimeRecord: Uint8Array, pqRecord: Uint8Array, b: Binding): { plain: Uint8Array; record: Uint8Array; consumed: Consumed } {
    const call = bound(Call.to('gv_session_open_first').bytes(identitySecret).num(registrationId).bytes(record).bytes(opener).bytes(signedRecord).bytes(oneTimeRecord).bytes(pqRecord), b)
    return call.out().out().pad(64).finish(([plain, out], [consumed]) => {
      const v = consumed.view()
      return {
        plain,
        record: out,
        consumed: { used: v.getUint8(0) === 1, oneTimeId: signedId(v, 8), signedId: v.getUint32(16, true), pqId: v.getUint32(20, true), base: consumed.bytes(24, 33) },
      }
    })
  },
  openerParse(opener: Uint8Array): { info: OpenerInfo; inner: Uint8Array } {
    return Call.to('gv_opener_parse').bytes(opener).pad(104).out().finish(([inner], [pad]) => {
      const v = pad.view()
      return {
        info: {
          version: v.getUint8(0),
          registrationId: v.getUint32(4, true),
          oneTimeId: signedId(v, 8),
          signedId: v.getUint32(16, true),
          pqId: signedId(v, 24),
          base: pad.bytes(32, 33),
          identity: pad.bytes(65, 33),
        },
        inner,
      }
    })
  },
  whisperParse(whisper: Uint8Array): { info: WhisperInfo; body: Uint8Array } {
    return Call.to('gv_whisper_parse').bytes(whisper).pad(48).out().finish(([body], [pad]) => {
      const v = pad.view()
      return { info: { version: v.getUint8(0), index: v.getUint32(4, true), previousIndex: v.getUint32(8, true), ratchet: pad.bytes(12, 33) }, body }
    })
  },

  // Circles
  circleAnnounce(record: Uint8Array, circleId: Uint8Array): { record: Uint8Array; announce: Uint8Array } {
    const [out, announce] = Call.to('gv_circle_announce').bytes(record).bytes(circleId).out().out().run()
    return { record: out, announce }
  },
  circleAdmit(record: Uint8Array, announce: Uint8Array): Uint8Array {
    return Call.to('gv_circle_admit').bytes(record).bytes(announce).out().first()
  },
  announceParse(announce: Uint8Array): { version: number; circleId: Uint8Array; chainId: number; step: number; seed: Uint8Array; signing: Uint8Array } {
    return Call.to('gv_announce_parse').bytes(announce).pad(96).finish((_, [pad]) => {
      const v = pad.view()
      return { version: v.getUint8(0), circleId: pad.bytes(1, 16), chainId: v.getUint32(20, true), step: v.getUint32(24, true), seed: pad.bytes(28, 32), signing: pad.bytes(60, 33) }
    })
  },
  circleSeal(record: Uint8Array, circleId: Uint8Array, plain: Uint8Array): { note: Uint8Array; record: Uint8Array } {
    const [note, out] = Call.to('gv_circle_seal').bytes(record).bytes(circleId).bytes(plain).out().out().run()
    return { note, record: out }
  },
  circleOpen(record: Uint8Array, note: Uint8Array): { plain: Uint8Array; record: Uint8Array } {
    const [plain, out] = Call.to('gv_circle_open').bytes(record).bytes(note).out().out().run()
    return { plain, record: out }
  },
  noteParse(note: Uint8Array): { version: number; circleId: Uint8Array; chainId: number; step: number; body: Uint8Array } {
    return Call.to('gv_note_parse').bytes(note).pad(28).out().finish(([body], [pad]) => {
      const v = pad.view()
      return { version: v.getUint8(0), circleId: pad.bytes(1, 16), chainId: v.getUint32(20, true), step: v.getUint32(24, true), body }
    })
  },

  // Envelopes
  serverCert(keyId: number, key: Uint8Array, trustSecret: Uint8Array): Uint8Array {
    return Call.to('gv_server_cert').num(keyId).bytes(key).bytes(trustSecret).out().first()
  },
  serverCertParse(cert: Uint8Array): { keyId: number; key: Uint8Array; body: Uint8Array; signature: Uint8Array } {
    return Call.to('gv_server_cert_parse').bytes(cert).pad(40).out().out().finish(([body, signature], [pad]) => ({ keyId: pad.view().getUint32(0, true), key: pad.bytes(4, 33), body, signature }))
  },
  serverCertCheck(cert: Uint8Array, trustRoot: Uint8Array): boolean {
    return Call.to('gv_server_cert_check').bytes(cert).bytes(trustRoot).flag()
  },
  senderCert(senderId: string, phone: string | null, device: number, key: Uint8Array, expiresMs: bigint, serverCert: Uint8Array, serverSecret: Uint8Array): Uint8Array {
    return Call.to('gv_sender_cert').bytes(senderId).bytes(phone ?? '').num(device).bytes(key).num(expiresMs).bytes(serverCert).bytes(serverSecret).out().first()
  },
  senderCertParse(cert: Uint8Array): { device: number; expiresMs: bigint; key: Uint8Array; senderId: Uint8Array; phone: Uint8Array | null; serverCert: Uint8Array; body: Uint8Array; signature: Uint8Array } {
    return Call.to('gv_sender_cert_parse').bytes(cert).pad(56).out().out().out().out().out().finish(([senderId, phone, serverCert, body, signature], [pad]) => {
      const v = pad.view()
      return { device: v.getUint32(0, true), expiresMs: v.getBigUint64(8, true), key: pad.bytes(16, 33), senderId, phone: v.getUint8(49) === 1 ? phone : null, serverCert, body, signature }
    })
  },
  senderCertCheck(cert: Uint8Array, trustRoot: Uint8Array, nowMs: bigint): boolean {
    return Call.to('gv_sender_cert_check').bytes(cert).bytes(trustRoot).num(nowMs).flag()
  },
  content(kind: number, senderCert: Uint8Array, body: Uint8Array, hint: number, circleId: Uint8Array | null): Uint8Array {
    return Call.to('gv_content').num(kind).bytes(senderCert).bytes(body).num(hint).bytes(circleId ?? new Uint8Array(0)).num(circleId === null ? 0 : 1).out().first()
  },
  contentParse(content: Uint8Array): { kind: number; hint: number; body: Uint8Array; senderCert: Uint8Array; circleId: Uint8Array | null } {
    return Call.to('gv_content_parse').bytes(content).pad(4).out().out().out().finish(([body, senderCert, circleId], [pad]) => {
      const v = pad.view()
      return { kind: v.getUint8(0), hint: v.getUint8(1), body, senderCert, circleId: v.getUint8(2) === 1 ? circleId : null }
    })
  },
  envelopeSeal(identitySecret: Uint8Array, recipientIdentity: Uint8Array, content: Uint8Array): Uint8Array {
    return Call.to('gv_envelope_seal').bytes(identitySecret).bytes(recipientIdentity).bytes(content).out().first()
  },
  envelopeOpen(identitySecret: Uint8Array, envelope: Uint8Array): Uint8Array {
    return Call.to('gv_envelope_open').bytes(identitySecret).bytes(envelope).out().first()
  },
  envelopeSealMany(identitySecret: Uint8Array, recipients: Uint8Array, excluded: Uint8Array, content: Uint8Array): Uint8Array {
    return Call.to('gv_envelope_seal_many').bytes(identitySecret).bytes(recipients).bytes(excluded).bytes(content).out().first()
  },
  envelopeForSingle(sent: Uint8Array): Uint8Array {
    return Call.to('gv_envelope_for_single').bytes(sent).out().first()
  },
  envelopeForRecipient(sent: Uint8Array, serviceId: Uint8Array, device: number): Uint8Array {
    return Call.to('gv_envelope_for_recipient').bytes(sent).bytes(serviceId).num(device).out().first()
  },

  // Safety numbers
  safety(version: number, iterations: number, localId: Uint8Array, localKey: Uint8Array, remoteId: Uint8Array, remoteKey: Uint8Array): { display: string; scannable: Uint8Array } {
    const [display, scannable] = Call.to('gv_safety').num(version).num(iterations).bytes(localId).bytes(localKey).bytes(remoteId).bytes(remoteKey).out().out().run()
    return { display: textDecoder.decode(display), scannable }
  },
  safetyMatches(ours: Uint8Array, theirs: Uint8Array): boolean {
    return Call.to('gv_safety_matches').bytes(ours).bytes(theirs).flag()
  },

  // Handles
  handleHash(handle: string): Uint8Array {
    return Call.to('gv_handle_hash').bytes(handle).out().first()
  },
  handleProof(handle: string, randomness: Uint8Array): Uint8Array {
    return Call.to('gv_handle_proof').bytes(handle).bytes(randomness).out().first()
  },
  handleVerify(proof: Uint8Array, hash: Uint8Array): boolean {
    return Call.to('gv_handle_verify').bytes(proof).bytes(hash).flag()
  },
  handleCandidates(nickname: string, minLen: number, maxLen: number): string[] {
    const text = textDecoder.decode(Call.to('gv_handle_candidates').bytes(nickname).num(minLen).num(maxLen).out().first())
    return text.length === 0 ? [] : text.split('\n')
  },
  handleFromParts(nickname: string, discriminator: string, minLen: number, maxLen: number): { handle: string; hash: Uint8Array } {
    const [handle, hash] = Call.to('gv_handle_from_parts').bytes(nickname).bytes(discriminator).num(minLen).num(maxLen).out().out().run()
    return { handle: textDecoder.decode(handle), hash }
  },
  handleLink(handle: string, entropy: Uint8Array | null): { entropy: Uint8Array; sealed: Uint8Array } {
    const [outEntropy, sealed] = Call.to('gv_handle_link').bytes(handle).bytes(entropy ?? new Uint8Array(0)).out().out().run()
    return { entropy: outEntropy, sealed }
  },
  handleLinkOpen(entropy: Uint8Array, sealed: Uint8Array): string {
    return textDecoder.decode(Call.to('gv_handle_link_open').bytes(entropy).bytes(sealed).out().first())
  },

  // The vault
  poolRandom(): string {
    return textDecoder.decode(Call.to('gv_pool_random').out().first())
  },
  poolValid(pool: string): boolean {
    const input = new In(pool)
    try {
      return invoke('gv_pool_valid', input.ptr, input.len) === 1
    } finally {
      input.free()
    }
  },
  poolDerive(pool: string): { recoveryKey: Uint8Array; backupKey: Uint8Array } {
    const [recoveryKey, backupKey] = Call.to('gv_pool_derive').bytes(pool).out().out().run()
    return { recoveryKey, backupKey }
  },
  backupKeyRandom(): Uint8Array {
    return Call.to('gv_backup_key_random').out().first()
  },
  backupKeyForAccount(key: Uint8Array, accountId: string): { backupId: Uint8Array; signingKey: Uint8Array } {
    const [backupId, signingKey] = Call.to('gv_backup_key_for_account').bytes(key).bytes(accountId).out().out().run()
    return { backupId, signingKey }
  },
  backupKeyLocalMetadata(key: Uint8Array): Uint8Array {
    return Call.to('gv_backup_key_local_metadata').bytes(key).out().first()
  },
  backupKeyMedia(key: Uint8Array, mediaName: string): { mediaId: Uint8Array; mediaKey: Uint8Array; thumbnailKey: Uint8Array } {
    const [mediaId, mediaKey, thumbnailKey] = Call.to('gv_backup_key_media').bytes(key).bytes(mediaName).out().out().out().run()
    return { mediaId, mediaKey, thumbnailKey }
  },
  backupKeyMediaKeys(key: Uint8Array, mediaId: Uint8Array): { mediaKey: Uint8Array; thumbnailKey: Uint8Array } {
    const [mediaKey, thumbnailKey] = Call.to('gv_backup_key_media_keys').bytes(key).bytes(mediaId).out().out().run()
    return { mediaKey, thumbnailKey }
  },
  circleMasterRandom(): Uint8Array {
    return Call.to('gv_circle_master_random').out().first()
  },
  circleSecretParams(master: Uint8Array): Uint8Array {
    return Call.to('gv_circle_secret_params').bytes(master).out().first()
  },
  circleParamsInfo(params: Uint8Array): { master: Uint8Array; identifier: Uint8Array; publicParams: Uint8Array } {
    const [master, identifier, publicParams] = Call.to('gv_circle_params_info').bytes(params).out().out().out().run()
    return { master, identifier, publicParams }
  },

  // Streams, primitives, reports
  hkdf(material: Uint8Array, salt: Uint8Array | null, info: Uint8Array, length: number): Uint8Array {
    return Call.to('gv_hkdf').bytes(material).bytes(salt ?? new Uint8Array(0)).num(salt === null ? 0 : 1).bytes(info).num(length).out().first()
  },
  sivSeal(key: Uint8Array, nonce: Uint8Array, plain: Uint8Array, aad: Uint8Array): Uint8Array {
    return Call.to('gv_siv_seal').bytes(key).bytes(nonce).bytes(plain).bytes(aad).out().first()
  },
  sivOpen(key: Uint8Array, nonce: Uint8Array, sealed: Uint8Array, aad: Uint8Array): Uint8Array {
    return Call.to('gv_siv_open').bytes(key).bytes(nonce).bytes(sealed).bytes(aad).out().first()
  },
  random(length: number): Uint8Array {
    return Call.to('gv_random').num(length).out().first()
  },
  chunkTags(key: Uint8Array, chunk: number, data: Uint8Array): Uint8Array {
    return Call.to('gv_chunk_tags').bytes(key).num(chunk).bytes(data).out().first()
  },
  chunkCheck(key: Uint8Array, chunk: number, data: Uint8Array, tags: Uint8Array): void {
    Call.to('gv_chunk_check').bytes(key).num(chunk).bytes(data).bytes(tags).status()
  },
  report(original: Uint8Array, kind: number, stampMs: bigint, device: number): Uint8Array {
    return Call.to('gv_report').bytes(original).num(kind).num(stampMs).num(device).out().first()
  },
  reportParse(report: Uint8Array): { stampMs: bigint; device: number; ratchet: Uint8Array | null } {
    return Call.to('gv_report_parse').bytes(report).pad(48).finish((_, [pad]) => {
      const v = pad.view()
      return { stampMs: v.getBigUint64(0, true), device: v.getUint32(8, true), ratchet: v.getUint8(12) === 1 ? pad.bytes(13, 33) : null }
    })
  },
  reportInBody(body: Uint8Array): Uint8Array {
    return Call.to('gv_report_in_body').bytes(body).out().first()
  },
  plainFromReport(report: Uint8Array): Uint8Array {
    return Call.to('gv_plain_from_report').bytes(report).out().first()
  },
  plainBody(plain: Uint8Array): Uint8Array {
    return Call.to('gv_plain_body').bytes(plain).out().first()
  },
}

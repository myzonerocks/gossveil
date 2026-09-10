// The seam between JavaScript and the wasm core: loading, linear memory and
// the status-to-error mapping. Every call copies its inputs in, reads its
// outputs out and frees both, so no wasm memory outlives a call.

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module
export type SyncInitInput = BufferSource | WebAssembly.Module

export interface InitOutput {
  readonly memory: WebAssembly.Memory
}

interface Exports extends WebAssembly.Exports {
  memory: WebAssembly.Memory
  gv_abi_version(): number
  gv_alloc(len: number): number
  gv_free(ptr: number, len: number): void
  gv_status_text(status: number): number
  [name: string]: WebAssembly.ExportValue
}

export class GossveilError extends Error {
  readonly status: number
  readonly kind: string

  constructor(status: number, kind: string, message: string) {
    super(message)
    this.name = 'GossveilError'
    this.status = status
    this.kind = kind
  }
}

export const Status = {
  ok: 0,
  invalidArgument: 1,
  invalidState: 2,
  invalidKey: 3,
  invalidSignature: 4,
  invalidMessage: 5,
  invalidKeyId: 6,
  untrustedIdentity: 7,
  sessionNotFound: 8,
  duplicateMessage: 9,
  legacyVersion: 10,
  unrecognizedVersion: 11,
  outOfMemory: 12,
  verificationFailed: 13,
  internal: 14,
} as const

const kinds: Record<number, string> = {
  1: 'InvalidArgument',
  2: 'InvalidState',
  3: 'InvalidKey',
  4: 'InvalidSignature',
  5: 'InvalidMessage',
  6: 'InvalidKeyIdentifier',
  7: 'UntrustedIdentity',
  8: 'SessionNotFound',
  9: 'DuplicatedMessage',
  10: 'LegacyCiphertextVersion',
  11: 'UnrecognizedMessageVersion',
  12: 'OutOfMemory',
  13: 'VerificationFailed',
  14: 'InternalError',
}

export function fault(kind: keyof typeof Status, message: string): GossveilError {
  const status = Status[kind]
  return new GossveilError(status, kinds[status] ?? 'InternalError', message)
}

let exports: Exports | null = null

function fillRandom(memory: WebAssembly.Memory, ptr: number, len: number): void {
  const view = new Uint8Array(memory.buffer, ptr, len)
  // getRandomValues caps one request at 65536 bytes.
  for (let at = 0; at < len; at += 65536) {
    crypto.getRandomValues(view.subarray(at, Math.min(len, at + 65536)))
  }
}

function imports(): WebAssembly.Imports {
  return {
    env: {
      gv_random_bytes(ptr: number, len: number) {
        fillRandom(exports!.memory, ptr, len)
      },
    },
  }
}

function adopt(instance: WebAssembly.Instance): InitOutput {
  exports = instance.exports as Exports
  return { memory: exports.memory }
}

function defaultLocation(): URL {
  return new URL('../wasm/gossveil.wasm', import.meta.url)
}

/** A built specifier, so only a runtime with these modules ever resolves them. */
function nodeSpecifier(name: string): string {
  return 'node:' + name
}

async function loadSource(input: InitInput | undefined): Promise<BufferSource | WebAssembly.Module | Response> {
  if (input === undefined) input = defaultLocation()
  if (input instanceof WebAssembly.Module || ArrayBuffer.isView(input) || input instanceof ArrayBuffer) return input
  if (typeof Response !== 'undefined' && input instanceof Response) return input
  const url = input instanceof URL ? input : typeof input === 'string' ? new URL(input, import.meta.url) : null
  const node = typeof (globalThis as { process?: { versions?: { node?: string } } }).process?.versions?.node === 'string'
  if (url && url.protocol === 'file:' && node) {
    // Named at run time so a browser bundler never follows these into the graph.
    const { readFile } = await import(/* @vite-ignore */ nodeSpecifier('fs/promises'))
    const { fileURLToPath } = await import(/* @vite-ignore */ nodeSpecifier('url'))
    return await readFile(fileURLToPath(url))
  }
  return await fetch(input as RequestInfo | URL)
}

/** Loads the core; resolves once every export is callable. Safe to call more than once. */
export async function init(input?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput> {
  if (exports) return { memory: exports.memory }
  const unwrapped = await (input && typeof input === 'object' && 'module_or_path' in input ? input.module_or_path : input)
  const source = await loadSource(unwrapped)
  let instance: WebAssembly.Instance
  if (source instanceof WebAssembly.Module) {
    instance = await WebAssembly.instantiate(source, imports())
  } else if (typeof Response !== 'undefined' && source instanceof Response && typeof WebAssembly.instantiateStreaming === 'function') {
    instance = (await WebAssembly.instantiateStreaming(source, imports())).instance
  } else {
    const bytes: BufferSource = source instanceof Response ? await source.arrayBuffer() : source
    const result = (await WebAssembly.instantiate(bytes, imports())) as WebAssembly.WebAssemblyInstantiatedSource | WebAssembly.Instance
    instance = 'instance' in result ? result.instance : result
  }
  return adopt(instance)
}

export function initSync(input: { module: SyncInitInput } | SyncInitInput): InitOutput {
  if (exports) return { memory: exports.memory }
  const source = input && typeof input === 'object' && 'module' in input ? input.module : input
  const module = source instanceof WebAssembly.Module ? source : new WebAssembly.Module(source)
  return adopt(new WebAssembly.Instance(module, imports()))
}

export function isReady(): boolean {
  return exports !== null
}

export function loaded(): Exports {
  if (!exports) throw fault('invalidState', 'the core is not loaded: await init() first')
  return exports
}

function reserve(len: number): number {
  const ptr = loaded().gv_alloc(len)
  if (ptr === 0) throw fault('outOfMemory', 'out of memory')
  return ptr
}

/** An input copied into wasm memory for one call. */
export class In {
  readonly ptr: number
  readonly len: number

  constructor(value: Uint8Array | string) {
    const data = typeof value === 'string' ? textEncoder.encode(value) : value
    this.len = data.length
    this.ptr = data.length === 0 ? 0 : reserve(data.length)
    if (data.length > 0) new Uint8Array(loaded().memory.buffer, this.ptr, data.length).set(data)
  }

  free(): void {
    if (this.len > 0) loaded().gv_free(this.ptr, this.len)
  }
}

/** A library-owned output: an 8-byte {ptr, len} cell in wasm memory. */
export class Out {
  readonly cell: number

  constructor() {
    this.cell = reserve(8)
    new Uint32Array(loaded().memory.buffer, this.cell, 2).fill(0)
  }

  /** Copies the bytes out and frees both the buffer and the cell. */
  take(): Uint8Array {
    const c = loaded()
    const [ptr, len] = new Uint32Array(c.memory.buffer, this.cell, 2)
    const copy = new Uint8Array(len)
    if (len > 0) {
      copy.set(new Uint8Array(c.memory.buffer, ptr, len))
      c.gv_free(ptr, len)
    }
    c.gv_free(this.cell, 8)
    return copy
  }
}

/** A zeroed region in wasm memory for structs and scalars a call fills in. */
export class Pad {
  readonly ptr: number
  readonly len: number

  constructor(len: number) {
    this.len = len
    this.ptr = reserve(len)
    new Uint8Array(loaded().memory.buffer, this.ptr, len).fill(0)
  }

  view(): DataView {
    return new DataView(loaded().memory.buffer, this.ptr, this.len)
  }

  bytes(offset: number, len: number): Uint8Array {
    return new Uint8Array(loaded().memory.buffer, this.ptr + offset, len).slice()
  }

  free(): void {
    loaded().gv_free(this.ptr, this.len)
  }
}

export function check(status: number): void {
  if (status === 0) return
  const c = loaded()
  const at = c.gv_status_text(status)
  const mem = new Uint8Array(c.memory.buffer)
  let end = at
  while (mem[end] !== 0) end++
  throw new GossveilError(status, kinds[status] ?? 'InternalError', textDecoder.decode(mem.subarray(at, end)))
}

export type Arg = number | bigint

export function invoke(name: string, ...args: Arg[]): number {
  const fn = loaded()[name] as (...a: Arg[]) => number
  if (typeof fn !== 'function') throw fault('internal', `missing export ${name}`)
  return fn(...args)
}

export const textEncoder = new TextEncoder()
export const textDecoder = new TextDecoder()

export function utf8(bytes: Uint8Array): string {
  return textDecoder.decode(bytes)
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i]
  return diff === 0
}

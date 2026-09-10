// UUID text and bytes, shared by both API shapes.
import { fault } from './core'

export function uuidToBytes(s: string): Uint8Array {
  const hex = s.replace(/-/g, '')
  if (!/^[0-9a-fA-F]{32}$/.test(hex)) throw fault('invalidArgument', `not a uuid: ${s}`)
  const out = new Uint8Array(16)
  for (let i = 0; i < 16; i++) out[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16)
  return out
}

export function bytesToUuid(bytes: Uint8Array): string {
  if (bytes.length !== 16) throw fault('invalidArgument', 'a uuid is 16 bytes')
  const hex = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
}

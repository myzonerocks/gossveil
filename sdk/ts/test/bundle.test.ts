// The artifact a consumer imports. The source tests cover behaviour; this one
// covers the built bundle, which a bundler can break on its own.
import { describe, expect, test } from 'bun:test'

describe('the built bundle', () => {
  test('loads and exports the whole surface', async () => {
    const bundle: Record<string, unknown> = await import('../dist/index.js')
    for (const name of ['default', 'initSync', 'isReady', 'GossveilError', 'Status', 'MessageType', 'PQ_ROUND_THREE', 'KEM_KYBER1024', 'ProtocolAddress', 'PrivateKey', 'InMemoryProtocolStore', 'processBundle', 'processPreKeyBundle', 'WasmProtocolAddress', 'usernames', 'abiVersion']) {
      expect(bundle[name], name).toBeDefined()
    }
  })

  test('runs a round trip through the bundle', async () => {
    const bundle = await import('../dist/index.js')
    await bundle.default()
    const secret = bundle.PrivateKey.generate()
    const message = new TextEncoder().encode('through the bundle')
    expect(secret.getPublicKey().verify(message, secret.sign(message))).toBe(true)
    expect(bundle.abiVersion()).toBe(1)
  })
})

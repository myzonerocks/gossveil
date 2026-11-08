import { processBundle, sessionEncrypt, sessionDecryptPreKey } from '@myzonerocks/gossveil'

// Pick up the bundle they published. This creates the session.
await processBundle(theirBundle, theirAddress, store, store)

// Write. The ratchet advances and hands back a new session record.
const sealed = await sessionEncrypt(plaintext, theirAddress, store, store)

// On their side, the first message opens with the pre-key path.
const opened = await sessionDecryptPreKey(sealed, ourAddress, theirStore, theirStore)

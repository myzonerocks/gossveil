import Gossveil

// Pick up the bundle they published. This creates the session.
try processPreKeyBundle(
    theirBundle, for: theirAddress,
    sessionStore: store, identityStore: store, context: NullContext()
)

// Write. The ratchet advances and hands back a new session record.
let sealed = try sessionEncrypt(
    message: Array("see you at six".utf8), for: theirAddress,
    sessionStore: store, identityStore: store, context: NullContext()
)

// On their side, the first message opens with the pre-key path.
let plaintext = try sessionDecryptPreKey(
    PreKeyMessage(bytes: sealed.serialize()), from: ourAddress,
    sessionStore: theirStore, identityStore: theirStore,
    preKeyStore: theirStore, signedPreKeyStore: theirStore,
    kyberPreKeyStore: theirStore, context: NullContext()
)

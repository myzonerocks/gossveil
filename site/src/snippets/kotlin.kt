import com.gossveil.*

// Pick up the bundle they published. This creates the session.
SessionBuilder(store, theirAddress).process(theirBundle)

// Write. The ratchet advances and the store keeps the new record.
val sealed = SessionCipher(store, theirAddress)
    .encrypt("see you at six".toByteArray())

// On their side, the first message opens with the pre-key path.
val plaintext = SessionCipher(theirStore, ourAddress)
    .decrypt(PreKeyMessage(sealed.serialize()))

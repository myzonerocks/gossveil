import Foundation

// The names the clients called before the rename. Each one forwards to the
// gossveil name; new code uses the gossveil name.

public typealias SignalError = GossveilError
public typealias SignalMessage = WhisperMessage
public typealias PreKeySignalMessage = PreKeyMessage
public typealias InMemorySignalProtocolStore = InMemoryProtocolStore
public typealias LibSignal = Gossveil

public func signalEncrypt<Bytes: ContiguousBytes>(
    message: Bytes,
    for address: ProtocolAddress,
    localAddress: ProtocolAddress? = nil,
    sessionStore: SessionStore,
    identityStore: IdentityKeyStore,
    now: Date = Date(),
    context: StoreContext
) throws -> CiphertextMessage {
    try sessionEncrypt(message: message, for: address, localAddress: localAddress, sessionStore: sessionStore, identityStore: identityStore, now: now, context: context)
}

public func signalDecrypt(
    message: WhisperMessage,
    from address: ProtocolAddress,
    to localAddress: ProtocolAddress? = nil,
    sessionStore: SessionStore,
    identityStore: IdentityKeyStore,
    context: StoreContext
) throws -> Data {
    try sessionDecrypt(message: message, from: address, to: localAddress, sessionStore: sessionStore, identityStore: identityStore, context: context)
}

public func signalDecryptPreKey(
    message: PreKeyMessage,
    from address: ProtocolAddress,
    localAddress: ProtocolAddress? = nil,
    sessionStore: SessionStore,
    identityStore: IdentityKeyStore,
    preKeyStore: PreKeyStore,
    signedPreKeyStore: SignedPreKeyStore,
    kyberPreKeyStore: KyberPreKeyStore,
    context: StoreContext,
    usePqRatchet: UsePQRatchet = .no
) throws -> Data {
    try sessionDecryptPreKey(message: message, from: address, localAddress: localAddress, sessionStore: sessionStore, identityStore: identityStore, preKeyStore: preKeyStore, signedPreKeyStore: signedPreKeyStore, kyberPreKeyStore: kyberPreKeyStore, context: context, usePqRatchet: usePqRatchet)
}

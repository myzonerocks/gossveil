package com.gossveil;

/** Java so a Kotlin host can both override the getters and read them as properties. */
public interface IdentityKeyStore {
    enum Direction { SENDING, RECEIVING }

    enum IdentityChange { NEW_OR_UNCHANGED, REPLACED_EXISTING }

    IdentityKeyPair getIdentityKeyPair();

    int getLocalRegistrationId();

    IdentityChange saveIdentity(ProtocolAddress address, IdentityKey identityKey);

    boolean isTrustedIdentity(ProtocolAddress address, IdentityKey identityKey, Direction direction);

    IdentityKey getIdentity(ProtocolAddress address);
}

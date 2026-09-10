package com.gossveil;

import java.util.List;

public interface SignedPreKeyStore {
    SignedPreKeyRecord loadSignedPreKey(int signedPreKeyId) throws InvalidKeyIdException;

    List<SignedPreKeyRecord> loadSignedPreKeys();

    void storeSignedPreKey(int signedPreKeyId, SignedPreKeyRecord record);

    boolean containsSignedPreKey(int signedPreKeyId);

    void removeSignedPreKey(int signedPreKeyId);
}

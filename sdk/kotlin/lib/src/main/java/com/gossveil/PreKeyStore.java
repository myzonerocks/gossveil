package com.gossveil;

public interface PreKeyStore {
    PreKeyRecord loadPreKey(int preKeyId) throws InvalidKeyIdException;

    void storePreKey(int preKeyId, PreKeyRecord record);

    boolean containsPreKey(int preKeyId);

    void removePreKey(int preKeyId);
}

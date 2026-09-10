package com.gossveil;

import java.util.List;

public interface KyberPreKeyStore {
    KyberPreKeyRecord loadKyberPreKey(int kyberPreKeyId) throws InvalidKeyIdException;

    List<KyberPreKeyRecord> loadKyberPreKeys();

    void storeKyberPreKey(int kyberPreKeyId, KyberPreKeyRecord record);

    boolean containsKyberPreKey(int kyberPreKeyId);

    void markKyberPreKeyUsed(int kyberPreKeyId, int signedPreKeyId, ECPublicKey baseKey);
}

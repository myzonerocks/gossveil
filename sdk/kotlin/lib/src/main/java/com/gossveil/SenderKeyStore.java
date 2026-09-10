package com.gossveil;

import java.util.UUID;

public interface SenderKeyStore {
    void storeSenderKey(ProtocolAddress sender, UUID distributionId, SenderKeyRecord record);

    SenderKeyRecord loadSenderKey(ProtocolAddress sender, UUID distributionId);
}

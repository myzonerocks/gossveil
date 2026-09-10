package com.gossveil;

import java.util.List;

public interface SessionStore {
    SessionRecord loadSession(ProtocolAddress address);

    List<SessionRecord> loadExistingSessions(List<ProtocolAddress> addresses) throws NoSessionException;

    List<Integer> getSubDeviceSessions(String name);

    void storeSession(ProtocolAddress address, SessionRecord record);

    boolean containsSession(ProtocolAddress address);

    void deleteSession(ProtocolAddress address);

    void deleteAllSessions(String name);
}

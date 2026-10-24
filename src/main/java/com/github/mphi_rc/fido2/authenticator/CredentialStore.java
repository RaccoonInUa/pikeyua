package com.github.mphi_rc.fido2.authenticator;

import java.util.Collection;
import com.github.mphi_rc.fido2.authenticator.crypto.AttestationKeyPair;

public interface CredentialStore {
    int MAX_DISCOVERABLE_CREDENTIALS = 128;

    Collection<Credential> getCredentials(String relayingPartyId);
    Credential saveCredential(String relayingPartyId, byte[] userId, AttestationKeyPair keyPair);
    void incrementCredentialCounter(String relayingPartyId, AttestationKeyPair keyPair);

    /** Implementations must replace an existing RK for this exact RP/user atomically. */
    default Credential saveCredential(String rpId, byte[] userId, AttestationKeyPair keyPair,
            boolean discoverable, String userName, String userDisplayName) {
        if (discoverable) throw new UnsupportedOperationException("Resident credential storage unavailable");
        return saveCredential(rpId, userId, keyPair);
    }

    final class Full extends RuntimeException {
        public Full() { super("Discoverable credential capacity reached"); }
    }
}

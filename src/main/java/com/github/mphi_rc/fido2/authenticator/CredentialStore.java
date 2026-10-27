package com.github.mphi_rc.fido2.authenticator;

import java.util.Collection;
import com.github.mphi_rc.fido2.authenticator.crypto.AttestationKeyPair;

/** Legacy software persistence API. New CTAP code uses keys.CredentialBackend. */
public interface CredentialStore {
    int MAX_DISCOVERABLE_CREDENTIALS = 128;
    Collection<Credential> getCredentials(String relayingPartyId);
    Credential saveCredential(String relayingPartyId, byte[] userId, AttestationKeyPair keyPair);
    void incrementCredentialCounter(String relayingPartyId, AttestationKeyPair keyPair);
    default Credential saveCredential(String rpId, byte[] userId, AttestationKeyPair keyPair,
            boolean discoverable, String userName, String userDisplayName) {
        if (discoverable) throw new UnsupportedOperationException("Resident credential storage unavailable");
        return saveCredential(rpId, userId, keyPair);
    }
    /** Owner-only operation; legacy/custom stores must opt in rather than silently succeed. */
    default void deleteCredential(String rpId, byte[] credentialId) {
        throw new UnsupportedOperationException("Credential deletion unavailable");
    }
    final class Full extends RuntimeException {
        public Full() { super("Discoverable credential capacity reached"); }
    }
}

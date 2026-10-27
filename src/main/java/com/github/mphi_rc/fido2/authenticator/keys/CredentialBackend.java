package com.github.mphi_rc.fido2.authenticator.keys;

import java.util.Collection;
import java.util.Set;
import com.github.mphi_rc.fido2.authenticator.crypto.Algorithm;
import com.github.mphi_rc.fido2.protocol.ctap2.AuthenticatorData;

/**
 * Storage + signing boundary used by CTAP business logic. The API exposes only
 * public descriptors and opaque locators, NEVER private key bytes or key pairs.
 * This interface alone does not provide hardware isolation or trusted UV/UP.
 *
 * A provider owns generation, persistent key references, RK replacement and
 * cleanup. create() must publish a credential durably before returning. Failure
 * must not silently choose a software provider. Hardware orphan reconciliation
 * and a future handle-only on-disk schema belong to the actual hardware adapter.
 */
public interface CredentialBackend {
    Set<Algorithm> supportedAlgorithms();
    Collection<CredentialDescriptor> find(String rpId);
    CredentialDescriptor create(String rpId, byte[] userId, Algorithm algorithm,
            boolean discoverable, String userName, String userDisplayName);
    /** Existing packed SELF-attestation; not manufacturer attestation. */
    byte[] signRegistration(KeyHandle handle, AuthenticatorData data, byte[] clientDataHash);
    /**
     * Validate the next counter, sign, commit it durably, and ONLY THEN return
     * the signature. Stale/missing/foreign handles or uncertain commits fail.
     */
    byte[] signAssertion(KeyHandle handle, AuthenticatorData data, byte[] clientDataHash);
    /** Local owner operation, not a newly exposed CTAP command. */
    void delete(KeyHandle handle);
}

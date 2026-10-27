package com.github.mphi_rc.fido2.authenticator.keys;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import com.github.mphi_rc.fido2.authenticator.Credential;
import com.github.mphi_rc.fido2.authenticator.CredentialStore;
import com.github.mphi_rc.fido2.authenticator.crypto.Algorithm;
import com.github.mphi_rc.fido2.authenticator.crypto.AttestationKeyPair;
import com.github.mphi_rc.fido2.authenticator.crypto.Ed25519AttestationKeyPair;
import com.github.mphi_rc.fido2.authenticator.crypto.P256AttestationKeyPair;
import com.github.mphi_rc.fido2.protocol.ctap2.AuthenticatorData;
import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.CborException;

/**
 * Compatibility bridge for existing schema-v1/v2/v3 software credentials.
 * Secrets STILL exist in the legacy store/JVM/SD; no hardware security claim.
 * CTAP code sees only descriptors. The old serialized DTO stays below this
 * boundary so installed credentials and the separate owner CLI are unchanged.
 */
public final class LegacySoftwareCredentialBackend implements CredentialBackend {
    public static final String PROVIDER = "legacy-software-v1";
    private static final Set<Algorithm> ALGORITHMS = Collections.unmodifiableSet(
            EnumSet.of(Algorithm.P256_ECDSA, Algorithm.Ed25519));
    private final CredentialStore store;

    public LegacySoftwareCredentialBackend(CredentialStore store) {
        this.store = Objects.requireNonNull(store, "store");
    }
    @Override public Set<Algorithm> supportedAlgorithms() { return ALGORITHMS; }
    @Override public Collection<CredentialDescriptor> find(String rpId) {
        synchronized (store) {
            List<CredentialDescriptor> out = new ArrayList<>();
            for (Credential credential : store.getCredentials(rpId)) {
                if (!credential.relayingPartyId().equals(rpId)) throw unavailable();
                out.add(describe(credential));
            }
            return Collections.unmodifiableList(out);
        }
    }
    @Override public CredentialDescriptor create(String rpId, byte[] userId, Algorithm algorithm,
            boolean discoverable, String name, String displayName) {
        if (!ALGORITHMS.contains(algorithm)) throw new IllegalArgumentException("Unsupported key algorithm");
        synchronized (store) {
            AttestationKeyPair keys;
            switch (algorithm) {
                case P256_ECDSA: keys = P256AttestationKeyPair.generate(); break;
                case Ed25519: keys = Ed25519AttestationKeyPair.generate(); break;
                default: throw new IllegalArgumentException("Unsupported key algorithm");
            }
            return describe(store.saveCredential(rpId, userId.clone(), keys, discoverable, name, displayName));
        }
    }
    @Override public byte[] signRegistration(KeyHandle handle, AuthenticatorData data, byte[] hash) {
        synchronized (store) {
            Credential credential = resolve(handle, data, hash);
            if (credential.signatureCount() != 0 || data.signatureCount() != 0
                    || !data.attestedCredentialData().isPresent()) throw unavailable();
            return credential.keyPair().sign(data, hash);
        }
    }
    @Override public byte[] signAssertion(KeyHandle handle, AuthenticatorData data, byte[] hash) {
        synchronized (store) {
            Credential credential = resolve(handle, data, hash);
            int count = credential.signatureCount();
            if (data.attestedCredentialData().isPresent() || count < 0 || count == Integer.MAX_VALUE
                    || data.signatureCount() != count + 1) throw unavailable();
            byte[] signature = credential.keyPair().sign(data, hash);
            try {
                store.incrementCredentialCounter(credential.relayingPartyId(), credential.keyPair());
                return signature;
            } catch (RuntimeException e) {
                Arrays.fill(signature, (byte) 0);
                throw e;
            }
        }
    }
    @Override public void delete(KeyHandle handle) {
        synchronized (store) {
            Credential credential = lookup(handle);
            store.deleteCredential(credential.relayingPartyId(), credential.id());
        }
    }
    private Credential resolve(KeyHandle handle, AuthenticatorData data, byte[] hash) {
        if (data == null || hash == null || hash.length != 32 || handle == null
                || !handle.rpId().equals(data.relayingPartyId())) throw unavailable();
        return lookup(handle);
    }
    private Credential lookup(KeyHandle handle) {
        if (handle == null || !PROVIDER.equals(handle.provider())) throw unavailable();
        Credential match = null;
        for (Credential candidate : store.getCredentials(handle.rpId())) {
            if (candidate.relayingPartyId().equals(handle.rpId()) && Arrays.equals(candidate.id(), handle.id())) {
                if (match != null) throw unavailable();
                match = candidate;
            }
        }
        if (match == null) throw unavailable();
        return match;
    }
    private static CredentialDescriptor describe(Credential credential) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            new CborEncoder(out).encode(credential.keyPair().getCborEncodedPublicKey());
            return new CredentialDescriptor(new KeyHandle(PROVIDER, credential.relayingPartyId(), credential.id()),
                    credential.id(), credential.creation(), credential.userId(), credential.keyPair().namedCurve(),
                    credential.keyPair().publicKey(), out.toByteArray(), credential.signatureCount(),
                    credential.discoverable(), credential.userName(), credential.userDisplayName());
        } catch (CborException e) {
            throw new IllegalStateException("Cannot encode public credential metadata", e);
        }
    }
    private static IllegalStateException unavailable() {
        // Do not include account identifiers, PINs or key material in exceptions.
        return new IllegalStateException("Credential operation refused");
    }
}

package com.github.mphi_rc.fido2.authenticator;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;
import com.github.mphi_rc.fido2.ConfigurationFile;
import com.github.mphi_rc.fido2.authenticator.crypto.AttestationKeyPair;

/** All modifications are published only after ConfigurationFile's durable write succeeds. */
public class ConfigurationCredentialStore implements CredentialStore {
    private final ConfigurationFile config;
    public ConfigurationCredentialStore(ConfigurationFile config) { this.config = config; }
    @Override public Collection<Credential> getCredentials(String rpId) {
        return config.credentials().stream().filter(c -> c.relayingPartyId().equals(rpId))
                .collect(Collectors.toList());
    }
    @Override public Credential saveCredential(String rpId, byte[] userId, AttestationKeyPair keys) {
        return saveCredential(rpId, userId, keys, false, "", "");
    }
    @Override public Credential saveCredential(String rpId, byte[] userId, AttestationKeyPair keys,
            boolean discoverable, String name, String displayName) {
        synchronized (config) {
            Credential added = ImmutableCredential.builder()
                    .relayingPartyId(rpId).creation(Instant.now()).userId(userId)
                    .keyPair(keys).signatureCount(0).discoverable(discoverable)
                    .userName(name).userDisplayName(displayName).build();
            List<Credential> next = new ArrayList<>(config.credentials());
            if (discoverable) {
                next.removeIf(c -> c.discoverable() && c.relayingPartyId().equals(rpId)
                        && Arrays.equals(c.userId(), userId));
                if (next.stream().filter(Credential::discoverable).count()
                        >= MAX_DISCOVERABLE_CREDENTIALS) throw new CredentialStore.Full();
            }
            next.add(added);
            config.updateAllStoredCredentials(next);
            return added;
        }
    }
    @Override public void incrementCredentialCounter(String rpId, AttestationKeyPair keys) {
        synchronized (config) {
            List<Credential> next = new ArrayList<>(config.credentials());
            for (int index = 0; index < next.size(); index++) {
                Credential old = next.get(index);
                if (old.relayingPartyId().equals(rpId) && old.keyPair().equals(keys)) {
                    if (old.signatureCount() < 0 || old.signatureCount() == Integer.MAX_VALUE) {
                        throw new IllegalStateException("Signature counter exhausted");
                    }
                    next.set(index, ImmutableCredential.builder().from(old)
                            .signatureCount(old.signatureCount() + 1).build());
                    config.updateAllStoredCredentials(next);
                    return;
                }
            }
            throw new IllegalStateException("Credential disappeared before counter commit");
        }
    }
    @Override public void deleteCredential(String rpId, byte[] id) {
        synchronized (config) {
            List<Credential> next = new ArrayList<>(config.credentials());
            int before = next.size();
            next.removeIf(c -> c.relayingPartyId().equals(rpId) && Arrays.equals(c.id(), id));
            if (before - next.size() != 1) throw new IllegalStateException("Credential deletion refused");
            config.updateAllStoredCredentials(next);
        }
    }
}

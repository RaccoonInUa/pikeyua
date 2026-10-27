package com.github.mphi_rc.fido2.authenticator.keys;

import java.util.Arrays;
import java.util.Objects;

/** A provider-scoped locator, not a secret, authorization token or hardware claim. */
public final class KeyHandle {
    private final String provider, rpId;
    private final byte[] id;

    public KeyHandle(String provider, String rpId, byte[] id) {
        this.provider = Objects.requireNonNull(provider, "provider");
        this.rpId = Objects.requireNonNull(rpId, "rpId");
        Objects.requireNonNull(id, "id");
        if (provider.isEmpty() || provider.length() > 128 || rpId.isEmpty()
                || id.length == 0 || id.length > 65535) {
            throw new IllegalArgumentException("Invalid key handle");
        }
        this.id = id.clone();
    }
    public String provider() { return provider; }
    public String rpId() { return rpId; }
    public byte[] id() { return id.clone(); }
    @Override public boolean equals(Object other) {
        if (!(other instanceof KeyHandle)) return false;
        KeyHandle that = (KeyHandle) other;
        return provider.equals(that.provider) && rpId.equals(that.rpId) && Arrays.equals(id, that.id);
    }
    @Override public int hashCode() { return 31 * Objects.hash(provider, rpId) + Arrays.hashCode(id); }
    @Override public String toString() { return "KeyHandle[redacted]"; }
}

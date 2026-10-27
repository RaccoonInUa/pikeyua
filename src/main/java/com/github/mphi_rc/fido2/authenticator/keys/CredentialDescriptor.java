package com.github.mphi_rc.fido2.authenticator.keys;

import java.io.ByteArrayOutputStream;
import java.time.Instant;
import java.util.Objects;
import com.github.mphi_rc.fido2.authenticator.crypto.Algorithm;

/** Immutable PUBLIC credential view. No key-pair reference or private-key accessor. */
public final class CredentialDescriptor {
    private final KeyHandle handle;
    private final byte[] id, userId, publicKey, coseKey;
    private final Instant creation;
    private final Algorithm algorithm;
    private final boolean discoverable;
    private final String userName, userDisplayName;
    private final int signatureCount;

    public CredentialDescriptor(KeyHandle handle, byte[] id, Instant creation, byte[] userId,
            Algorithm algorithm, byte[] publicKey, byte[] coseKey, int signatureCount,
            boolean discoverable, String userName, String userDisplayName) {
        this.handle = Objects.requireNonNull(handle, "handle");
        this.creation = Objects.requireNonNull(creation, "creation");
        this.algorithm = Objects.requireNonNull(algorithm, "algorithm");
        this.userName = Objects.requireNonNull(userName, "userName");
        this.userDisplayName = Objects.requireNonNull(userDisplayName, "userDisplayName");
        Objects.requireNonNull(id, "id"); Objects.requireNonNull(userId, "userId");
        Objects.requireNonNull(publicKey, "publicKey"); Objects.requireNonNull(coseKey, "coseKey");
        if (id.length == 0 || id.length > 65535 || publicKey.length == 0 || coseKey.length == 0) {
            throw new IllegalArgumentException("Invalid public credential data");
        }
        this.id = id.clone(); this.userId = userId.clone();
        this.publicKey = publicKey.clone(); this.coseKey = coseKey.clone();
        this.signatureCount = signatureCount; this.discoverable = discoverable;
    }
    public KeyHandle handle() { return handle; }
    public String relayingPartyId() { return handle.rpId(); }
    public byte[] id() { return id.clone(); }
    public Instant creation() { return creation; }
    public byte[] userId() { return userId.clone(); }
    public Algorithm algorithm() { return algorithm; }
    /** Public SubjectPublicKeyInfo, retained for compatibility and offline verification. */
    public byte[] publicKey() { return publicKey.clone(); }
    public byte[] cosePublicKey() { return coseKey.clone(); }
    public int signatureCount() { return signatureCount; }
    public boolean discoverable() { return discoverable; }
    public String userName() { return userName; }
    public String userDisplayName() { return userDisplayName; }
    public byte[] encodeAttestedCredentialData(byte[] aaguid) {
        if (aaguid == null || aaguid.length != 16) throw new IllegalArgumentException("Invalid AAGUID");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(aaguid, 0, aaguid.length);
        out.write((id.length >>> 8) & 255); out.write(id.length & 255);
        out.write(id, 0, id.length); out.write(coseKey, 0, coseKey.length);
        return out.toByteArray();
    }
    @Override public String toString() { return "CredentialDescriptor[public metadata redacted]"; }
}

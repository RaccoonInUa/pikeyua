package com.github.mphi_rc.fido2.authenticator;

import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;
import javax.crypto.Cipher;
import com.github.mphi_rc.fido2.ConfigurationFile;
import com.github.mphi_rc.fido2.authenticator.crypto.PinProtocol1;
import com.github.mphi_rc.fido2.protocol.ctap2.Ctap2ResponseCode;

/** Protocol-1 PIN state. Persistent retry budget; transient keys/tokens; no secrets in logs. */
public final class PinState {
    private static final long TOKEN_LIFETIME = TimeUnit.MINUTES.toNanos(10);
    private final ConfigurationFile config;
    private final LongSupplier clock;
    private final SecureRandom random = new SecureRandom();
    private KeyPair keyAgreement;
    private byte[] token;
    private boolean tokenIssued;
    private boolean tokenExpired;
    private long issuedAt;
    private int badPinsThisProcess;
    private int badAuthThisProcess;
    private boolean storageFailed;

    public PinState(ConfigurationFile config) { this(config, System::nanoTime); }
    /** Clock injection for deterministic expiration tests. Never persists a token or clock value. */
    public PinState(ConfigurationFile config, LongSupplier monotonicClock) {
        this.config = config;
        clock = monotonicClock;
        keyAgreement = PinProtocol1.newKeyAgreement();
        rotateToken();
    }
    private void usable() {
        if (storageFailed) throw new IllegalStateException("PIN storage failed; process restart required");
    }
    private void storeRetries(int remaining) {
        try { config.updatePinRetries(remaining); }
        catch (RuntimeException e) { storageFailed = true; rotateToken(); throw e; }
    }
    private void storePin(byte[] hash) {
        try { config.updatePinState(hash, 8); }
        catch (RuntimeException e) { storageFailed = true; rotateToken(); throw e; }
    }
    private void rotateToken() {
        PinProtocol1.wipe(token);
        token = new byte[32];
        random.nextBytes(token);
        tokenIssued = false;
        tokenExpired = false;
    }
    public synchronized int getCountRemainingPinAttempts() { usable(); return config.pinRetries(); }
    public synchronized boolean isPinSet() { return config.pinHash().isPresent(); }
    public synchronized PublicKey getKeyAgreementKey() { usable(); return keyAgreement.getPublic(); }

    private Ctap2ResponseCode blocked() {
        if (config.pinRetries() == 0) return Ctap2ResponseCode.PIN_BLOCKED;
        if (badPinsThisProcess >= 3 || badAuthThisProcess >= 3) return Ctap2ResponseCode.PIN_AUTH_BLOCKED;
        return null;
    }
    private boolean tagValid(byte[] shared, byte[] given, byte[]... data) {
        if (given == null || given.length != 16) return false;
        byte[] expected = PinProtocol1.hmac16(shared, data);
        try { return MessageDigest.isEqual(expected, given); }
        finally { PinProtocol1.wipe(expected); }
    }

    public synchronized Ctap2ResponseCode setNewPin(PublicKey host, byte[] encrypted, byte[] auth) {
        usable();
        if (isPinSet()) return Ctap2ResponseCode.PIN_AUTH_INVALID;
        if (!PinProtocol1.validNewPinCipher(encrypted)) return Ctap2ResponseCode.PIN_POLICY_VIOLATION;
        byte[] shared = PinProtocol1.sharedSecret(keyAgreement, host), plain = null, hash = null;
        try {
            if (!tagValid(shared, auth, encrypted)) return Ctap2ResponseCode.PIN_AUTH_INVALID;
            plain = PinProtocol1.crypt(Cipher.DECRYPT_MODE, shared, encrypted);
            hash = PinProtocol1.pinHashFromPadded(plain);
            if (hash == null) return Ctap2ResponseCode.PIN_POLICY_VIOLATION;
            storePin(hash);
            badPinsThisProcess = badAuthThisProcess = 0;
            rotateToken();
            return Ctap2ResponseCode.OK;
        } finally { PinProtocol1.wipe(shared); PinProtocol1.wipe(plain); PinProtocol1.wipe(hash); }
    }

    /** Verify the old PIN BEFORE changing it; failed MACs are not password guesses. */
    public synchronized Ctap2ResponseCode setPin(PublicKey host, byte[] encryptedNew,
            byte[] encryptedHash, byte[] auth) {
        usable();
        if (!isPinSet()) return Ctap2ResponseCode.PIN_NOT_SET;
        Ctap2ResponseCode blocked = blocked();
        if (blocked != null) return blocked;
        if (!PinProtocol1.validNewPinCipher(encryptedNew) || encryptedHash == null || encryptedHash.length != 16) {
            return Ctap2ResponseCode.PIN_AUTH_INVALID;
        }
        byte[] shared = PinProtocol1.sharedSecret(keyAgreement, host), plain = null, hash = null;
        try {
            if (!tagValid(shared, auth, encryptedNew, encryptedHash)) return Ctap2ResponseCode.PIN_AUTH_INVALID;
            Ctap2ResponseCode result = verifyPin(shared, encryptedHash);
            if (result != Ctap2ResponseCode.OK) return result;
            plain = PinProtocol1.crypt(Cipher.DECRYPT_MODE, shared, encryptedNew);
            hash = PinProtocol1.pinHashFromPadded(plain);
            if (hash == null) return Ctap2ResponseCode.PIN_POLICY_VIOLATION;
            storePin(hash);
            rotateToken(); // A previously verified token must not survive a PIN change.
            return Ctap2ResponseCode.OK;
        } finally { PinProtocol1.wipe(shared); PinProtocol1.wipe(plain); PinProtocol1.wipe(hash); }
    }

    private Ctap2ResponseCode verifyPin(byte[] shared, byte[] encryptedHash) {
        // Consume durably BEFORE computing/returning whether the supplied PIN was right.
        storeRetries(config.pinRetries() - 1);
        byte[] supplied = null, expected = null;
        try {
            supplied = PinProtocol1.crypt(Cipher.DECRYPT_MODE, shared, encryptedHash);
            expected = config.pinHash().get();
            if (!MessageDigest.isEqual(expected, supplied)) {
                badPinsThisProcess++;
                keyAgreement = PinProtocol1.newKeyAgreement();
                if (config.pinRetries() == 0) return Ctap2ResponseCode.PIN_BLOCKED;
                if (badPinsThisProcess >= 3) return Ctap2ResponseCode.PIN_AUTH_BLOCKED;
                return Ctap2ResponseCode.PIN_INVALID;
            }
            storeRetries(8);
            badPinsThisProcess = 0;
            return Ctap2ResponseCode.OK;
        } finally { PinProtocol1.wipe(supplied); PinProtocol1.wipe(expected); }
    }

    public synchronized Result<byte[], Ctap2ResponseCode> getPinTokenEncrypted(PublicKey host, byte[] encryptedHash) {
        usable();
        if (!isPinSet()) return Result.err(Ctap2ResponseCode.PIN_NOT_SET);
        Ctap2ResponseCode blocked = blocked();
        if (blocked != null) return Result.err(blocked);
        if (encryptedHash == null || encryptedHash.length != 16) return Result.err(Ctap2ResponseCode.PIN_AUTH_INVALID);
        byte[] shared = PinProtocol1.sharedSecret(keyAgreement, host);
        try {
            Ctap2ResponseCode result = verifyPin(shared, encryptedHash);
            if (result != Ctap2ResponseCode.OK) return Result.err(result);
            if (!tokenIssued || expired()) rotateToken();
            issuedAt = clock.getAsLong();
            tokenIssued = true;
            tokenExpired = false;
            badAuthThisProcess = 0;
            return Result.ok(PinProtocol1.crypt(Cipher.ENCRYPT_MODE, shared, token));
        } finally { PinProtocol1.wipe(shared); }
    }

    private boolean expired() {
        long elapsed = clock.getAsLong() - issuedAt;
        return tokenIssued && (elapsed < 0 || elapsed >= TOKEN_LIFETIME);
    }
    public synchronized boolean authorizationActive() {
        usable();
        return isPinSet() && blocked() == null && tokenIssued && !expired();
    }
    public synchronized Optional<Ctap2ResponseCode> isPinAuthValid(byte[] clientHash, byte[] auth) {
        usable();
        if (!isPinSet()) return Optional.of(Ctap2ResponseCode.PIN_AUTH_INVALID);
        Ctap2ResponseCode blocked = blocked();
        if (blocked != null) return Optional.of(blocked);
        if (expired()) { rotateToken(); tokenExpired = true; }
        if (tokenExpired) return Optional.of(Ctap2ResponseCode.PIN_TOKEN_EXPIRED);
        boolean valid = tokenIssued && clientHash != null && clientHash.length == 32
                && tagValid(token, auth, clientHash);
        if (!valid) {
            badAuthThisProcess++;
            return Optional.of(badAuthThisProcess >= 3
                    ? Ctap2ResponseCode.PIN_AUTH_BLOCKED : Ctap2ResponseCode.PIN_AUTH_INVALID);
        }
        badAuthThisProcess = 0;
        return Optional.empty(); // Only a delivered token from a correct PIN can reach this.
    }
}

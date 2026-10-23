package com.github.mphi_rc.fido2;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import com.github.mphi_rc.fido2.authenticator.ConfigurationCredentialStore;
import com.github.mphi_rc.fido2.authenticator.Credential;
import com.github.mphi_rc.fido2.authenticator.crypto.P256AttestationKeyPair;

/**
 * Each phase is a separate JVM process. Never attaches USB, touches systemd,
 * or uses real credentials. State and fingerprints are test-only and private.
 */
public final class StateLifecycleProbe {
    private static final String RP = "pikeyua-lifecycle.invalid";
    private static final byte[] USER = { 0x70, 0x69, 0x6b, 0x65, 0x79 };
    private static final byte[] PIN = new byte[16];
    private static final BouncyCastleProvider CRYPTO = new BouncyCastleProvider();
    static { Arrays.fill(PIN, (byte) 0x5a); }

    private StateLifecycleProbe() { }

    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            throw new IllegalArgumentException("Usage: StateLifecycleProbe <phase> <private-test-dir>");
        }
        Path directory = Paths.get(args[1]).toAbsolutePath().normalize();
        check(Files.isDirectory(directory), "Missing test directory");
        check(Files.getPosixFilePermissions(directory).equals(
                PosixFilePermissions.fromString("rwx------")), "Test directory must be 0700");
        Path state = directory.resolve("config.json");
        Path baseline = directory.resolve("expected.sha256");

        switch (args[0]) {
            case "create":
                check(!Files.exists(state), "Test state already exists");
                ConfigurationFile created = new ConfigurationFile(state);
                created.persistToDisk();
                Credential newCredential = new ConfigurationCredentialStore(created)
                        .saveCredential(RP, USER, P256AttestationKeyPair.generate());
                check(newCredential.signatureCount() == 0, "New credential counter != 0");
                AtomicStateFile.write(baseline,
                        fingerprint(created).getBytes(StandardCharsets.US_ASCII));
                break;
            case "verify":
                verify(new ConfigurationFile(state), baseline, 0, false);
                break;
            case "increment":
                ConfigurationFile mutable = new ConfigurationFile(state);
                verify(mutable, baseline, 0, false);
                Credential previous = mutable.credentials().get(0);
                new ConfigurationCredentialStore(mutable)
                        .incrementCredentialCounter(RP, previous.keyPair());
                check(mutable.credentials().get(0).signatureCount() == 1, "Counter did not increment");
                mutable.updatePinHash(PIN);
                break;
            case "verify-updated":
                verify(new ConfigurationFile(state), baseline, 1, true);
                break;
            case "negative-corrupt":
                verify(new ConfigurationFile(state), baseline, 1, true);
                Path malformed = directory.resolve("malformed.json");
                Path incomplete = directory.resolve("incomplete.json");
                Path symlink = directory.resolve("linked.json");
                Path missingBackup = directory.resolve("missing-state-backup.json");
                Path marker = directory.resolve("config.json.identity");
                try {
                    AtomicStateFile.write(malformed, "{broken".getBytes(StandardCharsets.UTF_8));
                    assertLoadRejected(malformed, "Malformed JSON");
                    AtomicStateFile.write(incomplete, "{}".getBytes(StandardCharsets.UTF_8));
                    assertLoadRejected(incomplete, "Missing identity/credentials");
                    Files.createSymbolicLink(symlink, state);
                    assertLoadRejected(symlink, "State symlink");
                    byte[] pinnedIdentity = AtomicStateFile.read(marker);
                    try {
                        AtomicStateFile.write(marker, "wrong-id".getBytes(StandardCharsets.US_ASCII));
                        assertLoadRejected(state, "Mismatched persisted identity");
                    } finally {
                        AtomicStateFile.write(marker, pinnedIdentity);
                    }
                    Files.move(state, missingBackup);
                    try {
                        assertLoadRejected(state, "Previously initialized missing state");
                    } finally {
                        Files.move(missingBackup, state);
                    }
                } finally {
                    Files.deleteIfExists(malformed);
                    Files.deleteIfExists(incomplete);
                    Files.deleteIfExists(symlink);
                    Files.deleteIfExists(missingBackup);
                }
                verify(new ConfigurationFile(state), baseline, 1, true);
                break;
            case "negative-denied":
                ConfigurationFile denied = new ConfigurationFile(state);
                verify(denied, baseline, 1, true);
                byte[] before = Files.readAllBytes(state);
                Files.setPosixFilePermissions(directory,
                        PosixFilePermissions.fromString("r-x------"));
                try {
                    expectWriteFailure(() -> denied.updatePinHash(new byte[16]), "PIN update");
                    expectWriteFailure(() -> new ConfigurationCredentialStore(denied)
                            .incrementCredentialCounter(RP, denied.credentials().get(0).keyPair()),
                            "Signature counter");
                    check(Arrays.equals(denied.pinHash().get(), PIN),
                            "Failed PIN write changed in-memory state");
                    check(denied.credentials().get(0).signatureCount() == 1,
                            "Failed counter write changed in-memory state");
                } finally {
                    Files.setPosixFilePermissions(directory,
                            PosixFilePermissions.fromString("rwx------"));
                }
                check(Arrays.equals(before, Files.readAllBytes(state)),
                        "Denied write modified state on disk");
                verify(new ConfigurationFile(state), baseline, 1, true);
                break;
            default:
                throw new IllegalArgumentException("Unknown test phase: " + args[0]);
        }
        System.out.println("PASS: " + args[0]);
    }

    private static void verify(ConfigurationFile config, Path baseline,
                               int counter, boolean pinPresent) throws Exception {
        check(config.credentials().size() == 1, "Missing/duplicate credential");
        Credential cred = config.credentials().get(0);
        check(RP.equals(cred.relayingPartyId()), "RP ID changed");
        check(Arrays.equals(USER, cred.userId()), "User ID changed");
        check(cred.signatureCount() == counter, "Counter changed");
        check(config.pinHash().isPresent() == pinPresent, "PIN state changed");
        if (pinPresent) check(Arrays.equals(PIN, config.pinHash().get()), "PIN hash changed");
        String expected = new String(AtomicStateFile.read(baseline), StandardCharsets.US_ASCII);
        check(expected.equals(fingerprint(config)), "AAGUID, credential ID or keys changed");
        checkSignature(cred);
    }

    private static void checkSignature(Credential cred) throws Exception {
        KeyFactory kf = KeyFactory.getInstance("EC", CRYPTO);
        PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(
                cred.keyPair().privateKey()));
        PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(
                cred.keyPair().publicKey()));
        byte[] challenge = "pikeyua-v7.1-synthetic-test".getBytes(StandardCharsets.UTF_8);
        Signature sign = Signature.getInstance("SHA256withECDSA", CRYPTO);
        sign.initSign(priv);
        sign.update(challenge);
        byte[] signature = sign.sign();
        Signature verify = Signature.getInstance("SHA256withECDSA", CRYPTO);
        verify.initVerify(pub);
        verify.update(challenge);
        check(verify.verify(signature), "Restored private key cannot sign");
    }

    private static String fingerprint(ConfigurationFile config) throws Exception {
        Credential cred = config.credentials().get(0);
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        return config.id() + "\n" + encode(config.getAaguid())
                + "\n" + encode(cred.id())
                + "\n" + encode(sha.digest(cred.keyPair().privateKey()))
                + "\n" + encode(sha.digest(cred.keyPair().publicKey())) + "\n";
    }

    private static String encode(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    private static void assertLoadRejected(Path path, String name) {
        try {
            new ConfigurationFile(path);
            throw new AssertionError(name + " was incorrectly accepted");
        } catch (IllegalStateException expected) {
            // Correct: reject state rather than silently generating new keys.
        }
    }

    private static void expectWriteFailure(Runnable action, String name) {
        try {
            action.run();
            throw new AssertionError(name + " was acknowledged despite storage failure");
        } catch (IllegalStateException expected) {
            // Correct: no successful acknowledgement or memory update.
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}

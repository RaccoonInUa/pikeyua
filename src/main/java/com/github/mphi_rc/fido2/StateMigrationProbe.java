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
import com.github.mphi_rc.fido2.authenticator.ImmutableCredential;
import com.github.mphi_rc.fido2.authenticator.crypto.P256AttestationKeyPair;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * Non-USB migration probe. Each phase executes in an independent JVM.
 * Uses only synthetic P-256 keys under an isolated private directory.
 */
public final class StateMigrationProbe {
    private static final String LEGACY_RP = "pikeyua-lifecycle.invalid";
    private static final String NEW_RP = "new.rp.invalid";
    private static final BouncyCastleProvider PROVIDER = new BouncyCastleProvider();
    private static final byte[] LEGACY_USER = new byte[] {0x70, 0x69, 0x6b, 0x65, 0x79};

    private StateMigrationProbe() { }

    public static void main(String[] args) throws Exception {
        if (args.length != 2) throw new IllegalArgumentException(
                "Usage: StateMigrationProbe <legacy-create|legacy-import|legacy-read|upgrade|verify> <test-dir>");
        Path dir = Paths.get(args[1]).toAbsolutePath().normalize();
        check(Files.getPosixFilePermissions(dir).equals(
                PosixFilePermissions.fromString("rwx------")), "Directory must be 0700");
        Path path = dir.resolve("config.json");
        Path expected = dir.resolve("legacy-fingerprint.txt");
        Path oldJson = dir.resolve("legacy-state.json");
        switch (args[0]) {
            case "legacy-create": {
                check(!Files.exists(path), "Test state already exists");
                ConfigurationFile first = new ConfigurationFile(path);
                first.persistToDisk();
                new ConfigurationCredentialStore(first).saveCredential(
                        LEGACY_RP, LEGACY_USER, P256AttestationKeyPair.generate());
                JsonObject old = new JsonParser().parse(
                        new String(AtomicStateFile.read(path), StandardCharsets.UTF_8))
                        .getAsJsonObject();
                old.remove("schemaVersion");
                JsonArray records = old.getAsJsonArray("credentials");
                check(records.size() == 1, "Unexpected legacy credential count");
                for (int i = 0; i < records.size(); i++) {
                    JsonObject credential = records.get(i).getAsJsonObject();
                    credential.remove("discoverable");
                    credential.remove("userName");
                    credential.remove("userDisplayName");
                }
                byte[] oldBytes = old.toString().getBytes(StandardCharsets.UTF_8);
                AtomicStateFile.write(path, oldBytes);
                AtomicStateFile.write(oldJson, oldBytes);
                AtomicStateFile.write(expected, fingerprint(first.credentials().get(0),
                        first.id().toString(), first.getAaguid()).getBytes(StandardCharsets.US_ASCII));
                break;
            }
            case "legacy-import": {
                check(Files.exists(path), "Authentic V7.1 test state must already exist");
                byte[] legacyBytes = AtomicStateFile.read(path);
                JsonObject doc = new JsonParser().parse(
                        new String(legacyBytes, StandardCharsets.UTF_8)).getAsJsonObject();
                check(!doc.has("schemaVersion"), "Expected genuine unversioned V7.1 state");
                JsonArray entries = doc.getAsJsonArray("credentials");
                check(entries.size() == 1, "Expected one real V7.1 test credential");
                JsonObject entry = entries.get(0).getAsJsonObject();
                check(!entry.has("discoverable") && !entry.has("userName")
                        && !entry.has("userDisplayName"),
                        "V7.1 state unexpectedly contains V7.2 fields");
                ConfigurationFile initial = new ConfigurationFile(path);
                check(initial.schemaVersion() == 1, "Real V7.1 state not interpreted as schema v1");
                Credential old = initial.credentials().get(0);
                check(LEGACY_RP.equals(old.relayingPartyId()), "Unexpected legacy test RP");
                check(Arrays.equals(LEGACY_USER, old.userId()), "Unexpected legacy test handle");
                verifySigning(old);
                AtomicStateFile.write(expected, fingerprint(old, initial.id().toString(),
                        initial.getAaguid()).getBytes(StandardCharsets.US_ASCII));
                AtomicStateFile.write(oldJson, legacyBytes);
                break;
            }
            case "legacy-read": {
                ConfigurationFile old = new ConfigurationFile(path);
                check(old.schemaVersion() == 1, "Missing schema version not interpreted as v1");
                check(old.credentials().size() == 1, "V7.1 credential missing");
                Credential cred = old.credentials().get(0);
                check(!cred.discoverable(), "Legacy credential incorrectly made discoverable");
                check(cred.userName().isEmpty() && cred.userDisplayName().isEmpty(),
                        "Legacy user metadata default differs");
                verifyLegacy(old, expected);
                check(Arrays.equals(AtomicStateFile.read(path), AtomicStateFile.read(oldJson)),
                        "Reading legacy state silently modified its JSON");
                break;
            }
            case "upgrade": {
                ConfigurationFile old = new ConfigurationFile(path);
                check(old.schemaVersion() == 1, "Must start with old state");
                verifyLegacy(old, expected);
                Credential newRK = ImmutableCredential.builder()
                        .relayingPartyId(NEW_RP)
                        .creation(Instant.now())
                        .userId(new byte[]{ 4, 5, 6 })
                        .keyPair(P256AttestationKeyPair.generate())
                        .signatureCount(0)
                        .discoverable(true)
                        .userName("rk-test")
                        .userDisplayName("RK Test")
                        .build();
                old.addCredential(newRK);
                check(old.schemaVersion() == 2, "State was not upgraded to v2");
                check(old.credentials().size() == 2, "New credential missing");
                verifyLegacy(old, expected);
                break;
            }
            case "verify": {
                ConfigurationFile restored = new ConfigurationFile(path);
                check(restored.schemaVersion() == 2, "V7.2 schema did not survive JVM restart");
                check(restored.credentials().size() == 2, "Credential count changed");
                verifyLegacy(restored, expected);
                Credential newRK = restored.credentials().stream()
                        .filter(c -> c.relayingPartyId().equals(NEW_RP)).findFirst()
                        .orElseThrow(() -> new AssertionError("RK credential missing"));
                check(newRK.discoverable(), "Discoverability did not persist");
                check(newRK.userName().equals("rk-test"), "Username did not persist");
                check(newRK.userDisplayName().equals("RK Test"), "Display name did not persist");
                verifySigning(newRK);
                break;
            }
            default: throw new IllegalArgumentException("Unsupported migration phase");
        }
        System.out.println("PASS: V7.2 migration " + args[0]);
    }

    private static void verifyLegacy(ConfigurationFile file, Path expected) throws Exception {
        Credential old = file.credentials().stream()
                .filter(c -> c.relayingPartyId().equals(LEGACY_RP))
                .findFirst().orElseThrow(() -> new AssertionError("Legacy credential missing"));
        check(!old.discoverable(), "Legacy credential became discoverable");
        check(Arrays.equals(LEGACY_USER, old.userId()), "Legacy handle changed");
        String actual = fingerprint(old, file.id().toString(), file.getAaguid());
        String original = new String(AtomicStateFile.read(expected), StandardCharsets.US_ASCII);
        check(original.equals(actual), "Legacy AAGUID, credential ID or keys changed");
        verifySigning(old);
    }

    private static String fingerprint(Credential c, String identity, byte[] aaguid) throws Exception {
        MessageDigest hash = MessageDigest.getInstance("SHA-256");
        return identity + "\n" + enc(aaguid) + "\n"
                + enc(c.id()) + "\n"
                + enc(hash.digest(c.keyPair().privateKey())) + "\n"
                + enc(hash.digest(c.keyPair().publicKey())) + "\n";
    }

    private static void verifySigning(Credential c) throws Exception {
        KeyFactory factory = KeyFactory.getInstance("EC", PROVIDER);
        PrivateKey privateKey = factory.generatePrivate(
                new PKCS8EncodedKeySpec(c.keyPair().privateKey()));
        PublicKey publicKey = factory.generatePublic(
                new X509EncodedKeySpec(c.keyPair().publicKey()));
        byte[] message = "isolated-v72-migration".getBytes(StandardCharsets.UTF_8);
        Signature signer = Signature.getInstance("SHA256withECDSA", PROVIDER);
        signer.initSign(privateKey);
        signer.update(message);
        byte[] sig = signer.sign();
        Signature verifier = Signature.getInstance("SHA256withECDSA", PROVIDER);
        verifier.initVerify(publicKey);
        verifier.update(message);
        check(verifier.verify(sig), "Restored credential cannot sign");
    }

    private static String enc(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    private static void check(boolean ok, String reason) {
        if (!ok) throw new AssertionError(reason);
    }
}

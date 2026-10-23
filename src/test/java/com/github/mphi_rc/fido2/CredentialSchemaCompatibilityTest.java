package com.github.mphi_rc.fido2;

import static org.junit.Assert.*;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import com.github.mphi_rc.fido2.authenticator.ConfigurationCredentialStore;
import com.github.mphi_rc.fido2.authenticator.Credential;
import com.github.mphi_rc.fido2.authenticator.ImmutableCredential;
import com.github.mphi_rc.fido2.authenticator.crypto.P256AttestationKeyPair;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/** Synthetic file fixtures shaped as genuine V7.1 state: missing all V7.2 fields. */
public class CredentialSchemaCompatibilityTest {
    @Rule public TemporaryFolder root = new TemporaryFolder();

    private Path privateState() throws Exception {
        Path dir = root.newFolder("auth").toPath();
        Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx------"));
        return dir.resolve("config.json");
    }

    @Test
    public void legacyRecordDeserializesWithoutChangingIdentityOrPrivateKey() throws Exception {
        Path file = privateState();
        ConfigurationFile initial = new ConfigurationFile(file);
        initial.persistToDisk();
        Credential old = new ConfigurationCredentialStore(initial).saveCredential(
                "legacy.example.invalid",
                new byte[]{ 0x05, 0x06, 0x07 },
                P256AttestationKeyPair.generate());
        UUID aaguidIdentity = initial.id();
        byte[] oldId = old.id();
        byte[] oldPrivate = old.keyPair().privateKey();
        byte[] oldPublic = old.keyPair().publicKey();

        // Recreate the exact *shape* of V7.1 JSON (no V7.2 attributes).
        JsonObject document = new JsonParser().parse(
                new String(AtomicStateFile.read(file), StandardCharsets.UTF_8))
                .getAsJsonObject();
        document.remove("schemaVersion");
        JsonArray records = document.getAsJsonArray("credentials");
        assertEquals(1, records.size());
        JsonObject record = records.get(0).getAsJsonObject();
        record.remove("discoverable");
        record.remove("userName");
        record.remove("userDisplayName");
        AtomicStateFile.write(file, document.toString().getBytes(StandardCharsets.UTF_8));

        ConfigurationFile migrated = new ConfigurationFile(file);
        assertEquals(1, migrated.schemaVersion());
        assertEquals(aaguidIdentity, migrated.id());
        Credential legacy = migrated.credentials().get(0);
        assertFalse("Legacy records must NEVER become discoverable implicitly",
                legacy.discoverable());
        assertEquals("", legacy.userName());
        assertEquals("", legacy.userDisplayName());
        assertArrayEquals(oldId, legacy.id());
        assertArrayEquals(oldPrivate, legacy.keyPair().privateKey());
        assertArrayEquals(oldPublic, legacy.keyPair().publicKey());

        // No disk upgrade merely from reading an old state.
        JsonObject beforeUpdate = new JsonParser().parse(
                new String(AtomicStateFile.read(file), StandardCharsets.UTF_8))
                .getAsJsonObject();
        assertFalse(beforeUpdate.has("schemaVersion"));

        // A normal V7.2 mutation upgrades schema atomically.
        new ConfigurationCredentialStore(migrated).incrementCredentialCounter(
                legacy.relayingPartyId(), legacy.keyPair());
        assertEquals(2, migrated.schemaVersion());
        ConfigurationFile restored = new ConfigurationFile(file);
        assertEquals(2, restored.schemaVersion());
        assertEquals(aaguidIdentity, restored.id());
        Credential recovered = restored.credentials().get(0);
        assertFalse(recovered.discoverable());
        assertEquals(1, recovered.signatureCount());
        assertArrayEquals(oldId, recovered.id());
        assertArrayEquals(oldPrivate, recovered.keyPair().privateKey());
        assertArrayEquals(oldPublic, recovered.keyPair().publicKey());
        assertEquals(PosixFilePermissions.fromString("rw-------"),
                Files.getPosixFilePermissions(file));
    }

    @Test
    public void newlyCreatedMetadataSurvivesSaveAndReload() throws Exception {
        Path file = privateState();
        ConfigurationFile config = new ConfigurationFile(file);
        config.persistToDisk();
        Credential created = ImmutableCredential.builder()
                .relayingPartyId("new.example.invalid")
                .creation(Instant.now())
                .userId(new byte[]{ 0x01, 0x02, 0x03 })
                .keyPair(P256AttestationKeyPair.generate())
                .signatureCount(0)
                .discoverable(true)
                .userName("user@example.invalid")
                .userDisplayName("Test User")
                .build();
        config.addCredential(created);
        ConfigurationFile restored = new ConfigurationFile(file);
        assertEquals(2, restored.schemaVersion());
        Credential saved = restored.credentials().get(0);
        assertTrue(saved.discoverable());
        assertEquals("user@example.invalid", saved.userName());
        assertEquals("Test User", saved.userDisplayName());
        assertArrayEquals(created.id(), saved.id());
        assertArrayEquals(created.keyPair().privateKey(), saved.keyPair().privateKey());
        assertArrayEquals(created.keyPair().publicKey(), saved.keyPair().publicKey());
    }

    @Test
    public void metadataDoesNotEnterCredentialIdComputation() {
        P256AttestationKeyPair keys = (P256AttestationKeyPair) P256AttestationKeyPair.generate();
        ImmutableCredential legacy = ImmutableCredential.of(
                "example.invalid", Instant.ofEpochMilli(123456789L),
                new byte[]{ 0x01 }, keys, 0);
        Credential upgraded = ImmutableCredential.builder()
                .from(legacy).discoverable(true)
                .userName("changed").userDisplayName("Different Name").build();
        assertArrayEquals(legacy.id(), upgraded.id());
        assertArrayEquals(legacy.keyPair().privateKey(), upgraded.keyPair().privateKey());
    }

    @Test
    public void invalidDiscoverableUserHandleAndMetadataAreRejected() {
        try {
            ImmutableCredential.builder().relayingPartyId("test.invalid")
                    .creation(Instant.now()).userId(new byte[0])
                    .keyPair(P256AttestationKeyPair.generate())
                    .signatureCount(0).discoverable(true).build();
            fail("Empty discoverable user handle was accepted");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("Discoverable"));
        }
        try {
            ImmutableCredential.builder().relayingPartyId("test.invalid")
                    .creation(Instant.now()).userId(new byte[]{ 1 })
                    .keyPair(P256AttestationKeyPair.generate())
                    .signatureCount(0).discoverable(true)
                    .userName(new String(new char[100]).replace('\0', 'x'))
                    .build();
            fail("Oversized userName was accepted");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("metadata"));
        }
    }

    @Test
    public void futureSchemaVersionFailsClosed() throws Exception {
        Path file = privateState();
        ConfigurationFile config = new ConfigurationFile(file);
        config.persistToDisk();
        JsonObject document = new JsonParser().parse(
                new String(AtomicStateFile.read(file), StandardCharsets.UTF_8))
                .getAsJsonObject();
        document.addProperty("schemaVersion", 999);
        AtomicStateFile.write(file, document.toString().getBytes(StandardCharsets.UTF_8));
        try {
            new ConfigurationFile(file);
            fail("Unknown future schema must not be silently accepted");
        } catch (IllegalStateException expected) {
            assertNotNull(expected.getCause());
        }
    }
}

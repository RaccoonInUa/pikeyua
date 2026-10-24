package com.github.mphi_rc.fido2;

import static org.junit.Assert.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class PinStorageValidationTest {
    @Rule public TemporaryFolder temp = new TemporaryFolder();
    private Path state() throws Exception {
        Path dir = temp.newFolder().toPath();
        Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx------"));
        Path file = dir.resolve("config.json");
        ConfigurationFile config = new ConfigurationFile(file);
        config.updatePinHash(new byte[16]);
        return file;
    }
    @Test public void nullPinHashCannotTurnInitializedV3BackIntoAnUnconfiguredKey() throws Exception {
        Path file = state();
        JsonObject object = new JsonParser().parse(new String(AtomicStateFile.read(file), StandardCharsets.UTF_8)).getAsJsonObject();
        object.add("pinHash", JsonNull.INSTANCE);
        AtomicStateFile.write(file, object.toString().getBytes(StandardCharsets.UTF_8));
        try { new ConfigurationFile(file); fail("Null v3 PIN hash accepted"); }
        catch (IllegalStateException expected) { assertNotNull(expected.getCause()); }
    }
    @Test public void otherStateWritesDoNotDowngradeSchemaOrRefundBlockedPin() throws Exception {
        Path file = state(); ConfigurationFile config = new ConfigurationFile(file);
        config.updatePinRetries(0); config.persistToDisk();
        config.updateAllStoredCredentials(config.credentials());
        ConfigurationFile restored = new ConfigurationFile(file);
        assertEquals(3, restored.schemaVersion()); assertEquals(0, restored.pinRetries());
        assertTrue(restored.pinHash().isPresent());
    }
}

package com.github.mphi_rc.fido2;

import static org.junit.Assert.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class AtomicStateFileTest {
    @Rule public TemporaryFolder temporary = new TemporaryFolder();

    private Path privateDirectory() throws IOException {
        Path dir = temporary.newFolder("state").toPath();
        Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx------"));
        return dir;
    }

    @Test public void persistsAndAtomicallyReplacesWithPrivatePermissions() throws Exception {
        Path file = privateDirectory().resolve("config.json");
        AtomicStateFile.write(file, "first".getBytes(StandardCharsets.UTF_8));
        assertEquals("first", new String(AtomicStateFile.read(file), StandardCharsets.UTF_8));
        AtomicStateFile.write(file, "second".getBytes(StandardCharsets.UTF_8));
        assertEquals("second", new String(AtomicStateFile.read(file), StandardCharsets.UTF_8));
        assertEquals(PosixFilePermissions.fromString("rw-------"),
                Files.getPosixFilePermissions(file));
        try (java.util.stream.Stream<Path> entries = Files.list(file.getParent())) {
            assertEquals(1L, entries.count()); // No residual temp files
        }
    }

    @Test public void rejectsWorldReadableStateDirectory() throws Exception {
        Path dir = privateDirectory();
        Path file = dir.resolve("config.json");
        Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwxr-xr-x"));
        try {
            AtomicStateFile.write(file, new byte[]{ 1, 2, 3 });
            fail("Expected unsafe state directory to be rejected");
        } catch (IOException expected) {
            assertFalse(Files.exists(file));
        }
    }

    @Test public void rejectsSymlinkAndProtectsTarget() throws Exception {
        Path dir = privateDirectory();
        Path outside = temporary.newFile("outside.json").toPath();
        Files.write(outside, "original".getBytes(StandardCharsets.UTF_8));
        Path link = dir.resolve("config.json");
        Files.createSymbolicLink(link, outside);
        try {
            AtomicStateFile.write(link, "malicious".getBytes(StandardCharsets.UTF_8));
            fail("Expected symlink to be rejected");
        } catch (IOException expected) {
            assertEquals("original", new String(Files.readAllBytes(outside), StandardCharsets.UTF_8));
        }
    }

    @Test public void rejectsUnsafeStateFilePermissions() throws Exception {
        Path file = privateDirectory().resolve("config.json");
        AtomicStateFile.write(file, "safe".getBytes(StandardCharsets.UTF_8));
        Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-r--r--"));
        try {
            AtomicStateFile.read(file);
            fail("Expected insecure state permissions to be rejected");
        } catch (IOException expected) {
            assertTrue(Files.exists(file));
        }
    }
}

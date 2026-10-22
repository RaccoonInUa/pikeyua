package com.github.mphi_rc.fido2;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import com.github.mphi_rc.fido2.authenticator.Credential;
import com.github.mphi_rc.fido2.authenticator.ImmutableCredential;
import com.github.mphi_rc.fido2.authenticator.crypto.P256AttestationKeyPair;

/**
 * Isolated ARMv6 integration smoke test. Does not attach a gadget, talk to HID,
 * read the running service state, or modify any production authenticator keys.
 * Requires the Raspberry Pi's UDC to exist because the upstream Configuration
 * model validates that controller during construction.
 */
public final class StateSmokeTest {
    private StateSmokeTest() { }

    public static void main(String[] args) throws Exception {
        if (args.length != 0) {
            throw new IllegalArgumentException("No arguments; the test always uses its own temporary state");
        }
        Path directory = Files.createTempDirectory(
                "pikeyua-persistence-smoke-",
                PosixFilePermissions.asFileAttribute(
                        PosixFilePermissions.fromString("rwx------")));
        Path state = directory.resolve("config.json");
        try {
            ConfigurationFile first = new ConfigurationFile(state);
            first.persistToDisk();
            UUID identity = first.id();

            Credential added = ImmutableCredential.of(
                    "pikeyua-smoke.invalid",
                    Instant.now(),
                    new byte[] { 1, 2, 3 },
                    P256AttestationKeyPair.generate(),
                    0);
            first.addCredential(added);

            ConfigurationFile second = new ConfigurationFile(state);
            check(identity.equals(second.id()), "AAGUID identity changed");
            check(second.credentials().size() == 1, "Credential was not restored");
            check(Arrays.equals(added.id(), second.credentials().get(0).id()),
                    "Credential ID changed after serialization");

            List<Credential> updated = new ArrayList<>(second.credentials());
            updated.set(0, ImmutableCredential.builder()
                    .from(updated.get(0))
                    .signatureCount(1)
                    .build());
            second.updateAllStoredCredentials(updated);

            byte[] pinHash = new byte[16]; // Fake test value, not a real PIN.
            Arrays.fill(pinHash, (byte) 0x5a);
            second.updatePinHash(pinHash);

            ConfigurationFile third = new ConfigurationFile(state);
            check(identity.equals(third.id()), "AAGUID changed after update");
            check(third.credentials().size() == 1, "Credential disappeared after update");
            check(third.credentials().get(0).signatureCount() == 1,
                    "Signature counter did not persist");
            check(third.pinHash().isPresent(), "PIN state disappeared");
            check(Arrays.equals(pinHash, third.pinHash().get()),
                    "PIN state changed after serialization");
            check(Files.getPosixFilePermissions(state).equals(
                    PosixFilePermissions.fromString("rw-------")),
                    "State permissions differ from 0600");

            System.out.println("PASS: ARMv6 authenticator state, credential, counter, PIN and AAGUID round-trip.");
        } finally {
            Files.deleteIfExists(state);
            Files.deleteIfExists(directory.resolve("config.json.identity"));
            Files.deleteIfExists(directory);
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }
}

package com.github.mphi_rc.fido2;

import java.nio.file.Paths;
import java.util.Arrays;
import com.github.mphi_rc.fido2.authenticator.Credential;

/** Compiled and run with ONLY the frozen V7.3 JAR, never candidate classes. */
public final class LegacyCredentialReadback {
    public static void main(String[] args) {
        if (args.length != 2) throw new IllegalArgumentException("Expected two synthetic state paths");
        ConfigurationFile before = new ConfigurationFile(Paths.get(args[0]));
        ConfigurationFile after = new ConfigurationFile(Paths.get(args[1]));
        check(before.id().equals(after.id()) && before.schemaVersion() == after.schemaVersion(), "Identity/schema changed");
        check(before.pinRetries() == after.pinRetries()
                && before.pinHash().isPresent() == after.pinHash().isPresent(), "PIN state changed");
        if (before.pinHash().isPresent()) check(Arrays.equals(before.pinHash().get(), after.pinHash().get()), "PIN hash changed");
        check(before.credentials().size() == 1 && after.credentials().size() == 1, "Unexpected fixture count");
        Credential a = before.credentials().get(0), b = after.credentials().get(0);
        check(Arrays.equals(a.id(), b.id()) && Arrays.equals(a.keyPair().publicKey(), b.keyPair().publicKey())
                && Arrays.equals(a.keyPair().privateKey(), b.keyPair().privateKey()), "Keys/IDs changed");
        check(b.signatureCount() == a.signatureCount() + 1, "Counter did not persist");
        System.out.println("PASS: original V7.3 binary reads candidate state with identical keys/PIN/AAGUID and updated counter");
    }
    private static void check(boolean value, String message) { if (!value) throw new AssertionError(message); }
}

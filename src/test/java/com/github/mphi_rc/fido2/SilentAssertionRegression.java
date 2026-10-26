package com.github.mphi_rc.fido2;

import static com.github.mphi_rc.fido2.PinUvProbe.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Arrays;
import java.util.Comparator;
import java.util.stream.Stream;
import com.github.mphi_rc.fido2.authenticator.Credential;
import co.nstant.in.cbor.model.*;

/** Synthetic CBOR regressions for CTAP2.0 up=false; no real account, PIN, or USB. */
public final class SilentAssertionRegression {
    private static final String TEST_PIN = "817264";
    private static final byte[] UNKNOWN_ID = new byte[32];
    private SilentAssertionRegression() { }

    private static final class Fixture implements AutoCloseable {
        final Path directory, state;
        final Session session;
        final Client client;
        Fixture() throws Exception {
            directory = Files.createTempDirectory("pikeyua-silent-",
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
            state = directory.resolve("config.json");
            session = new Session(state);
            client = new Client(session);
            ok(client.set(TEST_PIN));
            ok(client.getToken(TEST_PIN));
        }
        Credential create(String rp, int user, boolean resident) throws Exception {
            ok(client.make(rp, user, resident, true));
            return session.config.credentials().stream()
                    .filter(c -> c.relayingPartyId().equals(rp) && c.userId()[0] == (byte) user)
                    .findFirst().get();
        }
        Map request(String rp, byte[] id, boolean token) throws Exception {
            Map request = client.assertionRequest(rp, id, token);
            Map options = new Map(); options.put(new UnicodeString("up"), SimpleValue.FALSE);
            put(request, 5, options);
            return request;
        }
        Reply silent(String rp, byte[] id, boolean token) throws Exception {
            return client.call(2, request(rp, id, token));
        }
        @Override public void close() throws Exception {
            try (Stream<Path> entries = Files.walk(directory)) {
                for (Path p : (Iterable<Path>) entries.sorted(Comparator.reverseOrder())::iterator) Files.delete(p);
            }
        }
    }
    private static void expected(int status, Reply reply) {
        check(reply.status == status, "Expected CTAP 0x" + Integer.toHexString(status)
                + ", got 0x" + Integer.toHexString(reply.status));
    }
    private static void flags(Fixture f, Reply reply, boolean up, boolean uv) throws Exception {
        verifyAssertion(f.session, reply, uv);
        check(((bytes(reply.body, 2)[32] & 1) != 0) == up, "Incorrect signed UP flag");
    }
    private static Map exclude(byte[] id) {
        Map descriptor = new Map(); descriptor.put(new UnicodeString("type"), new UnicodeString("public-key"));
        descriptor.put(new UnicodeString("id"), new ByteString(id)); return descriptor;
    }

    public static void missingCredentialReturnsNoCredentialsWithoutWriting() throws Exception {
        try (Fixture f = new Fixture()) {
            f.create(OTHER, 1, true);
            byte[] before = Files.readAllBytes(f.state);
            expected(0x2e, f.silent(RP, UNKNOWN_ID, true));
            check(Arrays.equals(before, Files.readAllBytes(f.state)), "Miss mutated state");
            check(f.client.retries() == 8, "Miss consumed PIN retry");
        }
    }
    public static void wrongRpCannotMatchKnownId() throws Exception {
        try (Fixture f = new Fixture()) {
            Credential c = f.create(RP, 1, true);
            byte[] before = Files.readAllBytes(f.state);
            expected(0x2e, f.silent(OTHER, c.id(), true));
            check(Arrays.equals(before, Files.readAllBytes(f.state)), "Cross-RP miss mutated state");
        }
    }
    public static void knownLegacySilentAssertionHasUpZeroUvOne() throws Exception {
        try (Fixture f = new Fixture()) {
            Credential c = f.create(RP, 1, false);
            Reply response = f.silent(RP, c.id(), true);
            flags(f, response, false, true);
            check(field(response.body, 4) == null, "Legacy response unexpectedly exposes user");
            check(new ConfigurationFile(f.state).credentials().get(0).signatureCount() == 1,
                    "Silent signature counter was not durably advanced");
        }
    }
    public static void residentSilentAssertionHasValidSignedFlags() throws Exception {
        try (Fixture f = new Fixture()) {
            Credential c = f.create(RP, 1, true);
            flags(f, f.silent(RP, c.id(), true), false, true);
        }
    }
    public static void silentWithoutPinNeverClaimsUvOrDisclosesNames() throws Exception {
        try (Fixture f = new Fixture()) {
            Credential c = f.create(RP, 1, true);
            Reply response = f.silent(RP, c.id(), false);
            flags(f, response, false, false);
            Map user = (Map) field(response.body, 4);
            check(user.get(new UnicodeString("displayName")) == null, "Unverified name leak");
        }
    }
    public static void absentUpStillMeansTrue() throws Exception {
        try (Fixture f = new Fixture()) {
            Credential c = f.create(RP, 1, true);
            flags(f, f.client.assertion(RP, c.id(), true), true, true);
        }
    }
    public static void explicitUpTrueStillWorks() throws Exception {
        try (Fixture f = new Fixture()) {
            Credential c = f.create(RP, 1, true);
            Map request = f.request(RP, c.id(), true);
            ((Map) field(request, 5)).put(new UnicodeString("up"), SimpleValue.TRUE);
            flags(f, f.client.call(2, request), true, true);
        }
    }
    public static void badPinAuthCannotSignOrWrite() throws Exception {
        try (Fixture f = new Fixture()) {
            Credential c = f.create(RP, 1, true);
            Map request = f.request(RP, c.id(), true);
            byte[] tag = bytes(request, 6).clone(); tag[0] ^= 1; put(request, 6, new ByteString(tag));
            byte[] before = Files.readAllBytes(f.state);
            expected(0x33, f.client.call(2, request));
            check(Arrays.equals(before, Files.readAllBytes(f.state)), "Bad proof changed state");
            check(f.client.retries() == 8, "Token error consumed PIN-guess budget");
        }
    }
    public static void badPinAuthForMissingIdIsNotIgnored() throws Exception {
        try (Fixture f = new Fixture()) {
            Map request = f.request(RP, UNKNOWN_ID, true);
            byte[] tag = bytes(request, 6).clone(); tag[0] ^= 1; put(request, 6, new ByteString(tag));
            expected(0x33, f.client.call(2, request));
        }
    }
    public static void builtInUvIsStillUnsupported() throws Exception {
        try (Fixture f = new Fixture()) {
            Credential c = f.create(RP, 1, true);
            Map request = f.request(RP, c.id(), true);
            ((Map) field(request, 5)).put(new UnicodeString("uv"), SimpleValue.TRUE);
            byte[] before = Files.readAllBytes(f.state);
            expected(0x2b, f.client.call(2, request));
            check(Arrays.equals(before, Files.readAllBytes(f.state)), "Unsupported built-in UV mutated state");
        }
    }
    public static void dummySelectionDoesNotRejectRealPinOrConsumeAttempts() throws Exception {
        try (Fixture f = new Fixture()) {
            Map dummy = f.client.makeRequest(".dummy", 1, false, false);
            put(dummy, 8, new ByteString(new byte[0])); put(dummy, 9, new UnsignedInteger(1));
            byte[] before = Files.readAllBytes(f.state);
            expected(0x31, f.client.call(1, dummy));
            check(Arrays.equals(before, Files.readAllBytes(f.state)), "Selection probe mutated state");
            check(f.client.retries() == 8, "Selection consumed a PIN attempt");
            ok(f.client.make(RP, 1, true, true));
        }
    }
    public static void chromeShapedExcludeMissCanProceedToRegistration() throws Exception {
        try (Fixture f = new Fixture()) {
            Map probe = f.request(RP, UNKNOWN_ID, true);
            byte[] emptyHash = digest(new byte[0]);
            put(probe, 2, new ByteString(emptyHash));
            put(probe, 6, new ByteString(mac(f.client.token, emptyHash)));
            byte[] before = Files.readAllBytes(f.state);
            expected(0x2e, f.client.call(2, probe));
            check(Arrays.equals(before, Files.readAllBytes(f.state)), "Probe miss mutated state");
            Reply created = f.client.make(RP, 1, true, true); ok(created);
            check((bytes(created.body, 2)[32] & 5) == 5, "Registration lost UP/UV");
            verifyAssertion(f.session, f.client.assertion(RP, null, true), true);
        }
    }
    public static void knownExcludeCredentialIsNotRegisteredTwice() throws Exception {
        try (Fixture f = new Fixture()) {
            Credential c = f.create(RP, 1, true);
            flags(f, f.silent(RP, c.id(), true), false, true);
            Map make = f.client.makeRequest(RP, 2, true, true);
            Array list = new Array(); list.add(exclude(c.id())); put(make, 5, list);
            byte[] before = Files.readAllBytes(f.state);
            expected(0x19, f.client.call(1, make));
            check(Arrays.equals(before, Files.readAllBytes(f.state)), "Exclusion replaced a credential");
        }
    }
    public static void silentDiscoveryContinuationKeepsUpZero() throws Exception {
        try (Fixture f = new Fixture()) {
            f.create(RP, 1, true); f.create(RP, 2, true); f.create(OTHER, 3, true);
            Reply first = f.silent(RP, null, true); flags(f, first, false, true);
            check(((UnsignedInteger) field(first.body, 5)).getValue().intValue() == 2, "Wrong discovery count");
            Reply next = f.client.call(8, null); flags(f, next, false, true);
            check(field(next.body, 5) == null, "Continuation repeated count");
            byte[] id1 = ((ByteString) ((Map) field(first.body, 1)).get(new UnicodeString("id"))).getBytes();
            byte[] id2 = ((ByteString) ((Map) field(next.body, 1)).get(new UnicodeString("id"))).getBytes();
            check(!Arrays.equals(id1, id2), "Repeated account"); expected(0x30, f.client.call(8, null));
        }
    }
    public static void subsequentNormalRequestDoesNotInheritSilentUp() throws Exception {
        try (Fixture f = new Fixture()) {
            Credential c = f.create(RP, 1, true); f.create(RP, 2, true);
            flags(f, f.silent(RP, null, true), false, true);
            flags(f, f.client.assertion(RP, c.id(), true), true, true);
            expected(0x30, f.client.call(8, null));
        }
    }
    public static void silentSignatureStorageFailureCannotReturnSuccess() throws Exception {
        try (Fixture f = new Fixture()) {
            Credential c = f.create(RP, 1, true);
            byte[] before = Files.readAllBytes(f.state);
            Files.setPosixFilePermissions(f.directory, PosixFilePermissions.fromString("r-x------"));
            try {
                try { f.silent(RP, c.id(), true); throw new AssertionError("Storage denial returned normally"); }
                catch (IllegalStateException expected) {
                    check(expected.getMessage().contains("persist"), "Unexpected failure instead of storage denial");
                }
            } finally { Files.setPosixFilePermissions(f.directory, PosixFilePermissions.fromString("rwx------")); }
            check(Arrays.equals(before, Files.readAllBytes(f.state)), "Denied write changed state");
        }
    }

    public static void allAuthenticatorFlagCombinationsSerialize() throws Exception {
        for (int up = 0; up < 2; up++) for (int uv = 0; uv < 2; uv++) for (int at = 0; at < 2; at++) {
            com.github.mphi_rc.fido2.protocol.ctap2.ImmutableAuthenticatorData.Builder b =
                    com.github.mphi_rc.fido2.protocol.ctap2.ImmutableAuthenticatorData.builder()
                    .relayingPartyId(RP).isUserPresent(up == 1).isUserVerified(uv == 1)
                    .signatureCount(0x12345678);
            if (at == 1) b.attestedCredentialData(new byte[]{9, 8, 7});
            byte[] out = b.build().asBytes();
            check(out.length == 37 + at * 3, "Incorrect authenticator-data length");
            check(out[32] == (byte) (up | (uv << 2) | (at << 6)), "Incorrect flags byte");
            check(java.nio.ByteBuffer.wrap(out, 33, 4).getInt() == 0x12345678, "Counter encoding changed");
        }
    }

    public static void main(String[] args) throws Exception {
        int failed = 0, passed = 0;
        for (java.lang.reflect.Method test : SilentAssertionRegression.class.getDeclaredMethods()) {
            if (!java.lang.reflect.Modifier.isPublic(test.getModifiers()) || test.getParameterCount() != 0) continue;
            try { test.invoke(null); System.out.println("PASS: " + test.getName()); passed++; }
            catch (java.lang.reflect.InvocationTargetException e) {
                System.out.println("FAIL: " + test.getName() + " - " + e.getCause()); failed++;
            }
        }
        System.out.println("SILENT ASSERTION RESULTS: " + passed + " passed, " + failed + " failed");
        if (failed != 0) throw new AssertionError("Silent assertion regressions failed: " + failed);
    }
}

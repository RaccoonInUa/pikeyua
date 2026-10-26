package com.github.mphi_rc.fido2;

import static org.junit.Assert.*;
import static com.github.mphi_rc.fido2.PinUvProbe.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import com.github.mphi_rc.fido2.authenticator.Credential;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import co.nstant.in.cbor.model.*;

/** Actual CBOR protocol round-trips using an independent JCE platform implementation. */
public class PinUvTest {
    @Rule public TemporaryFolder root = new TemporaryFolder();
    private Path directory, state;
    private Session session;
    private Client client;
    private AtomicLong clock;
    private static final String PIN = "246810", NEW_PIN = "135790";

    @Before public void setup() throws Exception {
        directory = root.newFolder("state").toPath();
        Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwx------"));
        state = directory.resolve("config.json"); clock = new AtomicLong(1); reload();
    }
    private void reload() { session = new Session(state, clock::get); client = new Client(session); }
    private void configured() throws Exception { assertEquals(0, client.set(PIN).status); }
    private void unlocked() throws Exception { configured(); assertEquals(0, client.getToken(PIN).status); }
    private JsonObject json() throws Exception {
        return new JsonParser().parse(new String(AtomicStateFile.read(state), StandardCharsets.UTF_8)).getAsJsonObject();
    }
    private void write(JsonObject json) throws Exception { AtomicStateFile.write(state, json.toString().getBytes(StandardCharsets.UTF_8)); }
    private void rejectedLoad() {
        try { new ConfigurationFile(state); fail("Corrupt PIN state accepted"); }
        catch (IllegalStateException expected) { assertNotNull(expected.getCause()); }
    }

    @Test public void setPinPersistsHashAndRetriesAndReportsClientPinNotBuiltInUv() throws Exception {
        assertFalse(client.configured()); configured();
        assertTrue(client.configured()); assertEquals(8, client.retries()); assertEquals(3, session.config.schemaVersion());
        assertArrayEquals(Arrays.copyOf(digest(PIN.getBytes(StandardCharsets.UTF_8)), 16), session.config.pinHash().get());
        reload(); assertTrue(client.configured()); assertEquals(8, client.retries());
    }
    @Test public void configuredPinCannotBeOverwrittenBySetPin() throws Exception {
        configured(); byte[] before = Files.readAllBytes(state);
        assertEquals(0x33, client.set(NEW_PIN).status); assertArrayEquals(before, Files.readAllBytes(state));
    }
    @Test public void setPinRequiresAuthenticatedCiphertext() throws Exception {
        Map request = client.setRequest(padded(PIN)); put(request, 4, new ByteString(new byte[16]));
        assertEquals(0x33, client.call(6, request).status); assertFalse(client.configured()); assertEquals(8, client.retries());
    }
    @Test public void shortLongEmbeddedNulAndBadUtf8PinsAreRejected() throws Exception {
        for (String value : new String[]{"", "123", "1234\0hidden", new String(new char[64]).replace('\0', 'a')}) {
            assertEquals(0x37, client.set(value).status); assertFalse(client.configured());
        }
        byte[] badUtf8 = new byte[64]; badUtf8[0] = (byte) 0xf0;
        badUtf8[1] = badUtf8[2] = badUtf8[3] = (byte) 0x80;
        assertEquals(0x37, client.call(6, client.setRequest(badUtf8)).status); assertFalse(client.configured());
    }
    @Test public void fourUnicodeCodePointsWork() throws Exception {
        String unicode = "\u041a\u043b\u044e\u0447";
        assertEquals(0, client.set(unicode).status); assertEquals(0, client.getToken(unicode).status);
        assertEquals(0, client.make(RP, 1, true, true).status);
    }
    @Test public void maximum63BytePinWorks() throws Exception {
        String longPin = new String(new char[63]).replace('\0', 'x');
        assertEquals(0, client.set(longPin).status); assertEquals(0, client.getToken(longPin).status);
    }
    @Test public void getTokenBeforePinIsSetFailsWithoutCreatingState() throws Exception {
        byte[] before = Files.readAllBytes(state);
        assertEquals(0x35, client.getToken(PIN).status); assertArrayEquals(before, Files.readAllBytes(state));
    }
    @Test public void threeWrongPinsBlockThisProcessAndRestartDoesNotRefundAttempts() throws Exception {
        configured();
        assertEquals(0x31, client.getToken("000000").status); assertEquals(7, client.retries());
        assertEquals(0x31, client.getToken("000000").status); assertEquals(6, client.retries());
        assertEquals(0x34, client.getToken("000000").status); assertEquals(5, client.retries());
        assertEquals(0x34, client.getToken(PIN).status); assertEquals(5, client.retries());
        reload(); assertEquals(5, client.retries());
        assertEquals(0, client.getToken(PIN).status); assertEquals(8, client.retries());
    }
    @Test public void eightFailedPinsRemainBlockedAcrossRestartsEvenWithCorrectPin() throws Exception {
        configured();
        for (int i = 0; i < 8; i++) {
            if (i > 0 && i % 3 == 0) reload();
            int expected = i == 7 ? 0x32 : ((i + 1) % 3 == 0 ? 0x34 : 0x31);
            assertEquals(expected, client.getToken("wrong").status); assertEquals(7 - i, client.retries());
        }
        reload(); assertEquals(0, client.retries()); assertEquals(0x32, client.getToken(PIN).status);
        assertEquals(0x32, client.change(PIN, NEW_PIN).status);
    }
    @Test public void failedGuessRotatesEcdhKey() throws Exception {
        configured(); byte[] before = session.pin.getKeyAgreementKey().getEncoded();
        assertEquals(0x31, client.getToken("wrong").status);
        assertFalse(Arrays.equals(before, session.pin.getKeyAgreementKey().getEncoded()));
    }
    @Test public void verifiedRegistrationAndAssertionSetSignedUvAndGateNames() throws Exception {
        unlocked();
        Reply made = client.make(RP, 1, true, true); assertEquals(0, made.status);
        assertTrue((bytes(made.body, 2)[32] & 4) != 0);
        Reply yes = client.assertion(RP, null, true); verifyAssertion(session, yes, true);
        Reply no = client.assertion(RP, null, false); verifyAssertion(session, no, false);
        assertEquals(2, session.config.credentials().get(0).signatureCount());
        assertEquals(2, new ConfigurationFile(state).credentials().get(0).signatureCount());
    }
    @Test public void configuredPinRequiresPinAuthForNewRegistration() throws Exception {
        configured(); byte[] before = Files.readAllBytes(state);
        assertEquals(0x36, client.make(RP, 1, true, false).status);
        assertArrayEquals(before, Files.readAllBytes(state)); assertTrue(session.config.credentials().isEmpty());
    }
    @Test public void pinAuthBindsChallengeAndWrongProofCannotMutateCredential() throws Exception {
        unlocked(); Map request = client.makeRequest(RP, 1, true, true);
        put(request, 1, new ByteString(digest("different-challenge".getBytes(StandardCharsets.UTF_8))));
        byte[] before = Files.readAllBytes(state);
        assertEquals(0x33, client.call(1, request).status); assertArrayEquals(before, Files.readAllBytes(state));
        assertEquals(8, client.retries());
    }
    @Test public void badTokenMacBlocksTemporarilyWithoutConsumingPinBudget() throws Exception {
        unlocked(); byte[] valid = client.token.clone(); client.token = new byte[32];
        assertEquals(0x33, client.make(RP, 1, true, true).status);
        assertEquals(0x33, client.make(RP, 1, true, true).status);
        assertEquals(0x34, client.make(RP, 1, true, true).status);
        client.token = valid; assertEquals(0x34, client.make(RP, 1, true, true).status);
        assertEquals(8, client.retries()); reload(); assertEquals(8, client.retries());
        assertEquals(0, client.getToken(PIN).status); assertEquals(0, client.make(RP, 1, true, true).status);
    }
    @Test public void tokenExpiresAndFreshPinGetsNewToken() throws Exception {
        unlocked(); byte[] old = client.token.clone(); clock.addAndGet(TimeUnit.MINUTES.toNanos(10));
        assertEquals(0x38, client.make(RP, 1, true, true).status); assertTrue(session.config.credentials().isEmpty());
        assertEquals(0, client.getToken(PIN).status); assertFalse(Arrays.equals(old, client.token));
        assertEquals(0, client.make(RP, 1, true, true).status);
    }
    @Test public void tokenDoesNotSurviveProcessReconstruction() throws Exception {
        unlocked(); byte[] old = client.token.clone(); reload(); client.token = old;
        assertEquals(0x33, client.make(RP, 1, true, true).status);
        assertEquals(8, client.retries()); assertEquals(0, client.getToken(PIN).status);
        assertFalse(Arrays.equals(old, client.token));
    }
    @Test public void changePinRevokesTokenButPreservesCredentialAndIdentity() throws Exception {
        unlocked(); assertEquals(0, client.make(RP, 1, true, true).status);
        Credential old = session.config.credentials().get(0); java.util.UUID id = session.config.id();
        assertEquals(0, client.change(PIN, NEW_PIN).status);
        assertEquals(0x33, client.assertion(RP, old.id(), true).status);
        assertEquals(0x31, client.getToken(PIN).status); assertEquals(7, client.retries());
        assertEquals(0, client.getToken(NEW_PIN).status); verifyAssertion(session, client.assertion(RP, null, true), true);
        assertEquals(id, session.config.id()); assertArrayEquals(old.id(), session.config.credentials().get(0).id());
        assertArrayEquals(old.keyPair().privateKey(), session.config.credentials().get(0).keyPair().privateKey());
    }
    @Test public void wrongChangePinMacDoesNotConsumeAttemptsOrChangePin() throws Exception {
        configured(); Map request = client.changeRequest(PIN, NEW_PIN); put(request, 4, new ByteString(new byte[16]));
        byte[] before = Files.readAllBytes(state);
        assertEquals(0x33, client.call(6, request).status); assertArrayEquals(before, Files.readAllBytes(state));
        assertEquals(8, client.retries());
    }
    @Test public void wrongOldPinConsumesAttemptWhileWeakNewPinDoesNotReplaceOldPin() throws Exception {
        configured(); assertEquals(0x31, client.change("wrong", NEW_PIN).status); assertEquals(7, client.retries());
        assertEquals(0x37, client.change(PIN, "123").status); assertEquals(8, client.retries());
        assertEquals(0, client.getToken(PIN).status);
    }
    @Test public void malformedClientPinInputAndInvalidCurveAreProtocolErrorsNotCrashes() throws Exception {
        Map absent = new Map(); assertEquals(0x14, client.call(6, absent).status);
        Map unsupported = client.pinRequest(1); put(unsupported, 1, new UnsignedInteger(2));
        assertEquals(0x02, client.call(6, unsupported).status);
        Map wrongType = client.pinRequest(1); put(wrongType, 2, new UnicodeString("1"));
        assertEquals(0x11, client.call(6, wrongType).status);
        assertEquals(0x01, client.call(6, client.pinRequest(99)).status);
        Map request = client.setRequest(padded(PIN)); Map point = (Map) field(request, 3);
        point.put(new NegativeInteger(-2), new ByteString(new byte[32])); point.put(new NegativeInteger(-3), new ByteString(new byte[32]));
        assertEquals(0x02, client.call(6, request).status); assertEquals(8, client.retries());
        request = client.setRequest(padded(PIN)); point = (Map) field(request, 3); point.put(new UnsignedInteger(3), new NegativeInteger(-7));
        assertEquals(0x02, client.call(6, request).status); assertFalse(client.configured());
    }
    @Test public void malformedPinFieldLengthsCannotReachPasswordComparison() throws Exception {
        Map request = client.setRequest(padded(PIN)); put(request, 4, new ByteString(new byte[15]));
        assertEquals(0x02, client.call(6, request).status);
        configured(); client.agreement(); request = client.pinRequest(5); put(request, 3, client.publicKey);
        put(request, 6, new ByteString(new byte[17])); assertEquals(0x02, client.call(6, request).status);
        assertEquals(8, client.retries());
    }
    @Test public void storageDenialFailsBeforeComparisonAndPoisonsCurrentPinSession() throws Exception {
        configured(); byte[] before = Files.readAllBytes(state);
        Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("r-x------"));
        try {
            try { client.getToken(PIN); fail("Storage failure yielded a token"); }
            catch (IllegalStateException expected) { assertNotNull(expected.getMessage()); }
        } finally { Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwx------")); }
        assertArrayEquals(before, Files.readAllBytes(state));
        try { client.getToken(PIN); fail("Failed storage session was silently reused"); }
        catch (IllegalStateException expected) { assertTrue(expected.getMessage().contains("storage")); }
        reload(); assertEquals(8, client.retries()); assertEquals(0, client.getToken(PIN).status);
    }
    @Test public void missingMalformedAndOutOfRangeRetryStateFailsClosed() throws Exception {
        configured(); JsonObject valid = json();
        JsonObject missing = new JsonParser().parse(valid.toString()).getAsJsonObject(); missing.remove("pinRetries");
        write(missing); rejectedLoad();
        for (String value : new String[]{"-1", "9", "0.5", "\"8\"", "null"}) {
            JsonObject malformed = new JsonParser().parse(valid.toString()).getAsJsonObject();
            malformed.add("pinRetries", new JsonParser().parse(value)); write(malformed); rejectedLoad();
        }
        JsonObject missingPin = new JsonParser().parse(valid.toString()).getAsJsonObject(); missingPin.remove("pinHash");
        write(missingPin); rejectedLoad();
    }
    @Test public void legacyPinStateMigratesWithoutChangingIdKeysOrPin() throws Exception {
        unlocked(); assertEquals(0, client.make(RP, 1, true, true).status);
        Credential old = session.config.credentials().get(0); java.util.UUID id = session.config.id();
        JsonObject legacy = json(); legacy.addProperty("schemaVersion", 2); legacy.remove("pinRetries"); write(legacy);
        reload(); assertEquals(8, client.retries()); assertEquals(0, client.getToken(PIN).status);
        assertEquals(3, session.config.schemaVersion()); assertEquals(id, session.config.id());
        assertArrayEquals(old.id(), session.config.credentials().get(0).id()); verifyAssertion(session, client.assertion(RP, null, true), true);
    }
    @Test public void pinHashStateNeverContainsPlainPinSharedSecretOrToken() throws Exception {
        unlocked(); String stored = new String(Files.readAllBytes(state), StandardCharsets.UTF_8);
        assertFalse(stored.contains("\"" + PIN + "\"")); assertFalse(stored.contains("pinToken")); assertFalse(stored.contains("sharedSecret"));
        assertFalse(stored.contains(java.util.Base64.getEncoder().encodeToString(client.token)));
        assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(state)));
    }
    @Test public void emptyPinSelectionProbeDoesNotConsumeAttemptsOrRegisterAnything() throws Exception {
        Map request = client.makeRequest(RP, 1, true, false); put(request, 8, new ByteString(new byte[0])); put(request, 9, new UnsignedInteger(1));
        assertEquals(0x35, client.call(1, request).status); configured();
        assertEquals(0x31, client.call(1, request).status); assertEquals(8, client.retries()); assertTrue(session.config.credentials().isEmpty());
    }
    @Test public void verifiedMultiAccountContinuationPreservesUvAndPinChangeCancelsIt() throws Exception {
        unlocked(); assertEquals(0, client.make(RP, 1, true, true).status); assertEquals(0, client.make(RP, 2, true, true).status);
        Reply first = client.assertion(RP, null, true); verifyAssertion(session, first, true);
        assertEquals(2, ((UnsignedInteger) field(first.body, 5)).getValue().intValue());
        verifyAssertion(session, client.call(8, null), true); assertEquals(0x30, client.call(8, null).status);
        verifyAssertion(session, client.assertion(RP, null, true), true);
        assertEquals(0, client.change(PIN, NEW_PIN).status); assertEquals(0x30, client.call(8, null).status);
    }
}

package com.github.mphi_rc.fido2.protocol.ctap2;

import static org.junit.Assert.*;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import com.github.mphi_rc.fido2.*;
import com.github.mphi_rc.fido2.authenticator.*;
import com.github.mphi_rc.fido2.authenticator.crypto.P256AttestationKeyPair;
import com.github.mphi_rc.fido2.protocol.ctap2.pin.PinRequestHandler;
import com.github.mphi_rc.fido2.protocol.usbhid.*;
import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.model.*;

/** Wire-level CTAP2 requests, synthetic secrets only, no USB or production state. */
public class DiscoverableCredentialTest {
    @Rule public TemporaryFolder temp = new TemporaryFolder();
    private static final String RP = "rk.example.invalid";
    private static final String OTHER_RP = "other.example.invalid";
    private static final ChannelId CID = ImmutableChannelId.of(new byte[]{1, 2, 3, 4});
    private static final ChannelId OTHER_CID = ImmutableChannelId.of(new byte[]{4, 3, 2, 1});
    private static final byte[] HASH = new byte[32];
    private Path dir;
    private Path statePath;
    private ConfigurationFile config;
    private ConfigurationCredentialStore store;
    private Authenticator auth;
    private AuthenticatorRequestHandler handler;
    private AtomicLong time;

    @Before public void setup() throws Exception {
        dir = temp.newFolder("state").toPath();
        Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx------"));
        statePath = dir.resolve("config.json");
        config = new ConfigurationFile(statePath);
        config.persistToDisk();
        time = new AtomicLong(1);
        reload(true);
    }

    private void reload(boolean enabled) {
        config = new ConfigurationFile(statePath);
        store = new ConfigurationCredentialStore(config);
        PinState pin = new PinState(config);
        auth = new Authenticator(config, store, pin, enabled, time::get);
        handler = new AuthenticatorRequestHandler(auth, new PinRequestHandler(pin));
    }

    private static byte[] encode(Map value) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        new CborEncoder(out).encode(Collections.<DataItem>singletonList(value));
        return out.toByteArray();
    }
    private static byte[] command(int command, Map value) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(command);
        if (value != null) out.write(encode(value));
        return out.toByteArray();
    }
    private byte[] call(ChannelId cid, int command, Map value) throws Exception {
        return handler.handleCborRequest(cid, command(command, value)).payload();
    }
    private byte[] call(int command, Map value) throws Exception { return call(CID, command, value); }
    private static Map body(byte[] response) throws Exception {
        assertEquals("CTAP status", 0, response[0] & 255);
        List<DataItem> items = CborDecoder.decode(Arrays.copyOfRange(response, 1, response.length));
        assertEquals(1, items.size());
        return (Map) items.get(0);
    }
    private static DataItem field(Map value, int key) { return value.get(new UnsignedInteger(key)); }
    private static DataItem field(Map value, String key) { return value.get(new UnicodeString(key)); }
    private static byte[] bytes(Map value, int key) { return ((ByteString) field(value, key)).getBytes(); }
    private static byte[] id(Map response) {
        return ((ByteString) field((Map) field(response, 1), "id")).getBytes();
    }
    private static Map descriptor(byte[] id) {
        Map value = new Map();
        value.put(new UnicodeString("id"), new ByteString(id));
        value.put(new UnicodeString("type"), new UnicodeString("public-key"));
        return value;
    }
    private static Map make(String rpId, byte[] user, boolean rk) {
        Map root = new Map();
        root.put(new UnsignedInteger(1), new ByteString(HASH));
        Map rp = new Map(); rp.put(new UnicodeString("id"), new UnicodeString(rpId));
        root.put(new UnsignedInteger(2), rp);
        Map account = new Map();
        account.put(new UnicodeString("id"), new ByteString(user));
        account.put(new UnicodeString("name"), new UnicodeString("private@example.invalid"));
        account.put(new UnicodeString("displayName"), new UnicodeString("Private Person"));
        root.put(new UnsignedInteger(3), account);
        Array algorithms = new Array();
        Map algorithm = new Map();
        algorithm.put(new UnicodeString("alg"), new NegativeInteger(-7));
        algorithm.put(new UnicodeString("type"), new UnicodeString("public-key"));
        algorithms.add(algorithm);
        root.put(new UnsignedInteger(4), algorithms);
        Map options = new Map(); options.put(new UnicodeString("rk"), rk ? SimpleValue.TRUE : SimpleValue.FALSE);
        root.put(new UnsignedInteger(7), options);
        return root;
    }
    private static Map get(String rpId, byte[]... allowed) {
        Map root = new Map();
        root.put(new UnsignedInteger(1), new UnicodeString(rpId));
        root.put(new UnsignedInteger(2), new ByteString(HASH));
        if (allowed != null) {
            Array list = new Array();
            for (byte[] credential : allowed) list.add(descriptor(credential));
            root.put(new UnsignedInteger(3), list);
        }
        return root;
    }
    private Credential seed(String rpId, int user, boolean rk, long timestamp) {
        Credential c = ImmutableCredential.builder().relayingPartyId(rpId)
                .creation(Instant.ofEpochMilli(timestamp)).userId(new byte[]{(byte) user})
                .keyPair(P256AttestationKeyPair.generate()).signatureCount(0)
                .discoverable(rk).userName("private").userDisplayName("Secret Name").build();
        config.addCredential(c);
        return c;
    }
    private void seedThree() {
        seed(RP, 1, true, 1000); seed(RP, 2, true, 2000); seed(RP, 3, true, 3000);
    }
    private Credential stored(byte[] id) {
        return config.credentials().stream().filter(c -> Arrays.equals(id, c.id())).findFirst().get();
    }
    private static void verifySignature(Map response, Credential c, byte[] hash) throws Exception {
        byte[] data = bytes(response, 2);
        assertArrayEquals(MessageDigest.getInstance("SHA-256").digest(
                c.relayingPartyId().getBytes(StandardCharsets.UTF_8)), Arrays.copyOf(data, 32));
        assertEquals("UV must not be claimed", 0, data[32] & 4);
        Signature verify = Signature.getInstance("SHA256withECDSA", new BouncyCastleProvider());
        verify.initVerify(KeyFactory.getInstance("EC", new BouncyCastleProvider())
                .generatePublic(new X509EncodedKeySpec(c.keyPair().publicKey())));
        verify.update(data); verify.update(hash);
        assertTrue(verify.verify(bytes(response, 3)));
    }

    @Test public void realRegistrationPersistsUserMetadataAndValidAttestation() throws Exception {
        byte[] user = {6, 7, 8};
        Map attestation = body(call(1, make(RP, user, true)));
        assertEquals(1, config.credentials().size());
        Credential c = config.credentials().get(0);
        assertTrue(c.discoverable());
        assertEquals("private@example.invalid", c.userName());
        assertEquals("Private Person", c.userDisplayName());
        assertArrayEquals(user, c.userId());
        byte[] data = bytes(attestation, 2);
        assertArrayEquals(c.id(), Arrays.copyOfRange(data, 55, 55 + c.id().length));
        Map statement = (Map) field(attestation, 3);
        Signature verify = Signature.getInstance("SHA256withECDSA", new BouncyCastleProvider());
        verify.initVerify(KeyFactory.getInstance("EC", new BouncyCastleProvider()).generatePublic(
                new X509EncodedKeySpec(c.keyPair().publicKey())));
        verify.update(data); verify.update(HASH);
        assertTrue(verify.verify(((ByteString) field(statement, "sig")).getBytes()));
        String identity = config.id().toString();
        reload(true);
        assertEquals(identity, config.id().toString());
        assertArrayEquals(c.id(), config.credentials().get(0).id());
        Map assertion = body(call(2, get(RP, (byte[][]) null)));
        verifySignature(assertion, c, HASH);
    }

    @Test public void omittedAndEmptyAllowListsDiscoverOnlyResidentKeys() throws Exception {
        Credential resident = seed(RP, 1, true, 1);
        seed(RP, 2, false, 2);
        seed(OTHER_RP, 3, true, 3);
        for (Map request : Arrays.asList(get(RP, (byte[][]) null), get(RP))) {
            Map response = body(call(2, request));
            assertArrayEquals(resident.id(), id(response));
            assertNull(field(response, 5));
            Map user = (Map) field(response, 4);
            assertArrayEquals(resident.userId(), ((ByteString) field(user, "id")).getBytes());
            assertNull(field(user, "name")); assertNull(field(user, "displayName"));
            verifySignature(response, resident, HASH);
        }
        assertEquals(2, stored(resident.id()).signatureCount());
        assertArrayEquals(new byte[]{0x2e}, call(2, get("missing.invalid", (byte[][]) null)));
    }

    @Test public void legacyCredentialStillNeedsExplicitIdAndDoesNotExposeUser() throws Exception {
        Credential legacy = seed(RP, 1, false, 1000);
        assertArrayEquals(new byte[]{0x2e}, call(2, get(RP, (byte[][]) null)));
        assertEquals(0, stored(legacy.id()).signatureCount());
        Map response = body(call(2, get(RP, legacy.id())));
        assertNull(field(response, 4)); assertNull(field(response, 5));
        verifySignature(response, legacy, HASH);
        assertArrayEquals(new byte[]{0x2e}, call(2, get(OTHER_RP, legacy.id())));
    }

    @Test public void multipleAccountsUseNewestFirstCountOnlyOnFirstAndDistinctSignatures() throws Exception {
        seedThree();
        List<byte[]> seen = new ArrayList<>();
        Map response = body(call(2, get(RP, (byte[][]) null)));
        assertEquals(3, ((UnsignedInteger) field(response, 5)).getValue().intValue());
        for (int expectedUser = 3; expectedUser >= 1; expectedUser--) {
            if (expectedUser < 3) {
                response = body(call(8, null));
                assertNull(field(response, 5));
            }
            Credential current = stored(id(response));
            assertArrayEquals(new byte[]{(byte) expectedUser}, current.userId());
            verifySignature(response, current, HASH);
            assertEquals(1, current.signatureCount());
            for (byte[] previous : seen) assertFalse(Arrays.equals(previous, current.id()));
            seen.add(current.id());
            assertEquals(1, ByteBuffer.wrap(bytes(response, 2), 33, 4).getInt());
        }
        assertArrayEquals(new byte[]{0x30}, call(8, null));
        assertArrayEquals(new byte[]{0x30}, call(8, null));
    }

    @Test public void explicitListChoosesOneCredentialWithoutEnumeration() throws Exception {
        Credential first = seed(RP, 1, true, 1);
        Credential second = seed(RP, 2, true, 2);
        Map response = body(call(2, get(RP, first.id(), second.id())));
        assertNull(field(response, 5));
        assertNotNull(field(response, 4));
        assertArrayEquals(new byte[]{0x30}, call(8, null));
    }

    @Test public void anotherChannelCannotContinueOrStealTheFirstChannelsSequence() throws Exception {
        seedThree(); body(call(2, get(RP, (byte[][]) null)));
        assertArrayEquals(new byte[]{0x30}, call(OTHER_CID, 8, null));
        assertArrayEquals(new byte[]{0x30}, call(8, null));
        assertEquals(1, config.credentials().stream().mapToInt(Credential::signatureCount).sum());
    }

    @Test public void timeoutsUseMonotonicTimeAndResetAfterEachSuccessfulResponse() throws Exception {
        seedThree(); body(call(2, get(RP, (byte[][]) null)));
        time.addAndGet(TimeUnit.SECONDS.toNanos(29)); body(call(8, null));
        time.addAndGet(TimeUnit.SECONDS.toNanos(29)); body(call(8, null));
        body(call(2, get(RP, (byte[][]) null)));
        time.addAndGet(TimeUnit.SECONDS.toNanos(30) + 1);
        assertArrayEquals(new byte[]{0x30}, call(8, null));
    }

    @Test public void newCommandMalformedRequestAndUnknownCommandInvalidateSequence() throws Exception {
        seedThree();
        body(call(2, get(RP, (byte[][]) null))); body(call(4, null));
        assertArrayEquals(new byte[]{0x30}, call(8, null));
        body(call(2, get(RP, (byte[][]) null)));
        assertArrayEquals(new byte[]{0x12}, call(2, new Map()));
        assertArrayEquals(new byte[]{0x30}, call(8, null));
        body(call(2, get(RP, (byte[][]) null)));
        assertArrayEquals(new byte[]{1}, call(0x7e, null));
        assertArrayEquals(new byte[]{0x30}, call(8, null));
    }

    @Test public void nextAssertionMustNotAcceptParameters() throws Exception {
        seedThree(); body(call(2, get(RP, (byte[][]) null)));
        assertArrayEquals(new byte[]{0x12}, call(8, new Map()));
        assertArrayEquals(new byte[]{0x30}, call(8, null));
    }

    @Test public void newRequestReplacesOldRpAndChallengeContext() throws Exception {
        seedThree(); seed(OTHER_RP, 9, true, 4);
        body(call(2, get(RP, (byte[][]) null)));
        Map other = get(OTHER_RP, (byte[][]) null);
        byte[] challenge = new byte[32]; Arrays.fill(challenge, (byte) 7);
        other.put(new UnsignedInteger(2), new ByteString(challenge));
        Map response = body(call(OTHER_CID, 2, other));
        verifySignature(response, stored(id(response)), challenge);
        assertArrayEquals(new byte[]{0x30}, call(8, null));
    }

    @Test public void processReconstructionDoesNotRestorePendingEnumeration() throws Exception {
        seedThree(); body(call(2, get(RP, (byte[][]) null)));
        reload(true);
        assertArrayEquals(new byte[]{0x30}, call(8, null));
        assertEquals(3, ((UnsignedInteger) field(body(call(2, get(RP))), 5)).getValue().intValue());
    }

    @Test public void reregistrationReplacesOnlySameRpUserResidentCredential() throws Exception {
        byte[] user = {1};
        body(call(1, make(RP, user, false)));
        Credential legacy = config.credentials().get(0);
        body(call(1, make(RP, user, true)));
        Credential previous = config.credentials().get(1);
        body(call(1, make(OTHER_RP, user, true)));
        Credential unrelated = config.credentials().get(2);
        body(call(1, make(RP, user, true)));
        assertEquals(3, config.credentials().size());
        assertArrayEquals(legacy.id(), stored(legacy.id()).id());
        assertArrayEquals(unrelated.id(), stored(unrelated.id()).id());
        assertFalse(config.credentials().stream().anyMatch(c -> Arrays.equals(c.id(), previous.id())));
        assertArrayEquals(new byte[]{0x2e}, call(2, get(RP, previous.id())));
        verifySignature(body(call(2, get(RP, legacy.id()))), legacy, HASH);
    }

    @Test public void excludeListPreventsReplacementWithoutChangingDisk() throws Exception {
        body(call(1, make(RP, new byte[]{1}, true)));
        Credential existing = config.credentials().get(0);
        byte[] original = AtomicStateFile.read(statePath);
        Map request = make(RP, new byte[]{1}, true);
        Array excluded = new Array(); excluded.add(descriptor(existing.id()));
        request.put(new UnsignedInteger(5), excluded);
        assertArrayEquals(new byte[]{0x19}, call(1, request));
        assertArrayEquals(original, AtomicStateFile.read(statePath));
    }

    @Test public void deniedStorageCannotCreateResidentKeyOrReplaceExistingOne() throws Exception {
        seed(RP, 1, true, 1);
        byte[] original = AtomicStateFile.read(statePath);
        Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("r-x------"));
        try {
            try { call(1, make(RP, new byte[]{1}, true)); fail("Storage failure accepted"); }
            catch (IllegalStateException expected) { assertNotNull(expected.getCause()); }
        } finally {
            Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx------"));
        }
        assertArrayEquals(original, AtomicStateFile.read(statePath));
        assertEquals(1, config.credentials().size());
        assertEquals(1, config.credentials().get(0).creation().toEpochMilli());
    }

    @Test public void failedContinuationDoesNotAdvanceCounterAndClearsPendingState() throws Exception {
        seedThree(); body(call(2, get(RP, (byte[][]) null)));
        byte[] original = AtomicStateFile.read(statePath);
        Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("r-x------"));
        try {
            try { call(8, null); fail("Uncommitted signature returned"); }
            catch (IllegalStateException expected) { assertNotNull(expected.getCause()); }
        } finally {
            Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx------"));
        }
        assertArrayEquals(original, AtomicStateFile.read(statePath));
        assertArrayEquals(new byte[]{0x30}, call(8, null));
        assertEquals(1, config.credentials().stream().mapToInt(Credential::signatureCount).sum());
    }

    @Test public void capacityIsBoundedButReplacementAtCapacityStillWorks() throws Exception {
        List<Credential> full = new ArrayList<>();
        // Reuse one synthetic keypair here: this tests capacity, not key generation.
        P256AttestationKeyPair keys = P256AttestationKeyPair.generate();
        for (int i = 0; i < CredentialStore.MAX_DISCOVERABLE_CREDENTIALS; i++) {
            full.add(ImmutableCredential.builder().relayingPartyId(RP).userId(new byte[]{(byte) i})
                    .keyPair(keys).creation(Instant.ofEpochMilli(i)).signatureCount(0)
                    .discoverable(true).build());
        }
        config.updateAllStoredCredentials(full);
        byte[] before = AtomicStateFile.read(statePath);
        assertArrayEquals(new byte[]{0x28}, call(1, make(RP, new byte[]{99, 99}, true)));
        assertArrayEquals(before, AtomicStateFile.read(statePath));
        body(call(1, make(RP, new byte[]{1}, true)));
        assertEquals(128, config.credentials().size());
    }

    @Test public void experimentalCapabilityIsConsistentAndDisabledByDefault() throws Exception {
        Map options = (Map) field(body(call(4, null)), 4);
        assertEquals(SimpleValue.TRUE, field(options, "rk"));
        reload(false);
        options = (Map) field(body(call(4, null)), 4);
        assertEquals(SimpleValue.FALSE, field(options, "rk"));
        assertArrayEquals(new byte[]{0x2b}, call(1, make(RP, new byte[]{1}, true)));
    }

    @Test public void invalidVerificationNeverCreatesAResidentCredential() throws Exception {
        Map request = make(RP, new byte[]{1}, true);
        ((Map) field(request, 7)).put(new UnicodeString("uv"), SimpleValue.TRUE);
        assertArrayEquals(new byte[]{0x2b}, call(1, request));
        request = make(RP, new byte[]{1}, true);
        request.put(new UnsignedInteger(8), new ByteString(new byte[16]));
        request.put(new UnsignedInteger(9), new UnsignedInteger(1));
        assertArrayEquals(new byte[]{0x33}, call(1, request));
        assertTrue(config.credentials().isEmpty());
    }

    @Test public void emptyPinSelectionProbeDoesNotLeaveDummyCredential() throws Exception {
        Map request = make(".dummy", new byte[]{1}, false);
        request.put(new UnsignedInteger(8), new ByteString(new byte[0]));
        request.put(new UnsignedInteger(9), new UnsignedInteger(1));
        assertArrayEquals(new byte[]{0x35}, call(1, request));
        assertTrue(config.credentials().isEmpty());
    }

    @Test public void hidCancelAndInitDiscardContinuationWithoutCancelReply() throws Exception {
        seedThree();
        UsbHidRequestHandler hid = new UsbHidRequestHandler(handler);
        RawMessage init = hid.handle(ImmutableRawMessage.of(ChannelId.broadcast(), HidCommand.INIT, new byte[8]));
        ChannelId channel = ImmutableChannelId.of(Arrays.copyOfRange(init.payload(), 8, 12));
        body(hid.handle(ImmutableRawMessage.of(channel, HidCommand.CBOR,
                command(2, get(RP, (byte[][]) null)))).payload());
        assertNull(hid.handle(ImmutableRawMessage.of(channel, HidCommand.CANCEL, new byte[0])));
        assertArrayEquals(new byte[]{0x30}, hid.handle(ImmutableRawMessage.of(channel, HidCommand.CBOR,
                new byte[]{8})).payload());
        body(hid.handle(ImmutableRawMessage.of(channel, HidCommand.CBOR,
                command(2, get(RP, (byte[][]) null)))).payload());
        hid.handle(ImmutableRawMessage.of(channel, HidCommand.INIT, new byte[8]));
        assertArrayEquals(new byte[]{0x30}, hid.handle(ImmutableRawMessage.of(channel, HidCommand.CBOR,
                new byte[]{8})).payload());
    }
}

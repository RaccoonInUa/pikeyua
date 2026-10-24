package com.github.mphi_rc.fido2.protocol.ctap2;

import static org.junit.Assert.*;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Arrays;
import java.util.Collections;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import com.github.mphi_rc.fido2.AtomicStateFile;
import com.github.mphi_rc.fido2.ConfigurationFile;
import com.github.mphi_rc.fido2.authenticator.Authenticator;
import com.github.mphi_rc.fido2.authenticator.ConfigurationCredentialStore;
import com.github.mphi_rc.fido2.authenticator.Credential;
import com.github.mphi_rc.fido2.authenticator.PinState;
import com.github.mphi_rc.fido2.authenticator.crypto.P256AttestationKeyPair;
import com.github.mphi_rc.fido2.protocol.ctap2.pin.PinRequestHandler;
import com.github.mphi_rc.fido2.protocol.usbhid.ImmutableChannelId;
import com.github.mphi_rc.fido2.protocol.usbhid.RawMessage;

import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.NegativeInteger;
import co.nstant.in.cbor.model.SimpleValue;
import co.nstant.in.cbor.model.UnicodeString;
import co.nstant.in.cbor.model.UnsignedInteger;

/** CBOR fixtures and fail-closed execution tests for V7.2 protocol stage B. */
public class CtapRequestParsingTest {
    @Rule public TemporaryFolder folder = new TemporaryFolder();

    private static final byte[] HASH = new byte[32];
    private static final String RP = "ctap.example.invalid";

    private static Map user() {
        Map user = new Map();
        user.put(new UnicodeString("id"), new ByteString(new byte[]{ 1, 2, 3 }));
        user.put(new UnicodeString("name"), new UnicodeString("user@ctap.invalid"));
        user.put(new UnicodeString("displayName"), new UnicodeString("Test Account"));
        return user;
    }

    private static Map baseMake() {
        Map root = new Map();
        root.put(new UnsignedInteger(1), new ByteString(HASH));
        Map rp = new Map();
        rp.put(new UnicodeString("id"), new UnicodeString(RP));
        root.put(new UnsignedInteger(2), rp);
        root.put(new UnsignedInteger(3), user());
        Array algorithms = new Array();
        Map entry = new Map();
        entry.put(new UnicodeString("type"), new UnicodeString("public-key"));
        entry.put(new UnicodeString("alg"), new NegativeInteger(-7));
        algorithms.add(entry);
        root.put(new UnsignedInteger(4), algorithms);
        return root;
    }

    private static Map descriptor(byte[] id) {
        Map descriptor = new Map();
        descriptor.put(new UnicodeString("type"), new UnicodeString("public-key"));
        descriptor.put(new UnicodeString("id"), new ByteString(id));
        return descriptor;
    }

    private static Map baseAssertion() {
        Map root = new Map();
        root.put(new UnsignedInteger(1), new UnicodeString(RP));
        root.put(new UnsignedInteger(2), new ByteString(HASH));
        return root;
    }

    private static byte[] encode(Map root) throws CborException {
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        new CborEncoder(result).encode(Collections.<DataItem>singletonList(root));
        return result.toByteArray();
    }

    private static byte[] cmd(byte command, Map request) throws CborException {
        byte[] encoded = encode(request);
        byte[] out = new byte[encoded.length + 1];
        out[0] = command;
        System.arraycopy(encoded, 0, out, 1, encoded.length);
        return out;
    }

    private static void invalidMake(Map root) {
        try {
            MakeCredentialRequest.fromBytes(encode(root));
            fail("Malformed MakeCredential request accepted");
        } catch (CborException expected) {
            assertNotNull(expected.getMessage());
        }
    }

    private static void invalidAssertion(Map root) {
        try {
            GetAssertionRequest.fromBytes(encode(root));
            fail("Malformed GetAssertion request accepted");
        } catch (CborException expected) {
            assertNotNull(expected.getMessage());
        }
    }

    @Test public void makeCredentialParsesRkMetadataAndExcludeList() throws Exception {
        Map root = baseMake();
        Array excluded = new Array();
        excluded.add(descriptor(new byte[]{ 5, 6, 7 }));
        root.put(new UnsignedInteger(5), excluded);
        Map options = new Map();
        options.put(new UnicodeString("rk"), SimpleValue.TRUE);
        options.put(new UnicodeString("uv"), SimpleValue.FALSE);
        root.put(new UnsignedInteger(7), options);
        MakeCredentialRequest request = MakeCredentialRequest.fromBytes(encode(root));
        assertTrue(request.residentKeyRequested());
        assertFalse(request.userVerificationRequested());
        assertFalse(request.upOptionPresent());
        assertEquals("user@ctap.invalid", request.userName());
        assertEquals("Test Account", request.userDisplayName());
        assertEquals(1, request.excludedCredentialIds().size());
        assertArrayEquals(new byte[]{ 5, 6, 7 }, request.excludedCredentialIds().get(0));
        assertTrue(request.supportedAlgorithmIds().contains(-7));
    }

    @Test public void makeCredentialDefaultsToNonResidentAndRejectsInvalidValues() throws Exception {
        MakeCredentialRequest normal = MakeCredentialRequest.fromBytes(encode(baseMake()));
        assertFalse(normal.residentKeyRequested());
        assertTrue(normal.excludedCredentialIds().isEmpty());
        Map malformed = baseMake();
        Map options = new Map();
        options.put(new UnicodeString("rk"), new UnicodeString("true"));
        malformed.put(new UnsignedInteger(7), options);
        invalidMake(malformed);

        Map malformedDescriptor = baseMake();
        Array excluded = new Array();
        excluded.add(new UnicodeString("not-a-descriptor"));
        malformedDescriptor.put(new UnsignedInteger(5), excluded);
        invalidMake(malformedDescriptor);

        Map badHash = baseMake();
        badHash.put(new UnsignedInteger(1), new ByteString(new byte[1]));
        invalidMake(badHash);
    }

    @Test public void assertionDistinguishesMissingEmptyAndPresentAllowList() throws Exception {
        Map absent = baseAssertion();
        GetAssertionRequest notSupplied = GetAssertionRequest.fromBytes(encode(absent));
        assertFalse(notSupplied.allowListPresent());
        assertTrue(notSupplied.publicKeyIds().isEmpty());

        Map empty = baseAssertion();
        empty.put(new UnsignedInteger(3), new Array());
        GetAssertionRequest suppliedEmpty = GetAssertionRequest.fromBytes(encode(empty));
        assertTrue(suppliedEmpty.allowListPresent());
        assertTrue(suppliedEmpty.publicKeyIds().isEmpty());

        Map provided = baseAssertion();
        Array ids = new Array();
        ids.add(descriptor(new byte[]{ 0x0a, 0x0b }));
        provided.put(new UnsignedInteger(3), ids);
        GetAssertionRequest parsed = GetAssertionRequest.fromBytes(encode(provided));
        assertTrue(parsed.allowListPresent());
        assertEquals(1, parsed.publicKeyIds().size());
        assertArrayEquals(new byte[]{ 0x0a, 0x0b }, parsed.publicKeyIds().get(0));
    }

    @Test public void assertionRejectsInvalidDescriptorsAndOptions() throws Exception {
        Map malformed = baseAssertion();
        malformed.put(new UnsignedInteger(3), new UnicodeString("not an array"));
        invalidAssertion(malformed);

        Map malformedId = baseAssertion();
        Array list = new Array();
        Map item = descriptor(new byte[]{ 1 });
        item.put(new UnicodeString("id"), new UnicodeString("string not bytes"));
        list.add(item);
        malformedId.put(new UnsignedInteger(3), list);
        invalidAssertion(malformedId);

        Map invalidBoolean = baseAssertion();
        Map options = new Map();
        options.put(new UnicodeString("uv"), new UnicodeString("yes"));
        invalidBoolean.put(new UnsignedInteger(5), options);
        invalidAssertion(invalidBoolean);
    }

    private ConfigurationFile config() throws Exception {
        Path dir = folder.newFolder("private").toPath();
        Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx------"));
        ConfigurationFile state = new ConfigurationFile(dir.resolve("config.json"));
        state.persistToDisk();
        return state;
    }

    private static AuthenticatorRequestHandler handler(ConfigurationFile state) {
        PinState pin = new PinState(state);
        Authenticator authenticator = new Authenticator(state,
                new ConfigurationCredentialStore(state), pin);
        return new AuthenticatorRequestHandler(authenticator, new PinRequestHandler(pin));
    }

    private static byte[] answer(AuthenticatorRequestHandler handler, byte command, Map map)
            throws Exception {
        RawMessage result = handler.handleCborRequest(
                ImmutableChannelId.of(new byte[]{ 1, 2, 3, 4 }), cmd(command, map));
        return result.payload();
    }

    @Test public void rkRequestedIsGatedAndCannotMutateState() throws Exception {
        ConfigurationFile state = config();
        int before = state.credentials().size();
        Map request = baseMake();
        Map options = new Map();
        options.put(new UnicodeString("rk"), SimpleValue.TRUE);
        request.put(new UnsignedInteger(7), options);
        byte[] response = answer(handler(state), (byte) 0x01, request);
        assertArrayEquals(new byte[]{ 0x2b }, response); // UNSUPPORTED_OPTION, raw CTAP status
        assertEquals(before, state.credentials().size());
    }

    @Test public void existingCredentialIsExcludedBeforeCreatingNewKey() throws Exception {
        ConfigurationFile state = config();
        Credential already = new ConfigurationCredentialStore(state).saveCredential(
                RP, new byte[]{ 1, 2, 3 }, P256AttestationKeyPair.generate());
        byte[] before = AtomicStateFile.read(
                folder.getRoot().toPath().resolve("private").resolve("config.json"));
        Map request = baseMake();
        Array excluded = new Array();
        excluded.add(descriptor(already.id()));
        request.put(new UnsignedInteger(5), excluded);
        assertArrayEquals(new byte[]{ 0x19 },
                answer(handler(state), (byte) 0x01, request));
        assertEquals(1, state.credentials().size());
        assertArrayEquals(before, AtomicStateFile.read(
                folder.getRoot().toPath().resolve("private").resolve("config.json")));
    }

    @Test public void noAllowListCannotLeakLegacyCredential() throws Exception {
        ConfigurationFile state = config();
        new ConfigurationCredentialStore(state).saveCredential(
                RP, new byte[]{ 1 }, P256AttestationKeyPair.generate());
        assertArrayEquals(new byte[]{ 0x2e },
                answer(handler(state), (byte) 0x02, baseAssertion()));
        assertEquals(1, state.credentials().size());
    }

    @Test public void invalidPinAuthCannotCreateCredential() throws Exception {
        ConfigurationFile state = config();
        Map request = baseMake();
        request.put(new UnsignedInteger(8), new ByteString(new byte[16]));
        // PIN auth with an invalid token must be checked before persistence.
        assertArrayEquals(new byte[]{ 0x33 },
                answer(handler(state), (byte) 0x01, request));
        assertEquals(0, state.credentials().size());
    }

    @Test public void suppliedUvOptionMustFailWithoutNewCredential() throws Exception {
        ConfigurationFile state = config();
        Map request = baseMake();
        Map options = new Map();
        options.put(new UnicodeString("uv"), SimpleValue.TRUE);
        request.put(new UnsignedInteger(7), options);
        assertArrayEquals(new byte[]{ 0x2b }, answer(handler(state), (byte) 0x01, request));
        assertEquals(0, state.credentials().size());
    }
    @Test public void upOptionInMakeCredentialRejectedWithoutStateMutation() throws Exception {
        ConfigurationFile state = config();
        Map request = baseMake();
        Map options = new Map();
        options.put(new UnicodeString("up"), SimpleValue.TRUE);
        request.put(new UnsignedInteger(7), options);
        assertArrayEquals(new byte[]{ 0x2c },
                answer(handler(state), (byte) 0x01, request));
        assertEquals(0, state.credentials().size());
    }

    @Test public void exclusionDoesNotExposeCredentialsOwnedByAnotherRp() throws Exception {
        ConfigurationFile state = config();
        Credential other = new ConfigurationCredentialStore(state).saveCredential(
                "other.example.invalid", new byte[]{ 5 }, P256AttestationKeyPair.generate());
        Map request = baseMake();
        Array ids = new Array();
        ids.add(descriptor(other.id()));
        request.put(new UnsignedInteger(5), ids);
        byte[] result = answer(handler(state), (byte) 0x01, request);
        assertEquals(0, result[0]); // Ordinary non-RK credential created.
        assertEquals(2, state.credentials().size());
    }

    @Test public void requestedAssertionUvCannotSucceedOrAdvanceCounter() throws Exception {
        ConfigurationFile state = config();
        Credential existing = new ConfigurationCredentialStore(state).saveCredential(
                RP, new byte[]{ 1 }, P256AttestationKeyPair.generate());
        Map assertion = baseAssertion();
        Array ids = new Array();
        ids.add(descriptor(existing.id()));
        assertion.put(new UnsignedInteger(3), ids);
        Map options = new Map();
        options.put(new UnicodeString("uv"), SimpleValue.TRUE);
        assertion.put(new UnsignedInteger(5), options);
        assertArrayEquals(new byte[]{ 0x2b },
                answer(handler(state), (byte) 0x02, assertion));
        assertEquals(0, state.credentials().get(0).signatureCount());
    }

    @Test public void metadataCannotEnableUnimplementedDiscovery() throws Exception {
        ConfigurationFile state = config();
        Credential existing = new ConfigurationCredentialStore(state).saveCredential(
                RP, new byte[]{ 1 }, P256AttestationKeyPair.generate());
        Credential flagged = com.github.mphi_rc.fido2.authenticator.ImmutableCredential.builder()
                .from(existing).discoverable(true).build();
        state.updateAllStoredCredentials(Collections.singletonList(flagged));
        assertArrayEquals(new byte[]{ 0x2e },
                answer(handler(state), (byte) 0x02, baseAssertion()));
        assertEquals(0, state.credentials().get(0).signatureCount());
    }

}

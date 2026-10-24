package com.github.mphi_rc.fido2;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import com.github.mphi_rc.fido2.authenticator.*;
import com.github.mphi_rc.fido2.protocol.ctap2.*;
import com.github.mphi_rc.fido2.protocol.ctap2.pin.PinRequestHandler;
import com.github.mphi_rc.fido2.protocol.usbhid.*;
import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.model.*;

/** Isolated real CTAP request lifecycle across three JVMs, never USB or live state. */
public final class ResidentCredentialProbe {
    private static final String RP = "rk-probe.invalid";
    private static final String OTHER = "other-probe.invalid";
    private static final byte[] HASH = new byte[32];
    private static final ChannelId CHANNEL = ImmutableChannelId.of(new byte[]{1, 3, 5, 7});
    private ResidentCredentialProbe() { }

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            lifecycle();
            return;
        }
        if (args.length != 2 || !Arrays.asList("create", "verify-1", "verify-2").contains(args[0])) {
            throw new IllegalArgumentException("Run ResidentCredentialProbe without arguments");
        }
        Path directory = Paths.get(args[1]).toAbsolutePath().normalize();
        check(directory.getFileName().toString().startsWith("pikeyua-rk-probe-"), "Not a probe directory");
        check(Files.isRegularFile(directory.resolve("probe-marker")), "Missing probe marker");
        check(Files.getPosixFilePermissions(directory).equals(
                PosixFilePermissions.fromString("rwx------")), "Probe directory must be private");
        Path state = directory.resolve("config.json");
        Path baseline = directory.resolve("expected-fingerprint");
        if (args[0].equals("create")) check(!Files.exists(state), "State already exists");
        else check(Files.isRegularFile(state), "Expected existing state");
        ConfigurationFile config = new ConfigurationFile(state);
        PinState pin = new PinState(config);
        Authenticator auth = new Authenticator(config, new ConfigurationCredentialStore(config), pin,
                true, System::nanoTime);
        AuthenticatorRequestHandler handler = new AuthenticatorRequestHandler(auth, new PinRequestHandler(pin));
        if (args[0].equals("create")) {
            config.persistToDisk();
            ok(handler, 1, make(RP, 1, false));
            ok(handler, 1, make(RP, 2, true));
            ok(handler, 1, make(RP, 3, true));
            ok(handler, 1, make(OTHER, 4, true));
            check(config.credentials().size() == 4, "Wrong registration count");
            AtomicStateFile.write(baseline, fingerprint(config).getBytes(StandardCharsets.US_ASCII));
        } else {
            int expected = args[0].equals("verify-1") ? 0 : 1;
            check(config.credentials().size() == 4, "Credential lost on reload");
            check(fingerprint(config).equals(new String(AtomicStateFile.read(baseline),
                    StandardCharsets.US_ASCII)), "AAGUID, credential IDs or key bytes changed");
            for (Credential c : config.credentials()) check(c.signatureCount() == expected, "Counter not restored");
            check(Arrays.equals(new byte[]{0x30}, call(handler, 8, null)), "Pending sequence survived process exit");
            Map first = ok(handler, 2, get(RP, null));
            check(((UnsignedInteger) first.get(new UnsignedInteger(5))).getValue().intValue() == 2,
                    "Discovery count includes a legacy or different-RP credential");
            Set<String> seen = new HashSet<>();
            for (int i = 0; i < 2; i++) {
                Map response = i == 0 ? first : ok(handler, 8, null);
                if (i > 0) check(response.get(new UnsignedInteger(5)) == null, "Count repeated on continuation");
                byte[] id = responseId(response);
                Credential c = config.credentials().stream().filter(v -> Arrays.equals(v.id(), id)).findFirst().get();
                check(c.discoverable() && c.relayingPartyId().equals(RP), "Discovery scope violated");
                check(seen.add(Base64.getEncoder().encodeToString(id)), "Duplicate assertion");
                verify(response, c, expected + 1);
            }
            check(Arrays.equals(new byte[]{0x30}, call(handler, 8, null)), "Exhausted sequence accepted");
            Credential legacy = config.credentials().stream().filter(c -> !c.discoverable()).findFirst().get();
            verify(ok(handler, 2, get(RP, legacy.id())), legacy, expected + 1);
            check(Arrays.equals(new byte[]{0x2e}, call(handler, 2, get(OTHER, legacy.id()))), "Cross-RP assertion leaked");
            Credential other = config.credentials().stream().filter(c -> c.relayingPartyId().equals(OTHER)).findFirst().get();
            verify(ok(handler, 2, get(OTHER, null)), other, expected + 1);
            for (Credential c : new ConfigurationFile(state).credentials()) {
                check(c.signatureCount() == expected + 1, "Counter update not durable");
            }
        }
        System.out.println("PASS: resident-credential " + args[0]);
    }

    private static void lifecycle() throws Exception {
        Path directory = Files.createTempDirectory("pikeyua-rk-probe-",
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        try {
            AtomicStateFile.write(directory.resolve("probe-marker"), new byte[]{1});
            for (String phase : Arrays.asList("create", "verify-1", "verify-2")) {
                Process child = new ProcessBuilder(Paths.get(System.getProperty("java.home"), "bin", "java").toString(),
                        "-cp", System.getProperty("java.class.path"), ResidentCredentialProbe.class.getName(),
                        phase, directory.toString()).inheritIO().start();
                if (!child.waitFor(180, TimeUnit.SECONDS)) {
                    child.destroyForcibly(); child.waitFor();
                    throw new IllegalStateException("Probe phase timed out");
                }
                check(child.exitValue() == 0, "Probe child failed: " + phase);
            }
            System.out.println("PASS: RK creation, RP-scoped discovery, GetNextAssertion, signatures and counters across independent JVMs");
        } finally {
            try (Stream<Path> paths = Files.walk(directory)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).collect(Collectors.toList())) {
                    Files.deleteIfExists(path);
                }
            }
        }
    }

    private static Map make(String rpId, int userId, boolean rk) {
        Map root = new Map(); root.put(new UnsignedInteger(1), new ByteString(HASH));
        Map rp = new Map(); rp.put(new UnicodeString("id"), new UnicodeString(rpId));
        root.put(new UnsignedInteger(2), rp);
        Map user = new Map(); user.put(new UnicodeString("id"), new ByteString(new byte[]{(byte) userId}));
        user.put(new UnicodeString("name"), new UnicodeString("synthetic-user"));
        root.put(new UnsignedInteger(3), user);
        Map algorithm = new Map(); algorithm.put(new UnicodeString("type"), new UnicodeString("public-key"));
        algorithm.put(new UnicodeString("alg"), new NegativeInteger(-7));
        Array algorithms = new Array(); algorithms.add(algorithm);
        root.put(new UnsignedInteger(4), algorithms);
        Map options = new Map(); options.put(new UnicodeString("rk"), rk ? SimpleValue.TRUE : SimpleValue.FALSE);
        root.put(new UnsignedInteger(7), options); return root;
    }
    private static Map get(String rpId, byte[] allowed) {
        Map root = new Map(); root.put(new UnsignedInteger(1), new UnicodeString(rpId));
        root.put(new UnsignedInteger(2), new ByteString(HASH));
        if (allowed != null) {
            Map descriptor = new Map(); descriptor.put(new UnicodeString("id"), new ByteString(allowed));
            descriptor.put(new UnicodeString("type"), new UnicodeString("public-key"));
            Array list = new Array(); list.add(descriptor); root.put(new UnsignedInteger(3), list);
        }
        return root;
    }
    private static byte[] call(AuthenticatorRequestHandler handler, int command, Map params) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream(); out.write(command);
        if (params != null) new CborEncoder(out).encode(Collections.<DataItem>singletonList(params));
        return handler.handleCborRequest(CHANNEL, out.toByteArray()).payload();
    }
    private static Map ok(AuthenticatorRequestHandler handler, int command, Map params) throws Exception {
        byte[] response = call(handler, command, params);
        check(response[0] == 0, "CTAP operation failed");
        return (Map) CborDecoder.decode(Arrays.copyOfRange(response, 1, response.length)).get(0);
    }
    private static byte[] responseId(Map response) {
        Map descriptor = (Map) response.get(new UnsignedInteger(1));
        return ((ByteString) descriptor.get(new UnicodeString("id"))).getBytes();
    }
    private static void verify(Map response, Credential credential, int counter) throws Exception {
        byte[] data = ((ByteString) response.get(new UnsignedInteger(2))).getBytes();
        check(Arrays.equals(responseId(response), credential.id()), "Wrong credential");
        check(Arrays.equals(Arrays.copyOf(data, 32), MessageDigest.getInstance("SHA-256")
                .digest(credential.relayingPartyId().getBytes(StandardCharsets.UTF_8))), "Wrong RP binding");
        check((data[32] & 4) == 0, "UV incorrectly asserted");
        check(ByteBuffer.wrap(data, 33, 4).getInt() == counter, "Wrong signed counter");
        if (credential.discoverable()) {
            Map user = (Map) response.get(new UnsignedInteger(4));
            check(user != null && Arrays.equals(((ByteString) user.get(new UnicodeString("id"))).getBytes(),
                    credential.userId()), "Missing resident user handle");
            check(user.get(new UnicodeString("name")) == null && user.get(new UnicodeString("displayName")) == null,
                    "User-identifying metadata leaked without UV");
        }
        Signature verifier = Signature.getInstance("SHA256withECDSA", new BouncyCastleProvider());
        verifier.initVerify(KeyFactory.getInstance("EC", new BouncyCastleProvider())
                .generatePublic(new X509EncodedKeySpec(credential.keyPair().publicKey())));
        verifier.update(data); verifier.update(HASH);
        check(verifier.verify(((ByteString) response.get(new UnsignedInteger(3))).getBytes()), "Invalid signature");
    }
    private static String fingerprint(ConfigurationFile file) throws Exception {
        List<String> records = new ArrayList<>();
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        Base64.Encoder encoder = Base64.getEncoder();
        for (Credential c : file.credentials()) records.add(encoder.encodeToString(c.id()) + ":"
                + encoder.encodeToString(digest.digest(c.keyPair().privateKey())) + ":"
                + encoder.encodeToString(digest.digest(c.keyPair().publicKey())));
        Collections.sort(records);
        return file.id() + "\n" + String.join("\n", records);
    }
    private static void check(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }
}

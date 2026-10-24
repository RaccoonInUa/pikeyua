package com.github.mphi_rc.fido2;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.*;
import java.util.function.LongSupplier;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import com.github.mphi_rc.fido2.authenticator.*;
import com.github.mphi_rc.fido2.protocol.ctap2.*;
import com.github.mphi_rc.fido2.protocol.ctap2.pin.PinRequestHandler;
import com.github.mphi_rc.fido2.protocol.usbhid.ImmutableChannelId;
import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.NegativeInteger;
import co.nstant.in.cbor.model.SimpleValue;
import co.nstant.in.cbor.model.UnicodeString;
import co.nstant.in.cbor.model.UnsignedInteger;

/** Synthetic protocol client + three-JVM probe. No defaultPath(), USB, shell commands or live state. */
public final class PinUvProbe {
    static final String RP = "pin-probe.example.invalid";
    static final String OTHER = "other-pin-probe.example.invalid";
    static final byte[] HASH = digest("synthetic-pin-uv-challenge".getBytes(StandardCharsets.UTF_8));
    private PinUvProbe() { }

    static final class Session {
        final ConfigurationFile config;
        final PinState pin;
        final AuthenticatorRequestHandler handler;
        Session(Path state) { this(state, System::nanoTime); }
        Session(Path state, LongSupplier clock) {
            config = new ConfigurationFile(state);
            config.persistToDisk();
            pin = new PinState(config, clock);
            Authenticator auth = new Authenticator(config, new ConfigurationCredentialStore(config), pin, true, clock);
            handler = new AuthenticatorRequestHandler(auth, new PinRequestHandler(pin));
        }
    }
    static final class Reply {
        final int status;
        final Map body;
        Reply(byte[] bytes) throws Exception {
            check(bytes != null && bytes.length > 0, "Missing CTAP response");
            status = bytes[0] & 255;
            body = bytes.length == 1 ? null : (Map) CborDecoder.decode(Arrays.copyOfRange(bytes, 1, bytes.length)).get(0);
            check(status == 0 || bytes.length == 1, "Error status was not a raw one-byte response");
        }
    }

    /** Host implementation intentionally does NOT use authenticator PinProtocol1 helpers. */
    static final class Client {
        final AuthenticatorRequestHandler handler;
        byte[] shared, token;
        Map publicKey;
        Client(Session session) { handler = session.handler; }
        Reply call(int command, Map params) throws Exception {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write(command);
            if (params != null) new CborEncoder(out).encode(Collections.<DataItem>singletonList(params));
            return new Reply(handler.handleCborRequest(ImmutableChannelId.of(new byte[]{7, 3, 0, 1}), out.toByteArray()).payload());
        }
        Map pinRequest(int subcommand) {
            Map body = new Map();
            put(body, 1, new UnsignedInteger(1)); put(body, 2, new UnsignedInteger(subcommand));
            return body;
        }
        int retries() throws Exception { Reply r = call(6, pinRequest(1)); ok(r); return ((UnsignedInteger) field(r.body, 3)).getValue().intValue(); }
        boolean configured() throws Exception {
            Reply r = call(4, null); ok(r);
            Map options = (Map) field(r.body, 4);
            check(options.get(new UnicodeString("uv")) == null, "ClientPIN must not advertise built-in UV");
            return SimpleValue.TRUE.equals(options.get(new UnicodeString("clientPin")));
        }
        void agreement() throws Exception {
            Reply r = call(6, pinRequest(2)); ok(r);
            Map peer = (Map) field(r.body, 1);
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec("secp256r1"));
            ECParameterSpec curve = parameters.getParameterSpec(ECParameterSpec.class);
            BigInteger x = new BigInteger(1, ((ByteString) peer.get(new NegativeInteger(-2))).getBytes());
            BigInteger y = new BigInteger(1, ((ByteString) peer.get(new NegativeInteger(-3))).getBytes());
            PublicKey remote = KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new java.security.spec.ECPoint(x, y), curve));
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair own = generator.generateKeyPair();
            KeyAgreement ka = KeyAgreement.getInstance("ECDH"); ka.init(own.getPrivate()); ka.doPhase(remote, true);
            shared = digest(ka.generateSecret());
            ECPublicKey pub = (ECPublicKey) own.getPublic();
            publicKey = new Map();
            put(publicKey, 1, new UnsignedInteger(2)); put(publicKey, 3, new NegativeInteger(-25));
            publicKey.put(new NegativeInteger(-1), new UnsignedInteger(1));
            publicKey.put(new NegativeInteger(-2), new ByteString(fixed(pub.getW().getAffineX())));
            publicKey.put(new NegativeInteger(-3), new ByteString(fixed(pub.getW().getAffineY())));
        }
        Map setRequest(byte[] padded) throws Exception {
            agreement();
            byte[] encrypted = crypt(Cipher.ENCRYPT_MODE, shared, padded);
            Map request = pinRequest(3); put(request, 3, publicKey);
            put(request, 4, new ByteString(mac(shared, encrypted))); put(request, 5, new ByteString(encrypted));
            return request;
        }
        Reply set(String pin) throws Exception { return call(6, setRequest(padded(pin))); }
        Reply getToken(String pin) throws Exception {
            agreement();
            Map request = pinRequest(5); put(request, 3, publicKey);
            byte[] hash = Arrays.copyOf(digest(pin.getBytes(StandardCharsets.UTF_8)), 16);
            put(request, 6, new ByteString(crypt(Cipher.ENCRYPT_MODE, shared, hash)));
            Reply result = call(6, request);
            if (result.status == 0) token = crypt(Cipher.DECRYPT_MODE, shared, bytes(result.body, 2));
            Arrays.fill(hash, (byte) 0);
            return result;
        }
        Map changeRequest(String oldPin, String newPin) throws Exception {
            agreement();
            byte[] encryptedNew = crypt(Cipher.ENCRYPT_MODE, shared, padded(newPin));
            byte[] encryptedHash = crypt(Cipher.ENCRYPT_MODE, shared, Arrays.copyOf(digest(oldPin.getBytes(StandardCharsets.UTF_8)), 16));
            Map request = pinRequest(4); put(request, 3, publicKey);
            put(request, 4, new ByteString(mac(shared, encryptedNew, encryptedHash)));
            put(request, 5, new ByteString(encryptedNew)); put(request, 6, new ByteString(encryptedHash));
            return request;
        }
        Reply change(String oldPin, String newPin) throws Exception { return call(6, changeRequest(oldPin, newPin)); }
        Map makeRequest(String rpId, int user, boolean rk, boolean useToken) throws Exception {
            Map request = new Map(); put(request, 1, new ByteString(HASH));
            Map rp = new Map(); rp.put(new UnicodeString("id"), new UnicodeString(rpId)); put(request, 2, rp);
            Map account = new Map(); account.put(new UnicodeString("id"), new ByteString(new byte[]{(byte) user}));
            account.put(new UnicodeString("name"), new UnicodeString("synthetic-" + user));
            account.put(new UnicodeString("displayName"), new UnicodeString("Synthetic Account " + user)); put(request, 3, account);
            Map algorithm = new Map(); algorithm.put(new UnicodeString("alg"), new NegativeInteger(-7));
            algorithm.put(new UnicodeString("type"), new UnicodeString("public-key"));
            Array algorithms = new Array(); algorithms.add(algorithm); put(request, 4, algorithms);
            Map options = new Map(); options.put(new UnicodeString("rk"), rk ? SimpleValue.TRUE : SimpleValue.FALSE); put(request, 7, options);
            if (useToken) { put(request, 8, new ByteString(mac(token, HASH))); put(request, 9, new UnsignedInteger(1)); }
            return request;
        }
        Reply make(String rpId, int user, boolean rk, boolean useToken) throws Exception { return call(1, makeRequest(rpId, user, rk, useToken)); }
        Map assertionRequest(String rpId, byte[] id, boolean useToken) throws Exception {
            Map request = new Map(); put(request, 1, new UnicodeString(rpId)); put(request, 2, new ByteString(HASH));
            if (id != null) {
                Map descriptor = new Map(); descriptor.put(new UnicodeString("id"), new ByteString(id));
                descriptor.put(new UnicodeString("type"), new UnicodeString("public-key"));
                Array allow = new Array(); allow.add(descriptor); put(request, 3, allow);
            }
            if (useToken) { put(request, 6, new ByteString(mac(token, HASH))); put(request, 7, new UnsignedInteger(1)); }
            return request;
        }
        Reply assertion(String rpId, byte[] id, boolean useToken) throws Exception { return call(2, assertionRequest(rpId, id, useToken)); }
    }
    static byte[] padded(String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        return Arrays.copyOf(bytes, Math.max(64, ((bytes.length + 16) / 16) * 16));
    }
    static byte[] digest(byte[] bytes) {
        try { return MessageDigest.getInstance("SHA-256").digest(bytes); }
        catch (GeneralSecurityException e) { throw new IllegalStateException(e); }
    }
    static byte[] fixed(BigInteger value) {
        byte[] raw = value.toByteArray(), result = new byte[32]; int n = Math.min(32, raw.length);
        System.arraycopy(raw, raw.length - n, result, 32 - n, n); return result;
    }
    static byte[] mac(byte[] key, byte[]... chunks) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256"); mac.init(new SecretKeySpec(key, "HmacSHA256"));
        for (byte[] chunk : chunks) mac.update(chunk);
        return Arrays.copyOf(mac.doFinal(), 16);
    }
    static byte[] crypt(int mode, byte[] key, byte[] bytes) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(mode, new SecretKeySpec(key, "AES"), new IvParameterSpec(new byte[16]));
        return cipher.doFinal(bytes);
    }
    static void put(Map map, int key, DataItem value) { map.put(new UnsignedInteger(key), value); }
    static DataItem field(Map map, int key) { return map.get(new UnsignedInteger(key)); }
    static byte[] bytes(Map map, int key) { return ((ByteString) field(map, key)).getBytes(); }
    static void ok(Reply reply) { check(reply.status == 0, "Unexpected CTAP status 0x" + Integer.toHexString(reply.status)); }
    static void check(boolean ok, String reason) { if (!ok) throw new IllegalStateException(reason); }

    static void verifyAssertion(Session session, Reply reply, boolean uv) throws Exception {
        ok(reply);
        byte[] data = bytes(reply.body, 2);
        check(((data[32] & 4) != 0) == uv, "Incorrect signed UV bit");
        byte[] id = ((ByteString) ((Map) field(reply.body, 1)).get(new UnicodeString("id"))).getBytes();
        Credential credential = session.config.credentials().stream().filter(c -> Arrays.equals(c.id(), id)).findFirst().get();
        PublicKey publicKey = KeyFactory.getInstance("EC", new BouncyCastleProvider()).generatePublic(new X509EncodedKeySpec(credential.keyPair().publicKey()));
        Signature verifier = Signature.getInstance("SHA256withECDSA", new BouncyCastleProvider());
        verifier.initVerify(publicKey); verifier.update(data); verifier.update(HASH);
        check(verifier.verify(bytes(reply.body, 3)), "Assertion signature invalid");
        Map user = (Map) field(reply.body, 4);
        if (credential.discoverable()) {
            check(user != null, "Missing user handle");
            check((user.get(new UnicodeString("name")) != null) == uv, "User-name disclosure policy failed");
        }
    }
    private static String fingerprint(ConfigurationFile config) {
        StringBuilder value = new StringBuilder(config.id().toString());
        for (Credential c : config.credentials()) value.append('\n').append(Base64.getEncoder().encodeToString(c.id()))
                .append(':').append(Base64.getEncoder().encodeToString(digest(c.keyPair().privateKey())))
                .append(':').append(Base64.getEncoder().encodeToString(digest(c.keyPair().publicKey())));
        return value.toString();
    }
    private static void child(String phase, Path directory) throws Exception {
        Session session = new Session(directory.resolve("config.json")); Client client = new Client(session);
        Path baseline = directory.resolve("expected.txt");
        if (phase.equals("create")) {
            check(!client.configured(), "Fresh probe unexpectedly has PIN");
            ok(client.set("246810")); check(client.configured(), "PIN not reported");
            check(client.make(RP, 1, true, false).status == 0x36, "Registration bypassed configured PIN");
            ok(client.getToken("246810"));
            ok(client.make(RP, 1, true, true)); ok(client.make(RP, 2, true, true));
            ok(client.make(OTHER, 3, true, true)); ok(client.make(RP, 4, false, true));
            AtomicStateFile.write(baseline, fingerprint(session.config).getBytes(StandardCharsets.UTF_8));
        } else {
            check(client.configured(), "PIN did not survive restart");
            check(new String(AtomicStateFile.read(baseline), StandardCharsets.UTF_8).equals(fingerprint(session.config)), "Credential keys/identity changed");
            if (phase.equals("change")) {
                ok(client.getToken("246810"));
                verifyAssertion(session, client.assertion(RP, null, true), true);
                verifyAssertion(session, client.call(8, null), true);
                verifyAssertion(session, client.assertion(RP, null, false), false);
                ok(client.change("246810", "135790"));
                check(client.make(RP, 99, true, true).status == 0x33, "Old token survived PIN change");
                check(client.getToken("246810").status == 0x31, "Old PIN survived change");
                check(client.retries() == 7, "Wrong PIN did not consume a durable attempt");
            } else if (phase.equals("verify")) {
                check(client.retries() == 7, "Restart refunded a failed PIN attempt");
                ok(client.getToken("135790")); check(client.retries() == 8, "Correct PIN did not reset retry budget");
                verifyAssertion(session, client.assertion(RP, null, true), true);
                verifyAssertion(session, client.call(8, null), true);
                Credential legacy = session.config.credentials().stream().filter(c -> !c.discoverable()).findFirst().get();
                verifyAssertion(session, client.assertion(RP, legacy.id(), true), true);
                check(client.assertion("wrong-rp.invalid", null, true).status == 0x2e, "Cross-RP lookup leaked credential");
                check(session.config.credentials().size() == 4, "Failed auth created a credential");
            } else throw new IllegalArgumentException("Unknown probe phase");
        }
        System.out.println("PASS: pin-uv " + phase);
    }
    public static void main(String[] args) throws Exception {
        if (args.length == 4 && args[0].equals("--child")) {
            Path directory = Paths.get(args[2]).toAbsolutePath().normalize();
            check(!Files.isSymbolicLink(directory) && directory.getFileName().toString().startsWith("pikeyua-v73-"), "Not a probe directory");
            check(Files.getPosixFilePermissions(directory).equals(PosixFilePermissions.fromString("rwx------")), "Probe directory must be private");
            check(new String(AtomicStateFile.read(directory.resolve("probe.marker")), StandardCharsets.US_ASCII).equals(args[3]), "Probe marker mismatch");
            child(args[1], directory); return;
        }
        if (args.length != 0) throw new IllegalArgumentException("Run without arguments; never pass live state to the probe");
        Path dir = Files.createTempDirectory("pikeyua-v73-", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        String marker = UUID.randomUUID().toString();
        try {
            AtomicStateFile.write(dir.resolve("probe.marker"), marker.getBytes(StandardCharsets.US_ASCII));
            for (String phase : new String[]{"create", "change", "verify"}) {
                Process process = new ProcessBuilder(Paths.get(System.getProperty("java.home"), "bin", "java").toString(),
                        "-cp", System.getProperty("java.class.path"), PinUvProbe.class.getName(), "--child", phase, dir.toString(), marker)
                        .inheritIO().start();
                if (!process.waitFor(180, java.util.concurrent.TimeUnit.SECONDS)) {
                    process.destroyForcibly(); process.waitFor(); throw new IllegalStateException("Probe phase timed out");
                }
                check(process.exitValue() == 0, "Probe child failed");
            }
            System.out.println("PASS: PIN set/change, verified RK assertions, token invalidation and persisted retries across independent JVMs");
        } finally {
            try (java.util.stream.Stream<Path> files = Files.walk(dir)) {
                for (Path file : files.sorted(Comparator.reverseOrder()).collect(java.util.stream.Collectors.toList())) Files.deleteIfExists(file);
            }
        }
    }
}

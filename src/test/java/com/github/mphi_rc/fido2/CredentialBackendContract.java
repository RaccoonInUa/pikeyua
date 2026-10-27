package com.github.mphi_rc.fido2;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;
import com.github.mphi_rc.fido2.authenticator.*;
import com.github.mphi_rc.fido2.authenticator.crypto.*;
import com.github.mphi_rc.fido2.authenticator.keys.*;
import com.github.mphi_rc.fido2.protocol.ctap2.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.CborEncoder;

/** Standalone synthetic checks; no USB, defaultPath, live state, systemd or network. */
public final class CredentialBackendContract {
    private static final String RP = "backend.example.invalid";
    private static final byte[] HASH = new byte[32];
    private static final String[] CASES = {"public-api", "immutable-handle", "immutable-view", "p256", "ed25519",
        "readonly-load", "restart", "foreign-provider", "foreign-rp", "stale-counter", "deleted-handle",
        "delete-preserves-state", "denied-sign", "denied-delete", "rk-replacement", "wire-length",
        "opaque-registration-assertion", "opaque-no-fallback", "unsupported-algorithm", "opaque-continuation"};
    private CredentialBackendContract() { }
    public static void main(String[] args) throws Exception {
        if (args.length == 2 && args[0].equals("existing-state")) {
            existingState(Paths.get(args[1]));
            System.out.println("PASS: frozen V7.3 state read/sign through backend");
            return;
        }
        if (args.length != 0) throw new IllegalArgumentException("No arguments, or existing-state <synthetic state directory>");
        for (String name : CASES) { run(name); System.out.println("PASS: backend " + name); }
    }
    public static void run(String name) throws Exception {
        Path dir = Files.createTempDirectory("pikeyua-backend-contract-");
        Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx------"));
        try { scenario(name, dir); }
        finally {
            Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx------"));
            try (java.util.stream.Stream<Path> paths = Files.walk(dir)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).collect(Collectors.toList())) Files.delete(path);
            }
        }
    }
    private static void scenario(String name, Path dir) throws Exception {
        if (name.equals("public-api")) {
            for (Class<?> type : new Class<?>[]{CredentialBackend.class, CredentialDescriptor.class, KeyHandle.class}) {
                for (java.lang.reflect.Method method : type.getDeclaredMethods()) {
                    check(!method.getName().equals("privateKey") && !method.getName().equals("keyPair"), "Private API present");
                    check(!PrivateKey.class.isAssignableFrom(method.getReturnType())
                            && !AttestationKeyPair.class.isAssignableFrom(method.getReturnType()), "Private return type present");
                }
            }
            try (java.io.InputStream input = Authenticator.class.getResourceAsStream("Authenticator.class")) {
                ByteArrayOutputStream out = new ByteArrayOutputStream(); byte[] buffer = new byte[4096]; int n;
                while ((n = input.read(buffer)) >= 0) out.write(buffer, 0, n);
                String constants = new String(out.toByteArray(), StandardCharsets.ISO_8859_1);
                check(!constants.contains("AttestationKeyPair") && !constants.contains("privateKey")
                        && !constants.contains("keyPair"), "CTAP logic references legacy secret types");
            }
            return;
        }
        if (name.equals("immutable-handle")) {
            byte[] source = {1, 2}; KeyHandle handle = new KeyHandle("test", RP, source); source[0] = 99;
            handle.id()[0] = 98; check(handle.id()[0] == 1, "Handle aliases caller memory");
            check(handle.equals(new KeyHandle("test", RP, new byte[]{1, 2})), "Handle equality broken");
            check(!handle.equals(new KeyHandle("other", RP, new byte[]{1, 2})), "Provider not scoped");
            check(!handle.toString().contains(RP), "Handle toString discloses metadata"); return;
        }
        ConfigurationFile config = new ConfigurationFile(dir.resolve("config.json")); config.persistToDisk();
        ConfigurationCredentialStore store = new ConfigurationCredentialStore(config);
        LegacySoftwareCredentialBackend backend = new LegacySoftwareCredentialBackend(store);
        if (name.startsWith("opaque-") || name.equals("unsupported-algorithm")) { opaque(name, config); return; }
        Algorithm algorithm = name.equals("ed25519") ? Algorithm.Ed25519 : Algorithm.P256_ECDSA;
        CredentialDescriptor credential = backend.create(RP, new byte[]{1}, algorithm, true, "synthetic", "Synthetic");
        if (name.equals("immutable-view")) {
            byte[] id = credential.id(), pub = credential.publicKey(), cose = credential.cosePublicKey();
            credential.id()[0] ^= 1; credential.publicKey()[0] ^= 1; credential.cosePublicKey()[0] ^= 1; credential.userId()[0] ^= 1;
            check(Arrays.equals(id, credential.id()) && Arrays.equals(pub, credential.publicKey())
                    && Arrays.equals(cose, credential.cosePublicKey()) && credential.userId()[0] == 1, "Descriptor aliases array"); return;
        }
        if (name.equals("p256") || name.equals("ed25519")) {
            AuthenticatorData registration = ImmutableAuthenticatorData.builder().relayingPartyId(RP).isUserPresent(true)
                    .isUserVerified(false).signatureCount(0).attestedCredentialData(credential.encodeAttestedCredentialData(config.getAaguid())).build();
            verify(credential, registration.asBytes(), HASH, backend.signRegistration(credential.handle(), registration, HASH));
            AuthenticatorData assertion = assertion(RP, 1);
            verify(credential, assertion.asBytes(), HASH, backend.signAssertion(credential.handle(), assertion, HASH));
            check(config.credentials().get(0).signatureCount() == 1, "Counter not committed"); return;
        }
        if (name.equals("readonly-load")) {
            byte[] before = Files.readAllBytes(dir.resolve("config.json"));
            LegacySoftwareCredentialBackend restored = new LegacySoftwareCredentialBackend(new ConfigurationCredentialStore(new ConfigurationFile(dir.resolve("config.json"))));
            CredentialDescriptor read = restored.find(RP).iterator().next();
            check(Arrays.equals(credential.id(), read.id()) && Arrays.equals(before, Files.readAllBytes(dir.resolve("config.json"))), "Read mutated state/ID"); return;
        }
        if (name.equals("restart")) {
            UUID identity = config.id(); byte[] originalPrivate = config.credentials().get(0).keyPair().privateKey().clone();
            ConfigurationFile next = new ConfigurationFile(dir.resolve("config.json"));
            CredentialBackend restored = new LegacySoftwareCredentialBackend(new ConfigurationCredentialStore(next));
            CredentialDescriptor read = restored.find(RP).iterator().next();
            verify(read, assertion(RP, 1).asBytes(), HASH, restored.signAssertion(credential.handle(), assertion(RP, 1), HASH));
            check(identity.equals(next.id()) && Arrays.equals(credential.id(), read.id())
                    && Arrays.equals(originalPrivate, next.credentials().get(0).keyPair().privateKey()), "Restart changed keys/identity"); return;
        }
        if (name.equals("foreign-provider") || name.equals("foreign-rp")) {
            KeyHandle wrong = new KeyHandle(name.equals("foreign-provider") ? "missing-provider" : credential.handle().provider(),
                    name.equals("foreign-rp") ? "other.invalid" : RP, credential.id());
            refused(() -> backend.signAssertion(wrong, assertion(RP, 1), HASH));
            check(config.credentials().get(0).signatureCount() == 0, "Refusal advanced counter"); return;
        }
        if (name.equals("stale-counter")) {
            backend.signAssertion(credential.handle(), assertion(RP, 1), HASH);
            refused(() -> backend.signAssertion(credential.handle(), assertion(RP, 1), HASH));
            check(config.credentials().get(0).signatureCount() == 1, "Stale operation mutated counter"); return;
        }
        if (name.equals("deleted-handle")) {
            backend.delete(credential.handle());
            refused(() -> backend.signAssertion(credential.handle(), assertion(RP, 1), HASH));
            refused(() -> backend.delete(credential.handle())); check(backend.find(RP).isEmpty(), "Deleted credential remains"); return;
        }
        if (name.equals("delete-preserves-state")) {
            CredentialDescriptor other = backend.create("other.invalid", new byte[]{2}, algorithm, false, "", "");
            config.updatePinHash(new byte[16]); config.updatePinRetries(0); UUID identity = config.id();
            byte[] otherPrivate = config.credentials().get(1).keyPair().privateKey().clone();
            backend.delete(credential.handle()); ConfigurationFile read = new ConfigurationFile(dir.resolve("config.json"));
            check(read.credentials().size() == 1 && read.pinRetries() == 0 && read.pinHash().isPresent() && identity.equals(read.id()), "Delete changed protected state");
            check(Arrays.equals(other.id(), read.credentials().get(0).id())
                    && Arrays.equals(otherPrivate, read.credentials().get(0).keyPair().privateKey()), "Delete changed another key"); return;
        }
        if (name.equals("denied-sign") || name.equals("denied-delete")) {
            byte[] original = Files.readAllBytes(dir.resolve("config.json"));
            Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwxr-xr-x"));
            if (name.equals("denied-sign")) refused(() -> backend.signAssertion(credential.handle(), assertion(RP, 1), HASH));
            else refused(() -> backend.delete(credential.handle()));
            check(config.credentials().size() == 1 && config.credentials().get(0).signatureCount() == 0
                    && Arrays.equals(original, Files.readAllBytes(dir.resolve("config.json"))), "Failed write changed state"); return;
        }
        if (name.equals("rk-replacement")) {
            CredentialDescriptor legacy = backend.create(RP, new byte[]{1}, algorithm, false, "", "");
            CredentialDescriptor replacement = backend.create(RP, new byte[]{1}, algorithm, true, "new", "New");
            check(backend.find(RP).size() == 2 && !Arrays.equals(replacement.id(), credential.id()), "RK replacement broken");
            refused(() -> backend.signAssertion(credential.handle(), assertion(RP, 1), HASH));
            verify(legacy, assertion(RP, 1).asBytes(), HASH, backend.signAssertion(legacy.handle(), assertion(RP, 1), HASH)); return;
        }
        if (name.equals("wire-length")) {
            byte[] aaguid = config.getAaguid();
            for (int length : new int[]{1, 16, 255, 256, 1024, 65535}) {
                CredentialDescriptor view = new CredentialDescriptor(credential.handle(), new byte[length], Instant.now(), new byte[]{1},
                        algorithm, credential.publicKey(), credential.cosePublicKey(), 0, true, "", "");
                byte[] bytes = view.encodeAttestedCredentialData(aaguid);
                check((((bytes[16] & 255) << 8) | (bytes[17] & 255)) == length, "Incorrect two-byte credential ID length");
            }
            refused(() -> credential.encodeAttestedCredentialData(new byte[15])); return;
        }
        throw new IllegalArgumentException("Unknown synthetic case");
    }
    private static void opaque(String name, ConfigurationFile config) throws Exception {
        OpaqueTestBackend provider = new OpaqueTestBackend();
        Authenticator auth = new Authenticator(config, provider, new PinState(config), true, System::nanoTime);
        MakeCredentialRequest make = ImmutableMakeCredentialRequest.builder().relayingPartyId(RP).clientDataHash(HASH)
                .userId(new byte[]{1}).addSupportedAlgorithmIds(-7).residentKeyRequested(true).build();
        if (name.equals("unsupported-algorithm")) {
            MakeCredentialRequest unsupported = ImmutableMakeCredentialRequest.builder().from(make).supportedAlgorithmIds(Collections.singleton(-8)).build();
            int result = auth.makeCredential(unsupported).<Integer>handleError(e -> (int) e.asBytes()[0] & 255).elseGet(v -> 0);
            check(result == 0x26 && provider.entries.isEmpty() && config.credentials().isEmpty(), "Unsupported algorithm fell back"); return;
        }
        if (name.equals("opaque-no-fallback")) {
            provider.fail = true; refused(() -> success(auth.makeCredential(make)));
            check(provider.entries.isEmpty() && config.credentials().isEmpty(), "Create silently fell back");
            provider.fail = false; success(auth.makeCredential(make)); provider.fail = true;
            refused(() -> success(auth.getAssertion(ImmutableGetAssertionRequest.builder().relayingPartyId(RP).clientDataHash(HASH).build())));
            check(provider.entries.values().iterator().next().count == 0 && config.credentials().isEmpty(), "Sign silently fell back"); return;
        }
        MakeCredentialResponse registration = success(auth.makeCredential(make));
        CredentialDescriptor descriptor = provider.find(RP).iterator().next();
        verify(descriptor, registration.authData(), HASH, registration.signature());
        if (name.equals("opaque-continuation")) {
            success(auth.makeCredential(ImmutableMakeCredentialRequest.builder().from(make).userId(new byte[]{2}).build()));
        }
        GetAssertionResponse response = success(auth.getAssertion(ImmutableGetAssertionRequest.builder().relayingPartyId(RP).clientDataHash(HASH).build()));
        CredentialDescriptor matched = provider.find(RP).stream().filter(c -> Arrays.equals(c.id(), response.credentialId())).findFirst().get();
        verify(matched, response.authData(), HASH, response.signature());
        if (name.equals("opaque-continuation")) {
            GetAssertionResponse next = success(auth.getNextAssertion(com.github.mphi_rc.fido2.protocol.usbhid.ImmutableChannelId.of(new byte[]{0, 0, 0, 1})));
            CredentialDescriptor second = provider.find(RP).stream().filter(c -> Arrays.equals(c.id(), next.credentialId())).findFirst().get();
            check(!Arrays.equals(response.credentialId(), next.credentialId()), "Continuation repeated credential");
            verify(second, next.authData(), HASH, next.signature());
        }
        check(config.credentials().isEmpty(), "Opaque provider leaked keys into legacy software state");
    }
    /** TEST ONLY. Memory-only JCE keys; not hardware, not durable, never a production option. */
    private static final class OpaqueTestBackend implements CredentialBackend {
        private static final String ID = "test-only-opaque";
        private static final class Entry { KeyPair pair; CredentialDescriptor view; int count; }
        final java.util.Map<KeyHandle, Entry> entries = new LinkedHashMap<>(); boolean fail;
        public Set<Algorithm> supportedAlgorithms() { return Collections.singleton(Algorithm.P256_ECDSA); }
        public Collection<CredentialDescriptor> find(String rp) {
            return entries.values().stream().filter(e -> e.view.relayingPartyId().equals(rp)).map(this::view).collect(Collectors.toList());
        }
        public CredentialDescriptor create(String rp, byte[] user, Algorithm algorithm, boolean rk, String name, String display) {
            if (fail) throw new IllegalStateException("Synthetic unavailable provider");
            try {
                KeyPairGenerator generator = KeyPairGenerator.getInstance("EC"); generator.initialize(new ECGenParameterSpec("secp256r1"));
                Entry entry = new Entry(); entry.pair = generator.generateKeyPair();
                byte[] id = new byte[16]; new SecureRandom().nextBytes(id); KeyHandle handle = new KeyHandle(ID, rp, id);
                ECPublicKey pub = (ECPublicKey) entry.pair.getPublic(); ByteArrayOutputStream out = new ByteArrayOutputStream();
                new CborEncoder(out).encode(new CborBuilder().addMap().put(1, 2).put(3, -7).put(-1, 1)
                        .put(-2, fixed(pub.getW().getAffineX())).put(-3, fixed(pub.getW().getAffineY())).end().build());
                entry.view = new CredentialDescriptor(handle, id, Instant.now(), user, algorithm,
                        pub.getEncoded(), out.toByteArray(), 0, rk, name, display);
                entries.put(handle, entry); return view(entry);
            } catch (Exception e) { throw new IllegalStateException(e); }
        }
        private CredentialDescriptor view(Entry e) {
            CredentialDescriptor c = e.view;
            return new CredentialDescriptor(c.handle(), c.id(), c.creation(), c.userId(), c.algorithm(), c.publicKey(),
                    c.cosePublicKey(), e.count, c.discoverable(), c.userName(), c.userDisplayName());
        }
        public byte[] signRegistration(KeyHandle handle, AuthenticatorData data, byte[] hash) { return sign(handle, data, hash, false); }
        public byte[] signAssertion(KeyHandle handle, AuthenticatorData data, byte[] hash) { return sign(handle, data, hash, true); }
        private byte[] sign(KeyHandle handle, AuthenticatorData data, byte[] hash, boolean assertion) {
            if (fail || !entries.containsKey(handle)) throw new IllegalStateException("Synthetic unavailable provider");
            Entry entry = entries.get(handle);
            try {
                if (assertion && data.signatureCount() != entry.count + 1) throw new IllegalStateException("Stale counter");
                Signature signer = Signature.getInstance("SHA256withECDSA"); signer.initSign(entry.pair.getPrivate());
                signer.update(data.asBytes()); signer.update(hash); byte[] signature = signer.sign();
                if (assertion) entry.count++; return signature;
            } catch (GeneralSecurityException e) { throw new IllegalStateException(e); }
        }
        public void delete(KeyHandle handle) { if (entries.remove(handle) == null) throw new IllegalStateException("Missing key"); }
    }
    private static byte[] fixed(java.math.BigInteger n) { byte[] raw = n.toByteArray(), out = new byte[32]; System.arraycopy(raw, Math.max(0, raw.length - 32), out, Math.max(0, 32 - raw.length), Math.min(32, raw.length)); return out; }
    private static AuthenticatorData assertion(String rp, int count) { return ImmutableAuthenticatorData.builder().relayingPartyId(rp).signatureCount(count).isUserPresent(false).isUserVerified(false).build(); }
    private static <T> T success(Result<T, Ctap2ResponseCode> result) { return result.<T>handleError(e -> { throw new AssertionError("Unexpected CTAP status: " + e); }).elseGet(value -> value); }
    private static void verify(CredentialDescriptor c, byte[] data, byte[] hash, byte[] signature) throws Exception {
        Provider provider = new BouncyCastleProvider(); boolean ec = c.algorithm() == Algorithm.P256_ECDSA;
        PublicKey pub = KeyFactory.getInstance(ec ? "EC" : "Ed25519", provider).generatePublic(new X509EncodedKeySpec(c.publicKey()));
        Signature verifier = Signature.getInstance(ec ? "SHA256withECDSA" : "Ed25519", provider);
        verifier.initVerify(pub); verifier.update(data); verifier.update(hash); check(verifier.verify(signature), "Invalid cryptographic signature");
    }
    private static void existingState(Path dir) throws Exception {
        Path file = dir.resolve("config.json"); byte[] before = Files.readAllBytes(file);
        ConfigurationFile config = new ConfigurationFile(file); UUID identity = config.id();
        Credential old = config.credentials().get(0); byte[] secret = old.keyPair().privateKey().clone();
        CredentialBackend backend = new LegacySoftwareCredentialBackend(new ConfigurationCredentialStore(config));
        CredentialDescriptor descriptor = backend.find(old.relayingPartyId()).iterator().next();
        check(Arrays.equals(before, Files.readAllBytes(file)) && Arrays.equals(old.id(), descriptor.id()), "Cross-version read changed bytes/ID");
        AuthenticatorData assertion = assertion(old.relayingPartyId(), old.signatureCount() + 1);
        verify(descriptor, assertion.asBytes(), HASH, backend.signAssertion(descriptor.handle(), assertion, HASH));
        ConfigurationFile restored = new ConfigurationFile(file);
        check(identity.equals(restored.id()) && Arrays.equals(secret, restored.credentials().get(0).keyPair().privateKey()), "Cross-version changed key/identity");
    }
    private interface Action { void run() throws Exception; }
    private static void refused(Action action) throws Exception { try { action.run(); } catch (RuntimeException expected) { return; } throw new AssertionError("Operation unexpectedly succeeded"); }
    private static void check(boolean value, String message) { if (!value) throw new AssertionError(message); }
}

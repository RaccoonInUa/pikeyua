package com.github.mphi_rc.fido2.authenticator.keys.token;

import com.github.mphi_rc.fido2.AtomicStateFile;
import com.github.mphi_rc.fido2.authenticator.keys.pkcs11.Pkcs11P256Signer;
import com.github.mphi_rc.fido2.authenticator.keys.pkcs11.Pkcs11TokenKeyDriver;
import com.github.mphi_rc.fido2.authenticator.keys.CredentialDescriptor;
import com.github.mphi_rc.fido2.authenticator.crypto.Algorithm;
import com.github.mphi_rc.fido2.protocol.ctap2.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;

/** Kills only children created by this test. No USB, systemd, account secrets or host TPM. */
public final class TokenRecoveryProbe {
    private static final String RP = "recovery.synthetic.invalid", OTHER = "other.synthetic.invalid";
    private static final byte[] HASH = new byte[32];
    private static final String SENTINEL = "PIKEYUA_SYNTHETIC_RECOVERY_LAB";
    private static String[] nativeSettings;
    private TokenRecoveryProbe() { }
    private static void nativeSettings(String[] settings) {
        if (settings.length != 4 || !settings[0].equals("--software-native"))
            throw new IllegalArgumentException("Explicit software-token fixture required");
        String soft = System.getenv("SOFTHSM2_CONF"), tcti = System.getenv("TPM2_PKCS11_TCTI");
        if (settings[1].contains("softhsm")) {
            if (soft == null || !soft.startsWith("/tmp/pikeyua-p11-ci-"))
                throw new IllegalArgumentException("Not an isolated SoftHSM fixture");
        } else if (tcti == null || !tcti.startsWith("tabrmd:bus_type=session,bus_name=com.intel.tss2.Tabrmd.pikeyua"))
            throw new IllegalArgumentException("Not an isolated software TPM fixture");
        if (!Paths.get(settings[3]).toAbsolutePath().normalize().toString().startsWith("/tmp/pikeyua-p11-ci-"))
            throw new IllegalArgumentException("Synthetic token PIN fixture required");
        nativeSettings = settings.clone();
    }
    private static final class LabSession implements AutoCloseable {
        final DurableTokenCredentialBackend backend;
        private final Pkcs11P256Signer token;
        LabSession(Path root, TokenStateFile.Checkpoint checkpoint) throws Exception {
            Pkcs11P256Signer opened = null;
            try {
                TokenKeyDriver driver;
                if (nativeSettings == null) driver = new SyntheticFileToken(root.resolve("token"));
                else {
                    char[] pin = new String(Files.readAllBytes(Paths.get(nativeSettings[3])), StandardCharsets.US_ASCII).trim().toCharArray();
                    try { opened = Pkcs11P256Signer.open(Paths.get(nativeSettings[1]), Long.parseLong(nativeSettings[2]), pin); }
                    finally { Arrays.fill(pin, '\0'); }
                    driver = new Pkcs11TokenKeyDriver(opened);
                }
                backend = new DurableTokenCredentialBackend(state(root), driver, checkpoint);
                token = opened;
            } catch (Exception e) { if (opened != null) opened.close(); throw e; }
        }
        public void close() throws Exception { try { backend.close(); } finally { if (token != null) token.close(); } }
    }
    public static void main(String[] args) throws Exception {
        if ((args.length == 4 || args.length == 8) && args[0].equals("--synthetic-child")) {
            if (args.length == 8) nativeSettings(Arrays.copyOfRange(args, 4, 8));
            child(Paths.get(args[1]), args[2], args[3]); return;
        }
        if (args.length == 4) {
            nativeSettings(args);
            scenario("create", "create.token_ready");
            scenario("create", "create.redo.dir_synced");
            scenario("assert", "counter.redo.dir_synced");
            scenario("delete", "delete.committed");
            scenario("delete", "delete.token_removed");
            interruptedReplay();
            System.out.println("PASS: 6 forced-process recovery scenarios through real PKCS11 software-token stack");
            return;
        }
        if (args.length != 0) throw new IllegalArgumentException("No arguments for isolated test suite");
        int count = 0;
        String[] creation = {"intent.redo.file_synced", "intent.redo.dir_synced", "intent.state.dir_synced",
                "create.token_ready", "create.redo.file_synced", "create.redo.dir_synced",
                "create.state.renamed", "create.state.dir_synced"};
        for (String point : creation) { scenario("create", point); count++; }
        for (String point : new String[]{"intent.state.dir_synced", "create.token_ready", "create.redo.dir_synced"}) {
            scenario("replace", point); count++;
        }
        for (String point : new String[]{"counter.signed", "counter.redo.file_synced", "counter.redo.dir_synced",
                "counter.state.renamed", "counter.state.dir_synced"}) { scenario("assert", point); count++; }
        for (String point : new String[]{"delete.redo.file_synced", "delete.redo.dir_synced", "delete.committed",
                "delete.token_removed", "cleanup.redo.dir_synced", "cleanup.state.dir_synced"}) {
            scenario("delete", point); count++;
        }
        interruptedReplay(); count++;
        System.out.println("PASS: " + count + " forced-child-termination recovery scenarios; unrelated credentials still sign");
        System.out.println("NOT TESTED: physical power cuts, SD failure, physical TPM or USB/browser interoperability");
    }
    private static Path directory(Path parent, String name) throws IOException {
        return Files.createDirectory(parent.resolve(name), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
    }
    private static Path fresh() throws IOException {
        Path root = Files.createTempDirectory("pikeyua-recovery-test-", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))).toRealPath();
        directory(root, "state"); directory(root, "token");
        AtomicStateFile.write(root.resolve("synthetic.marker"), SENTINEL.getBytes(StandardCharsets.US_ASCII));
        return root;
    }
    private static Path state(Path root) { return root.resolve("state/credentials.json"); }
    private static CredentialDescriptor create(DurableTokenCredentialBackend backend, String rp, int user) {
        return backend.create(rp, new byte[]{(byte) user}, Algorithm.P256_ECDSA, true, "synthetic", "Synthetic");
    }
    private static AuthenticatorData data(CredentialDescriptor c) {
        return ImmutableAuthenticatorData.builder().relayingPartyId(c.relayingPartyId())
                .signatureCount(c.signatureCount() + 1).isUserPresent(true).isUserVerified(true).build();
    }
    private static void verify(CredentialDescriptor c, AuthenticatorData data, byte[] signature) throws Exception {
        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(c.publicKey())));
        verifier.update(data.asBytes()); verifier.update(HASH);
        check(verifier.verify(signature), "Recovered credential cannot sign with original public key");
    }
    private static List<CredentialDescriptor> seed(Path root) throws Exception {
        List<CredentialDescriptor> originals = new ArrayList<>();
        try (LabSession session = new LabSession(root, TokenStateFile.NONE)) {
            DurableTokenCredentialBackend backend = session.backend;
            originals.add(create(backend, RP, 1)); originals.add(create(backend, OTHER, 2));
            originals.add(create(backend, OTHER, 3));
            for (int i = 0; i < 3; i++) {
                CredentialDescriptor c = backend.find(RP).iterator().next();
                backend.signAssertion(c.handle(), data(c), HASH);
            }
        }
        return originals;
    }
    private static void child(Path root, String operation, String point) throws Exception {
        if (!SENTINEL.equals(new String(AtomicStateFile.read(root.resolve("synthetic.marker")), StandardCharsets.US_ASCII)))
            throw new IllegalArgumentException("Not a synthetic fixture");
        TokenStateFile.Checkpoint checkpoint = name -> {
            if (name.equals(point)) {
                System.out.println("READY_TO_KILL " + point); System.out.flush();
                for (;;) { try { Thread.sleep(1000); } catch (InterruptedException ignored) { } }
            }
        };
        try (LabSession session = new LabSession(root, checkpoint)) {
            DurableTokenCredentialBackend backend = session.backend;
            switch (operation) {
                case "create": create(backend, "new.synthetic.invalid", 4); break;
                case "replace": create(backend, RP, 1); break;
                case "assert": {
                    CredentialDescriptor c = backend.find(RP).iterator().next();
                    backend.signAssertion(c.handle(), data(c), HASH); break;
                }
                case "delete": backend.delete(backend.find(RP).iterator().next().handle()); break;
                case "reopen": break;
                default: throw new IllegalArgumentException("Unknown synthetic phase");
            }
        }
        throw new AssertionError("Requested kill checkpoint was not reached");
    }
    private static void killAt(Path root, String operation, String point) throws Exception {
        String java = Paths.get(System.getProperty("java.home"), "bin", "java").toString();
        List<String> command = new ArrayList<>(Arrays.asList(java, "-Xmx96m", "-cp", System.getProperty("java.class.path"),
                TokenRecoveryProbe.class.getName(), "--synthetic-child", root.toString(), operation, point));
        if (nativeSettings != null) command.addAll(Arrays.asList(nativeSettings));
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        ExecutorService reader = Executors.newSingleThreadExecutor();
        try {
            Future<Boolean> ready = reader.submit(() -> {
                try (BufferedReader lines = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                    String line; StringBuilder failure = new StringBuilder();
                    while ((line = lines.readLine()) != null) {
                        if (line.equals("READY_TO_KILL " + point)) return true;
                        if (failure.length() < 8192) failure.append(line).append('\n');
                    }
                    throw new IOException("Child exited before checkpoint: " + failure);
                }
            });
            check(ready.get(120, TimeUnit.SECONDS), "No child checkpoint");
            process.destroyForcibly();
            check(process.waitFor(30, TimeUnit.SECONDS) && process.exitValue() != 0, "Child was not forcibly terminated");
        } finally {
            if (process.isAlive()) { process.destroyForcibly(); process.waitFor(30, TimeUnit.SECONDS); }
            reader.shutdownNow();
        }
    }
    private static void scenario(String operation, String point) throws Exception {
        Path root = fresh();
        try {
            List<CredentialDescriptor> originals = seed(root);
            killAt(root, operation, point);
            try (LabSession session = new LabSession(root, TokenStateFile.NONE)) {
                DurableTokenCredentialBackend recovered = session.backend;
                for (CredentialDescriptor original : originals) {
                    Optional<CredentialDescriptor> restored = recovered.find(original.relayingPartyId()).stream()
                            .filter(c -> Arrays.equals(c.id(), original.id())).findFirst();
                    if (!restored.isPresent()) {
                        check(original.relayingPartyId().equals(RP) && (operation.equals("delete") || operation.equals("replace")),
                                "An unrelated credential disappeared");
                        if (operation.equals("replace")) check(new String(Files.readAllBytes(state(root)), StandardCharsets.UTF_8)
                                .contains(Base64.getEncoder().encodeToString(original.publicKey())), "Replaced public reference lost");
                        continue;
                    }
                    CredentialDescriptor c = restored.get();
                    check(Arrays.equals(c.publicKey(), original.publicKey()), "Recovered key was substituted");
                    if (c.relayingPartyId().equals(RP)) check(c.signatureCount() >= 3, "Acknowledged counter regressed");
                    AuthenticatorData signed = data(c);
                    verify(c, signed, recovered.signAssertion(c.handle(), signed, HASH));
                }
                if (operation.equals("delete") && !point.equals("delete.redo.file_synced"))
                    check(recovered.find(RP).isEmpty(), "Durably deleted credential resurrected");
                check(recovered.recoveryStatus().get("activeCredentials") >= 2, "Survivor records lost");
            }
            // A second independent construction must not repeatedly re-apply the transaction.
            try (LabSession session = new LabSession(root, TokenStateFile.NONE)) {
                DurableTokenCredentialBackend again = session.backend;
                check(again.recoveryStatus().get("abortedCreates") == 0, "Recovery is not idempotent");
            }
            System.out.println("PASS: forced termination " + operation + " / " + point);
        } finally { removeFixture(root); }
    }
    private static void interruptedReplay() throws Exception {
        Path root = fresh();
        try {
            seed(root); killAt(root, "assert", "counter.redo.dir_synced");
            killAt(root, "reopen", "replay.state.renamed");
            try (LabSession session = new LabSession(root, TokenStateFile.NONE)) {
                DurableTokenCredentialBackend recovered = session.backend;
                CredentialDescriptor c = recovered.find(RP).iterator().next();
                check(c.signatureCount() == 4, "Interrupted replay regressed the consumed counter");
                AuthenticatorData signed = data(c); verify(c, signed, recovered.signAssertion(c.handle(), signed, HASH));
            }
            System.out.println("PASS: recovery interrupted and repeated without counter rollback");
        } finally { removeFixture(root); }
    }
    private static void check(boolean value, String message) { if (!value) throw new AssertionError(message); }
    private static void removeFixture(Path root) throws IOException {
        try (java.util.stream.Stream<Path> stream = Files.walk(root)) {
            for (Path path : stream.sorted(Comparator.reverseOrder()).collect(Collectors.toList())) Files.delete(path);
        }
    }
}

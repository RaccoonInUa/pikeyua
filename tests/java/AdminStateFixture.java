import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import com.github.mphi_rc.fido2.AtomicStateFile;
import com.github.mphi_rc.fido2.ConfigurationFile;
import com.github.mphi_rc.fido2.authenticator.Credential;
import com.github.mphi_rc.fido2.authenticator.ImmutableCredential;
import com.github.mphi_rc.fido2.authenticator.crypto.P256AttestationKeyPair;

/** Real V7.3 serialization fixture; synthetic keys only, never USB/live state. */
public final class AdminStateFixture {
    private static String hex(byte[] value) {
        StringBuilder out = new StringBuilder();
        for (byte b : value) out.append(String.format("%02x", b & 255));
        return out.toString();
    }
    private static void check(boolean ok, String reason) {
        if (!ok) throw new AssertionError(reason);
    }
    private static String fingerprint(Credential c) throws Exception {
        MessageDigest hash = MessageDigest.getInstance("SHA-256");
        return hex(c.id()) + ":" + hex(hash.digest(c.keyPair().privateKey())) + ":"
                + hex(hash.digest(c.keyPair().publicKey())) + ":" + c.signatureCount()
                + ":" + c.userName() + ":" + c.userDisplayName() + ":" + c.discoverable();
    }
    private static void sign(Credential c) throws Exception {
        BouncyCastleProvider provider = new BouncyCastleProvider();
        KeyFactory factory = KeyFactory.getInstance("EC", provider);
        Signature signer = Signature.getInstance("SHA256withECDSA", provider);
        signer.initSign(factory.generatePrivate(new PKCS8EncodedKeySpec(c.keyPair().privateKey())));
        byte[] input = "admin-delete-survivor".getBytes(StandardCharsets.UTF_8);
        signer.update(input);
        byte[] signature = signer.sign();
        Signature verifier = Signature.getInstance("SHA256withECDSA", provider);
        verifier.initVerify(factory.generatePublic(new X509EncodedKeySpec(c.keyPair().publicKey())));
        verifier.update(input);
        check(verifier.verify(signature), "Surviving private key cannot sign");
    }
    public static void main(String[] args) throws Exception {
        check(args.length == 2, "Usage: AdminStateFixture <create|verify> <private-temp-directory>");
        Path dir = Paths.get(args[1]);
        Path file = dir.resolve("config.json");
        Path reference = dir.resolve("expected.txt");
        if ("create".equals(args[0])) {
            check(!Files.exists(file), "Test file already exists");
            ConfigurationFile config = new ConfigurationFile(file);
            config.persistToDisk();
            for (int i = 1; i <= 3; i++) {
                config.addCredential(ImmutableCredential.builder()
                    .relayingPartyId(i < 3 ? "admin.example.invalid" : "other.example.invalid")
                    .creation(Instant.ofEpochMilli(1700000000000L + i))
                    .userId(new byte[]{(byte) i}).keyPair(P256AttestationKeyPair.generate())
                    .signatureCount(i * 3).discoverable(i < 3)
                    .userName("synthetic-" + i).userDisplayName("Synthetic Account " + i).build());
            }
            byte[] pinHash = Arrays.copyOf(MessageDigest.getInstance("SHA-256")
                    .digest("synthetic-fixture-pin".getBytes(StandardCharsets.UTF_8)), 16);
            config.updatePinState(pinHash, 0); // Admin deletion must NOT refund a blocked budget.
            List<Credential> records = config.credentials();
            String expected = config.id() + "\n" + hex(config.getAaguid()) + "\n"
                    + Base64.getEncoder().encodeToString(config.pinHash().get()) + "\n"
                    + hex(records.get(0).id()) + "\n" + fingerprint(records.get(1)) + "\n"
                    + fingerprint(records.get(2)) + "\n";
            AtomicStateFile.write(reference, expected.getBytes(StandardCharsets.UTF_8));
            System.out.println("PASS: genuine V7.3 fixture created with RK, legacy credentials and blocked PIN");
        } else if ("verify".equals(args[0])) {
            ConfigurationFile config = new ConfigurationFile(file);
            List<String> lines = Files.readAllLines(reference, StandardCharsets.UTF_8);
            check(config.schemaVersion() == 3, "Schema changed");
            check(config.id().toString().equals(lines.get(0)), "Identity changed");
            check(hex(config.getAaguid()).equals(lines.get(1)), "AAGUID changed");
            check(Base64.getEncoder().encodeToString(config.pinHash().get()).equals(lines.get(2)), "PIN hash changed");
            check(config.pinRetries() == 0, "Deletion refunded blocked PIN attempts");
            check(config.credentials().size() == 2, "Must remove exactly one credential");
            check(config.credentials().stream().noneMatch(c -> hex(c.id()).equals(lines.get(3))), "Deleted credential remains");
            check(fingerprint(config.credentials().get(0)).equals(lines.get(4)), "RK survivor changed");
            check(fingerprint(config.credentials().get(1)).equals(lines.get(5)), "Legacy survivor changed");
            for (Credential c : config.credentials()) sign(c);
            System.out.println("PASS: fresh V7.3 JVM reads deletion; surviving IDs, keys, signatures, counters, PIN and AAGUID preserved");
        } else throw new IllegalArgumentException("Unsupported phase");
    }
}

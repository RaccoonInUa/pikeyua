package com.github.mphi_rc.fido2.authenticator.keys.pkcs11;

import java.lang.reflect.InvocationTargetException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.charset.StandardCharsets;
import java.security.AuthProvider;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.AlgorithmParameters;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.UUID;

/**
 * Experimental native signing primitive; NOT wired into the FIDO service.
 * A trusted caller supplies one explicit native module and one slot. No provider
 * search, software fallback, token initialization, PIN guessing or key import.
 * Public-key pinning prevents an alias on another token from silently replacing
 * a key. It is not device attestation and does not protect a compromised JVM.
 */
public final class Pkcs11P256Signer implements AutoCloseable {
    private final Provider provider;
    private final KeyStore store;
    private boolean closed;

    private Pkcs11P256Signer(Provider provider, KeyStore store) {
        this.provider = provider;
        this.store = store;
    }

    /** PIN is a token login credential, NOT the browser/FIDO PIN. Caller owns its buffer. */
    public static Pkcs11P256Signer open(Path library, long slot, char[] pin) throws Exception {
        if (library == null || !library.isAbsolute() || slot < 0 || slot > 0xffffffffL
                || pin == null || pin.length == 0) throw new IllegalArgumentException("Invalid token settings");
        Path real = library.toRealPath();
        if (!Files.isRegularFile(real) || !real.toString().matches("/[A-Za-z0-9_./+:-]+")) {
            throw new IllegalArgumentException("Unsupported native module path");
        }
        Provider base = Security.getProvider("SunPKCS11");
        if (base == null) throw new IllegalStateException("SunPKCS11 is unavailable");
        Path config = Files.createTempFile("pikeyua-p11-", ".cfg",
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        Provider configured = null;
        char[] ownedPin = pin.clone();
        try {
            String text = configuration(real, slot);
            Files.write(config, text.getBytes(StandardCharsets.UTF_8));
            // Public JDK 9+ API, reflected only to retain the project's --release 8 bytecode.
            // No sun.security.* exports or reflective access to JDK internals.
            configured = (Provider) Provider.class.getMethod("configure", String.class)
                    .invoke(base, config.toString());
            KeyStore store = KeyStore.getInstance("PKCS11", configured);
            store.load(null, ownedPin);
            return new Pkcs11P256Signer(configured, store);
        } catch (InvocationTargetException e) {
            if (configured instanceof AuthProvider) try { ((AuthProvider) configured).logout(); } catch (Exception ignored) { }
            throw new IllegalStateException("Native token initialization refused");
        } catch (Exception e) {
            if (configured instanceof AuthProvider) try { ((AuthProvider) configured).logout(); } catch (Exception ignored) { }
            throw e;
        } finally {
            Arrays.fill(ownedPin, '\0');
            Files.deleteIfExists(config);
        }
    }

    static String configuration(Path library, long slot) {
        return "name = Pikeyua" + UUID.randomUUID().toString().replace("-", "") + "\n"
                + "library = " + library + "\nslot = " + slot + "\nhandleStartupErrors = halt\n"
                + "attributes(generate, CKO_PRIVATE_KEY, CKK_EC) = {\n"
                + " CKA_TOKEN = true\n CKA_PRIVATE = true\n CKA_SENSITIVE = true\n"
                + " CKA_EXTRACTABLE = false\n CKA_SIGN = true\n CKA_DERIVE = false\n}\n"
                + "attributes(generate, CKO_PUBLIC_KEY, CKK_EC) = {\n"
                + " CKA_TOKEN = false\n CKA_VERIFY = true\n}\n";
    }

    /** Immutable public reference; not a bearer authorization or a hardware claim. */
    public static final class Reference {
        private final String alias;
        private final byte[] publicKey;
        public Reference(String alias, byte[] spki) throws Exception {
            if (alias == null || !alias.matches("[A-Za-z0-9_.-]{1,128}")
                    || spki == null || spki.length == 0 || spki.length > 1024) {
                throw new IllegalArgumentException("Invalid public token reference");
            }
            requireP256(KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(spki)));
            this.alias = alias;
            this.publicKey = spki.clone();
        }
        public String alias() { return alias; }
        public byte[] publicKey() { return publicKey.clone(); }
        @Override public String toString() { return "Pkcs11Reference[redacted]"; }
    }

    /** Caller constructs the exact FIDO signed bytes. Authorization stays outside this primitive. */
    public synchronized byte[] sign(Reference reference, byte[] message) throws Exception {
        if (closed) throw new IllegalStateException("Token session is closed");
        if (reference == null || message == null || message.length == 0 || message.length > 65536) {
            throw new IllegalArgumentException("Invalid signing request");
        }
        java.security.cert.Certificate certificate = store.getCertificate(reference.alias());
        if (certificate == null || !Arrays.equals(reference.publicKey, certificate.getPublicKey().getEncoded())) {
            throw new IllegalStateException("Token reference unavailable or public key differs");
        }
        requireP256(certificate.getPublicKey());
        Key key = store.getKey(reference.alias(), null);
        if (!(key instanceof PrivateKey) || !"EC".equals(key.getAlgorithm())) {
            throw new IllegalStateException("Token private key unavailable");
        }
        requireOpaque(key);
        Signature signer = Signature.getInstance("SHA256withECDSA", provider);
        signer.initSign((PrivateKey) key);
        signer.update(message);
        byte[] signature = signer.sign();
        // Pin the actual signer as well as its certificate mapping. Never return a
        // signature from a mismatched private object even if metadata was replaced.
        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(certificate.getPublicKey());
        verifier.update(message);
        if (!verifier.verify(signature)) {
            Arrays.fill(signature, (byte) 0);
            throw new IllegalStateException("Token returned a signature for a different key");
        }
        return signature;
    }

    static void requireOpaque(Key key) {
        byte[] encoded = key.getEncoded();
        if (encoded != null) {
            Arrays.fill(encoded, (byte) 0);
            throw new IllegalStateException("Exportable private keys are refused");
        }
        if (key.getFormat() != null) throw new IllegalStateException("Unexpected private-key encoding");
    }

    static void requireP256(PublicKey key) throws Exception {
        if (!(key instanceof ECPublicKey)) throw new IllegalArgumentException("P-256 public key required");
        AlgorithmParameters expected = AlgorithmParameters.getInstance("EC");
        expected.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec p = expected.getParameterSpec(ECParameterSpec.class);
        ECParameterSpec actual = ((ECPublicKey) key).getParams();
        if (actual == null || !p.getCurve().equals(actual.getCurve())
                || !p.getGenerator().equals(actual.getGenerator()) || !p.getOrder().equals(actual.getOrder())
                || p.getCofactor() != actual.getCofactor()) throw new IllegalArgumentException("Wrong EC curve");
    }

    // Package access is for the isolated qualification harness only. Public API
    // never returns the KeyStore, Provider or private-key object.
    KeyStore qualificationStore() { return store; }
    Provider qualificationProvider() { return provider; }

    @Override public synchronized void close() throws Exception {
        if (!closed) {
            closed = true;
            if (provider instanceof AuthProvider) ((AuthProvider) provider).logout();
        }
    }
}

package com.github.mphi_rc.fido2.authenticator.keys.pkcs11;

import java.nio.file.Paths;
import java.security.KeyPairGenerator;
import java.security.Key;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

public final class Pkcs11BoundaryChecks {
    interface Attempt { void run() throws Exception; }
    private static int count;
    private static void rejected(Attempt run) throws Exception {
        try { run.run(); } catch (Exception expected) { count++; return; }
        throw new AssertionError("Invalid input accepted");
    }
    private static void check(boolean ok) { if (!ok) throw new AssertionError("Boundary invariant failed"); count++; }
    public static void main(String[] args) throws Exception {
        count = 0;
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        byte[] pub = generator.generateKeyPair().getPublic().getEncoded();
        byte[] original = pub.clone();
        Pkcs11P256Signer.Reference ref = new Pkcs11P256Signer.Reference("pikeyua-lab-key", pub);
        pub[0] ^= 1;
        check(Arrays.equals(original, ref.publicKey()));
        byte[] result = ref.publicKey(); result[0] ^= 1;
        check(Arrays.equals(original, ref.publicKey()));
        check(!ref.toString().contains("pikeyua-lab-key"));
        rejected(() -> new Pkcs11P256Signer.Reference("", original));
        rejected(() -> new Pkcs11P256Signer.Reference("bad\nlabel", original));
        rejected(() -> new Pkcs11P256Signer.Reference("valid", new byte[1]));
        generator.initialize(new ECGenParameterSpec("secp384r1"));
        byte[] wrongCurve = generator.generateKeyPair().getPublic().getEncoded();
        rejected(() -> new Pkcs11P256Signer.Reference("valid", wrongCurve));
        rejected(() -> Pkcs11P256Signer.open(Paths.get("relative.so"), 1, new char[]{'1'}));
        rejected(() -> Pkcs11P256Signer.open(Paths.get("/nonexistent/pikeyua.so"), 1, new char[]{'1'}));
        rejected(() -> Pkcs11P256Signer.open(Paths.get("/nonexistent/pikeyua.so"), -1, new char[]{'1'}));
        rejected(() -> Pkcs11P256Signer.open(Paths.get("/nonexistent/pikeyua.so"), 1, new char[0]));
        Key exportable = new Key() {
            public String getAlgorithm() { return "EC"; }
            public String getFormat() { return "PKCS#8"; }
            public byte[] getEncoded() { return new byte[]{ 1 }; }
        };
        rejected(() -> Pkcs11P256Signer.requireOpaque(exportable));
        String config = Pkcs11P256Signer.configuration(Paths.get("/opt/native/module.so"), 42);
        check(config.contains("slot = 42\n") && !config.contains("slotListIndex"));
        check(config.contains("CKA_EXTRACTABLE = false") && config.contains("CKA_SENSITIVE = true"));
        check(config.contains("CKA_SIGN = true") && config.contains("handleStartupErrors = halt"));
        for (java.lang.reflect.Method method : Pkcs11P256Signer.class.getMethods()) {
            check(!java.security.PrivateKey.class.isAssignableFrom(method.getReturnType())
                    && method.getReturnType() != java.security.KeyStore.class
                    && method.getReturnType() != java.security.Provider.class);
        }
        System.out.println("PASS: " + count + " PKCS11 boundary assertions (no hardware required)");
    }
}

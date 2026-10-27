package com.github.mphi_rc.fido2.authenticator.keys.pkcs11;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.LinkOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.KeyStore;
import java.security.spec.ECGenParameterSpec;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.math.BigInteger;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

/** TEST SOURCES ONLY. Explicit, disposable tokens. Never runs against FIDO state. */
public final class Pkcs11LabProbe {
    private static final String ALIAS = "pikeyua-lab-key";
    public static void main(String[] args) throws Exception {
        if (args.length != 6 || !args[0].equals("--disposable-token")) {
            throw new IllegalArgumentException("--disposable-token <create|verify|delete|absent> <module> <slot> <pin-file> <public-ref>");
        }
        Path pinFile = Paths.get(args[4]);
        if (!Files.isRegularFile(pinFile, LinkOption.NOFOLLOW_LINKS)
                || !Files.getPosixFilePermissions(pinFile).equals(PosixFilePermissions.fromString("rw-------"))) {
            throw new IllegalArgumentException("Lab PIN file must be regular 0600");
        }
        byte[] rawPin = Files.readAllBytes(pinFile);
        char[] pin = new String(rawPin, StandardCharsets.US_ASCII).trim().toCharArray();
        Arrays.fill(rawPin, (byte) 0);
        Path refFile = Paths.get(args[5]);
        try (Pkcs11P256Signer token = Pkcs11P256Signer.open(Paths.get(args[2]), Long.parseLong(args[3]), pin)) {
            Arrays.fill(pin, '\0');
            KeyStore store = token.qualificationStore();
            switch (args[1]) {
                case "create": {
                    if (store.size() != 0 || Files.exists(refFile, LinkOption.NOFOLLOW_LINKS)) {
                        throw new IllegalStateException("Create requires a fresh dedicated token and new reference file");
                    }
                    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", token.qualificationProvider());
                    generator.initialize(new ECGenParameterSpec("secp256r1"));
                    KeyPair pair = generator.generateKeyPair();
                    Pkcs11P256Signer.requireOpaque(pair.getPrivate());
                    X509Certificate certificate = certificate(pair, token);
                    store.setKeyEntry(ALIAS, pair.getPrivate(), null,
                            new java.security.cert.Certificate[]{ certificate });
                    Pkcs11P256Signer.Reference ref = new Pkcs11P256Signer.Reference(ALIAS, pair.getPublic().getEncoded());
                    byte[] message = "pikeyua-p11-create-synthetic".getBytes(StandardCharsets.US_ASCII);
                    checkSignature(ref, message, token.sign(ref, message));
                    Files.write(refFile, ref.publicKey(), StandardOpenOption.CREATE_NEW);
                    break;
                }
                case "verify": {
                    Pkcs11P256Signer.Reference ref = reference(refFile);
                    byte[] message = new byte[69];
                    new java.security.SecureRandom().nextBytes(message);
                    checkSignature(ref, message, token.sign(ref, message));
                    // Substituted public key under an otherwise correct alias must fail.
                    KeyPairGenerator other = KeyPairGenerator.getInstance("EC");
                    other.initialize(new ECGenParameterSpec("secp256r1"));
                    Pkcs11P256Signer.Reference foreign = new Pkcs11P256Signer.Reference(ALIAS, other.generateKeyPair().getPublic().getEncoded());
                    try { token.sign(foreign, message); throw new AssertionError("Wrong public key accepted"); }
                    catch (IllegalStateException expected) { }
                    break;
                }
                case "delete": {
                    Pkcs11P256Signer.Reference ref = reference(refFile);
                    token.sign(ref, new byte[]{ 1 }); // Require a valid bound key before deletion.
                    store.deleteEntry(ALIAS);
                    if (store.containsAlias(ALIAS)) throw new AssertionError("Alias still exists");
                    break;
                }
                case "absent": {
                    Pkcs11P256Signer.Reference ref = reference(refFile);
                    try { token.sign(ref, new byte[]{ 1 }); throw new AssertionError("Absent key signed"); }
                    catch (IllegalStateException expected) { }
                    break;
                }
                default: throw new IllegalArgumentException("Unknown probe phase");
            }
            System.out.println("PASS: native PKCS11 " + args[1] + " (software test token; NOT hardware qualification)");
        } finally { Arrays.fill(pin, '\0'); }
    }
    private static Pkcs11P256Signer.Reference reference(Path path) throws Exception {
        return new Pkcs11P256Signer.Reference(ALIAS, Files.readAllBytes(path));
    }
    private static void checkSignature(Pkcs11P256Signer.Reference ref, byte[] message, byte[] sig) throws Exception {
        Signature verify = Signature.getInstance("SHA256withECDSA");
        verify.initVerify(java.security.KeyFactory.getInstance("EC").generatePublic(
                new java.security.spec.X509EncodedKeySpec(ref.publicKey())));
        verify.update(message);
        if (!verify.verify(sig)) throw new AssertionError("Independent signature verification failed");
    }
    private static X509Certificate certificate(KeyPair pair, Pkcs11P256Signer token) throws Exception {
        // This self-signed cert is ONLY Java PKCS11 alias metadata, never a FIDO
        // attestation chain, manufacturer identity or external trust anchor.
        AlgorithmIdentifier algorithm = new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA256);
        V3TBSCertificateGenerator generator = new V3TBSCertificateGenerator();
        generator.setSerialNumber(new ASN1Integer(BigInteger.ONE));
        generator.setSignature(algorithm);
        generator.setIssuer(new X500Name("CN=pikeyua disposable PKCS11 test"));
        generator.setSubject(new X500Name("CN=pikeyua disposable PKCS11 test"));
        generator.setStartDate(new Time(new Date(System.currentTimeMillis() - 60000)));
        generator.setEndDate(new Time(new Date(System.currentTimeMillis() + 86400000L)));
        generator.setSubjectPublicKeyInfo(SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded()));
        org.bouncycastle.asn1.x509.TBSCertificate tbs = generator.generateTBSCertificate();
        Signature signer = Signature.getInstance("SHA256withECDSA", token.qualificationProvider());
        signer.initSign(pair.getPrivate());
        signer.update(tbs.getEncoded("DER"));
        byte[] der = new DERSequence(new org.bouncycastle.asn1.ASN1Encodable[]{
                tbs, algorithm, new DERBitString(signer.sign()) }).getEncoded("DER");
        X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(der));
        cert.verify(pair.getPublic());
        return cert;
    }
}

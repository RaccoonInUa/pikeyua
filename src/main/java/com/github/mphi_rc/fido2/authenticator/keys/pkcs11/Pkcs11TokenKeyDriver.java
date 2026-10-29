package com.github.mphi_rc.fido2.authenticator.keys.pkcs11;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.Objects;

import com.github.mphi_rc.fido2.authenticator.keys.token.TokenKeyDriver;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

/**
 * Experimental PKCS#11 token adapter, not wired into the FIDO CLI.
 * An alias certificate is Java KeyStore metadata ONLY, never FIDO attestation.
 * Token-bound P-256 private key bytes are never returned to the caller.
 * Creation failures may leave native orphan objects; B2's write-ahead marker
 * intentionally denies further operations pending owner reconciliation.
 */
public final class Pkcs11TokenKeyDriver implements TokenKeyDriver {
    private final Pkcs11P256Signer token;
    public Pkcs11TokenKeyDriver(Pkcs11P256Signer token) {
        this.token = Objects.requireNonNull(token, "token");
    }
    private static void alias(String alias) {
        if (alias == null || !alias.matches("pk-[0-9a-f]{32}"))
            throw new IllegalArgumentException("Invalid token alias");
    }
    @Override public synchronized PublicKey generateP256(String alias) throws Exception {
        alias(alias);
        KeyStore store = token.qualificationStore();
        if (store.containsAlias(alias)) throw new IllegalStateException("Token alias already exists");
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", token.qualificationProvider());
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair pair = generator.generateKeyPair();
        Pkcs11P256Signer.requireOpaque(pair.getPrivate());
        Pkcs11P256Signer.requireP256(pair.getPublic());
        X509Certificate metadata = aliasCertificate(pair);
        store.setKeyEntry(alias, pair.getPrivate(), null, new java.security.cert.Certificate[]{metadata});
        PublicKey stored = store.getCertificate(alias).getPublicKey();
        if (!java.util.Arrays.equals(pair.getPublic().getEncoded(), stored.getEncoded()))
            throw new IllegalStateException("Stored token public key differs");
        // No key export: Java receives only a reference to the private object.
        return stored;
    }
    @Override public synchronized byte[] sign(String alias, byte[] signedBytes) throws Exception {
        alias(alias);
        KeyStore store = token.qualificationStore();
        java.security.cert.Certificate cert = store.getCertificate(alias);
        if (cert == null) throw new IllegalStateException("Missing PKCS11 alias");
        Pkcs11P256Signer.Reference ref =
                new Pkcs11P256Signer.Reference(alias, cert.getPublicKey().getEncoded());
        return token.sign(ref, signedBytes);
    }
    @Override public synchronized void delete(String alias) throws Exception {
        alias(alias);
        KeyStore store = token.qualificationStore();
        if (!store.containsAlias(alias)) throw new IllegalStateException("Missing PKCS11 alias");
        store.deleteEntry(alias);
        if (store.containsAlias(alias)) throw new IllegalStateException("PKCS11 alias still present");
    }
    @Override public synchronized void deleteIfMatches(String alias, byte[] expectedPublicKey) throws Exception {
        alias(alias);
        synchronized (token) {
            KeyStore store = token.qualificationStore();
            java.security.cert.Certificate cert = store.getCertificate(alias);
            if (cert == null || expectedPublicKey == null
                    || !java.util.Arrays.equals(expectedPublicKey, cert.getPublicKey().getEncoded()))
                throw new IllegalStateException("Pinned deletion key is absent or differs");
            // Verify actual private-key ownership, not just a replacement certificate.
            byte[] challenge = new byte[32]; new java.security.SecureRandom().nextBytes(challenge);
            byte[] proof = token.sign(new Pkcs11P256Signer.Reference(alias, expectedPublicKey), challenge);
            java.util.Arrays.fill(proof, (byte) 0);
            store.deleteEntry(alias);
            if (store.containsAlias(alias)) throw new IllegalStateException("Native deletion unconfirmed");
        }
    }
    private X509Certificate aliasCertificate(KeyPair pair) throws Exception {
        AlgorithmIdentifier algorithm = new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA256);
        V3TBSCertificateGenerator generator = new V3TBSCertificateGenerator();
        generator.setSerialNumber(new ASN1Integer(new BigInteger(128, new java.security.SecureRandom()).abs().add(BigInteger.ONE)));
        generator.setSignature(algorithm);
        generator.setIssuer(new X500Name("CN=pikeyua PKCS11 metadata"));
        generator.setSubject(new X500Name("CN=pikeyua PKCS11 metadata"));
        generator.setStartDate(new Time(new Date(System.currentTimeMillis() - 60000)));
        generator.setEndDate(new Time(new Date(System.currentTimeMillis() + 31536000000L)));
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

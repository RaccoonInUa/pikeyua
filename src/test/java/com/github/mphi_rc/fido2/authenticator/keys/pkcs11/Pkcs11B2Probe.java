package com.github.mphi_rc.fido2.authenticator.keys.pkcs11;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.util.Arrays;
import java.security.Signature;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import com.github.mphi_rc.fido2.authenticator.keys.*;
import com.github.mphi_rc.fido2.authenticator.keys.token.*;
import com.github.mphi_rc.fido2.authenticator.crypto.Algorithm;
import com.github.mphi_rc.fido2.protocol.ctap2.*;

/** Disposable software-token native B2 contract. NO personal FIDO state or device. */
public final class Pkcs11B2Probe {
    private static final String RP="pikeyua-b2.synthetic.invalid";
    private static final byte[] HASH=new byte[32];
    private static AuthenticatorData data(CredentialDescriptor c,boolean registration) {
        ImmutableAuthenticatorData.Builder b=ImmutableAuthenticatorData.builder()
          .relayingPartyId(c.relayingPartyId()).signatureCount(registration?0:c.signatureCount()+1)
          .isUserPresent(true).isUserVerified(true);
        if(registration)b.attestedCredentialData(c.encodeAttestedCredentialData(new byte[16]));
        return b.build();
    }
    private static void verify(CredentialDescriptor c,AuthenticatorData data,byte[] signature) throws Exception {
        Signature v=Signature.getInstance("SHA256withECDSA");
        v.initVerify(KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(c.publicKey())));
        v.update(data.asBytes());v.update(HASH);
        if(!v.verify(signature)) throw new AssertionError("Wrong FIDO signature");
    }
    public static void main(String[] args) throws Exception {
        if(args.length!=6 || !"--disposable-token".equals(args[0]))
            throw new IllegalArgumentException("B2 isolated test requires phase, native library, slot, PIN file, test directory");
        String phase=args[1];
        Path stateDir=Paths.get(args[5]);Path state=stateDir.resolve("b2-public-credentials.json");
        char[] pin=new String(Files.readAllBytes(Paths.get(args[4])),StandardCharsets.US_ASCII).trim().toCharArray();
        try(Pkcs11P256Signer token=Pkcs11P256Signer.open(Paths.get(args[2]),Long.parseLong(args[3]),pin)) {
            Pkcs11TokenKeyDriver driver=new Pkcs11TokenKeyDriver(token);
            try(DurableTokenCredentialBackend backend=new DurableTokenCredentialBackend(state,driver)) {
                if("create".equals(phase)) {
                    if(!backend.find(RP).isEmpty()) throw new AssertionError("B2 test state not empty");
                    CredentialDescriptor c=backend.create(RP,new byte[]{4,5},Algorithm.P256_ECDSA,true,"test","test");
                    AuthenticatorData registered=data(c,true);
                    verify(c,registered,backend.signRegistration(c.handle(),registered,HASH));
                    AuthenticatorData assertion=data(c,false);
                    verify(c,assertion,backend.signAssertion(c.handle(),assertion,HASH));
                    if(backend.find(RP).iterator().next().signatureCount()!=1)throw new AssertionError("Counter not persisted");
                } else if("verify".equals(phase)) {
                    CredentialDescriptor c=backend.find(RP).iterator().next();
                    AuthenticatorData assertion=data(c,false);
                    verify(c,assertion,backend.signAssertion(c.handle(),assertion,HASH));
                } else if("delete".equals(phase)) {
                    CredentialDescriptor c=backend.find(RP).iterator().next();
                    backend.delete(c.handle());
                    if(!backend.find(RP).isEmpty())throw new AssertionError("Delete metadata remains");
                } else if("absent".equals(phase)) {
                    if(!backend.find(RP).isEmpty())throw new AssertionError("Deleted metadata revived");
                } else throw new IllegalArgumentException("Unknown B2 phase");
                System.out.println("PASS: B2 PKCS11 " + phase + " via disposable software token");
            }
        } finally {Arrays.fill(pin,'\0');}
    }
}

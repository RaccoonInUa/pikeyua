package com.github.mphi_rc.fido2.authenticator.keys.token;

import static org.junit.Assert.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import com.github.mphi_rc.fido2.authenticator.keys.*;
import com.github.mphi_rc.fido2.authenticator.crypto.Algorithm;
import com.github.mphi_rc.fido2.protocol.ctap2.*;

public class DurableTokenCredentialBackendTest {
    @Rule public TemporaryFolder temp = new TemporaryFolder();
    private Path state() throws Exception {
        Path d=temp.newFolder("token-"+UUID.randomUUID()).toPath();
        Files.setPosixFilePermissions(d,PosixFilePermissions.fromString("rwx------"));
        return d.resolve("credentials.json");
    }
    private static final class Fake implements TokenKeyDriver {
        final Map<String,KeyPair> keys = new HashMap<>();
        boolean refuseGenerate, refuseSign, refuseDelete;
        @Override public PublicKey generateP256(String alias) throws Exception {
            if(refuseGenerate) throw new IllegalStateException("generation failed");
            KeyPairGenerator g=KeyPairGenerator.getInstance("EC");g.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair pair=g.generateKeyPair();keys.put(alias,pair);return pair.getPublic();
        }
        @Override public byte[] sign(String alias,byte[] message) throws Exception {
            if(refuseSign)throw new IllegalStateException("signing failed");
            KeyPair p=keys.get(alias);if(p==null)throw new IllegalStateException("missing key");
            Signature s=Signature.getInstance("SHA256withECDSA");s.initSign(p.getPrivate());s.update(message);return s.sign();
        }
        @Override public void delete(String alias) throws Exception {
            if(refuseDelete)throw new IllegalStateException("deletion refused");
            if(keys.remove(alias)==null)throw new IllegalStateException("missing key");
        }
    }
    private static final String RP="example.test";
    private static final byte[] HASH=new byte[32];
    private static AuthenticatorData data(CredentialDescriptor c,boolean attested) {
        ImmutableAuthenticatorData.Builder b=ImmutableAuthenticatorData.builder()
                .relayingPartyId(c.relayingPartyId()).isUserPresent(true).isUserVerified(true)
                .signatureCount(attested?0:c.signatureCount()+1);
        if(attested)b.attestedCredentialData(c.encodeAttestedCredentialData(new byte[16]));
        return b.build();
    }
    private static CredentialDescriptor create(DurableTokenCredentialBackend b) {
        return b.create(RP,new byte[]{1,2},Algorithm.P256_ECDSA,true,"synthetic","synthetic");
    }
    @Test public void createSignRestartAndNoSecretsOnDisk() throws Exception {
        Path file=state();Fake f=new Fake();CredentialDescriptor first;
        try(DurableTokenCredentialBackend b=new DurableTokenCredentialBackend(file,f)){
            first=create(b);
            byte[] sig=b.signRegistration(first.handle(),data(first,true),HASH);
            assertTrue(sig.length>16);
            assertEquals(1,b.find(RP).size());
            assertEquals(32,first.id().length);
            assertEquals(0,first.signatureCount());
            b.signAssertion(first.handle(),data(first,false),HASH);
            assertEquals(1,b.find(RP).iterator().next().signatureCount());
            String saved=new String(Files.readAllBytes(file),StandardCharsets.UTF_8);
            assertFalse(saved.contains("PRIVATE KEY"));
            assertFalse(saved.contains("privateKey"));
            assertEquals("rw-------",PosixFilePermissions.toString(Files.getPosixFilePermissions(file)));
        }
        try(DurableTokenCredentialBackend b=new DurableTokenCredentialBackend(file,f)){
            CredentialDescriptor restored=b.find(RP).iterator().next();
            assertArrayEquals(first.id(),restored.id());
            assertEquals(1,restored.signatureCount());
            b.signAssertion(restored.handle(),data(restored,false),HASH);
            assertEquals(2,b.find(RP).iterator().next().signatureCount());
        }
    }
    @Test public void noSilentFallbackAndWrongTokenRejected() throws Exception {
        Path file=state();Fake f=new Fake();CredentialDescriptor c;
        try(DurableTokenCredentialBackend b=new DurableTokenCredentialBackend(file,f)){c=create(b);}
        Fake foreign=new Fake();
        try(DurableTokenCredentialBackend b=new DurableTokenCredentialBackend(file,foreign)){
            try {b.signAssertion(c.handle(),data(c,false),HASH);fail("Signed without original key");}
            catch(IllegalStateException expected){}
            assertEquals(0,b.find(RP).iterator().next().signatureCount());
        }
    }
    @Test public void persistentMutationFenceSurvivesReboot() throws Exception {
        Path file=state();Fake f=new Fake();f.refuseGenerate=true;
        try(DurableTokenCredentialBackend b=new DurableTokenCredentialBackend(file,f)){
            try {create(b);fail("Generation succeeded");}catch(IllegalStateException expected){}
            try {b.find(RP);fail("Uncertain backend still available");}catch(IllegalStateException expected){}
        }
        try {new DurableTokenCredentialBackend(file,new Fake());fail("Unresolved intent ignored");}
        catch(IllegalStateException expected){}
        assertTrue(new String(Files.readAllBytes(file),StandardCharsets.UTF_8).contains("\"pending\""));
    }
    @Test public void singleOwnerLockAndReadonlyListing() throws Exception {
        Path file=state();Fake f=new Fake();
        try(DurableTokenCredentialBackend first=new DurableTokenCredentialBackend(file,f)){
            try {new DurableTokenCredentialBackend(file,f);fail("Second writer accepted");}
            catch(Exception expected){}
            assertTrue(first.find(RP).isEmpty());
        }
        try(DurableTokenCredentialBackend second=new DurableTokenCredentialBackend(file,f)){
            assertTrue(second.find(RP).isEmpty());
        }
    }
    @Test public void staleCountersAreRefusedAndDoNotMutate() throws Exception {
        Path file=state();Fake f=new Fake();
        try(DurableTokenCredentialBackend b=new DurableTokenCredentialBackend(file,f)){
            CredentialDescriptor original=create(b);
            AuthenticatorData one=data(original,false);
            b.signAssertion(original.handle(),one,HASH);
            try {b.signAssertion(original.handle(),one,HASH);fail("Stale count signed");}
            catch(IllegalStateException expected){}
            assertEquals(1,b.find(RP).iterator().next().signatureCount());
        }
    }
    @Test public void deletionIsDurableAndFailureIsSticky() throws Exception {
        Path file=state();Fake f=new Fake();
        try(DurableTokenCredentialBackend b=new DurableTokenCredentialBackend(file,f)){
            CredentialDescriptor c=create(b);
            b.delete(c.handle());
            assertTrue(b.find(RP).isEmpty());
        }
        try(DurableTokenCredentialBackend b=new DurableTokenCredentialBackend(file,f)){
            CredentialDescriptor c=create(b);f.refuseDelete=true;
            try{b.delete(c.handle());fail("Deletion succeeded");}catch(IllegalStateException expected){}
        }
        try{new DurableTokenCredentialBackend(file,f);fail("Failed delete auto-reconciled");}
        catch(IllegalStateException expected){}
    }
    @Test public void discoverableReplacementKeepsOnlyNewMetadata() throws Exception {
        Path file=state();Fake f=new Fake();
        try(DurableTokenCredentialBackend b=new DurableTokenCredentialBackend(file,f)){
            CredentialDescriptor a=create(b), c=create(b);
            assertFalse(Arrays.equals(a.id(),c.id()));
            assertEquals(1,b.find(RP).size());
            assertArrayEquals(c.id(),b.find(RP).iterator().next().id());
            assertEquals(2,f.keys.size()); // obsolete object retained for operator reconciliation
        }
    }
    @Test public void actualAuthenticatorUsesTokenBackendForRegistrationAndDiscovery() throws Exception {
        Path file=state();Fake driver=new Fake();
        Path legacy=file.getParent().resolve("config.json");
        com.github.mphi_rc.fido2.ConfigurationFile config=new com.github.mphi_rc.fido2.ConfigurationFile(legacy);
        config.persistToDisk();
        com.github.mphi_rc.fido2.authenticator.PinState pin=new com.github.mphi_rc.fido2.authenticator.PinState(config);
        try(DurableTokenCredentialBackend backend=new DurableTokenCredentialBackend(file,driver)) {
            com.github.mphi_rc.fido2.authenticator.Authenticator authenticator=
                new com.github.mphi_rc.fido2.authenticator.Authenticator(config,backend,pin,true,System::nanoTime);
            com.github.mphi_rc.fido2.protocol.ctap2.MakeCredentialRequest request=
                com.github.mphi_rc.fido2.protocol.ctap2.ImmutableMakeCredentialRequest.builder()
                .relayingPartyId(RP).clientDataHash(HASH).userId(new byte[]{1,2})
                .addSupportedAlgorithmIds(-7).residentKeyRequested(true).build();
            com.github.mphi_rc.fido2.protocol.ctap2.MakeCredentialResponse registration=
                authenticator.makeCredential(request).<com.github.mphi_rc.fido2.protocol.ctap2.MakeCredentialResponse>handleError(e->{throw new AssertionError("Registration denied");}).elseGet(x->x);
            CredentialDescriptor credential=backend.find(RP).iterator().next();
            assertArrayEquals(credential.id(),Arrays.copyOfRange(registration.authData(),55,87));
            com.github.mphi_rc.fido2.protocol.ctap2.GetAssertionRequest assertion=
                com.github.mphi_rc.fido2.protocol.ctap2.ImmutableGetAssertionRequest.builder()
                .relayingPartyId(RP).clientDataHash(HASH).build();
            com.github.mphi_rc.fido2.protocol.ctap2.GetAssertionResponse response=
                authenticator.getAssertion(assertion).<com.github.mphi_rc.fido2.protocol.ctap2.GetAssertionResponse>handleError(e->{throw new AssertionError("Assertion denied");}).elseGet(x->x);
            assertArrayEquals(credential.id(),response.credentialId());
            assertEquals(1,backend.find(RP).iterator().next().signatureCount());
            assertTrue(config.credentials().isEmpty());
        }
    }
}

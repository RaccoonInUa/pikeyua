package com.github.mphi_rc.fido2.authenticator.keys.token;

import static org.junit.Assert.*;
import com.github.mphi_rc.fido2.AtomicStateFile;
import com.github.mphi_rc.fido2.authenticator.keys.CredentialDescriptor;
import com.github.mphi_rc.fido2.authenticator.crypto.Algorithm;
import com.github.mphi_rc.fido2.protocol.ctap2.*;
import com.google.gson.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.*;
import org.junit.rules.TemporaryFolder;

public class TokenRecoveryTest {
    @Rule public TemporaryFolder temp = new TemporaryFolder();
    private Path state, redo, marker;
    private SyntheticFileToken driver;
    private static final String RP = "unit.synthetic.invalid";
    private static final byte[] HASH = new byte[32];
    interface Checked { void run() throws Exception; }
    private static void denied(Checked action) throws Exception {
        try { action.run(); fail("Unsafe operation accepted"); } catch (IOException | IllegalStateException | IllegalArgumentException expected) { }
    }
    @Before public void prepare() throws Exception {
        Path root = temp.getRoot().toPath().toRealPath();
        Path metadata = Files.createDirectory(root.resolve("state"), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        Path token = Files.createDirectory(root.resolve("token"), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        state = metadata.resolve("credentials.json"); redo = metadata.resolve("credentials.json.redo");
        marker = metadata.resolve("credentials.json.initialized"); driver = new SyntheticFileToken(token);
    }
    private DurableTokenCredentialBackend open() throws Exception { return new DurableTokenCredentialBackend(state, driver); }
    private CredentialDescriptor create(DurableTokenCredentialBackend b, int user) {
        return b.create(RP, new byte[]{(byte)user}, Algorithm.P256_ECDSA, true, "synthetic", "Synthetic");
    }
    private AuthenticatorData data(CredentialDescriptor c) {
        return ImmutableAuthenticatorData.builder().relayingPartyId(RP).signatureCount(c.signatureCount()+1)
                .isUserPresent(true).isUserVerified(true).build();
    }
    private CredentialDescriptor seed() throws Exception {
        try (DurableTokenCredentialBackend b = open()) {
            CredentialDescriptor c = create(b, 1); b.signAssertion(c.handle(), data(c), HASH);
            return b.find(RP).iterator().next();
        }
    }
    private JsonObject json(Path p) throws Exception {
        return new JsonParser().parse(new String(Files.readAllBytes(p),StandardCharsets.UTF_8)).getAsJsonObject();
    }
    private void writeBoth(JsonObject object) throws Exception {
        object.remove("checksum"); object.addProperty("checksum", Base64.getEncoder().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(object.toString().getBytes(StandardCharsets.UTF_8))));
        byte[] bytes=object.toString().getBytes(StandardCharsets.UTF_8); AtomicStateFile.write(state,bytes);AtomicStateFile.write(redo,bytes);
    }
    private void assertOriginal(CredentialDescriptor old, int counter) throws Exception {
        try (DurableTokenCredentialBackend b=open()) {
            CredentialDescriptor c=b.find(RP).iterator().next();assertArrayEquals(old.id(),c.id());
            assertArrayEquals(old.publicKey(),c.publicKey()); assertEquals(counter,c.signatureCount());
            assertTrue(b.signAssertion(c.handle(),data(c),HASH).length>0);
        }
    }
    @Test public void corruptCurrentRecoversExactNewestGeneration() throws Exception {
        CredentialDescriptor c=seed();AtomicStateFile.write(state,"{broken".getBytes(StandardCharsets.UTF_8));assertOriginal(c,1);
    }
    @Test public void missingCurrentRecoversWithoutEmptyInitialization() throws Exception {
        CredentialDescriptor c=seed();Files.delete(state);assertOriginal(c,1);
    }
    @Test public void missingRedoRefusesEvenWhenCurrentLooksValid() throws Exception {
        seed();byte[] saved=Files.readAllBytes(state);Files.delete(redo);denied(this::open);assertArrayEquals(saved,Files.readAllBytes(state));
    }
    @Test public void corruptRedoDoesNotFallBackToPossiblyStaleCurrent() throws Exception {
        seed();byte[] saved=Files.readAllBytes(state);AtomicStateFile.write(redo,"[]".getBytes(StandardCharsets.UTF_8));
        denied(this::open);assertArrayEquals(saved,Files.readAllBytes(state));
    }
    @Test public void bothSnapshotsMissingNeverResetIdentity() throws Exception {
        seed();Files.delete(state);Files.delete(redo);denied(this::open);assertFalse(Files.exists(state));
    }
    @Test public void missingMarkerDoesNotAdoptState() throws Exception { seed();Files.delete(marker);denied(this::open); }
    @Test public void sameGenerationDifferentValidSnapshotsRefused() throws Exception {
        seed();byte[] old=Files.readAllBytes(state);JsonObject modified=json(state);
        modified.getAsJsonArray("entries").get(0).getAsJsonObject().addProperty("name","different");
        writeBoth(modified);AtomicStateFile.write(state,old);denied(this::open);
    }
    @Test public void olderRedoCannotRegressAnAcknowledgedCounter() throws Exception {
        CredentialDescriptor c=seed();byte[] old=Files.readAllBytes(redo);
        try(DurableTokenCredentialBackend b=open()){b.signAssertion(c.handle(),data(c),HASH);}
        AtomicStateFile.write(redo,old);denied(this::open);
    }
    @Test public void failedCounterAfterRedoConsumesCountButReleasesNoSignature() throws Exception {
        CredentialDescriptor c=seed();AtomicBoolean hit=new AtomicBoolean();
        try(DurableTokenCredentialBackend b=new DurableTokenCredentialBackend(state,driver,name->{
            if(name.equals("counter.redo.dir_synced")){hit.set(true);throw new IOException("synthetic write interruption");}
        })){
            denied(()->b.signAssertion(c.handle(),data(c),HASH));assertTrue(hit.get());denied(()->b.find(RP));
        }
        assertOriginal(c,2);
    }
    @Test public void failedCounterBeforeRedoPublicationDoesNotInventCommit() throws Exception {
        CredentialDescriptor c=seed();
        try(DurableTokenCredentialBackend b=new DurableTokenCredentialBackend(state,driver,name->{
            if(name.equals("counter.redo.file_synced"))throw new IOException("synthetic rename failure");
        })){denied(()->b.signAssertion(c.handle(),data(c),HASH));}
        assertOriginal(c,1);
    }
    @Test public void interruptedReplacementBeforePublicationPreservesOldAccount() throws Exception {
        CredentialDescriptor old=seed();
        try(DurableTokenCredentialBackend b=new DurableTokenCredentialBackend(state,driver,name->{
            if(name.equals("create.token_ready"))throw new IOException("synthetic interruption");
        })){denied(()->create(b,1));}
        try(DurableTokenCredentialBackend b=open()){
            assertEquals(Integer.valueOf(1),b.recoveryStatus().get("abortedCreates"));
            CredentialDescriptor c=b.find(RP).iterator().next();assertArrayEquals(old.id(),c.id());
            assertArrayEquals(old.publicKey(),c.publicKey());assertEquals(1,c.signatureCount());
        }
    }
    @Test public void deletionCleanupFailureDoesNotBlockOtherCredentialsOrResurrectTarget() throws Exception {
        seed();final TokenKeyDriver refusing=new TokenKeyDriver(){
            public PublicKey generateP256(String a)throws Exception{return driver.generateP256(a);}
            public byte[] sign(String a,byte[] b)throws Exception{return driver.sign(a,b);}
            public void delete(String a){throw new AssertionError("Unbound deletion invoked");}
        };
        CredentialDescriptor survivor;
        try(DurableTokenCredentialBackend b=new DurableTokenCredentialBackend(state,refusing)){
            CredentialDescriptor old=b.find(RP).iterator().next();survivor=create(b,2);
            denied(()->b.delete(old.handle()));assertEquals(1,b.find(RP).size());
            assertTrue(b.signAssertion(survivor.handle(),data(survivor),HASH).length>0);
        }
        try(DurableTokenCredentialBackend b=open()){
            assertEquals(1,b.find(RP).size());assertArrayEquals(survivor.id(),b.find(RP).iterator().next().id());
            assertEquals(1,b.reconcileDeletedObjects());assertEquals(Integer.valueOf(0),b.recoveryStatus().get("pendingDeletions"));
        }
    }
    @Test public void invalidRegistrationMetadataNeverReachesNativeToken() throws Exception {
        try(DurableTokenCredentialBackend b=open()){
            byte[] before=Files.readAllBytes(state);
            denied(()->b.create(RP,new byte[65],Algorithm.P256_ECDSA,true,"",""));
            denied(()->b.create(RP,new byte[0],Algorithm.P256_ECDSA,true,"",""));
            denied(()->b.create(RP,new byte[]{1},Algorithm.Ed25519,true,"",""));
            assertArrayEquals(before,Files.readAllBytes(state));
        }
    }
    @Test public void numericStringsFractionsBooleansAndUnknownFieldsRejected() throws Exception {
        seed();JsonObject good=json(state);
        for(String value:new String[]{"\"2\"","2.5","true","null","-1","4294967297"}){
            JsonObject bad=new JsonParser().parse(good.toString()).getAsJsonObject();
            bad.getAsJsonArray("entries").get(0).getAsJsonObject().add("counter",new JsonParser().parse(value));
            writeBoth(bad);denied(this::open);
        }
        JsonObject extra=new JsonParser().parse(good.toString()).getAsJsonObject();extra.addProperty("privateKey","never accepted");
        writeBoth(extra);denied(this::open);
    }
    @Test public void duplicateJsonFieldsAreNotLastOneWins() throws Exception {
        seed();String text=new String(Files.readAllBytes(state),StandardCharsets.UTF_8);
        text=text.replace("\"version\":2","\"version\":2,\"version\":2");
        AtomicStateFile.write(state,text.getBytes(StandardCharsets.UTF_8));AtomicStateFile.write(redo,text.getBytes(StandardCharsets.UTF_8));denied(this::open);
    }
    @Test public void duplicateAliasAcrossLiveAndRetiredRefused() throws Exception {
        seed();JsonObject doc=json(state);JsonObject e=doc.getAsJsonArray("entries").get(0).getAsJsonObject();
        JsonObject old=new JsonObject();old.add("alias",e.get("alias"));old.addProperty("reason","deleted");old.add("entry",e);old.addProperty("cleaned",false);
        doc.getAsJsonArray("retired").add(old);writeBoth(doc);denied(this::open);
    }
    @Test public void legacyV1IdleStateUpgradesWithoutChangingKeysOrCounters() throws Exception {
        CredentialDescriptor original=seed();JsonObject legacy=json(state);legacy.addProperty("version",1);
        legacy.remove("revision");legacy.remove("retired");legacy.remove("checksum");
        AtomicStateFile.write(state,legacy.toString().getBytes(StandardCharsets.UTF_8));Files.delete(redo);
        assertOriginal(original,1);assertEquals(2,json(state).get("version").getAsInt());
    }
    @Test public void legacyDestructivePendingStateRequiresOwnerReview() throws Exception {
        seed();JsonObject legacy=json(state);legacy.addProperty("version",1);legacy.remove("revision");legacy.remove("retired");legacy.remove("checksum");
        legacy.addProperty("pending","delete:"+legacy.getAsJsonArray("entries").get(0).getAsJsonObject().get("alias").getAsString());
        AtomicStateFile.write(state,legacy.toString().getBytes(StandardCharsets.UTF_8));Files.delete(redo);denied(this::open);
    }
    @Test public void unsafeSymlinkCannotBeReplacedByRecovery() throws Exception {
        seed();Path saved=state.resolveSibling("saved.json");Files.move(state,saved);Files.createSymbolicLink(state,saved);
        denied(this::open);assertTrue(Files.isSymbolicLink(state));
    }
    @Test public void externalStateWritePoisonsInsteadOfOverwriting() throws Exception {
        CredentialDescriptor c=seed();
        try(DurableTokenCredentialBackend b=open()){
            AtomicStateFile.write(state,"[]".getBytes(StandardCharsets.UTF_8));
            denied(()->b.signAssertion(c.handle(),data(c),HASH));denied(()->b.find(RP));
        }
        assertOriginal(c,1);
    }
}

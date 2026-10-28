package com.github.mphi_rc.fido2.authenticator.keys.token;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.EnumSet;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;

import com.github.mphi_rc.fido2.AtomicStateFile;
import com.github.mphi_rc.fido2.authenticator.CredentialStore;
import com.github.mphi_rc.fido2.authenticator.crypto.Algorithm;
import com.github.mphi_rc.fido2.authenticator.keys.CredentialBackend;
import com.github.mphi_rc.fido2.authenticator.keys.CredentialDescriptor;
import com.github.mphi_rc.fido2.authenticator.keys.KeyHandle;
import com.github.mphi_rc.fido2.protocol.ctap2.AuthenticatorData;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * Experimental isolated-token backend, deliberately NOT installed or enabled by the FIDO CLI.
 * Public metadata lives in a separate 0600 file. A persistent pending marker is written
 * before token-side mutations. Any uncertain mutation freezes further work for review.
 * One owner process holds an OS file lock for the backend lifetime.
 *
 * This is storage and protocol integration, NOT trusted user presence or PIN protection.
 */
public final class DurableTokenCredentialBackend implements CredentialBackend, AutoCloseable {
    public static final String PROVIDER = "token-p256-b2";
    private static final int VERSION = 1;
    private static final SecureRandom RANDOM = new SecureRandom();
    private final TokenKeyDriver driver;
    private final Path path;
    private final FileChannel lockChannel;
    private final FileLock lock;
    private final List<Entry> entries = new ArrayList<>();
    private String pending;
    private boolean poisoned;
    private boolean closed;

    public DurableTokenCredentialBackend(Path file, TokenKeyDriver driver) throws Exception {
        this.path = Objects.requireNonNull(file, "file").toAbsolutePath().normalize();
        this.driver = Objects.requireNonNull(driver, "driver");
        Path dir = path.getParent();
        if (dir == null || !Files.isDirectory(dir, LinkOption.NOFOLLOW_LINKS)
                || !Files.getPosixFilePermissions(dir).equals(PosixFilePermissions.fromString("rwx------")))
            throw new IllegalStateException("Private token state directory must be 0700");
        Path guard = dir.resolve(".pikeyua-token-owner.lock");
        if (Files.isSymbolicLink(guard)) throw new IllegalStateException("Unsafe lock");
        lockChannel = FileChannel.open(guard, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
        FileLock candidate = null;
        try {
            Files.setPosixFilePermissions(guard, PosixFilePermissions.fromString("rw-------"));
            candidate = lockChannel.tryLock();
            if (candidate == null) throw new IllegalStateException("Another token backend owns this state");
            lock = candidate;
            restore();
        } catch (Exception e) {
            if (candidate != null) candidate.release();
            lockChannel.close();
            throw e;
        }
    }
    private void ready() {
        if (closed || poisoned || pending != null) throw new IllegalStateException("Token state unavailable or requires reconciliation");
    }
    @Override public Set<Algorithm> supportedAlgorithms() { return Collections.unmodifiableSet(EnumSet.of(Algorithm.P256_ECDSA)); }
    @Override public synchronized Collection<CredentialDescriptor> find(String rpId) {
        ready();
        List<CredentialDescriptor> result = new ArrayList<>();
        for (Entry e : entries) if (e.rp.equals(rpId)) result.add(e.descriptor());
        return Collections.unmodifiableList(result);
    }
    @Override public synchronized CredentialDescriptor create(String rpId, byte[] userId, Algorithm algorithm,
            boolean discoverable, String userName, String userDisplayName) {
        ready();
        if (rpId == null || rpId.isEmpty() || userId == null || algorithm != Algorithm.P256_ECDSA
                || userName == null || userDisplayName == null) throw new IllegalArgumentException("Invalid registration");
        long count = entries.stream().filter(e -> e.discoverable).count();
        boolean replacing = false;
        for (Entry e : entries) if (discoverable && e.discoverable && e.rp.equals(rpId)
                && Arrays.equals(e.user, userId)) replacing = true;
        if (discoverable && count >= CredentialStore.MAX_DISCOVERABLE_CREDENTIALS && !replacing)
            throw new CredentialStore.Full();
        byte[] id = new byte[32]; RANDOM.nextBytes(id);
        String alias = "pk-" + UUID.randomUUID().toString().replace("-", "");
        // Fail closed after any uncertain token-side mutation.
        try {
            publish(alias, entries);
            PublicKey key = driver.generateP256(alias);
            if (!(key instanceof ECPublicKey)) throw new IllegalStateException("Token did not generate EC key");
            // Curve and returned-key checks are performed before admitting the public reference.
            byte[] spki = key.getEncoded();
            PublicKey validated = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(spki));
            byte[] cose = encodeP256((ECPublicKey) validated);
            Entry created = new Entry(alias, rpId, id, userId.clone(), spki, cose, System.currentTimeMillis(),
                    0, discoverable, userName, userDisplayName);
            List<Entry> next = new ArrayList<>(entries);
            if (discoverable) next.removeIf(e -> e.discoverable && e.rp.equals(rpId) && Arrays.equals(e.user, userId));
            next.add(created);
            publish(null, next);
            entries.clear(); entries.addAll(next);
            pending = null;
            // Superseded token objects are deliberately NOT deleted automatically: cleanup after
            // successful publication must be an owner-reviewed reconciliation step.
            return created.descriptor();
        } catch (Exception e) {
            poisoned = true;
            throw new IllegalStateException("Token registration uncertain; operator reconciliation required", e);
        }
    }
    @Override public synchronized byte[] signRegistration(KeyHandle handle, AuthenticatorData data, byte[] hash) {
        ready();
        Entry entry = resolve(handle, data, hash);
        if (entry.counter != 0 || data.signatureCount() != 0 || !data.attestedCredentialData().isPresent())
            throw new IllegalStateException("Registration not valid");
        return verifiedSign(entry, data, hash);
    }
    @Override public synchronized byte[] signAssertion(KeyHandle handle, AuthenticatorData data, byte[] hash) {
        ready();
        Entry entry = resolve(handle, data, hash);
        if (data.attestedCredentialData().isPresent() || entry.counter == Integer.MAX_VALUE
                || entry.counter < 0 || data.signatureCount() != entry.counter + 1)
            throw new IllegalStateException("Stale or exhausted counter");
        byte[] signature = verifiedSign(entry, data, hash);
        List<Entry> next = new ArrayList<>(entries);
        int index = entries.indexOf(entry);
        next.set(index, entry.withCounter(entry.counter + 1));
        try {
            publish(null, next);
            entries.clear(); entries.addAll(next);
            return signature;
        } catch (Exception e) {
            Arrays.fill(signature, (byte)0);
            poisoned = true;
            throw new IllegalStateException("Counter commit uncertain", e);
        }
    }
    @Override public synchronized void delete(KeyHandle handle) {
        ready();
        Entry entry = lookup(handle);
        try {
            publish("delete:" + entry.alias, entries);
            driver.delete(entry.alias);
            List<Entry> next = new ArrayList<>(entries);
            next.remove(entry);
            publish(null, next);
            entries.clear(); entries.addAll(next); pending = null;
        } catch (Exception e) {
            poisoned = true;
            throw new IllegalStateException("Deletion uncertain; operator reconciliation required", e);
        }
    }
    private Entry resolve(KeyHandle h, AuthenticatorData data, byte[] hash) {
        if (data == null || hash == null || hash.length != 32 || h == null || !h.rpId().equals(data.relayingPartyId()))
            throw new IllegalStateException("Invalid signing request");
        return lookup(h);
    }
    private Entry lookup(KeyHandle handle) {
        if (handle == null || !PROVIDER.equals(handle.provider())) throw new IllegalStateException("Foreign key provider");
        Entry found = null;
        for (Entry e : entries) if (e.rp.equals(handle.rpId()) && Arrays.equals(e.id, handle.id())) {
            if (found != null) throw new IllegalStateException("Ambiguous credential");
            found = e;
        }
        if (found == null) throw new IllegalStateException("Unknown credential");
        return found;
    }
    private byte[] verifiedSign(Entry entry, AuthenticatorData data, byte[] hash) {
        try {
            byte[] signed = join(data.asBytes(), hash);
            byte[] signature = driver.sign(entry.alias, signed);
            Signature v = Signature.getInstance("SHA256withECDSA");
            v.initVerify(KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(entry.publicKey)));
            v.update(signed);
            if (!v.verify(signature)) {
                Arrays.fill(signature, (byte) 0);
                throw new IllegalStateException("Token key mismatch");
            }
            return signature;
        } catch (Exception e) { throw new IllegalStateException("Token signing refused", e); }
    }
    private static byte[] join(byte[] a, byte[] b) {
        byte[] result = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, result, a.length, b.length); return result;
    }
    private static byte[] encodeP256(ECPublicKey key) throws Exception {
        java.security.AlgorithmParameters params = java.security.AlgorithmParameters.getInstance("EC");
        params.init(new java.security.spec.ECGenParameterSpec("secp256r1"));
        java.security.spec.ECParameterSpec expected = params.getParameterSpec(java.security.spec.ECParameterSpec.class);
        java.security.spec.ECParameterSpec p = key.getParams();
        if (p == null || !expected.getCurve().equals(p.getCurve()) || !expected.getGenerator().equals(p.getGenerator())
                || !expected.getOrder().equals(p.getOrder()) || expected.getCofactor() != p.getCofactor())
            throw new IllegalArgumentException("Only P-256 accepted");
        byte[] x = fixed32(key.getW().getAffineX()), y = fixed32(key.getW().getAffineY());
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        // COSE_Key: {1:2, 3:-7, -1:1, -2:x, -3:y}
        out.write(new byte[]{(byte)0xa5, 1, 2, 3, 0x26, 0x20, 1, 0x21, 0x58, 0x20});
        out.write(x); out.write(new byte[]{0x22, 0x58, 0x20}); out.write(y);
        return out.toByteArray();
    }
    private static byte[] fixed32(java.math.BigInteger n) {
        byte[] v = n.toByteArray();
        if (v.length > 33 || n.signum() < 0) throw new IllegalArgumentException("Invalid EC coordinate");
        byte[] out = new byte[32];
        if (v.length == 33 && v[0] != 0) throw new IllegalArgumentException("Invalid EC coordinate");
        int start = v.length == 33 ? 1 : 0, length = v.length - start;
        if (length > 32) throw new IllegalArgumentException("Invalid coordinate");
        System.arraycopy(v, start, out, 32 - length, length); return out;
    }
    private void restore() throws Exception {
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            publish(null, Collections.<Entry>emptyList());
            return;
        }
        JsonObject doc = new JsonParser().parse(new String(AtomicStateFile.read(path), StandardCharsets.UTF_8)).getAsJsonObject();
        if (!doc.has("version") || doc.get("version").getAsInt() != VERSION || !doc.has("entries")
                || !doc.get("entries").isJsonArray() || !doc.has("pending"))
            throw new IllegalStateException("Invalid token state schema");
        JsonElement p = doc.get("pending");
        pending = p.isJsonNull() ? null : p.getAsString();
        for (JsonElement raw : doc.getAsJsonArray("entries")) entries.add(Entry.parse(raw.getAsJsonObject()));
        if (entries.size() > 1024) throw new IllegalStateException("Credential capacity exceeded");
        for (int i = 0; i < entries.size(); i++)
            for (int j = i + 1; j < entries.size(); j++)
                if (entries.get(i).rp.equals(entries.get(j).rp)
                        && Arrays.equals(entries.get(i).id, entries.get(j).id))
                    throw new IllegalStateException("Duplicate credential ID");
        if (pending != null) throw new IllegalStateException("Unresolved token mutation; manual review required");
    }
    private void publish(String operation, List<Entry> next) throws Exception {
        JsonObject root = new JsonObject();
        root.addProperty("version", VERSION);
        if (operation == null) root.add("pending", com.google.gson.JsonNull.INSTANCE);
        else root.addProperty("pending", operation);
        JsonArray list = new JsonArray(); for (Entry entry : next) list.add(entry.json());
        root.add("entries", list);
        AtomicStateFile.write(path, root.toString().getBytes(StandardCharsets.UTF_8));
        pending = operation;
    }
    @Override public synchronized void close() throws Exception {
        if (!closed) { closed = true; lock.release(); lockChannel.close(); }
    }
    private static final class Entry {
        final String alias, rp, userName, displayName;
        final byte[] id, user, publicKey, cose;
        final long created;
        final int counter;
        final boolean discoverable;
        Entry(String alias, String rp, byte[] id, byte[] user, byte[] pub, byte[] cose,
                long created, int counter, boolean discoverable, String userName, String displayName) {
            this.alias=alias; this.rp=rp; this.id=id.clone(); this.user=user.clone();
            this.publicKey=pub.clone(); this.cose=cose.clone(); this.created=created;
            this.counter=counter; this.discoverable=discoverable; this.userName=userName; this.displayName=displayName;
        }
        Entry withCounter(int value) { return new Entry(alias,rp,id,user,publicKey,cose,created,value,discoverable,userName,displayName); }
        CredentialDescriptor descriptor() {
            return new CredentialDescriptor(new KeyHandle(PROVIDER,rp,id),id,Instant.ofEpochMilli(created),user,
                    Algorithm.P256_ECDSA,publicKey,cose,counter,discoverable,userName,displayName);
        }
        JsonObject json() {
            JsonObject o = new JsonObject();
            o.addProperty("alias",alias); o.addProperty("rp",rp); o.addProperty("id",b64(id));
            o.addProperty("user",b64(user)); o.addProperty("public",b64(publicKey));
            o.addProperty("cose",b64(cose)); o.addProperty("created",created);
            o.addProperty("counter",counter); o.addProperty("rk",discoverable);
            o.addProperty("name",userName); o.addProperty("display",displayName);
            return o;
        }
        static Entry parse(JsonObject o) throws Exception {
            String alias=o.get("alias").getAsString(), rp=o.get("rp").getAsString();
            if (!alias.matches("pk-[0-9a-f]{32}") || rp.isEmpty() || rp.length()>253) throw new IllegalStateException("Invalid credential metadata");
            byte[] id=unb64(o.get("id").getAsString()), user=unb64(o.get("user").getAsString());
            byte[] pub=unb64(o.get("public").getAsString()), cose=unb64(o.get("cose").getAsString());
            if (id.length!=32 || pub.length>1024 || cose.length!=77) throw new IllegalStateException("Invalid key metadata");
            PublicKey key=KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(pub));
            if (!Arrays.equals(cose,encodeP256((ECPublicKey)key))) throw new IllegalStateException("Public-key encoding mismatch");
            long created=o.get("created").getAsLong(); int counter=o.get("counter").getAsInt();
            if (created<=0 || counter<0) throw new IllegalStateException("Bad credential counter");
            return new Entry(alias,rp,id,user,pub,cose,created,counter,o.get("rk").getAsBoolean(),o.get("name").getAsString(),o.get("display").getAsString());
        }
        static String b64(byte[] b) { return Base64.getEncoder().encodeToString(b); }
        static byte[] unb64(String s) { return Base64.getDecoder().decode(s); }
    }
}

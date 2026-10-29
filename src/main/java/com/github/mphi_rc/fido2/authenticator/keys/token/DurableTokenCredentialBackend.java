package com.github.mphi_rc.fido2.authenticator.keys.token;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.time.Instant;
import java.util.*;

import com.github.mphi_rc.fido2.authenticator.CredentialStore;
import com.github.mphi_rc.fido2.authenticator.crypto.Algorithm;
import com.github.mphi_rc.fido2.authenticator.keys.CredentialBackend;
import com.github.mphi_rc.fido2.authenticator.keys.CredentialDescriptor;
import com.github.mphi_rc.fido2.authenticator.keys.KeyHandle;
import com.github.mphi_rc.fido2.protocol.ctap2.AuthenticatorData;
import com.google.gson.*;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;

/**
 * Experimental token credential backend, NOT selected by the installed FIDO CLI.
 *
 * Every publication durably replaces the redo snapshot BEFORE the current file.
 * Therefore recovery can roll forward, but must NEVER fall back to an older
 * backup (which could regress counters or resurrect a deleted credential).
 * A durable create intent preserves previous credentials if generation stops.
 * Deletion is logically committed before native cleanup; its tombstone survives
 * failure or process death. Only explicitly deleted, public-key-pinned objects
 * are eligible for cleanup. Aborted and superseded objects are retained.
 *
 * Assumptions: local POSIX storage honors fsync/atomic rename, one cooperative
 * writer, trusted directory/native module. Not anti-rollback against root, not
 * protection against whole-card failure, nor trusted FIDO PIN/UP enforcement.
 */
public final class DurableTokenCredentialBackend implements CredentialBackend, AutoCloseable {
    public static final String PROVIDER = "token-p256-b2";
    private static final int VERSION = 2, MAX_ACTIVE = 1024, MAX_RETIRED = 4096;
    // Kept stable so a valid B2-v1 store can be upgraded without a two-file marker transition.
    private static final byte[] MARKER = "pikeyua-token-b2-v1".getBytes(StandardCharsets.US_ASCII);
    private static final SecureRandom RANDOM = new SecureRandom();
    private final TokenKeyDriver driver;
    private final Path path, redo, marker;
    private final TokenStateFile.Checkpoint checkpoint;
    private final FileChannel lockChannel;
    private final FileLock lock;
    private Snapshot snapshot;
    private byte[] expectedBytes;
    private boolean poisoned, closed;
    private int replayedSnapshots, abortedCreates;

    public DurableTokenCredentialBackend(Path file, TokenKeyDriver driver) throws Exception {
        this(file, driver, TokenStateFile.NONE);
    }
    DurableTokenCredentialBackend(Path file, TokenKeyDriver driver, TokenStateFile.Checkpoint checkpoint) throws Exception {
        path = Objects.requireNonNull(file, "file").toAbsolutePath().normalize();
        this.driver = Objects.requireNonNull(driver, "driver");
        this.checkpoint = Objects.requireNonNull(checkpoint, "checkpoint");
        redo = path.resolveSibling(path.getFileName() + ".redo");
        marker = path.resolveSibling(path.getFileName() + ".initialized");
        TokenStateFile.validate(path);
        Path guard = path.getParent().resolve(".pikeyua-token-owner.lock");
        TokenStateFile.validate(guard);
        Set<OpenOption> options = new HashSet<>(Arrays.asList(StandardOpenOption.CREATE,
                StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS));
        lockChannel = FileChannel.open(guard, options,
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        FileLock candidate = null;
        try {
            candidate = lockChannel.tryLock();
            if (candidate == null) throw new IllegalStateException("Another backend owns this token state");
            lock = candidate;
            restore();
        } catch (Exception e) {
            try { if (candidate != null) candidate.release(); }
            finally { lockChannel.close(); }
            throw e;
        }
    }
    private void ready() {
        if (closed || poisoned || snapshot == null || snapshot.pending != null)
            throw new IllegalStateException("Token state is not ready; close and reopen for recovery");
    }
    @Override public Set<Algorithm> supportedAlgorithms() {
        return Collections.singleton(Algorithm.P256_ECDSA);
    }
    @Override public synchronized Collection<CredentialDescriptor> find(String rpId) {
        ready();
        List<CredentialDescriptor> result = new ArrayList<>();
        for (Entry e : snapshot.entries) if (e.rp.equals(rpId)) result.add(e.descriptor());
        return Collections.unmodifiableList(result);
    }
    /** Counts only; does not expose accounts, aliases, PINs or native secrets. */
    public synchronized Map<String, Integer> recoveryStatus() {
        ready();
        Map<String, Integer> result = new LinkedHashMap<>();
        result.put("replayedSnapshots", replayedSnapshots);
        result.put("abortedCreates", abortedCreates);
        result.put("activeCredentials", snapshot.entries.size());
        result.put("retainedObjects", snapshot.retired.size());
        result.put("pendingDeletions", (int) snapshot.retired.stream()
                .filter(r -> r.reason.equals("deleted") && !r.cleaned).count());
        return Collections.unmodifiableMap(result);
    }
    @Override public synchronized CredentialDescriptor create(String rpId, byte[] userId, Algorithm algorithm,
            boolean discoverable, String userName, String userDisplayName) {
        ready();
        validateAccount(rpId, userId, userName, userDisplayName);
        if (algorithm != Algorithm.P256_ECDSA) throw new IllegalArgumentException("Unsupported token algorithm");
        List<Entry> replaced = new ArrayList<>();
        for (Entry e : snapshot.entries) if (discoverable && e.discoverable && e.rp.equals(rpId)
                && Arrays.equals(e.user, userId)) replaced.add(e);
        if (snapshot.entries.size() >= MAX_ACTIVE && replaced.isEmpty()) throw new CredentialStore.Full();
        if (discoverable && replaced.isEmpty() && snapshot.entries.stream().filter(e -> e.discoverable).count()
                >= CredentialStore.MAX_DISCOVERABLE_CREDENTIALS) throw new CredentialStore.Full();
        // Reserve room for an aborted generation as well as retired replacement metadata.
        if (snapshot.retired.size() + Math.max(1, replaced.size()) > MAX_RETIRED)
            throw new IllegalStateException("Retained token object capacity reached; owner review required");
        byte[] id = new byte[32];
        do { RANDOM.nextBytes(id); } while (idExists(id));
        String alias;
        do { alias = "pk-" + UUID.randomUUID().toString().replace("-", ""); } while (aliasExists(alias));
        try {
            publish("intent", alias, snapshot.entries, snapshot.retired);
            PublicKey key = driver.generateP256(alias);
            if (!(key instanceof ECPublicKey)) throw new IllegalStateException("Token returned a non-EC key");
            byte[] spki = key.getEncoded();
            byte[] cose = encodeP256((ECPublicKey) KeyFactory.getInstance("EC")
                    .generatePublic(new X509EncodedKeySpec(spki)));
            Entry created = new Entry(alias, rpId, id, userId, spki, cose, System.currentTimeMillis(),
                    0, discoverable, userName, userDisplayName);
            // A misbound native alias must be detected before publishing a credential.
            proof(created);
            checkpoint.hit("create.token_ready");
            List<Entry> next = new ArrayList<>(snapshot.entries);
            next.removeAll(replaced);
            next.add(created);
            List<Retired> retired = new ArrayList<>(snapshot.retired);
            for (Entry old : replaced) retired.add(new Retired(old.alias, "superseded", old, false));
            publish("create", null, next, retired);
            checkpoint.hit("create.committed");
            return created.descriptor();
        } catch (Exception e) {
            poisoned = true;
            throw new IllegalStateException("Registration interrupted; reopen to recover the durable state", e);
        }
    }
    @Override public synchronized byte[] signRegistration(KeyHandle handle, AuthenticatorData data, byte[] hash) {
        ready();
        Entry entry = resolve(handle, data, hash);
        if (entry.counter != 0 || data.signatureCount() != 0 || !data.attestedCredentialData().isPresent())
            throw new IllegalStateException("Invalid registration signature request");
        byte[] attested = data.attestedCredentialData().get();
        if (attested.length < 18 || !Arrays.equals(attested,
                entry.descriptor().encodeAttestedCredentialData(Arrays.copyOf(attested, 16))))
            throw new IllegalStateException("Attested credential metadata differs from stored key");
        return verifiedSign(entry, join(data.asBytes(), hash));
    }
    @Override public synchronized byte[] signAssertion(KeyHandle handle, AuthenticatorData data, byte[] hash) {
        ready();
        Entry entry = resolve(handle, data, hash);
        if (data.attestedCredentialData().isPresent() || entry.counter == Integer.MAX_VALUE
                || data.signatureCount() != entry.counter + 1) throw new IllegalStateException("Stale or exhausted counter");
        byte[] signature = verifiedSign(entry, join(data.asBytes(), hash));
        try {
            checkpoint.hit("counter.signed");
            List<Entry> next = new ArrayList<>(snapshot.entries);
            next.set(next.indexOf(entry), entry.withCounter(entry.counter + 1));
            publish("counter", null, next, snapshot.retired);
            checkpoint.hit("counter.committed");
            return signature;
        } catch (Exception e) {
            Arrays.fill(signature, (byte) 0);
            poisoned = true;
            throw new IllegalStateException("Counter commit interrupted; no signature released", e);
        }
    }
    @Override public synchronized void delete(KeyHandle handle) {
        ready();
        Entry entry = lookup(handle);
        if (snapshot.retired.size() == MAX_RETIRED)
            throw new IllegalStateException("Retained token object capacity reached");
        List<Entry> next = new ArrayList<>(snapshot.entries);
        next.remove(entry);
        List<Retired> retired = new ArrayList<>(snapshot.retired);
        retired.add(new Retired(entry.alias, "deleted", entry, false));
        // This publication is the logical deletion. Recovery must not resurrect it,
        // even when the next token call fails or the process is killed there.
        publish("delete", null, next, retired);
        try {
            checkpoint.hit("delete.committed");
            cleanDeleted(entry.alias);
        } catch (Exception e) {
            throw new IllegalStateException("Credential deletion committed; native cleanup remains pending", e);
        }
    }
    /**
     * Explicit owner operation. Never runs from the constructor. Only already
     * deleted records, with their original pinned public keys, can be cleaned.
     * Missing/wrong token is a refusal, not proof of successful native erasure.
     */
    public synchronized int reconcileDeletedObjects() {
        ready();
        int completed = 0;
        List<String> aliases = new ArrayList<>();
        for (Retired r : snapshot.retired) if (r.reason.equals("deleted") && !r.cleaned) aliases.add(r.alias);
        for (String alias : aliases) {
            try { cleanDeleted(alias); completed++; }
            catch (Exception e) {
                throw new IllegalStateException("Native cleanup unconfirmed; committed credentials remain intact", e);
            }
        }
        return completed;
    }
    private void cleanDeleted(String alias) throws Exception {
        Retired target = snapshot.retired.stream().filter(r -> r.alias.equals(alias)).findFirst()
                .orElseThrow(() -> new IllegalStateException("No deletion tombstone"));
        if (!target.reason.equals("deleted") || target.cleaned || target.entry == null)
            throw new IllegalStateException("Object is not eligible for cleanup");
        driver.deleteIfMatches(alias, target.entry.publicKey.clone());
        checkpoint.hit("delete.token_removed");
        List<Retired> next = new ArrayList<>(snapshot.retired);
        next.set(next.indexOf(target), new Retired(alias, target.reason, target.entry, true));
        publish("cleanup", null, snapshot.entries, next);
    }
    private Entry resolve(KeyHandle handle, AuthenticatorData data, byte[] hash) {
        if (data == null || hash == null || hash.length != 32 || handle == null
                || !handle.rpId().equals(data.relayingPartyId())) throw new IllegalStateException("Invalid signing request");
        return lookup(handle);
    }
    private Entry lookup(KeyHandle handle) {
        if (handle == null || !PROVIDER.equals(handle.provider())) throw new IllegalStateException("Foreign key provider");
        for (Entry e : snapshot.entries) if (e.rp.equals(handle.rpId()) && Arrays.equals(e.id, handle.id())) return e;
        throw new IllegalStateException("Unknown credential");
    }
    private boolean idExists(byte[] id) {
        for (Entry e : snapshot.entries) if (Arrays.equals(e.id, id)) return true;
        for (Retired r : snapshot.retired) if (r.entry != null && Arrays.equals(r.entry.id, id)) return true;
        return false;
    }
    private boolean aliasExists(String alias) {
        for (Entry e : snapshot.entries) if (e.alias.equals(alias)) return true;
        for (Retired r : snapshot.retired) if (r.alias.equals(alias)) return true;
        return false;
    }
    private byte[] verifiedSign(Entry entry, byte[] message) {
        byte[] signature = null;
        try {
            signature = driver.sign(entry.alias, message);
            if (signature == null || signature.length == 0 || signature.length > 80)
                throw new IllegalStateException("Invalid token signature length");
            Signature v = Signature.getInstance("SHA256withECDSA");
            v.initVerify(KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(entry.publicKey)));
            v.update(message);
            if (!v.verify(signature)) throw new IllegalStateException("Token key mismatch");
            return signature;
        } catch (Exception e) {
            if (signature != null) Arrays.fill(signature, (byte) 0);
            throw new IllegalStateException("Token signing refused", e);
        }
    }
    private void proof(Entry entry) {
        byte[] nonce = new byte[32]; RANDOM.nextBytes(nonce);
        byte[] signature = verifiedSign(entry, join("pikeyua key-binding proof\0".getBytes(StandardCharsets.US_ASCII), nonce));
        Arrays.fill(signature, (byte) 0);
    }
    private void restore() throws Exception {
        TokenStateFile.validate(redo); TokenStateFile.validate(marker);
        boolean currentExists = Files.exists(path, LinkOption.NOFOLLOW_LINKS);
        boolean redoExists = Files.exists(redo, LinkOption.NOFOLLOW_LINKS);
        if (!Files.exists(marker, LinkOption.NOFOLLOW_LINKS)) {
            if (currentExists || redoExists) throw new IllegalStateException("Initialization marker missing");
            TokenStateFile.write(marker, MARKER, "marker", checkpoint);
            snapshot = new Snapshot(0, null, Collections.emptyList(), Collections.emptyList(), false);
            publish("initialize", null, snapshot.entries, snapshot.retired);
        } else {
            if (!Arrays.equals(MARKER, TokenStateFile.read(marker))) throw new IllegalStateException("Invalid initialization marker");
            Snapshot current = readSnapshot(path); // malformed current can be recovered from validated redo
            Snapshot journal = readSnapshot(redo);
            if (!redoExists) {
                if (current == null || !current.legacy)
                    throw new IllegalStateException("Recovery snapshot missing; refusing a possible rollback");
                // Valid, idle B2-v1 state is upgraded in place. Interrupted legacy
                // delete cannot safely prove which token was altered; refuse it.
                snapshot = current;
                publish("upgrade", current.pending, current.entries, current.retired);
            } else {
                if (journal == null || journal.legacy)
                    throw new IllegalStateException("Recovery snapshot corrupt; older state is not a safe fallback");
                if (current != null && !current.legacy) {
                    if (current.revision > journal.revision || journal.revision > current.revision + 1)
                        throw new IllegalStateException("Inconsistent recovery generations");
                    if (current.revision == journal.revision && !Arrays.equals(current.bytes(), journal.bytes()))
                        throw new IllegalStateException("Conflicting recovery snapshots");
                } else if (current != null && journal.revision != 1) {
                    throw new IllegalStateException("Invalid legacy upgrade generation");
                }
                byte[] bytes = journal.bytes();
                if (current == null || current.legacy || !Arrays.equals(current.bytes(), bytes)) {
                    TokenStateFile.write(path, bytes, "replay.state", checkpoint);
                    replayedSnapshots++;
                }
                snapshot = journal;
                expectedBytes = bytes;
            }
        }
        if (snapshot.pending != null) {
            List<Retired> retired = new ArrayList<>(snapshot.retired);
            retired.add(new Retired(snapshot.pending, "aborted-create", null, false));
            publish("recover", null, snapshot.entries, retired);
            abortedCreates++;
        }
    }
    private Snapshot readSnapshot(Path source) throws Exception {
        TokenStateFile.validate(source); // permissions/types/links are NOT repaired by content recovery
        if (!Files.exists(source, LinkOption.NOFOLLOW_LINKS)) return null;
        byte[] bytes = TokenStateFile.read(source);
        try { return Snapshot.parse(bytes); }
        catch (IllegalArgumentException | IllegalStateException | IOException e) { return null; }
    }
    private void publish(String stage, String pending, List<Entry> entries, List<Retired> retired) {
        try {
            if (expectedBytes != null && (!Arrays.equals(expectedBytes, TokenStateFile.read(path))
                    || !Arrays.equals(expectedBytes, TokenStateFile.read(redo))))
                throw new IOException("Token state changed outside its owning process");
            if (snapshot.revision == Long.MAX_VALUE) throw new IllegalStateException("Generation exhausted");
            Snapshot candidate = new Snapshot(snapshot.revision + 1, pending, entries, retired, false);
            candidate.validate();
            byte[] bytes = candidate.bytes();
            // Complete redo is newer than or equal to current at every acknowledged step.
            TokenStateFile.write(redo, bytes, stage + ".redo", checkpoint);
            TokenStateFile.write(path, bytes, stage + ".state", checkpoint);
            expectedBytes = bytes;
            snapshot = candidate;
        } catch (Exception e) {
            poisoned = true;
            throw new IllegalStateException("Token commit uncertain; reopen for roll-forward recovery", e);
        }
    }
    @Override public synchronized void close() throws Exception {
        if (!closed) { closed = true; try { lock.release(); } finally { lockChannel.close(); } }
    }
    private static byte[] join(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length); return out;
    }
    private static byte[] encodeP256(ECPublicKey key) throws Exception {
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec expected = params.getParameterSpec(ECParameterSpec.class), p = key.getParams();
        if (p == null || !expected.getCurve().equals(p.getCurve()) || !expected.getGenerator().equals(p.getGenerator())
                || !expected.getOrder().equals(p.getOrder()) || expected.getCofactor() != p.getCofactor())
            throw new IllegalArgumentException("Only P-256 accepted");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(new byte[]{(byte)0xa5, 1, 2, 3, 0x26, 0x20, 1, 0x21, 0x58, 0x20});
        out.write(fixed32(key.getW().getAffineX())); out.write(new byte[]{0x22, 0x58, 0x20});
        out.write(fixed32(key.getW().getAffineY())); return out.toByteArray();
    }
    private static byte[] fixed32(java.math.BigInteger value) {
        if (value.signum() < 0 || value.bitLength() > 256) throw new IllegalArgumentException("Invalid EC coordinate");
        byte[] raw = value.toByteArray(), result = new byte[32];
        int n = Math.min(32, raw.length); System.arraycopy(raw, raw.length - n, result, 32 - n, n); return result;
    }
    private static void validateAccount(String rp, byte[] user, String name, String display) {
        if (rp == null || rp.isEmpty() || utf8(rp) > 253 || rp.indexOf('\0') >= 0
                || user == null || user.length == 0 || user.length > 64
                || name == null || display == null || utf8(name) > 1024 || utf8(display) > 1024)
            throw new IllegalArgumentException("Invalid account metadata");
    }
    private static int utf8(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isHighSurrogate(c)) {
                if (++i == s.length() || !Character.isLowSurrogate(s.charAt(i)))
                    throw new IllegalArgumentException("Invalid Unicode metadata");
            } else if (Character.isLowSurrogate(c)) throw new IllegalArgumentException("Invalid Unicode metadata");
        }
        return s.getBytes(StandardCharsets.UTF_8).length;
    }
    private static String digest(JsonObject o) {
        try {
            return Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256")
                    .digest(o.toString().getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException e) { throw new IllegalStateException(e); }
    }
    private static void fields(JsonObject object, String... names) {
        if (object.entrySet().size() != names.length) throw new IllegalArgumentException("Unexpected state fields");
        for (String name : names) if (!object.has(name)) throw new IllegalArgumentException("Missing state field");
    }
    private static String string(JsonObject object, String name) {
        JsonElement e = object.get(name);
        if (e == null || !e.isJsonPrimitive() || !e.getAsJsonPrimitive().isString())
            throw new IllegalArgumentException("String required");
        return e.getAsString();
    }
    private static long number(JsonObject object, String name, long min, long max) {
        JsonElement e = object.get(name);
        if (e == null || !e.isJsonPrimitive() || !e.getAsJsonPrimitive().isNumber()
                || !e.getAsString().matches("0|[1-9][0-9]*")) throw new IllegalArgumentException("Integer required");
        long n = Long.parseLong(e.getAsString());
        if (n < min || n > max) throw new IllegalArgumentException("Integer outside range");
        return n;
    }
    private static boolean bool(JsonObject object, String name) {
        JsonElement e = object.get(name);
        if (e == null || !e.isJsonPrimitive() || !e.getAsJsonPrimitive().isBoolean())
            throw new IllegalArgumentException("Boolean required");
        return e.getAsBoolean();
    }
    private static byte[] decoded(JsonObject object, String name, int min, int max) {
        String encoded = string(object, name);
        if (encoded.length() > (max + 2) / 3 * 4) throw new IllegalArgumentException("Encoded field too large");
        byte[] raw = Base64.getDecoder().decode(encoded);
        if (raw.length < min || raw.length > max || !Base64.getEncoder().encodeToString(raw).equals(encoded))
            throw new IllegalArgumentException("Invalid encoded field");
        return raw;
    }
    private static final class Snapshot {
        final long revision;
        final String pending;
        final List<Entry> entries;
        final List<Retired> retired;
        final boolean legacy;
        Snapshot(long revision, String pending, List<Entry> entries, List<Retired> retired, boolean legacy) {
            this.revision = revision; this.pending = pending; this.entries = new ArrayList<>(entries);
            this.retired = new ArrayList<>(retired); this.legacy = legacy;
        }
        void validate() {
            if (entries.size() > MAX_ACTIVE || retired.size() > MAX_RETIRED
                    || (pending != null && (!pending.matches("pk-[0-9a-f]{32}") || retired.size() == MAX_RETIRED)))
                throw new IllegalArgumentException("Invalid state capacity/intent");
            Set<String> aliases = new HashSet<>(), ids = new HashSet<>(), residents = new HashSet<>();
            int residentCount = 0;
            for (Entry e : entries) {
                if (!aliases.add(e.alias) || !ids.add(Base64.getEncoder().encodeToString(e.id)))
                    throw new IllegalArgumentException("Duplicate active credential");
                if (e.discoverable) {
                    residentCount++;
                    if (!residents.add(e.rp + "\0" + Base64.getEncoder().encodeToString(e.user)))
                        throw new IllegalArgumentException("Duplicate resident account");
                }
            }
            if (residentCount > CredentialStore.MAX_DISCOVERABLE_CREDENTIALS) throw new IllegalArgumentException("Too many resident accounts");
            for (Retired r : retired) {
                if (!aliases.add(r.alias) || (r.entry != null && !ids.add(Base64.getEncoder().encodeToString(r.entry.id))))
                    throw new IllegalArgumentException("Retired object overlaps live state");
            }
            if (pending != null && aliases.contains(pending)) throw new IllegalArgumentException("Intent overlaps existing alias");
        }
        byte[] bytes() {
            JsonObject object = new JsonObject();
            object.addProperty("version", VERSION); object.addProperty("revision", revision);
            if (pending == null) object.add("pending", JsonNull.INSTANCE); else object.addProperty("pending", pending);
            JsonArray list = new JsonArray(); for (Entry entry : entries) list.add(entry.json()); object.add("entries", list);
            JsonArray old = new JsonArray(); for (Retired entry : retired) old.add(entry.json()); object.add("retired", old);
            object.addProperty("checksum", digest(object));
            return object.toString().getBytes(StandardCharsets.UTF_8);
        }
        static Snapshot parse(byte[] bytes) throws IOException {
            if (bytes.length > 8 * 1024 * 1024) throw new IllegalArgumentException("Oversized state");
            // REPORT malformed UTF-8, duplicate JSON keys, trailing input and coercions.
            String text;
            try { text = StandardCharsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(bytes)).toString(); }
            catch (java.nio.charset.CharacterCodingException e) { throw new IOException("Invalid state encoding", e); }
            JsonReader reader = new JsonReader(new StringReader(text)); reader.setLenient(false);
            JsonElement value = strictJson(reader, 0);
            if (reader.peek() != JsonToken.END_DOCUMENT || !value.isJsonObject()) throw new IOException("Invalid state document");
            JsonObject o = value.getAsJsonObject();
            int version = (int) number(o, "version", 1, VERSION);
            boolean legacy = version == 1;
            if (legacy) fields(o, "version", "pending", "entries");
            else {
                fields(o, "version", "revision", "pending", "entries", "retired", "checksum");
                String actual = string(o, "checksum"); o.remove("checksum");
                if (!actual.equals(digest(o))) throw new IllegalArgumentException("State checksum mismatch");
            }
            String pending = o.get("pending").isJsonNull() ? null : string(o, "pending");
            // Old delete called native mutation first. Never guess or auto-revive it.
            if (pending != null && !pending.matches("pk-[0-9a-f]{32}")) throw new IllegalArgumentException("Unknown or legacy destructive intent");
            if (!o.get("entries").isJsonArray() || (!legacy && !o.get("retired").isJsonArray()))
                throw new IllegalArgumentException("State array required");
            List<Entry> entries = new ArrayList<>(); List<Retired> retired = new ArrayList<>();
            for (JsonElement e : o.getAsJsonArray("entries")) {
                entries.add(Entry.parse(e.getAsJsonObject()));
                if (entries.size() > MAX_ACTIVE) throw new IllegalArgumentException("Too many entries");
            }
            if (!legacy) for (JsonElement e : o.getAsJsonArray("retired")) {
                retired.add(Retired.parse(e.getAsJsonObject()));
                if (retired.size() > MAX_RETIRED) throw new IllegalArgumentException("Too many retired entries");
            }
            Snapshot result = new Snapshot(legacy ? 0 : number(o, "revision", 1, Long.MAX_VALUE), pending, entries, retired, legacy);
            result.validate(); return result;
        }
    }
    private static JsonElement strictJson(JsonReader reader, int depth) throws IOException {
        if (depth > 12) throw new IOException("State nesting too deep");
        switch (reader.peek()) {
            case BEGIN_OBJECT:
                reader.beginObject(); JsonObject object = new JsonObject();
                while (reader.hasNext()) {
                    String key = reader.nextName();
                    if (object.has(key) || object.entrySet().size() > 16) throw new IOException("Duplicate/excessive state fields");
                    object.add(key, strictJson(reader, depth + 1));
                }
                reader.endObject(); return object;
            case BEGIN_ARRAY:
                reader.beginArray(); JsonArray array = new JsonArray();
                while (reader.hasNext()) {
                    if (array.size() >= MAX_RETIRED) throw new IOException("State array too large");
                    array.add(strictJson(reader, depth + 1));
                }
                reader.endArray(); return array;
            case STRING: return new JsonPrimitive(reader.nextString());
            case NUMBER: return new JsonPrimitive(new com.google.gson.internal.LazilyParsedNumber(reader.nextString()));
            case BOOLEAN: return new JsonPrimitive(reader.nextBoolean());
            case NULL: reader.nextNull(); return JsonNull.INSTANCE;
            default: throw new IOException("Unexpected state token");
        }
    }
    private static final class Retired {
        final String alias, reason;
        final Entry entry;
        final boolean cleaned;
        Retired(String alias, String reason, Entry entry, boolean cleaned) {
            this.alias = alias; this.reason = reason; this.entry = entry; this.cleaned = cleaned;
        }
        JsonObject json() {
            JsonObject o = new JsonObject(); o.addProperty("alias", alias); o.addProperty("reason", reason);
            o.add("entry", entry == null ? JsonNull.INSTANCE : entry.json()); o.addProperty("cleaned", cleaned); return o;
        }
        static Retired parse(JsonObject o) throws IOException {
            fields(o, "alias", "reason", "entry", "cleaned");
            String alias = string(o, "alias"), reason = string(o, "reason"); boolean cleaned = bool(o, "cleaned");
            if (!alias.matches("pk-[0-9a-f]{32}") || !Arrays.asList("aborted-create", "superseded", "deleted").contains(reason))
                throw new IllegalArgumentException("Invalid retired object");
            Entry entry = o.get("entry").isJsonNull() ? null : Entry.parse(o.getAsJsonObject("entry"));
            if (reason.equals("aborted-create") ? entry != null || cleaned
                    : entry == null || !alias.equals(entry.alias) || (reason.equals("superseded") && cleaned))
                throw new IllegalArgumentException("Inconsistent retired object");
            return new Retired(alias, reason, entry, cleaned);
        }
    }
    private static final class Entry {
        final String alias, rp, userName, displayName;
        final byte[] id, user, publicKey, cose;
        final long created;
        final int counter;
        final boolean discoverable;
        Entry(String alias, String rp, byte[] id, byte[] user, byte[] pub, byte[] cose,
                long created, int counter, boolean discoverable, String name, String display) {
            this.alias = alias; this.rp = rp; this.id = id.clone(); this.user = user.clone();
            this.publicKey = pub.clone(); this.cose = cose.clone(); this.created = created;
            this.counter = counter; this.discoverable = discoverable; userName = name; displayName = display;
        }
        Entry withCounter(int n) { return new Entry(alias, rp, id, user, publicKey, cose, created, n, discoverable, userName, displayName); }
        CredentialDescriptor descriptor() {
            return new CredentialDescriptor(new KeyHandle(PROVIDER, rp, id), id, Instant.ofEpochMilli(created), user,
                    Algorithm.P256_ECDSA, publicKey, cose, counter, discoverable, userName, displayName);
        }
        JsonObject json() {
            JsonObject o = new JsonObject(); o.addProperty("alias", alias); o.addProperty("rp", rp);
            o.addProperty("id", Base64.getEncoder().encodeToString(id)); o.addProperty("user", Base64.getEncoder().encodeToString(user));
            o.addProperty("public", Base64.getEncoder().encodeToString(publicKey)); o.addProperty("cose", Base64.getEncoder().encodeToString(cose));
            o.addProperty("created", created); o.addProperty("counter", counter); o.addProperty("rk", discoverable);
            o.addProperty("name", userName); o.addProperty("display", displayName); return o;
        }
        static Entry parse(JsonObject o) throws IOException {
            fields(o, "alias", "rp", "id", "user", "public", "cose", "created", "counter", "rk", "name", "display");
            String alias = string(o, "alias"), rp = string(o, "rp"), name = string(o, "name"), display = string(o, "display");
            if (!alias.matches("pk-[0-9a-f]{32}")) throw new IllegalArgumentException("Invalid alias");
            byte[] id = decoded(o, "id", 32, 32), user = decoded(o, "user", 1, 64);
            validateAccount(rp, user, name, display);
            byte[] pub = decoded(o, "public", 1, 1024), cose = decoded(o, "cose", 77, 77);
            try {
                PublicKey key = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(pub));
                if (!(key instanceof ECPublicKey) || !Arrays.equals(cose, encodeP256((ECPublicKey) key)))
                    throw new IllegalArgumentException("Invalid public key");
            } catch (Exception e) { throw new IOException("Invalid persisted token public key", e); }
            return new Entry(alias, rp, id, user, pub, cose, number(o, "created", 1, Long.MAX_VALUE),
                    (int) number(o, "counter", 0, Integer.MAX_VALUE), bool(o, "rk"), name, display);
        }
    }
}

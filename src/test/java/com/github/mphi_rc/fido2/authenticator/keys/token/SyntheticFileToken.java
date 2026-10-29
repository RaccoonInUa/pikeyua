package com.github.mphi_rc.fido2.authenticator.keys.token;

import com.github.mphi_rc.fido2.AtomicStateFile;
import com.google.gson.*;
import java.nio.charset.StandardCharsets;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.*;
import java.security.spec.*;
import java.util.*;

/** TEST SOURCES ONLY. Stores synthetic private keys on disk; emphatically NOT a secure token. */
public final class SyntheticFileToken implements TokenKeyDriver {
    private final Path root;
    public SyntheticFileToken(Path root) throws Exception {
        this.root = root.toAbsolutePath().normalize();
        if (!Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)
                || !Files.getPosixFilePermissions(root).equals(PosixFilePermissions.fromString("rwx------")))
            throw new IllegalArgumentException("Synthetic token directory must be 0700");
    }
    private Path path(String alias) {
        if (alias == null || !alias.matches("pk-[0-9a-f]{32}")) throw new IllegalArgumentException("Invalid test alias");
        return root.resolve(alias + ".json");
    }
    @Override public PublicKey generateP256(String alias) throws Exception {
        Path path = path(alias);
        if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) throw new IllegalStateException("Alias already exists");
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair pair = generator.generateKeyPair();
        JsonObject object = new JsonObject();
        object.addProperty("public", Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()));
        object.addProperty("syntheticPrivate", Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()));
        AtomicStateFile.write(path, object.toString().getBytes(StandardCharsets.UTF_8));
        return pair.getPublic();
    }
    private JsonObject read(String alias) throws Exception {
        return new JsonParser().parse(new String(AtomicStateFile.read(path(alias)), StandardCharsets.UTF_8)).getAsJsonObject();
    }
    @Override public byte[] sign(String alias, byte[] message) throws Exception {
        byte[] secret = Base64.getDecoder().decode(read(alias).get("syntheticPrivate").getAsString());
        try {
            PrivateKey key = KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(secret));
            Signature signer = Signature.getInstance("SHA256withECDSA");
            signer.initSign(key); signer.update(message); return signer.sign();
        } finally { Arrays.fill(secret, (byte) 0); }
    }
    @Override public void delete(String alias) throws Exception {
        Files.delete(path(alias));
        try (FileChannel channel = FileChannel.open(root, StandardOpenOption.READ)) { channel.force(true); }
    }
    @Override public void deleteIfMatches(String alias, byte[] pinned) throws Exception {
        if (!Arrays.equals(pinned, Base64.getDecoder().decode(read(alias).get("public").getAsString())))
            throw new IllegalStateException("Synthetic key differs");
        delete(alias);
    }
}

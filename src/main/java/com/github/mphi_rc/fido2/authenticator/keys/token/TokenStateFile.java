package com.github.mphi_rc.fido2.authenticator.keys.token;

import com.github.mphi_rc.fido2.AtomicStateFile;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Arrays;

/** POSIX writes; a checkpoint is an injected test seam, never an environment switch. */
final class TokenStateFile {
    interface Checkpoint { void hit(String name) throws IOException; }
    static final Checkpoint NONE = name -> { };
    private TokenStateFile() { }

    static void validate(Path path) throws IOException {
        Path dir = path.getParent();
        if (dir == null || !Files.isDirectory(dir, LinkOption.NOFOLLOW_LINKS)
                || !dir.toRealPath().equals(dir)
                || !Files.getPosixFilePermissions(dir).equals(PosixFilePermissions.fromString("rwx------")))
            throw new IOException("Private token directory must be real and 0700");
        if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
                    || Files.isSymbolicLink(path)
                    || !Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS)
                        .equals(PosixFilePermissions.fromString("rw-------"))
                    || !Files.getOwner(path, LinkOption.NOFOLLOW_LINKS).equals(Files.getOwner(dir))
                    || ((Number) Files.getAttribute(path, "unix:nlink", LinkOption.NOFOLLOW_LINKS)).longValue() != 1)
                throw new IOException("Unsafe token state file");
        }
    }
    static byte[] read(Path path) throws IOException {
        validate(path);
        return AtomicStateFile.read(path);
    }
    static void write(Path path, byte[] bytes, String stage, Checkpoint checkpoint) throws IOException {
        validate(path);
        if (bytes.length > 8 * 1024 * 1024) throw new IOException("Token state too large");
        Path temp = Files.createTempFile(path.getParent(), ".pikeyua-token-", ".tmp",
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        try {
            try (FileChannel channel = FileChannel.open(temp, StandardOpenOption.WRITE)) {
                ByteBuffer data = ByteBuffer.wrap(bytes);
                while (data.hasRemaining()) channel.write(data);
                channel.force(true);
            }
            checkpoint.hit(stage + ".file_synced");
            Files.move(temp, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            temp = null;
            checkpoint.hit(stage + ".renamed");
            try (FileChannel channel = FileChannel.open(path.getParent(), StandardOpenOption.READ)) {
                channel.force(true);
            }
            checkpoint.hit(stage + ".dir_synced");
        } finally {
            if (temp != null) Files.deleteIfExists(temp);
        }
    }
}

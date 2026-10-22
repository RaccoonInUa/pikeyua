package com.github.mphi_rc.fido2;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Objects;
import java.util.Set;

/**
 * POSIX-only persistent state storage. A successful return means that bytes
 * were written, flushed, atomically renamed and the containing directory
 * was flushed. Callers must not acknowledge a credential mutation on failure.
 */
public final class AtomicStateFile {
    private static final Set<PosixFilePermission> DIR_MODE =
            PosixFilePermissions.fromString("rwx------");
    private static final Set<PosixFilePermission> FILE_MODE =
            PosixFilePermissions.fromString("rw-------");
    private static final long MAX_STATE_BYTES = 16L * 1024 * 1024;

    private AtomicStateFile() { }

    private static void validatePrivateDirectory(Path parent) throws IOException {
        if (parent == null || !Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("Authenticator state directory does not exist: " + parent);
        }
        if (!Files.getPosixFilePermissions(parent, LinkOption.NOFOLLOW_LINKS).equals(DIR_MODE)) {
            throw new IOException("Authenticator state directory must have permissions 0700: " + parent);
        }
    }

    public static byte[] read(Path destination) throws IOException {
        Objects.requireNonNull(destination, "destination");
        Path target = destination.toAbsolutePath().normalize();
        validatePrivateDirectory(target.getParent());
        if (Files.isSymbolicLink(target) ||
                !Files.isRegularFile(target, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("Authenticator state is not a regular file");
        }
        if (!Files.getPosixFilePermissions(target, LinkOption.NOFOLLOW_LINKS).equals(FILE_MODE)) {
            throw new IOException("Authenticator state file must have permissions 0600");
        }
        if (Files.size(target) > MAX_STATE_BYTES) {
            throw new IOException("Authenticator state file exceeds maximum size");
        }
        return Files.readAllBytes(target);
    }

    public static void write(Path destination, byte[] contents) throws IOException {
        Objects.requireNonNull(destination, "destination");
        Objects.requireNonNull(contents, "contents");
        if (contents.length > MAX_STATE_BYTES) {
            throw new IOException("Authenticator state exceeds maximum size");
        }
        Path target = destination.toAbsolutePath().normalize();
        Path parent = target.getParent();
        validatePrivateDirectory(parent);
        if (Files.isSymbolicLink(target)) {
            throw new IOException("Refusing symlink for authenticator state");
        }
        Path temporary = Files.createTempFile(
                parent, ".pikeyua-state-", ".tmp",
                PosixFilePermissions.asFileAttribute(FILE_MODE));
        try {
            try (FileChannel output = FileChannel.open(temporary, StandardOpenOption.WRITE)) {
                ByteBuffer buffer = ByteBuffer.wrap(contents);
                while (buffer.hasRemaining()) {
                    output.write(buffer);
                }
                output.force(true);
            }
            Files.move(temporary, target,
                    StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING);
            temporary = null;
            // Make the directory entry durable as well as the file contents.
            try (FileChannel directory = FileChannel.open(parent, StandardOpenOption.READ)) {
                directory.force(true);
            }
        } finally {
            if (temporary != null) {
                Files.deleteIfExists(temporary);
            }
        }
    }
}

package com.github.mphi_rc.fido2;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.mphi_rc.fido2.authenticator.Credential;
import com.github.mphi_rc.fido2.authenticator.GsonAdaptersCredential;
import com.github.mphi_rc.fido2.authenticator.crypto.Algorithm;
import com.github.mphi_rc.fido2.authenticator.crypto.AttestationKeyPair;
import com.github.mphi_rc.fido2.authenticator.crypto.GsonAdaptersEd25519AttestationKeyPair;
import com.github.mphi_rc.fido2.authenticator.crypto.GsonAdaptersP256AttestationKeyPair;
import com.github.mphi_rc.fido2.authenticator.user.AlwaysAllowUserVerifier;
import com.github.mphi_rc.fido2.authenticator.user.UserVerifier;
import com.github.mphi_rc.gson.AttestationKeyPairTypeAdapter;
import com.github.mphi_rc.gson.Base64TypeAdapter;
import com.github.mphi_rc.gson.MillisTypeAdapter;
import com.github.mphi_rc.gson.OptionalBytesTypeAdapterFactory;
import com.github.mphi_rc.usb.gadget.GsonAdaptersUsbDeviceController;
import com.github.mphi_rc.usb.gadget.UsbDeviceController;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * State owner. Credential and PIN updates are durably written before exposing
 * the new in-memory configuration. A failed write cannot silently succeed.
 */
public final class ConfigurationFile implements Configuration {
    private static final Logger log = LoggerFactory.getLogger(ConfigurationFile.class);
    private static final String DEFAULT_STATE = "/var/lib/pikeyua/config.json";

    private final Gson gson;
    private final Path configFile;
    private final Path identityMarker;
    private volatile Configuration config;

    public static ConfigurationFile defaultPath() {
        String location = System.getProperty("pikeyua.stateFile");
        if (location == null || location.trim().isEmpty()) {
            location = System.getenv("PIKEYUA_STATE_FILE");
        }
        if (location == null || location.trim().isEmpty()) {
            location = DEFAULT_STATE;
        }
        return new ConfigurationFile(Paths.get(location));
    }

    public ConfigurationFile(Path stateFile) {
        this.gson = new GsonBuilder()
                .setPrettyPrinting()
                .registerTypeAdapterFactory(new GsonAdaptersConfiguration())
                .registerTypeAdapterFactory(new GsonAdaptersUsbDeviceController())
                .registerTypeAdapterFactory(new GsonAdaptersCredential())
                .registerTypeAdapterFactory(new GsonAdaptersEd25519AttestationKeyPair())
                .registerTypeAdapterFactory(new GsonAdaptersP256AttestationKeyPair())
                .registerTypeAdapter(AttestationKeyPair.class, new AttestationKeyPairTypeAdapter())
                .registerTypeAdapter(byte[].class, new Base64TypeAdapter())
                .registerTypeAdapter(Instant.class, new MillisTypeAdapter())
                .registerTypeAdapterFactory(new OptionalBytesTypeAdapterFactory())
                .create();
        this.configFile = stateFile.toAbsolutePath().normalize();
        this.identityMarker = configFile.resolveSibling(configFile.getFileName() + ".identity");
        this.config = readFromDisk();
    }

    public UserVerifier userVerifier() {
        if (config.enableBonnet()) {
            throw new UnsupportedOperationException(
                "OLED Bonnet verification is not included in the V7.1 headless build");
        }
        return new AlwaysAllowUserVerifier();
    }

    private Configuration persist(Configuration proposed) {
        // Upgrade only on a successful write. Reads of V7.1 state are
        // non-destructive and never rewrite identities or private keys.
        final Configuration updated = ImmutableConfiguration.builder()
                .from(proposed)
                .schemaVersion(2)
                .build();
        final byte[] serialized;
        try {
            serialized = gson.toJson(updated).getBytes(StandardCharsets.UTF_8);
        } catch (RuntimeException e) {
            log.error("Authenticator state serialization failed", e);
            throw new IllegalStateException("Unable to serialize authenticator state", e);
        }
        try {
            AtomicStateFile.write(configFile, serialized);
            // An independent marker distinguishes genuine first initialization
            // from accidental deletion of an already initialized state file.
            AtomicStateFile.write(identityMarker,
                    updated.id().toString().getBytes(StandardCharsets.US_ASCII));
        } catch (IOException e) {
            log.error("Authenticator state write failed", e);
            throw new IllegalStateException("Unable to persist authenticator state", e);
        }
        return updated;
    }

    /** Persists initial UUID/config before exposing the FIDO2 USB device. */
    public synchronized void persistToDisk() {
        config = persist(config);
    }

    public synchronized void updatePinHash(byte[] pinHash) {
        Configuration next = ImmutableConfiguration.builder()
                .from(config)
                .pinHash(Optional.of(pinHash))
                .build();
        config = persist(next);
    }

    public synchronized void addCredential(Credential credential) {
        Configuration next = ImmutableConfiguration.builder()
                .from(config)
                .addCredentials(credential)
                .build();
        config = persist(next);
    }

    public synchronized void updateAllStoredCredentials(List<Credential> credentials) {
        Configuration next = ImmutableConfiguration.builder()
                .from(config)
                .credentials(credentials)
                .build();
        config = persist(next);
    }

    public byte[] getAaguid() {
        ByteBuffer buffer = ByteBuffer.wrap(new byte[16]);
        buffer.putLong(id().getMostSignificantBits());
        buffer.putLong(id().getLeastSignificantBits());
        return buffer.array();
    }

    @Override public UsbDeviceController usbDeviceController() { return config.usbDeviceController(); }
    @Override public List<Credential> credentials() { return config.credentials(); }
    @Override public List<Algorithm> enabledAlgorithms() { return config.enabledAlgorithms(); }
    @Override public UUID id() { return config.id(); }
    @Override public Optional<byte[]> pinHash() { return config.pinHash(); }
    @Override public boolean enableBonnet() { return config.enableBonnet(); }
    @Override public String usbGadgetDevicePath() { return config.usbGadgetDevicePath(); }
    @Override public String usbGadgetName() { return config.usbGadgetName(); }

    private Configuration readFromDisk() {
        if (!Files.exists(configFile, LinkOption.NOFOLLOW_LINKS)) {
            if (Files.exists(identityMarker, LinkOption.NOFOLLOW_LINKS)) {
                throw new IllegalStateException(
                        "Previously initialized authenticator state is missing");
            }
            if (Files.isSymbolicLink(configFile)) {
                throw new IllegalStateException("Refusing symbolic link as authenticator state");
            }
            return ImmutableConfiguration.builder().build();
        }
        try {
            String json = new String(AtomicStateFile.read(configFile), StandardCharsets.UTF_8);
            JsonObject object = new JsonParser().parse(json).getAsJsonObject();
            // Never silently regenerate an identity or discard credentials
            // when a partially written or incomplete state is loaded.
            if (!object.has("id") || object.get("id").isJsonNull()
                    || !object.has("credentials")
                    || !object.get("credentials").isJsonArray()) {
                throw new IllegalStateException("Incomplete authenticator state");
            }
            Configuration restored = gson.fromJson(json, Configuration.class);
            if (restored == null) {
                throw new IllegalStateException("Empty authenticator state");
            }
            if (restored.schemaVersion() < 1 || restored.schemaVersion() > 2) {
                throw new IllegalStateException(
                        "Unsupported authenticator state schema version: "
                                + restored.schemaVersion());
            }
            if (Files.exists(identityMarker, LinkOption.NOFOLLOW_LINKS)) {
                String pinnedId = new String(AtomicStateFile.read(identityMarker),
                        StandardCharsets.US_ASCII);
                if (!restored.id().toString().equals(pinnedId)) {
                    throw new IllegalStateException(
                            "Authenticator identity does not match persistent marker");
                }
            }
            return restored;
        } catch (IOException | RuntimeException e) {
            log.error("Authenticator state load failed; refusing to start with new keys", e);
            throw new IllegalStateException("Unable to restore authenticator state", e);
        }
    }
}

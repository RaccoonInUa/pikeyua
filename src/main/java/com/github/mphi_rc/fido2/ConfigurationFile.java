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
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/** Durable state: mutations publish in memory only after a successful storage commit. */
public final class ConfigurationFile implements Configuration {
    private static final Logger log = LoggerFactory.getLogger(ConfigurationFile.class);
    private static final String DEFAULT_STATE = "/var/lib/pikeyua/config.json";
    private final Gson gson;
    private final Path configFile;
    private final Path identityMarker;
    private volatile Configuration config;

    public static ConfigurationFile defaultPath() {
        String location = System.getProperty("pikeyua.stateFile");
        if (location == null || location.trim().isEmpty()) location = System.getenv("PIKEYUA_STATE_FILE");
        if (location == null || location.trim().isEmpty()) location = DEFAULT_STATE;
        return new ConfigurationFile(Paths.get(location));
    }

    public ConfigurationFile(Path stateFile) {
        gson = new GsonBuilder().setPrettyPrinting()
                .registerTypeAdapterFactory(new GsonAdaptersConfiguration())
                .registerTypeAdapterFactory(new GsonAdaptersUsbDeviceController())
                .registerTypeAdapterFactory(new GsonAdaptersCredential())
                .registerTypeAdapterFactory(new GsonAdaptersEd25519AttestationKeyPair())
                .registerTypeAdapterFactory(new GsonAdaptersP256AttestationKeyPair())
                .registerTypeAdapter(AttestationKeyPair.class, new AttestationKeyPairTypeAdapter())
                .registerTypeAdapter(byte[].class, new Base64TypeAdapter())
                .registerTypeAdapter(Instant.class, new MillisTypeAdapter())
                .registerTypeAdapterFactory(new OptionalBytesTypeAdapterFactory()).create();
        configFile = stateFile.toAbsolutePath().normalize();
        identityMarker = configFile.resolveSibling(configFile.getFileName() + ".identity");
        config = readFromDisk();
    }

    public UserVerifier userVerifier() {
        if (config.enableBonnet()) throw new UnsupportedOperationException("Bonnet is unavailable in the headless build");
        return new AlwaysAllowUserVerifier();
    }

    private Configuration persist(Configuration proposed) {
        // Non-PIN changes preserve schema-v2 compatibility; PIN mutations opt into v3.
        Configuration updated = ImmutableConfiguration.builder().from(proposed)
                .schemaVersion(Math.max(2, proposed.schemaVersion())).build();
        validatePinState(updated);
        try {
            byte[] serialized = gson.toJson(updated).getBytes(StandardCharsets.UTF_8);
            AtomicStateFile.write(configFile, serialized);
            AtomicStateFile.write(identityMarker, updated.id().toString().getBytes(StandardCharsets.US_ASCII));
        } catch (IOException | RuntimeException e) {
            // Do not include serialized state, passwords or cryptographic material in messages.
            log.error("Authenticator state commit failed");
            throw new IllegalStateException("Unable to persist authenticator state", e);
        }
        return updated;
    }

    public synchronized void persistToDisk() { config = persist(config); }

    public synchronized void updatePinHash(byte[] hash) { updatePinState(hash, 8); }

    /** Set/change PIN hash and retry count together in the same atomic JSON replacement. */
    public synchronized void updatePinState(byte[] hash, int retries) {
        if (hash == null || hash.length != 16 || retries < 0 || retries > 8) {
            throw new IllegalArgumentException("Invalid persistent PIN state");
        }
        config = persist(ImmutableConfiguration.builder().from(config).schemaVersion(3)
                .pinHash(Optional.of(hash.clone())).pinRetries(retries).build());
    }

    /** Called BEFORE comparing a decrypted PIN hash, so reboot cannot refund an attempt. */
    public synchronized void updatePinRetries(int retries) {
        if (!config.pinHash().isPresent() || retries < 0 || retries > 8) {
            throw new IllegalArgumentException("Invalid PIN retry transition");
        }
        config = persist(ImmutableConfiguration.builder().from(config).schemaVersion(3)
                .pinRetries(retries).build());
    }

    public synchronized void addCredential(Credential credential) {
        config = persist(ImmutableConfiguration.builder().from(config).addCredentials(credential).build());
    }
    public synchronized void updateAllStoredCredentials(List<Credential> credentials) {
        config = persist(ImmutableConfiguration.builder().from(config).credentials(credentials).build());
    }
    public byte[] getAaguid() {
        return ByteBuffer.allocate(16).putLong(id().getMostSignificantBits()).putLong(id().getLeastSignificantBits()).array();
    }
    @Override public int schemaVersion() { return config.schemaVersion(); }
    @Override public int pinRetries() { return config.pinRetries(); }
    @Override public UsbDeviceController usbDeviceController() { return config.usbDeviceController(); }
    @Override public List<Credential> credentials() { return config.credentials(); }
    @Override public List<Algorithm> enabledAlgorithms() { return config.enabledAlgorithms(); }
    @Override public UUID id() { return config.id(); }
    @Override public Optional<byte[]> pinHash() { return config.pinHash().map(byte[]::clone); }
    @Override public boolean enableBonnet() { return config.enableBonnet(); }
    @Override public String usbGadgetDevicePath() { return config.usbGadgetDevicePath(); }
    @Override public String usbGadgetName() { return config.usbGadgetName(); }

    private static void validatePinState(Configuration value) {
        if (value.pinRetries() < 0 || value.pinRetries() > 8
                || (value.pinHash().isPresent() && value.pinHash().get().length != 16)
                || (!value.pinHash().isPresent() && value.pinRetries() != 8)) {
            throw new IllegalStateException("Invalid persisted PIN state");
        }
    }

    private static int integerField(JsonObject object, String name) {
        JsonElement element = object.get(name);
        if (element == null || !element.isJsonPrimitive() || !element.getAsJsonPrimitive().isNumber()) {
            throw new IllegalStateException("Missing or invalid numeric state field: " + name);
        }
        try { return element.getAsBigDecimal().intValueExact(); }
        catch (ArithmeticException | NumberFormatException e) {
            throw new IllegalStateException("Invalid integer state field: " + name);
        }
    }

    private Configuration readFromDisk() {
        if (!Files.exists(configFile, LinkOption.NOFOLLOW_LINKS)) {
            if (Files.exists(identityMarker, LinkOption.NOFOLLOW_LINKS)) {
                throw new IllegalStateException("Previously initialized authenticator state is missing");
            }
            if (Files.isSymbolicLink(configFile)) throw new IllegalStateException("Refusing state symlink");
            return ImmutableConfiguration.builder().build();
        }
        try {
            String json = new String(AtomicStateFile.read(configFile), StandardCharsets.UTF_8);
            JsonObject object = new JsonParser().parse(json).getAsJsonObject();
            if (!object.has("id") || object.get("id").isJsonNull() || !object.has("credentials")
                    || !object.get("credentials").isJsonArray()) {
                throw new IllegalStateException("Incomplete authenticator state");
            }
            int version = object.has("schemaVersion") ? integerField(object, "schemaVersion") : 1;
            if (version < 1 || version > 3) throw new IllegalStateException("Unsupported authenticator state schema");
            if (version == 3 || object.has("pinRetries")) integerField(object, "pinRetries");
            if (version == 3 && !object.has("pinHash")) {
                throw new IllegalStateException("Missing protected PIN state");
            }
            Configuration restored = gson.fromJson(json, Configuration.class);
            if (restored == null) throw new IllegalStateException("Empty authenticator state");
            validatePinState(restored);
            if (Files.exists(identityMarker, LinkOption.NOFOLLOW_LINKS)) {
                String pinnedId = new String(AtomicStateFile.read(identityMarker), StandardCharsets.US_ASCII);
                if (!restored.id().toString().equals(pinnedId)) throw new IllegalStateException("Authenticator identity does not match persistent marker");
            }
            return restored;
        } catch (IOException | RuntimeException e) {
            log.error("Authenticator state load failed; refusing to start with new keys");
            throw new IllegalStateException("Unable to restore authenticator state", e);
        }
    }
}

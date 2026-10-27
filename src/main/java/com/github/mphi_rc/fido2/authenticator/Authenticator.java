package com.github.mphi_rc.fido2.authenticator;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;
import java.util.stream.Collectors;
import com.github.mphi_rc.fido2.ConfigurationFile;
import com.github.mphi_rc.fido2.authenticator.crypto.Algorithm;
import com.github.mphi_rc.fido2.authenticator.keys.CredentialBackend;
import com.github.mphi_rc.fido2.authenticator.keys.CredentialDescriptor;
import com.github.mphi_rc.fido2.authenticator.keys.LegacySoftwareCredentialBackend;
import com.github.mphi_rc.fido2.authenticator.user.UserVerifier;
import com.github.mphi_rc.fido2.protocol.ctap2.*;
import com.github.mphi_rc.fido2.protocol.usbhid.ChannelId;
import com.github.mphi_rc.fido2.protocol.usbhid.ImmutableChannelId;

/** Software lab authenticator. PIN verification is real; headless physical UP is still simulated. */
public class Authenticator {
    private static final long ASSERTION_TIMEOUT = TimeUnit.SECONDS.toNanos(30);
    private static final ChannelId INTERNAL_CHANNEL = ImmutableChannelId.of(new byte[]{0, 0, 0, 1});
    private final ConfigurationFile config;
    private final CredentialBackend credentialBackend;
    private final PinState pinState;
    private final UserVerifier userVerifier;
    private final boolean residentKeysEnabled;
    private final LongSupplier clock;
    private Pending pending;

    public Authenticator(ConfigurationFile config, CredentialStore store, PinState pin) {
        this(config, store, pin, Boolean.getBoolean("pikeyua.experimentalRk"), System::nanoTime);
    }
    public Authenticator(ConfigurationFile config, CredentialStore store, PinState pin,
            boolean residentKeysEnabled, LongSupplier clock) {
        this(config, new LegacySoftwareCredentialBackend(store), pin, residentKeysEnabled, clock);
    }
    /** Explicit provider injection. No fallback when a provider is unavailable. */
    public Authenticator(ConfigurationFile config, CredentialBackend backend, PinState pin,
            boolean residentKeysEnabled, LongSupplier clock) {
        this.config = config;
        credentialBackend = java.util.Objects.requireNonNull(backend, "backend");
        pinState = pin;
        userVerifier = config.userVerifier();
        this.residentKeysEnabled = residentKeysEnabled;
        this.clock = clock;
    }
    public synchronized void cancelAssertionSequence() {
        if (pending != null) Arrays.fill(pending.hash, (byte) 0);
        pending = null;
    }
    public synchronized Result<MakeCredentialResponse, Ctap2ResponseCode> makeCredential(MakeCredentialRequest request) {
        cancelAssertionSequence();
        if (request.upOptionPresent()) return Result.err(Ctap2ResponseCode.INVALID_OPTION);
        // CTAP options.uv denotes built-in UV. Client PIN uses pinAuth/pinProtocol instead.
        if (request.userVerificationRequested() || (request.residentKeyRequested() && !residentKeysEnabled)) {
            return Result.err(Ctap2ResponseCode.UNSUPPORTED_OPTION);
        }
        if (!userVerifier.isRegistrationApproved(request.relayingPartyId())) return Result.err(Ctap2ResponseCode.OPERATION_DENIED);
        for (CredentialDescriptor known : credentialBackend.find(request.relayingPartyId())) {
            if (containsId(request.excludedCredentialIds(), known.id())) return Result.err(Ctap2ResponseCode.CREDENTIAL_EXCLUDED);
        }
        Algorithm algorithm = config.enabledAlgorithms().stream()
                .filter(a -> credentialBackend.supportedAlgorithms().contains(a)
                        && request.supportedAlgorithmIds().contains(a.getCoseAlgorithmId())).findFirst().orElse(null);
        if (algorithm == null) return Result.err(Ctap2ResponseCode.UNSUPPORTED_ALGORITHM);
        Optional<Ctap2ResponseCode> error = checkPin(request.clientDataHash(), request.pinAuth(), request.pinProtocolVersion(), true);
        if (error.isPresent()) return Result.err(error.get());
        boolean verified = request.pinAuth().isPresent(); // True only after successful checkPin.
        final CredentialDescriptor credential;
        try {
            credential = credentialBackend.create(request.relayingPartyId(), request.userId(), algorithm,
                    request.residentKeyRequested(), request.userName(), request.userDisplayName());
        } catch (CredentialStore.Full full) { return Result.err(Ctap2ResponseCode.KEY_STORE_FULL); }
        AuthenticatorData data = ImmutableAuthenticatorData.builder().relayingPartyId(request.relayingPartyId())
                .attestedCredentialData(credential.encodeAttestedCredentialData(config.getAaguid()))
                .isUserPresent(true).isUserVerified(verified).signatureCount(0).build();
        return Result.ok(ImmutableMakeCredentialResponse.builder().format("packed")
                .algorithm(algorithm.getCoseAlgorithmId()).authData(data.asBytes())
                .signature(credentialBackend.signRegistration(credential.handle(), data, request.clientDataHash())).build());
    }
    public Result<MakeCredentialResponse, Ctap2ResponseCode> makeCredential(byte[] hash, String rpId,
            byte[] userId, Set<Integer> algorithms, Optional<byte[]> pinAuth) {
        ImmutableMakeCredentialRequest.Builder builder = ImmutableMakeCredentialRequest.builder()
                .clientDataHash(hash).relayingPartyId(rpId).userId(userId)
                .addAllSupportedAlgorithmIds(algorithms).pinAuth(pinAuth);
        if (pinAuth.isPresent()) builder.pinProtocolVersion(1);
        return makeCredential(builder.build());
    }
    public Result<GetAssertionResponse, Ctap2ResponseCode> getAssertion(GetAssertionRequest request) {
        return getAssertion(request, INTERNAL_CHANNEL);
    }
    public synchronized Result<GetAssertionResponse, Ctap2ResponseCode> getAssertion(GetAssertionRequest request, ChannelId channel) {
        cancelAssertionSequence();
        if (request.userVerificationRequested()) return Result.err(Ctap2ResponseCode.UNSUPPORTED_OPTION);
        // CTAP2.0 supports up=false, including Chrome's excludeList probes.
        // Skip the presence ceremony, NOT PIN authorization or RP/ID matching.
        boolean present = request.userPresenceRequested();
        if (present && !userVerifier.isAuthenticationApproved(request.relayingPartyId())) return Result.err(Ctap2ResponseCode.OPERATION_DENIED);
        Optional<Ctap2ResponseCode> error = checkPin(request.clientDataHash(), request.pinAuth(), request.pinProtocolVersion(), false);
        if (error.isPresent()) return Result.err(error.get());
        boolean discovery = request.publicKeyIds().isEmpty();
        if (discovery && !residentKeysEnabled) return Result.err(Ctap2ResponseCode.NO_CREDENTIALS);
        List<CredentialDescriptor> eligible = credentialBackend.find(request.relayingPartyId()).stream()
                .filter(c -> discovery ? c.discoverable() : containsId(request.publicKeyIds(), c.id()))
                .sorted(Comparator.comparingLong((CredentialDescriptor c) -> c.creation().toEpochMilli()).reversed()
                        .thenComparing((a, b) -> compareIds(a.id(), b.id()))).collect(Collectors.toList());
        if (eligible.isEmpty()) return Result.err(Ctap2ResponseCode.NO_CREDENTIALS);
        if (discovery && eligible.size() > CredentialStore.MAX_DISCOVERABLE_CREDENTIALS) return Result.err(Ctap2ResponseCode.LIMIT_EXCEEDED);
        CredentialDescriptor first = eligible.get(0);
        if (counterExhausted(first)) return Result.err(Ctap2ResponseCode.OTHER);
        boolean verified = request.pinAuth().isPresent();
        int count = discovery && eligible.size() > 1 ? eligible.size() : 0;
        GetAssertionResponse response = sign(first, request.clientDataHash(), present, verified, count);
        if (count > 1) pending = new Pending(channel.id(), request.relayingPartyId(), request.clientDataHash(), present, verified, eligible, clock.getAsLong());
        return Result.ok(response);
    }
    public synchronized Result<GetAssertionResponse, Ctap2ResponseCode> getNextAssertion(ChannelId channel) {
        Pending sequence = pending;
        long elapsed = sequence == null ? 0 : clock.getAsLong() - sequence.lastResponse;
        if (sequence == null || !Arrays.equals(sequence.channel, channel.id()) || elapsed < 0
                || elapsed > ASSERTION_TIMEOUT || sequence.nextIndex >= sequence.ids.size()
                || (sequence.verified && !pinState.authorizationActive())) {
            cancelAssertionSequence();
            return Result.err(Ctap2ResponseCode.NOT_ALLOWED);
        }
        byte[] id = sequence.ids.get(sequence.nextIndex);
        CredentialDescriptor credential = credentialBackend.find(sequence.rpId).stream()
                .filter(c -> c.discoverable() && Arrays.equals(c.id(), id)).findFirst().orElse(null);
        if (credential == null) { cancelAssertionSequence(); return Result.err(Ctap2ResponseCode.NOT_ALLOWED); }
        if (counterExhausted(credential)) { cancelAssertionSequence(); return Result.err(Ctap2ResponseCode.OTHER); }
        try {
            GetAssertionResponse response = sign(credential, sequence.hash, sequence.present, sequence.verified, 0);
            sequence.nextIndex++;
            sequence.lastResponse = clock.getAsLong();
            if (sequence.nextIndex == sequence.ids.size()) cancelAssertionSequence();
            return Result.ok(response);
        } catch (RuntimeException e) { cancelAssertionSequence(); throw e; }
    }
    private GetAssertionResponse sign(CredentialDescriptor credential, byte[] hash, boolean present, boolean verified, int count) {
        AuthenticatorData data = ImmutableAuthenticatorData.builder().relayingPartyId(credential.relayingPartyId())
                .isUserPresent(present).isUserVerified(verified).signatureCount(credential.signatureCount() + 1).build();
        byte[] signature = credentialBackend.signAssertion(credential.handle(), data, hash);
        return ImmutableGetAssertionResponse.builder().credentialId(credential.id()).authData(data.asBytes())
                .signature(signature).userId(credential.userId()).includeUser(credential.discoverable())
                .userName(verified ? credential.userName() : "")
                .userDisplayName(verified ? credential.userDisplayName() : "").numberOfCredentials(count).build();
    }
    private Optional<Ctap2ResponseCode> checkPin(byte[] hash, Optional<byte[]> auth, Optional<Integer> protocol, boolean registration) {
        if (!auth.isPresent()) return registration && pinState.isPinSet()
                ? Optional.of(Ctap2ResponseCode.PIN_REQUIRED) : Optional.empty();
        if (auth.get().length == 0) return Optional.of(pinState.isPinSet() ? Ctap2ResponseCode.PIN_INVALID : Ctap2ResponseCode.PIN_NOT_SET);
        if (!protocol.isPresent() || protocol.get() != 1 || auth.get().length != 16) return Optional.of(Ctap2ResponseCode.PIN_AUTH_INVALID);
        return pinState.isPinAuthValid(hash, auth.get());
    }
    private static boolean counterExhausted(CredentialDescriptor c) { return c.signatureCount() < 0 || c.signatureCount() == Integer.MAX_VALUE; }
    private static boolean containsId(List<byte[]> list, byte[] id) {
        for (byte[] candidate : list) if (Arrays.equals(candidate, id)) return true;
        return false;
    }
    private static int compareIds(byte[] a, byte[] b) {
        for (int i = 0; i < Math.min(a.length, b.length); i++) {
            int comparison = Integer.compare(a[i] & 255, b[i] & 255);
            if (comparison != 0) return comparison;
        }
        return Integer.compare(a.length, b.length);
    }
    public GetInfoResponse getInfo() {
        return ImmutableGetInfoResponse.builder().version(GetInfoResponse.Version.FIDO_2_0).aaguid(config.getAaguid())
                .isPinConfigured(pinState.isPinSet()).residentKeySupported(residentKeysEnabled).build();
    }
    private static final class Pending {
        final byte[] channel, hash;
        final String rpId;
        final boolean present, verified;
        final List<byte[]> ids = new ArrayList<>();
        int nextIndex = 1;
        long lastResponse;
        Pending(byte[] channel, String rpId, byte[] hash, boolean present, boolean verified, List<CredentialDescriptor> credentials, long now) {
            this.channel = channel.clone(); this.rpId = rpId; this.hash = hash.clone(); this.present = present; this.verified = verified;
            for (CredentialDescriptor credential : credentials) ids.add(credential.id().clone());
            lastResponse = now;
        }
    }
}

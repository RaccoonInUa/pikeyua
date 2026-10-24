package com.github.mphi_rc.fido2.protocol.ctap2;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.immutables.value.Value;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.Map;

/** Strict CTAP2.0 MakeCredential request. RK remains gated until stage C. */
@Value.Immutable
public abstract class MakeCredentialRequest {
    public static MakeCredentialRequest fromBytes(byte[] bytes) throws CborException {
        Map root = Ctap2CborInput.root(bytes);
        byte[] hash = Ctap2CborInput.requiredBytes(root, 0x01, 32, 32);
        Map rp = Ctap2CborInput.requiredMap(root, 0x02);
        Map user = Ctap2CborInput.requiredMap(root, 0x03);
        String rpId = Ctap2CborInput.requiredString(rp, "id", 253);
        byte[] userId = Ctap2CborInput.requiredBytes(user, "id", 1, 64);
        Set<Integer> algorithms = new HashSet<>(Ctap2CborInput.algorithms(root));
        List<byte[]> excluded = Ctap2CborInput.descriptorIds(root, 0x05);
        Map options = Ctap2CborInput.options(root, 0x07);
        boolean rk = Ctap2CborInput.booleanOption(options, "rk", false);
        boolean uv = Ctap2CborInput.booleanOption(options, "uv", false);
        boolean upPresent = Ctap2CborInput.containsOption(options, "up");
        if (upPresent) Ctap2CborInput.booleanOption(options, "up", true);

        ImmutableMakeCredentialRequest.Builder builder = ImmutableMakeCredentialRequest.builder()
                .clientDataHash(hash).relayingPartyId(rpId).userId(userId)
                .userName(Ctap2CborInput.optionalString(user, "name", 64))
                .userDisplayName(Ctap2CborInput.optionalString(user, "displayName", 128))
                .addAllSupportedAlgorithmIds(algorithms)
                .addAllExcludedCredentialIds(excluded)
                .residentKeyRequested(rk)
                .userVerificationRequested(uv)
                .upOptionPresent(upPresent);
        byte[] pinAuth = Ctap2CborInput.optionalPinAuth(root, 0x08);
        if (pinAuth != null) builder.pinAuth(pinAuth);
        Integer protocol = Ctap2CborInput.optionalPinProtocol(root, 0x09);
        if (protocol != null) builder.pinProtocolVersion(protocol);
        return builder.build();
    }

    public abstract byte[] clientDataHash();
    public abstract String relayingPartyId();
    public abstract byte[] userId();
    public abstract Set<Integer> supportedAlgorithmIds();
    public abstract Optional<byte[]> pinAuth();
    public abstract Optional<Integer> pinProtocolVersion();

    @Value.Default public String userName() { return ""; }
    @Value.Default public String userDisplayName() { return ""; }
    @Value.Default public boolean residentKeyRequested() { return false; }
    @Value.Default public boolean userVerificationRequested() { return false; }
    @Value.Default public boolean upOptionPresent() { return false; }
    @Value.Default public List<byte[]> excludedCredentialIds() {
        return Collections.emptyList();
    }
}

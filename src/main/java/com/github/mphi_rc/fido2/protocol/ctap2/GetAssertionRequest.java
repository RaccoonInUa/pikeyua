package com.github.mphi_rc.fido2.protocol.ctap2;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import org.immutables.value.Value;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.Map;

/** Strict GetAssertion parser. Missing allowList never implies any arbitrary key. */
@Value.Immutable
public abstract class GetAssertionRequest {
    public static GetAssertionRequest fromBytes(byte[] bytes) throws CborException {
        Map root = Ctap2CborInput.root(bytes);
        String rpId = Ctap2CborInput.requiredString(root, 0x01, 253);
        byte[] hash = Ctap2CborInput.requiredBytes(root, 0x02, 32, 32);
        boolean listPresent = Ctap2CborInput.lookup(root, 0x03) != null;
        List<byte[]> ids = Ctap2CborInput.descriptorIds(root, 0x03);
        Map options = Ctap2CborInput.options(root, 0x05);
        boolean uv = Ctap2CborInput.booleanOption(options, "uv", false);
        boolean up = Ctap2CborInput.booleanOption(options, "up", true);

        ImmutableGetAssertionRequest.Builder builder = ImmutableGetAssertionRequest.builder()
                .clientDataHash(hash).relayingPartyId(rpId)
                .addAllPublicKeyIds(ids)
                .allowListPresent(listPresent)
                .userVerificationRequested(uv)
                .userPresenceRequested(up);
        byte[] pinAuth = Ctap2CborInput.optionalPinAuth(root, 0x06);
        if (pinAuth != null) builder.pinAuth(pinAuth);
        Integer protocol = Ctap2CborInput.optionalPinProtocol(root, 0x07);
        if (protocol != null) builder.pinProtocolVersion(protocol);
        return builder.build();
    }

    public abstract String relayingPartyId();
    public abstract byte[] clientDataHash();
    public abstract Optional<byte[]> pinAuth();
    public abstract Optional<Integer> pinProtocolVersion();
    @Value.Default public List<byte[]> publicKeyIds() {
        return Collections.emptyList();
    }
    @Value.Default public boolean allowListPresent() { return false; }
    @Value.Default public boolean userVerificationRequested() { return false; }
    @Value.Default public boolean userPresenceRequested() { return true; }
}

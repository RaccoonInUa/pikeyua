package com.github.mphi_rc.fido2.protocol.usbhid;

import java.util.HashSet;
import java.util.Set;
import com.github.mphi_rc.fido2.protocol.ctap2.AuthenticatorRequestHandler;
import com.github.mphi_rc.fido2.protocol.usbhid.command.ImmutableInitResponsePayload;
import com.github.mphi_rc.fido2.protocol.usbhid.command.InitRequestPayload;
import com.github.mphi_rc.fido2.protocol.usbhid.command.InitResponsePayload;

public class UsbHidRequestHandler {
    private final AuthenticatorRequestHandler authenticator;
    private final Set<ChannelId> activeChannels = new HashSet<>();

    public UsbHidRequestHandler(AuthenticatorRequestHandler authenticator) {
        this.authenticator = authenticator;
    }

    /** Returns null only for CTAPHID_CANCEL, which must not receive its own reply. */
    public RawMessage handle(RawMessage message) {
        if (message.channelId().equals(ChannelId.broadcast())) {
            authenticator.cancelAssertionSequence();
            if (message.command() != HidCommand.INIT) {
                return RawMessage.error(message.channelId(), HidError.INVALID_CMD);
            }
            return initialize(message, allocateChannel());
        }
        if (!activeChannels.contains(message.channelId())) {
            return RawMessage.error(message.channelId(), HidError.INVALID_CHANNEL);
        }
        if (message.command() != HidCommand.CBOR) authenticator.cancelAssertionSequence();
        switch (message.command()) {
            case CBOR: return authenticator.handleCborRequest(message.channelId(), message.payload());
            case INIT: return initialize(message, message.channelId());
            case PING: return ImmutableRawMessage.of(message.channelId(), HidCommand.PING, message.payload());
            case CANCEL: return null;
            default: return RawMessage.error(message.channelId(), HidError.INVALID_CMD);
        }
    }

    private RawMessage initialize(RawMessage message, ChannelId channel) {
        InitRequestPayload request = InitRequestPayload.from(message);
        InitResponsePayload response = ImmutableInitResponsePayload.builder()
                .nonce(request.nonce()).channel(channel).build();
        return ImmutableRawMessage.of(message.channelId(), HidCommand.INIT, response.asBytes());
    }

    private ChannelId allocateChannel() {
        ChannelId id;
        do { id = ChannelId.random(); }
        while (activeChannels.contains(id) || id.equals(ChannelId.broadcast())
                || java.util.Arrays.equals(id.id(), new byte[4]));
        activeChannels.add(id);
        return id;
    }
}

package com.github.mphi_rc.fido2.protocol.ctap2;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.github.mphi_rc.fido2.authenticator.Authenticator;
import com.github.mphi_rc.fido2.authenticator.Result;
import com.github.mphi_rc.fido2.protocol.ctap2.pin.PinRequestHandler;
import com.github.mphi_rc.fido2.protocol.usbhid.ChannelId;
import com.github.mphi_rc.fido2.protocol.usbhid.HidCommand;
import com.github.mphi_rc.fido2.protocol.usbhid.HidError;
import com.github.mphi_rc.fido2.protocol.usbhid.ImmutableRawMessage;
import com.github.mphi_rc.fido2.protocol.usbhid.RawMessage;
import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.DataItem;

/** New/intervening commands invalidate pending assertions; no sensitive request logs. */
public class AuthenticatorRequestHandler {
    private static final Logger log = LoggerFactory.getLogger(AuthenticatorRequestHandler.class);
    private final PinRequestHandler pinRequestHandler;
    private final Authenticator authenticator;
    public AuthenticatorRequestHandler(Authenticator authenticator, PinRequestHandler pinRequestHandler) {
        this.authenticator = authenticator;
        this.pinRequestHandler = pinRequestHandler;
    }
    public synchronized void cancelAssertionSequence() { authenticator.cancelAssertionSequence(); }
    private RawMessage failure(ChannelId channel, Ctap2ResponseCode error) {
        return ImmutableRawMessage.of(channel, HidCommand.CBOR, error.asBytes());
    }
    private byte[] asPayload(Ctap2ResponseCode status, List<DataItem> data) {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        output.write(status.asBytes()[0]);
        try { new CborEncoder(output).encode(data); }
        catch (CborException e) { throw new IllegalStateException("Cannot encode CTAP response", e); }
        return output.toByteArray();
    }
    private RawMessage success(ChannelId channel, List<DataItem> data) {
        return ImmutableRawMessage.of(channel, HidCommand.CBOR, asPayload(Ctap2ResponseCode.OK, data));
    }
    private RawMessage assertion(ChannelId channel, Result<GetAssertionResponse, Ctap2ResponseCode> result) {
        byte[] body = result.handleError(error -> asPayload(error, Collections.emptyList()))
                .elseGet(value -> asPayload(Ctap2ResponseCode.OK, value.asCborMap()));
        return ImmutableRawMessage.of(channel, HidCommand.CBOR, body);
    }
    public synchronized RawMessage handleCborRequest(ChannelId channel, byte[] payload) {
        if (payload == null || payload.length == 0) {
            cancelAssertionSequence();
            return RawMessage.error(channel, HidError.INVALID_LEN);
        }
        Ctap2Method method = Ctap2Method.from(payload[0]);
        byte[] params = Arrays.copyOfRange(payload, 1, payload.length);
        if (method != Ctap2Method.GET_NEXT_ASSERTION) cancelAssertionSequence();
        log.debug("CTAP2 method {}", method);
        try {
            switch (method) {
                case MAKE_CREDENTIAL: {
                    Result<MakeCredentialResponse, Ctap2ResponseCode> made = authenticator.makeCredential(MakeCredentialRequest.fromBytes(params));
                    byte[] credential = made.handleError(error -> asPayload(error, Collections.emptyList()))
                            .elseGet(value -> asPayload(Ctap2ResponseCode.OK, value.asCborMap()));
                    return ImmutableRawMessage.of(channel, HidCommand.CBOR, credential);
                }
                case GET_ASSERTION:
                    return assertion(channel, authenticator.getAssertion(GetAssertionRequest.fromBytes(params), channel));
                case GET_NEXT_ASSERTION:
                    if (params.length != 0) { cancelAssertionSequence(); return failure(channel, Ctap2ResponseCode.INVALID_CBOR); }
                    return assertion(channel, authenticator.getNextAssertion(channel));
                case GET_INFO:
                    if (params.length != 0) return failure(channel, Ctap2ResponseCode.INVALID_CBOR);
                    return success(channel, authenticator.getInfo().asCborMap());
                case CLIENT_PIN: {
                    byte[] response = pinRequestHandler.handle(params)
                            .handleError(error -> asPayload(error, Collections.emptyList()))
                            .elseGet(value -> asPayload(Ctap2ResponseCode.OK, value));
                    return ImmutableRawMessage.of(channel, HidCommand.CBOR, response);
                }
                case SELECTION:
                    if (params.length != 0) return failure(channel, Ctap2ResponseCode.INVALID_CBOR);
                    return success(channel, Collections.emptyList());
                default: return failure(channel, Ctap2ResponseCode.INVALID_COMMAND);
            }
        } catch (CborException | ClassCastException | IndexOutOfBoundsException e) {
            cancelAssertionSequence();
            return failure(channel, Ctap2ResponseCode.INVALID_CBOR);
        } catch (RuntimeException e) {
            cancelAssertionSequence();
            throw e; // Storage uncertainty must fail closed, not be silently acknowledged.
        }
    }
}

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
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.UnsignedInteger;

/** A new command (including malformed input) invalidates any previous assertion sequence. */
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
        try {
            new CborEncoder(output).encode(data);
        } catch (CborException e) {
            throw new IllegalStateException("Cannot encode CTAP response", e);
        }
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
        log.debug("CTAP2 method {}", method); // Never log handles, names or PIN material.
        try {
            switch (method) {
                case MAKE_CREDENTIAL:
                    Result<MakeCredentialResponse, Ctap2ResponseCode> made =
                            authenticator.makeCredential(MakeCredentialRequest.fromBytes(params));
                    byte[] credential = made.handleError(error -> asPayload(error, Collections.emptyList()))
                            .elseGet(value -> asPayload(Ctap2ResponseCode.OK, value.asCborMap()));
                    return ImmutableRawMessage.of(channel, HidCommand.CBOR, credential);
                case GET_ASSERTION:
                    return assertion(channel, authenticator.getAssertion(
                            GetAssertionRequest.fromBytes(params), channel));
                case GET_NEXT_ASSERTION:
                    if (params.length != 0) {
                        cancelAssertionSequence();
                        return failure(channel, Ctap2ResponseCode.INVALID_CBOR);
                    }
                    return assertion(channel, authenticator.getNextAssertion(channel));
                case GET_INFO:
                    if (params.length != 0) return failure(channel, Ctap2ResponseCode.INVALID_CBOR);
                    return success(channel, authenticator.getInfo().asCborMap());
                case CLIENT_PIN:
                    return clientPin(channel, params);
                case SELECTION:
                    if (params.length != 0) return failure(channel, Ctap2ResponseCode.INVALID_CBOR);
                    return success(channel, Collections.emptyList());
                default:
                    return failure(channel, Ctap2ResponseCode.INVALID_COMMAND);
            }
        } catch (CborException | ClassCastException | IndexOutOfBoundsException e) {
            cancelAssertionSequence();
            return failure(channel, Ctap2ResponseCode.INVALID_CBOR);
        } catch (RuntimeException e) {
            // In particular, never swallow a failed or uncertain durable storage commit.
            cancelAssertionSequence();
            throw e;
        }
    }

    /** Existing PIN protocol support is not qualified as secure UV by Stage C. */
    private RawMessage clientPin(ChannelId channel, byte[] params) throws CborException {
        Map map = Ctap2CborInput.root(params);
        Integer protocol = Ctap2CborInput.optionalPinProtocol(map, 1);
        Integer command = Ctap2CborInput.optionalPinProtocol(map, 2);
        if (command == null) return failure(channel, Ctap2ResponseCode.MISSING_PARAMETER);
        if (protocol == null || protocol != 1) return failure(channel, Ctap2ResponseCode.PIN_AUTH_INVALID);
        switch (command) {
            case 1: return success(channel, pinRequestHandler.getRetries());
            case 2: return success(channel, pinRequestHandler.getKeyAgreementKey());
            case 3: {
                Ctap2ResponseCode status = pinRequestHandler.setPin(Ctap2CborInput.requiredMap(map, 3),
                        Ctap2CborInput.requiredBytes(map, 5, 64, 1024),
                        Ctap2CborInput.requiredBytes(map, 4, 16, 16));
                return failure(channel, status);
            }
            case 4: {
                Ctap2ResponseCode status = pinRequestHandler.changePin(Ctap2CborInput.requiredMap(map, 3),
                        Ctap2CborInput.requiredBytes(map, 6, 16, 16),
                        Ctap2CborInput.requiredBytes(map, 5, 64, 1024),
                        Ctap2CborInput.requiredBytes(map, 4, 16, 16));
                return failure(channel, status);
            }
            case 5: {
                Result<List<DataItem>, Ctap2ResponseCode> token = pinRequestHandler.getPinToken(
                        Ctap2CborInput.requiredMap(map, 3),
                        Ctap2CborInput.requiredBytes(map, 6, 16, 16));
                byte[] body = token.handleError(error -> asPayload(error, Collections.emptyList()))
                        .elseGet(value -> asPayload(Ctap2ResponseCode.OK, value));
                return ImmutableRawMessage.of(channel, HidCommand.CBOR, body);
            }
            default: return failure(channel, Ctap2ResponseCode.INVALID_COMMAND);
        }
    }
}

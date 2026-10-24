package com.github.mphi_rc.fido2.protocol.ctap2.pin;

import java.security.PublicKey;
import java.util.Collections;
import java.util.List;
import com.github.mphi_rc.fido2.authenticator.PinState;
import com.github.mphi_rc.fido2.authenticator.Result;
import com.github.mphi_rc.fido2.authenticator.crypto.PinProtocol1;
import com.github.mphi_rc.fido2.protocol.ctap2.Ctap2ResponseCode;
import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.*;

/** Typed protocol-1 ClientPIN dispatcher. Malformed host data cannot enter the PIN state machine. */
public final class PinRequestHandler {
    private final PinState pin;
    public PinRequestHandler(PinState pin) { this.pin = pin; }

    public Result<List<DataItem>, Ctap2ResponseCode> handle(byte[] body) {
        if (body == null || body.length == 0) return Result.err(Ctap2ResponseCode.INVALID_CBOR);
        if (body.length > 1024) return Result.err(Ctap2ResponseCode.REQUEST_TOO_LARGE);
        try {
            List<DataItem> values = CborDecoder.decode(body);
            if (values.size() != 1) throw new InputError(Ctap2ResponseCode.INVALID_CBOR);
            Map root = map(values.get(0));
            if (uint(root, 1) != 1) throw new InputError(Ctap2ResponseCode.INVALID_PARAMETER);
            int command = uint(root, 2);
            switch (command) {
                case 1: return Result.ok(getRetries());
                case 2: return Result.ok(getKeyAgreementKey());
                case 3: {
                    Map key = map(required(root, 3));
                    byte[] auth = bytes(root, 4, 16, 16);
                    byte[] encrypted = bytes(root, 5, 64, 256);
                    if (encrypted.length % 16 != 0) throw new InputError(Ctap2ResponseCode.INVALID_PARAMETER);
                    return status(setPin(key, encrypted, auth));
                }
                case 4: {
                    Map key = map(required(root, 3));
                    byte[] auth = bytes(root, 4, 16, 16);
                    byte[] encrypted = bytes(root, 5, 64, 256);
                    byte[] hash = bytes(root, 6, 16, 16);
                    if (encrypted.length % 16 != 0) throw new InputError(Ctap2ResponseCode.INVALID_PARAMETER);
                    return status(changePin(key, hash, encrypted, auth));
                }
                case 5: return getPinToken(map(required(root, 3)), bytes(root, 6, 16, 16));
                default: return Result.err(Ctap2ResponseCode.INVALID_COMMAND);
            }
        } catch (InputError e) { return Result.err(e.code); }
        catch (CborException e) { return Result.err(Ctap2ResponseCode.INVALID_CBOR); }
        // Storage errors intentionally propagate, never become successful CTAP replies.
    }
    private static Result<List<DataItem>, Ctap2ResponseCode> status(Ctap2ResponseCode code) {
        return code == Ctap2ResponseCode.OK ? Result.ok(Collections.emptyList()) : Result.err(code);
    }
    private static DataItem required(Map map, int key) {
        DataItem value = map.get(new UnsignedInteger(key));
        if (value == null) throw new InputError(Ctap2ResponseCode.MISSING_PARAMETER);
        return value;
    }
    private static Map map(DataItem value) {
        if (!(value instanceof Map)) throw new InputError(Ctap2ResponseCode.CBOR_UNEXPECTED_TYPE);
        return (Map) value;
    }
    private static int uint(Map map, int key) {
        DataItem value = required(map, key);
        if (!(value instanceof UnsignedInteger)) throw new InputError(Ctap2ResponseCode.CBOR_UNEXPECTED_TYPE);
        java.math.BigInteger number = ((UnsignedInteger) value).getValue();
        if (number.signum() < 0 || number.bitLength() > 31) throw new InputError(Ctap2ResponseCode.INVALID_PARAMETER);
        return number.intValue();
    }
    private static byte[] bytes(Map map, int key, int min, int max) {
        DataItem value = required(map, key);
        if (!(value instanceof ByteString)) throw new InputError(Ctap2ResponseCode.CBOR_UNEXPECTED_TYPE);
        byte[] bytes = ((ByteString) value).getBytes();
        if (bytes == null || bytes.length < min || bytes.length > max) throw new InputError(Ctap2ResponseCode.INVALID_PARAMETER);
        return bytes;
    }
    private static PublicKey peer(Map key) {
        try { return PinProtocol1.decodePublicKey(key); }
        catch (IllegalArgumentException e) { throw new InputError(Ctap2ResponseCode.INVALID_PARAMETER); }
    }
    private static List<DataItem> field(int key, DataItem value) {
        Map result = new Map();
        result.put(new UnsignedInteger(key), value);
        return Collections.singletonList(result);
    }
    public List<DataItem> getRetries() {
        return field(3, new UnsignedInteger(pin.getCountRemainingPinAttempts()));
    }
    public List<DataItem> getKeyAgreementKey() {
        return field(1, PinProtocol1.encodePublicKey(pin.getKeyAgreementKey()));
    }
    public Ctap2ResponseCode setPin(Map key, byte[] encrypted, byte[] auth) {
        return pin.setNewPin(peer(key), encrypted, auth);
    }
    public Ctap2ResponseCode changePin(Map key, byte[] encryptedHash, byte[] encryptedNew, byte[] auth) {
        return pin.setPin(peer(key), encryptedNew, encryptedHash, auth);
    }
    public Result<List<DataItem>, Ctap2ResponseCode> getPinToken(Map key, byte[] encryptedHash) {
        return pin.getPinTokenEncrypted(peer(key), encryptedHash)
                .handleError(error -> Result.<List<DataItem>, Ctap2ResponseCode>err(error))
                .elseGet(token -> Result.ok(field(2, new ByteString(token))));
    }
    private static final class InputError extends RuntimeException {
        private final Ctap2ResponseCode code;
        InputError(Ctap2ResponseCode code) { super("Invalid ClientPIN request"); this.code = code; }
    }
}

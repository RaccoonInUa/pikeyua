package com.github.mphi_rc.fido2.protocol.ctap2;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.NegativeInteger;
import co.nstant.in.cbor.model.Number;
import co.nstant.in.cbor.model.SimpleValue;
import co.nstant.in.cbor.model.UnicodeString;
import co.nstant.in.cbor.model.UnsignedInteger;

/**
 * Narrow, type-checked CTAP2 CBOR reader.
 * Do not trust unchecked map values, optional lists or booleans from the host.
 * This class deliberately does not log raw requests (user handles/PIN material).
 */
final class Ctap2CborInput {
    private static final int MAX_INPUT_BYTES = 65535;
    private static final int MAX_CREDENTIAL_DESCRIPTORS = 128;
    private static final int MAX_CREDENTIAL_ID_BYTES = 1024;
    private Ctap2CborInput() { }

    static Map root(byte[] bytes) throws CborException {
        if (bytes == null || bytes.length == 0 || bytes.length > MAX_INPUT_BYTES) {
            throw new CborException("CTAP2 CBOR body is empty or too large");
        }
        List<DataItem> values = CborDecoder.decode(bytes);
        if (values.size() != 1 || !(values.get(0) instanceof Map)) {
            throw new CborException("Expected one CTAP2 CBOR map");
        }
        return (Map) values.get(0);
    }

    static DataItem lookup(Map map, int key) {
        return map.get(new UnsignedInteger(key));
    }

    static Map requiredMap(Map root, int key) throws CborException {
        return asMap(lookup(root, key), "map at 0x" + Integer.toHexString(key));
    }

    static Map asMap(DataItem raw, String context) throws CborException {
        if (!(raw instanceof Map)) throw new CborException("Missing or invalid " + context);
        return (Map) raw;
    }

    static byte[] requiredBytes(Map map, String key, int min, int max) throws CborException {
        return bytes(map.get(new UnicodeString(key)), key, min, max);
    }

    static byte[] requiredBytes(Map map, int key, int min, int max) throws CborException {
        return bytes(lookup(map, key), "field 0x" + Integer.toHexString(key), min, max);
    }

    private static byte[] bytes(DataItem raw, String field, int min, int max) throws CborException {
        if (!(raw instanceof ByteString)) throw new CborException("Missing/invalid bytes: " + field);
        byte[] value = ((ByteString) raw).getBytes();
        if (value == null || value.length < min || value.length > max) {
            throw new CborException("Invalid byte length: " + field);
        }
        return value;
    }

    static String requiredString(Map map, String field, int maxBytes) throws CborException {
        String value = optionalString(map, field, maxBytes);
        if (value.isEmpty()) throw new CborException("Missing/empty " + field);
        return value;
    }

    static String optionalString(Map map, String field, int maxBytes) throws CborException {
        DataItem raw = map.get(new UnicodeString(field));
        if (raw == null) return "";
        if (!(raw instanceof UnicodeString)) throw new CborException("Invalid text: " + field);
        String value = ((UnicodeString) raw).getString();
        if (value == null || value.getBytes(StandardCharsets.UTF_8).length > maxBytes) {
            throw new CborException("Invalid text length: " + field);
        }
        return value;
    }

    static String requiredString(Map map, int key, int maxBytes) throws CborException {
        DataItem raw = lookup(map, key);
        if (!(raw instanceof UnicodeString)) {
            throw new CborException("Missing/invalid RP ID");
        }
        String value = ((UnicodeString) raw).getString();
        if (value == null || value.isEmpty()
                || value.getBytes(StandardCharsets.UTF_8).length > maxBytes) {
            throw new CborException("Invalid RP ID length");
        }
        return value;
    }

    static List<byte[]> descriptorIds(Map root, int key) throws CborException {
        DataItem value = lookup(root, key);
        if (value == null) return Collections.emptyList();
        if (!(value instanceof Array)) throw new CborException("Invalid credential descriptor list");
        List<DataItem> list = ((Array) value).getDataItems();
        if (list.size() > MAX_CREDENTIAL_DESCRIPTORS) {
            throw new CborException("Too many credential descriptors");
        }
        List<byte[]> ids = new ArrayList<>(list.size());
        for (DataItem entry : list) {
            Map item = asMap(entry, "credential descriptor");
            String type = requiredString(item, "type", 32);
            if (!"public-key".equals(type)) throw new CborException("Unsupported credential type");
            ids.add(requiredBytes(item, "id", 1, MAX_CREDENTIAL_ID_BYTES));
        }
        return ids;
    }

    static List<Integer> algorithms(Map root) throws CborException {
        DataItem value = lookup(root, 0x04);
        if (!(value instanceof Array)) throw new CborException("Missing algorithms array");
        List<DataItem> items = ((Array) value).getDataItems();
        if (items.isEmpty() || items.size() > 32) throw new CborException("Invalid algorithms count");
        List<Integer> result = new ArrayList<>();
        for (DataItem raw : items) {
            Map item = asMap(raw, "algorithm descriptor");
            if (!"public-key".equals(requiredString(item, "type", 32))) {
                throw new CborException("Invalid public key algorithm type");
            }
            DataItem identifier = item.get(new UnicodeString("alg"));
            if (!(identifier instanceof Number)) throw new CborException("Invalid COSE algorithm ID");
            java.math.BigInteger big = ((Number) identifier).getValue();
            if (big.bitLength() > 31) throw new CborException("Out of range COSE algorithm");
            result.add(big.intValue());
        }
        return result;
    }

    static byte[] optionalPinAuth(Map map, int key) throws CborException {
        DataItem raw = lookup(map, key);
        if (raw == null) return null;
        return bytes(raw, "pinUvAuthParam", 0, 64);
    }

    static Integer optionalPinProtocol(Map map, int key) throws CborException {
        DataItem raw = lookup(map, key);
        if (raw == null) return null;
        if (!(raw instanceof UnsignedInteger)) throw new CborException("Invalid PIN protocol");
        java.math.BigInteger number = ((UnsignedInteger) raw).getValue();
        if (number.signum() < 0 || number.bitLength() > 16) {
            throw new CborException("Invalid PIN protocol version");
        }
        return number.intValue();
    }

    static Map options(Map root, int key) throws CborException {
        DataItem raw = lookup(root, key);
        return raw == null ? null : asMap(raw, "options");
    }

    static boolean booleanOption(Map options, String option, boolean defaultValue)
            throws CborException {
        if (options == null) return defaultValue;
        DataItem raw = options.get(new UnicodeString(option));
        if (raw == null) return defaultValue;
        if (SimpleValue.TRUE.equals(raw)) return true;
        if (SimpleValue.FALSE.equals(raw)) return false;
        throw new CborException("Option is not a CBOR boolean: " + option);
    }

    static boolean containsOption(Map options, String option) {
        return options != null && options.get(new UnicodeString(option)) != null;
    }
}

package com.github.mphi_rc.gson;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.lang.reflect.Type;
import java.util.Optional;

import org.junit.Test;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

/** Regression for InaccessibleObjectException on Java 17+ and Java 21. */
public class OptionalBytesTypeAdapterFactoryTest {
    private final Gson gson = new GsonBuilder()
            .registerTypeAdapter(byte[].class, new Base64TypeAdapter())
            .registerTypeAdapterFactory(new OptionalBytesTypeAdapterFactory())
            .create();

    private static final Type HASH_TYPE = new TypeToken<Optional<byte[]>>() {}.getType();

    @Test
    public void presentBytesRoundTripThroughBase64() {
        byte[] secret = new byte[] { 0, 1, 2, 3, 4, (byte) 0xff };
        String json = gson.toJson(Optional.of(secret), HASH_TYPE);
        assertEquals("\"AAECAwT/\"", json);
        Optional<byte[]> decoded = gson.fromJson(json, HASH_TYPE);
        assertTrue(decoded.isPresent());
        assertArrayEquals(secret, decoded.get());
    }

    @Test
    public void emptyBytesRoundTripWithoutJdkReflection() {
        String json = gson.toJson(Optional.empty(), HASH_TYPE);
        assertEquals("null", json);
        Optional<byte[]> restored = gson.fromJson(json, HASH_TYPE);
        assertFalse(restored.isPresent());
    }

    @Test
    public void unsupportedOptionalTypeIsRejected() {
        Type unsupported = new TypeToken<Optional<String>>() {}.getType();
        try {
            gson.getAdapter(TypeToken.get(unsupported));
            fail("Unexpected support for Optional<String>");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("Unsupported state Optional"));
        }
    }
}

package com.github.mphi_rc.gson;

import java.io.IOException;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.Optional;

import com.google.gson.Gson;
import com.google.gson.TypeAdapter;
import com.google.gson.TypeAdapterFactory;
import com.google.gson.reflect.TypeToken;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import com.google.gson.stream.JsonWriter;

/**
 * Gson 2.8.5 cannot reflect into java.util.Optional on modern JDKs.
 *
 * The current authenticator state has exactly one Optional field:
 * Configuration.pinHash(): Optional<byte[]>.
 *
 * Serialize a present hash with the existing base64 byte[] adapter and
 * represent an empty hash as JSON null. Reject any other Optional type
 * rather than silently persisting unsupported state.
 */
public final class OptionalBytesTypeAdapterFactory implements TypeAdapterFactory {
    @Override
    @SuppressWarnings("unchecked")
    public <T> TypeAdapter<T> create(Gson gson, TypeToken<T> type) {
        if (type.getRawType() != Optional.class) {
            return null;
        }

        Type requested = type.getType();
        if (!(requested instanceof ParameterizedType)) {
            throw new IllegalArgumentException("Raw Optional is not a supported state type");
        }
        Type[] args = ((ParameterizedType) requested).getActualTypeArguments();
        if (args.length != 1 || args[0] != byte[].class) {
            throw new IllegalArgumentException(
                    "Unsupported state Optional type: " + requested);
        }

        final TypeAdapter<byte[]> bytesAdapter = gson.getAdapter(byte[].class);
        return (TypeAdapter<T>) new TypeAdapter<Optional<byte[]>>() {
            @Override
            public void write(JsonWriter output, Optional<byte[]> value) throws IOException {
                if (value == null || !value.isPresent()) {
                    output.nullValue();
                } else {
                    bytesAdapter.write(output, value.get());
                }
            }

            @Override
            public Optional<byte[]> read(JsonReader input) throws IOException {
                if (input.peek() == JsonToken.NULL) {
                    input.nextNull();
                    return Optional.empty();
                }
                byte[] value = bytesAdapter.read(input);
                return Optional.ofNullable(value);
            }
        };
    }
}

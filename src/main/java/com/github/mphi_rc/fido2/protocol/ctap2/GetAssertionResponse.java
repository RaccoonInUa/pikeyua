package com.github.mphi_rc.fido2.protocol.ctap2;

import java.util.Collections;
import java.util.List;
import org.immutables.value.Value;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.UnicodeString;
import co.nstant.in.cbor.model.UnsignedInteger;

@Value.Immutable
public abstract class GetAssertionResponse {
    public abstract byte[] credentialId();
    public abstract byte[] authData();
    public abstract byte[] signature();
    public abstract byte[] userId();
    @Value.Default public boolean includeUser() { return false; }
    /** Zero means absent. Only the first discovery response may contain a count > 1. */
    @Value.Default public int numberOfCredentials() { return 0; }

    public List<DataItem> asCborMap() {
        Map root = new Map();
        Map descriptor = new Map();
        descriptor.put(new UnicodeString("id"), new ByteString(credentialId()));
        descriptor.put(new UnicodeString("type"), new UnicodeString("public-key"));
        root.put(new UnsignedInteger(1), descriptor);
        root.put(new UnsignedInteger(2), new ByteString(authData()));
        root.put(new UnsignedInteger(3), new ByteString(signature()));
        if (includeUser()) {
            Map user = new Map();
            user.put(new UnicodeString("id"), new ByteString(userId()));
            // User-identifying name/displayName are deliberately never released in Stage C.
            // We do not rely on the old, not-yet-qualified PIN implementation for that.
            root.put(new UnsignedInteger(4), user);
        }
        if (numberOfCredentials() > 1) {
            root.put(new UnsignedInteger(5), new UnsignedInteger(numberOfCredentials()));
        }
        return Collections.<DataItem>singletonList(root);
    }
}

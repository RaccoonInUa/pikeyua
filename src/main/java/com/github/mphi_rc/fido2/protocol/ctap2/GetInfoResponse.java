package com.github.mphi_rc.fido2.protocol.ctap2;

import java.util.List;
import org.immutables.value.Value;
import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.model.DataItem;

@Value.Immutable
public abstract class GetInfoResponse {
    public enum Version { FIDO_2_0, U2F_V2 }
    @Value.Parameter public abstract Version version();
    @Value.Parameter public abstract byte[] aaguid();
    @Value.Parameter public abstract boolean isPinConfigured();
    /** Experimental RK is disabled by default pending physical qualification. */
    @Value.Default public boolean residentKeySupported() { return false; }

    public List<DataItem> asCborMap() {
        return new CborBuilder().addMap()
                .putArray((byte) 0x01).add(version().name()).end()
                .put((byte) 0x03, aaguid())
                .putMap((byte) 0x04)
                    .put("rk", residentKeySupported())
                    .put("up", true)
                    .put("plat", false)
                    .put("clientPin", isPinConfigured())
                .end()
                .putArray((byte) 0x06).add(1).end()
                .end().build();
    }
}

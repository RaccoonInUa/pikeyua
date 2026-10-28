package com.github.mphi_rc.fido2.authenticator.keys.token;

import java.security.PublicKey;

/** An isolated key service. The API never reveals private-key bytes. */
public interface TokenKeyDriver {
    /** Generate a fresh P-256 key INSIDE the selected token. No software fallback. */
    PublicKey generateP256(String uniqueAlias) throws Exception;
    /** Must refuse when the exact alias is absent or bound to another key. */
    byte[] sign(String uniqueAlias, byte[] signedBytes) throws Exception;
    /** A best-effort cleanup operation; failure must remain visible to the owner. */
    void delete(String uniqueAlias) throws Exception;
}

package com.github.mphi_rc.fido2.authenticator.keys.token;

import java.security.PublicKey;

/** An isolated key service. This API never returns private-key bytes. */
public interface TokenKeyDriver {
    PublicKey generateP256(String uniqueAlias) throws Exception;
    byte[] sign(String uniqueAlias, byte[] signedBytes) throws Exception;
    /** Legacy driver primitive; the credential backend never calls this unbound delete. */
    void delete(String uniqueAlias) throws Exception;
    /**
     * Delete only the object matching this pinned public key, or refuse. The driver
     * must serialize lookup/proof/deletion with its other operations. A missing
     * object is NOT proof that the correct token is present and must not succeed.
     */
    default void deleteIfMatches(String uniqueAlias, byte[] expectedPublicKey) throws Exception {
        throw new UnsupportedOperationException("Bound token deletion is unavailable");
    }
}

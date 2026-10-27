package com.github.mphi_rc.fido2;

import org.junit.Test;

public class CredentialBackendTest {
    @Test public void public_api() throws Exception { CredentialBackendContract.run("public-api"); }
    @Test public void immutable_handle() throws Exception { CredentialBackendContract.run("immutable-handle"); }
    @Test public void immutable_view() throws Exception { CredentialBackendContract.run("immutable-view"); }
    @Test public void p256() throws Exception { CredentialBackendContract.run("p256"); }
    @Test public void ed25519() throws Exception { CredentialBackendContract.run("ed25519"); }
    @Test public void readonly_load() throws Exception { CredentialBackendContract.run("readonly-load"); }
    @Test public void restart() throws Exception { CredentialBackendContract.run("restart"); }
    @Test public void foreign_provider() throws Exception { CredentialBackendContract.run("foreign-provider"); }
    @Test public void foreign_rp() throws Exception { CredentialBackendContract.run("foreign-rp"); }
    @Test public void stale_counter() throws Exception { CredentialBackendContract.run("stale-counter"); }
    @Test public void deleted_handle() throws Exception { CredentialBackendContract.run("deleted-handle"); }
    @Test public void delete_preserves_state() throws Exception { CredentialBackendContract.run("delete-preserves-state"); }
    @Test public void denied_sign() throws Exception { CredentialBackendContract.run("denied-sign"); }
    @Test public void denied_delete() throws Exception { CredentialBackendContract.run("denied-delete"); }
    @Test public void rk_replacement() throws Exception { CredentialBackendContract.run("rk-replacement"); }
    @Test public void wire_length() throws Exception { CredentialBackendContract.run("wire-length"); }
    @Test public void opaque_registration_assertion() throws Exception { CredentialBackendContract.run("opaque-registration-assertion"); }
    @Test public void opaque_no_fallback() throws Exception { CredentialBackendContract.run("opaque-no-fallback"); }
    @Test public void unsupported_algorithm() throws Exception { CredentialBackendContract.run("unsupported-algorithm"); }
    @Test public void opaque_continuation() throws Exception { CredentialBackendContract.run("opaque-continuation"); }
}

package com.github.mphi_rc.fido2.authenticator.keys.pkcs11;
import org.junit.Test;
public class Pkcs11BoundaryTest {
    @Test public void publicBoundaryFailsClosed() throws Exception {
        Pkcs11BoundaryChecks.main(new String[0]);
    }
}

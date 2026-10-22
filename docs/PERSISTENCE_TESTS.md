# V7.1 persistence acceptance

This is a controlled test plan. **Do not deploy to the running V6 key yet.**

1. Clean compile: `gradle test shadowJar` using JDK 17 and Gradle 8.8; all automated tests pass.
2. Cold start with a fresh `0700` state directory; a `0600` config file is written before the USB gadget is advertised.
3. Register one test credential and authenticate with `libfido2` and WebAuthn.io. Do not use real accounts.
4. Restart the new test process; the device AAGUID stays constant and the credential still authenticates.
5. Simulate failed storage using an unwritable/misconfigured directory; enrollment or counter updates must not report success.
6. Confirm a corrupt state or insecure state file aborts startup instead of silently regenerating keys.
7. Verify that no private state, PIN, token, secret or build output is committed.

The original V6 binary has not been compared byte-for-byte to its reconstructed source. Functional regressions are possible. The first end-to-end tests must happen in an isolated installation.

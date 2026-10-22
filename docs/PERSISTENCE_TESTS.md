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

## Isolated no-downtime test on Pi

Run `java -cp pikeyua.jar com.github.mphi_rc.fido2.StateSmokeTest` against the newly built V7.1 test JAR. This does not invoke the FIDO gadget or stop V6. The required output is `PASS: ARMv6 authenticator state, credential, counter, PIN and AAGUID round-trip.` A failure should include an exception and must be resolved before deployment.

## CI: cross-process lifecycle (no USB)

`sh scripts/verify-persistence.sh build/libs/pikeyua.jar` executes each phase in its own JVM:
- `create`: secure test directory, initial UUID and synthetic P-256 credential
- `verify`: same AAGUID, credential ID, public/private key fingerprints and working signature
- `increment`: persist signature counter and synthetic PIN hash
- `verify-updated`: separate JVM confirms both updated fields and valid signing key
- `negative-corrupt`: malformed/incomplete JSON, symlink, deleted state after initialization and mismatched identity marker all fail closed
- `negative-denied`: denied writes to PIN and counter are not acknowledged or reflected in memory/on disk
- `verify-updated`: confirms the original persistent state survived negative tests

The suite cleans up all synthetic state and never accesses the live USB HID function or live `config.json`.
GitHub CI on Java 17/21 is a host-level check, **not a Raspberry reboot test**.

## Still pending hardware/service qualification

- Run this latest separate-process test with the CI artifact on Raspberry Pi Zero W.
- Run the candidate in an **isolated** USB gadget test environment (not the live V6 gadget), register/authenticate with a test RP, and restart/power-cycle the candidate while preserving AAGUID and credential ID.
- Test actual disk full / I/O errors; the CI denied-write case simulates a refused storage operation, **not** ENOSPC or power-cut behavior.
- Confirm build-to-deployed V6 behavioral parity; neither reconstructed source nor the candidate has been verified byte-identical to the installed V6 JAR.

Keep PR as Draft and do not switch the running V6 until these qualify.

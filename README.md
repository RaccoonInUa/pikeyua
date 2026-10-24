# pikeyua

Experimental USB FIDO2 software authenticator for Raspberry Pi Zero W, derived from [mphi-rc/pi-zero-security-key](https://github.com/mphi-rc/pi-zero-security-key). Apache-2.0; see `LICENSE.txt`.

## Current development

The laboratory Pi has the V7.2 candidate, an ARMv6-isolated RK probe PASS and USB GetInfo reporting RK. Actual RK-required/browser no-allowList authentication has not yet been reported. This branch, `feature/v7.3-pin-uv`, adds **Client PIN / PIN-based UV**, not another deployment controller. The owner explicitly cancelled the separate cutover mechanism; no additional timer/service/snapshot framework is required.

V7.3 implements protocol1 PIN setup/change/token exchange, persistent retries, temporary and persistent lockout, token invalidation, signed UV and verification-gated account names. It remains an unqualified hardware/browser candidate until those tests are actually performed. Existing RK is enabled with `-Dpikeyua.experimentalRk=true`; no additional PIN feature flag is needed. GetInfo's clientPin reflects whether a PIN has been set, not a claim of built-in biometric UV.

- [V7.3 implementation, limitations and isolated probe](docs/V7_3_PIN_UV.md)
- [V7.2 RK implementation](docs/V7_2_PROTOCOL_STAGE_C.md)
- [V7.2 design review](docs/V7_2_RK_DESIGN_REVIEW.md)
- [Credential schema migration](docs/V7_2_STORAGE_MIGRATION.md)
- [V7.2 request parsing](docs/V7_2_PROTOCOL_STAGE_B.md)
- [V7.1 persistence tests](docs/PERSISTENCE_TESTS.md)
- [Historic V6/V7.1 cutover](docs/V7_1_CUTOVER.md) — not an upgrader for V7.3

## Build and test

Use Gradle 8.8 and JDK 17 or 21:

```sh
gradle --no-daemon test shadowJar
sh scripts/verify-persistence.sh build/libs/pikeyua.jar
sh scripts/verify-v72-migration.sh build/libs/pikeyua.jar
java -cp build/libs/pikeyua.jar com.github.mphi_rc.fido2.ResidentCredentialProbe
java -cp build/libs/pikeyua.jar com.github.mphi_rc.fido2.PinUvProbe
```

Both probes use private synthetic temporary state and independent JVMs, never live credentials or USB. The historical wrapper lacks a tracked wrapper JAR; use the named Gradle version or regenerate/verify the wrapper separately. CI's `pikeyua-v7.3-pin-uv-lab-jdk17` artifact contains the JAR, commit, checksum and test instructions. Generated binaries and actual device state never belong in Git.

## Storage and security

State is root-private (`0700` directory, `0600` files), using atomic JSON replacement and fsync. PIN mutation promotes to schema v3 to retain the retry budget across restarts; older V7.2 must not be pointed at v3 state. Forward migration preserves credentials, keys and AAGUID. See the V7.3 document for PIN optionality, lockout, downgrade and storage-error boundaries.

This is a laboratory authenticator with **no secure element and simulated physical UP**. PIN verification does not encrypt private keys on the SD card or protect against root access. Browser/physical USB and real power-loss qualification remain necessary; no FIDO certification or production-security claim is made. Never use as the sole authenticator for important accounts.

Keep source, tests and necessary documentation only: no real credentials, private config, build artifacts, agent workspaces or AGENTS.md.

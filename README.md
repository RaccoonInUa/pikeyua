# pikeyua

Experimental USB FIDO2 software authenticator for Raspberry Pi Zero W, derived from [mphi-rc/pi-zero-security-key](https://github.com/mphi-rc/pi-zero-security-key). Apache-2.0; see `LICENSE.txt`.

## Current development status

The physical Raspberry is running the tested **V7.1 persistence baseline**. This branch, `feature/v7.2-discoverable-credentials`, develops **V7.2** separately; it has not been deployed to that device. PR #4 is a draft against `v7.1-persistence`.

V7.2 contains backward-compatible credential schema migration, typed CTAP2 parsing and an **opt-in** implementation of discoverable credentials: RK creation, RP-scoped lookup and multi-account GetNextAssertion. The default executable continues reporting `rk=false`. An isolated candidate may enable RK with `-Dpikeyua.experimentalRk=true` for qualification. Do not change the working service or use live state without a separate migration/rollback plan.

- [V7.2 design review](docs/V7_2_RK_DESIGN_REVIEW.md)
- [Phase A: storage migration](docs/V7_2_STORAGE_MIGRATION.md)
- [Phase B: request parsing](docs/V7_2_PROTOCOL_STAGE_B.md)
- [Stage C: RK implementation, limits and test procedure](docs/V7_2_PROTOCOL_STAGE_C.md)
- [V7.1 persistence acceptance](docs/PERSISTENCE_TESTS.md)
- [Historic V6-to-V7.1 cutover](docs/V7_1_CUTOVER.md) — NOT a V7.2 upgrade procedure

## Build and isolated testing

Use Gradle 8.8 and JDK 17 or 21:

```sh
gradle --no-daemon test shadowJar
sh scripts/verify-persistence.sh build/libs/pikeyua.jar
sh scripts/verify-v72-migration.sh build/libs/pikeyua.jar
java -cp build/libs/pikeyua.jar com.github.mphi_rc.fido2.ResidentCredentialProbe
```

The historic Gradle wrapper script is retained, but its wrapper JAR is not tracked; `./gradlew` needs a separately generated/verified wrapper. No compiled product binaries are committed.

The RK probe uses synthetic keys in its own private temporary directory and three independent JVMs. It never touches the live FIDO service, real credentials, USB, Wi-Fi or boot settings. Its passing result is NOT a browser/USB/ARMv6 qualification result unless separately executed and reported on that hardware.

CI builds the original V7.1 commit `2b218392` independently for a genuine cross-version state test. Candidate JARs are short-lived Actions artifacts, not releases. `pikeyua-v7.2-rk-lab-jdk17` contains the test JAR, commit and SHA-256 checksum; never install it over a live V7.1 JAR just because CI is green.

## Storage and security

State is private software storage (`0700` directory, `0600` JSON and identity marker) with atomic JSON replacement and fsync. Default live path is `/var/lib/pikeyua/config.json`. AAGUID and legacy credential IDs are preserved during forward migration. Downgrading to V7.1 after writing RK state needs a matching protected snapshot; old code may discard RK metadata.

This is a laboratory authenticator **without a secure element or physical touch confirmation**. The headless verifier auto-approves UP. PIN-based UV is not yet qualified; RK alone does not meet `userVerification=required`. Privileged access to the SD card can expose keys. Never rely on this project as the sole authenticator for important accounts.

Repository contents are source, necessary build configuration, tests and product documentation only. Do not commit secrets, real state, binary artifacts, agent workspaces or AGENTS.md.

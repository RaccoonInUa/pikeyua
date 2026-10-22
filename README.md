# pikeyua

Experimental FIDO2 USB authenticator for Raspberry Pi Zero W. Based on [mphi-rc/pi-zero-security-key](https://github.com/mphi-rc/pi-zero-security-key), distributed under Apache License 2.0 (see `LICENSE.txt`).

This repository contains **source, build configuration, tests, and essential documentation only**. No credential state, private keys, compiled authenticators, local secrets or agent workspaces are committed.

## Status

The `main` branch contains a **source reconstruction of the V6 laboratory baseline**, following the previously demonstrated successful CTAP2 `GetInfo`, `MakeCredential`, `GetAssertion` and WebAuthn.io registration/authentication on the owner's Raspberry Pi Zero W.

**Important:** Reconstructed source is not yet proven byte-for-byte equivalent to the installed V6 JAR. It has not passed a clean build/test cycle. The working Pi is intentionally not modified.

The `v7.1-persistence` branch introduces persistence work. Discoverable credentials and reliable PIN-based user verification are not yet complete.

## Build

Use JDK 17 or 21, and Gradle 8.8 for the first clean build:

```sh
gradle test shadowJar
```

The historic wrapper script is included for provenance, but the original binary `gradle-wrapper.jar` is intentionally excluded until a regenerated, verified wrapper is committed. Once Gradle is installed, generate a wrapper if needed with `gradle wrapper --gradle-version 8.8`.

## Security

This is an experimental **software** authenticator, without a secure element. Automatic user-presence approval does not provide meaningful physical touch verification. Never depend on it as the sole security factor for important accounts. Data on the SD card is not hardware protected.

Do not commit `config.json`, credentials, PIN secrets, private keys, system backups or release JARs.

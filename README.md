# pikeyua

A research-grade USB FIDO2 authenticator for Raspberry Pi Zero W, derived from [mphi-rc/pi-zero-security-key](https://github.com/mphi-rc/pi-zero-security-key) (Apache-2.0; see `LICENSE.txt`).

**V7.1 is an unverified persistence candidate, not a production release.** `main` holds the reconstructed V6 baseline. Current work is isolated on `v7.1-persistence`. The original V6 Java archive and Raspberry Pi service are intentionally left untouched.

## What V7.1 changes

- Writes the initial authenticator identity and state **before** attaching USB gadget.
- Makes credential/PIN/counter updates synchronous: a CTAP operation cannot return success if state persistence fails.
- Uses atomic same-directory replacement, file/directory fsync, file permissions `0600`, and a state directory restricted to `0700`.
- Rejects state symlinks, corrupt/unreadable state and insecure permissions instead of silently creating a new identity.
- Stores mutable state in a dedicated directory (default `/var/lib/pikeyua/config.json`, override via `PIKEYUA_STATE_FILE` or Java property `-Dpikeyua.stateFile=...`).
- Adds isolated Java tests for file persistence and insecure storage configurations.

**Unknown:** The original silent `config.json` failure may involve Gson serialization, not just swallowed background exceptions. The new path fails visibly, but is not considered fixed until the actual Pi has successfully written and reloaded credentials. No device installation has been performed.

The V7.1 core deliberately excludes the optional OLED Bonnet / Pi4J dependency, unavailable in Maven Central. If `enableBonnet=true`, startup fails explicitly rather than silently falling back to auto-approval. The default headless mode retains V6's laboratory-only automatic presence approval.

## Build / development

Recommended: JDK 17 and Gradle **8.8** on the Mac. Run:

```sh
gradle test shadowJar
```

The historic wrapper shell script is retained, but this source-only repository does not yet contain the historical binary `gradle-wrapper.jar`; `./gradlew` will require a newly generated, verified wrapper first. Do not assume builds are validated merely because source is committed.

## Isolated Raspberry Pi serialization smoke test

After copying the **candidate** shadow JAR to a separate test location on the Pi, run:

```sh
java -cp pikeyua.jar com.github.mphi_rc.fido2.StateSmokeTest
```

This test requires the Pi's UDC to exist, but **does not bind the USB controller or touch the running V6 service**. It uses a unique private temporary directory and removes its synthetic state afterward. It checks serialization, reload, AAGUID identity, generated test credential, signature counter and a dummy PIN hash. **No live FIDO credential is used.**

## Deployment prerequisites (after build/tests)

The working V6 installation must not be overwritten until V7.1 has passed independent persistence tests. For an isolated test Pi, provision a private persistent directory:

```sh
sudo install -d -o root -g root -m 0700 /var/lib/pikeyua
```

Then start the test JAR with an explicit state path (the default already points here). Never copy `config.json` or private keys into Git. Keep logs free of credentials and PIN material. Test enrollment, assertion, restart, AAGUID/credential stability, and failed writes before upgrading any existing device.

## Security limits

This is not a hardware-secured key. A normal Raspberry Pi SD card does not provide non-extractable secrets. Automatic user-presence approval is not a meaningful physical confirmation. PIN/UV and discoverable credentials are not yet fully implemented; do not claim support. Do not use this as a sole authentication factor for sensitive accounts.

## License

Derived source remains under Apache License 2.0. See `LICENSE.txt`.

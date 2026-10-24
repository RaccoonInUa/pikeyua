# V7.3 — Client PIN and PIN-based User Verification

Status: laboratory implementation candidate, pending exact-build ARMv6 and physical browser/USB qualification. No new switcher, rollback timer, systemd service or deployment subsystem is introduced. Issue #5 was cancelled by the owner. The running Pi has V7.2 with RK advertised; a successful RK-required browser ceremony has not yet been reported.

## Protocol and supported operations

The advertised version remains FIDO_2_0 and PIN protocol remains **1**. This increment implements ClientPIN getRetries, getKeyAgreement, setPIN, changePIN and getPINToken. It does not pretend to support protocol 2 or CTAP2.1 permission-scoped tokens.

Public key agreement is validated P-256 ECDH followed by SHA-256. PIN data uses AES-256-CBC with the protocol-mandated zero IV and zero padding, not PKCS#7. Set/change requests are authenticated with the first 16 bytes of HMAC-SHA-256. Curve identifiers, coordinate sizes/ranges/membership, CBOR types and field lengths are checked before invoking the state machine. Missing fields, wrong types, unsupported protocols and malformed cryptographic input return distinct CTAP errors rather than unchecked casts.

Local new-PIN policy: 4 Unicode code points minimum, at most 63 UTF-8 bytes, well-formed UTF-8, no embedded NUL followed by data, and all-zero trailing padding. The padded ciphertext is bounded to 64–256 bytes, a multiple of 16. The authenticator stores only the first 16 bytes of SHA-256(PIN), not the plaintext. Temporary byte buffers are wiped where practical, but Java does not guarantee elimination of all heap/provider copies.

## Durable retry rules

The PIN hash and PIN retry counter are held in the same atomically replaced JSON record. A PIN hash comparison consumes a retry **durably before the comparison**; a successful PIN resets the counter to eight. A failed/uncertain storage operation yields no token/UV success and latches that PinState unusable until reconstruction. Writes retain the existing fsync/private-permissions behavior; actual power-cut and media-error behavior is not claimed to be tested.

Three consecutive incorrect PIN hashes block further PIN operations for the current daemon process. Eight failed PIN attempts across process restarts produce a persistent PIN_BLOCKED condition. Correct PIN does not unblock zero retries. This is a Linux software emulator: restarting the daemon clears the temporary block, not necessarily requiring a physical power cycle; the persistent eight-attempt budget is not refunded by restart.

Wrong token-HMAC proofs are **not password guesses**, so they do not consume persistent PIN attempts. Three consecutive wrong proofs temporarily block PIN authorization for the process. Malformed requests and bad set/change MACs do not silently change the PIN or decrement the password budget. No host-callable unauthenticated PIN-unlock operation is added. Factory-reset-with-physical-consent remains unimplemented; do not deliberately exhaust your active lab key while expecting an implemented reset ceremony.

## Token and UV semantics

The 32-byte PIN token and ECDH private key are memory-only. A token is delivered only after a correct encrypted PIN hash, never merely because a PIN exists. Successful proofs bind to the 32-byte clientDataHash. Tokens are invalidated by PIN change, process reconstruction, or a ten-minute monotonic lifetime. Assertions and registrations set the signed UV flag only after the token proof is valid. Invalid proofs must not create a credential, release a successful signature or advance a counter.

GetInfo reports `clientPin=false` before PIN setup and `clientPin=true` afterwards. It does **not** advertise the `uv` option, which denotes built-in verification on the authenticator, such as biometrics. Browser WebAuthn `userVerification=required` can instead use the ClientPIN path (pinAuth/pinProtocol). CTAP options.uv requesting an unavailable built-in verification mechanism is still rejected; adding `uv=true` alone never grants verification.

As required by CTAP2.0, once PIN is set, new MakeCredential operations require pinAuth. A GetAssertion without pinAuth may still return a valid UV=0 assertion; the relying party must actually require/check UV to demand PIN verification. PIN setup therefore does **not** mean that every possible authentication is automatically PIN-required.

Names/display names are emitted only when the signed authenticatorData contains UV=1; without verification a discoverable response exposes only its binary user handle. RP scoping, credential IDs, AAGUID, multi-account continuation and durable signature counters are preserved. A verified pending continuation cannot outlive token authorization. Headless User Presence is still simulated, not a real touch.

## State compatibility

V1/V2 files remain readable. Without PIN mutation the existing schema-v2 migration behavior is retained. The first PIN setup, change or retry update writes schema v3, including pinRetries. Legacy stored PIN hashes are imported with eight attempts because historical versions did not store the previous budget. V3 refuses absent/null PIN hash, missing/fractional/string/out-of-range retry count and corrupted state; it does not silently become a new unconfigured authenticator.

Do not downgrade a schema-v3 state file to V7.2; the older reader rejects that schema. This protects persistent PIN lockout from accidental bypass through an older daemon. No important data is assumed on this laboratory Pi, but ordinary credential IDs/private keys/AAGUID are retained rather than deleted.

## Verification

PinUvTest uses a separately written host-side JCE implementation, not the authenticator's PIN crypto helpers. It sends actual CBOR ClientPIN and credential commands, performs encrypted PIN set/change/getToken, checks raw error codes, verifies signatures and signed UV, tests names only after verification, temporary/persistent lockout, token expiry/change/restart, invalid points/types/lengths, malformed state and denied storage. PinStorageValidationTest covers null protected state and non-PIN writes preserving the blocked retry count.

The standalone **PinUvProbe** runs three independent JVMs against a private temporary state with synthetic PINs/credentials only:

```sh
java -cp /path/to/pikeyua.jar com.github.mphi_rc.fido2.PinUvProbe
```

It sets PIN, performs RK and legacy operations using a verified token, changes PIN, refuses the old token/PIN, restarts, verifies the remaining retry count, obtains a new token and verifies signatures. It cleans up its temporary files. It does not access USB, `/dev/hidg0`, systemd, Wi-Fi, boot files or `/var/lib/pikeyua`; run it **without sudo**, with no arguments.

Expected last line:

```text
PASS: PIN set/change, verified RK assertions, token invalidation and persisted retries across independent JVMs
```

CI also retains the V7.2 resident-credential probe, persistence failure cases, schema migration and genuine state generated by a separately built frozen V7.1 JAR. CI success is not a claim that Chrome, libfido2 or the ARMv6 host has tested this exact candidate.

## Remaining limits

There is no secure element, hardware-backed retry counter, anti-rollback SD storage, encrypted-at-rest key store or physical touch. Privileged users or SD-card readers can extract keys and rewrite hashes/counters. Full CTAP canonical-CBOR validation, protocol2, permission-scoped tokens, credProtect, reset hardware and physical storage-fault qualification are separate work. Do not use as the only factor for important accounts.

## Reference

FIDO CTAP 2.0, sections 5.1–5.5: https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html

Use that version's ClientPIN semantics; do not infer CTAP2.1 support from a protocol1 implementation.

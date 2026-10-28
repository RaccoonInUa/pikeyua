# B2 — isolated PKCS#11 FIDO credential lifecycle (laboratory candidate)

Status: source integration and synthetic tests; **not deployed on Pi Zero W**. Based on B1 head `0dc9d2b3ac52dd16f86310dacd3be84b668db747` (PR #9).

## Purpose

B1 validated an external PKCS#11 signing primitive. B2 introduces a `CredentialBackend` using that primitive, with new hardware-style P-256 credentials represented by public descriptors, opaque aliases, and metadata persisted in a **separate** 0600 JSON file in a 0700 directory.

- `TokenKeyDriver`: create, sign, delete. Its interface never exports raw private-key bytes.
- `Pkcs11TokenKeyDriver`: generate P-256 key pairs within the selected provider and create alias metadata certificates through that same provider. Such certificates are **not WebAuthn/FIDO attestation** and never leave as manufacturer proof.
- `DurableTokenCredentialBackend`: create, find, self-attestation registration signing, counter-committed assertion signing, and explicit deletion.
- `Authenticator` already accepts an explicitly injected `CredentialBackend` from phase A. Existing deployed constructors continue using the legacy software backend.
- The **deployed CLI does not select this provider**. Do not install this lab candidate over V7.3.

## Fail-closed persistence

The backend owns one lock file for the full process lifetime. Before generating or deleting token objects, it persists a pending intent using `AtomicStateFile` (file flush, atomic rename, parent directory flush). An interrupted/uncertain mutation causes refusal on startup until manual reconciliation. An absent token or wrong alias never triggers software-key fallback.

Assertions verify a signature with the stored public key, then durably advance their stored counters **before** returning the signature. A failed counter write poisons that backend process. This cannot make dual-file/token transitions fully atomic: token object creation and JSON publication are different persistence domains; crash or storage uncertainty requires conservative owner reconciliation.

Discoverable replacement removes prior **metadata** after the new record is published but intentionally leaves old native key objects for explicit orphan cleanup. There is no automatic deletion after publication because a crash or misidentified alias could destroy a live credential. This means native token storage consumption must be monitored.

The state file contains public SPKI/COSE key bytes, ID, RP, user metadata, alias, created time and counter. It must not contain raw private key bytes. The native PKCS#11 database is a separate store with protected blobs and may contain sensitive metadata; do not treat it as publicly shareable.

## Qualification

- Seven synthetic JUnit cases cover create/sign/reopen, no software fallback with wrong token, pending-marker refusal after uncertain generation/deletion, single-writer locking, stale counter rejection, and discoverable replacement.
- `Pkcs11B2Probe` executes against disposable SoftHSM2 and swtpm + tpm2-pkcs11 native libraries, with separate JVM phases for create, verify, delete and absent state. Independent ECDSA verification checks the actual signed bytes.
- Full Java CI (JDK17+21), original-V7.3 compatibility, and native software-token workflows must pass for the exact head SHA.
- No test proves Java PIN/user-presence policy against compromised Linux, physical non-extractability, real SPI/ARMv6 compatibility, hardware restart latency or acceptance by a third-party site.

## Remaining engineering work for daily use

1. Verify readiness on the actual ARMv6 Pi, confirm exact SPI TPM firmware, vendor advisories and 3.3 V wiring.
2. Qualify token and metadata persistence over power loss, not just process termination. Verify no orphan handling can erase live credentials.
3. Run actual CTAP2 CBOR registration/authorization end to end with injected B2 backend, including ClientPIN UV, RK, GetNextAssertion, and silent up=false probes.
4. Define operator-safe, audit-backed pending-intent reconciliation with independent key checks before any deletion.
5. Add explicit provider selection in a **separate** staging CLI and versioned metadata transitions; never default an old credential into hardware.
6. Design trusted user presence and token-backed PIN/retry enforcement. TPM-backed signatures alone do not make a complete FIDO hardware key.
7. Verify genuine model attestation and service acceptance independently. No vendor AAGUID spoofing.

All test tokens and PINs are synthetic. Existing Pi service, credentials, GPIO and network configuration have not been touched.

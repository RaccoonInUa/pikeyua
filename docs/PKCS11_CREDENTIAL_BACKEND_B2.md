# B2 — isolated PKCS#11 credential backend and recovery laboratory

Status: experimental candidate; not deployed on Pi Zero W. Based on B1
`0dc9d2b3ac52dd16f86310dacd3be84b668db747` (PR #9). Per-commit verification belongs in PR #10.

The current recovery contract, one-command laboratory runner, test coverage and explicit
limitations are in [TOKEN_RECOVERY_B2.md](TOKEN_RECOVERY_B2.md). This replaces the earlier
pending-marker-only design, which deliberately refused all operations after an interruption.

## Components

- `TokenKeyDriver` isolates generation, signing and public-key-bound deletion.
- `Pkcs11TokenKeyDriver` implements the interface with the explicit native provider. Its
  self-signed alias certificate is Java KeyStore metadata, NOT FIDO attestation.
- `DurableTokenCredentialBackend` keeps only public credential data and token references
  in a separate schema-2 state file and a newest-generation redo snapshot.
- `TokenStateFile` flushes file contents, atomically renames and flushes the parent directory.
- `Authenticator` can use this backend by explicit injection. Installed FIDO CLI constructors
  still use the original software backend; there is no silent fallback or automatic migration.

## Recovery behavior

A durable redo snapshot is written before current. Interrupted publication rolls forward;
older backups are never used to regress counters or resurrect deleted credentials.
Incomplete create intents preserve all previous entries and quarantine the incomplete alias.
Deletion commits a pinned tombstone before native cleanup; failure to confirm cleanup does
not revive that credential or prevent unrelated accounts from being used after reopen.
An explicit owner operation retries only bound, already-deleted objects. Unknown orphans
and superseded keys are not automatically destroyed. Conflicting snapshots, lost redo and
unsafe file metadata refuse operation rather than guessing. See the detailed contract.

## Qualification

The suite includes strict state-validation tests, 23 actual forced-child-termination scenarios,
and four independent-JVM CTAP CBOR phases covering ClientPIN, RK/UV, GetNextAssertion,
`up:false`, PIN change/revocation and deletion. Native CI additionally executes the CTAP
phases and six recovery checkpoints with SoftHSM and tpm2-pkcs11 + swtpm. Java 17/21 and
original V7.3 compatibility workflows must pass for the exact published head.

The downloadable laboratory bundle runs without root and only with synthetic credentials.
It does not read real FIDO state, install services or packages, or open USB/TPM devices.
Do not deploy the laboratory JAR over the working V7.3 service after a lab PASS.

## Remaining physical and security qualification

Actual ARMv6 runtime and native ABI, SPI wiring and TPM firmware, physical power cuts and
SD-controller behavior, USB/browser integration, and original-chip versus copied-SD tests
remain separate. Linux-controlled PIN and simulated user presence are not trusted hardware
policy. Whole-card failure, malicious root rollback and loss of a non-exportable private key
cannot be solved by this redo file. Model attestation and third-party site acceptance also
remain independent requirements; no vendor identity is impersonated.

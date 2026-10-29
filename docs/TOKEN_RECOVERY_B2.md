# PiKeyUa B2 recovery laboratory

This is a test candidate, not an installer and not a certified hardware authenticator.
It does not select the native backend in the deployed FIDO CLI. Existing V7.3 credentials,
PIN, network, boot configuration and service must remain unchanged during this qualification.

## One command on the Pi

Unpack the laboratory archive in a new directory owned by the ordinary `key` user. Run:

```sh
bash verify-recovery-lab.sh
```

Do not use sudo. The script checks SHA256SUMS, runs all packaged JUnit classes, starts and
forcibly terminates its own synthetic child processes, checks complete CTAP CBOR/PIN/RK
flows over independent JVMs, runs the existing persistence/PIN probes and prints read-only
hardware inventory. Every state directory is temporary and contains synthetic keys only.
It never opens `/dev/hidg*`, `/dev/tpm*` or `/var/lib/pikeyua/config.json`, and never invokes
systemctl, resets a real PIN, installs packages or edits a boot file. No real state/PIN is
accepted as an input. Do not install this JAR over the running service after a lab PASS.

The fixture token stores synthetic private keys on disk. That is deliberately a test driver,
not a claim of hardware protection. Native CI additionally runs the same lifecycle against
SoftHSM and real TPM2-PKCS11 libraries with independent software TPM instances. Native runtime
libraries, kernel devices and a physical TPM are not supplied in the Pi test archive.

Expected final lines include:

```
PASS: 23 forced-child-termination recovery scenarios; unrelated credentials still sign
PASS: isolated Java, recovery, CBOR, PIN/RK and persistence suite
UNCHANGED: running FIDO service, PIN, real credentials, network and boot configuration
NOT RUN: physical TPM, actual power removal, USB/browser tests or site classification
```

Missing TPM/library fields in the inventory are not a failed FIDO authentication. They are
outstanding prerequisites for physical testing. Keep another independent login method.

## Recovery contract

State schema 2 uses `credentials.json`, `credentials.json.redo` and the pre-existing
`.initialized` marker, in a real 0700 POSIX directory. Files must be regular single-link
0600 files owned by that directory's owner. An OS lock serializes cooperative owner processes.
The marker prevents silent first-boot initialization when both state copies disappear.
It is not a tamper-resistant hardware identity.

For each mutation the complete next generation is checksummed, flushed to a temporary file,
atomically renamed to `.redo` and its parent directory flushed. Only then is the same
snapshot written/flushed/renamed to the current file. Success is returned only after both.
The redo file is the newest durable intended state, NOT a rotating older backup.

Recovery accepts matching generations or rolls the current file forward by one generation.
If current is missing or malformed but redo is valid, it is restored from redo. If redo is
missing/corrupt, or snapshots conflict or regress, startup refuses: an older-looking current
file is not enough evidence to safely restore counters or deletions. Missing marker also
refuses. Permissions, symlinks and hardlinks are not automatically "repaired".

Strict parsing rejects duplicate/unknown JSON keys, numeric strings, fractional/out-of-range
counters, invalid Unicode, duplicate aliases/credential IDs, inconsistent COSE/SPKI public
keys and overlapping active/retired objects. The checksum detects accidental damage; a root
attacker can recompute it or roll back both copies. No hardware anti-rollback is claimed.

### Interrupted creation

A create intent is durably stored before invoking native generation. Until the final creation
snapshot is durable, all existing entries, including a record proposed for replacement,
remain intact. On reopen an incomplete intent is aborted, its unique alias quarantined as
`aborted-create`, and the previous entries remain usable. Recovery never creates another key
under that alias and never deletes an unidentified orphan object.

If the final creation redo is already durable, recovery completes its publication. A response
may have been lost after commit: the new credential is not thereby proved registered on the
relying party. WebAuthn and the local token do not have a shared atomic commit. A deliberately
superseded resident record is retained with its public metadata and native key for owner
review, but is not silently reactivated. Unrelated acknowledged credentials are preserved.

### Interrupted assertion

The signature is independently verified, then its new counter is committed before the signature
is returned. A storage failure releases no signature and poisons that in-process backend.
On reopen redo can consume an extra counter even when the caller never received a signature.
Such gaps are intentional; restoring a smaller counter from an older backup is prohibited.
A repeated request using a stale descriptor/counter is refused.

### Interrupted deletion

Logical deletion and a full pinned tombstone are committed BEFORE attempting native deletion.
The object is absent from discovery and signing even when cleanup fails or the process dies.
Other credentials can still be used after reopen. The owner may explicitly call
`reconcileDeletedObjects()` to retry cleanup. It can only delete a previously revoked alias
whose actual private-key proof matches its pinned public key. It never sweeps arbitrary keys.

If the native object was removed but the cleanup acknowledgment was lost, its tombstone can
remain pending: absence on the currently presented token does not prove which token was
modified. This conservative residue does not revive the credential or block unrelated
credentials. It is not falsely reported as physical secure erasure. Unpinned aborted objects
and superseded objects are never automatically destroyed. Retained records are bounded;
capacity exhaustion refuses new mutation instead of silently discarding audit metadata.

### Existing state

A valid idle B2 schema-1 store upgrades without generating different keys, changing IDs or
resetting counters. A legacy interrupted create can be aborted safely. A legacy pending
`delete:` used native-first ordering and requires owner review: it is not guessed away.
The live V7.3 software state format is unchanged and is not migrated into a hardware backend.
Old software credentials do not retroactively become non-exportable hardware credentials.

## Qualification and its limits

`TokenRecoveryTest` adds malformed/absent/conflicting snapshot tests, counter-write failures,
interrupted replacement, bound deletion cleanup, strict parsing, legacy upgrade and file
safety. `TokenRecoveryProbe` has 23 fresh-child-process termination scenarios at intent,
token generation, redo/current flush/rename, signature/counter, deletion and repeated recovery
boundaries. Its explicit software-native mode adds six checkpoints on each native test stack.

`TokenCtapProbe` uses real CBOR request handlers and an independently implemented ClientPIN
client. Four separate JVM phases cover PIN persistence and retry count, old token invalidation,
PIN change, two resident accounts/GetNextAssertion, silent `up:false`, RP isolation, signed
UV/UP flags, independent P-256 signature verification and deletion without affecting another
account. User presence is still simulated in the current authenticator.

The tests execute on ordinary local POSIX filesystems with injected I/O errors and forced
process termination. They do NOT reproduce a power cut in an SD controller, torn NAND writes,
a lying storage device, filesystem-wide failure or actual TPM hardware reset. Physical Pi
ARMv6, USB/browser, power-cycle and original-chip-versus-copied-SD qualification remain separate.
Recovery cannot reconstruct a lost non-exportable key or rescue an entirely failed SD card.
PIN/UP trust against compromised Linux and third-party model/attestation acceptance are
separate unsolved integration requirements, not inferred from a PKCS11 API flag.

Exact source SHA and checksums are included in the bundle. Per-SHA CI results belong in PR #10;
no undocumented promise that this candidate is production-ready should accompany the archive.

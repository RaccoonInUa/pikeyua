# V7.2 Stage C — experimental discoverable credentials

Status: implementation candidate; on-device and browser qualification pending. The Raspberry Pi's working V7.1 installation is not changed by this branch. PR #4 remains Draft.

## Capability policy

The default executable still reports `rk=false`. Stage C is explicitly enabled with the Java system property `pikeyua.experimentalRk=true`, or through the constructor used by isolated tests. Only an opted-in instance reports `rk=true` and accepts `MakeCredential.options.rk=true` or discoverable lookups. This avoids silently exposing an unqualified feature in existing installations. The test probe enables the feature in synthetic instances only; it never starts a USB gadget.

This property is NOT a PIN, authentication mechanism or security boundary. It is a deployment/qualification gate. The current headless verifier still simulates UP, and the inherited PIN implementation has not been qualified as production-grade UV. Do not use this candidate for real accounts.

## Registration and storage

- MakeCredential is parsed through the shared typed CBOR reader, including RK, UV, RP, user handle, user metadata, algorithms and excludeList.
- A successful RK registration durably stores `discoverable=true`, userId, optional name/displayName and the generated keypair before returning success.
- Re-registering the same RP ID and byte-identical user handle replaces only the prior RK credential(s) in ONE state-list update. Non-discoverable V7.1 credentials for the same account and credentials of other RPs are retained.
- A matching same-RP excludeList entry rejects the request before replacement or key generation. Unsupported UV and invalid PIN authentication never produce new credentials.
- Global RK capacity is 128 records. A new account at capacity returns KEY_STORE_FULL; replacing an existing RK account still succeeds. Physical ENOSPC is a distinct, not-yet-qualified failure case.
- The existing credential-ID formula, AAGUID and schema migration from V7.1 are preserved. New fields do not recalculate legacy IDs.
- Empty `pinAuth` is handled as a CTAP2.0 selection probe: PIN_NOT_SET or PIN_INVALID as appropriate, without creating a dummy credential. Actual Chrome selection behavior must be retested on hardware because the old code used a nonstandard success workaround.

## Assertion discovery and privacy

With RK enabled, an omitted or empty allowList searches ONLY explicitly discoverable credentials for the EXACT RP ID. Non-RK credentials never become discoverable merely because their private keys reside on disk. A nonempty allowList constrains selection to the specified IDs within that RP, including valid legacy credentials.

A discoverable assertion includes `user` at CBOR key 0x04 and at least its binary `id`. Stage C deliberately returns NO userName/displayName values, even though they are stored. In particular, no such identifying metadata is exposed without verified UV. RP binding and signature counters are part of the signed authenticatorData, and signatures are verified in tests against the stored public key.

More than one discovered RK is ordered newest-first by the stored millisecond creation time, with a deterministic bytewise credential-ID tie-breaker. The first response contains `numberOfCredentials` (key 0x05) only when the count exceeds one. Later GetNextAssertion responses omit it. For an explicit allowList, a single applicable credential is returned and no enumeration is created.

## Continuation lifecycle

There is at most ONE transient sequence, bounded by the RK capacity. It stores RP ID, cloned clientDataHash, IDs (not copied private keys), verification outcome, originating HID channel and last successful response time. It is not written to disk.

- GetNextAssertion has no parameters and must arrive on the SAME CID.
- More than 30 seconds since the previous successful response expires the sequence. A monotonic clock is used; each successful continuation refreshes the timer.
- A different CID cannot obtain a signature from another request. The rejected attempt discards the pending sequence.
- Any intervening CTAP command, malformed request, unsupported command, HID INIT or CANCEL invalidates the sequence.
- HID CANCEL returns no standalone response. This implementation cancels pending enumeration; it is not a general asynchronous cancellation implementation for every in-flight cryptographic operation.
- Exhaustion, timeout, missing pending state or a removed credential returns NOT_ALLOWED (0x30).
- Each selected credential is resolved again by RP and ID before use. A signature is returned only after its incremented counter has been durably committed. An unexpected storage error propagates, clears continuation state and must not turn into a successful response.
- Counter rollover is not permitted: the inherited signed-int storage currently fails closed at Integer.MAX_VALUE rather than wrapping. Full uint32 counters are a separate change.

## Automated verification

`DiscoverableCredentialTest` covers real CBOR registration, attestation verification, omitted/empty/explicit allowLists, legacy compatibility, RP scoping, binary user handles without names, multi-account order/count/signatures, CID isolation, timeout refresh/expiry, intervening and malformed commands, reconstruction without pending state, atomic replacement/exclusion, storage denial, bounded capacity, default-off capability reporting, invalid UV/PIN and HID INIT/CANCEL.

The existing V7.1 state/persistence tests and the cross-version test built from the frozen V7.1 JAR remain required.

`ResidentCredentialProbe` additionally uses THREE independent JVMs. The first creates one legacy credential, two RK accounts for one RP and one RK for another RP using actual CTAP MakeCredential CBOR. The next two processes restore them, verify identity/ID/key fingerprints, retrieve assertions and GetNextAssertion responses, verify their signatures and durable counters, and reject cross-RP lookup. No state from the working authenticator is read.

Run the isolated probe on a POSIX host or on Raspberry, without sudo:

```sh
java -cp /path/to/candidate/pikeyua.jar com.github.mphi_rc.fido2.ResidentCredentialProbe
```

It creates a private randomly named temporary directory, runs the child processes and removes synthetic state afterwards. It does not read `/var/lib/pikeyua`, bind UDC, access `/dev/hidg0`, restart services or modify Wi-Fi/boot files.

## Qualification and rollback boundaries

1. Automated Java 17/21 tests, cross-process RK probe, existing persistence and real V7.1-to-V7.2 migration must pass.
2. Run the isolated probe with the exact candidate artifact on Pi Zero W. Record commit/hash and outcome.
3. BEFORE any USB deployment, prepare a separate V7.1-to-V7.2 cutover plan with a protected state snapshot and one-UDC handover. The existing V6 cutover installer is not a V7.2 upgrader.
4. Only in an explicitly enabled isolated USB candidate, verify GetInfo, WebAuthn.io RK-required/UV-discouraged registration, allowList-free authentication, multiple accounts and the same credentials after reboot. No promise is made about browser account selection until those tests run.
5. Do not point old V7.1 code at a schema-v2 file containing RK records: it may discard metadata during writes. Downgrade requires the correct matching state backup and must account for credentials registered after that snapshot.

Remaining limitations: no secure element, simulated physical UP, unqualified old PIN retry/token behavior, no credProtect/credential management, no exhaustive CBOR conformance, and no physical SD power-cut/ENOSPC qualification. RK support alone does NOT satisfy services requiring verified UV.

## Protocol sources

CTAP 2.0, sections 5.1–5.3 (RK creation/replacement, allowList semantics, user privacy, numberOfCredentials and 30-second continuation) and 8.1.9 (HID INIT/CANCEL):
https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html

These are the semantics of the `FIDO_2_0` version advertised by this project. No FIDO certification or full CTAP conformance is claimed.

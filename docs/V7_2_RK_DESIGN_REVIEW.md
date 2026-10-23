# V7.2 design review — Discoverable Credentials (RK)

Status: **design only; no functional changes, no hardware deployment**. Based on inspected source in `v7.1-persistence` at commit `2b218392`. V7.1 is live on the Raspberry Pi Zero W and must not be modified by this branch.

## Verified V7.1 acceptance baseline

- USB CTAP2 GetInfo functional after reboot, stable AAGUID `c1158b74e9c24179825b357a73004f5c`
- Existing test credential successfully authenticates after reboot
- `pikeyua-v7.service` enabled/active, `fido2.service` disabled/inactive, rollback timer disabled
- UDC `20980000.usb` configured; state directory `0700 root:root`, both state JSON and identity marker `0600 root:root`
- Raspberry's Wi-Fi was separately recovered after two zero-byte Netplan YAML files; causality not proven

## Existing source analysis — important issues to fix before enabling RK

1. **Missing allowList crashes parser**: `GetAssertionRequest.fromBytes()` calls `allowList.getDataItems()` without checking whether the array exists. The guard mistakenly checks `relayingPartyId` instead. Correctly represent *absent* allowList, an *empty* allowList, and a non-empty allowList; add CBOR fixtures for each.
2. **Current empty-list behavior is unsafe**: `Authenticator.getAssertion()` selects `creds.iterator().next()` if `publicKeyIds()` is empty. Today this can pick a non-discoverable credential; this MUST NOT be interpreted as RK support. Only explicitly discoverable credentials may be selected without an allowList. No arbitrary first-account selection for multiple discoverable credentials.
3. **No RK option parsed on registration**: `MakeCredentialRequest` parses clientDataHash, RP ID, user ID, algorithms and PIN fields, but neither `options.rk` (CTAP map key `0x07`) nor `excludeList` (key `0x05`). `AuthenticatorRequestHandler` passes no RK flag to the credential creation operation. Validate user entity and CBOR types without unchecked casts.
4. **Credential model lacks discoverability and full user metadata**: `Credential` contains RP ID, created timestamp, raw user ID, keypair and signature count only. Add fields with compatible defaults for old serialized records. The existing computed credential ID must remain unchanged for old credentials; it hashes RP ID + creation time + user ID + public key. New metadata must not enter the existing ID formula until explicit migration/conformance work.
5. **GetAssertion response omits user entity**: `GetAssertionResponse` has a `userId()` member but `asCborMap()` does not emit CTAP key `0x04`. Its map currently contains credential descriptor, authenticatorData and signature only. Discoverable responses must return the required user entity and honor privacy/UV rules.
6. **No multiple-credential continuation**: `GET_NEXT_ASSERTION` is currently dispatched as `INVALID_COMMAND`, and `Authenticator.getNextAssertion()` throws. Implement transient, bounded, per-request enumeration state with expiry/cancellation and a correct `numberOfCredentials` only on the first response. Do not persist active enumeration.
7. **GetInfo correctly advertises `rk: false` today**. Do not flip to true until real implementation, negative tests, CI and Pi hardware/browser tests pass.
8. **Do not persist before rejecting invalid verification**: `Authenticator.makeCredential()` currently saves the credential before checking non-empty PIN authentication. In V7.2, validate CTAP options, permissions and PIN/UV inputs **before** durable mutation. The headless automatic User Presence response is *not* equivalent to physical touch.
9. **Byte arrays in sets**: `GetAssertionRequest.publicKeyIds()` currently returns `Set<byte[]>`, where Java array equality is identity-based. Prefer a value-semantic collection or explicit constant-time byte comparison where relevant, with bound checks. Do not trust arbitrary/unbounded request sizes.
10. **Existing storage is software-only**, with accessible private material to a sufficiently privileged local attacker. Neither RK nor PIN work retroactively supplies a hardware secure element.

## Incremental implementation

### A. Storage model + V7.1 migration

- Introduce discoverability (default false for records without the new field), stored user information and a schema/version marker; validate all before persisting.
- Migration reads V7.1 files without regenerating UUID or credential IDs, altering private keys, erasing credentials or replacing the identity marker. Keep atomic writes and fail-closed on invalid metadata.
- Fixture tests use a representative V7.1 saved record created by code under JDK17/21. Verify old non-discoverable assertions after migration.
- Avoid exposing user names in unauthenticated logs or during cross-RP searches.

### B. Strict MakeCredential semantics

- Parse `options.rk` and `excludeList`; treat absent RK as false.
- If `rk=true`, save a discoverable credential only on successful validation and durable commit.
- Reject unsupported combinations deterministically and avoid false UV claims.
- Preserve existing non-discoverable behavior for `rk=false`.

### C. GetAssertion and GetNextAssertion

- Distinguish missing, empty and non-empty allowList; only query discoverable credentials when no IDs supplied.
- RP ID scoping applies before credential selection. Never return a credential from another RP.
- Correct user entity, descriptor and first-response `numberOfCredentials`.
- Bounded continuation state with deterministic ordering, expiration and correct counter updates. No state leak on error/cancel or across sessions.
- Add negative tests for RP confusion, missing/invalid CBOR, stale continuation, zero matching credentials and multiple users.

### D. Capabilities and hardware acceptance

- Enable `GetInfo.options.rk=true` only at the end, behind test confirmation.
- Pass Gradle/JDK17+21 CI, multi-process persistence, libfido2 CTAP2 tests and WebAuthn.io with `residentKey=required` and `userVerification=discouraged` using synthetic accounts.
- Test with at least two users under one RP, another independent RP, and a legacy V7.1 credential.
- Reboot Pi and repeat *same* test credentials. No overwrite of the current V7.1 JAR prior to explicit acceptance and rollback preparation.

## Version boundaries

V7.2: discoverable credentials, user metadata, multi-assertion, safe storage migration.
V7.3: actual PIN-based UV and related CTAP pinUvAuth correctness.
Separate: physically meaningful User Presence, secure hardware key storage, independent USB rescue interface, full conformance.

**Security note:** this remains an experimental headless software authenticator; automatic UP is insufficient for accounts requiring physical possession proof, and UV must not be asserted without a real verification ceremony.

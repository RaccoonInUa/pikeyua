# V7.2 Stage B — strict CTAP2 request parsing and controlled capability gating

Status: **implemented and tested in development branch only**. Follow-up to [phase A storage migration](V7_2_STORAGE_MIGRATION.md). Actual Raspberry Pi remains on V7.1; no RK capability is advertised or enabled.

## Parser changes

The new `Ctap2CborInput` shares bounded, explicitly typed CBOR accessors:

- Exactly one top-level map and at most 65535 CBOR request bytes.
- Exact 32-byte `clientDataHash`; RP ID string (max 253 UTF-8 bytes) and user handle (1–64 bytes).
- COSE algorithm descriptors must use `type="public-key"` and have integral `alg`; at most 32 algorithm descriptors.
- Credential exclude/allow lists must be arrays of proper `public-key` maps with a 1–1024-byte ID. At most 128 descriptors per list.
- Options `rk` / `uv` / `up` must be CBOR booleans, not quoted strings or integers. Optional PIN fields are typed and bounded.
- For MakeCredential, parses `options.rk`, `options.uv`, optional `up`, `excludeList`, and the user name/displayName.
- For GetAssertion, distinguishes absent, empty and populated `allowList`, and parses `options.uv` / `options.up`.

Malformed fields produce structured CBOR parsing failure rather than unchecked host-controlled casts. The handler no longer logs raw decoded CBOR payloads. PIN hashes and authentication tags have also been removed from upstream debugging logs.

## Deliberately conservative CTAP2 behavior

- **RK true:** explicitly `UNSUPPORTED_OPTION` until the complete RP-scoped GetAssertion, user entity, and GetNextAssertion implementation is present. **GetInfo.rk remains false.** Merely storing `discoverable=true` in test records does not enable discovery.
- **Missing or empty allowList:** `NO_CREDENTIALS` for now; never select an arbitrary legacy non-discoverable credential.
- **Populated allowList:** normal legacy non-RK assertions continue to work with byte-content matching; signature counter is saved durably as before.
- **excludeList:** known credential of the same RP produces `CREDENTIAL_EXCLUDED` before creating new key material. IDs from other RPs do not reveal or exclude their credentials.
- **MakeCredential options.up:** explicit presence rejected with `INVALID_OPTION` under advertised CTAP2.0.
- **Unsupported UV:** requests requiring built-in UV fail rather than claiming verification. Invalid non-empty PIN authentication is checked **before saving any credential**, correcting an old persistence ordering flaw.
- **CTAP2 status framing:** first response byte is the raw status code; optional CBOR body starts *after* it. Previously, status values above 23 were mistakenly CBOR-encoded as multibyte integers.

All of this is part of protocol preparation, **not** a claim that discoverable passkeys already work. Older FIDO2 requests with explicit allowLists remain supported.

## Validation

`CtapRequestParsingTest` includes real CBOR fixtures for `rk=true`, default `rk=false`, metadata, excludeList, omitted/empty/present allowList, malformed descriptors and boolean types, invalid hash length, successful non-RK assertion, RP-scoped exclusion, PIN-auth failure without mutation, unsupported UV and `up` requests, and exact one-byte CTAP error codes.

Existing V7.1/7.2 schema migration and independent-JVM persistence suites remain in CI on Java 17 and Java 21. The original V7.1 frozen binary is still separately built and used as a genuine JSON cross-version compatibility fixture.

## Still needed for V7.2 C

Implement actual discoverable creation, RP ID–scoped lookup with no allowList, full user entity response (CTAP2 map key 0x04), multiple accounts with GetNextAssertion and expiry/cancel behavior, RP/user privacy rules, and end-to-end WebAuthn tests. Only then set `GetInfo.options.rk=true`.

The security model is unchanged: automatic simulated UP is not a physical touch, no PIN-based UV yet, and all software keys remain extractable to a privileged SD-card attacker. Test accounts only.

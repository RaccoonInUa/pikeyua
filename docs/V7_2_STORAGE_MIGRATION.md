# V7.2 phase A — credential schema and V7.1 compatibility

Status: **implemented and automatically verified; design/development branch only.** This change does not implement CTAP2 `rk=true`, modify GetInfo or deploy to the physical authenticator.

## Storage contract

Old V7.1 `config.json` objects omit `schemaVersion` and each credential has no `discoverable`, `userName` or `userDisplayName`. The V7.2 model interprets these omissions as:

- `schemaVersion = 1`: a legacy file; reading it is strictly non-mutating.
- `discoverable = false`: an existing key must **never** become discoverable without an explicit, separately reviewed action.
- `userName = ""`, `userDisplayName = ""`: display information is absent on legacy records.
- Existing `userId` is the CTAP user handle. V7.2 does not recalculate it.

On the first authorized write V7.2 serializes `schemaVersion = 2`, preserving the UUID, identity marker, original credentials and private/public key bytes. Future/invalid schema versions are rejected during load.

**Computed credential IDs are unchanged**. The original formula hashes RP ID, creation timestamp in milliseconds, user ID and public key. The new metadata and `discoverable` flag must not contribute to the ID.

This is an additive internal model change. **GetInfo continues to advertise `rk: false`**, and current WebAuthn/CTAP2 paths do not yet create or look up discoverable credentials.

## Validation and limits

- Metadata user name is limited to 64 UTF-8 bytes and display name to 128 UTF-8 bytes.
- A discoverable credential must have a non-empty user handle of at most 64 bytes.
- Existing legacy records may have a different shape and are accepted without silent modifications, to preserve compatibility.
- Gson reads v1 state with default values and writes v2 state through the existing atomic, root-private, fsynced V7.1 storage path.
- No real credentials or keys are copied into tests or Git. All test keys are generated temporarily and deleted after each test run.

### Automated tests

`CredentialSchemaCompatibilityTest` verifies:

1. Legacy JSON with missing V7.2 fields reads as schema v1 with non-discoverable credentials.
2. Reading old state leaves the JSON bytes unchanged.
3. After the first authorized mutation the schema is v2; same AAGUID, credential ID, key material and counter remain valid.
4. New discoverability and user metadata survive serialization and reload.
5. Metadata changes never alter the credential ID; invalid user handles and oversized metadata are rejected.
6. Unsupported future schema versions fail closed.

`sh scripts/verify-v72-migration.sh build/libs/pikeyua.jar` runs creation, legacy-load, upgrade and verification in **four independent JVMs**.

`sh scripts/verify-v72-cross-version.sh old-v71.jar candidate-v72.jar` provides a stronger guarantee: the **actual frozen V7.1 source at commit `2b218392` is separately compiled**, writes genuine V7.1 JSON with a synthetic credential, and the V7.2 code loads the file without rewriting it, upgrades only on a mutation and verifies the same AAGUID, credential ID, private/public key fingerprints and usable digital signature across fresh JVMs.

CI runs Java 17 and 21; the actual cross-version build runs on Java 17.

## Important safety limitations

**Do not test against the live Raspberry's `/var/lib/pikeyua/config.json`.** The installed V7.1 remains the accepted lab baseline.

After V7.2 begins writing discoverable credentials, **downgrading to V7.1 without a matching protected state snapshot is unsafe**: older code does not understand RK metadata and may silently drop it on subsequent writes. A future deployment migration/rollback procedure must account for that. The current V6→V7.1 cutover script is not a V7.2 migration tool.

State is still kept on the Pi microSD, without hardware protection. This version does not implement hardware User Presence, PIN-based User Verification, credential management or secure-element semantics.

## Next engineering increment

Implement strict CTAP2 parsing for `MakeCredential.options.rk`, `excludeList`, and `GetAssertion.allowList`, keeping legacy non-discoverable lookups correct. Then introduce RP-scoped discoverable lookups, user entity in assertion responses, bounded multi-credential enumeration and `GetNextAssertion`. Only after tests and real Pi WebAuthn qualification should `GetInfo.options.rk` become true.

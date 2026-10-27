# Credential backend boundary — phase A

Status: implemented software refactor; hardware provider NOT implemented or qualified.
Base: V7.3 `35193a6055519655c657e76ba4a83b9821737f3e`, including USB-boundary and silent-assertion fixes.
No live Raspberry deployment, new systemd unit, installer, switcher or timer.

## What changes

`Authenticator` depends on `CredentialBackend` for public credential discovery, creation,
self-attestation signing and assertion signing. It no longer imports any
`AttestationKeyPair`, constructs key pairs, calls `keyPair()` or uses private-key bytes.
Existing constructors remain compatible and explicitly install `LegacySoftwareCredentialBackend`.
A new constructor accepts exactly one backend. There is no provider fallback or automatic
substitution if the configured provider is unavailable, refuses an operation or lacks an algorithm.

The public contract exposes:

- `create(...)`: generate and durably publish a credential; return only `CredentialDescriptor`.
- `find(rpId)`: public descriptors for an exact relying party.
- `signRegistration(handle, data, hash)`: the existing packed SELF-attestation operation.
- `signAssertion(handle, data, hash)`: validate the next counter, sign, persist that counter,
  and only then return the signature. An uncertain write yields no successful response.
- `delete(handle)`: exact local owner operation; no new CTAP deletion command is exposed.
- `supportedAlgorithms()`: registration selects the intersection of request, configuration
  and provider algorithms, never a software fallback for a missing hardware algorithm.

`KeyHandle` is an immutable provider/RP/opaque-ID locator, NOT a bearer capability, secret,
proof of authorization, claim of hardware protection or promise of an uncopyable token.
A handle's opaque ID need not equal the wire credential ID. The legacy adapter uses the
existing credential ID as its locator. Arrays in handles/descriptors are defensively copied;
`toString()` does not print accounts, IDs or public key blobs.

`CredentialDescriptor` contains ID, user metadata, creation time, counter, algorithm and
public keys (SPKI and encoded COSE), but no key pair or private material. The public encoder
writes the credential-ID length correctly as an unsigned two-byte value; existing 16-byte
IDs retain the same encoding.

## Compatibility boundary

The legacy adapter is still SOFTWARE. It owns access to the existing `CredentialStore`
and serialized `Credential.keyPair`. Existing schema v1/v2/v3, private/public key bytes,
credential-ID derivation, PIN/retries, device identity/AAGUID and `.identity` marker are
unchanged. Merely loading/listing through the adapter never rewrites a state file.
The separate local credential-management utility continues to see the original format.
No old key is imported into hardware or relabelled as hardware-protected.

Assertion signing checks handle provider, RP and existence, rejects stale/exhausted counters,
and returns a signature only after durable counter update. If update fails, its temporary
signature byte array is wiped and the error propagates. This is not a guarantee that Java
or cryptographic providers erase all internal copies. Operations are serialized on the
legacy store object; the existing one-writer service/owner-management discipline remains
required. This is NOT a multiprocess transaction/locking redesign.

Owner deletion refuses absent, wrong-RP, foreign-provider and ambiguous IDs. It atomically
removes exactly one record and does not reset PIN/retries or identity. It is not secure SD
media erasure. The Java owner method does not stop services or replace the existing CLI's
operational safeguards.

Registration retains the previous ordering: durable credential publication precedes the
self-attestation signature. If signing then fails, an unused credential can remain. This
increment does not pretend to solve hardware generation/metadata crash reconciliation.

## What this does NOT secure

This is an architectural boundary, not an isolation boundary against a compromised JVM,
root, malicious SD contents or a modified JAR. The compatibility provider still holds
software private keys in memory and on SD. Legacy persistence DTOs and compatibility/test
helpers intentionally retain `privateKey()` below the boundary. PIN/UP decisions still
execute in Linux; headless UP is still simulated.

No TPM, secure element, hardware-enforced PIN retry counter, protected touch, verified boot,
manufacturer attestation, non-exportability claim, new AAGUID, vendor impersonation or
server-side hardware classification is added. The test-only opaque backend uses ordinary
in-memory JCE keys; it is NEVER registered as a production provider and is not hardware.

## Tests

20 new standalone/JUnit contract scenarios cover the public API and Authenticator constant
pool, defensive copies, P-256/Ed25519 real signatures, read-only loads, stable references
across reconstruction, provider/RP isolation, stale counters, deletion, preservation of
blocked PIN state and other credentials, denied writes, RK replacement, two-byte wire
lengths, opaque-provider registration/assertions/continuation, unavailable-provider failures
and unsupported algorithm refusal without software fallback.

The opaque test provider exposes no key-pair/private-byte accessor to Authenticator. Its
registration and assertion signatures are checked independently, and the legacy config
must remain empty. It demonstrates removal of the *protocol layer's* dependence on raw
keys; it does not demonstrate physical key non-extractability.

`verify-key-backend-cross-version.sh` uses an independently compiled original V7.3 JAR to
create synthetic state, the candidate backend to read it byte-preservingly and sign, then
ONLY the old JAR plus a tiny independent readback checker to reread candidate-written
state. The original private/public keys, ID, schema, PIN/retries and AAGUID must be unchanged,
while the signature counter advances once. No actual account or live state is used.

The full existing PIN, RK, silent assertions, USB, storage and frozen-V7.1 migration suites
remain required. CI success is not a physical USB/browser or ARMv6 qualification.

## Phase B gate: actual hardware provider

Choose one concrete component and verify its actual ARMv6 integration before buying an
unqualified module or claiming success. The provider must generate P-256 keys inside the
component, sign without bringing plaintext private bytes into Java, persist public metadata
and bound handles, and fail closed on token absence, foreign token, corruption or lost
objects. No plaintext fallback, implicit key import or automatic downgrade.

A future versioned handle-only state format must preserve legacy software credentials as
software, and separate model AAGUID from device identity without silently changing existing
records. Define crash-safe create/commit/replacement/delete and orphan reconciliation before
using hardware handles with durable credentials. Test an SD clone against another device:
the clone must not sign for the original hardware-backed credential.

Key non-extractability is separate from authorization: an unrestricted hardware signing
oracle controlled by compromised Linux does not enforce trusted UV/UP. A stronger design
must protect those decisions and retries, not merely key storage. A real hardware provider
and trusted attestation also do not by themselves establish acceptance by a third-party site.

References (design context, not evidence that hardware is implemented):
- https://www.w3.org/TR/webauthn-3/ — authenticator data and signature/attestation roles.
- https://docs.oracle.com/en/java/javase/21/security/pkcs11-reference-guide1.html — Java provider-based operations; an actual PKCS#11 implementation/library is separate.

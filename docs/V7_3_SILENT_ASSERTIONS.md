# V7.3 compatibility correction: silent GetAssertion

## Observed failure

An operator's Chrome trace showed successful ClientPIN getPINToken, then GetAssertion with an explicit allowList, valid-looking pinAuth/protocol 1 and `options.up=false`. The installed `ad1c3c7f` build returned UNSUPPORTED_OPTION (0x2b). Chrome followed with its `.dummy` MakeCredential touch/selection probe with an empty pinAuth; the authenticator returned PIN_INVALID (0x31), and the browser reported its generic OTHER (127) result.

The later PIN_INVALID is not evidence that the entered PIN failed. The real token request already succeeded. No PIN reset is needed for this sequence. No user account, credential ID, challenge, encrypted PIN proof or token from the report is stored here.

## Protocol basis

CTAP2.0 section 5.2 defines `up` separately from `uv`, defaults `up` to true, and defines signed flags UP=0/UV=0 (silent) and UP=0/UV=1 (verified without presence). The underlying credential matching, pinAuth validation, signature and counter rules still apply.

Chromium MakeCredentialTask::NextSilentRequest sends `up=false` to check excludeList batches, optionally using the token from PIN verification. A miss must be NO_CREDENTIALS, while a known matching credential yields an assertion and the later real registration can reject it as CREDENTIAL_EXCLUDED. An unexpected error triggers GetTouchRequest and HandleResponseToDummyTouch reports generic OTHER.

References:
- https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetAssertion
- https://raw.githubusercontent.com/chromium/chromium/main/device/fido/make_credential_task.cc

## Changes

- Do not reject GetAssertion merely because up=false. Skip the presence callback in that case, but continue validating supplied pinAuth/protocol and exact RP/credential ID matching.
- Encode UP from the actual request. Keep UV dependent on successful token proof. Do not silently force UP=1 or make all silent probes return success/miss.
- Preserve the UP decision in multi-account GetNextAssertion state. Ordinary requests (up omitted or true) retain their existing behavior.
- Replace BitSet.toByteArray()[0] flag encoding with a fixed one-byte bit mask. An all-zero UP/UV/AT flags byte is valid and previously caused an index exception.
- Existing PIN hashing, retry persistence, state schemas, storage paths, identity, keys and service configuration are unchanged. The original headless presence simulation remains a lab limitation. No deployment framework or credential deletion is introduced.

## Regression coverage

17 synthetic scenarios exercise known/unknown IDs, RP separation, legacy/RK signatures, signed UP/UV combinations, unauthenticated metadata privacy, supplied bad pinAuth, unsupported built-in UV, dummy-selection semantics, Chrome-shaped exclude probing with SHA-256(empty) followed by actual registration, duplicate exclusion, continuation, no flag carryover, denied persistence and all UP/UV/AT flag combinations.

The standalone runner can compile against the frozen V7.3 artifact to demonstrate failures before the fix. JUnit invokes each scenario separately in the normal Java 17/21 CI suite. Local verification with the fixed classes passed all 17 and retained passing PinUvProbe/ResidentCredentialProbe. Remote CI and the physical browser retry must be checked separately; a successful test harness is not a claim of successful registration on the reported site.

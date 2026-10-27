# Phase B1: native PKCS#11 qualification before a hardware credential backend

Status: experimental signing primitive and isolated native-library tests. NOT a complete
CredentialBackend, NOT installed on Pi, no physical TPM qualification or FIDO capability change.
Base: phase A d86857cb8d288fe314d9387710a8dfb910c4c6f3. Per-commit test outcomes are recorded in PR #9.

## Selected direction, not a purchase guarantee

First physical candidate: GPIO/SPI TPM2, evaluating LetsTrust TPM with Infineon SLB9672.
The manufacturer announced an SLB9670 -> SLB9672 change in May 2024 and continued use of
the tpm-slb9670 overlay. The Raspberry Pi overlay targets BCM2835, SPI0 CE1. This is an
integration path, not proof that our exact Zero W ARMv6 kernel, Java runtime, 32-bit native
dependencies, wiring or module firmware work. Do not buy solely on this note; first collect
read-only prerequisites and verify the exact board revision, current manufacturer firmware
security advisories, 3.3 V compatibility, available GPIO header and wiring. USB remains dedicated
to the existing FIDO gadget; no USB-host TPM is selected.

Architecture under evaluation:
Java -> explicit SunPKCS11 provider -> libtpm2_pkcs11 -> TPM2 TSS -> SPI TPM.

TPM2-PKCS11 stores metadata and protected object blobs in its database. Binding depends on
TPM-generated objects and attributes. CKA_EXTRACTABLE=false and Java getEncoded()==null alone
are NOT proof of hardware protection: the same interface supports SoftHSM or software TPMs.

## Code in this increment

Pkcs11P256Signer is an experimental signing primitive, not selected by the FIDO CLI. It
requires an explicit absolute native module, numeric slot and token-login PIN as a caller-owned
character array. There is no first-token search, provider-list fallback, private-key import,
package installation or token initialization. The token PIN is NOT the FIDO/ClientPIN PIN.

The class resolves the token key using a public reference (alias + pinned P-256 SPKI), refuses
an exportable private encoding, and signs with the explicit native provider. It independently
verifies the signature against the pinned public key before returning it. Missing token,
wrong public mapping, missing module or unsupported mechanism refuses instead of switching
to software. References are immutable with defensive copies and redacted string representations.

A reference is not an authorization, attestation or physical device-identity proof. The native
module is trusted code; an untrusted client must not choose its pathname. Root or a compromised
JVM can still request signatures; trusted PIN/touch/retry enforcement is NOT implemented here.

Runtime needs JDK17/21 with jdk.crypto.cryptoki and a matching native ABI. Public Provider.configure()
is reflected only to preserve the existing Java-8 bytecode target; no sun.security.* API or
--add-opens. Actual execution of this new path on Java 8 is unsupported. Legacy FIDO is unchanged.

## Real native test, explicitly software-only

Pkcs11LabProbe exists in test sources ONLY, not in the runnable JAR. A fresh dedicated test
token generates P-256 inside the selected provider with sensitive/non-extractable attributes.
A self-signed X.509 certificate supplies Java KeyStore alias metadata; it is NEVER FIDO
attestation, manufacturer identity, an x5c chain or a trust anchor. Only SPKI public bytes
are written to the reference file. Test PINs are public synthetic fixtures.

Separate JVM phases create, sign after restart, delete and refuse the deleted key. Another
token with the same alias but a different key must fail. Real DER ECDSA signatures are checked
independently. Missing native modules must refuse without fallback.

Run the native fixtures on a disposable Linux development runner, NOT on the working key:

```
dbus-run-session -- bash scripts/test-pkcs11-native.sh --software-tokens-only \
  "$PWD/build/classes/java/test:$PWD/build/libs/pikeyua.jar"
```

The script owns a private temporary root and explicitly forces SoftHSM configuration plus
two isolated software-TPM TCTIs. Each simulator has an ephemeral, unprivileged tpm2-abrmd
resource manager on that private session bus. It never chooses /dev/tpm*, changes live FIDO
state or installs packages. CI installs dependencies only on disposable runners. Package
installation may provision a default distro unit there, but the fixtures do not use it.
No resource-manager service or timer is installed on the user's Pi.

Two integration constraints were discovered with the actual native libraries, not mocks:

- Direct swtpm without a resource manager exhausted transient object slots during token
  provisioning (TPM_RC_OBJECT_MEMORY). The fixture now supplies its own bounded resource manager.
- TPM2-PKCS11 1.9 requires persistent CKA_TOKEN=true for BOTH public and private key templates.
  The private object remains sensitive and non-extractable. The upstream attribute diagnostic
  reverses actual/expected values; changing private-key protection is not a valid workaround.

The TPM test copies only the PKCS11 store to a second simulator with a different seed and
expects refusal. It has positive signing controls on both simulators before/after the refusal.
This checks stack/device binding, NOT physical anti-cloning. Copying an entire software TPM
state can clone it; actual SD-copy resistance must be qualified with physical components.

Generation may leave orphan objects if alias/certificate association fails. Lab tokens are
discarded on failure. Deleting a Java alias proves that the associated signing entry is gone;
it does not certify full native-object garbage collection or secure erasure. Production
crash-safe generation/metadata commit/replacement/deletion and orphan reconciliation are
not claimed or exposed as a FIDO implementation in B1.

## Read-only prerequisites on the existing Pi

Run without sudo: python3 pikeyua-hardware-readiness.py

It inventories model/ABI, Java cryptoki module, native-library ELF class/machine, TPM device-node
and overlay presence, and tool availability. It does not execute TPM commands, open TPM nodes,
modify service/boot/network state, read PINs or credentials, initialize tokens or load drivers.
ELF machine alone does not prove ARMv6 instruction compatibility. Missing TPM hardware is
expected before installation and does not instruct the user to change the running Pi.

## Separate remaining gates

1. Verify actual Pi Java/native ABI, SPI wiring/module detection without clearing any TPM.
2. Qualify token generation, signing, process restart and separation on physical hardware.
3. Implement versioned handle-only state and crash/orphan handling under CredentialBackend.
4. Integrate a separate FIDO candidate. Legacy keys stay software; fresh hardware-generated
   credentials require new registrations. No retroactive non-exportability labels.
5. Protect PIN/UP/sign authorization; a hardware signing oracle alone is not sufficient.
6. Model AAGUID, attestation trust and third-party acceptance remain independent work.

No new Pi service, timer, switcher, updater, model impersonation or site-policy workaround.

## Primary sources

- https://docs.oracle.com/en/java/javase/21/security/pkcs11-reference-guide1.html
- https://github.com/tpm2-software/tpm2-pkcs11/blob/1.10.1/docs/INITIALIZING.md
- https://github.com/tpm2-software/tpm2-pkcs11/blob/1.10.1/docs/ARCHITECTURE.md
- https://github.com/tpm2-software/tpm2-pkcs11/blob/1.9.0/src/lib/tpm.c (tpm_handlers CKA_TOKEN)
- https://github.com/tpm2-software/tpm2-abrmd/blob/3.0.0/man/tpm2-abrmd.8.in
- https://github.com/raspberrypi/linux/blob/rpi-6.12.y/arch/arm/boot/dts/overlays/tpm-slb9670-overlay.dts
- https://www.letstrust.de/ (2024-05-09 change notice and 2026 firmware advisories)

Dependency versions are recorded in CI logs. x86-64/emulator results are not ARMv6/physical
hardware qualification, nor a promise of third-party hardware-key classification.

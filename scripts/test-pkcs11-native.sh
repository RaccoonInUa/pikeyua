#!/usr/bin/env bash
# Dedicated CI/lab software tokens ONLY. No real TPM device or live FIDO state.
set -euo pipefail
umask 077
[[ $# == 2 && $1 == --software-tokens-only ]] || {
  echo 'Usage: bash scripts/test-pkcs11-native.sh --software-tokens-only /absolute/test-classpath' >&2; exit 2;
}
CP=$2
WORK=$(mktemp -d /tmp/pikeyua-p11-ci-XXXXXXXX)
PIDS=()
cleanup() {
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
  rm -rf -- "$WORK"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
for binary in java pkcs11-tool softhsm2-util swtpm tpm2_ptool tpm2_getcap; do
  command -v "$binary" >/dev/null || { echo "Missing dependency: $binary" >&2; exit 2; }
done
SOFT=$(find /usr/lib -name libsofthsm2.so -type f -print -quit)
TPM=$(find /usr/lib -name 'libtpm2_pkcs11.so.1*' -type f -print -quit)
[[ -n $SOFT && -n $TPM ]] || { echo 'Missing native PKCS11 modules' >&2; exit 2; }
# Deliberately public, disposable test credentials, never an account's real PIN.
printf '%s' 987654321 > "$WORK/pin"
chmod 600 "$WORK/pin"
slot_for() {
  pkcs11-tool --module "$1" --list-token-slots 2>/dev/null | python3 -c '
import re, sys
text=sys.stdin.read()
slots=[]
for block in re.split(r"(?=^Slot )",text,flags=re.M):
    if re.search(r"token label\s*:\s*pikeyua-lab\s*$",block,re.M):
        m=re.search(r"^Slot \d+ \((0x[0-9a-fA-F]+)\)",block)
        if m: slots.append(int(m.group(1),16))
if len(slots)!=1: raise SystemExit("Expected exactly one dedicated lab token")
print(slots[0])'
}
probe() {
  java -cp "$CP" com.github.mphi_rc.fido2.authenticator.keys.pkcs11.Pkcs11LabProbe \
    --disposable-token "$1" "$2" "$3" "$WORK/pin" "$4"
}
expect_failure() {
  if "$@" > "$WORK/expected-failure.log" 2>&1; then
    echo 'FAIL: negative control unexpectedly succeeded' >&2; exit 1
  fi
  echo 'PASS: mismatched/missing token refused (no software fallback)'
}
soft_token() {
  mkdir -p "$WORK/soft-$1/objects"
  export SOFTHSM2_CONF="$WORK/soft-$1/softhsm.conf"
  printf 'directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n' \
    "$WORK/soft-$1/objects" > "$SOFTHSM2_CONF"
  softhsm2-util --init-token --free --label pikeyua-lab --so-pin 123456789 --pin 987654321 >/dev/null
}
echo 'TEST: SoftHSM2 native PKCS11, independent JVMs'
soft_token a
SLOT=$(slot_for "$SOFT")
probe create "$SOFT" "$SLOT" "$WORK/a.spki"
probe verify "$SOFT" "$SLOT" "$WORK/a.spki"
pkcs11-tool --module "$SOFT" --slot "$SLOT" --login --pin 987654321 --list-objects > "$WORK/objects.txt"
grep -q 'never extractable' "$WORK/objects.txt"
echo 'PASS: PKCS11 token reports never-extractable key attribute (not physical proof)'
soft_token b
B_SLOT=$(slot_for "$SOFT")
probe create "$SOFT" "$B_SLOT" "$WORK/b.spki"
probe verify "$SOFT" "$B_SLOT" "$WORK/b.spki"
expect_failure probe verify "$SOFT" "$B_SLOT" "$WORK/a.spki"
export SOFTHSM2_CONF="$WORK/soft-a/softhsm.conf"
probe delete "$SOFT" "$SLOT" "$WORK/a.spki"
probe absent "$SOFT" "$SLOT" "$WORK/a.spki"
expect_failure probe verify /nonexistent/pikeyua-native.so "$SLOT" "$WORK/a.spki"

start_sim() {
  local name=$1
  mkdir -p "$WORK/$name/state" "$WORK/$name/store"
  swtpm socket --tpm2 --tpmstate "dir=$WORK/$name/state" \
    --server "type=unixio,path=$WORK/$name/tpm.sock" \
    --ctrl "type=unixio,path=$WORK/$name/tpm.sock.ctrl" \
    --flags not-need-init,startup-clear --daemon --pid "file=$WORK/$name/pid"
  PIDS+=("$(cat "$WORK/$name/pid")")
  export TPM2TOOLS_TCTI="swtpm:path=$WORK/$name/tpm.sock"
  export TPM2_PKCS11_TCTI="$TPM2TOOLS_TCTI"
  export TPM2_PKCS11_STORE="$WORK/$name/store"
  [[ $TPM2TOOLS_TCTI == swtpm:path=/tmp/pikeyua-p11-ci-* ]] || exit 2
  for attempt in {1..20}; do
    if tpm2_getcap properties-fixed >/dev/null 2>&1; then return 0; fi
    sleep 0.1
  done
  echo 'Software TPM did not start' >&2; exit 1
}
echo 'TEST: tpm2-pkcs11 + independent software TPM instances (NOT physical TPM)'
start_sim tpm-a
# These commands mutate TPM state only in the explicitly selected disposable
# simulator. NEVER use this script as a real TPM/Pi provisioning installer.
tpm2_ptool init --path "$TPM2_PKCS11_STORE" > "$WORK/init-a.log"
tpm2_ptool addtoken --pid=1 --sopin=123456789 --userpin=987654321 --label=pikeyua-lab \
  --path "$TPM2_PKCS11_STORE" > "$WORK/add-a.log"
T_SLOT=$(slot_for "$TPM")
probe create "$TPM" "$T_SLOT" "$WORK/tpm-a.spki"
probe verify "$TPM" "$T_SLOT" "$WORK/tpm-a.spki"
cp -a "$TPM2_PKCS11_STORE" "$WORK/clone-store"
start_sim tpm-b
tpm2_ptool init --path "$TPM2_PKCS11_STORE" > "$WORK/init-b.log"
tpm2_ptool addtoken --pid=1 --sopin=123456789 --userpin=987654321 --label=pikeyua-lab \
  --path "$TPM2_PKCS11_STORE" > "$WORK/add-b.log"
TB_SLOT=$(slot_for "$TPM")
probe create "$TPM" "$TB_SLOT" "$WORK/tpm-b.spki"
probe verify "$TPM" "$TB_SLOT" "$WORK/tpm-b.spki"
# Copy only the PKCS11 store, NOT the simulator seed/state, to another TPM.
export TPM2_PKCS11_STORE="$WORK/clone-store"
expect_failure probe verify "$TPM" "$T_SLOT" "$WORK/tpm-a.spki"
# Positive controls before and after clone denial distinguish actual separation
# from a broken simulator/native stack.
export TPM2_PKCS11_STORE="$WORK/tpm-b/store"
probe verify "$TPM" "$TB_SLOT" "$WORK/tpm-b.spki"
export TPM2TOOLS_TCTI="swtpm:path=$WORK/tpm-a/tpm.sock"
export TPM2_PKCS11_TCTI="$TPM2TOOLS_TCTI"
export TPM2_PKCS11_STORE="$WORK/tpm-a/store"
probe verify "$TPM" "$T_SLOT" "$WORK/tpm-a.spki"
probe delete "$TPM" "$T_SLOT" "$WORK/tpm-a.spki"
probe absent "$TPM" "$T_SLOT" "$WORK/tpm-a.spki"
echo 'PASS: native PKCS11 persistence, signatures, wrong-token/clone denial and deletion'
echo 'NOT TESTED: physical TPM, ARMv6, trusted PIN/touch, FIDO integration, physical anti-extraction'

#!/usr/bin/env bash
# Isolated tests only: this is NOT a service installer and never opens a real TPM/USB node.
set -euo pipefail
umask 077
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
if [[ ${EUID:-$(id -u)} == 0 ]]; then
  echo 'Run as the ordinary key user, without sudo. This test does not need root.' >&2
  exit 2
fi
for name in java python3 sha256sum; do
  command -v "$name" >/dev/null || { echo "Missing prerequisite: $name" >&2; exit 2; }
done
cd "$HERE"
sha256sum -c SHA256SUMS
[[ $(wc -l < COMMIT.txt) == 1 ]] || exit 2
WORK=$(mktemp -d "${TMPDIR:-/tmp}/pikeyua-all-checks-XXXXXXXX")
cleanup() { rm -rf -- "$WORK"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
export TMPDIR="$WORK"
CP="$HERE/pikeyua-lab-tests.jar:$HERE/pikeyua.jar:$HERE/junit-4.12.jar:$HERE/hamcrest-core-1.3.jar"
JAVA=(java -Xmx128m "-Djava.io.tmpdir=$WORK")
echo '=== PINNED LAB SOURCE ==='
cat COMMIT.txt
java -version 2>&1
echo '=== FULL JAVA UNIT SUITE (SYNTHETIC STATE) ==='
mapfile -t TESTS < TEST_CLASSES.txt
[[ ${#TESTS[@]} -gt 0 ]] || exit 2
"${JAVA[@]}" -cp "$CP" org.junit.runner.JUnitCore "${TESTS[@]}"
echo '=== CHILD-PROCESS INTERRUPTION AND RECOVERY ==='
"${JAVA[@]}" -cp "$CP" com.github.mphi_rc.fido2.authenticator.keys.token.TokenRecoveryProbe
echo '=== CTAP PIN + RESIDENT CREDENTIALS + RESTART ==='
mkdir -m 700 "$WORK/ctap"
for phase in create verify final remaining; do
  "${JAVA[@]}" -cp "$CP" com.github.mphi_rc.fido2.TokenCtapProbe \
    --software-token "$phase" file-fixture 0 /dev/null "$WORK/ctap"
done
echo '=== EXISTING PERSISTENCE / RK / PIN REGRESSIONS ==='
sh "$HERE/verify-persistence.sh" "$HERE/pikeyua.jar"
sh "$HERE/verify-v72-migration.sh" "$HERE/pikeyua.jar"
"${JAVA[@]}" -cp "$CP" com.github.mphi_rc.fido2.ResidentCredentialProbe
"${JAVA[@]}" -cp "$CP" com.github.mphi_rc.fido2.PinUvProbe
echo '=== READ-ONLY HARDWARE INVENTORY ==='
python3 "$HERE/pikeyua-hardware-readiness.py"
echo 'PASS: isolated Java, recovery, CBOR, PIN/RK and persistence suite'
echo 'UNCHANGED: running FIDO service, PIN, real credentials, network and boot configuration'
echo 'NOT RUN: physical TPM, actual power removal, USB/browser tests or site classification'

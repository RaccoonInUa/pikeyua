#!/bin/sh
# Real cross-version compatibility: V7.1 compiled separately creates state;
# V7.2 reads it unchanged, upgrades it, then verifies across fresh JVMs.
set -eu
if [ "$#" -ne 2 ] || [ ! -r "$1" ] || [ ! -r "$2" ]; then
  echo "Usage: sh scripts/verify-v72-cross-version.sh old-v71.jar candidate-v72.jar" >&2
  exit 2
fi
OLD=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
NEW=$(cd "$(dirname "$2")" && pwd)/$(basename "$2")
TEST_DIR=$(mktemp -d /tmp/pikeyua-crossversion-XXXXXXXX)
chmod 700 "$TEST_DIR"
trap 'rm -rf "$TEST_DIR"' EXIT HUP INT TERM
java -cp "$OLD" com.github.mphi_rc.fido2.StateLifecycleProbe create "$TEST_DIR"
for phase in legacy-import legacy-read upgrade verify; do
  java -cp "$NEW" com.github.mphi_rc.fido2.StateMigrationProbe "$phase" "$TEST_DIR"
done
echo "PASS: actual V7.1 JAR -> V7.2 independent-process migration and signing"

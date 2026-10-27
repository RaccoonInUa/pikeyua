#!/bin/sh
# Synthetic state ONLY. Frozen V7.3 creates it; candidate reads/signs; V7.3 rereads.
set -eu
if [ "$#" -ne 2 ] || [ ! -r "$1" ] || [ ! -r "$2" ]; then
    echo "Usage: sh scripts/verify-key-backend-cross-version.sh old-v73.jar candidate.jar" >&2
    exit 2
fi
OLD=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
NEW=$(cd "$(dirname "$2")" && pwd)/$(basename "$2")
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TEST_CLASSES="$ROOT/build/classes/java/test"
TEST_DIR=$(mktemp -d /tmp/pikeyua-backend-cross-XXXXXXXX)
chmod 700 "$TEST_DIR"
trap 'rm -rf "$TEST_DIR"' EXIT HUP INT TERM
java -cp "$OLD" com.github.mphi_rc.fido2.StateLifecycleProbe create "$TEST_DIR"
cp "$TEST_DIR/config.json" "$TEST_DIR/before.json"
chmod 600 "$TEST_DIR/before.json"
java -cp "$TEST_CLASSES:$NEW" com.github.mphi_rc.fido2.CredentialBackendContract existing-state "$TEST_DIR"
mkdir "$TEST_DIR/checker"
javac -cp "$OLD" -d "$TEST_DIR/checker" "$ROOT/src/test/java/com/github/mphi_rc/fido2/LegacyCredentialReadback.java"
java -cp "$TEST_DIR/checker:$OLD" com.github.mphi_rc.fido2.LegacyCredentialReadback "$TEST_DIR/before.json" "$TEST_DIR/config.json"

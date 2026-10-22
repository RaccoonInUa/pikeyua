#!/bin/sh
# Test-only, separate JVMs. No USB attach, systemd changes or real credentials.
set -eu
if [ "$#" -ne 1 ] || [ ! -r "$1" ]; then
  echo "Usage: sh scripts/verify-persistence.sh /path/to/pikeyua.jar" >&2
  exit 2
fi
JAR=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
TEST_DIR=$(mktemp -d /tmp/pikeyua-v71-XXXXXXXX)
chmod 700 "$TEST_DIR"
trap 'rm -rf "$TEST_DIR"' EXIT HUP INT TERM
for phase in create verify increment verify-updated negative-corrupt negative-denied verify-updated; do
  java -cp "$JAR" com.github.mphi_rc.fido2.StateLifecycleProbe "$phase" "$TEST_DIR"
done
echo "PASS: separate-JVM restart, credentials, key signature, AAGUID, PIN, counter, fail-closed"

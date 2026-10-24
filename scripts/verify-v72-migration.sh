#!/bin/sh
# Isolated V7.1-state -> V7.2 migration verification; no gadget, root or live state.
set -eu
if [ "$#" -ne 1 ] || [ ! -r "$1" ]; then
  echo "Usage: sh scripts/verify-v72-migration.sh /absolute/path/to/pikeyua.jar" >&2
  exit 2
fi
JAR=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
TEST_DIR=$(mktemp -d /tmp/pikeyua-v72-XXXXXXXX)
chmod 700 "$TEST_DIR"
trap 'rm -rf "$TEST_DIR"' EXIT HUP INT TERM
for phase in legacy-create legacy-read upgrade verify; do
  java -cp "$JAR" com.github.mphi_rc.fido2.StateMigrationProbe "$phase" "$TEST_DIR"
done
echo "PASS: V7.1 -> V7.2 separate-JVM migration and signatures"

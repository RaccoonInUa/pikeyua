#!/usr/bin/env bash
# Static/off-device gates; no root, ConfigFS or systemd changes.
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
for script in "$ROOT/scripts/pikeyua-cutover" "$ROOT/scripts/install-cutover.sh"; do
    bash -n "$script"
    [[ -x "$script" ]] || { echo "Not executable: $script" >&2; exit 1; }
done
for unit in pikeyua-v7.service pikeyua-trial-rollback.service pikeyua-trial-rollback.timer; do
    [[ -s "$ROOT/deploy/systemd/$unit" ]] || { echo "Missing unit: $unit" >&2; exit 1; }
done
grep -q 'store_status trial' "$ROOT/scripts/pikeyua-cutover"
grep -q 'systemctl enable --now "$TIMER"' "$ROOT/scripts/pikeyua-cutover"
grep -q 'check_running "$V7_UNIT"' "$ROOT/scripts/pikeyua-cutover"
grep -q 'rollback_internal' "$ROOT/scripts/pikeyua-cutover"
grep -q 'Conflicts=fido2.service' "$ROOT/deploy/systemd/pikeyua-v7.service"
grep -q 'OnActiveSec=25min' "$ROOT/deploy/systemd/pikeyua-trial-rollback.timer"
printf '%s\n' 'PASS: cutover scripts parse and safety guards are present'

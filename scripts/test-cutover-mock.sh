#!/usr/bin/env bash
# Mock integration tests; no real USB, root privileges, network or systemd access.
set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
source "$ROOT/scripts/pikeyua-cutover"
TEST_ROOT=$(mktemp -d)
trap 'rm -rf "$TEST_ROOT"' EXIT
CONTROL="$TEST_ROOT/control"
GADGET="$TEST_ROOT/fido2"
UDC_NAME=20980000.usb
UDC_FILE="$GADGET/UDC"
UDC_STATE="$TEST_ROOT/udc-state"
V6_JAR="$TEST_ROOT/fixed-v6.jar"
V7_JAR="$TEST_ROOT/fixed-v71.jar"
STATUS_FILE="$CONTROL/status"
V6_BACKUP="$CONTROL/backup/v6.jar"
STATE_FILE="$TEST_ROOT/v7-secret-state.json"
EVENTS="$TEST_ROOT/events.log"
mkdir -p "$CONTROL/backup" "$GADGET/functions/hid.usb0"
printf 'dummy v6 data\n' > "$V6_JAR"
cp "$V6_JAR" "$V6_BACKUP"
printf 'dummy v71 data\n' > "$V7_JAR"
printf '%s\n' "$V6_JAR" > "$CONTROL/v6-exec-jar"
printf 'staged\n' > "$STATUS_FILE"
printf '0x1050\n' > "$GADGET/idVendor"
printf '0x0402\n' > "$GADGET/idProduct"
printf '64\n' > "$GADGET/functions/hid.usb0/report_length"
printf '%s\n' "$UDC_NAME" > "$UDC_FILE"
printf 'configured\n' > "$UDC_STATE"
printf 'dummy private state\n' > "$STATE_FILE"
: > "$EVENTS"
V6_ACTIVE=1; V6_ENABLED=1; V7_ACTIVE=0; V7_ENABLED=0; TIMER_ACTIVE=0; TIMER_ENABLED=0
check_stage() { return 0; }
check_v6_backup() { return 0; }
ip() { echo '5: wlan0 inet 192.168.88.17/24 scope global wlan0'; }
service_active() {
    case "$1" in
        fido2.service) (( V6_ACTIVE == 1 ));;
        pikeyua-v7.service) (( V7_ACTIVE == 1 ));;
        *) return 1;;
    esac
}
service_enabled() {
    case "$1" in
        fido2.service) (( V6_ENABLED == 1 ));;
        pikeyua-v7.service) (( V7_ENABLED == 1 ));;
        *) return 1;;
    esac
}
check_running() {
    case "$1" in
        fido2.service) service_active fido2.service;;
        pikeyua-v7.service) service_active pikeyua-v7.service;;
        *) return 1;;
    esac
}
systemctl() {
    printf '%s\n' "$*" >> "$EVENTS"
    case "$*" in
        'enable --now pikeyua-trial-rollback.timer')
            [[ "$(status_value)" == trial ]] || { echo 'Timer was armed before trial marker' >&2; return 2; }
            TIMER_ACTIVE=1; TIMER_ENABLED=1;;
        'disable --now pikeyua-trial-rollback.timer') TIMER_ACTIVE=0; TIMER_ENABLED=0;;
        'disable fido2.service')
            (( TIMER_ACTIVE == 1 )) || { echo 'V6 disabled before timer armed' >&2; return 3; }
            V6_ENABLED=0;;
        'enable fido2.service') V6_ENABLED=1;;
        'disable pikeyua-v7.service') V7_ENABLED=0;;
        'enable pikeyua-v7.service') V7_ENABLED=1;;
        'stop fido2.service') V6_ACTIVE=0;;
        'stop pikeyua-v7.service') V7_ACTIVE=0;;
        'start fido2.service')
            [[ -z "$(tr -d '\r\n' < "$UDC_FILE")" ]] || { echo 'V6 started before UDC unbind' >&2; return 4; }
            V6_ACTIVE=1; printf '%s\n' "$UDC_NAME" > "$UDC_FILE";;
        'start pikeyua-v7.service')
            if [[ "${FAIL_V7_START:-0}" == 1 ]]; then
                echo 'Simulated V7 startup failure' >&2
                return 42
            fi
            (( V6_ACTIVE == 0 )) || { echo 'V7 started before V6 stopped' >&2; return 5; }
            [[ -z "$(tr -d '\r\n' < "$UDC_FILE")" ]] || { echo 'V7 started before UDC unbind' >&2; return 6; }
            V7_ACTIVE=1; printf '%s\n' "$UDC_NAME" > "$UDC_FILE";;
        reset-failed*) :;;
        *) echo "Unexpected mocked systemctl: $*" >&2; return 7;;
    esac
}

switch_to_v7
[[ "$(status_value)" == trial && "$V6_ACTIVE" == 0 && "$V7_ACTIVE" == 1 && "$TIMER_ACTIVE" == 1 ]]
[[ "$(tr -d '\r\n' < "$UDC_FILE")" == "$UDC_NAME" ]]
confirm_v7
[[ "$(status_value)" == v7-confirmed && "$TIMER_ACTIVE" == 0 ]]
rollback_internal
[[ "$(status_value)" == v6-restored && "$V6_ACTIVE" == 1 && "$V7_ACTIVE" == 0 && "$TIMER_ACTIVE" == 0 ]]
[[ "$(cat "$STATE_FILE")" == 'dummy private state' ]] || { echo 'Rollback removed V7 state' >&2; exit 8; }

# Deliberately fail V7 startup. The EXIT trap must restore V6.
printf 'staged\n' > "$STATUS_FILE"
if ( SWITCH_IN_PROGRESS=1; FAIL_V7_START=1; trap on_exit EXIT; switch_to_v7 ); then
    echo 'Simulated V7 failure unexpectedly succeeded' >&2
    exit 9
fi
[[ "$(status_value)" == v6-restored ]] || { echo 'Immediate rollback did not complete' >&2; exit 10; }
[[ "$(tr -d '\r\n' < "$UDC_FILE")" == "$UDC_NAME" ]] || { echo 'V6 gadget not rebound' >&2; exit 11; }

python3 - "$EVENTS" <<'PY'
import sys
lines=open(sys.argv[1]).read().splitlines()
a=lines.index('enable --now pikeyua-trial-rollback.timer')
b=lines.index('disable fido2.service')
c=lines.index('stop fido2.service')
d=lines.index('start pikeyua-v7.service')
assert a < b < c < d, lines
assert 'enable fido2.service' in lines
assert 'disable pikeyua-v7.service' in lines
PY
printf '%s\n' 'PASS: mocked guarded switch, confirmation, auto-rollback and timer order'

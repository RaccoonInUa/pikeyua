#!/usr/bin/env bash
# Stage a reversible V6 -> V7.1 trial; NEVER switches the USB gadget.
set -Eeuo pipefail
umask 077

HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
SOURCE_ROOT=$(cd -- "$HERE/.." && pwd)
CONTROL=/var/lib/pikeyua-cutover
TARGET=/opt/pikeyua/v7.1/pikeyua.jar
STATE_DIR=/var/lib/pikeyua

die() { printf '[pikeyua installer] ERROR: %s\n' "$*" >&2; exit 1; }
log() { printf '[pikeyua installer] %s\n' "$*"; }
[[ $(id -u) -eq 0 ]] || die 'Run as root: sudo bash scripts/install-cutover.sh <candidate-jar>'
[[ $# -eq 1 ]] || die 'Usage: sudo bash scripts/install-cutover.sh /home/key/pikeyua-v7.1-smoke.jar'
CANDIDATE=$(readlink -f -- "$1")
[[ -s "$CANDIDATE" ]] || die 'Candidate jar not present or empty'
command -v sha256sum >/dev/null || die 'sha256sum missing'
command -v flock >/dev/null || die 'flock missing'
command -v java >/dev/null || die 'Java missing'
command -v timeout >/dev/null || die 'timeout missing'
[[ -d /sys/kernel/config/usb_gadget && -e /sys/class/udc/20980000.usb ]] ||
    die 'Raspberry Pi Zero W USB ConfigFS/UDC not available'
systemctl is-active --quiet fido2.service || die 'Original fido2.service is not running'
systemctl is-enabled --quiet fido2.service || die 'Original fido2.service is not enabled'
[[ ! -e "$CONTROL/status" ]] || die 'Cutover already staged; do not overwrite snapshots'

# Resolve existing ExecStart instead of assuming that the original user is pi.
EXEC=$(systemctl show --value --property=ExecStart fido2.service)
if [[ $EXEC =~ -jar[[:space:]]+([^[:space:];}]+\.jar) ]]; then
    V6_JAR=${BASH_REMATCH[1]}
else
    die 'Could not identify original V6 JAR in systemd ExecStart'
fi
[[ "$V6_JAR" == /* && -s "$V6_JAR" ]] || die "V6 JAR not readable: $V6_JAR"
V6_JAR=$(readlink -f -- "$V6_JAR")
[[ "$V6_JAR" != "$CANDIDATE" ]] || die 'V6 and candidate paths are identical'
[[ "$(sha256sum "$V6_JAR" | cut -d' ' -f1)" != "$(sha256sum "$CANDIDATE" | cut -d' ' -f1)" ]] ||
    die 'Candidate JAR is identical to V6 JAR'

log 'Running isolated synthetic lifecycle tests on candidate JAR; no USB gadget operations'
timeout 240 bash "$SOURCE_ROOT/scripts/verify-persistence.sh" "$CANDIDATE" ||
    die 'Candidate independent-JVM lifecycle test failed. Original V6 remains untouched.'

# Backups and paths are private, owned by root. No live credentials are copied.
install -d -m 0700 -o root -g root "$CONTROL" "$CONTROL/backup" "$STATE_DIR"
install -d -m 0755 -o root -g root /opt/pikeyua /opt/pikeyua/v7.1
install -m 0644 -o root -g root "$CANDIDATE" "$TARGET"
install -m 0600 -o root -g root "$V6_JAR" "$CONTROL/backup/v6.jar"
( cd "$CONTROL/backup" && sha256sum v6.jar ) > "$CONTROL/v6.sha256"
( cd /opt/pikeyua/v7.1 && sha256sum pikeyua.jar ) > "$CONTROL/v7.sha256"
printf '%s\n' "$V6_JAR" > "$CONTROL/v6-exec-jar"
systemctl cat fido2.service > "$CONTROL/backup/systemd-v6-cat.txt"
FRAGMENT=$(systemctl show --value --property=FragmentPath fido2.service)
[[ -r "$FRAGMENT" ]] && cp -a -- "$FRAGMENT" "$CONTROL/backup/v6-service-file" || true
if [[ -d /etc/systemd/system/fido2.service.d ]]; then
    cp -a -- /etc/systemd/system/fido2.service.d "$CONTROL/backup/fido2.service.d"
fi
install -m 0700 -o root -g root "$SOURCE_ROOT/scripts/pikeyua-cutover" /usr/local/sbin/pikeyua-cutover
install -m 0644 -o root -g root "$SOURCE_ROOT/deploy/systemd/pikeyua-v7.service" /etc/systemd/system/pikeyua-v7.service
install -m 0644 -o root -g root "$SOURCE_ROOT/deploy/systemd/pikeyua-trial-rollback.service" /etc/systemd/system/pikeyua-trial-rollback.service
install -m 0644 -o root -g root "$SOURCE_ROOT/deploy/systemd/pikeyua-trial-rollback.timer" /etc/systemd/system/pikeyua-trial-rollback.timer
chmod 0600 "$CONTROL"/*.sha256 "$CONTROL/v6-exec-jar"
find "$CONTROL/backup" -type f -exec chmod 0600 {} +
printf 'staged\n' > "$CONTROL/status"
chmod 0600 "$CONTROL/status"
systemctl daemon-reload
log 'V7.1 staged successfully. Original V6 is still active; NOTHING has been switched.'
log 'Next: sudo pikeyua-cutover status; sudo pikeyua-cutover switch'

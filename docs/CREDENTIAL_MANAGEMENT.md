# Local credential management

This is an administrator utility for the existing V7.3 laboratory Pi, not a new
authenticator version or USB credential-management implementation. It needs
Python 3.9+ and its standard library, root via sudo, and the existing
`pikeyua-v7.service`. It does not replace the JAR, change boot/network settings,
install services, set/reset PINs, export keys, or implement factory reset.

## Install and list

Copy `scripts/pikeyua-credentials.py` to the Raspberry and install it:

```sh
sudo install -o root -g root -m 0755 ~/pikeyua-credentials.py /usr/local/sbin/pikeyua-credentials
sudo pikeyua-credentials list
sudo pikeyua-credentials list --rp webauthn.io
sudo pikeyua-credentials list --json
```

List is read-only and does not call systemd or stop FIDO2. The output contains
full hexadecimal credential IDs, RP IDs, account/display names when stored,
discoverability, creation time and counters. It never prints PIN hash/retries,
private/public key bytes, binary user handles or arbitrary state extensions.
Names and RP IDs can still be personal information: do not publish the output
unnecessarily. Terminal control characters are escaped. Old credentials without
names are displayed with empty names, not invented identities.

## Delete exactly one credential

Close browser registration/authentication dialogs before deletion. Copy the
complete 32-character ID from `list`; row numbers, substrings and partial IDs
are deliberately not accepted. Replace `FULL_ID_FROM_LIST` below.

```sh
sudo pikeyua-credentials delete FULL_ID_FROM_LIST --dry-run
sudo pikeyua-credentials delete FULL_ID_FROM_LIST
```

The dry run displays the exact selected record without stopping the service,
writing files or asking for confirmation. Actual deletion shows the record and
requires typing `DELETE` in an interactive terminal. Enter/EOF cancels. There is
no `--yes`, no batch delete and no wipe-all command.

After confirmation the utility serializes its own invocations with an advisory
lock, checks the configured service/state path, stops the existing daemon, and
reads the state again. This fresh read is important: authentication counters and
PIN retries might have changed while you were considering the prompt. Only the
selected credential is removed. Other fields and records are retained,
including unknown JSON extensions. The schema is not migrated and the identity
marker is never rewritten.

Writes use a private same-directory temporary file, fsync, atomic replacement,
and directory fsync. File permissions remain 0600 and the state directory remains
0700. The utility verifies the resulting file. A service that was active is then
started again; an already stopped service is left stopped. Restart invalidates
memory-only PIN tokens/temporary process lockouts, but the durable PIN hash and
retry budget are preserved, including a blocked zero-attempt state. No ConfigFS
USB tree is changed. Browser/USB readiness is not inferred from `active` status.

Removing a credential prevents future use of that credential by this device. It
does not log out existing website sessions or remove the site's stored public
credential entry. Register a new credential when needed. No backup is created
by the delete command: retaining copies would retain deleted private keys.
Previous backups made elsewhere still exist. Removal is NOT secure SD erasure.

## Failure behavior and boundaries

Invalid/corrupt/future-schema state, missing identity marker, identity mismatch,
unsafe permissions, symlinks/hardlinks, duplicate IDs, truncated IDs, ambiguous
selection and non-interactive deletion are refused. The utility expects saved
credential IDs emitted by the genuine V7.3 serializer; it does not invent IDs
for undocumented state formats. Only the documented default state path
`/var/lib/pikeyua/config.json` is managed. Alternative Java state overrides are
refused, not silently edited.

If a write is failed or uncertain, the utility leaves the daemon stopped and
prints `WRITE NOT CONFIRMED`. It does not claim deletion succeeded or silently
roll back a possibly committed write. If the write succeeds but restart fails,
`DELETED` and `SERVICE NOT RESTORED` distinguish these outcomes. Inspect:

```sh
sudo systemctl status pikeyua-v7.service --no-pager -l
sudo journalctl -u pikeyua-v7.service -b -n 50 --no-pager
```

The lock coordinates this utility's own processes, not arbitrary root programs.
Do not run another manual Java daemon or manually start/edit the same state
while deletion is in progress. Root compromise, sudden power loss/SIGKILL,
malicious replacement of trusted parent directories, hardware storage faults
and automatic recovery are outside this utility's guarantees. Existing root
access already permits reading all software keys; this is local administration,
not a new unauthenticated USB operation.

## Tests

```sh
python3 -m unittest discover -s tests -p 'test_credentials_cli.py' -v
python3 tests/verify_credentials_with_jar.py /path/to/verified-v73.jar
```

The tests use private temporary directories, synthetic credentials and mocked
systemd calls only. The integration test compiles a small fixture against the
actual frozen V7.3 JAR, which creates real serialized RK/legacy records and a
blocked PIN. Python deletes one record; a new Java process restores the edited
state and verifies retained IDs, keys, signatures, counters, AAGUID and unchanged
blocked PIN state. Nothing accesses USB or the operator's actual files.

CI builds the exact baseline `ad1c3c7fbefdaacffe3bf5024fcb03c07df4f662` on
JDK 17 and 21 for this regression. The standalone downloadable artifact contains
only the Python utility, this guide, its commit and SHA-256 checksums. Actual Pi
CLI/service integration still needs an operator test; no real records are
removed by CI or by preparing the artifact.

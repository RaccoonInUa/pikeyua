#!/usr/bin/env python3
"""Local administrator-only credential list/delete for pikeyua V7.3.

Python 3.9+, standard library only. No PIN, private key or raw state output.
The daemon is paused only for a confirmed deletion, never for list/dry-run.
This is not the USB CTAP credential-management protocol or secure erasure.
"""
from __future__ import annotations

import argparse
import base64
import copy
import fcntl
import json
import os
from pathlib import Path
import re
import shlex
import signal
import stat
import subprocess
import sys
import tempfile
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone

STATE = Path('/var/lib/pikeyua/config.json')
UNIT = 'pikeyua-v7.service'
MAX_BYTES = 16 * 1024 * 1024
HEX_ID = re.compile(r'[0-9a-fA-F]{32}\Z')


class Refused(Exception):
    """Only fixed, non-secret messages may leave the implementation."""


def require(ok, message):
    if not ok:
        raise Refused(message)


def private_directory(path, owner):
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
            and info.st_uid == owner, 'State directory must be owned by the administrator with mode 0700.')


def read_private(path, owner, limit=MAX_BYTES):
    # O_NONBLOCK prevents hanging on a substituted FIFO; fstat rejects it.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == owner,
                'State and identity must be private regular files (0600), not links.')
        require(info.st_size <= limit, 'State file exceeds the supported size.')
        data = stream.read(limit + 1)
        require(len(data) <= limit, 'State file exceeds the supported size.')
        return data


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate JSON fields are not supported.')
        result[key] = value
    return result


def invalid_constant(_value):
    raise Refused('Non-finite JSON values are not supported.')


def decode64(value):
    require(isinstance(value, str), 'Invalid binary field in stored credential.')
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, UnicodeError):
        raise Refused('Invalid binary field in stored credential.') from None


def credential_id(record):
    require(isinstance(record, dict), 'Invalid credential record.')
    value = decode64(record.get('id'))
    require(len(value) == 16, 'Expected a complete saved 16-byte credential ID.')
    return value.hex()


def validate(document, marker):
    require(isinstance(document, dict), 'Invalid state document.')
    version = document.get('schemaVersion', 1)
    require(type(version) is int and version in (1, 2, 3), 'Unsupported state schema; no changes made.')
    identity = document.get('id')
    try:
        require(str(uuid.UUID(identity)) == identity and marker.decode('ascii') == identity,
                'State identity does not match its marker.')
    except (ValueError, TypeError, AttributeError, UnicodeError):
        raise Refused('Invalid state identity.') from None
    retries = document.get('pinRetries', 8)
    require(type(retries) is int and 0 <= retries <= 8, 'Invalid PIN retry state.')
    pin = document.get('pinHash')
    if version == 3 or pin is not None:
        require(pin is not None and len(decode64(pin)) == 16, 'Invalid protected PIN state.')
    if version == 3:
        require('pinRetries' in document, 'Missing protected PIN retry state.')
    if pin is None:
        require(retries == 8, 'Invalid unconfigured PIN state.')
    records = document.get('credentials')
    require(isinstance(records, list), 'Missing credentials array.')
    seen = set()
    for record in records:
        identifier = credential_id(record)
        require(identifier not in seen, 'Duplicate credential IDs; deletion would be ambiguous.')
        seen.add(identifier)
        require(isinstance(record.get('relayingPartyId'), str) and record['relayingPartyId'],
                'Invalid relying-party ID.')
        for field in ('userName', 'userDisplayName'):
            require(isinstance(record.get(field, ''), str), 'Invalid account metadata.')
        require(type(record.get('creation')) is int and type(record.get('signatureCount')) is int
                and record['signatureCount'] >= 0, 'Invalid credential timestamp or counter.')
        require(type(record.get('discoverable', False)) is bool, 'Invalid discoverability flag.')
        decode64(record.get('userId'))
        keys = record.get('keyPair')
        require(isinstance(keys, dict) and len(decode64(keys.get('publicKey'))) > 0
                and len(decode64(keys.get('privateKey'))) > 0, 'Invalid credential key record.')


@dataclass
class Snapshot:
    raw: bytes
    marker: bytes
    document: dict


class StateFile:
    def __init__(self, path=STATE, owner=0):
        self.path, self.owner = Path(path), owner
        self.marker = self.path.with_name(self.path.name + '.identity')

    def load(self):
        private_directory(self.path.parent, self.owner)
        raw = read_private(self.path, self.owner)
        marker = read_private(self.marker, self.owner, 128)
        try:
            document = json.loads(raw, object_pairs_hook=unique_object,
                                  parse_constant=invalid_constant)
        except (ValueError, UnicodeError, RecursionError):
            raise Refused('Cannot parse state; no changes made.') from None
        validate(document, marker)
        return Snapshot(raw, marker, document)

    @contextmanager
    def lock(self):
        private_directory(self.path.parent, self.owner)
        path = self.path.parent / '.credentials-admin.lock'
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                    and stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == self.owner,
                    'Unsafe administrator lock file.')
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Refused('Another credential-management command is running.') from None
            yield
        finally:
            os.close(fd)

    def replace(self, snapshot, proposed, guard):
        # Preserve unknown fields and all non-target records. Do not reserialize
        # through the Java model, migrate schemas or rewrite the identity marker.
        validate(proposed, snapshot.marker)
        contents = (json.dumps(proposed, ensure_ascii=True, indent=2, allow_nan=False) + '\n').encode('utf-8')
        require(len(contents) <= MAX_BYTES, 'Updated state exceeds the supported size.')
        fd, name = tempfile.mkstemp(prefix='.credential-edit-', dir=self.path.parent)
        try:
            with os.fdopen(fd, 'wb') as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(contents)
                stream.flush()
                os.fsync(stream.fileno())
            current = self.load()
            require(current.raw == snapshot.raw and current.marker == snapshot.marker,
                    'State changed concurrently; refusing to overwrite it.')
            guard()  # Daemon must still be stopped immediately before rename.
            os.replace(name, self.path)
            directory = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            saved = self.load()
            require(saved.raw == contents and saved.marker == snapshot.marker,
                    'Post-write verification failed; leave the service stopped.')
        finally:
            if os.path.exists(name):
                os.unlink(name)


class Service:
    def run(self, *args):
        try:
            process = subprocess.run(['/usr/bin/systemctl', *args], check=False,
                                     capture_output=True, text=True, timeout=45,
                                     env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C'})
        except (OSError, subprocess.TimeoutExpired):
            raise Refused('systemctl failed or timed out; inspect the service before proceeding.') from None
        require(process.returncode == 0, 'systemctl failed; inspect the service before proceeding.')
        return process.stdout

    def inspect(self):
        text = self.run('show', UNIT, '--no-pager',
                        '--property=LoadState,ActiveState,SubState,MainPID,Job,Environment,ExecStart')
        data = dict(line.split('=', 1) for line in text.splitlines() if '=' in line)
        require(data.get('LoadState') == 'loaded', 'The existing pikeyua-v7.service is not loaded.')
        return data

    def initially_active(self):
        data = self.inspect()
        require(not data.get('Job'), 'Service has a pending job; try again when stable.')
        require(data.get('ActiveState') in ('active', 'inactive'), 'Service is not in a stable active/inactive state.')
        if data['ActiveState'] == 'active':
            require(data.get('SubState') == 'running' and int(data.get('MainPID', 0)) > 0,
                    'Authenticator service is not running normally.')
        else:
            require(data.get('MainPID') == '0', 'Inactive service still has a process.')
        env = dict(part.split('=', 1) for part in shlex.split(data.get('Environment', '')) if '=' in part)
        require(env.get('PIKEYUA_STATE_FILE', str(STATE)) == str(STATE)
                and '-Dpikeyua.stateFile' not in data.get('ExecStart', ''),
                'Non-standard state path; this utility only manages /var/lib/pikeyua/config.json.')
        # Do not stop or rewrite units; reject competing historical services.
        for other in ('fido2.service', 'pikeyua-v72.service'):
            info = self.run('show', other, '--property=ActiveState,MainPID,Job')
            fields = dict(line.split('=', 1) for line in info.splitlines() if '=' in line)
            require(fields.get('ActiveState') in ('inactive', 'failed') and fields.get('MainPID', '0') == '0'
                    and not fields.get('Job'), 'Another FIDO service is active; no edit performed.')
        return data['ActiveState'] == 'active'

    def stop(self):
        self.run('stop', UNIT)
        self.require_stopped()

    def require_stopped(self):
        data = self.inspect()
        require(data.get('ActiveState') in ('inactive', 'failed') and data.get('MainPID') == '0'
                and not data.get('Job'), 'Daemon is not fully stopped; no edit is permitted.')

    def start(self):
        # Existing application reuses its ConfigFS gadget. No USB tree changes.
        self.run('start', UNIT)
        data = self.inspect()
        require(data.get('ActiveState') == 'active' and int(data.get('MainPID', 0)) > 0,
                'Service did not start; inspect its journal.')


def public_record(record):
    try:
        created = datetime.fromtimestamp(record['creation'] / 1000, timezone.utc).isoformat()
    except (ValueError, OverflowError, OSError):
        created = 'out-of-range timestamp'
    return {'id': credential_id(record), 'rp': record['relayingPartyId'],
            'userName': record.get('userName', ''), 'displayName': record.get('userDisplayName', ''),
            'discoverable': record.get('discoverable', False), 'createdUtc': created,
            'signatureCount': record['signatureCount']}


def print_record(record):
    view = public_record(record)
    print('ID:', view['id'])
    print('  RP:', json.dumps(view['rp'], ensure_ascii=True))
    print('  Account:', json.dumps(view['userName'], ensure_ascii=True),
          '| Display name:', json.dumps(view['displayName'], ensure_ascii=True))
    print('  Type:', 'discoverable' if view['discoverable'] else 'non-discoverable',
          '| Created:', view['createdUtc'], '| Counter:', view['signatureCount'])


def select(document, identifier):
    require(HEX_ID.fullmatch(identifier) is not None, 'Use the complete 32-character hexadecimal ID from list.')
    matches = [c for c in document['credentials'] if credential_id(c) == identifier.lower()]
    require(len(matches) == 1, 'Credential not found uniquely; nothing deleted.')
    return matches[0]


def stable_record(record):
    return {k: v for k, v in record.items() if k != 'signatureCount'}


def confirm_delete(identifier):
    try:
        # A TTY is not seekable: separate read/write streams, not buffered r+.
        with open('/dev/tty', 'w', encoding='utf-8') as prompt, \
                open('/dev/tty', 'r', encoding='utf-8') as terminal:
            require(terminal.isatty() and prompt.isatty(), 'Deletion requires an interactive terminal.')
            prompt.write('This removes only the selected credential. It cannot be used for future logins.\n'
                           'Type DELETE to confirm, or press Enter to cancel: ')
            prompt.flush()
            return terminal.readline().strip() == 'DELETE'
    except OSError:
        raise Refused('Deletion requires an interactive SSH terminal; no --yes mode is provided.') from None


def delete_one(store, service, identifier, confirm=confirm_delete, dry_run=False):
    before = store.load()
    target = select(before.document, identifier)
    print_record(target)
    if dry_run:
        print('DRY RUN: no files or service state changed.')
        return False
    if not confirm(identifier):
        print('CANCELLED: no files or service state changed.')
        return False
    # Take a new snapshot AFTER stopping. PIN retries and counters may have
    # changed while the user was reading the confirmation prompt.
    with store.lock():
        was_active = service.initially_active()
        writing = committed = False
        try:
            service.stop()
            stopped = store.load()
            current = select(stopped.document, identifier)
            require(stopped.marker == before.marker and stable_record(current) == stable_record(target),
                    'The selected credential changed during confirmation; nothing deleted.')
            proposed = copy.deepcopy(stopped.document)
            proposed['credentials'] = [c for c in proposed['credentials'] if credential_id(c) != identifier.lower()]
            require(len(proposed['credentials']) == len(stopped.document['credentials']) - 1,
                    'Deletion must remove exactly one credential.')
            writing = True
            store.replace(stopped, proposed, service.require_stopped)
            committed = True
            print('DELETED:', identifier.lower())
            print('PRESERVED: PIN state, identity, other credentials and their counters.')
        finally:
            if writing and not committed:
                print('WRITE NOT CONFIRMED: service left stopped; inspect state before restarting.', file=sys.stderr)
            elif was_active:
                try:
                    service.start()
                    print('SERVICE: started (USB/browser readiness is not verified here).')
                except BaseException:
                    print('SERVICE NOT RESTORED: inspect with systemctl status pikeyua-v7.service.', file=sys.stderr)
                    raise
            else:
                print('SERVICE: left stopped, as it was before the command.')
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    listing = commands.add_parser('list', help='Read metadata only; never stops the daemon')
    listing.add_argument('--rp', help='Exact RP ID filter (not a substring)')
    listing.add_argument('--json', action='store_true', help='Public metadata only; no keys or PIN fields')
    deletion = commands.add_parser('delete', help='Confirm and remove exactly one full credential ID')
    deletion.add_argument('id')
    deletion.add_argument('--dry-run', action='store_true')
    args = parser.parse_args(argv)
    try:
        require(os.geteuid() == 0, 'Run with sudo on the Raspberry, not on the Mac.')
        store = StateFile()
        if args.command == 'list':
            records = store.load().document['credentials']
            records = [c for c in records if args.rp is None or c['relayingPartyId'] == args.rp]
            if args.json:
                print(json.dumps([public_record(c) for c in records], ensure_ascii=True, indent=2))
            else:
                print('Credentials:', len(records))
                for record in records:
                    print_record(record)
            return 0
        delete_one(store, Service(), args.id, dry_run=args.dry_run)
        return 0
    except Refused as error:
        print('REFUSED:', error, file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print('INTERRUPTED: inspect service status if deletion had started.', file=sys.stderr)
        return 130
    except Exception:
        # Never print parser exceptions, raw state, subprocess stderr or traceback.
        print('FAILED: cannot safely complete this command. No secret diagnostics were printed.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    def interrupt(_signum, _frame):
        raise KeyboardInterrupt
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, interrupt)
    sys.exit(main())

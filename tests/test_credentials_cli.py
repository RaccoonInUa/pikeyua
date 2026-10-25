"""Synthetic-only CLI tests. No USB, real systemd, /var/lib or real accounts."""
import base64
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('credential_cli', ROOT / 'scripts/pikeyua-credentials.py')
cli = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = cli
spec.loader.exec_module(cli)


def b64(value):
    return base64.b64encode(value).decode('ascii')


def record(number, rp='example.invalid', rk=True):
    return {'id': b64(bytes([number]) * 16), 'relayingPartyId': rp,
            'creation': 1700000000000 + number, 'userId': b64(b'private-user-handle'),
            'keyPair': {'publicKey': b64(b'public-key'), 'privateKey': b64(b'SECRET-KEY')},
            'signatureCount': number, 'discoverable': rk,
            'userName': 'test-' + str(number), 'userDisplayName': 'Test Account',
            'unknownRecordExtension': {'keep': [1, True, None]}}


class FakeService:
    def __init__(self, active=True, stop_hook=lambda: None):
        self.active, self.stop_hook = active, stop_hook
        self.calls = []

    def initially_active(self):
        self.calls.append('inspect')
        return self.active

    def stop(self):
        self.calls.append('stop')
        self.active = False
        self.stop_hook()

    def require_stopped(self):
        self.calls.append('guard')
        cli.require(not self.active, 'Daemon is still running.')

    def start(self):
        self.calls.append('start')
        self.active = True


class CredentialCliTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.path = self.root / 'config.json'
        self.marker = self.root / 'config.json.identity'
        self.document = {'schemaVersion': 3, 'id': '7bb9a380-9dde-42ea-9e2e-3a3a91a82ddf',
                         'pinHash': b64(b'PIN-HASH-SECRET!'), 'pinRetries': 0,
                         'credentials': [record(1), record(2), record(3, 'other.invalid', False)],
                         'unknownTopLevel': {'preserve': 12345678901234567890}}
        self.marker.write_text(self.document['id'])
        self.marker.chmod(0o600)
        self.save()
        self.store = cli.StateFile(self.path, owner=os.geteuid())
        self.service = FakeService()
        self.identifier = '01' * 16
        self.out, self.err = io.StringIO(), io.StringIO()
        self.stdout = contextlib.redirect_stdout(self.out)
        self.stderr = contextlib.redirect_stderr(self.err)
        self.stdout.__enter__(); self.stderr.__enter__()
        self.addCleanup(self.stdout.__exit__, None, None, None)
        self.addCleanup(self.stderr.__exit__, None, None, None)

    def save(self):
        self.path.write_text(json.dumps(self.document))
        self.path.chmod(0o600)

    def delete(self, **kwargs):
        return cli.delete_one(self.store, self.service, self.identifier,
                              confirm=lambda _identifier: True, **kwargs)

    def call_main(self, *args):
        with mock.patch.object(cli, 'StateFile', return_value=self.store), \
                mock.patch.object(cli.os, 'geteuid', return_value=0):
            return cli.main(list(args))

    def test_list_is_read_only_and_does_not_touch_service(self):
        before = self.path.read_bytes()
        with mock.patch.object(cli, 'Service', side_effect=AssertionError('must not call systemd')):
            self.assertEqual(0, self.call_main('list'))
        self.assertEqual(before, self.path.read_bytes())
        self.assertFalse((self.root / '.credentials-admin.lock').exists())
        self.assertIn('Credentials: 3', self.out.getvalue())

    def test_json_output_has_only_whitelisted_metadata(self):
        self.assertEqual(0, self.call_main('list', '--json'))
        rows = json.loads(self.out.getvalue())
        self.assertEqual(set(rows[0]), {'id', 'rp', 'userName', 'displayName', 'discoverable',
                                       'createdUtc', 'signatureCount'})
        for sensitive in ('pinHash', 'pinRetries', 'privateKey', 'keyPair', 'userId', 'SECRET-KEY',
                          b64(b'SECRET-KEY'), b64(b'PIN-HASH-SECRET!')):
            self.assertNotIn(sensitive, self.out.getvalue())

    def test_rp_filter_exact_not_substring(self):
        self.assertEqual(0, self.call_main('list', '--rp', 'example', '--json'))
        self.assertEqual([], json.loads(self.out.getvalue()))
        self.out.seek(0); self.out.truncate()
        self.assertEqual(0, self.call_main('list', '--rp', 'example.invalid', '--json'))
        self.assertEqual(2, len(json.loads(self.out.getvalue())))

    def test_empty_list(self):
        self.document['credentials'] = []; self.save()
        self.assertEqual(0, self.call_main('list'))
        self.assertIn('Credentials: 0', self.out.getvalue())

    def test_metadata_control_characters_cannot_execute_terminal_sequences(self):
        self.document['credentials'][0]['userName'] = '\x1b[2J\n\u202eevil'; self.save()
        self.assertEqual(0, self.call_main('list'))
        self.assertNotIn('\x1b', self.out.getvalue())
        self.assertNotIn('\u202e', self.out.getvalue())
        self.assertIn('\\u001b', self.out.getvalue())

    def test_delete_one_preserves_every_other_field_and_identity_bytes(self):
        marker = self.marker.read_bytes()
        self.assertTrue(self.delete())
        expected = copy.deepcopy(self.document)
        del expected['credentials'][0]
        self.assertEqual(expected, json.loads(self.path.read_text()))
        self.assertEqual(marker, self.marker.read_bytes())
        self.assertEqual(0o600, stat.S_IMODE(self.path.stat().st_mode))
        self.assertEqual(['inspect', 'stop', 'guard', 'start'], self.service.calls)
        self.assertEqual([], list(self.root.glob('.credential-edit-*')))

    def test_cancel_does_not_stop_or_write(self):
        old = self.path.read_bytes()
        self.assertFalse(cli.delete_one(self.store, self.service, self.identifier, lambda _: False))
        self.assertEqual(old, self.path.read_bytes())
        self.assertEqual([], self.service.calls)
        self.assertFalse((self.root / '.credentials-admin.lock').exists())

    def test_dry_run_never_prompts_or_writes_or_stops(self):
        old = self.path.read_bytes()
        self.assertFalse(cli.delete_one(self.store, self.service, self.identifier,
                                       lambda _: self.fail('no prompt'), dry_run=True))
        self.assertEqual(old, self.path.read_bytes()); self.assertEqual([], self.service.calls)

    def test_missing_id_does_not_touch_service(self):
        with self.assertRaises(cli.Refused):
            cli.delete_one(self.store, self.service, 'fe' * 16, lambda _: True)
        self.assertEqual([], self.service.calls)

    def test_prefix_index_and_nonhex_selectors_are_refused(self):
        for value in ('01', '1', '*', 'foo', 'aa' * 17):
            with self.subTest(value=value), self.assertRaises(cli.Refused):
                cli.select(self.document, value)

    def test_full_uppercase_identifier_is_supported(self):
        self.identifier = 'AB' * 16
        self.document['credentials'][0]['id'] = b64(bytes.fromhex(self.identifier)); self.save()
        self.assertTrue(self.delete())

    def test_stopped_service_stays_stopped(self):
        self.service = FakeService(active=False)
        self.delete()
        self.assertNotIn('start', self.service.calls)
        self.assertFalse(self.service.active)

    def test_latest_counter_and_pin_retries_are_preserved_after_confirmation(self):
        def concurrent_change():
            self.document['credentials'][0]['signatureCount'] = 300
            self.document['credentials'][1]['signatureCount'] = 200
            self.document['pinRetries'] = 3
            self.save()
        self.service.stop_hook = concurrent_change
        self.delete()
        saved = json.loads(self.path.read_text())
        self.assertEqual(3, saved['pinRetries'])
        self.assertEqual(200, saved['credentials'][0]['signatureCount'])

    def test_changed_selected_record_is_not_deleted(self):
        def changed():
            self.document['credentials'][0]['userName'] = 'different'; self.save()
        self.service.stop_hook = changed
        with self.assertRaises(cli.Refused): self.delete()
        self.assertEqual(3, len(json.loads(self.path.read_text())['credentials']))
        self.assertEqual('start', self.service.calls[-1])

    def test_concurrent_removal_does_not_delete_another_record(self):
        def removed():
            del self.document['credentials'][0]; self.save()
        self.service.stop_hook = removed
        with self.assertRaises(cli.Refused): self.delete()
        self.assertEqual(2, len(json.loads(self.path.read_text())['credentials']))
        self.assertTrue(self.service.active)

    def test_stop_failure_never_writes(self):
        old = self.path.read_bytes()
        with mock.patch.object(self.service, 'stop', side_effect=cli.Refused('stop failed')):
            with self.assertRaises(cli.Refused): self.delete()
        self.assertEqual(old, self.path.read_bytes())

    def test_restart_failure_does_not_undo_a_committed_delete(self):
        with mock.patch.object(self.service, 'start', side_effect=cli.Refused('start failed')):
            with self.assertRaises(cli.Refused): self.delete()
        self.assertEqual(2, len(json.loads(self.path.read_text())['credentials']))
        self.assertIn('DELETED:', self.out.getvalue())
        self.assertIn('SERVICE NOT RESTORED', self.err.getvalue())

    def test_write_failure_leaves_service_stopped_and_original_state_intact(self):
        old = self.path.read_bytes()
        with mock.patch.object(cli.os, 'replace', side_effect=OSError('simulated failure')):
            with self.assertRaises(OSError): self.delete()
        self.assertEqual(old, self.path.read_bytes()); self.assertFalse(self.service.active)
        self.assertIn('WRITE NOT CONFIRMED', self.err.getvalue())
        self.assertEqual([], list(self.root.glob('.credential-edit-*')))

    def test_uncertain_directory_fsync_does_not_restart_or_claim_success(self):
        original_fsync = os.fsync
        def fail_directory(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode): raise OSError('uncertain directory write')
            original_fsync(fd)
        with mock.patch.object(cli.os, 'fsync', side_effect=fail_directory):
            with self.assertRaises(OSError): self.delete()
        self.assertFalse(self.service.active); self.assertNotIn('DELETED:', self.out.getvalue())
        self.assertEqual(2, len(json.loads(self.path.read_text())['credentials']))

    def test_concurrent_write_before_replace_refused(self):
        snapshot = self.store.load()
        proposed = copy.deepcopy(snapshot.document); del proposed['credentials'][0]
        self.document['pinRetries'] = 4; self.save()
        with self.assertRaises(cli.Refused): self.store.replace(snapshot, proposed, lambda: None)
        self.assertEqual(4, json.loads(self.path.read_text())['pinRetries'])
        self.assertEqual(3, len(json.loads(self.path.read_text())['credentials']))

    def test_daemon_reactivation_prevents_replace(self):
        snapshot = self.store.load()
        proposed = copy.deepcopy(snapshot.document); del proposed['credentials'][0]
        with self.assertRaises(cli.Refused):
            self.store.replace(snapshot, proposed, self.service.require_stopped)
        self.assertEqual(snapshot.raw, self.path.read_bytes())

    def test_two_admin_commands_cannot_write_simultaneously(self):
        with self.store.lock():
            with self.assertRaises(cli.Refused):
                with self.store.lock(): self.fail('concurrent lock')

    def test_duplicate_ids_are_refused(self):
        self.document['credentials'].append(copy.deepcopy(self.document['credentials'][0])); self.save()
        with self.assertRaises(cli.Refused): self.store.load()

    def test_duplicate_json_keys_rejected(self):
        self.path.write_bytes(b'{"id":"a","id":"b"}')
        with self.assertRaises(cli.Refused): self.store.load()

    def test_corrupt_json_is_sanitized(self):
        self.path.write_text('{"secret":"TOP_SECRET",')
        self.assertEqual(1, self.call_main('list'))
        self.assertNotIn('TOP_SECRET', self.err.getvalue() + self.out.getvalue())
        self.assertNotIn('Traceback', self.err.getvalue())

    def test_future_schema_and_invalid_pin_state_refused(self):
        for change in ({'schemaVersion': 99}, {'schemaVersion': True}, {'pinRetries': -1},
                       {'pinRetries': 9}, {'pinRetries': 2.5}, {'pinHash': None}):
            with self.subTest(change=change):
                original = copy.deepcopy(self.document)
                self.document.update(change); self.save()
                with self.assertRaises(cli.Refused): self.store.load()
                self.document = original
        del self.document['pinRetries']; self.save()
        with self.assertRaises(cli.Refused): self.store.load()

    def test_unknown_fields_preserved_and_never_printed(self):
        self.assertEqual(0, self.call_main('list'))
        self.assertNotIn('unknownTopLevel', self.out.getvalue())
        self.delete()
        self.assertEqual(self.document['unknownTopLevel'], json.loads(self.path.read_text())['unknownTopLevel'])

    def test_bad_identity_and_missing_marker_refused(self):
        self.marker.write_text('some-other-identity')
        with self.assertRaises(cli.Refused): self.store.load()
        self.marker.unlink()
        with self.assertRaises(OSError): self.store.load()

    def test_symlink_file_is_refused(self):
        other = self.root / 'actual.json'; self.path.rename(other); self.path.symlink_to(other)
        with self.assertRaises(OSError): self.store.load()

    def test_hardlinked_file_refused(self):
        os.link(self.path, self.root / 'alias.json')
        with self.assertRaises(cli.Refused): self.store.load()

    def test_symlink_directory_is_refused(self):
        alias = self.root / 'alias'; alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(cli.Refused): cli.StateFile(alias / 'config.json', os.geteuid()).load()

    def test_permissions_must_be_private(self):
        self.path.chmod(0o644)
        with self.assertRaises(cli.Refused): self.store.load()
        self.path.chmod(0o600); self.root.chmod(0o755)
        with self.assertRaises(cli.Refused): self.store.load()

    def test_nonregular_file_refused_without_blocking(self):
        self.path.unlink(); os.mkfifo(self.path, 0o600)
        with self.assertRaises(cli.Refused): self.store.load()

    def test_nonfinite_json_is_refused(self):
        self.path.write_text('{"field":NaN}')
        with self.assertRaises(cli.Refused): self.store.load()

    def test_wrong_owner_refused(self):
        with self.assertRaises(cli.Refused): cli.StateFile(self.path, os.geteuid() + 1).load()

    def test_nonroot_cli_refused_without_reading_state(self):
        with mock.patch.object(cli.os, 'geteuid', return_value=1234), \
                mock.patch.object(cli, 'StateFile', side_effect=AssertionError('must not read')):
            self.assertEqual(1, cli.main(['list']))

    def test_no_tty_cannot_delete(self):
        with mock.patch('builtins.open', side_effect=OSError()):
            with self.assertRaises(cli.Refused): cli.confirm_delete(self.identifier)

    def test_confirmation_works_with_real_nonseekable_pty(self):
        master, slave = os.openpty()
        real_open = open
        device = os.ttyname(slave)
        try:
            os.write(master, b'DELETE\n')
            def redirected(path, *args, **kwargs):
                return real_open(device if path == '/dev/tty' else path, *args, **kwargs)
            with mock.patch('builtins.open', side_effect=redirected):
                self.assertTrue(cli.confirm_delete(self.identifier))
        finally:
            os.close(master); os.close(slave)

    def test_enter_on_real_pty_cancels(self):
        master, slave = os.openpty()
        real_open = open
        device = os.ttyname(slave)
        try:
            os.write(master, b'\n')
            with mock.patch('builtins.open', side_effect=lambda p, *a, **k: real_open(device if p == '/dev/tty' else p, *a, **k)):
                self.assertFalse(cli.confirm_delete(self.identifier))
        finally:
            os.close(master); os.close(slave)

    def test_service_properties_are_checked_and_secret_stderr_not_printed(self):
        service = cli.Service()
        good = ('LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=99\nJob=\n'
                'Environment=PIKEYUA_STATE_FILE=/var/lib/pikeyua/config.json\nExecStart=/usr/bin/java -jar example.jar\n')
        with mock.patch.object(service, 'run', side_effect=[good, 'ActiveState=inactive\nMainPID=0', 'ActiveState=inactive\nMainPID=0']):
            self.assertTrue(service.initially_active())
        with mock.patch.object(service, 'run', return_value=good.replace('config.json', 'other.json')):
            with self.assertRaises(cli.Refused): service.initially_active()
        with mock.patch.object(cli.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '', 'SECRET')):
            with self.assertRaises(cli.Refused): service.run('start', cli.UNIT)
        self.assertNotIn('SECRET', self.out.getvalue() + self.err.getvalue())

    def test_lock_symlink_refused(self):
        (self.root / '.credentials-admin.lock').symlink_to(self.path)
        with self.assertRaises(OSError):
            with self.store.lock(): self.fail('symlink lock')

    def test_legacy_state_stays_legacy_without_schema_migration(self):
        self.document.pop('schemaVersion'); self.document.pop('pinHash'); self.document.pop('pinRetries')
        for value in self.document['credentials']:
            for key in ('discoverable', 'userName', 'userDisplayName'): value.pop(key)
        self.save(); self.delete()
        saved = json.loads(self.path.read_text())
        self.assertNotIn('schemaVersion', saved); self.assertNotIn('pinRetries', saved)
        self.assertNotIn('discoverable', saved['credentials'][0])


if __name__ == '__main__':
    unittest.main()

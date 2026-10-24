# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""R8 continuity boundaries. Main runs pure tests; real X11 is X230 opt-in only."""
from __future__ import annotations

import array
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'deploy'))
from dc_compat import x11_selection as selection
from dc_compat.processes import _private_root, _publish


class RecoveryBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.authority = self.path / 'authority'
        self.authority.write_bytes(b'fixture-is-not-an-X-cookie')
        self.authority.chmod(0o600)
        self.client = selection.X11Selection({'clipboard_persistent_daemon': True}, ':29999',
            {'XAUTHORITY': str(self.authority)}, self.path / 'state', 1024 * 1024)
        self.addCleanup(self.release_client)
        self.binding = {'server': {'display': ':29999', 'pid': 12, 'starttime': 34},
                        'state': {'device': self.client.root_identity[0], 'inode': self.client.root_identity[1]}}
        self.client._binding = lambda: self.binding

    def release_client(self):
        if self.client.root_fd is not None:
            os.close(self.client.root_fd); self.client.root_fd = None

    def snapshot(self, identity='a' * 32):
        folder = self.client.state_path / identity
        folder.mkdir(mode=0o700)
        entries = {}
        values = [('UTF8_STRING', 'UTF8_STRING', 8, '原始 café Ω🙂'.encode()),
                  ('application/x-u16', 'INTEGER', 16, array.array('H', [0, 1, 65535]).tobytes()),
                  ('application/x-u32', 'INTEGER', 32, array.array('l', [0, 1, -2147483648, -1]).tobytes())]
        for index, (target, typ, fmt, raw) in enumerate(values):
            name = 'format-' + str(index).zfill(6) + '.bin'
            file = folder / name
            file.write_bytes(raw); file.chmod(0o600)
            entries[target] = {'type': typ, 'format': fmt, 'file': name, 'bytes': len(raw),
                               'sha256': hashlib.sha256(raw).hexdigest()}
        row = {'version': 2, 'complete': True, 'entries': entries, 'source_empty': False,
               'source_owner': 998, 'source_epoch': 4, 'binding': self.binding}
        fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
        try:_publish(fd, 'snapshot.json', row)
        finally:os.close(fd)
        return folder, row

    def rewrite(self, folder, row):
        fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
        try:_publish(fd, 'snapshot.json', row)
        finally:os.close(fd)

    def test_complete_typed_snapshot_preserves_native_16_and_32_bytes(self):
        _, row = self.snapshot()
        offer = selection._snapshot_offer(self.client.root_fd, 'a' * 32, self.client.budget, self.binding)
        self.assertEqual(offer['entries'], row['entries'])
        listing = self.client.list_backups()
        self.assertEqual(listing['total'], 1)
        self.assertTrue(listing['backups'][0]['restore_eligible'])
        self.assertNotIn('entries', listing['backups'][0])

    def test_changed_raw_or_missing_member_refuses_before_daemon_or_publication(self):
        folder, _ = self.snapshot()
        (folder / 'format-000000.bin').write_bytes(b'changed')
        self.client._ensure_daemon = lambda **kw: self.fail('Corrupt snapshot started a daemon')
        with self.assertRaises(ValueError):self.client.restore_clipboard('a' * 32, 0)
        self.assertFalse(self.client.list_backups()['backups'][0]['restore_eligible'])

    def test_symlink_or_world_readable_snapshot_bytes_refused(self):
        folder, _ = self.snapshot()
        member = folder / 'format-000000.bin'
        member.chmod(0o644)
        with self.assertRaises(Exception):selection._snapshot_offer(self.client.root_fd, 'a' * 32, self.client.budget, self.binding)
        member.unlink(); member.symlink_to(self.authority)
        with self.assertRaises(Exception):selection._snapshot_offer(self.client.root_fd, 'a' * 32, self.client.budget, self.binding)

    def test_extra_member_incomplete_old_or_different_server_not_restore_eligible(self):
        folder, row = self.snapshot()
        (folder / 'unaccounted').write_bytes(b'x')
        self.assertFalse(self.client.list_backups()['backups'][0]['restore_eligible'])
        (folder / 'unaccounted').unlink()
        for change in ({'complete': False}, {'version': 1}, {'binding': {'server': {}, 'state': {}}}):
            self.rewrite(folder, dict(row, **change))
            self.assertFalse(self.client.list_backups()['backups'][0]['restore_eligible'])

    def test_null_resource_and_misaligned_typed_entries_refused(self):
        folder, row = self.snapshot()
        for change in ({'type': 'PIXMAP'}, {'type': 'bad\0atom'}, {'format': 32, 'bytes': 3}):
            altered = dict(row, entries={k: dict(v) for k, v in row['entries'].items()})
            altered['entries']['UTF8_STRING'].update(change)
            self.rewrite(folder, altered)
            with self.assertRaises(ValueError):selection._snapshot_offer(self.client.root_fd, 'a' * 32, self.client.budget, self.binding)

    def test_budget_and_unverified_server_refuse_even_complete_snapshot(self):
        self.snapshot()
        with self.assertRaises(ValueError):selection._snapshot_offer(self.client.root_fd, 'a' * 32, 1, self.binding)
        with self.assertRaises(ValueError):selection._snapshot_offer(self.client.root_fd, 'a' * 32, self.client.budget, None)

    def test_live_reconnect_never_begins_publishes_or_pastes(self):
        calls = []
        self.client._ensure = lambda: calls.append('attach-only')
        self.client._rpc = lambda op: calls.append(op) or {'result': {'helper_alive': True, 'serving_original': True}}
        self.assertTrue(self.client.reconnect()['serving_original'])
        self.assertEqual(calls, ['attach-only', 'status'])

    def test_no_anchor_status_is_read_only_and_does_not_start_helper(self):
        self.client._ensure_daemon = lambda **kw: self.fail('Metadata status started a helper')
        self.assertFalse(self.client.status()['helper_alive'])

    def test_dead_anchor_requires_explicit_recovery_never_auto_start(self):
        _publish(self.client.root_fd, 'helper.json', {'status': 'running', 'pid': 99999999})
        self.client._verify_daemon = lambda row: (_ for _ in ()).throw(ValueError('dead'))
        with patch.object(selection.subprocess, 'run', side_effect=AssertionError('Auto-started replacement')):
            with self.assertRaisesRegex(ValueError, 'explicit restore'):self.client._ensure_daemon()
        self.assertFalse(self.client.status()['helper_alive'])
        self.assertTrue(self.client.status()['recovery_required'])

    def test_restore_accepts_only_explicit_zero_owner(self):
        for owner in (None, False, True, 1, -1, '0'):
            with self.assertRaises(ValueError):self.client.restore_clipboard('a' * 32, owner)

    def test_explicit_restore_checks_complete_bytes_then_uses_single_restore_no_input(self):
        self.snapshot()
        calls = []
        self.client._ensure_daemon = lambda **kw: calls.append(('attach', kw))
        self.client._rpc = lambda op, **kw: calls.append((op, kw)) or {'result': {'restored': True, 'input_replayed': False}}
        result = self.client.restore_clipboard('a' * 32, 0)
        self.assertFalse(result['input_replayed'])
        self.assertEqual(calls, [('attach', {'explicit_recovery': True}),
            ('restore_backup', {'transaction_id': 'a' * 32, 'expected_owner': 0})])

    def helper(self):
        helper = selection._Helper.__new__(selection._Helper)
        helper.root = self.client.root_fd; helper.budget = self.client.budget
        helper.binding = self.binding; helper.active = None; helper.serving = None
        helper.persistent = True; helper.config = {'display': ':29999'}
        helper.xid = 123; helper.epoch = 2; helper.foreign = 0
        helper._guard = helper._pump = lambda: None
        helper._publish_offer = lambda offer: self.fail('Unexpected selection publication')
        return helper

    def test_foreign_owner_is_never_overwritten_even_by_explicit_restore(self):
        self.snapshot()
        helper = self.helper(); helper._owner = lambda: 456
        with patch.object(selection, '_server_identity', return_value=self.binding['server']), patch.dict(os.environ, XAUTHORITY='not-read'):
            result = helper._dispatch({'op': 'restore_backup', 'transaction_id': 'a' * 32, 'expected_owner': 0})['result']
        self.assertFalse(result['restored'])
        self.assertEqual(result['reason'], 'external_owner_not_overwritten')

    def test_empty_owner_epoch_change_refuses_before_publication(self):
        self.snapshot(); helper = self.helper(); helper._owner = lambda: 0
        pumps = []
        def pump():
            pumps.append(True)
            if len(pumps) == 2:helper.epoch += 1
        helper._pump = pump
        with patch.object(selection, '_server_identity', return_value=self.binding['server']), patch.dict(os.environ, XAUTHORITY='not-read'):
            with self.assertRaisesRegex(ValueError, 'changed'):helper._dispatch({'op': 'restore_backup', 'transaction_id': 'a' * 32, 'expected_owner': 0})

    def test_other_client_cannot_arm_or_finish_an_owned_transaction(self):
        helper = self.helper()
        helper.active = {'client_id': 'b' * 32, 'receipt': {'transaction_id': 'a' * 32}}
        for op in ('arm', 'finish'):
            with self.assertRaisesRegex(ValueError, 'another private client'):
                helper._dispatch({'op': op, 'transaction_id': 'a' * 32, 'client_id': 'c' * 32})

    def test_reused_control_fd_cannot_resurrect_a_disconnected_snapshot_caller(self):
        helper = self.helper()
        old, new = object(), object()
        helper.connected = True
        helper.active = {'phase': 'snapshot', 'deadline': time.monotonic() + 10,
                         'control_fd': 17, 'control_state': old}
        helper.clients = {17: new}
        helper._owner = lambda: 456
        with self.assertRaisesRegex(TimeoutError, 'lease expired'):helper._same(456, helper.epoch)

    def test_completed_begin_is_read_back_not_replayed_or_reset(self):
        helper = self.helper()
        prior = {'transaction_id': 'a' * 32, 'phase': 'completed', 'paste_attempted': True}
        _publish(self.client.root_fd, 'receipt-' + 'a' * 32 + '.json', prior)
        self.assertEqual(helper._dispatch({'op': 'begin', 'transaction_id': 'a' * 32}),
                         {'status': 'not_replayed', 'receipt': prior})
        self.assertIsNone(helper.active)

    def test_interrupted_created_receipt_or_partial_snapshot_never_resets_publication_evidence(self):
        helper = self.helper()
        prior = selection._receipt('a' * 32)
        prior['clipboard_publication_attempted'] = True
        _publish(self.client.root_fd, 'receipt-' + 'a' * 32 + '.json', prior)
        self.assertEqual(helper._dispatch({'op': 'begin', 'transaction_id': 'a' * 32})['receipt'], prior)
        prior = selection._receipt('a' * 32)
        _publish(self.client.root_fd, 'receipt-' + 'a' * 32 + '.json', prior)
        (self.client.state_path / ('a' * 32)).mkdir(mode=0o700)
        self.assertEqual(helper._dispatch({'op': 'begin', 'transaction_id': 'a' * 32})['status'], 'not_replayed')
        self.assertIsNone(helper.active)

    def test_unit_manager_env_never_uses_desktop_private_bus(self):
        self.client.env['DBUS_SESSION_BUS_ADDRESS'] = 'unix:path=/private-desktop/bus'
        with patch.object(selection, '_file_identity', return_value={}):
            env = self.client._manager_env()
        self.assertEqual(env['DBUS_SESSION_BUS_ADDRESS'], 'unix:path=/run/user/' + str(os.getuid()) + '/bus')

    def test_unit_launch_is_independent_no_restart_with_explicit_display_and_private_new_bus(self):
        commands = []
        self.client._manager_env = lambda: {'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/run/user/fixture/bus'}
        self.client._verify_daemon = lambda row: row
        def launch(argv, **kwargs):
            commands.append((argv, kwargs))
            config = json.loads(argv[-1])
            _publish(self.client.root_fd, 'helper.json', {'nonce': config['nonce'], 'unit': config['unit'], 'status': 'running'})
            return SimpleNamespace(returncode=0)
        with patch.object(selection.subprocess, 'run', side_effect=launch):self.client._ensure_daemon()
        self.assertEqual(len(commands), 1)
        argv, kwargs = commands[0]
        self.assertEqual(argv[:3], ['systemd-run', '--user', '--quiet'])
        self.assertIn('--property=Restart=no', argv)
        self.assertIn('--setenv=DISPLAY=:29999', argv)
        self.assertIn('--setenv=GTK_USE_PORTAL=0', argv)
        self.assertIn('/usr/bin/dbus-run-session', argv)
        self.assertIn('--daemon', argv)
        self.assertEqual(kwargs['env']['DBUS_SESSION_BUS_ADDRESS'], 'unix:path=/run/user/fixture/bus')

    def test_uncertain_launch_keeps_same_nonce_and_never_resubmits_or_claims_closed(self):
        self.client._manager_env = lambda: {}
        calls = []
        def fail(argv, **kw):
            calls.append(argv)
            raise subprocess.TimeoutExpired('systemd-run', 8)
        with patch.object(selection.subprocess, 'run', side_effect=fail):
            with self.assertRaises(subprocess.TimeoutExpired):self.client._ensure_daemon()
        marker = json.loads((self.client.state_path / 'launch.json').read_bytes())
        self.assertEqual(marker['phase'], 'submission_outcome_unknown')
        self.assertEqual(len(calls), 1)
        self.client._wait_launch = lambda value: self.assertEqual(value['nonce'], marker['nonce'])
        with patch.object(selection.subprocess, 'run', side_effect=AssertionError('Resubmitted unknown launch')):
            self.client._ensure_daemon()
            closed = self.client.close()
        self.assertFalse(closed['closed'])
        self.assertTrue(closed['initialization_outcome_unknown'])
        self.assertIsNone(self.client.status()['helper_alive'])
        self.assertTrue(self.client.status()['launch_pending'])

    def test_pending_launch_explicit_recovery_refuses_until_unit_is_proven_stopped(self):
        marker = {'version': selection.PROTOCOL, 'nonce': 'a' * 32,
            'unit': 'hepta-x11-selection-' + 'a' * 32 + '.service', 'binding': self.binding,
            'source_sha256': hashlib.sha256(Path(selection.__file__).read_bytes()).hexdigest(),
            'budget': self.client.budget, 'timeout': self.client.timeout, 'python': self.client.python,
            'phase': 'submission_outcome_unknown'}
        _publish(self.client.root_fd, 'launch.json', marker)
        self.client._unit_stopped = lambda unit: (_ for _ in ()).throw(ValueError('still activating'))
        with patch.object(selection.subprocess, 'run', side_effect=AssertionError('New launch before old stop proof')):
            with self.assertRaisesRegex(ValueError, 'still activating'):self.client._ensure_daemon(explicit_recovery=True)
        self.assertEqual(json.loads((self.client.state_path / 'launch.json').read_bytes()), marker)

    def test_pending_launch_does_not_retry_on_ambiguous_unit_query(self):
        self.client._manager_env = lambda: {}
        response = SimpleNamespace(stdout=b'', returncode=1)
        with patch.object(selection.subprocess, 'run', return_value=response):
            with self.assertRaisesRegex(ValueError, 'not been proven stopped'):
                self.client._unit_stopped('hepta-x11-selection-' + 'a' * 32 + '.service')

    def test_concurrent_launch_lock_prevents_a_second_systemd_submission(self):
        import fcntl
        fd = os.open('launch.lock', os.O_RDWR | os.O_CREAT, 0o600, dir_fd=self.client.root_fd)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with patch.object(selection.subprocess, 'run', side_effect=AssertionError('Concurrent duplicate launch')):
                with self.assertRaises(BlockingIOError):self.client._ensure_daemon()
        finally:os.close(fd)

    def test_socket_peer_mismatch_refuses_before_any_control_request(self):
        self.client.daemon = {'pid': 12345, 'starttime': 99, 'nonce': 'd' * 32}
        self.client._verify_daemon = lambda row: row
        peer = SimpleNamespace(settimeout=lambda _: None, connect=lambda _: None,
            getsockopt=lambda *args: selection.struct.pack('3i', 12346, os.getuid(), 0),
            sendall=lambda raw: self.fail('Wrong peer received a control request'))
        class Context:
            def __enter__(self):return peer
            def __exit__(self, *args):pass
        with patch.object(selection.socket, 'socket', return_value=Context()):
            with self.assertRaisesRegex(ValueError, 'peer identity'):self.client._socket_rpc('status')

    def test_control_anchor_change_refuses_before_unit_or_peer_adoption(self):
        row = {'version': 2, 'status': 'running'}
        _publish(self.client.root_fd, 'helper.json', dict(row, nonce='changed'))
        self.client._unit_identity = lambda unit: self.fail('Changed anchor reached unit adoption')
        with self.assertRaisesRegex(ValueError, 'anchor changed'):self.client._verify_daemon(row)

    def test_detach_preserves_holder_and_new_operations_cannot_reuse_detached_client(self):
        self.client.daemon = {'pid': 999}
        with patch.object(selection.subprocess, 'run', side_effect=AssertionError('Detach stopped a unit')):
            self.assertFalse(self.client.detach()['holder_stopped'])
        with self.assertRaises(ValueError):self.client._ensure_daemon()
        self.assertFalse(self.client.close()['holder_stopped'])

    def test_long_private_directory_control_socket_uses_pinned_descriptor_path(self):
        # AF_UNIX's short address limit must not impose a state-path limit.
        longroot = self.path / ('x' * 120)
        longroot.mkdir(mode=0o700)
        fd = os.open(longroot, os.O_RDONLY | os.O_DIRECTORY)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.bind('/proc/self/fd/' + str(fd) + '/control.sock')
            listener.listen(1)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.connect('/proc/self/fd/' + str(fd) + '/control.sock')
                server, _ = listener.accept(); server.close()
        finally:listener.close(); os.close(fd)


# This worker imitates an operator's control-group lifetime, not a user desktop.
# Its only paste callback reads the temporary selection; no keys are synthesized.
OPERATOR_WORKER = r'''
import hashlib,json,os,pathlib,subprocess,sys,time
sys.path.insert(0,sys.argv[1])
from dc_compat.x11_selection import X11Selection
from dc_compat.processes import _publish,_private_root
config=json.loads(sys.argv[2]);root=pathlib.Path(config['root']);env=config['env']
helper=X11Selection({'clipboard_persistent_daemon':True},env['DISPLAY'],env,root,8*1024*1024)
text='Hepta X230 restart 测试 café Ω 🙂'
def consume(keys,preflight=False):
 if not preflight:
  raw=subprocess.run(['/usr/bin/xclip','-selection','clipboard','-o','-target','UTF8_STRING'],env=env,capture_output=True,check=True,timeout=10).stdout
  if raw!=text.encode():raise RuntimeError('Unicode temporary offer differs')
 return {'submitted':False,'target_input_verified':False}
receipt=helper.run(text,consume)
fd=_private_root(root)
_publish(fd,'operator-proof.json',{'receipt':receipt,'daemon':helper.daemon,'pid':os.getpid()})
os.close(fd)
while True:time.sleep(1)
'''


@unittest.skipUnless(os.environ.get('HEPTA_X230_SELECTION_RECOVERY_REAL') == '1'
                     and socket.gethostname() == 'qian-ThinkPad-X230',
                     'Real selection continuity requires explicit pinned X230 R8 opt-in')
class X230RecoveryTests(unittest.TestCase):
    """Only a fresh R8 test desktop. No main/GDM/old runtime is accepted."""
    def setUp(self):
        self.assertEqual(os.getuid(), 1000)
        runtime_file = Path(os.environ['HEPTA_X230_TEST_RUNTIME'])
        self.base = runtime_file.parent
        self.assertIn(self.base, {Path('/home/qian/.local/share/hepta-computer-x230-qualification-20261015-' + suffix)
                                 for suffix in ('r8', 'r7-r8-probe')})
        self.assertEqual(runtime_file, self.base / 'runtime.private.json')
        selection._file_identity(runtime_file, 0o600, stat.S_ISREG)
        stage_file = self.base / 'stage_x230_computer_test.py'
        source = stage_file.read_bytes()
        self.assertEqual(hashlib.sha256(source).hexdigest(), os.environ['HEPTA_X230_STAGE_SHA256'])
        namespace = {'__name__': 'read_only_r8_stage_verifier', '__file__': str(stage_file)}
        exec(compile(source, str(stage_file), 'exec'), namespace)
        stage = namespace['load_stage'](self.base)
        self.runtime = json.loads(runtime_file.read_bytes())
        for name in ('base_identity', 'state_identity', 'profile_id', 'nonce', 'unit', 'release', 'xauthority'):
            self.assertEqual(self.runtime[name], stage[name])
        self.assertEqual(namespace['unit_identity'](self.runtime['unit']), self.runtime['unit_identity'])
        self.assertEqual(self.runtime['hostname'], socket.gethostname())
        self.assertEqual(self.runtime['status'], 'ready'); self.assertEqual(self.runtime['backend'], 'x11')
        self.assertTrue(self.runtime['display'].startswith(':2'))
        self.env = dict(self.runtime['desktop_environment'], PATH='/usr/bin:/bin', HOME='/home/qian',
                        GDK_BACKEND='x11', GTK_USE_PORTAL='0', NO_AT_BRIDGE='1', GTK_IM_MODULE='simple')
        server = selection._server_identity(self.runtime['display'], self.runtime['xauthority'])
        self.assertEqual(server['pid'], self.runtime['xvfb_pid'])
        self.assertEqual(server['starttime'], self.runtime['xvfb_starttime'])
        self.assertEqual(Path(os.readlink('/proc/' + str(server['pid']) + '/exe')).name, 'Xvfb')
        args = Path('/proc/' + str(server['pid']) + '/cmdline').read_bytes().split(b'\0')
        self.assertIn(self.runtime['display'].encode(), args)
        self.assertEqual(args[args.index(b'-auth') + 1], self.runtime['xauthority'].encode())
        self.assertIn(self.runtime['nonce'], self.runtime['xauthority'])
        from dc_compat_x11_selection_tests import OWNER_SOURCE, wait_state
        self.wait_state = wait_state
        self.temp = tempfile.TemporaryDirectory(prefix='r8-selection-continuity-', dir=self.base)
        self.folder = Path(self.temp.name)
        self.reader_folder = self.folder / 'reader'; self.reader_folder.mkdir(mode=0o700)
        self.nonce = os.urandom(16).hex(); self.reader_nonce = os.urandom(16).hex()
        self.serial = self.reader_serial = 0; self.helper = None; self.operator_unit = self.operator_proof = None
        self.owner = subprocess.Popen(['/usr/bin/python3', '-I', '-B', '-c', OWNER_SOURCE, str(self.folder), self.nonce],
                                      env=self.env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.reader = subprocess.Popen(['/usr/bin/python3', '-I', '-B', '-c', OWNER_SOURCE,
            str(self.reader_folder), self.reader_nonce, '--reader-only'], env=self.env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(self.cleanup)
        wait_state(self.folder, self.nonce); wait_state(self.reader_folder, self.reader_nonce)

    def command(self, action, *, reader=False):
        if reader:
            self.reader_serial += 1; serial, folder, nonce = self.reader_serial, self.reader_folder, self.reader_nonce
        else:
            self.serial += 1; serial, folder, nonce = self.serial, self.folder, self.nonce
        path = folder / 'clipboard-command.json'
        path.write_text(json.dumps({'nonce': nonce, 'serial': serial, 'action': action,
                                   'profile': 'external' if action == 'external' else 'normal'}))
        if action == 'external':
            path.write_text(json.dumps({'nonce': nonce, 'serial': serial, 'action': 'offer', 'profile': 'external'}))
        path.chmod(0o600)
        return self.wait_state(folder, nonce, lambda row: row['serial'] == serial and (
            action != 'inspect' or row.get('inspection') and not row['inspection']['pending']))

    def baseline(self):
        self.command('offer')
        row = self.command('inspect', reader=True)['inspection']
        self.assertEqual(len(row['formats']), 7)
        self.assertTrue(all('error' not in item for item in row['formats']))
        return row['formats']

    def stop_operator(self):
        if not self.operator_unit:return
        probe = selection.X11Selection.__new__(selection.X11Selection)
        probe.env, probe.timeout = self.env, 8
        self.assertEqual(probe._unit_identity(self.operator_unit), self.operator_proof)
        subprocess.run(['systemctl', '--user', 'stop', self.operator_unit], env=probe._manager_env(), check=True, timeout=15)
        self.operator_unit = None

    def cleanup(self):
        safe = False
        try:
            if self.operator_unit:self.stop_operator()
            self.command('external')
            if self.helper is not None:safe = self.helper.close().get('closed', False)
        finally:
            for child in (self.owner, self.reader):
                if child.poll() is None:child.terminate(); child.wait(timeout=8)
            if safe:self.temp.cleanup()
            else:self.temp._finalizer.detach()

    def test_independent_holder_survives_operator_control_group_restart_and_same_root_reconnect(self):
        before = self.baseline()
        root = self.folder / 'provider'
        root.mkdir(mode=0o700)
        self.helper = selection.X11Selection({'clipboard_persistent_daemon': True}, self.env['DISPLAY'], self.env,
                                              root, 8 * 1024 * 1024)
        # The helper's unit name validator also protects this owned fixture unit.
        self.operator_unit = 'hepta-x11-selection-operator-fixture-' + self.nonce + '.service'
        command = ['systemd-run', '--user', '--quiet', '--collect', '--unit=' + self.operator_unit,
                   '--property=Type=exec', '--property=KillMode=control-group', '--property=UMask=0077']
        command += ['--', '/usr/bin/python3', '-I', '-B', '-c', OPERATOR_WORKER,
            str(Path(selection.__file__).resolve().parents[1]), json.dumps({'root': str(root), 'env': self.env})]
        subprocess.run(command, env=self.helper._manager_env(), capture_output=True, timeout=12, check=True)
        self.operator_proof = self.helper._unit_identity(self.operator_unit)
        deadline = time.monotonic() + 30
        while not (root / 'operator-proof.json').exists():
            self.assertLess(time.monotonic(), deadline, 'Owned operator fixture did not finish a Unicode transaction')
            time.sleep(.05)
        proof = json.loads((root / 'operator-proof.json').read_bytes())
        self.assertTrue(proof['receipt']['original_bytes_offer_restored'])
        self.assertNotEqual(proof['daemon']['unit'], self.operator_unit)
        self.assertEqual(self.command('inspect', reader=True)['inspection']['formats'], before)

        self.stop_operator()  # Real KillMode=control-group, not merely wrapper.detach.
        self.assertEqual(selection._process_start(proof['daemon']['pid']), proof['daemon']['starttime'])
        self.assertEqual(self.command('inspect', reader=True)['inspection']['formats'], before)
        state = self.helper.reconnect()
        self.assertTrue(state['serving_original'])
        self.assertEqual(self.helper.daemon['pid'], proof['daemon']['pid'])
        self.assertEqual(self.helper.receipt(proof['receipt']['transaction_id']), proof['receipt'])
        text = 'After restart 完整 Unicode café Ω🙂'
        phases = []
        def consume(keys, preflight=False):
            phases.append(preflight)
            if not preflight:
                raw = subprocess.run(['/usr/bin/xclip', '-selection', 'clipboard', '-o', '-target', 'UTF8_STRING'],
                    env=self.env, capture_output=True, timeout=10, check=True).stdout
                self.assertEqual(raw, text.encode())
            return {'submitted': False}
        self.assertTrue(self.helper.run(text, consume)['original_bytes_offer_restored'])
        self.assertEqual(phases, [True, False])
        self.assertEqual(self.command('inspect', reader=True)['inspection']['formats'], before)

    def test_dead_holder_requires_explicit_empty_owner_restore_and_never_overwrites_foreign(self):
        before = self.baseline()
        root = self.folder / 'provider-explicit-recovery'
        self.helper = selection.X11Selection({'clipboard_persistent_daemon': True}, self.env['DISPLAY'], self.env,
                                              root, 8 * 1024 * 1024)
        text = 'Recovery snapshot 原始 Unicode Ω🙂'
        def consume(keys, preflight=False):
            if not preflight:
                raw = subprocess.run(['/usr/bin/xclip', '-selection', 'clipboard', '-o', '-target', 'UTF8_STRING'],
                    env=self.env, capture_output=True, timeout=10, check=True).stdout
                self.assertEqual(raw, text.encode())
            return {'submitted': False}
        receipt = self.helper.run(text, consume)
        daemon = self.helper.daemon
        self.assertEqual(self.helper._unit_identity(daemon['unit']), daemon['unit_identity'])
        self.assertEqual(selection._process_start(daemon['pid']), daemon['starttime'])
        subprocess.run(['systemctl', '--user', 'stop', daemon['unit']], env=self.helper._manager_env(),
                       check=True, timeout=15)
        self.assertFalse(self.helper.status()['helper_alive'])
        self.assertTrue(self.helper.status()['recovery_required'])
        with self.assertRaises(Exception):self.helper.reconnect()
        self.assertEqual(self.command('inspect', reader=True)['inspection']['owner_after'], 0)
        self.helper.detach()
        self.helper = selection.X11Selection({'clipboard_persistent_daemon': True}, self.env['DISPLAY'], self.env,
                                              root, 8 * 1024 * 1024)
        restored = self.helper.restore_clipboard(receipt['transaction_id'], expected_owner=0)
        self.assertTrue(restored['original_bytes_offer_restored'])
        self.assertFalse(restored['input_replayed'])
        self.assertFalse(restored['ownership_history_during_downtime_known'])
        self.assertEqual(self.command('inspect', reader=True)['inspection']['formats'], before)
        external = self.command('external')['owner_xid']
        refused = self.helper.restore_clipboard(receipt['transaction_id'], expected_owner=0)
        self.assertFalse(refused['restored'])
        self.assertEqual(self.wait_state(self.folder, self.nonce)['owner_xid'], external)



if __name__ == '__main__':
    unittest.main()

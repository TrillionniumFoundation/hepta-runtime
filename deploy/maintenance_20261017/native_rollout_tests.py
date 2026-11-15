"""Local safety regressions; service/network calls are mocked, no real services."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import time
import types
import unittest
from unittest import mock

import native_rollout as N


class HistoricTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.ns = self.root / 'request-operations-v10'
        self.ns.mkdir()
        for leaf in ('.intents', '.outcomes'):
            (self.ns / leaf).mkdir()
        self.lock = self.ns / '.controller.lock'
        self.lock.write_bytes(b''); self.lock.chmod(0o600)
        binding = {key: 'synthetic-' + key for key in ('owner', 'tool_name', 'request_hash', 'policy_binding', 'key_hash', 'ledger_identity')}
        binding.update(request_id=N.HISTORIC, accepted_unix_ms=1000)
        for leaf in ('.intents', '.outcomes'):
            value = dict(binding)
            if leaf == '.outcomes':
                value['state'] = 'completed'
            path = self.ns / leaf / (N.HISTORIC + '.json')
            path.write_text(json.dumps(value)); path.chmod(0o600)
        ns, lock = self.ns.stat(), self.lock.stat()
        anchor = self.root / '.request-operations-v10-anchor.json'
        anchor.write_text(json.dumps(dict(device=ns.st_dev, inode=ns.st_ino,
                                         controller_lock_device=lock.st_dev, controller_lock_inode=lock.st_ino)))
        anchor.chmod(0o600)
        self.unit = {'unit': N.SUCCESSOR, 'state_dir': str(self.root)}
        self.process = {'pid': 6543, 'start_unix': time.time() + 10}
        self.real_read_text = Path.read_text

    def run_with_locks(self, text):
        original = self.real_read_text
        def read(path, *args, **kwargs):
            return text if str(path) == '/proc/locks' else original(path, *args, **kwargs)
        with mock.patch.object(Path, 'read_text', read), mock.patch.object(N, 'event') as event:
            N.historic_quiescent(self.unit, self.process)
            return event.call_args.kwargs

    def line(self, pid):
        info = self.lock.stat()
        return f'1: FLOCK ADVISORY WRITE {pid} {os.major(info.st_dev):02x}:{os.minor(info.st_dev):02x}:{info.st_ino} 0 EOF\n'

    def test_successfully_read_empty_lock_table_accepts_historical_terminal(self):
        self.assertEqual(self.run_with_locks('')['controller_lock_holders'], [])

    def test_only_current_controller_is_accepted(self):
        self.assertEqual(self.run_with_locks(self.line(6543))['controller_lock_holders'], [6543])
        with self.assertRaisesRegex(RuntimeError, 'foreign'):
            self.run_with_locks(self.line(6544))

    def test_malformed_lock_table_cannot_be_treated_as_empty(self):
        with self.assertRaisesRegex(RuntimeError, 'parse'):
            self.run_with_locks('not a lock table\n')

    def test_changed_binding_or_recent_record_refuses(self):
        path = self.ns / '.outcomes' / (N.HISTORIC + '.json')
        value = json.loads(path.read_text()); value['owner'] = 'other-synthetic-owner'
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(RuntimeError, 'binding'):
            self.run_with_locks('')
        value['owner'] = 'synthetic-owner'; path.write_text(json.dumps(value))
        self.process['start_unix'] = time.time() - 60
        with self.assertRaisesRegex(RuntimeError, 'newer'):
            self.run_with_locks('')


class RollbackTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.preflight = {'units': [dict(unit=name, MainPID=str(1000 + index), exe_sha256=N.OLD_BINARY,
            argv=['/synthetic/hepta-runtime', '--bind', '127.0.0.1:' + str(8790 + index),
                  '--runtime-config', '/synthetic/runtime.json', '--auth-token-file', '/synthetic/token'],
            config_path='/synthetic/runtime.json', config_sha256='d' * 64, state_dir='/synthetic/state',
            DropInPaths='') for index, name in enumerate((*N.ORDER, N.FRONT))]}
        self.preflight['units'][-1]['argv'] = ['/usr/bin/python3', '-B', '/synthetic/chatgpt_computer_http.py',
            '--bind', '127.0.0.1:8795', '--auth-token-file', '/synthetic/token']
        expected = {'endpoints': [dict(unit=name, items=[{'id': format(index + 1, '064x'), 'kind': 'request_status'}
            for index in range(count)]) for name, count in ((N.OPERATOR, 0), (N.SUCCESSOR, 4), (N.V11, 11))]}
        self.old = self.root / 'r22-pager65k-shared-rebind-c1da232ee930ecfa-20261017'
        self.target = self.root / 'candidate'
        self.old.mkdir(); self.target.mkdir()
        binary = self.target / 'hepta-runtime'; binary.write_bytes(b'synthetic executable'); binary.chmod(0o700)
        self.newhash = N.digest(binary.read_bytes())
        self.front_raw = ('[Service]\nExecStart=\nExecStart=/usr/bin/python3 -B ' + str(self.old / 'chatgpt_computer_http.py') + '\n').encode()
        for unit in self.preflight['units']:
            unit['FragmentPath'] = str(self.root / 'systemd' / unit['unit'])
            folder = Path(unit['FragmentPath'] + '.d'); folder.mkdir(parents=True)
            if unit['unit'] == N.FRONT:
                unit['argv'][2] = str(self.old / 'chatgpt_computer_http.py')
                self.front_drop = folder / '90-runtime-pager65k-20261017.conf'
                self.front_drop.write_bytes(self.front_raw); self.front_drop.chmod(0o600)
                unit['DropInPaths'] = str(self.front_drop)
            elif unit['unit'] == N.OPERATOR:
                self.existing_drop = folder / '50-native-documents.conf'
                self.existing_drop.write_bytes(b'existing configuration must survive\n')
                unit['DropInPaths'] = str(self.existing_drop)
        for name, value in (
            ('native-rollout-preflight.json', self.preflight),
            ('native-async-preflight.json', expected),
            ('native-release-current.json', dict(release_path=str(self.target), closure_sha256='a' * 64,
                                               binary_sha256=self.newhash, source_commit='b' * 40))):
            (self.root / name).write_text(json.dumps(value))
        self.events, self.waits = [], []
        self.service_states = {}
        for name in (*N.ORDER, N.FRONT, N.BRIDGE, N.TUNNEL):
            fragment = self.root / 'systemd' / name
            if name in N.CONTROL_DEPENDENCIES:
                fragment.write_text('[Unit]\nRequires=' + ' '.join(sorted(N.CONTROL_DEPENDENCIES[name])) + '\n')
            self.service_states[name] = dict(Id=name, LoadState='loaded', ActiveState='active', SubState='running',
                MainPID='2000', FragmentPath=str(fragment), DropInPaths='',
                Requires=' '.join(sorted(N.CONTROL_DEPENDENCIES.get(name, set()))), Wants='', BindsTo='', PartOf='', After='')

    def execute(self, check=False, failed_unit=None, tamper=False, fail_drain=False, acceptance=True,
                inactive_control=None, failed_control=None, unchanged_controls=False, change_control=None):
        if inactive_control:
            self.service_states[inactive_control].update(ActiveState='inactive', SubState='dead', MainPID='0')
        def release(path, expected=None):
            return {'hepta-runtime': self.newhash if Path(path) == self.target else N.OLD_BINARY,
                    'chatgpt_computer_http.py': 'c' * 64}
        def wait(unit, argv, binary=None):
            self.waits.append((unit['unit'], binary))
            if unit['unit'] == failed_unit and binary == self.newhash:
                if tamper:
                    (Path(unit['FragmentPath'] + '.d') / '91-native-throughput-20261017.conf').write_bytes(b'external change\n')
                raise RuntimeError('synthetic candidate failure')
            return {'pid': int(unit['MainPID']) + 100, 'exe_sha256': binary, 'start_unix': time.time()}
        def observe(unit, expected, phase, *args, **kwargs):
            if fail_drain and phase == 'drained':
                raise RuntimeError('new async intent appeared')
            return {}
        def acceptance_run(command, **kwargs):
            output = Path(command[command.index('--output') + 1])
            output.write_text(json.dumps({'passed': acceptance, 'steps': []}))
            if change_control:
                Path(self.service_states[change_control]['FragmentPath']).write_bytes(b'external unit edit\n')
            return types.SimpleNamespace(returncode=0 if acceptance else 1)
        def stop(name):
            self.events.append(('stop', name))
            self.service_states[name].update(ActiveState='inactive', SubState='dead', MainPID='0')
            if not unchanged_controls:
                for control, dependencies in N.CONTROL_DEPENDENCIES.items():
                    if name in dependencies:
                        self.service_states[control].update(ActiveState='inactive', SubState='dead', MainPID='0')
        def system(*args, **kwargs):
            self.events.append(args)
            if args[0] == 'show':
                value = self.service_states[args[1]]
                return '\n'.join(key + '=' + value.get(key, '') for key in (arg.split('=', 1)[1] for arg in args[2:]))
            if args[0] == 'start':
                if args[1] == failed_control:
                    raise RuntimeError('synthetic control start failure')
                self.service_states[args[1]].update(ActiveState='active', SubState='running', MainPID='3000')
            return ''
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(N, 'ROOT', self.root))
            stack.enter_context(mock.patch.object(N, 'release', side_effect=release))
            stack.enter_context(mock.patch.object(N, 'identity', return_value={'pid': 1, 'start_unix': 0}))
            stack.enter_context(mock.patch.object(N, 'roots', return_value={'synthetic-root': [1, 2, 3, 4]}))
            stack.enter_context(mock.patch.object(N, 'observe', side_effect=observe))
            stack.enter_context(mock.patch.object(N, 'stop', side_effect=stop))
            stack.enter_context(mock.patch.object(N, 'system', side_effect=system))
            stack.enter_context(mock.patch.object(N, 'wait', side_effect=wait))
            stack.enter_context(mock.patch.object(N.subprocess, 'run', side_effect=acceptance_run))
            stack.enter_context(mock.patch('sys.argv', ['native_rollout.py', '--check-only' if check else '--apply', '--output-prefix', 'test']))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            return N.main()

    def test_check_only_does_not_stop_services_or_write_overrides(self):
        self.assertEqual(self.execute(check=True), 0)
        self.assertTrue(all(event[0] == 'show' for event in self.events))
        self.assertFalse(list(self.root.rglob('91-native-throughput-20261017.conf')))
        self.assertEqual(self.front_drop.read_bytes(), self.front_raw)

    def test_second_native_failure_restores_reverse_order_and_existing_config(self):
        self.assertEqual(self.execute(failed_unit=N.OPERATOR), 1)
        restored = [name for name, sha in self.waits if sha == N.OLD_BINARY]
        self.assertEqual(restored, [N.OPERATOR, N.SUCCESSOR])
        self.assertFalse(list(self.root.rglob('91-native-throughput-20261017.conf')))
        self.assertEqual(self.existing_drop.read_bytes(), b'existing configuration must survive\n')
        self.assertEqual(self.front_drop.read_bytes(), self.front_raw)
        self.assertTrue(json.loads((self.root / 'test-apply.json').read_text())['rolled_back'])
        restored_controls = [event[1] for event in self.events if event[0] == 'start' and event[1] in N.CONTROL_DEPENDENCIES]
        self.assertEqual(restored_controls, [N.BRIDGE, N.TUNNEL])
        self.assertEqual([name for name, _ in self.waits][-1], N.FRONT)

    def test_unexpected_async_after_front_drain_does_not_stop_native(self):
        self.assertEqual(self.execute(fail_drain=True), 1)
        self.assertFalse(any(event == ('stop', unit) for event in self.events for unit in N.ORDER))
        self.assertFalse(list(self.root.rglob('91-native-throughput-20261017.conf')))

    def test_external_override_change_is_preserved_and_rollback_incomplete(self):
        self.assertEqual(self.execute(failed_unit=N.OPERATOR, tamper=True), 1)
        remaining = list(self.root.rglob('91-native-throughput-20261017.conf'))
        self.assertEqual(len(remaining), 1)
        self.assertEqual(remaining[0].read_bytes(), b'external change\n')
        self.assertFalse(json.loads((self.root / 'test-apply.json').read_text())['rolled_back'])
        self.assertFalse(any(event[0] == 'start' and event[1] in N.CONTROL_DEPENDENCIES for event in self.events))

    def test_frontend_acceptance_failure_restores_all_native_and_frontend_bytes(self):
        self.assertEqual(self.execute(acceptance=False), 1)
        self.assertEqual([name for name, sha in self.waits if sha == N.OLD_BINARY], [N.V11, N.OPERATOR, N.SUCCESSOR])
        self.assertEqual(self.front_drop.read_bytes(), self.front_raw)
        self.assertFalse(list(self.root.rglob('91-native-throughput-20261017.conf')))
        receipt = json.loads((self.root / 'test-apply.json').read_text())
        self.assertFalse(receipt['passed']); self.assertTrue(receipt['rolled_back'])

    def test_success_commits_only_owned_overrides_and_keeps_original_backup(self):
        self.assertEqual(self.execute(), 0)
        self.assertEqual(len(list(self.root.rglob('91-native-throughput-20261017.conf'))), 3)
        self.assertEqual(self.front_drop.read_bytes(), self.front_raw.replace(str(self.old).encode(), str(self.target).encode()))
        self.assertEqual((self.root / 'test-apply-frontend-original.conf').read_bytes(), self.front_raw)
        receipt = json.loads((self.root / 'test-apply.json').read_text())
        self.assertTrue(receipt['passed']); self.assertTrue(receipt['activated'])
        self.assertTrue(receipt['dependent_services_restored'])
        self.assertFalse(receipt['external_mcp_verified'])
        self.assertEqual([event[1] for event in self.events if event[0] == 'start' and event[1] in N.CONTROL_DEPENDENCIES], [N.BRIDGE, N.TUNNEL])

    def test_originally_inactive_control_is_not_started(self):
        self.assertEqual(self.execute(inactive_control=N.BRIDGE), 0)
        self.assertNotIn(('start', N.BRIDGE), self.events)
        self.assertIn(('start', N.TUNNEL), self.events)

    def test_still_active_controls_are_never_restarted(self):
        self.assertEqual(self.execute(unchanged_controls=True), 0)
        self.assertFalse(any(event[0] in ('start', 'restart', 'stop') and event[1] in N.CONTROL_DEPENDENCIES for event in self.events))

    def test_late_control_failure_does_not_roll_back_committed_native(self):
        self.assertEqual(self.execute(failed_control=N.BRIDGE), 0)
        receipt = json.loads((self.root / 'test-apply.json').read_text())
        self.assertTrue(receipt['passed']); self.assertTrue(receipt['activated'])
        self.assertNotIn('rolled_back', receipt)
        self.assertFalse(receipt['dependent_services_restored'])
        self.assertIn(('start', N.TUNNEL), self.events)
        self.assertEqual(len(list(self.root.rglob('91-native-throughput-20261017.conf'))), 3)
        self.assertFalse(any(sha == N.OLD_BINARY for _, sha in self.waits))

    def test_changed_control_configuration_is_not_started_or_replaced(self):
        self.assertEqual(self.execute(change_control=N.TUNNEL), 0)
        self.assertNotIn(('start', N.TUNNEL), self.events)
        self.assertEqual(Path(self.service_states[N.TUNNEL]['FragmentPath']).read_bytes(), b'external unit edit\n')
        self.assertFalse(json.loads((self.root / 'test-apply.json').read_text())['dependent_services_restored'])

    def test_unreviewed_control_dependency_refuses_before_frontend_stop(self):
        self.service_states[N.TUNNEL]['Requires'] += ' unexpected.service'
        self.assertEqual(self.execute(), 1)
        self.assertFalse(any(event[0] in ('start', 'stop', 'restart') for event in self.events))
        self.assertEqual(self.front_drop.read_bytes(), self.front_raw)


if __name__ == '__main__':
    unittest.main()

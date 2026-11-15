#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Regressions for system/user namespace resolution, without changing services."""
import importlib.util
import json
import pathlib
import subprocess
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('service_inspect', ROOT / 'src/mcp/runtime/service_inspect.py')
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


def observation(scope, load='loaded', complete=True, **extra):
    return dict(scope=scope, exit_code=0 if complete else None,
                properties={'LoadState': load, 'MainPID': '123' if load == 'loaded' else '0'},
                stderr='', observation_complete=complete, **extra)


class ResolutionTests(unittest.TestCase):
    def resolve(self, *rows):
        with patch.object(MOD, 'probe', side_effect=rows) as p:
            result = MOD.inspect_linux_service('example.service', 777)
        self.assertEqual(p.call_args_list[0].args, ('example.service', 'system', 777))
        self.assertEqual(p.call_args_list[1].args, ('example.service', 'user', 777))
        self.assertEqual(result['observations'], list(rows))
        return result

    def test_user_unit_not_misreported_absent(self):
        row = self.resolve(observation('system', 'not-found'), observation('user'))
        self.assertEqual(row['scope'], 'user')
        self.assertEqual(row['resolution'], 'unique')
        self.assertEqual(row['properties']['MainPID'], '123')
        self.assertTrue(row['resolution_complete'])

    def test_system_unit_preserves_properties(self):
        system = observation('system')
        row = self.resolve(system, observation('user', 'not-found'))
        self.assertEqual(row['scope'], 'system')
        self.assertEqual(row['properties'], system['properties'])

    def test_colliding_units_not_arbitrarily_selected(self):
        row = self.resolve(observation('system'), observation('user'))
        self.assertEqual(row['resolution'], 'ambiguous')
        self.assertIsNone(row['scope'])
        self.assertIsNone(row['exit_code'])
        self.assertEqual(row['properties'], {})

    def test_both_missing_is_proven_absent(self):
        row = self.resolve(observation('system', 'not-found'), observation('user', 'not-found'))
        self.assertEqual(row['resolution'], 'not_found')
        self.assertEqual(row['properties'], {'LoadState': 'not-found'})
        self.assertTrue(row['resolution_complete'])

    def test_failed_user_probe_is_not_absence(self):
        row = self.resolve(observation('system', 'not-found'), observation('user', 'not-found', False))
        self.assertEqual(row['resolution'], 'unknown')
        self.assertEqual(row['properties'], {})
        self.assertFalse(row['resolution_complete'])

    def test_system_present_user_unknown_is_explicit(self):
        row = self.resolve(observation('system'), observation('user', 'not-found', False))
        self.assertEqual(row['resolution'], 'present_other_scope_unknown')
        self.assertEqual(row['scope'], 'system')
        self.assertFalse(row['resolution_complete'])

    def test_user_present_system_unknown_is_explicit(self):
        row = self.resolve(observation('system', 'not-found', False), observation('user'))
        self.assertEqual(row['resolution'], 'present_other_scope_unknown')
        self.assertEqual(row['scope'], 'user')

    def test_masked_unit_is_present(self):
        row = self.resolve(observation('system', 'masked'), observation('user', 'not-found'))
        self.assertEqual(row['scope'], 'system')
        self.assertEqual(row['resolution'], 'unique')

    def test_both_failed_is_unknown(self):
        row = self.resolve(observation('system', 'not-found', False), observation('user', 'not-found', False))
        self.assertEqual(row['resolution'], 'unknown')
        self.assertIsNone(row['exit_code'])


class ProbeTests(unittest.TestCase):
    def run_probe(self, stdout='LoadState=loaded\nMainPID=123\n', stderr='', rc=0, scope='system'):
        response = subprocess.CompletedProcess([], rc, stdout, stderr)
        with patch.object(MOD.time, 'monotonic', return_value=10), \
             patch.object(MOD, 'user_environment', return_value={'XDG_RUNTIME_DIR': '/run/user/1000'}), \
             patch.object(MOD.subprocess, 'run', return_value=response) as run:
            row = MOD.probe('example.service', scope, 12)
        return row, run

    def test_system_command_is_read_only(self):
        row, run = self.run_probe()
        argv = run.call_args.args[0]
        self.assertEqual(argv[:3], ['systemctl', 'show', '--no-pager'])
        self.assertEqual(argv[-2:], ['--', 'example.service'])
        self.assertNotIn('shell', run.call_args.kwargs)
        self.assertEqual(run.call_args.kwargs['timeout'], 2)
        self.assertTrue(row['observation_complete'])

    def test_user_command_has_explicit_manager(self):
        row, run = self.run_probe(scope='user')
        self.assertEqual(run.call_args.args[0][:3], ['systemctl', '--user', 'show'])
        self.assertEqual(row['scope'], 'user')
        self.assertEqual(run.call_args.kwargs['env']['XDG_RUNTIME_DIR'], '/run/user/1000')

    def test_missing_loadstate_does_not_claim_complete(self):
        row, _ = self.run_probe(stdout='ActiveState=inactive\n')
        self.assertFalse(row['observation_complete'])

    def test_unknown_loadstate_does_not_claim_complete(self):
        row, _ = self.run_probe(stdout='LoadState=unexpected-new-state\n')
        self.assertFalse(row['observation_complete'])

    def test_nonzero_exit_is_not_proof_of_absence(self):
        row, _ = self.run_probe(stdout='LoadState=not-found\n', rc=1)
        self.assertFalse(row['observation_complete'])

    def test_unrequested_properties_are_discarded(self):
        row, _ = self.run_probe(stdout='LoadState=loaded\nEnvironment=PRIVATE\nExecStart=PRIVATE\n')
        self.assertNotIn('Environment', row['properties'])
        self.assertNotIn('PRIVATE', json.dumps(row))

    def test_timeout_is_explicit(self):
        with patch.object(MOD.time, 'monotonic', return_value=10), \
             patch.object(MOD.subprocess, 'run', side_effect=subprocess.TimeoutExpired('systemctl', 1)):
            row = MOD.probe('example.service', 'system', 12)
        self.assertEqual(row['error'], 'manager_query_timeout')
        self.assertFalse(row['observation_complete'])

    def test_no_executable_is_unknown(self):
        with patch.object(MOD.time, 'monotonic', return_value=10), \
             patch.object(MOD.subprocess, 'run', side_effect=FileNotFoundError()):
            row = MOD.probe('example.service', 'system', 12)
        self.assertEqual(row['error'], 'manager_unavailable')

    def test_budget_exhaustion_never_spawns(self):
        with patch.object(MOD.time, 'monotonic', return_value=12), \
             patch.object(MOD.subprocess, 'run') as run:
            row = MOD.probe('example.service', 'system', 12)
        run.assert_not_called()
        self.assertEqual(row['error'], 'budget_exhausted')

    def test_missing_user_runtime_never_uses_foreign_bus(self):
        with patch.object(MOD.time, 'monotonic', return_value=10), \
             patch.object(MOD, 'user_environment', side_effect=FileNotFoundError()), \
             patch.object(MOD.subprocess, 'run') as run:
            row = MOD.probe('example.service', 'user', 12)
        run.assert_not_called()
        self.assertEqual(row['error'], 'manager_unavailable')

    def test_valid_user_runtime_binds_current_uid(self):
        import stat
        from types import SimpleNamespace
        with patch.dict(MOD.os.environ, {'XDG_RUNTIME_DIR': '/wrong', 'DBUS_SESSION_BUS_ADDRESS': 'tcp:foreign'}), \
             patch.object(MOD.os, 'getuid', return_value=1000), \
             patch.object(MOD.os, 'lstat', return_value=SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=1000)):
            env = MOD.user_environment()
        self.assertEqual(env['XDG_RUNTIME_DIR'], '/run/user/1000')
        self.assertEqual(env['DBUS_SESSION_BUS_ADDRESS'], 'unix:path=/run/user/1000/bus')

    def test_symlink_user_runtime_refused(self):
        import stat
        from types import SimpleNamespace
        with patch.object(MOD.os, 'getuid', return_value=1000), \
             patch.object(MOD.os, 'lstat', return_value=SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=1000)):
            with self.assertRaises(OSError): MOD.user_environment()

    def test_foreign_uid_runtime_refused(self):
        import stat
        from types import SimpleNamespace
        with patch.object(MOD.os, 'getuid', return_value=1000), \
             patch.object(MOD.os, 'lstat', return_value=SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=2000)):
            with self.assertRaises(OSError): MOD.user_environment()


    def test_unicode_description_byte_bound_is_explicit(self):
        row, _ = self.run_probe(stdout='LoadState=loaded\nDescription=' + '中' * 1000 + '\n')
        self.assertLessEqual(len(row['properties']['Description'].encode('utf-8')), 512)
        self.assertEqual(row['properties_truncated'], ['Description'])
        self.assertTrue(row['observation_complete'])

    def test_stderr_byte_bound_is_explicit(self):
        row, _ = self.run_probe(stderr='中' * 1000)
        self.assertLessEqual(len(row['stderr'].encode('utf-8')), 512)
        self.assertTrue(row['stderr_truncated'])

    def test_ordinary_fields_are_not_reported_truncated(self):
        row, _ = self.run_probe()
        self.assertEqual(row['properties_truncated'], [])
        self.assertFalse(row['stderr_truncated'])


if __name__ == '__main__':
    unittest.main()

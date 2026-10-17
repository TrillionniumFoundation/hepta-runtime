"""Local recovery guards; never invoke a real service or network connection."""
import contextlib
import fcntl
import io
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

import recover_control_channel as C


ACTUAL_JOB_FIELDS = json.loads((Path(__file__).with_name('actual_job_fields_fixture.json')).read_text())


class RecoveryTests(unittest.TestCase):
    def run_recovery(self, *, cutover='inactive', tunnel='inactive', unfinished=False,
                     corrupt=False, missing=False, contradiction=False, gc=False,
                     timer_overrides=None, cutover_overrides=None, tunnel_load='loaded',
                     hold_lock=False, check_only=False, raw_statuses=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); path = root / 'native-cutover-v1-apply.json'
            value = {'schema': 'hepta-native-rollout-v1', 'mode': 'apply', 'passed': True, 'activated': True,
                     'started_utc': '2026-10-17T11:07:25+00:00', 'finished_utc': '2026-10-17T11:10:00+00:00',
                     'calls': [], 'events': []}
            if unfinished:
                value.pop('finished_utc'); value.pop('activated'); value['passed'] = False
            if contradiction:
                value['rolled_back'] = True
            if not missing:
                path.write_text('{invalid' if corrupt else json.dumps(value)); path.chmod(0o600)
            lock = root / '.native-rollout-20261017.lock'; lock.write_bytes(b''); lock.chmod(0o600)
            starts = []
            def status(name):
                if name == C.TIMER:
                    value = {'Id': name, 'LoadState': 'not-found', 'ActiveState': 'inactive',
                             'SubState': 'dead', 'Job': '0',
                             'NextElapseUSecRealtime': '', 'NextElapseUSecMonotonic': '0'}
                    value.update(timer_overrides or {})
                    return {key: item for key, item in value.items() if item is not None}
                state = cutover if name == C.CUTOVER else ('active' if starts else tunnel)
                value = {'Id': name, 'LoadState': ('not-found' if gc else 'loaded') if name == C.CUTOVER else tunnel_load,
                         'ActiveState': state, 'SubState': 'running' if state == 'active' else 'dead',
                         'MainPID': '100' if state == 'active' else '0',
                         'Result': 'success', 'ExecMainStatus': '0', 'Job': '0'}
                if name == C.CUTOVER:
                    value.update(cutover_overrides or {})
                return {key: item for key, item in value.items() if item is not None}
            def run(command, **kwargs):
                if command[:3] == ['systemctl', '--user', 'show']:
                    self.assertIn(command[3], (C.CUTOVER, C.TIMER, C.TUNNEL))
                    value = status(command[3])
                    requested = [item.removeprefix('--property=') for item in command[4:]]
                    stdout = '\n'.join(key + '=' + value[key] for key in requested if key in value)
                    if raw_statuses and command[3] in raw_statuses:
                        stdout = raw_statuses[command[3]]
                    return types.SimpleNamespace(returncode=0, stdout=stdout, stderr='')
                self.assertEqual(command, ['systemctl', '--user', 'start', C.TUNNEL])
                starts.append(command)
                return types.SimpleNamespace(returncode=0, stdout='', stderr='')
            output = io.StringIO()
            with lock.open('rb') as holder:
                if hold_lock:
                    fcntl.flock(holder.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                with mock.patch.object(C, 'ROOT', root), mock.patch.object(C, 'RECEIPT', path), \
                        mock.patch.object(C.subprocess, 'run', side_effect=run), \
                        mock.patch('sys.argv', ['recover_control_channel.py'] + (['--check-only'] if check_only else [])), \
                        contextlib.redirect_stdout(output):
                    code = C.main()
            return code, json.loads(output.getvalue()), starts

    def test_active_cutover_never_touches_services(self):
        code, report, starts = self.run_recovery(cutover='active')
        self.assertEqual(code, 0); self.assertEqual(starts, [])
        self.assertIn('no_service_changes', report['decision'])

    def test_unfinished_receipt_never_touches_services(self):
        code, report, starts = self.run_recovery(unfinished=True)
        self.assertEqual(code, 0); self.assertEqual(starts, [])

    def test_finished_cutover_starts_only_original_tunnel_once(self):
        code, report, starts = self.run_recovery()
        self.assertEqual(code, 0)
        self.assertEqual(starts, [['systemctl', '--user', 'start', C.TUNNEL]])
        self.assertFalse(report['external_mcp_verified'])

    def test_already_active_tunnel_is_not_restarted(self):
        code, report, starts = self.run_recovery(tunnel='active')
        self.assertEqual(code, 0); self.assertEqual(starts, [])
        self.assertIn('external_reconnect_must_be_verified', report['decision'])

    def test_contradictory_receipt_refuses_without_service_action(self):
        code, report, starts = self.run_recovery(contradiction=True)
        self.assertEqual(code, 1); self.assertEqual(starts, [])

    def test_missing_or_corrupt_receipt_refuses_without_service_action(self):
        for condition in ({'missing': True}, {'corrupt': True}):
            code, report, starts = self.run_recovery(**condition)
            self.assertEqual(code, 1); self.assertEqual(starts, [])

    def test_gc_finished_success_uses_receipt_not_exit_defaults(self):
        code, report, starts = self.run_recovery(gc=True, cutover_overrides={'Result': 'exit-code', 'ExecMainStatus': '99'})
        self.assertEqual(code, 0)
        self.assertEqual(starts, [['systemctl', '--user', 'start', C.TUNNEL]])
        self.assertEqual(report['cutover_exit_evidence'], 'unavailable_transient_unit_garbage_collected')
        self.assertEqual(report['cutover_end_evidence'], 'finished_receipt_rechecked_under_rollout_lock_with_quiet_timer')
        self.assertFalse(report['external_mcp_verified'])

    def test_gc_unfinished_receipt_never_touches_services(self):
        code, report, starts = self.run_recovery(gc=True, unfinished=True)
        self.assertEqual(code, 0); self.assertEqual(starts, [])
        self.assertIn('receipt_unfinished', report['decision'])

    def test_gc_missing_corrupt_or_contradictory_receipt_refuses(self):
        for condition in ({'missing': True}, {'corrupt': True}, {'contradiction': True}):
            with self.subTest(condition=condition):
                code, report, starts = self.run_recovery(gc=True, **condition)
                self.assertEqual(code, 1); self.assertEqual(starts, [])

    def test_gc_held_rollout_lock_never_touches_services(self):
        code, report, starts = self.run_recovery(gc=True, hold_lock=True)
        self.assertEqual(code, 0); self.assertEqual(starts, [])
        self.assertEqual(report['decision'], 'rollout_lock_still_held_no_service_changes')

    def test_gc_busy_or_pending_timer_never_touches_services(self):
        conditions = ({'LoadState': 'loaded', 'ActiveState': 'active', 'SubState': 'waiting'},
                      {'LoadState': 'loaded', 'ActiveState': 'activating'},
                      {'Job': '42'},
                      {'LoadState': 'loaded', 'NextElapseUSecMonotonic': '123456'})
        for condition in conditions:
            with self.subTest(condition=condition):
                code, report, starts = self.run_recovery(gc=True, timer_overrides=condition)
                self.assertEqual(code, 0); self.assertEqual(starts, [])
                self.assertEqual(report['decision'], 'cutover_timer_busy_or_pending_no_service_changes')

    def test_gc_missing_timer_pending_evidence_refuses(self):
        code, report, starts = self.run_recovery(gc=True, timer_overrides={'Job': None})
        self.assertEqual(code, 1); self.assertEqual(starts, [])
        self.assertEqual(report['decision'], 'read_only_failure')

    def test_gc_pending_cutover_job_never_touches_services(self):
        code, report, starts = self.run_recovery(gc=True, cutover_overrides={'Job': '42'})
        self.assertEqual(code, 0); self.assertEqual(starts, [])
        self.assertEqual(report['decision'], 'cutover_job_pending_no_service_changes')

    def test_gc_missing_or_invalid_cutover_job_evidence_refuses(self):
        for gc in (False, True):
            for job in (None, 'unknown', ' ', '-1', '0 /org/freedesktop/systemd1/job/0', '\u00b2'):
                with self.subTest(gc=gc, job=job):
                    code, report, starts = self.run_recovery(gc=gc, cutover_overrides={'Job': job})
                    self.assertEqual(code, 1); self.assertEqual(starts, [])
                    self.assertEqual(report['error'], 'cutover pending-job evidence is unavailable')

    def test_gc_missing_tunnel_is_still_rejected(self):
        code, report, starts = self.run_recovery(gc=True, tunnel_load='not-found')
        self.assertEqual(code, 1); self.assertEqual(starts, [])

    def test_loaded_cutover_still_requires_successful_exit(self):
        code, report, starts = self.run_recovery(cutover_overrides={'Result': 'exit-code', 'ExecMainStatus': '99'})
        self.assertEqual(code, 1); self.assertEqual(starts, [])
        self.assertEqual(report['cutover_exit_evidence'], 'loaded_unit_properties')

    def test_gc_active_tunnel_is_not_restarted(self):
        code, report, starts = self.run_recovery(gc=True, tunnel='active')
        self.assertEqual(code, 0); self.assertEqual(starts, [])
        self.assertEqual(report['decision'], 'tunnel_already_active_external_reconnect_must_be_verified')
        self.assertFalse(report['external_mcp_verified'])

    def test_gc_check_only_never_starts_tunnel(self):
        code, report, starts = self.run_recovery(gc=True, check_only=True)
        self.assertEqual(code, 0); self.assertEqual(starts, [])
        self.assertEqual(report['decision'], 'eligible_to_start_original_tunnel_check_only')

    def test_actual_show_empty_job_fixture_passes_check_only_without_action(self):
        raw = {name: value['raw_stdout'] for name, value in ACTUAL_JOB_FIELDS['unit_statuses'].items()}
        for tunnel in ('inactive', 'active'):
            with self.subTest(tunnel=tunnel):
                code, report, starts = self.run_recovery(raw_statuses=raw, tunnel=tunnel, check_only=True)
                self.assertEqual(code, 0); self.assertEqual(starts, [])
                self.assertEqual(report['service_action'], 'none')
                self.assertEqual(report['cutover_status']['Job'], '')
                self.assertEqual(report['cutover_timer_status']['Job'], '')
                self.assertEqual(report['cutover_timer_status']['NextElapseUSecMonotonic'], 'infinity')
                expected = ('eligible_to_start_original_tunnel_check_only' if tunnel == 'inactive'
                            else 'tunnel_already_active_external_reconnect_must_be_verified')
                self.assertEqual(report['decision'], expected)

    def test_actual_show_empty_job_fixture_can_only_start_original_tunnel_once(self):
        raw = {name: value['raw_stdout'] for name, value in ACTUAL_JOB_FIELDS['unit_statuses'].items()}
        code, report, starts = self.run_recovery(raw_statuses=raw)
        self.assertEqual(code, 0)
        self.assertEqual(starts, [['systemctl', '--user', 'start', C.TUNNEL]])
        self.assertFalse(report['external_mcp_verified'])

    def test_actual_show_missing_job_is_not_the_same_as_empty_job(self):
        original = {name: value['raw_stdout'] for name, value in ACTUAL_JOB_FIELDS['unit_statuses'].items()}
        for name in (C.CUTOVER, C.TIMER):
            with self.subTest(unit=name):
                raw = dict(original)
                raw[name] = raw[name].replace('Job=\n', '')
                code, report, starts = self.run_recovery(raw_statuses=raw)
                self.assertEqual(code, 1); self.assertEqual(starts, [])
                self.assertIn('pending-job evidence is unavailable', report['error'])

    def test_empty_and_numeric_zero_jobs_remain_explicit_no_job_evidence(self):
        for gc in (False, True):
            for job in ('', '0'):
                with self.subTest(gc=gc, job=job):
                    code, report, starts = self.run_recovery(gc=gc, check_only=True,
                        cutover_overrides={'Job': job}, timer_overrides={'Job': job})
                    self.assertEqual(code, 0); self.assertEqual(starts, [])
                    self.assertEqual(report['decision'], 'eligible_to_start_original_tunnel_check_only')

    def test_loaded_and_actual_gc_pending_cutover_jobs_block_all_service_actions(self):
        code, report, starts = self.run_recovery(cutover_overrides={'Job': '42'})
        self.assertEqual(code, 0); self.assertEqual(starts, [])
        self.assertEqual(report['decision'], 'cutover_job_pending_no_service_changes')
        original = {name: value['raw_stdout'] for name, value in ACTUAL_JOB_FIELDS['unit_statuses'].items()}
        for name in (C.CUTOVER, C.TIMER):
            with self.subTest(unit=name):
                raw = dict(original)
                raw[name] = raw[name].replace('Job=\n', 'Job=42\n')
                code, report, starts = self.run_recovery(raw_statuses=raw)
                self.assertEqual(code, 0); self.assertEqual(starts, [])
                self.assertIn('pending_no_service_changes', report['decision'])

    def test_loaded_timer_accepts_only_documented_no_deadline_sentinel(self):
        for value, expected in (('infinity', 'eligible_to_start_original_tunnel_check_only'),
                                ('unknown', 'cutover_timer_busy_or_pending_no_service_changes'),
                                ('123456', 'cutover_timer_busy_or_pending_no_service_changes')):
            with self.subTest(monotonic=value):
                code, report, starts = self.run_recovery(gc=True, check_only=True,
                    timer_overrides={'LoadState': 'loaded', 'NextElapseUSecMonotonic': value})
                self.assertEqual(code, 0); self.assertEqual(starts, [])
                self.assertEqual(report['decision'], expected)
        code, report, starts = self.run_recovery(gc=True, timer_overrides={
            'LoadState': 'loaded', 'NextElapseUSecRealtime': 'infinity', 'NextElapseUSecMonotonic': 'infinity'})
        self.assertEqual(code, 0); self.assertEqual(starts, [])
        self.assertEqual(report['decision'], 'cutover_timer_busy_or_pending_no_service_changes')


if __name__ == '__main__':
    unittest.main()

"""Regression for a complete public-control snapshot followed by later controls."""
from pathlib import Path
import ast
import copy
import hashlib
import json
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'scripts/compare_hia_runtime_rust.py'


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def functions():
    tree = ast.parse(SOURCE.read_bytes())
    wanted = {'public_registry_control_command', 'public_registry_control_evidence'}
    nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in wanted]
    constants = [node for node in tree.body if isinstance(node, ast.Assign)
                 and any(isinstance(target, ast.Name) and target.id == 'PUBLIC_REGISTRY_CONTROL_LABELS'
                         for target in node.targets)]
    assert {node.name for node in nodes} == wanted and len(constants) == 1
    module = ast.Module(body=[*constants, *nodes], type_ignores=[])
    ast.fix_missing_locations(module)
    scope = dict(Path=Path, ROOT=ROOT, sys=sys, json=json)
    exec(compile(module, str(SOURCE), 'exec'), scope)
    return scope


class PublicControlCheckpointTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(prefix='hia-public-control-checkpoint-')
        self.addCleanup(self.folder.cleanup)
        self.output = Path(self.folder.name)
        self.ns = functions()
        self.name = 'public-registry-evidence-controls'
        self.prior = [dict(name='native-registry', argv=['actual-native'], timeout_seconds=180,
                           exit_code=0, stdout_sha256='1' * 64),
                      dict(name='original-registry', argv=['actual-original'], timeout_seconds=180,
                           exit_code=0, stdout_sha256='2' * 64)]
        self.control = dict(name=self.name, phase='original_rust_comparison', exit_code=0, timeout_seconds=180)
        self.report = dict(checks=copy.deepcopy(self.prior) + [self.control], source_sha256={'source': '3' * 64},
                           modules={'module': '4' * 64}, public_registry_evidence={'status': 'PASS'},
                           original_rust_comparisons={'public_registry': {'records': 216}},
                           compiler_checkout='/exact/compiler', compiler_commit='5' * 40,
                           compiler_image_sha256='6' * 64)
        self.snapshot = copy.deepcopy(self.report)
        self.snapshot['checks'] = copy.deepcopy(self.prior)
        (self.output / 'public-registry-controls-input.json').write_bytes(encoded(self.snapshot))
        self.baseline = dict(all_sessions=True, full_source='7' * 64)
        digest = sha(encoded(self.baseline))
        self.value = dict(schema='hepta.public-registry.evidence-controls.v1', status='PASS',
                          rejections=20, full_baseline_admissions=22, actual_native_calls_added=0,
                          actual_rust_calls_added=0, restored_file_bytes_and_modes=True,
                          report_sha256=sha(encoded(self.snapshot)), baseline_evidence_sha256=digest,
                          final_evidence_sha256=digest, elapsed_seconds=1.0,
                          controls=[dict(label=label, rejected=True, exception='expected semantic refusal')
                                    for label in self.ns['PUBLIC_REGISTRY_CONTROL_LABELS']])
        (self.output / 'public-registry-evidence-controls.json').write_bytes(encoded(self.value))
        for stream in ('stdout', 'stderr'):
            (self.output / (self.name + '.' + stream)).write_bytes(encoded(self.value) if stream == 'stdout' else b'')
        self.helper = types.SimpleNamespace(
            object_at=lambda path: json.loads(path.read_bytes()),
            completed=Mock(return_value=(encoded(self.value), b'')),
            original_evidence=Mock(return_value=self.baseline),
            sha=sha, encoded=encoded,
            duration=lambda value, maximum: self.assertTrue(0 < value < maximum))
        self.ns.update(public_registry_qualification=self.helper,
                       completed_test_summary=Mock(return_value=(self.control, self.value)),
                       sha=lambda path: sha(path.read_bytes()))

    def call(self):
        return self.ns['public_registry_control_evidence'](self.output, self.report)

    def refuse(self):
        with self.assertRaisesRegex(ValueError, 'complete prior process set'):
            self.call()
        self.helper.completed.assert_not_called()

    def test_exact_current_prefix_is_admitted(self):
        actual = self.call()
        self.assertEqual(actual['status'], 'PASS')
        self.assertEqual(actual['rejections'], 20)
        self.assertEqual(actual['full_baseline_admissions'], 22)
        self.assertEqual(actual['actual_native_calls_added'], 0)
        self.assertEqual(actual['actual_rust_calls_added'], 0)
        self.helper.original_evidence.assert_called_once()

    def test_later_storage_control_preserves_the_original_public_snapshot(self):
        before = self.call()
        self.report['checks'].append(dict(name='result-storage-evidence-controls', exit_code=0,
                                          timeout_seconds=180, stdout_sha256='8' * 64))
        self.assertEqual(self.call(), before)
        self.assertEqual(json.loads((self.output / 'public-registry-controls-input.json').read_bytes()), self.snapshot)

    def test_missing_and_duplicate_own_process_are_refused(self):
        for checks in (copy.deepcopy(self.prior), copy.deepcopy(self.prior) + [self.control, self.control]):
            with self.subTest(checks=checks):
                self.report['checks'] = checks
                self.refuse()

    def test_missing_inserted_or_reordered_prior_process_is_refused(self):
        for prefix in (self.prior[:1], self.prior[::-1], self.prior + [dict(name='unexpected-before-control')]):
            with self.subTest(prefix=prefix):
                self.report['checks'] = copy.deepcopy(prefix) + [self.control]
                self.refuse()

    def test_actual_prior_command_limit_exit_and_full_stream_pin_remain_bound(self):
        for field, changed in (('argv', ['another-command']), ('timeout_seconds', 181),
                               ('exit_code', 1), ('stdout_sha256', '0' * 64)):
            with self.subTest(field=field):
                self.report['checks'] = copy.deepcopy(self.prior) + [self.control]
                self.report['checks'][0][field] = changed
                self.refuse()

    def test_control_moved_ahead_of_a_prior_process_is_refused(self):
        self.report['checks'] = [self.prior[0], self.control, self.prior[1]]
        self.refuse()

    def test_every_other_complete_snapshot_binding_remains_required(self):
        for field in ('source_sha256', 'modules', 'public_registry_evidence', 'original_rust_comparisons',
                      'compiler_checkout', 'compiler_commit', 'compiler_image_sha256'):
            with self.subTest(field=field):
                original = self.report[field]
                self.report[field] = {'changed': True}
                with self.assertRaisesRegex(ValueError, 'public evidence control input changed: ' + field):
                    self.call()
                self.report[field] = original
        self.helper.completed.assert_not_called()

    def test_real_completion_failure_is_not_reclassified(self):
        self.helper.completed.side_effect = ValueError('actual process completion was nonzero')
        with self.assertRaisesRegex(ValueError, 'actual process completion was nonzero'):
            self.call()
        self.helper.original_evidence.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)

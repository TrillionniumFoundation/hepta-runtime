#!/usr/bin/env python3
"""Small rejection controls over the retained actual view evidence.

One complete baseline read precedes the controls. Mutations are private in-memory
overlays; no original capture or running native state is edited. These controls
execute no new HIA call, kernel fixture, Cargo build, or original Rust process.
"""
from __future__ import annotations
import copy
import gzip
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('_view_call_evidence_reader', ROOT / 'scripts/hia_native_view_call_qualification.py')
q = importlib.util.module_from_spec(spec); spec.loader.exec_module(q)
EXPECTED_GROUPS, EXPECTED_CONTROLS = 8, 64
CONTROLS = []
OUTPUT = REPORT = NATIVE = None


class Overlay(q.Evidence):
    def __init__(self, *, objects=None, raw=None, zipped=None):
        super().__init__(ROOT, OUTPUT)
        self.objects = objects or {}; self.raw_overrides = raw or {}; self.zip_overrides = zipped or {}

    def json(self, path):
        path = Path(path)
        return copy.deepcopy(self.objects[path]) if path in self.objects else super().json(path)

    def raw(self, path):
        path = Path(path)
        return self.raw_overrides[path] if path in self.raw_overrides else super().raw(path)

    def zipped(self, folder, name, expected=None):
        path = self.path(name, folder)
        return self.zip_overrides[path] if path in self.zip_overrides else super().zipped(folder, name, expected)


def changed(raw, offset, value):
    value_raw = bytearray(raw); struct.pack_into('<Q', value_raw, offset, value); return bytes(value_raw)


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = OUTPUT / NATIVE['corpora']['caller']
        cls.read_folder = OUTPUT / NATIVE['corpora']['read']
        cls.e = q.Evidence(ROOT, OUTPUT)
        cls.rows = cls.e.rows(cls.folder / 'native-cases.jsonl')
        cls.row = cls.rows[0]
        cls.read = cls.e.json(cls.read_folder / 'read-native-result.json')
        cls.cases = q.load_module('evidence_case_inputs', ROOT / 'tests/hia_native/view_call_oracle/cases.py')
        cls.support = q.load_module('evidence_frame_inputs', ROOT / 'tests/hia_native/test_view_call_support.py')
        cls.case = next(cls.cases.iter_cases())
        cls.process = cls.e.json(cls.folder / 'session-0.process.json')
        cls.streams = {key: cls.e.zipped(cls.folder, descriptor['path'], descriptor)
                       for key, descriptor in cls.process['streams'].items()}

    def rejects(self, name, function):
        with self.assertRaises(ValueError, msg=name): function()
        CONTROLS.append(dict(name=name, rejected=True))

    def test_01_strict_json_types_and_paths(self):
        for name, raw in [('duplicate-key', b'{"a":1,"a":2}'), ('nan', b'{"a":NaN}'),
                          ('exponent-overflow', b'{"a":1e999}')]:
            self.rejects(name, lambda raw=raw: q.json_value(raw))
        self.rejects('boolean-integer', lambda: q.integer(True, 'control'))
        self.rejects('negative-count', lambda: q.integer(-1, 'control'))
        self.rejects('u64-overflow', lambda: q.integer(1 << 64, 'control'))
        self.rejects('parent-path-traversal', lambda: q.inside(OUTPUT, '../outside'))
        with tempfile.TemporaryDirectory(prefix='view-evidence-path-') as temporary:
            root = Path(temporary); (root / 'real').write_bytes(b'x'); (root / 'alias').symlink_to('real')
            self.rejects('internal-symlink-alias', lambda: q.inside(root, 'alias'))

    def test_02_actual_suite_receipts(self):
        name = 'test_view_call_read.py'; summary = self.read
        def check(mutate):
            report = copy.deepcopy(REPORT)
            row = next(item for item in report['checks'] if item['name'] == name)
            mutate(report, row)
            q._check(q.Evidence(ROOT, OUTPUT), report, name, summary, 'tests/hia_native/' + name)
        values = [
            ('missing-suite-deadline', lambda report, row: row.pop('timeout_seconds')),
            ('missing-suite-timeout-observation', lambda report, row: row.pop('timed_out')),
            ('suite-start-error', lambda report, row: row.update(start_error={'type': 'OSError', 'message': 'control'})),
            ('non-isolated-test-command', lambda report, row: row['command'].__setitem__(1, '-O')),
            ('inflated-suite-deadline', lambda report, row: row.update(timeout_seconds=300)),
            ('duplicate-suite-receipt', lambda report, row: report['checks'].append(copy.deepcopy(row))),
            ('changed-complete-suite-stdout', lambda report, row: row.update(stdout_sha256='0' * 64)),
            ('boolean-suite-exit-code', lambda report, row: row.update(exit_code=False)),
        ]
        for label, mutate in values: self.rejects(label, lambda mutate=mutate: check(mutate))

    def test_03_actual_compiler_and_source_binding(self):
        bundle = self.e.json(q.inside(OUTPUT, REPORT['view_call']['manifest']))
        build = q.inside(OUTPUT, REPORT['view_call']['manifest']).parent.parent
        path = q.inside(build, bundle['members'][0]['manifest']); metadata = self.e.json(path)
        def changed_manifest(key, value):
            altered = copy.deepcopy(metadata); altered[key] = value
            q._module(Overlay(objects={path: altered}), path, 'native/view_call.hepta')
        for key, value in [('compiler_commit', '0' * 40), ('compiler_sha256', '0' * 64),
                           ('source_sha256', '0' * 64), ('image_sha256', '0' * 64),
                           ('input_capacity', True), ('output_capacity', metadata['output_capacity'] + 1)]:
            self.rejects('module-' + key, lambda key=key, value=value: changed_manifest(key, value))
        receipt_path = path.parent / 'module.receipt.json'; build_path = path.parent / 'build.json'
        receipt, build_record = self.e.json(receipt_path), self.e.json(build_path)
        receipt['produced_bytes'] += 1; build_record['compile_receipt'] = receipt
        self.rejects('actual-compiler-produced-length', lambda: q._module(
            Overlay(objects={receipt_path: receipt, build_path: build_record}), path, 'native/view_call.hepta'))
        output_path = path.parent / 'module.output.bin'; raw = output_path.read_bytes()
        self.rejects('actual-compiler-full-output', lambda: q._module(
            Overlay(raw={output_path: bytes([raw[0] ^ 1]) + raw[1:]}), path, 'native/view_call.hepta'))

    def test_04_logical_generation_sequence_and_cancel_ack(self):
        event = self.row['events'][0]; raw = self.e.zipped(self.folder, event['payload_path']); ack = self.e.zipped(self.folder, event['ack_path'])
        q._event(raw, ack, 0, None, False)
        values = [
            ('zero-request-generation', lambda: q._event(changed(raw, 8, 0), ack, 0, None, False)),
            ('changed-request-generation', lambda: q._event(raw, ack, 0, event['generation'] + 1, False)),
            ('duplicate-logical-sequence', lambda: q._event(raw, ack, event['sequence'], None, False)),
            ('unknown-logical-kind', lambda: q._event(changed(raw, 24, 7), ack, 0, None, False)),
            ('wrong-reader-child-slot', lambda: q._event(changed(raw, 32, 9), ack, 0, None, False)),
            ('truncated-logical-payload', lambda: q._event(raw[:-1], ack, 0, None, False)),
            ('late-ack-sequence', lambda: q._event(raw, changed(ack, 16, event['sequence'] + 1), 0, None, False)),
        ]
        for name, control in values: self.rejects(name, control)
        cancelled = self.rows[52]['events'][-1]
        cancel_raw = self.e.zipped(self.folder, cancelled['payload_path']); cancel_ack = self.e.zipped(self.folder, cancelled['ack_path'])
        self.rejects('cancel-gate-ack-lost-action', lambda: q._event(cancel_raw, changed(cancel_ack, 24, 0), 0, None, True))

    def test_05_actual_kernel_receipt_ownership(self):
        raw = self.streams['stderr']
        parts = [raw[at:at + 128] for at in range(0, len(raw), 128) if raw[at:at + 8] == b'HVRDACK1']
        first = parts[0]; read = next(part for part in parts if struct.unpack_from('<Q', part, 24)[0] == 3)
        close = next(part for part in parts if struct.unpack_from('<Q', part, 24)[0] == 4)
        logical = [(event['child_slot'], observation['native_reader'], 4)
                   for event, observation in zip(self.row['events'], self.row['io'])]
        at = raw.index(first); seq = struct.unpack_from('<Q', first, 8)[0]
        gap = changed(changed(first, 8, seq + 1), 120, seq + 1)
        self.rejects('kernel-per-slot-sequence-gap', lambda: q._kernel(raw[:at] + gap + raw[at + 128:], logical))
        self.rejects('kernel-zero-generation', lambda: q._receipt(changed(first, 16, 0)))
        self.rejects('kernel-errno-does-not-match-syscall', lambda: q._receipt(changed(first, 80, 5)))
        self.rejects('kernel-normalized-result-differs', lambda: q._receipt(changed(first, 72, 1)))
        self.rejects('kernel-read-exceeds-window', lambda: q._receipt(changed(changed(read, 64, 65537), 72, 65537)))
        fd = struct.unpack_from('<Q', read, 104)[0]
        self.rejects('kernel-read-switches-descriptor', lambda: q._receipt(changed(read, 112, fd + 1)))
        fd = struct.unpack_from('<Q', close, 104)[0]
        self.rejects('kernel-close-does-not-retire', lambda: q._receipt(changed(close, 112, fd)))
        self.rejects('truncated-kernel-receipt', lambda: q._receipt(first[:-1]))

    def test_06_complete_caller_artifact_stream_binding(self):
        wire = self.support.call_frame(b'file', b'file', self.case['metadata']['params'])
        encoded = self.cases.encode_cases([self.case])
        def run(overrides=None, stdout=None):
            q._caller_case(Overlay(zipped=overrides), self.folder, self.row, self.case,
                io.BytesIO(self.streams['input']), io.BytesIO(self.streams['stdout'] if stdout is None else stdout), wire, encoded)
        paths = [('complete-original-input', self.row['input_path']), ('complete-native-request', self.row['call_path']),
                 ('complete-visible-body', self.row['body_path']), ('complete-after-render-base', self.row['after_render_path']),
                 ('complete-cache-probe', self.row['cache_after'][0]['probe_path']),
                 ('complete-reader-result', self.row['io'][0]['reader_result_path']),
                 ('complete-native-result', self.row['result_path'])]
        for label, name in paths:
            actual = self.e.zipped(self.folder, name)
            self.rejects(label, lambda name=name, actual=actual: run({self.folder / name: actual + b'x'}))
        self.rejects('truncated-actual-elf-stdout', lambda: run(stdout=self.streams['stdout'][:-1]))

    def test_07_private_reader_failure_and_lifecycle(self):
        self.rejects('failed-owner-mutates-state', lambda: q._refusal(b'\0', b'\1', b'\xa5', q.CAPACITY))
        self.rejects('failed-owner-mutates-output', lambda: q._refusal(b'\0', b'\0', b'\0', q.INVALID))
        self.rejects('pending-is-not-refusal', lambda: q._refusal(b'\0', b'\0', b'\xa5', q.PENDING))
        def event_mutation(kind, mutate, predicate=lambda event: True):
            summary = copy.deepcopy(self.read)
            event = next(event for event in summary['events'] if event['kind'] == kind and predicate(event))
            mutate(event); q._read_direct(q.Evidence(ROOT, OUTPUT), self.read_folder, summary)
        self.rejects('private-completion-sequence-changed', lambda: event_mutation('private_completion_control', lambda event: event.update(sequence=event['sequence'] + 1)))
        self.rejects('private-completion-data-incomplete', lambda: event_mutation('private_completion_control', lambda event: event.update(data_sha256='0' * 64), lambda event: event['data_bytes'] > 0))
        self.rejects('private-relocation-extent-changed', lambda: event_mutation('relocation', lambda event: event.update(capacity=event['capacity'] + 1)))
        self.rejects('private-counter-fault-changed', lambda: event_mutation('private_counter_fault', lambda event: event.update(writes=[[8, q.MAX - 1]])))
        self.rejects('private-event-unknown-session', lambda: event_mutation('private_completion_control', lambda event: event.update(session=35)))

    def test_08_original_process_receipt_contract(self):
        # Private reader controls, not claims that these synthetic rows executed.
        command = ['/control/cargo', 'build', '--locked', '--release']
        valid = dict(command=command, timeout_seconds=180, exit_code=0, timed_out=False,
                     spawn_error=None, elapsed_seconds=1.0)
        q._original_process(valid, command)
        def run(mutate):
            row = copy.deepcopy(valid); mutate(row); q._original_process(row, command)
        controls = [
            ('original-missing-locked-build', lambda row: row['command'].remove('--locked')),
            ('original-inflated-deadline', lambda row: row.update(timeout_seconds=300)),
            ('original-missing-deadline', lambda row: row.pop('timeout_seconds')),
            ('original-missing-timeout-observation', lambda row: row.pop('timed_out')),
            ('original-spawn-failure', lambda row: row.update(spawn_error='control')),
            ('original-boolean-exit', lambda row: row.update(exit_code=False)),
            ('original-nonfinite-elapsed', lambda row: row.update(elapsed_seconds=float('inf'))),
            ('original-exceeded-deadline', lambda row: row.update(elapsed_seconds=180)),
        ]
        for name, mutate in controls: self.rejects(name, lambda mutate=mutate: run(mutate))


def main():
    global OUTPUT, REPORT, NATIVE
    OUTPUT = Path(os.environ['HIA_VIEW_CALL_QUALIFICATION_OUTPUT']).resolve()
    report_path = Path(os.environ.get('HIA_VIEW_CALL_QUALIFICATION_REPORT', str(OUTPUT / 'result.json')))
    REPORT = q.json_value(report_path.read_bytes()); started = time.monotonic()
    NATIVE = q.native_evidence(ROOT, OUTPUT, REPORT)
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(EvidenceTests))
    passed = result.wasSuccessful() and result.testsRun == EXPECTED_GROUPS and len(CONTROLS) == EXPECTED_CONTROLS and not result.skipped
    summary = dict(schema='hepta.runtime.view-call-evidence-tests.v1', status='PASS' if passed else 'FAIL',
        groups=result.testsRun, expected_groups=EXPECTED_GROUPS, controls=len(CONTROLS), expected_controls=EXPECTED_CONTROLS,
        failures=len(result.failures), errors=len(result.errors), skipped=len(result.skipped), rejection_controls=CONTROLS,
        baseline_native_sha256=q.digest(q.canonical(NATIVE)), baseline_artifacts=len(NATIVE['artifact_sha256']),
        reader_sha256=q.pin(Path(q.__file__))['sha256'], test_sha256=q.pin(Path(__file__))['sha256'],
        elapsed_seconds=time.monotonic() - started, new_native_calls=0, new_original_processes=0,
        original_captures_modified=False, whole_view_replaced=False, whole_runtime_replaced=False)
    folder = Path(os.environ.get('HIA_VIEW_CALL_EVIDENCE_CAPTURE_DIR', str(OUTPUT / 'view-call-evidence')))
    folder.mkdir(parents=True, exist_ok=False); (folder / 'result.json').write_bytes(q.canonical(summary))
    print(json.dumps(summary, sort_keys=True), flush=True)
    return 0 if passed else 1


if __name__ == '__main__': raise SystemExit(main())

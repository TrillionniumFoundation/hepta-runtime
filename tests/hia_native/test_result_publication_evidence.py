"""Admit retained native evidence and reject corruptions; execute no new HIA.

Only a few early artifact controls use private hard-link snapshots. Stream
controls reuse retained bytes in memory and exercise the reader's own helpers,
so the large direct trace is not copied or decoded for every small control.
"""
from __future__ import annotations
from contextlib import contextmanager
import copy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
import hia_native_result_publication_qualification as q
from qualify_hia_runtime_native import completed_test_summary

CONTROLS = []
EXPECTED_GROUPS = 8
EXPECTED_CONTROLS = 68
MAX = (1 << 64) - 1


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def replace(path, raw):
    # Unlink our temporary name before writing: never mutate a shared inode.
    path.unlink()
    path.write_bytes(raw)


def framed(frames):
    return b''.join(struct.pack('<Q', len(wire)) + wire for wire in frames)


def receipt(seq=1, off=0, wanted=4, result=4, after=4, ack=64):
    return b'HRPWACK1' + struct.pack('<7Q', 1, seq, off, wanted, result & MAX, after, ack)


class CachedReader:
    def __init__(self, output, cache, changes=None):
        self.output, self.cache, self.changes = output, cache, changes or {}

    def read(self, relative):
        if relative in self.changes:
            return self.changes[relative]
        if relative not in self.cache:
            self.cache[relative] = q.owned(self.output, relative).read_bytes()
        return self.cache[relative]

    def plain(self, relative):
        return gzip.decompress(self.read(relative))

    def object(self, relative):
        return q.decode(self.read(relative))


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.output = Path(os.environ['HIA_RESULT_PUBLICATION_QUALIFICATION_OUTPUT']).resolve(strict=True)
        report_path = Path(os.environ.get('HIA_RESULT_PUBLICATION_QUALIFICATION_REPORT', str(cls.output / 'result.json')))
        cls.report = q.decode(report_path.read_bytes())
        cls.reader_source = ROOT / 'scripts/hia_native_result_publication_qualification.py'
        cls.reader_sha = sha(cls.reader_source.read_bytes())
        cls.test_sha = sha(Path(__file__).read_bytes())
        cls.actual = q.native_evidence(ROOT, cls.output, cls.report, completed_test_summary)
        cls.artifacts = cls.actual['artifact_sha256']
        cls.cache = {}
        cls.reader = CachedReader(cls.output, cls.cache)
        cls.summary = cls.reader.object(q.FOLDER + '/native-result.json')
        cls.events = q.json_lines(cls.reader.plain(q.FOLDER + '/events.jsonl.gz'))
        cls.logical, cls.cases = q.cases_at(ROOT)
        cls.entry = cls.report['modules']['result_publication']
        cls.bundle = cls.reader.object(cls.entry['manifest'])
        cls.elf_relative = (Path(cls.entry['manifest']).parent / cls.bundle['elf']).as_posix()
        cls.origin = Path(cls.summary['identities']['fixture_manifest']['path'][:-len('/' + cls.entry['manifest'])])
        cls.raw_name = q.FOLDER + '/actual-native-calls.bin.gz'
        # A single recompressed tail allows complete, one-header mutations with
        # concatenated gzip members, without copying a 160 MiB trace per control.
        tail = io.BytesIO()
        with gzip.GzipFile(fileobj=io.BytesIO(cls.reader.read(cls.raw_name))) as original:
            cls.first_header = original.read(56)
            with gzip.GzipFile(fileobj=tail, mode='wb', compresslevel=1, mtime=0) as out:
                while chunk := original.read(1 << 20):
                    out.write(chunk)
        cls.trace_tail = tail.getvalue()
        with gzip.GzipFile(fileobj=io.BytesIO(cls.reader.read(cls.raw_name))) as original:
            header = struct.unpack('<7Q', original.read(56))
            cls.first_request, cls.first_response = original.read(header[4]), original.read(header[6])

    def refuses(self, label, invoke):
        with self.assertRaises((ValueError, KeyError, IndexError, OSError, EOFError, struct.error)):
            invoke()
        self.assertNotIn(label, CONTROLS)
        CONTROLS.append(label)

    def check(self, report):
        return next(row for row in report['checks'] if row['name'] == q.SUITE)

    @contextmanager
    def snapshot(self):
        with tempfile.TemporaryDirectory(prefix='publication-evidence-', dir=self.output.parent) as directory:
            target = Path(directory) / 'capture'; target.mkdir()
            for relative in self.artifacts:
                destination = target / relative; destination.parent.mkdir(parents=True, exist_ok=True)
                os.link(q.owned(self.output, relative), destination)
            yield target, copy.deepcopy(self.report)

    def direct(self, changes=None, events=None):
        return q._native_calls(CachedReader(self.output, self.cache, changes), self.summary,
                               self.events if events is None else events, self.cases, self.logical)

    def processes(self, changes):
        return q._processes(CachedReader(self.output, self.cache, changes), self.origin,
                            self.elf_relative, self.bundle['elf_sha256'], self.cases, self.logical)

    def test_01_actual_admission_and_private_snapshot(self):
        self.assertEqual((self.actual['status'], self.actual['semantic_cases'], self.actual['actual_elf_processes']),
                         ('PASS', 90, 11))
        for field in ('original_rust_replay', 'production_scheduler_replaced',
                      'filesystem_callers_replaced', 'whole_runtime_replaced'):
            self.assertIs(self.actual[field], False)
        with self.snapshot() as (output, report):
            self.assertEqual(q.native_evidence(ROOT, output, report, completed_test_summary), self.actual)

    def test_02_actual_suite_command_and_deadline(self):
        mutations = {
            'missing-suite': None, 'duplicate-suite': None, 'nonzero-exit': ('exit_code', 1),
            'boolean-exit': ('exit_code', False), 'timed-out': ('timed_out', True),
            'deadline-changed': ('timeout_seconds', 181), 'deadline-float': ('timeout_seconds', 180.0),
            'wrong-command': ('command', ['/bin/true']), 'stdout-bytes': ('stdout_bytes', 0),
            'stderr-digest': ('stderr_sha256', '0' * 64), 'zero-elapsed': ('elapsed_seconds', 0),
            'over-deadline': ('elapsed_seconds', 180),
        }
        for label, mutation in mutations.items():
            with self.subTest(label=label):
                report = copy.deepcopy(self.report); row = self.check(report)
                if label == 'missing-suite':
                    report['checks'].remove(row)
                elif label == 'duplicate-suite':
                    report['checks'].append(copy.deepcopy(row))
                else:
                    row[mutation[0]] = mutation[1]
                self.refuses('process-' + label, lambda: q.completed_suite(ROOT, self.output, report,
                                                                          q.SUITE, completed_test_summary))

    def test_03_typed_json_and_owned_paths(self):
        for label, raw in (('duplicate-key', b'{"a":1,"a":1}'), ('nan', b'{"a":NaN}'),
                           ('infinity', b'{"a":Infinity}'), ('negative-infinity', b'{"a":-Infinity}')):
            self.refuses('json-' + label, lambda raw=raw: q.decode(raw))
        self.refuses('typed-bool-int', lambda: q.exact(False, 0, 'type mismatch'))
        self.refuses('typed-int-float', lambda: q.exact(1, 1.0, 'type mismatch'))
        self.refuses('typed-integer-bool', lambda: q.integer(True))
        self.refuses('path-parent', lambda: q.owned(self.output, '../outside'))
        self.refuses('path-absolute', lambda: q.owned(self.output, str(self.output / 'result.json')))
        with tempfile.TemporaryDirectory(prefix='publication-path-', dir=self.output.parent) as directory:
            root = Path(directory); (root / 'alias').symlink_to(self.output / 'result.json')
            self.refuses('path-symlink', lambda: q.owned(root, 'alias'))

    def test_04_real_artifact_binding(self):
        for label in ('missing-calls', 'symlink-calls', 'corrupt-calls', 'owner-image', 'actual-elf', 'manifest-path'):
            with self.subTest(label=label), self.snapshot() as (output, report):
                if label in ('missing-calls', 'symlink-calls', 'corrupt-calls'):
                    path = output / self.raw_name
                    if label == 'corrupt-calls':
                        raw = bytearray(path.read_bytes()); raw[-1] ^= 1; replace(path, raw)
                    else:
                        path.unlink()
                        if label == 'symlink-calls':
                            path.symlink_to(self.output / self.raw_name)
                elif label == 'manifest-path':
                    report['modules']['result_publication']['manifest'] = '../outside.json'
                else:
                    if label == 'actual-elf':
                        path = output / self.elf_relative
                    else:
                        owner = Path(self.entry['manifest']).parent.parent / self.bundle['owner_manifest']
                        meta = self.reader.object(owner.as_posix())
                        path = output / owner.parent / meta['image']
                    raw = bytearray(path.read_bytes()); raw[-1] ^= 1; replace(path, raw)
                self.refuses('artifact-' + label, lambda: q.native_evidence(ROOT, output, report, completed_test_summary))

    def test_05_native_trace_lifetimes_and_complete_semantic_bytes(self):
        for label, index, value in (('ordinal', 0, 2), ('unknown-session', 1, 0),
                                     ('output-profile', 3, MAX), ('unknown-return', 5, 0xffffffc0)):
            header = list(struct.unpack('<7Q', self.first_header)); header[index] = value
            changed = gzip.compress(struct.pack('<7Q', *header), mtime=0) + self.trace_tail
            self.refuses('trace-' + label, lambda changed=changed: self.direct({self.raw_name: changed}))
        for label in ('closed-before-call', 'created-after-call', 'relocation-session'):
            events = copy.deepcopy(self.events)
            if label == 'closed-before-call':
                next(row for row in events if row['kind'] == 'direct_arena_close')['after_native_call'] = 0
            elif label == 'created-after-call':
                next(row for row in events if row['kind'] == 'direct_arena_create')['after_native_call'] = 1
            else:
                next(row for row in events if row['kind'] == 'direct_driver_relocation')['session'] = 146
            self.refuses('trace-' + label, lambda events=events: self.direct(events=events))
        for label, relative, plain in (
            ('complete-input', q.FOLDER + '/semantic/0000.input.bin.gz',
             self.reader.plain(q.FOLDER + '/semantic/0000.input.bin.gz') + b'x'),
            ('complete-output', q.FOLDER + '/semantic/0000.native-output.bin.gz', b'x')):
            changes = {relative: gzip.compress(plain, mtime=0)}
            self.refuses('semantic-' + label, lambda changes=changes: self.direct(changes))
        rows = q.json_lines(self.reader.read(q.FOLDER + '/semantic-cases.jsonl'))
        rows[0]['output_bytes'] = 0.0
        changed = b''.join(encoded(row) for row in rows)
        self.refuses('semantic-typed-count', lambda: self.direct({q.FOLDER + '/semantic-cases.jsonl': changed}))
        for label, offset, value in (('invalid-create-boolean', 40, 2), ('unused-sequence', 24, 1)):
            wire = bytearray(self.first_request); struct.pack_into('<Q', wire, offset, value)
            state = dict(created=False, base=bytearray(), prefix=bytearray(), hints=[], output=bytearray(),
                         pending=b'', sequence=0, finished=False, dropped=False)
            self.refuses('semantic-' + label, lambda wire=wire, state=state: q._semantic_call(state, bytes(wire), self.first_response))

    def test_06_actual_kernel_receipts_and_pending_windows(self):
        raw = self.reader.plain(q.FOLDER + '/elf/original-case-0087.stderr.bin.gz')
        actual = q._receipts(raw, 8765544)
        self.assertGreater(actual['kernel_partial_writes'], 0)
        self.assertGreater(actual['kernel_eagain'], 0)
        changes = (
            ('initial-sequence', receipt(seq=9), 4, False),
            ('initial-offset', receipt(off=7), 4, False),
            ('advance-unacknowledged-window', receipt(result=1, after=1) + receipt(seq=2, wanted=3, result=3, after=4), 4, False),
            ('reuse-completed-window', receipt(wanted=1, result=1, after=1) + receipt(off=1, wanted=1, result=1, after=2), 2, False),
            ('advance-after-eagain', receipt(result=-11, after=0, ack=MAX) + receipt(seq=2), 4, False),
            ('change-window-extent', receipt(result=1, after=1) + receipt(off=1, wanted=2, result=2, after=3), 3, False),
            ('ack-after-eagain', receipt(result=-11, after=0), 0, False),
            ('missing-positive-ack', receipt(ack=MAX), 4, False),
            ('excessive-write', receipt(result=5, after=5), 5, False),
            ('false-confirmed-count', receipt(after=3), 4, False),
            ('trailing-receipt-byte', receipt() + b'x', 4, False),
            ('broken-pipe-positive-write', receipt(), 4, True),
        )
        for label, changed, size, broken in changes:
            self.refuses('kernel-' + label, lambda changed=changed, size=size, broken=broken:
                         q._receipts(changed, size, broken=broken))

    def test_07_actual_owner_resource_cancel_and_generation_controls(self):
        prefix = q.FOLDER + '/elf/' + q.OWNER_NAME
        frames = q._frames(self.reader.plain(prefix + '.input.bin.gz'))
        output = self.reader.plain(prefix + '.stdout.bin.gz')
        q._owner_trace(frames, output)
        for label, position, offset, value in (
            ('resource-input-not-retried', 2, 64, b'B'),
            ('retry-input-changed', 4, 64, b'B'),
            ('late-ack-new-generation', 13, 16, struct.pack('<Q', 2)),
            ('late-ack-wrong-offset', 11, 32, struct.pack('<Q', 0)),
        ):
            changed = list(frames); body = bytearray(changed[position]); body[offset:offset + len(value)] = value
            changed[position] = bytes(body)
            self.refuses('owner-' + label, lambda changed=changed: q._owner_trace(changed, output))
        records = []
        stream = io.BytesIO(output)
        while header := stream.read(16):
            code, size = struct.unpack('<QQ', header); records.append((code, stream.read(size)))
        for label in ('resource-code', 'resource-payload', 'cancel-confirmed', 'reused-generation'):
            changed = list(records)
            if label == 'resource-code':
                changed[2] = (q.CAPACITY, b'')
            elif label == 'resource-payload':
                changed[2] = (q.RESOURCE, b'x')
            else:
                index = 10 if label == 'cancel-confirmed' else 12
                code, body = changed[index]; body = bytearray(body)
                if label == 'cancel-confirmed':
                    struct.pack_into('<Q', body, 48, 0); struct.pack_into('<Q', body, 56, 2)
                else:
                    struct.pack_into('<Q', body, 16, 1)
                changed[index] = (code, bytes(body))
            raw = b''.join(struct.pack('<QQ', code, len(body)) + body for code, body in changed)
            self.refuses('owner-' + label, lambda raw=raw: q._owner_trace(frames, raw))

    def test_08_publisher_inputs_complete_output_and_metadata(self):
        prefix = q.FOLDER + '/elf/original-case-0003'
        frames = q._frames(self.reader.plain(prefix + '.input.bin.gz'))
        q._construction(frames, self.cases[3])
        changed = list(frames)
        position = next(i for i, wire in enumerate(changed) if q.request(wire)[0] == 2)
        body = bytearray(changed[position]); body[64] ^= 1; changed[position] = bytes(body)
        self.refuses('publisher-base-bytes', lambda: q._construction(changed, self.cases[3]))
        changed = list(frames)
        changed.pop(next(i for i, wire in enumerate(changed) if q.request(wire)[0] == 6))
        self.refuses('publisher-unsealed-hint', lambda: q._construction(changed, self.cases[3]))
        output = self.reader.plain(prefix + '.stdout.bin.gz')
        receipts = self.reader.plain(prefix + '.stderr.bin.gz')
        self.refuses('publisher-truncated-stdout', lambda: q._receipts(receipts, len(output) - 1))
        path = q.FOLDER + '/elf/original-case-0087.json'
        for label in ('typed-flags', 'wrong-command', 'boolean-exit'):
            meta = self.reader.object(path)
            if label == 'typed-flags':
                meta['after_flags'] = float(meta['after_flags'])
            elif label == 'wrong-command':
                meta['command'] = ['/bin/true']
            else:
                meta['returncode'] = False
            self.refuses('publisher-' + label, lambda meta=meta: self.processes({path: encoded(meta)}))
        for name in ('unfinished-utf8-seal', 'broken-pipe-0'):
            frames = q._frames(self.reader.plain(q.FOLDER + '/elf/' + name + '.input.bin.gz'))
            if name == 'unfinished-utf8-seal':
                changed = list(frames)
                body = bytearray(changed[1][:64]); struct.pack_into('<Q', body, 48, 1)
                changed[1] = bytes(body) + b'A'
            else:
                changed = [wire for wire in frames if q.request(wire)[0] != 2]
            self.refuses('failure-construction-' + name,
                         lambda changed=changed, name=name: q._failure_construction(name, changed))


def main():
    result = unittest.TextTestRunner(verbosity=2, stream=sys.stderr).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(EvidenceTests))
    reader_unchanged = (hasattr(EvidenceTests, 'reader_sha')
                        and sha(EvidenceTests.reader_source.read_bytes()) == EvidenceTests.reader_sha)
    test_unchanged = (hasattr(EvidenceTests, 'test_sha')
                      and sha(Path(__file__).read_bytes()) == EvidenceTests.test_sha)
    passed = (result.wasSuccessful() and result.testsRun == EXPECTED_GROUPS and not result.skipped
              and not result.expectedFailures and not result.unexpectedSuccesses
              and len(CONTROLS) == len(set(CONTROLS)) == EXPECTED_CONTROLS
              and reader_unchanged and test_unchanged)
    report = dict(schema='hepta.runtime.result-publication-evidence-tests.v1', status='PASS' if passed else 'FAIL',
                  test_groups=result.testsRun, expected_groups=EXPECTED_GROUPS, controls=len(CONTROLS),
                  expected_controls=EXPECTED_CONTROLS, control_names=sorted(CONTROLS),
                  skipped=len(result.skipped), errors=len(result.errors), failures=len(result.failures),
                  expected_failures=len(result.expectedFailures), unexpected_successes=len(result.unexpectedSuccesses),
                  native_cases_added_by_replay=0, actual_elf_processes_added=0,
                  test_sha256=getattr(EvidenceTests, 'test_sha', None),
                  reader_sha256=getattr(EvidenceTests, 'reader_sha', None),
                  test_unchanged_during_run=test_unchanged, reader_unchanged_during_run=reader_unchanged,
                  baseline_native_evidence_sha256=sha(encoded(EvidenceTests.actual)) if hasattr(EvidenceTests, 'actual') else None,
                  validation_kind='actual retained evidence and refusal controls; no new native execution')
    print(json.dumps(report, sort_keys=True))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())

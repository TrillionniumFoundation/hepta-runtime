"""Admit actual captures and refuse changed receipts; no new native execution."""
from __future__ import annotations
import base64
from contextlib import contextmanager
import copy
import gzip
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from hia_native_request_context_qualification import native_evidence
from qualify_hia_runtime_native import completed_test_summary

NAMES = ('test_request_context.py', 'test_response_hints.py', 'test_request_context_transport.py')
STORED = {
    NAMES[0]: 'request-context-rust-oracle/summary.json',
    NAMES[1]: 'response-hints-rust-oracle/native-corpus.json',
    NAMES[2]: 'request-context-transport/transport.json',
}
CONTROLS = []

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()

def replace(path, raw):
    # Every mutation is on a private snapshot link. Never overwrite its shared
    # inode: unlink the private name before creating the replacement bytes.
    path.unlink()
    path.write_bytes(raw)

class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.output = Path(os.environ['HIA_REQUEST_CONTEXT_QUALIFICATION_OUTPUT']).resolve(strict=True)
        cls.report = json.loads((cls.output / 'result.json').read_bytes())
        cls.actual = native_evidence(ROOT, cls.output, cls.report, completed_test_summary)
        cls.artifacts = cls.actual['artifact_sha256']
        if not cls.artifacts:
            raise ValueError('empty admitted capture inventory')

    @contextmanager
    def snapshot(self):
        # This test also runs inside the full qualifier. Only the reader's exact
        # closed inventory is linked; unrelated multi-hundred-MiB gates are not.
        with tempfile.TemporaryDirectory(prefix='request-context-evidence-', dir=self.output.parent) as directory:
            output = Path(directory) / 'capture'
            output.mkdir()
            for relative, expected in self.artifacts.items():
                source = self.output / relative
                self.assertEqual(sha(source.read_bytes()), expected)
                target = output / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                os.link(source, target)
            report = copy.deepcopy(self.report)
            (output / 'result.json').write_bytes(encoded(report))
            yield output, report

    def refuses(self, label, output, report, root=ROOT):
        with self.assertRaises((ValueError, KeyError, IndexError, AssertionError, OSError, EOFError, struct.error)):
            native_evidence(root, output, report, completed_test_summary)
        self.assertNotIn(label, CONTROLS)
        CONTROLS.append(label)

    def check(self, report, name=NAMES[0]):
        return next(row for row in report['checks'] if row['name'] == name)

    def summary(self, output, name=NAMES[0]):
        return json.loads((output / STORED[name]).read_bytes())

    def rewrite_summary(self, output, report, summary, name=NAMES[0]):
        raw = encoded(summary)
        replace(output / STORED[name], raw)
        replace(output / (name + '.stdout'), raw)
        self.check(report, name).update(summary=summary, stdout_sha256=sha(raw), stdout_bytes=len(raw))

    def rewrite_events(self, output, report, plain):
        raw = gzip.compress(plain, compresslevel=1, mtime=0)
        replace(output / 'request-context-rust-oracle/native-events.jsonl.gz', raw)
        summary = self.summary(output); summary['corpus_sha256'] = sha(raw)
        self.rewrite_summary(output, report, summary)

    def rewrite_response(self, output, report, filename, plain):
        raw = gzip.compress(plain, compresslevel=1, mtime=0)
        replace(output / 'response-hints-rust-oracle' / filename, raw)
        summary = self.summary(output, NAMES[1])
        summary['corpus'][filename] = {'bytes': len(raw), 'sha256': sha(raw),
                                      'raw_bytes': len(plain), 'raw_sha256': sha(plain)}
        self.rewrite_summary(output, report, summary, NAMES[1])

    def test_01_complete_actual_snapshot_is_not_execution(self):
        self.assertEqual(self.actual['status'], 'PASS')
        self.assertEqual(self.actual['native_cases_added_by_replay'], 0)
        for key in ('production_scheduler_qualified', 'unbounded_storage_qualified', 'production_call_sites_replaced'):
            self.assertIs(self.actual[key], False)
        with self.snapshot() as (output, report):
            accepted = native_evidence(ROOT, output, report, completed_test_summary)
            self.assertEqual(accepted, self.actual)

    def test_02_actual_process_receipts_are_required(self):
        for name in NAMES:
            with self.subTest(name=name), self.snapshot() as (output, report):
                report['checks'].remove(self.check(report, name))
                self.refuses('missing-' + name, output, report)
        changes = {
            'duplicate-suite': None, 'nonzero-exit': 7, 'boolean-exit': False,
            'timeout': True, 'changed-budget': 181, 'wrong-command': ['/bin/true'],
            'wrong-stdout-bytes': 0, 'wrong-stderr-bytes': 0, 'start-error': 'not started',
        }
        fields = {'nonzero-exit': 'exit_code', 'boolean-exit': 'exit_code', 'timeout': 'timed_out',
                  'changed-budget': 'timeout_seconds', 'wrong-command': 'command',
                  'wrong-stdout-bytes': 'stdout_bytes', 'wrong-stderr-bytes': 'stderr_bytes',
                  'start-error': 'start_error'}
        for label, value in changes.items():
            with self.subTest(label=label), self.snapshot() as (output, report):
                check = self.check(report)
                if label == 'duplicate-suite': report['checks'].append(copy.deepcopy(check))
                else: check[fields[label]] = value
                self.refuses(label, output, report)

    def test_03_summary_and_source_claims_cannot_replace_capture(self):
        changes = ('count', 'missing-group', 'skip', 'error', 'status', 'source', 'manifest',
                   'scheduler-claim', 'response-activation', 'transport-claim')
        for label in changes:
            with self.subTest(label=label), self.snapshot() as (output, report):
                name = NAMES[1] if label == 'response-activation' else NAMES[2] if label == 'transport-claim' else NAMES[0]
                summary = self.summary(output, name)
                if label == 'count': summary['counts']['semantic_rows'] -= 1
                elif label == 'missing-group': summary['tests_run'] -= 1
                elif label == 'skip': summary['skipped'] = 1
                elif label == 'error': summary['errors'] = 1
                elif label == 'status': summary['status'] = 'FAIL'
                elif label == 'source': summary['source_sha256'] = '0' * 64
                elif label == 'manifest': summary['manifest_sha256'] = '0' * 64
                elif label == 'scheduler-claim': summary['native_scheduler_qualified'] = True
                elif label == 'response-activation': summary['production_activated'] = True
                elif label == 'transport-claim': summary['whole_runtime_replaced'] = True
                self.rewrite_summary(output, report, summary, name)
                self.refuses('summary-' + label, output, report)

    def test_04_module_and_image_bytes_are_bound(self):
        for label in ('source-bytes', 'image-bytes', 'response-elf', 'compiler', 'module-manifest', 'owned-path'):
            with self.subTest(label=label), self.snapshot() as (output, report):
                entry = report['modules']['request_context']
                path = output / entry['manifest']; module = json.loads(path.read_bytes())
                if label in ('source-bytes', 'image-bytes'):
                    member = path.parent / module['source' if label == 'source-bytes' else 'image']
                    data = bytearray(member.read_bytes()); data[-1] ^= 1; replace(member, data)
                elif label == 'response-elf':
                    path = output / report['modules']['response_hints']['manifest']; module = json.loads(path.read_bytes())
                    member = path.parent / module['standalone']['path']
                    data = bytearray(member.read_bytes()); data[-1] ^= 1; replace(member, data)
                elif label == 'compiler': report['compiler_image_sha256'] = '0' * 64
                elif label == 'module-manifest':
                    module['compiler_commit'] = '0' * 40; replace(path, encoded(module))
                else: entry['manifest'] = '../outside-manifest.json'
                self.refuses('artifact-' + label, output, report)

    def test_05_context_events_remain_complete_and_ordered(self):
        changes = ('compressed-corruption', 'missing-newline', 'missing-row', 'duplicate-row',
                   'duplicate-json-field', 'unknown-session', 'unknown-classification',
                   'bad-input-base64', 'response-length', 'operation-mismatch')
        for label in changes:
            with self.subTest(label=label), self.snapshot() as (output, report):
                path = output / 'request-context-rust-oracle/native-events.jsonl.gz'
                if label == 'compressed-corruption':
                    data = bytearray(path.read_bytes()); data[-1] ^= 1; replace(path, data)
                else:
                    plain = gzip.decompress(path.read_bytes()); lines = plain.splitlines(keepends=True)
                    if label == 'missing-newline': plain = plain[:-1]
                    elif label == 'missing-row': plain = b''.join(lines[:-1])
                    elif label == 'duplicate-row': plain = lines[0] + plain
                    elif label == 'duplicate-json-field': plain = b'{"ordinal":1,' + lines[0][1:] + b''.join(lines[1:])
                    else:
                        row = json.loads(lines[0])
                        if label == 'unknown-session': row['session'] = 23
                        elif label == 'unknown-classification': row['classification'] = 'claimed-pass'
                        elif label == 'bad-input-base64': row['input_base64'] = '!!!'
                        elif label == 'operation-mismatch': row['operation'] = 8
                        else:
                            raw = bytearray(base64.b64decode(row['output_base64'])); raw[24:32] = struct.pack('<Q', 1)
                            row['output_base64'] = base64.b64encode(raw).decode(); row['output_sha256'] = sha(raw)
                        plain = encoded(row) + b''.join(lines[1:])
                    self.rewrite_events(output, report, plain)
                self.refuses('events-' + label, output, report)

    def test_06_rehashed_response_gzip_cannot_hide_truncation(self):
        for filename in ('input.bin.gz', 'native-output.bin.gz'):
            for label in ('last-byte', 'remove-row', 'oversize-frame'):
                with self.subTest(filename=filename, label=label), self.snapshot() as (output, report):
                    plain = gzip.decompress((output / 'response-hints-rust-oracle' / filename).read_bytes())
                    if label == 'last-byte': plain = plain[:-1]
                    elif label == 'remove-row':
                        first, second = struct.unpack_from('<QQ', plain)
                        plain = plain[16 + (second if filename == 'native-output.bin.gz' else first):]
                    else: plain = struct.pack('<QQ', (1 << 64) - 1, (1 << 64) - 1) + plain[16:]
                    self.rewrite_response(output, report, filename, plain)
                    self.refuses('response-' + filename + '-' + label, output, report)

    def test_07_actual_transport_streams_and_processes_are_required(self):
        for label in ('raw-stream', 'removed-frame', 'nonempty-stderr', 'missing-process',
                      'process-exit', 'request-count', 'wrong-native-command'):
            with self.subTest(label=label), self.snapshot() as (output, report):
                summary = self.summary(output, NAMES[2]); row = summary['processes']['nested']
                if label == 'raw-stream':
                    path = output / 'request-context-transport/nested.stdout'
                    replace(path, path.read_bytes() + b'x')
                elif label in ('removed-frame', 'nonempty-stderr'):
                    suffix = 'stdout' if label == 'removed-frame' else 'stderr'
                    path = output / ('request-context-transport/nested.' + suffix)
                    raw = b''.join(path.read_bytes().splitlines(keepends=True)[:-1]) if suffix == 'stdout' else b'error\n'
                    replace(path, raw); row['streams'][suffix] = {'bytes': len(raw), 'sha256': sha(raw)}
                    self.rewrite_summary(output, report, summary, NAMES[2])
                else:
                    if label == 'missing-process': del summary['processes']['nested']
                    elif label == 'process-exit': row['exit_code'] = 1
                    elif label == 'request-count': row['context_requests'] -= 1
                    else: row['command'] = ['/bin/true']
                    self.rewrite_summary(output, report, summary, NAMES[2])
                self.refuses('transport-' + label, output, report)

    def test_08_artifact_aliases_and_source_owner_bytes(self):
        for label in ('missing-corpus', 'symlink-corpus', 'source-owner-bytes', 'duplicate-summary-field'):
            with self.subTest(label=label), self.snapshot() as (output, report):
                if label in ('missing-corpus', 'symlink-corpus'):
                    path = output / 'request-context-rust-oracle/native-events.jsonl.gz'; path.unlink()
                    if label == 'symlink-corpus': path.symlink_to(self.output / 'request-context-rust-oracle/native-events.jsonl.gz')
                    self.refuses(label, output, report)
                elif label == 'duplicate-summary-field':
                    path = output / STORED[NAMES[0]]
                    raw = path.read_bytes(); replace(path, b'{"status":"PASS",' + raw.lstrip()[1:])
                    self.refuses(label, output, report)
                else:
                    source = output.parent / 'source'; source.mkdir()
                    for relative in ('native/request_context.hepta', 'native/response_hints.hepta',
                                     'native/composition_packer.hepta', 'tests/hia_native/view_cache_hex_transport.hepta',
                                     'tests/hia_native/test_request_context_transport.py'):
                        target = source / relative; target.parent.mkdir(parents=True, exist_ok=True)
                        os.link(ROOT / relative, target)
                    path = source / 'native/request_context.hepta'; replace(path, path.read_bytes() + b'\n')
                    self.refuses(label, output, report, source)

if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2, stream=sys.stderr).run(unittest.defaultTestLoader.loadTestsFromTestCase(EvidenceTests))
    expected_controls = 55
    passed = (result.wasSuccessful() and result.testsRun == 8 and not result.skipped
              and len(CONTROLS) == expected_controls and len(set(CONTROLS)) == expected_controls)
    print(json.dumps({'schema': 'hepta.runtime.request-context-evidence-tests.v1',
        'status': 'PASS' if passed else 'FAIL', 'test_groups': result.testsRun,
        'skipped': len(result.skipped), 'errors': len(result.errors), 'failures': len(result.failures),
        'expected_failures': len(result.expectedFailures), 'unexpected_successes': len(result.unexpectedSuccesses),
        'controls': len(CONTROLS), 'control_names': sorted(CONTROLS),
        'native_cases_added_by_replay': 0, 'test_sha256': sha(Path(__file__).read_bytes()),
        'validation_kind': 'actual retained evidence, no new native execution'}, sort_keys=True))
    raise SystemExit(0 if passed else 1)

"""Refuse incomplete captures and changed native artifacts without new execution."""
from __future__ import annotations
import copy
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = Path(os.environ.get('HIA_REFERENCE_RUNTIME', ROOT))
sys.path.insert(0, str(REFERENCE / 'scripts'))
sys.path.insert(0, str(ROOT / 'scripts'))
from hia_native_build import json_bytes
from hia_native_history_qualification import FOLDER, native_evidence
from qualify_hia_runtime_native import completed_test_summary

CONTROLS = 0


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def replace(path, raw):
    path.unlink()
    path.write_bytes(raw)


def write_json(path, value):
    replace(path, json_bytes(value))


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.output = Path(os.environ['HIA_HISTORY_QUALIFICATION_OUTPUT'])
        cls.report = json.loads((cls.output / 'result.json').read_bytes())
        cls.actual = native_evidence(ROOT, cls.output, cls.report, completed_test_summary,
                                    reference_root=REFERENCE)

    def snapshot(self):
        temporary = tempfile.TemporaryDirectory(prefix='history-evidence-', dir=self.output.parent)
        output = Path(temporary.name) / 'capture'
        self.addCleanup(temporary.cleanup)
        output.mkdir()
        # Every admitted byte is copied; unrelated live fixtures are not traversed.
        files = {**self.actual['artifact_sha256'], **self.actual['corpus_sha256'],
                 'test_history.py.stdout': self.actual['test_stdout_sha256'],
                 'test_history.py.stderr': self.actual['test_stderr_sha256']}
        for relative, digest in sorted(files.items()):
            path = Path(relative)
            self.assertFalse(path.is_absolute() or '..' in path.parts)
            source = self.output / path
            self.assertEqual(source.resolve(strict=True), source.absolute())
            self.assertEqual(sha(source.read_bytes()), digest)
            target = output / path
            target.parent.mkdir(parents=True, exist_ok=True)
            os.link(source, target)
        self.assertEqual({str(path.relative_to(output)) for path in output.rglob('*')
                          if path.is_file()}, set(files))
        return output, copy.deepcopy(self.report)

    def refuses(self, output, report, root=ROOT):
        global CONTROLS
        with self.assertRaises((ValueError, KeyError, IndexError, AssertionError)):
            native_evidence(root, output, report, completed_test_summary, reference_root=REFERENCE)
        CONTROLS += 1

    def rewrite_capture(self, output, report, metadata):
        write_json(output / FOLDER / 'native-corpus.json', metadata)
        raw = (json.dumps(metadata['report'], sort_keys=True) + '\n').encode()
        replace(output / 'test_history.py.stdout', raw)
        check = next(c for c in report['checks'] if c['name'] == 'test_history.py')
        check.update(summary=metadata['report'], stdout_sha256=sha(raw), stdout_bytes=len(raw))

    def refresh_bundle(self, output, report, path, bundle):
        raw = json_bytes(bundle)
        replace(path, raw)
        changed = path.parent.with_name(sha(raw))
        path.parent.rename(changed)
        report['modules']['history'].update(manifest=str((changed / path.name).relative_to(output)),
                                            sha256=sha(raw))
        metadata = json.loads((output / FOLDER / 'native-corpus.json').read_bytes())
        metadata['report']['bundle_sha256'] = sha(raw)
        self.rewrite_capture(output, report, metadata)

    def test_01_complete_actual_capture_is_not_new_execution(self):
        self.assertEqual(self.actual['status'], 'PASS')
        self.assertEqual(self.actual['captured_native_cases'], 6198)
        self.assertEqual(self.actual['native_cases_added_by_replay'], 0)
        self.assertFalse(self.actual['shared_concurrency_qualified'])
        self.assertFalse(self.actual['filesystem_effects_qualified'])
        output, report = self.snapshot()
        self.assertEqual(native_evidence(ROOT, output, report, completed_test_summary,
                                         reference_root=REFERENCE), self.actual)

    def test_02_incomplete_actual_invocations_refuse(self):
        for change in ('missing', 'exit', 'timeout', 'count', 'source-claim'):
            with self.subTest(change=change):
                output, report = self.snapshot()
                check = next(c for c in report['checks'] if c['name'] == 'test_history.py')
                if change == 'missing':
                    report['checks'].remove(check)
                elif change == 'exit':
                    check['exit_code'] = 1
                elif change == 'timeout':
                    check['timed_out'] = True
                else:
                    metadata = json.loads((output / FOLDER / 'native-corpus.json').read_bytes())
                    if change == 'count':
                        metadata['report']['counts']['original_owner_rows'] -= 1
                    else:
                        metadata['report']['source_pins_unchanged'] = False
                    self.rewrite_capture(output, report, metadata)
                self.refuses(output, report)

    def test_03_consistently_rehashed_truncated_streams_refuse(self):
        for name in ('input.bin.gz', 'native-output.bin.gz', 'rows.jsonl.gz'):
            with self.subTest(name=name):
                output, report = self.snapshot()
                path = output / FOLDER / name
                replacement = path.with_suffix('.new')
                size, digest, trailing = 0, hashlib.sha256(), b''
                with gzip.open(path, 'rb') as source, replacement.open('xb') as target:
                    with gzip.GzipFile(fileobj=target, mode='wb', compresslevel=1, mtime=0) as dest:
                        while chunk := source.read(1 << 20):
                            combined = trailing + chunk
                            body, trailing = combined[:-1], combined[-1:]
                            dest.write(body)
                            digest.update(body)
                            size += len(body)
                path.unlink()
                replacement.rename(path)
                metadata = json.loads((output / FOLDER / 'native-corpus.json').read_bytes())
                metadata['streams'][name] = {'gzip_bytes': path.stat().st_size,
                    'gzip_sha256': sha(path.read_bytes()), 'raw_bytes': size, 'raw_sha256': digest.hexdigest()}
                self.rewrite_capture(output, report, metadata)
                self.refuses(output, report)

    def test_04_artifact_and_static_capture_mutations_refuse(self):
        changes = ('image', 'receipt', 'wide-profile', 'elf-prefix', 'elf-table',
                   'elf-observation', 'source-proof', 'oracle-source')
        for change in changes:
            with self.subTest(change=change):
                output, report = self.snapshot()
                bundle_path = output / report['modules']['history']['manifest']
                bundle = json.loads(bundle_path.read_bytes())
                module_path = output / 'build' / bundle['module']
                module = json.loads(module_path.read_bytes())
                if change in ('image', 'wide-profile'):
                    if change == 'image':
                        path = module_path.parent / module['image']
                        data = bytearray(path.read_bytes()); data[-1] ^= 1
                        replace(path, data)
                        module['image_sha256'] = sha(data)
                        bundle['image_sha256'] = sha(data)
                    else:
                        module['workspace_capacity'] -= 1
                    write_json(module_path, module)
                    bundle['module_sha256'] = sha(module_path.read_bytes())
                    self.refresh_bundle(output, report, bundle_path, bundle)
                elif change == 'receipt':
                    path = module_path.parent / 'module.receipt.json'
                    receipt = json.loads(path.read_bytes()); receipt['produced_sha256'] = '0' * 64
                    write_json(path, receipt)
                elif change in ('elf-prefix', 'elf-table'):
                    path = output / 'build' / bundle['fixture']
                    fixture = json.loads(path.read_bytes())
                    elf = path.parent / fixture['executable']
                    raw = bytearray(elf.read_bytes())
                    raw[300 if change == 'elf-prefix' else 8752 + 64 + 48] ^= 1
                    replace(elf, raw)
                    fixture['executable_sha256'] = sha(raw)
                    fixture['inspection']['sha256'] = sha(raw)
                    write_json(path, fixture)
                    bundle['fixture_sha256'] = sha(path.read_bytes())
                    self.refresh_bundle(output, report, bundle_path, bundle)
                elif change == 'elf-observation':
                    metadata = json.loads((output / FOLDER / 'native-corpus.json').read_bytes())
                    metadata['report']['elf_observations'][0]['stdout_hex'] += '00'
                    self.rewrite_capture(output, report, metadata)
                else:
                    source = output.parent / 'owner'
                    source.mkdir()
                    name = 'native/history_composition.json' if change == 'source-proof' else 'tests/hia_native/oracle_history.rs'
                    # Point the complete copied source tree at altered bytes; no shared file is edited.
                    shutil.copytree(ROOT / 'scripts', source / 'scripts', copy_function=os.link)
                    shutil.copytree(ROOT / 'native', source / 'native', copy_function=os.link)
                    shutil.copytree(ROOT / 'tests', source / 'tests', copy_function=os.link)
                    path = source / name
                    replace(path, path.read_bytes() + b'\n')
                    check = next(c for c in report['checks'] if c['name'] == 'test_history.py')
                    check['command'][-1] = str(source / 'tests/hia_native/test_history.py')
                    self.refuses(output, report, source)
                    continue
                self.refuses(output, report)


if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2, stream=sys.stderr).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(EvidenceTests))
    passed = result.wasSuccessful() and not result.skipped and result.testsRun == 4 and CONTROLS == 16
    print(json.dumps({'schema': 'hepta.runtime.history-evidence-tests.v1',
        'status': 'PASS' if passed else 'FAIL', 'test_groups': result.testsRun,
        'refusal_controls': CONTROLS, 'native_calls_added': 0,
        'test_sha256': sha(Path(__file__).read_bytes())}, sort_keys=True))
    raise SystemExit(0 if passed else 1)

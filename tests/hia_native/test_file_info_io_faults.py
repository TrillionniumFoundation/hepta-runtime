#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Actual static ELF file-info effects under owned-child syscall fault controls."""
from __future__ import annotations
import hashlib, json, os, subprocess, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(os.environ.get('HIA_RUNTIME_REPO', Path(__file__).resolve().parents[2]))
sys.path.insert(0, os.environ.get('HIA_INFO_SERVICE_TEST_DIR', str(ROOT / 'tests/hia_native')))
import test_local_service as shared

COUNTS = dict(actual_info_requests=0, syscall_faults=0, fixture_races=0, original_success_comparisons=0)


class Session(shared.Session):
    def __init__(self, executable, root, fixture, mode, log):
        command = [sys.executable, str(Path(__file__).with_name('info_fault_supervisor.py')),
                   '--log', str(log), '--fixture', str(fixture), '--mode', mode, '--',
                   str(executable), '--local-read-profile', str(root)]
        env = dict(os.environ, PATH='')
        self.proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, env=env, start_new_session=True)
        self.buffer = b''

    def abort(self):
        # The wrapper, service and inspection worker are all owned by this
        # qualification process group, including when an assertion fails.
        try:
            os.killpg(self.proc.pid, 9)
        except ProcessLookupError:
            pass
        self.proc.wait(timeout=10)
        for stream in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
            stream.close()

    def __exit__(self, kind, *rest):
        if kind:
            self.abort()
        else:
            try:
                self.close()
            except BaseException:
                self.abort()
                raise


class FileInfoFaultTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        shared.NativeServiceTests.setUpClass()
        cls.manifest = shared.NativeServiceTests.manifest
        cls.metadata = shared.NativeServiceTests.metadata
        cls.executable = shared.NativeServiceTests.executable
        cls.original = shared.NativeServiceTests.original
        assert len(cls.metadata['members']) == 7

    def run_case(self, mode, expected=None):
        with tempfile.TemporaryDirectory(prefix='hia-info-effect-') as directory:
            root = Path(directory)
            parent = root / 'inner'
            parent.mkdir()
            path = parent / 'value'
            path.write_bytes(b'owned native metadata fixture' * 5000)
            os.chmod(path, 0o640)
            os.setxattr(path, 'user.fixture', b'private xattr value')
            old = self.original.main(dict(op='info', root=str(root), path=str(path)))
            log = root / 'effects.json'
            with Session(self.executable, root, path, mode, log) as service:
                service.ready()
                failed, text = service.tool('file_info', {'host': 'native-local', 'path': str(path)})
                COUNTS['actual_info_requests'] += 1
                if expected is not None:
                    self.assertTrue(failed, mode)
                    self.assertEqual(text, expected)
                    self.assertNotIn('sha256', text)
                    self.assertNotIn('private xattr value', text)
                else:
                    self.assertFalse(failed, text)
                    actual = json.loads(text)
                    if mode == 'capture_gap':
                        self.assertEqual(actual['mode'], 0o640)
                        self.assertEqual(actual['metadata']['mode'], 0o2751)
                        self.assertEqual(actual['version'], old['version'])
                        self.assertEqual(actual['sha256'], old['sha256'])
                    else:
                        self.assertEqual(actual, old)
                        self.assertEqual(text, json.dumps(old, ensure_ascii=False, sort_keys=True,
                                                         separators=(',', ':')))
                        COUNTS['original_success_comparisons'] += 1
                self.assertEqual(service.call(shared.req('ping', identity=99))['result'], {})
            events = json.loads(log.read_bytes())
            changes = [event for event in events if event['mode'] != 'continue']
            self.assertTrue(changes, mode)
            COUNTS['syscall_faults'] += sum(event['mode'].startswith('injected_') for event in changes)
            COUNTS['fixture_races'] += sum(not event['mode'].startswith('injected_') for event in changes)
            return events

    def test_kernel_read_eintr_is_retried(self):
        events = self.run_case('eintr')
        reads = [event for event in events if 'file_read' in event]
        self.assertEqual(reads[0]['mode'], 'injected_eintr')
        self.assertGreaterEqual(len(reads), 3)
        self.assertTrue(all(event['count'] == 1 << 20 for event in reads))

    def test_kernel_version_races_have_no_partial_result(self):
        self.run_case('hash_change', 'file changed while hashing')
        self.run_case('metadata_replace', 'file changed during metadata inspection')
        self.run_case('metadata_symlink', 'native local open failed (errno 40)')
        self.run_case('capture_change', 'source metadata changed during capture')

    def test_capture_interval_and_retained_parent_are_separate(self):
        self.run_case('capture_gap')
        self.run_case('parent_rebind')

    def test_xattr_and_finalizer_errors_preserve_native_diagnostics(self):
        self.run_case('getxattr_error', 'native local extended attribute inspection failed (errno 5)')
        self.run_case('flistxattr_error', 'native local extended attribute inspection failed (errno 5)')
        events = self.run_case('close_precedence', 'native local close failed (errno 9)')
        self.assertEqual([event['error'] for event in events if event['mode'] == 'injected_finalizer_error'], [13, 9])


if __name__ == '__main__':
    outcome = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(FileInfoFaultTests))
    if not outcome.wasSuccessful():
        raise SystemExit(1)
    proof = dict(schema='hepta.runtime.native-info-io-fault-test.v1', status='pass', counts=COUNTS,
                 actual_elf_responses=shared.COUNTS['elf_requests'],
                 executable_sha256=FileInfoFaultTests.metadata['executable_sha256'],
                 manifest_sha256=hashlib.sha256(FileInfoFaultTests.manifest.read_bytes()).hexdigest(),
                 production_semantic_fallback=False,
                 original_helper_sha256=shared.ORIGINAL_SHA)
    if os.environ.get('HIA_INFO_IO_FAULT_RESULT'):
        Path(os.environ['HIA_INFO_IO_FAULT_RESULT']).write_text(json.dumps(proof, sort_keys=True, indent=2) + '\n')
    print(json.dumps(proof, sort_keys=True))

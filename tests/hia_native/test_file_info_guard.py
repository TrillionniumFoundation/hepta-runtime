#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Real seven-image, fixed-30-second cancellation and parent-custody tests.

The selected native worker syscall is held by Linux seccomp notification. This
test is distinct from both synthetic HIA acknowledgements and the separately
qualified native empty-pipe blocking-read probe. No result is supplied by the
supervisor; all MCP responses come from the actual static ELF.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(os.environ.get('HIA_RUNTIME_REPO', Path(__file__).resolve().parents[2]))
sys.path.insert(0, os.environ.get('HIA_INFO_SERVICE_TEST_DIR', str(ROOT / 'tests/hia_native')))
import test_local_service as shared
sys.path.insert(0, str(Path(__file__).parent))
from info_guard_supervisor import process_identity

METADATA_SHA = '24b9df89816536db16dd35a74d6460b1a215981a00798393a00853da6077f5d3'
SOURCE_PATHS = {'test_file_info_guard.py': Path(__file__),
                'info_guard_supervisor.py': Path(__file__).with_name('info_guard_supervisor.py'),
                'test_local_service.py': Path(shared.__file__),
                'io_fault_supervisor.py': ROOT / 'tests/hia_native/io_fault_supervisor.py'}
SOURCE_SHA = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in SOURCE_PATHS.items()}
COUNTS = {'deadline_requests': 0, 'kernel_notification_holds': 0, 'worker_cancellations': 0,
          'worker_reap_controls': 0, 'root_rebind_controls': 0,
          'original_info_comparisons': 0, 'original_read_comparisons': 0,
          'setup_failure_controls': 0, 'setup_recovery_controls': 0,
          'parent_resource_controls': 0, 'closed_stderr_controls': 0, 'root_fd2_controls': 0}
TIMINGS = []


class Session(shared.Session):
    def __init__(self, executable, root, fixture, mode, log, marker):
        command = [sys.executable, '-I', '-B', str(Path(__file__).with_name('info_guard_supervisor.py')),
                   '--log', str(log), '--held-state', str(marker), '--fixture', str(fixture),
                   '--mode', mode, '--', str(executable), '--local-read-profile', str(root)]
        self.proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, env=dict(os.environ, PATH='', LANG='C'),
                                     start_new_session=True)
        self.buffer = b''

    def receive(self):
        deadline = time.monotonic() + 38
        while b'\n' not in self.buffer:
            left = deadline - time.monotonic()
            if left <= 0 or not select.select([self.proc.stdout], [], [], left)[0]:
                raise AssertionError('fixed native deadline did not produce a bounded response')
            part = os.read(self.proc.stdout.fileno(), 65536)
            if not part:
                raise AssertionError(('early guard-service exit', self.proc.poll(), self.proc.stderr.read()))
            self.buffer += part
        line, self.buffer = self.buffer.split(b'\n', 1)
        shared.COUNTS['elf_requests'] += 1
        return json.loads(line)

    def abort(self):
        try:
            os.killpg(self.proc.pid, signal.SIGKILL)
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


class FileInfoGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        assert hashlib.sha256((ROOT / 'src/mcp/runtime/file_metadata.py').read_bytes()).hexdigest() == METADATA_SHA
        shared.NativeServiceTests.setUpClass()
        cls.manifest = shared.NativeServiceTests.manifest
        cls.metadata = shared.NativeServiceTests.metadata
        cls.executable = shared.NativeServiceTests.executable
        cls.original = shared.NativeServiceTests.original
        assert len(cls.metadata['members']) == 7
        profile = cls.metadata['profile'][3]
        assert (profile['flags'], profile['call_mask'], profile['workspace_capacity']) == (3, 4, 8 << 20)
        module = cls.manifest.parent / cls.metadata['members'][3]['manifest']
        cls.io_manifest_sha = hashlib.sha256(module.read_bytes()).hexdigest()
        cls.io_source_sha = json.loads(module.read_bytes())['source_sha256']
        source = Path(os.environ.get('HIA_INFO_IO_SOURCE', ROOT / 'native/io_policy.hepta'))
        assert hashlib.sha256(source.read_bytes()).hexdigest() == cls.io_source_sha

    @classmethod
    def tearDownClass(cls):
        assert hashlib.sha256(cls.executable.read_bytes()).hexdigest() == cls.metadata['executable_sha256']
        assert hashlib.sha256((ROOT / 'src/mcp/runtime/binary_file.py').read_bytes()).hexdigest() == shared.ORIGINAL_SHA
        assert hashlib.sha256((ROOT / 'src/mcp/runtime/file_metadata.py').read_bytes()).hexdigest() == METADATA_SHA

    def resources(self, pid):
        proc = Path(f'/proc/{pid}')
        shared_bytes = 0
        for line in (proc / 'maps').read_text().splitlines():
            fields = line.split()
            if fields[1][-1] == 's':
                first, last = (int(value, 16) for value in fields[0].split('-'))
                shared_bytes += last - first
        return len(tuple((proc / 'fd').iterdir())), shared_bytes

    def compare_info(self, service, path, expected):
        failed, text = service.tool('file_info', {'host': 'native-local', 'path': str(path)})
        self.assertFalse(failed, text)
        self.assertEqual(json.loads(text), expected)
        self.assertEqual(text, json.dumps(expected, ensure_ascii=False, sort_keys=True, separators=(',', ':')))
        COUNTS['original_info_comparisons'] += 1

    def wait_cancelled(self, marker, *, reaped):
        limit = time.monotonic() + 1
        while True:
            state = process_identity(marker['worker'])
            gone = state is None or state['start_ticks'] != marker['worker_start_ticks']
            if gone or (not reaped and state['state'] in ('Z', 'X')):
                return
            if time.monotonic() >= limit:
                self.fail(('owned native worker was not reaped' if reaped else
                           'owned native worker still executes after timeout', state))
            time.sleep(.01)

    def run_case(self, mode):
        with tempfile.TemporaryDirectory(prefix='hia-info-guard-') as directory:
            owned = Path(directory)
            root = owned / 'capability'
            root.mkdir()
            path = root / 'value'
            unit = b'owned private guarded metadata bytes\x00\xff'
            path.write_bytes((unit * (((1 << 20) + 257) // len(unit) + 1))[:(1 << 20) + 257])
            os.chmod(path, 0o640)
            os.setxattr(path, 'user.first', b'private retained attribute')
            os.setxattr(path, 'user.last', bytes(range(256)))
            expected_info = self.original.main({'op': 'info', 'root': str(root), 'path': str(path)})
            expected_read = self.original.main({'op': 'read', 'root': str(root), 'path': str(path),
                                                'offset': 0, 'limit': 64})
            log, marker_path = owned / 'guard-events.json', owned / 'held-state.json'
            with Session(self.executable, root, path, mode, log, marker_path) as service:
                service.ready()
                started = time.monotonic()
                failed, text = service.tool('file_info', {'host': 'native-local', 'path': str(path)})
                finished = time.monotonic()
                elapsed = finished - started
                COUNTS['deadline_requests'] += 1
                self.assertTrue(failed)
                self.assertEqual(text, 'native local file inspection deadline exceeded')
                self.assertGreaterEqual(elapsed, 29.5)
                self.assertLess(elapsed, 33)
                self.assertNotIn('sha256', text)
                self.assertNotIn('private retained attribute', text)
                marker = json.loads(marker_path.read_bytes())
                self.assertEqual(marker['syscall'], {'read': 0, 'flistxattr': 196}[mode])
                self.assertNotEqual(marker['worker'], marker['service'])
                self.assertIs(marker['root_rebound'], True)
                self.assertEqual(path.read_bytes(), b'replacement root must never become authorized')
                self.wait_cancelled(marker, reaped=False)
                COUNTS['worker_cancellations'] += 1
                self.assertEqual(service.call(shared.req('ping', identity=90))['result'], {})
                failed, text = service.tool('binary_read', {'host': 'native-local', 'path': str(path),
                                                           'offset': 0, 'limit': 64})
                self.assertFalse(failed, text)
                self.assertEqual(json.loads(text), expected_read)
                self.assertEqual(text, json.dumps(expected_read, ensure_ascii=False, sort_keys=True,
                                                 separators=(',', ':')))
                COUNTS['original_read_comparisons'] += 1
                failed, text = service.tool('file_info', {'host': 'native-local', 'path': str(path)})
                self.assertFalse(failed, text)
                self.assertEqual(json.loads(text), expected_info)
                self.assertEqual(text, json.dumps(expected_info, ensure_ascii=False, sort_keys=True,
                                                 separators=(',', ':')))
                COUNTS['original_info_comparisons'] += 1
                self.wait_cancelled(marker, reaped=True)
                COUNTS['worker_reap_controls'] += 1
                COUNTS['root_rebind_controls'] += 1
                TIMINGS.append({'mode': mode, 'fixed_deadline_seconds': 30, 'elapsed_seconds': elapsed,
                                'hold_seconds_until_response': finished - marker['held_at_monotonic']})
            events = json.loads(log.read_bytes())
            self.assertEqual(events['service_exit'], 0)
            self.assertIs(events['held_once'], True)
            holds = [event for event in events['events'] if event['event'] == 'held_worker_syscall']
            cancelled = [event for event in events['events'] if event['event'] == 'held_notification_cancelled']
            self.assertEqual(len(holds), 1)
            self.assertEqual(len(cancelled), 1)
            self.assertEqual(cancelled[0]['worker'], marker['worker'])
            reads = [event for event in events['events'] if event['event'] == 'file_read']
            self.assertTrue(reads)
            self.assertTrue(all(event['capacity'] == 1 << 20 for event in reads))
            self.assertTrue(all(event['owner'] != marker['service'] for event in reads))
            COUNTS['kernel_notification_holds'] += 1

    def test_read_deadline_discards_advanced_sha_and_preserves_parent_root(self):
        self.run_case('read')

    def test_metadata_deadline_discards_completed_fingerprint_and_recovers(self):
        self.run_case('flistxattr')

    def test_guard_setup_errors_preserve_parent_resources_and_recover(self):
        cases = {'map_failure': (9, 12), 'pipe_failure': (293, 24), 'fork_failure': (57, 11),
                 'clock_failure': (228, 5), 'pdeath_failure': (157, 5)}
        for mode, (number, returned_errno) in cases.items():
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix='hia-info-setup-') as directory:
                root = Path(directory)
                path = root / 'value'
                path.write_bytes(b'owned setup-failure recovery fixture')
                expected = self.original.main({'op': 'info', 'root': str(root), 'path': str(path)})
                log, marker_path = root / 'events.json', root / 'marker.json'
                with Session(self.executable, root, path, mode, log, marker_path) as service:
                    service.ready()
                    initial = json.loads(marker_path.read_bytes())
                    resources = self.resources(initial['service'])
                    started = time.monotonic()
                    failed, text = service.tool('file_info', {'host': 'native-local', 'path': str(path)})
                    self.assertLess(time.monotonic() - started, 5)
                    self.assertTrue(failed)
                    self.assertEqual(text, f'native local deadline setup failed (errno {returned_errno})')
                    marker = json.loads(marker_path.read_bytes())
                    self.assertEqual(marker['syscall'], number)
                    if mode == 'pdeath_failure':
                        self.wait_cancelled(marker, reaped=False)
                    self.assertEqual(self.resources(initial['service']), resources)
                    COUNTS['parent_resource_controls'] += 1
                    self.assertEqual(service.call(shared.req('ping', identity=91))['result'], {})
                    self.compare_info(service, path, expected)
                    self.assertEqual(self.resources(initial['service']), resources)
                    COUNTS['parent_resource_controls'] += 1
                    if mode == 'pdeath_failure':
                        self.wait_cancelled(marker, reaped=True)
                    COUNTS['setup_failure_controls'] += 1
                    COUNTS['setup_recovery_controls'] += 1
                observed = json.loads(log.read_bytes())
                self.assertEqual(observed['service_exit'], 0)
                self.assertIs(observed['fault_injected'], True)
                self.assertIs(observed['held_once'], False)
                faults = [row for row in observed['events'] if row['event'] == 'guard_setup_fault']
                self.assertEqual(len(faults), 1)
                self.assertEqual(faults[0]['syscall'], number)

    def test_closed_stderr_keeps_the_administrator_root_in_fd2(self):
        with tempfile.TemporaryDirectory(prefix='hia-info-stderr-') as directory:
            owned = Path(directory)
            # The retained descriptor alternates between 2 and 3 while the
            # startup walker closes each previous directory. Even path depth
            # makes fd2 custody explicit instead of merely closing stderr.
            root = owned
            if (len(root.parts) - 1) % 2:
                root = root / 'even-depth'
                root.mkdir()
            path = root / 'value'
            path.write_bytes(b'root descriptor two remains administrator owned')
            expected = self.original.main({'op': 'info', 'root': str(root), 'path': str(path)})
            log, marker_path = owned / 'events.json', owned / 'marker.json'
            with Session(self.executable, root, path, 'closed_stderr', log, marker_path) as service:
                service.ready()
                marker = json.loads(marker_path.read_bytes())
                self.assertIs(marker['stderr_closed'], True)
                resources = self.resources(marker['service'])
                original = root.stat()
                for index in range(3):
                    retained = os.stat(f'/proc/{marker["service"]}/fd/2')
                    self.assertEqual((retained.st_dev, retained.st_ino), (original.st_dev, original.st_ino))
                    COUNTS['root_fd2_controls'] += 1
                    if index != 2:
                        self.compare_info(service, path, expected)
                        self.assertEqual(self.resources(marker['service']), resources)
                        COUNTS['parent_resource_controls'] += 1
                self.assertEqual(service.call(shared.req('ping', identity=92))['result'], {})
                COUNTS['closed_stderr_controls'] += 1
            observed = json.loads(log.read_bytes())
            self.assertEqual(observed['service_exit'], 0)
            self.assertIs(observed['held_once'], False)
            self.assertIs(observed['fault_injected'], False)


if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(FileInfoGuardTests))
    if not result.wasSuccessful():
        raise SystemExit(1)
    assert {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in SOURCE_PATHS.items()} == SOURCE_SHA
    proof = {'schema': 'hepta.runtime.native-info-guard-test.v1', 'status': 'pass', 'counts': COUNTS,
             'actual_elf_responses': shared.COUNTS['elf_requests'], 'timings': TIMINGS,
             'executable_sha256': FileInfoGuardTests.metadata['executable_sha256'],
             'manifest_sha256': hashlib.sha256(FileInfoGuardTests.manifest.read_bytes()).hexdigest(),
             'io_manifest_sha256': FileInfoGuardTests.io_manifest_sha,
             'io_source_sha256': FileInfoGuardTests.io_source_sha,
             'original_helper_sha256': shared.ORIGINAL_SHA,
             'original_metadata_source_sha256': METADATA_SHA,
             'test_sources_sha256': SOURCE_SHA,
             'hold_kind': 'actual worker syscall held by kernel notification',
             'synthetic_hia_acknowledgements': False,
             'empty_pipe_kernel_block_probe_included': False,
             'production_semantic_fallback': False}
    if os.environ.get('HIA_INFO_GUARD_RESULT'):
        Path(os.environ['HIA_INFO_GUARD_RESULT']).write_text(json.dumps(proof, sort_keys=True, indent=2) + '\n')
    print(json.dumps(proof, sort_keys=True))

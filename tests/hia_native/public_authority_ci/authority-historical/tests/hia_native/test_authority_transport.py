"""Actual nine-image authority ELF and fixed startup OS boundary qualification."""
from pathlib import Path
import gzip
import hashlib
import json
import os
import select
import struct
import subprocess
import sys
import tempfile
import time
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
from authority_native_harness import frame, response

TOKEN = b'X' * 32
GOOD = [(b'x-hepta-runtime-token', TOKEN)]
COUNTS = {'processes': 0, 'frames_sent': 0, 'responses': 0, 'original_wire_comparisons': 0,
          'known_private_binding_comparisons': 0, 'kernel_supervised_processes': 0,
          'kernel_fault_processes': 0, 'new_original_rust_calls': 0}
CASES = []


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class AuthorityTransport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = Path(os.environ['HIA_AUTHORITY_ELF_MANIFEST'])
        cls.metadata = json.loads(cls.manifest.read_bytes())
        cls.exe = cls.manifest.parent / cls.metadata['executable']
        cls.exe_hash = sha(cls.exe.read_bytes())
        assert cls.exe_hash == cls.metadata['executable_sha256']
        assert cls.metadata['compiler_commit'] == 'd3e2c90173cf733e42b299d0c4274df4b593a12f'
        assert len(cls.metadata['members']) == 9
        profile = json.loads((ROOT / 'native/authority_profile.json').read_bytes())
        for index, row in enumerate(profile['members']):
            assert sha((ROOT / row['source']).read_bytes()) == row['source_sha256']
            assert cls.metadata['members'][index]['source_sha256'] == row['source_sha256']
            assert cls.metadata['members'][index]['image_sha256'] == row['image_sha256']
        raw = (HERE / 'authority_wire_vectors.json.gz').read_bytes()
        assert sha(raw) == '98e5da67f5b463bc57a0706f6f3c06fe49254603d8ecd455dfb0c8c259551e38'
        cls.vectors = json.loads(gzip.decompress(raw))
        cls.binding = cls.vectors['credential_binding_vector']
        cls.temp = tempfile.TemporaryDirectory(prefix='hia-authority-elf-')
        cls.folder = Path(cls.temp.name)
        cls.corpus = Path(os.environ['HIA_AUTHORITY_TRANSPORT_CORPUS_DIR']) if 'HIA_AUTHORITY_TRANSPORT_CORPUS_DIR' in os.environ else None
        if cls.corpus:
            cls.corpus.mkdir(parents=True, exist_ok=False)

    @classmethod
    def tearDownClass(cls):
        assert sha(cls.exe.read_bytes()) == cls.exe_hash
        cls.temp.cleanup()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='case-', dir=self.folder)
        self.root = Path(self.temporary.name)
        self.token = self.root / 'credential'
        self.token.write_bytes(TOKEN + b'\n')
        self.token.chmod(0o600)

    def tearDown(self):
        self.temporary.cleanup()

    def arguments(self, mode=2, path=None):
        return ['--authority-http-token', os.fspath(self.token if path is None else path)] if mode == 2 else [
            {1: '--authority-stdio', 3: '--authority-http-optional', 4: '--authority-http-required'}[mode]]

    def execute(self, label, wires=(), *, args=None, mode=2, expected_exit=0, final_lf=True,
                supervisor=None, closed_stderr=False):
        command = [str(self.exe)] + (self.arguments(mode) if args is None else args)
        payload = b'\n'.join(wires) + (b'\n' if wires and final_lf else b'')
        COUNTS['processes'] += 1
        COUNTS['frames_sent'] += len(wires)
        number = COUNTS['processes']
        log = self.root / f'trace-{number}.json'
        if supervisor:
            COUNTS['kernel_supervised_processes'] += 1
            command = [sys.executable, '-I', '-B', str(HERE / 'authority_backend_supervisor.py'),
                '--log', str(log), '--mode', supervisor] + (['--fixture', str(self.token)] if mode == 2 else []) + ['--'] + command
        run = subprocess.run(command, input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=dict(os.environ, PATH=''), timeout=20, preexec_fn=(lambda: os.close(2)) if closed_stderr else None)
        self.assertEqual(run.returncode, expected_exit, (label, run.stderr))
        self.assertEqual(run.stderr, b'')
        self.assertTrue(not run.stdout or run.stdout.endswith(b'\n'))
        results = [response(line) for line in run.stdout.splitlines()]
        COUNTS['responses'] += len(results)
        trace = None
        if supervisor:
            trace = json.loads(log.read_bytes())
            self.assertEqual(trace['exit_code'], expected_exit)
            self.assertTrue(trace['owned_process_reaped'] and trace['executable_unchanged'])
            self.assertEqual(trace['executable_sha256'], self.exe_hash)
            self.assertEqual(trace['fault_fired'], supervisor != 'observe')
            self.assertEqual(trace['native_cleanup'], {'module_count': 9, 'private_workspaces_zero': True,
                'transport_input_output_zero': True, 'private_descriptor_slots_retired': True,
                'inspected_bytes': 16777216 + sum(row['workspace_capacity'] for row in self.metadata['profile']) + 24,
                'exit_code': expected_exit})
            COUNTS['kernel_fault_processes'] += supervisor != 'observe'
            if self.corpus:
                (self.corpus / f'trace-{number:03d}.json').write_bytes(log.read_bytes())
        CASES.append({'case': label, 'input_sha256': sha(payload), 'input_bytes': len(payload),
            'output_sha256': sha(run.stdout), 'output_bytes': len(run.stdout), 'exit_code': run.returncode,
            'frames_sent': len(wires), 'responses': len(results), 'supervisor': supervisor,
            'closed_stderr': closed_stderr, 'trace': trace})
        return results, trace

    def binding_wire(self):
        return frame(2, GOOD, bytes.fromhex(self.binding['payload_hex']))

    def check_binding(self, result):
        self.assertEqual(result, (0, bytes.fromhex(self.binding['output_hex'])))
        COUNTS['known_private_binding_comparisons'] += 1

    def test_actual_original_normal_wire_contexts(self):
        for context in self.vectors['contexts']:
            start = context['startup']
            self.token.write_bytes(bytes.fromhex(start['token_file_hex']))
            self.token.chmod(start['file_mode'])
            wires = [frame(row['request_op'], [(bytes.fromhex(n), bytes.fromhex(v)) for n, v in row['headers']],
                           bytes.fromhex(row['payload_hex'])) for row in context['requests']]
            results, _ = self.execute('original-context-' + str(context['source_context']), wires, mode=start['mode'])
            expected = [(row['code'], bytes.fromhex(row['output_hex'])) for row in context['requests']]
            self.assertEqual(results, expected)
            COUNTS['original_wire_comparisons'] += len(expected)

    def test_startup_file_rules_and_argv(self):
        for index, args in enumerate([['--authority-http-required'], [], ['--unknown'],
            ['--authority-http-token'], ['--authority-stdio', 'unexpected']]):
            self.execute(f'argument-{index}', args=args, expected_exit=2 if index == 0 else 64)
        for label, data, mode in [('empty', b'', 0o600), ('short', b'X' * 31, 0o600),
            ('long', b'X' * 4097, 0o600), ('mode', TOKEN, 0o640)]:
            self.token.chmod(0o600)
            self.token.write_bytes(data)
            self.token.chmod(mode)
            self.execute('startup-' + label, expected_exit=2)
        self.token.chmod(0o600)
        self.token.write_bytes(TOKEN)
        link = self.root / 'alias'
        link.symlink_to(self.token)
        self.execute('final-symlink', args=self.arguments(path=link), expected_exit=2)
        link.unlink()
        os.link(self.token, link)
        self.execute('hardlink', expected_exit=2)
        link.unlink()
        self.execute('directory', args=self.arguments(path=self.root), expected_exit=2)
        fifo = self.root / 'fifo'
        os.mkfifo(fifo, 0o600)
        self.execute('nonblocking-fifo', args=self.arguments(path=fifo), expected_exit=2)
        self.execute('absent-file', args=self.arguments(path=self.root / 'absent'), expected_exit=2)
        self.execute('empty-path', args=self.arguments(path=''), expected_exit=2)
        self.token.write_bytes(b'Y' * 4096 + b'\n')
        result, _ = self.execute('maximum-private-token', [frame(1, [(GOOD[0][0], b'Y' * 4096)])])
        self.assertEqual(result, [(0, b'\1')])
        self.token.write_bytes(TOKEN)
        parent_link = self.root / 'parent-link'
        parent_link.symlink_to(self.root, target_is_directory=True)
        result, _ = self.execute('parent-symlink-allowed', [frame(1, GOOD)], args=self.arguments(path=parent_link / 'credential'))
        self.assertEqual(result, [(0, b'\1')])
        raw_path = os.fsencode(self.root) + b'/nonutf8-\xff'
        fd = os.open(raw_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, TOKEN)
        finally:
            os.close(fd)
        result, _ = self.execute('nonutf8-argv', [frame(1, GOOD)], args=self.arguments(path=raw_path))
        self.assertEqual(result, [(0, b'\1')])

    def test_private_credential_is_frozen_and_frames_cannot_reload(self):
        process = subprocess.Popen([str(self.exe)] + self.arguments(), stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=dict(os.environ, PATH=''), bufsize=0)
        COUNTS['processes'] += 1
        requests, responses = [], []
        def query(wire):
            requests.append(wire)
            COUNTS['frames_sent'] += 1
            process.stdin.write(wire + b'\n')
            if not select.select([process.stdout], [], [], 10)[0]:
                raise AssertionError('native authority response deadline exceeded')
            raw = process.stdout.readline()
            self.assertTrue(raw.endswith(b'\n'))
            responses.append(raw)
            COUNTS['responses'] += 1
            return response(raw.strip())
        try:
            self.assertEqual(query(frame(0, GOOD)), (0, b''))
            self.check_binding(query(self.binding_wire()))
            self.token.write_bytes(b'Y' * 32)
            wire = (b'HRLOAD01' + struct.pack('<2Q', 1, 0) + os.fsencode(self.token)).hex().encode()
            self.assertEqual(query(wire), (0xffffffff, b''))
            self.assertEqual(query(b'{"event":0,"authenticated":true,"owner":"forged"}'.hex().encode()), (0xffffffff, b''))
            self.assertEqual(query(frame(1, [(b'authenticated', b'true'), (b'owner', b'a' * 64)])), (0xffffffde, b''))
            self.assertEqual(query(frame(1, [(GOOD[0][0], b'Y' * 32)])), (0xffffffde, b''))
            self.token.unlink()
            self.assertEqual(query(frame(1, GOOD)), (0, b'\1'))
            self.check_binding(query(self.binding_wire()))
            process.stdin.close()
            self.assertEqual(process.wait(timeout=10), 0)
            self.assertEqual(process.stdout.read(), b'')
            self.assertEqual(process.stderr.read(), b'')
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            for stream in (process.stdin, process.stdout, process.stderr):
                if not stream.closed:
                    stream.close()
        CASES.append({'case': 'frozen-private-credential', 'frames_sent': len(requests), 'responses': len(responses),
            'input_sha256': sha(b'\n'.join(requests) + b'\n'), 'output_sha256': sha(b''.join(responses)),
            'exit_code': process.returncode, 'ordinary_frames_cannot_change_lifecycle': True})

    def test_stdio_optional_http_and_closed_descriptor_two(self):
        forged = GOOD + [(b'origin', b'null'), (b'authenticated', b'true')]
        result, _ = self.execute('stdio-authority', [frame(1), frame(1, forged), frame(2, payload=b'private stdio')], mode=1)
        self.assertEqual(result[:2], [(0, b'\0')] * 2)
        self.assertEqual(result[2][0], 0)
        self.assertRegex(result[2][1], b'^[0-9a-f]{64}$')
        result, _ = self.execute('optional-http-no-fallback', [frame(1), frame(1, GOOD), frame(2, forged, b'no fallback')], mode=3)
        self.assertEqual(result, [(0xffffffdd, b'')] * 3)
        result, _ = self.execute('stdio-owner-fd-two', [frame(1), frame(2, payload=b'fd two')], mode=1, closed_stderr=True)
        self.assertEqual(result[0], (0, b'\0'))
        self.assertEqual(result[1][0], 0)
        self.assertRegex(result[1][1], b'^[0-9a-f]{64}$')
        result, _ = self.execute('http-token-fd-two', [frame(1, GOOD), self.binding_wire()], closed_stderr=True)
        self.assertEqual(result[0], (0, b'\1'))
        self.check_binding(result[1])

    def test_native_newline_eof_and_frame_bounds(self):
        result, _ = self.execute('unterminated-final-frame', [frame(1, GOOD), frame(1), frame(1, GOOD)], final_lf=False)
        self.assertEqual(result, [(0, b'\1'), (0xffffffde, b''), (0, b'\1')])
        malformed = [b'', b'0', b'zz', b'00', b'7b2261757468656e74696361746564223a747275657d',
                     b'ffffffffffffffffffffffffffffffff']
        result, _ = self.execute('malformed-frame-recovery', malformed + [frame(1, GOOD)])
        self.assertEqual(result, [(0xffffffff, b'')] * len(malformed) + [(0, b'\1')])
        result, _ = self.execute('oversized-line-fails-closed', [b'0' * ((8 << 20) + 1)], expected_exit=2)
        self.assertEqual(result, [])
        result, _ = self.execute('empty-stdio-eof-cleanup', mode=1)
        self.assertEqual(result, [])

    def test_real_kernel_owner_crypto_order_and_failure_independence(self):
        plans = [(1, 'observe'), (2, 'observe'), (3, 'observe')]
        plans += [(mode, fault) for fault in ['owner_open_error', 'owner_read_error'] for mode in (1, 2)]
        plans += [(mode, f'entropy_fail_{index}') for index in range(1, 5) for mode in (1, 2)]
        plans += [(1, 'entropy_fallback'), (2, 'entropy_fallback')]
        for mode, fault in plans:
            wires = [frame(1, GOOD), self.binding_wire()] if mode == 2 else [frame(1), frame(2, payload=b'fixture binding')]
            result, trace = self.execute(f'kernel-{mode}-{fault}', wires, mode=mode, supervisor=fault)
            actions = [event['action'] for event in trace['events']]
            self.assertEqual(actions.count('owner_open'), 1)
            self.assertLess(actions.index('owner_open'), actions.index('entropy_probe'))
            if fault != 'owner_open_error':
                self.assertEqual(actions.count('owner_close'), 1)
                self.assertLess(actions.index('owner_close'), actions.index('entropy_probe'))
            if mode == 2:
                self.assertLess(actions.index('token_close'), actions.index('owner_open'))
                self.assertEqual(actions.count('token_open'), 1)
                self.assertEqual(actions.count('token_stat'), 2)
                self.assertLess(actions.index('token_stat'), actions.index('effective_uid'))
                self.assertEqual(result[0], (0, b'\1'))
                self.check_binding(result[1])
            elif mode == 3:
                self.assertEqual(result, [(0xffffffdd, b'')] * 2)
            elif fault.startswith('owner_'):
                self.assertEqual(result, [(0xffffffdc, b'')] * 2)
            elif fault.startswith('entropy_fail_'):
                self.assertEqual(result, [(0, b'\0'), (0xffffffda, b'')])
            else:
                self.assertEqual(result[0], (0, b'\0'))
                self.assertEqual(result[1][0], 0)
                self.assertRegex(result[1][1], b'^[0-9a-f]{64}$')
            if fault == 'entropy_fallback':
                self.assertEqual(actions.count('entropy_fill'), 0)
                for action in ('entropy_random_open', 'entropy_poll', 'entropy_random_close', 'entropy_urandom_open', 'entropy_urandom_close'):
                    self.assertEqual(actions.count(action), 1)
                self.assertEqual(actions.count('entropy_urandom_read'), 4)
                self.assertEqual(actions[-1], 'entropy_urandom_close')
            else:
                expected = int(fault[-1]) if fault.startswith('entropy_fail_') else 4
                self.assertEqual(actions.count('entropy_fill'), expected)
                self.assertEqual([event['entropy_bytes'] for event in trace['events'] if event['action'] == 'entropy_fill'], [32] * expected)


if __name__ == '__main__':
    started = time.monotonic()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(AuthorityTransport)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    expected_counts = {'processes': 48, 'frames_sent': 144, 'responses': 143, 'original_wire_comparisons': 78,
        'known_private_binding_comparisons': 11, 'kernel_supervised_processes': 17,
        'kernel_fault_processes': 14, 'new_original_rust_calls': 0}
    report = {'schema': 'hepta.runtime.authority-transport.tests.v1', 'tests_run': result.testsRun,
        'expected_tests': 6, 'failures': len(result.failures), 'errors': len(result.errors),
        'skipped': len(result.skipped), 'expected_failures': len(result.expectedFailures),
        'unexpected_successes': len(result.unexpectedSuccesses), 'counts': COUNTS,
        'expected_counts': expected_counts, 'counts_match': COUNTS == expected_counts,
        'sources': {name: sha((HERE / name).read_bytes()) for name in ['test_authority_transport.py',
            'authority_backend_supervisor.py', 'authority_loader_supervisor.py', 'authority_native_harness.py', 'authority_wire_vectors.json.gz']},
        'elapsed_seconds': round(time.monotonic() - started, 6), 'production_http_transport': False,
        'new_rust_replay_claimed': False, 'whole_runtime_replaced': False}
    passed = result.wasSuccessful() and result.testsRun == 6 and report['counts_match'] and all(report[k] == 0 for k in
        ('failures', 'errors', 'skipped', 'expected_failures', 'unexpected_successes'))
    report['status'] = 'PASS' if passed else 'FAIL'
    target = os.environ.get('HIA_AUTHORITY_TRANSPORT_CORPUS_DIR')
    if target:
        folder = Path(target)
        (folder / 'transport-cases.json').write_text(json.dumps(CASES, sort_keys=True, separators=(',', ':')) + '\n')
        (folder / 'transport-report.json').write_text(json.dumps(report, sort_keys=True, separators=(',', ':')) + '\n')
    print(json.dumps(report, sort_keys=True))
    raise SystemExit(0 if passed else 1)

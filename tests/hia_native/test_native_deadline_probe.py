#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Observe an actual blocked Linux read and owned native cancellation.

This explicit 200 ms assembly fixture is separate from the production fixed
30-second seven-image service. It supplies no HIA completion or MCP result.
The worker actually sleeps inside an empty-pipe SYS_read. The fixed native
parent times out, sends SIGKILL only to that worker, and reaps it with WNOHANG.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import struct
import subprocess
import tempfile
import time
import unittest

OBSERVATION = {}


def identity(pid):
    try:
        fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
    except (FileNotFoundError, ProcessLookupError):
        return None
    return {'state': fields[0], 'parent': int(fields[1]), 'start_ticks': int(fields[19])}


class NativeDeadlineProbeTests(unittest.TestCase):
    def test_actual_blocked_pipe_read_is_cancelled_and_reaped(self):
        source = Path(os.environ.get('HIA_DEADLINE_PROBE_SOURCE',
                                    Path(__file__).with_name('native_deadline_probe.S')))
        source_raw = source.read_bytes()
        with tempfile.TemporaryDirectory(prefix='hia-owned-deadline-') as directory:
            owned = Path(directory)
            obj, executable = owned / 'probe.o', owned / 'probe.elf'
            subprocess.run(['as', '--64', str(source), '-o', str(obj)], check=True,
                           capture_output=True, timeout=10)
            subprocess.run(['ld', '-nostdlib', '-static', '-z', 'noexecstack',
                            '-e', '_start', '-Ttext=0x400000', str(obj), '-o', str(executable)],
                           check=True, capture_output=True, timeout=10)
            executable_raw = executable.read_bytes()
            self.assertEqual(executable_raw[:4], b'\x7fELF')
            retained = os.environ.get('HIA_DEADLINE_PROBE_EXECUTABLE')
            if retained:
                with Path(retained).open('xb') as saved:
                    saved.write(executable_raw)
            proc = subprocess.Popen([str(executable)], stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    env={'PATH': ''}, bufsize=0, start_new_session=True)
            try:
                self.assertTrue(select.select([proc.stdout], [], [], 2)[0])
                raw_pid = os.read(proc.stdout.fileno(), 8)
                self.assertEqual(len(raw_pid), 8)
                worker = struct.unpack('<Q', raw_pid)[0]
                self.assertGreater(worker, 0)
                self.assertNotEqual(worker, proc.pid)
                observed = None
                until = time.monotonic() + .15
                while time.monotonic() < until:
                    state = identity(worker)
                    if state is not None:
                        syscall = Path(f'/proc/{worker}/syscall').read_text().strip().split()
                        wait_channel = Path(f'/proc/{worker}/wchan').read_text().strip()
                        if (syscall and syscall[0] == '0' and len(syscall) >= 4
                                and int(syscall[3], 0) == 1 and 'pipe_read' in wait_channel):
                            observed = dict(state, syscall=syscall[0], read_bytes=1,
                                            wait_channel=wait_channel)
                            break
                    time.sleep(.001)
                self.assertIsNotNone(observed, 'worker was not observed in the actual empty-pipe read')
                self.assertEqual(observed['parent'], proc.pid)
                self.assertEqual(observed['state'], 'S')
                output, errors = proc.communicate(timeout=3)
                self.assertEqual(proc.returncode, 0, errors)
                self.assertEqual(errors, b'')
                self.assertEqual(len(output), 48)
                code, elapsed, result_pid, kill_result, wait_status, entered_read = struct.unpack('<6Q', output)
                self.assertEqual((code, result_pid, kill_result, wait_status & 127, entered_read),
                                 (110, worker, 0, 9, 1))
                self.assertGreaterEqual(elapsed, 190_000_000)
                self.assertLess(elapsed, 2_000_000_000)
                remaining = identity(worker)
                self.assertTrue(remaining is None or remaining['start_ticks'] != observed['start_ticks'])
                OBSERVATION.update(status='pass', source_sha256=hashlib.sha256(source_raw).hexdigest(),
                                   executable_sha256=hashlib.sha256(executable_raw).hexdigest(),
                                   explicit_test_timeout_ms=200, elapsed_nanoseconds=elapsed,
                                   observed_block=observed, native_exit=0, wait_signal=9,
                                   worker_reaped=True, runtime_python_required=False,
                                   evidence_kind='actual empty-pipe blocking SYS_read')
                if retained:
                    OBSERVATION['retained_executable'] = Path(retained).name
                self.assertEqual(source.read_bytes(), source_raw)
            finally:
                if proc.poll() is None:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait(timeout=3)
                for stream in (proc.stdout, proc.stderr):
                    stream.close()


if __name__ == '__main__':
    result = unittest.main(exit=False, verbosity=2)
    proof = {'schema': 'hepta.runtime.native-deadline-probe.v1', **OBSERVATION,
             'status': 'pass' if result.result.wasSuccessful() else 'fail'}
    destination = os.environ.get('HIA_DEADLINE_PROBE_RESULT')
    if destination:
        Path(destination).write_text(json.dumps(proof, sort_keys=True, indent=2) + '\n')
    print(json.dumps(proof, sort_keys=True))
    raise SystemExit(0 if result.result.wasSuccessful() else 1)

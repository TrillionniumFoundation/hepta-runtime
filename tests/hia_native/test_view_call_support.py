"""Test-only input encoding, real filesystem scheduling and ELF stream capture.

This module supplies no view implementation or expected output. The native
controller selects its effects; the harness performs only input-authored file
mutations at explicit fixture observation points.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import os
from pathlib import Path
import select
import stat
import struct
import subprocess
import threading
import time

MAX = (1 << 64) - 1


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def endpoint(value):
    """Encode only the existing typed endpoint ABI, without parsing a line ID."""
    if value is None:
        return b''
    payload = b''; scalar = 0
    if type(value) is int:
        if -(1 << 63) <= value < 1 << 63:
            kind, scalar = 0, value & MAX
        else:
            kind = 1
    elif type(value) is float:
        if not (-float('inf') < value < float('inf')):
            raise ValueError('non-JSON numeric input')
        kind = 1
    elif type(value) is str:
        kind, payload = 2, value.encode('utf-8')
    else:
        kind = 3
        payload = json.dumps(value, sort_keys=True, separators=(',', ':'),
                             ensure_ascii=False, allow_nan=False).encode('utf-8')
    return b'HIAEP001' + struct.pack('<3Q', kind, len(payload), scalar) + payload


def call_frame(raw_path, resolved_path, params):
    start, end = endpoint(params.get('start')), endpoint(params.get('end'))
    flags = 4 if params.get('full') is True else 0
    return struct.pack('<8s7Q', b'HVCLQ001', flags, len(raw_path), len(resolved_path),
                       len(start), len(end), 0, 0) + raw_path + resolved_path + start + end


def save_gzip(directory, name, raw):
    path = Path(directory) / name
    with path.open('xb') as underlying:
        with gzip.GzipFile(filename='', mode='wb', fileobj=underlying, mtime=0) as output:
            output.write(raw)
    return dict(path=name, bytes=len(raw), sha256=sha(raw),
                compressed_bytes=path.stat().st_size, compressed_sha256=sha(path.read_bytes()))


class CaseFilesystem:
    """Execute the corpus's actual writes/renames and keep their timing record."""
    def __init__(self, directory, case):
        self.directory = os.fsencode(Path(directory).resolve())
        self.case = case
        self.meta = case['metadata']
        self.fired = set()
        self.events = []

    def path(self, value):
        raw = bytes.fromhex(value)
        if raw.startswith(b'/') or b'..' in raw.split(b'/'):
            raise AssertionError('case path escaped its private session directory')
        return self.directory + b'/' + raw

    def actions(self, actions):
        for action in actions:
            kind, path = action['kind'], self.path(action['path_hex'])
            if kind == 'write':
                with open(path, 'wb') as output:
                    output.write(self.case['blobs'][action['blob']])
            elif kind == 'remove':
                if stat.S_ISDIR(os.lstat(path).st_mode):
                    os.rmdir(path)
                else:
                    os.unlink(path)
            elif kind == 'mkdir':
                os.mkdir(path)
            elif kind == 'symlink':
                target = bytes.fromhex(action['target_hex'])
                if target.startswith(b'/') or b'..' in target.split(b'/'):
                    raise AssertionError('case symlink escaped its private session directory')
                os.symlink(target, path)
            elif kind == 'hardlink':
                os.link(self.path(action['target_hex']), path)
            else:
                raise AssertionError('unknown real-filesystem case action')

    def setup(self):
        self.actions(self.meta['setup'])

    def hooks(self, when, event, occurrence):
        for index, hook in enumerate(self.meta['hooks']):
            if (hook['when'], hook['event'], hook['occurrence']) != (when, event, occurrence):
                continue
            if index in self.fired:
                raise AssertionError('native fixture repeated a mutation observation point')
            self.actions(hook['actions'])
            self.fired.add(index)
            self.events.append(dict(hook=index, when=when, event=event, occurrence=occurrence,
                                    actions=hook['actions']))

    def complete(self):
        if self.fired != set(range(len(self.meta['hooks']))):
            raise AssertionError('native fixture did not reach every authored filesystem hook')


class RecordedElf:
    """Interact with one real ELF while retaining every actual stream byte."""
    def __init__(self, command, cwd, output, name, timeout=45):
        self.command = [str(part) for part in command]
        self.cwd = Path(cwd).resolve()
        self.output = Path(output)
        self.name = name
        self.timeout = timeout
        self.started = time.monotonic()
        self.deadline = self.started + timeout
        self.input = bytearray()
        self.stdout = bytearray()
        self.stderr = bytearray()
        self.pending = bytearray()
        self.drain_error = None
        self.eof = False
        self.closed = False
        self.timed_out = False
        self.forced_termination = False
        self.process = subprocess.Popen(self.command, cwd=self.cwd, stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        os.set_blocking(self.process.stdin.fileno(), False)
        self.error_thread = threading.Thread(target=self._drain_errors, daemon=True)
        self.error_thread.start()

    def _drain_errors(self):
        try:
            while True:
                chunk = self.process.stderr.read(65536)
                if not chunk:
                    return
                self.stderr.extend(chunk)
        except BaseException as error:
            self.drain_error = error

    def _remaining(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            self.timed_out = True
            raise TimeoutError(f'actual ELF {self.name} exceeded its {self.timeout}s deadline')
        return remaining

    def send(self, raw):
        if self.closed or self.process.stdin.closed:
            raise AssertionError('fixture input sent after EOF')
        self._remaining()
        view = memoryview(raw)
        while view:
            _, ready, _ = select.select([], [self.process.stdin], [], self._remaining())
            if not ready:
                self.timed_out = True
                raise TimeoutError(f'actual ELF {self.name} stdin timed out')
            try:
                count = os.write(self.process.stdin.fileno(), view)
            except BlockingIOError:
                continue
            if count <= 0:
                raise AssertionError('actual fixture stdin write made no progress')
            self.input.extend(view[:count]); view = view[count:]

    def send_frame(self, raw):
        self.send(struct.pack('<Q', len(raw)) + raw)

    def _read(self):
        if self.eof:
            return
        ready, _, _ = select.select([self.process.stdout], [], [], self._remaining())
        if not ready:
            self.timed_out = True
            raise TimeoutError(f'actual ELF {self.name} stdout timed out')
        chunk = os.read(self.process.stdout.fileno(), 65536)
        if not chunk:
            self.eof = True
            return
        self.stdout.extend(chunk); self.pending.extend(chunk)

    def read_exact(self, size):
        if type(size) is not int or size < 0:
            raise AssertionError('invalid fixture read extent')
        while len(self.pending) < size:
            self._read()
            if self.eof:
                raise AssertionError(f'actual ELF {self.name} ended before its complete frame')
        value = bytes(self.pending[:size]); del self.pending[:size]
        return value

    def close_input(self):
        if not self.process.stdin.closed:
            self.process.stdin.close()

    def finish(self, expected_exit=0):
        if self.closed:
            return self.receipt
        try:
            self.close_input()
            while not self.eof:
                self._read()
            self.process.wait(timeout=self._remaining())
            self.error_thread.join(timeout=self._remaining())
            if self.error_thread.is_alive() or self.drain_error:
                raise AssertionError('actual ELF stderr capture did not complete')
            if self.process.returncode != expected_exit:
                raise AssertionError(f'actual ELF {self.name} exited {self.process.returncode}')
            if self.pending:
                raise AssertionError('unparsed trailing actual ELF stdout')
        finally:
            if self.process.poll() is None:
                # The only process terminated here is this harness's own child.
                self.forced_termination = True
                self.process.kill(); self.process.wait()
            while not self.eof:
                chunk = os.read(self.process.stdout.fileno(), 65536)
                if not chunk:
                    self.eof = True
                else:
                    self.stdout.extend(chunk); self.pending.extend(chunk)
            self.error_thread.join(timeout=5)
            self.process.stdout.close()
            self.process.stderr.close()
            self.closed = True
            elapsed = time.monotonic() - self.started
            streams = {kind: save_gzip(self.output, f'{self.name}.{kind}.bin.gz', bytes(raw))
                       for kind, raw in [('input', self.input), ('stdout', self.stdout), ('stderr', self.stderr)]}
            self.receipt = dict(name=self.name, command=self.command, cwd=str(self.cwd),
                                timeout_seconds=self.timeout, elapsed_seconds=elapsed,
                                exit_code=self.process.returncode, streams=streams,
                                timed_out=self.timed_out, forced_termination=self.forced_termination,
                                stderr_capture_complete=not self.error_thread.is_alive() and not self.drain_error,
                                capture_error=None if self.drain_error is None else repr(self.drain_error))
            (self.output / f'{self.name}.process.json').write_text(
                json.dumps(self.receipt, sort_keys=True, indent=2, allow_nan=False) + '\n')
        return self.receipt

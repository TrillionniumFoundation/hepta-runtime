"""Observe a fixed native stdio host; never manufacture protocol responses.

Each process owns one session, one real shared worker port, and its fixed
private journal descriptor 3. The production entry is qualified separately;
the private entry uses the identical host pump and graph with this owned sink.
All stream writes and deadline failures remain failures. Process cleanup runs
before evidence sealing, including when capture storage itself fails.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import time


PROCESS_SECONDS = 180
EXCHANGE_SECONDS = 60
ENVIRONMENT = {'PATH': '', 'LC_ALL': 'C'}


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=True, allow_nan=False) + '\n').encode()


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def file_pin(path):
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'bytes': path.stat().st_size, 'sha256': digest}


class Stream:
    """Retain the full stream with deterministic compression and an uncompressed pin."""
    def __init__(self, path):
        self.path = path
        self.file = path.open('xb')
        try:
            self.output = gzip.GzipFile(filename='', fileobj=self.file, mode='wb',
                                        compresslevel=1, mtime=0)
        except BaseException:
            self.file.close()
            raise
        self.digest = hashlib.sha256()
        self.size = 0

    def write(self, raw):
        assert self.output.write(raw) == len(raw)
        self.digest.update(raw)
        self.size += len(raw)

    def close(self):
        try:
            self.output.close()
        finally:
            self.file.close()
        return {'file': self.path.name, 'compressed': file_pin(self.path),
                'uncompressed': {'bytes': self.size, 'sha256': self.digest.hexdigest()}}


class NativeStdio:
    def __init__(self, binary, expected_binary, cwd, config, output):
        self.binary = Path(binary).resolve(strict=True)
        self.output = Path(output).resolve(strict=True)
        self.cwd = Path(cwd).resolve(strict=True)
        self.config = Path(config).resolve(strict=True)
        assert self.binary.is_file() and file_pin(self.binary) == expected_binary
        self.expected_binary = expected_binary
        self.command = [str(self.binary), '--runtime-config', str(self.config)]
        self.process = None
        self.started_ns = None
        self.finished_ns = None
        self.deadline_ns = None
        self.streams = {}
        self.sealed = {}
        self.pending = bytearray()
        self.scan = 0
        self.eof = {'stdout': False, 'stderr': False}
        self.journal_fd = None
        self.journal_path = self.output / 'host-journal.bin'
        self.exchange_path = self.output / 'exchanges.jsonl'
        self.exchange_count = 0
        self.closed = False
        self.failure = None
        self.timed_out = False
        self.kill_requested = False
        self.returncode = None
        self.cleanup_errors = []
        try:
            # The driver is itself a fresh process with only standard FDs.
            # Never overwrite an unknown descriptor to obtain the fixture FD.
            self.journal_fd = os.open(self.journal_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
            assert self.journal_fd == 3, 'fixed owned journal FD3 is unavailable'
            assert stat.S_ISREG(os.fstat(self.journal_fd).st_mode)
            for name in ('attempted-stdin', 'stdin', 'stdout', 'stderr'):
                self.streams[name] = Stream(self.output / (name + '.bin.gz'))
            with self.exchange_path.open('xb'):
                pass
            self.started_ns = time.monotonic_ns()
            self.deadline_ns = self.started_ns + PROCESS_SECONDS * 1_000_000_000
            self.process = subprocess.Popen(self.command, cwd=self.cwd,
                env=ENVIRONMENT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, pass_fds=(3,), start_new_session=True)
            for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                os.set_blocking(stream.fileno(), False)
            with (self.output / 'started.json').open('xb') as stream:
                stream.write(encoded({'command': self.command, 'cwd': str(self.cwd),
                    'environment': ENVIRONMENT, 'pid': self.process.pid,
                    'pgid': os.getpgid(self.process.pid), 'parent_pid': os.getpid(),
                    'started_ns': self.started_ns, 'deadline_seconds': PROCESS_SECONDS,
                    'binary': expected_binary, 'journal_fd': 3}))
        except BaseException as failure:
            self.failure = self.error(failure)
            try:
                self._reap(failed=True)
            finally:
                try:
                    self._seal()
                except BaseException as cleanup_failure:
                    # Retain the original startup error, including when an
                    # unavailable FD or evidence ENOSPC also prevents sealing.
                    self.cleanup_errors.append(self.error(cleanup_failure))
            raise

    @staticmethod
    def error(failure):
        return {'type': type(failure).__name__, 'message': str(failure),
                'errno': getattr(failure, 'errno', None)}

    def journal_size(self):
        return os.fstat(self.journal_fd).st_size

    def _remaining(self, deadline_ns):
        remaining = min(deadline_ns, self.deadline_ns) - time.monotonic_ns()
        if remaining <= 0:
            self.timed_out = True
            raise TimeoutError('native stdio exceeded its original process/exchange deadline')
        return remaining / 1_000_000_000

    def _read(self, selector, key, responses):
        try:
            raw = os.read(key.fd, 65536)
        except BlockingIOError:
            return
        if not raw:
            self.eof[key.data] = True
            selector.unregister(key.fileobj)
            return
        self.streams[key.data].write(raw)
        if key.data != 'stdout':
            return
        self.pending.extend(raw)
        while True:
            end = self.pending.find(b'\n', self.scan)
            if end < 0:
                self.scan = len(self.pending)
                return
            responses.append(bytes(self.pending[:end + 1]))
            del self.pending[:end + 1]
            self.scan = 0

    def exchange(self, row, wire):
        assert not self.closed and not self.pending and row['opcode'] == 1
        assert row['frames'] in (0, 1, 2) and wire.endswith(b'\n')
        assert pin(wire) == row['wire']
        before = time.monotonic_ns()
        journal_before = self.journal_size()
        deadline = before + EXCHANGE_SECONDS * 1_000_000_000
        offsets = {name: stream.size for name, stream in self.streams.items()}
        written = 0
        responses = []
        failed = None
        try:
            self.streams['attempted-stdin'].write(wire)
            with selectors.DefaultSelector() as selector:
                selector.register(self.process.stdin, selectors.EVENT_WRITE, 'stdin')
                for name in ('stdout', 'stderr'):
                    assert not self.eof[name]
                    selector.register(getattr(self.process, name), selectors.EVENT_READ, name)
                while written < len(wire) or len(responses) < row['frames']:
                    events = selector.select(self._remaining(deadline))
                    if not events:
                        self.timed_out = True
                        raise TimeoutError('native stdio exchange made no progress before its deadline')
                    events.sort(key=lambda value: value[0].data == 'stdin')
                    for key, _ in events:
                        if key.data != 'stdin':
                            self._read(selector, key, responses)
                            continue
                        try:
                            count = os.write(key.fd, memoryview(wire)[written:written + 65536])
                        except BlockingIOError:
                            continue
                        assert count > 0, 'native input pipe made no progress'
                        accepted = written
                        written += count
                        self.streams['stdin'].write(memoryview(wire)[accepted:written])
                        if written == len(wire):
                            selector.unregister(self.process.stdin)
                    assert not self.eof['stdout'], 'native stdio closed before normal corpus EOF'
                    assert len(responses) <= row['frames'], 'native emitted an undeclared response'
                assert len(responses) == row['frames'] and written == len(wire)
                assert not self.pending, 'native emitted an undeclared partial response'
                self._remaining(deadline)
        except BaseException as failure:
            failed = self.error(failure)
            self.failure = failed
            raise
        finally:
            after = time.monotonic_ns()
            record = {'index': self.exchange_count, 'sequence': row['sequence'],
                'session': row['session'], 'before_ns': before, 'after_ns': after,
                'deadline_seconds': EXCHANGE_SECONDS, 'error': failed,
                'timed_out': self.timed_out, 'attempted_input': pin(wire),
                'accepted_input': pin(wire[:written]),
                'ranges': {name: {'offset': offsets[name], 'bytes': stream.size - offsets[name]}
                           for name, stream in self.streams.items()},
                'responses': [pin(response) for response in responses],
                'journal_before': journal_before, 'journal_after': self.journal_size()}
            # Append the complete observation once. No whole-history rewrite.
            try:
                with self.exchange_path.open('ab') as stream:
                    raw = encoded(record)
                    assert stream.write(raw) == len(raw)
            except BaseException as evidence_failure:
                if self.failure is None:
                    self.failure = self.error(evidence_failure)
                raise
            self.exchange_count += 1
        return b''.join(responses), record

    def _kill(self):
        if self.process is None:
            return
        self.kill_requested = True
        try:
            os.killpg(self.process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except BaseException as failure:
            # A failed kill must not bypass the later wait and pipe closes.
            # It is retained and always prevents a successful receipt.
            self.cleanup_errors.append(self.error(failure))

    def _reap(self, *, failed):
        if self.process is None:
            self.finished_ns = time.monotonic_ns()
            return
        try:
            if failed:
                self._kill()
            try:
                self.process.stdin.close()
            except (BrokenPipeError, OSError):
                pass
            deadline = time.monotonic_ns() + (5 if failed else EXCHANGE_SECONDS) * 1_000_000_000
            responses = []
            with selectors.DefaultSelector() as selector:
                for name in ('stdout', 'stderr'):
                    if not self.eof[name]:
                        selector.register(getattr(self.process, name), selectors.EVENT_READ, name)
                while selector.get_map():
                    if failed:
                        remaining = (deadline - time.monotonic_ns()) / 1_000_000_000
                        if remaining <= 0:
                            break
                    else:
                        remaining = self._remaining(deadline)
                    events = selector.select(remaining)
                    if not events:
                        if failed:
                            break
                        self.timed_out = True
                        raise TimeoutError('native EOF did not drain within its deadline')
                    for key, _ in events:
                        self._read(selector, key, responses)
            if not failed:
                assert not responses and not self.pending, 'native returned unclaimed EOF output'
                self.returncode = self.process.wait(timeout=self._remaining(deadline))
                assert self.returncode == 0
                # A successful host must join its workers. Do not hide a live
                # descendant group behind a successful root-process wait.
                try:
                    os.killpg(self.process.pid, 0)
                except ProcessLookupError:
                    pass
                else:
                    raise AssertionError('native left a live owned process group after EOF')
        except BaseException as failure:
            self.cleanup_errors.append(self.error(failure))
            self._kill()
        finally:
            if self.process.poll() is None:
                self._kill()
            try:
                self.returncode = self.process.wait(timeout=5)
            except BaseException as failure:
                self.cleanup_errors.append(self.error(failure))
                self._kill()
                try:
                    self.returncode = self.process.wait(timeout=5)
                except BaseException as final_wait_failure:
                    self.cleanup_errors.append(self.error(final_wait_failure))
            for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                try:
                    stream.close()
                except BaseException as failure:
                    self.cleanup_errors.append(self.error(failure))
            self.finished_ns = time.monotonic_ns()

    def _seal(self):
        # Evidence failures cannot bypass child cleanup: this method is always
        # entered only after _reap has attempted every kill/wait/pipe close.
        errors = []
        if self.journal_fd is not None:
            try:
                os.close(self.journal_fd)
            except BaseException as failure:
                errors.append(failure)
            self.journal_fd = None
        for name, stream in self.streams.items():
            try:
                self.sealed[name] = stream.close()
            except BaseException as failure:
                errors.append(failure)
        if errors:
            raise errors[0]
        row = {'schema': 'hepta.runtime.bellman-public-native-process.v1',
            'command': self.command, 'cwd': str(self.cwd), 'environment': ENVIRONMENT,
            'pid': None if self.process is None else self.process.pid,
            'pgid': None if self.process is None else self.process.pid,
            'parent_pid': os.getpid(), 'started_ns': self.started_ns,
            'finished_ns': self.finished_ns, 'deadline_seconds': PROCESS_SECONDS,
            'exchange_deadline_seconds': EXCHANGE_SECONDS, 'returncode': self.returncode,
            'failure': self.failure, 'timed_out': self.timed_out,
            'kill_requested': self.kill_requested, 'cleanup_errors': self.cleanup_errors,
            'binary': self.expected_binary, 'binary_after': file_pin(self.binary),
            'streams': self.sealed,
            'journal': {'file': self.journal_path.name, **file_pin(self.journal_path)},
            'exchanges': {'file': self.exchange_path.name, 'records': self.exchange_count,
                          **file_pin(self.exchange_path)},
            'pipe_eof': self.eof, 'pending_stdout': pin(bytes(self.pending)),
            'private_owned_journal_fd': 3}
        with (self.output / 'process.json').open('xb') as stream:
            stream.write(encoded(row))
        return row

    def close(self, *, failed=False):
        assert not self.closed
        self.closed = True
        self._reap(failed=failed)
        row = self._seal()
        assert failed or (self.failure is None and not self.timed_out
            and not self.kill_requested and not self.cleanup_errors
            and self.returncode == 0 and all(self.eof.values())
            and row['binary_after'] == self.expected_binary
            and not self.pending
            and self.finished_ns - self.started_ns <= PROCESS_SECONDS * 1_000_000_000)
        return row

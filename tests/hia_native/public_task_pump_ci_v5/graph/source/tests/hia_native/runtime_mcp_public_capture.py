"""Capture actual public stdio with a fixed 60-second request deadline.

Reads and writes progress together. Complete successful and failed streams are
stored as gzip bytes; no application operation is implemented in this helper.
"""
from pathlib import Path
import gzip
import hashlib
import json
import os
import selectors
import subprocess
import time

ENVIRONMENT = {'PATH': '', 'LC_ALL': 'C'}
sha = lambda value: hashlib.sha256(value).hexdigest()


class Stream:
    def __init__(self, path):
        self.path = path
        self.file = path.open('xb')
        self.gzip = gzip.GzipFile(fileobj=self.file, mode='wb', mtime=0)
        self.hash = hashlib.sha256()
        self.size = 0

    def write(self, raw):
        self.gzip.write(raw)
        self.hash.update(raw)
        self.size += len(raw)

    def close(self):
        self.gzip.close()
        self.file.close()
        return {'bytes': self.size, 'sha256': self.hash.hexdigest()}


class Public:
    def __init__(self, out, binary, cwd, config=None, *, expected_exit=0,
                 expected_stderr=b''):
        self.out = Path(out)
        self.out.mkdir(parents=True, exist_ok=False)
        self.command = [str(binary)] + ([] if config is None else ['--runtime-config', str(config)])
        self.cwd = str(cwd)
        self.streams = {name: Stream(self.out / (name + '.bin.gz')) for name in ('stdin', 'stdout', 'stderr')}
        self.started = time.monotonic()
        self.process = subprocess.Popen(self.command, cwd=cwd, env=ENVIRONMENT,
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            os.set_blocking(stream.fileno(), False)
        self.pending = bytearray()
        self.scanned = 0
        self.closed = False
        self.records = []
        self.stderr = bytearray()
        self.expected_exit = expected_exit
        self.expected_stderr = expected_stderr

    def _lines(self):
        result = []
        while True:
            end = self.pending.find(b'\n', self.scanned)
            if end < 0:
                self.scanned = len(self.pending)
                return result
            result.append(bytes(self.pending[:end]))
            del self.pending[:end + 1]
            self.scanned = 0

    def exchange(self, wire, expected=1):
        if type(wire) is not bytes or not wire.endswith(b'\n'):
            raise ValueError('complete public newline frame required')
        started = time.monotonic()
        written = 0
        replies = []
        error = None
        try:
            with selectors.DefaultSelector() as ready:
                ready.register(self.process.stdin, selectors.EVENT_WRITE, 'stdin')
                ready.register(self.process.stdout, selectors.EVENT_READ, 'stdout')
                ready.register(self.process.stderr, selectors.EVENT_READ, 'stderr')
                while written < len(wire) or len(replies) < expected:
                    remaining = 60 - (time.monotonic() - started)
                    if remaining <= 0:
                        raise TimeoutError('actual public request exceeded 60 seconds')
                    events = ready.select(remaining)
                    if not events:
                        raise TimeoutError('actual public request exceeded 60 seconds')
                    for key, _ in events:
                        if key.data == 'stdin':
                            try:
                                count = os.write(key.fd, memoryview(wire)[written:written + 65536])
                            except BlockingIOError:
                                continue
                            if count <= 0:
                                raise RuntimeError('public stdin made no progress')
                            self.streams['stdin'].write(memoryview(wire)[written:written + count])
                            written += count
                            if written == len(wire):
                                ready.unregister(self.process.stdin)
                        else:
                            try:
                                raw = os.read(key.fd, 65536)
                            except BlockingIOError:
                                continue
                            if not raw:
                                ready.unregister(key.fileobj)
                                if key.data == 'stdout' and len(replies) < expected:
                                    raise RuntimeError('public EOF before the expected response')
                                continue
                            self.streams[key.data].write(raw)
                            if key.data == 'stdout':
                                self.pending.extend(raw)
                                replies.extend(self._lines())
                            else:
                                self.stderr.extend(raw)
                if len(replies) != expected:
                    raise AssertionError('actual public response count differs')
                return replies
        except BaseException as exc:
            error = repr(exc)
            raise
        finally:
            self.records.append({'number': len(self.records), 'timeout_seconds': 60,
                'elapsed_seconds': time.monotonic() - started, 'requested_bytes': len(wire),
                'written_bytes': written, 'request_sha256': sha(wire),
                'responses': [{'bytes': len(raw), 'sha256': sha(raw)} for raw in replies], 'error': error})
            (self.out / 'exchanges.json').write_text(json.dumps(self.records, sort_keys=True, indent=2) + '\n')

    def close(self, failed=False):
        if self.closed:
            return self.receipt
        self.closed = True
        started = time.monotonic()
        timed = False
        try:
            self.process.stdin.close()
        except (BrokenPipeError, OSError):
            pass
        if failed and self.process.poll() is None:
            self.process.kill()
        try:
            with selectors.DefaultSelector() as ready:
                ready.register(self.process.stdout, selectors.EVENT_READ, 'stdout')
                ready.register(self.process.stderr, selectors.EVENT_READ, 'stderr')
                while ready.get_map():
                    remaining = 60 - (time.monotonic() - started)
                    if remaining <= 0:
                        timed = True
                        self.process.kill()
                        break
                    events = ready.select(remaining)
                    if not events:
                        timed = True
                        self.process.kill()
                        break
                    for key, _ in events:
                        try:
                            raw = os.read(key.fd, 65536)
                        except BlockingIOError:
                            continue
                        if not raw:
                            ready.unregister(key.fileobj)
                            continue
                        self.streams[key.data].write(raw)
                        if key.data == 'stdout':
                            self.pending.extend(raw)
                        else:
                            self.stderr.extend(raw)
            code = self.process.wait(timeout=5)
        finally:
            self.process.stdout.close()
            self.process.stderr.close()
            streams = {name: value.close() for name, value in self.streams.items()}
        self.receipt = {'command': self.command, 'cwd': self.cwd, 'environment': ENVIRONMENT,
            'timeout_seconds': 60, 'elapsed_seconds': time.monotonic() - self.started,
            'exit_code': code, 'timed_out': timed, 'failure_cleanup_requested': failed,
            'unconsumed_stdout_bytes': len(self.pending), 'exchanges': len(self.records), **streams}
        (self.out / 'capture-process.json').write_text(json.dumps(self.receipt, sort_keys=True, indent=2) + '\n')
        if not failed and (code != self.expected_exit or timed or self.pending or bytes(self.stderr) != self.expected_stderr):
            raise AssertionError(('actual public termination differs', self.receipt))
        return self.receipt

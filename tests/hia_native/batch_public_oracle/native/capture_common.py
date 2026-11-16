"""Mechanical test I/O and owned fixtures; no filesystem tool implementation.

This module never computes an expected tool response or substitutes for HIA.
The native gateway/observer adapter is a separately bound, required input.
"""
from pathlib import Path
import gzip
import hashlib
import importlib.util
import json
import os
import selectors
import shutil
import signal
import stat
import subprocess
import time

FENCE_KEYS = ('HEPTA_EFFECT_OWNER_FENCE_DIR', 'HEPTA_EFFECT_OWNER_SELF', 'HEPTA_EFFECT_OWNER_FENCE_REQUIRED')
TRACE_ARGS = ['-f', '-qq', '-ttt', '-T', '-v', '-yy', '-s', '4096', '-xx', '-e', 'trace=%file,read,write,readv,writev,close,fstat,statx,getpgid,getdents64,flock,fcntl,dup,dup2,dup3,clone,clone3,fork,vfork,wait4,waitid,mmap,mremap,munmap,fsync,fdatasync,fchmod,fchown,getrandom,clock_gettime,gettimeofday,exit,exit_group']


def need(value, message):
    if not value: raise ValueError('filesystem SDK capture: '+message)
def sha(raw): return hashlib.sha256(raw).hexdigest()
def canonical(value): return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode()+b'\n'
def file_pin(path):
    with Path(path).open('rb') as stream: return {'bytes': Path(path).stat().st_size, 'sha256': hashlib.file_digest(stream, 'sha256').hexdigest()}
def capture_tool(path, output, name):
    path = Path(path).absolute(); resolved = path.resolve(strict=True)
    need('..' not in path.parts and resolved.is_file() and resolved.stat().st_mode & 0o111, 'actual selected executable')
    saved = Path(output)/('tool-'+name+'.bin')
    with resolved.open('rb') as source, saved.open('xb') as target: shutil.copyfileobj(source, target)
    pin = file_pin(saved)
    need(pin == file_pin(path) == file_pin(resolved), 'tool bytes changed during capture')
    return {'path': str(path), 'resolved_path': str(resolved), 'captured_file': saved.name, **pin}
def check_tool(tool):
    need(str(Path(tool['path']).resolve(strict=True)) == tool['resolved_path'], 'selected executable target changed')
    need(file_pin(tool['path']) == {key: tool[key] for key in ('bytes', 'sha256')}, 'selected executable bytes changed')
def dump(path, value):
    with Path(path).open('xb') as stream: stream.write(canonical(value))
def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path); result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result); return result
def bytes_path(value):
    need(type(value) is str and len(value) % 2 == 0, 'raw path hex'); return bytes.fromhex(value)
def path_text(value): return os.fsdecode(bytes_path(value))
def wire(action):
    need(action.get('kind') == 'public', 'public wire action')
    result = bytes.fromhex(action['wire_hex']) if 'wire_hex' in action else json.dumps(action['message'], sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()+b'\n'
    need(result.endswith(b'\n'), 'complete newline request'); return result


class Stream:
    def __init__(self, path):
        self.path = Path(path); self.file = self.path.open('xb')
        self.zipped = gzip.GzipFile(filename='', fileobj=self.file, mode='wb', compresslevel=6, mtime=0)
        self.digest = hashlib.sha256(); self.size = 0; self.closed = False
    def write(self, raw):
        need(not self.closed, 'closed stream'); self.zipped.write(raw); self.digest.update(raw); self.size += len(raw)
    def close(self):
        need(not self.closed, 'double stream close'); self.closed = True; self.zipped.close(); self.file.close()
        return {'path': str(self.path), 'uncompressed': {'bytes': self.size, 'sha256': self.digest.hexdigest()}, 'compressed': file_pin(self.path)}


class RecordedPublicProcess:
    """Drive actual stdio and retain ordinary EOF/BrokenPipe as observations.

    Every exchange and drain retains its actual 60-second deadline. A deadline
    failure is an execution failure, never a synthetic tool response. Input
    attempts and bytes actually accepted by the pipe are separate full streams.
    """
    def __init__(self, output, binary, cwd, *, strace, config=None, fence=None, trace=True, extra_argv=(), observer_fd=None):
        self.output = Path(output).absolute(); self.output.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.binary = Path(binary).absolute(); self.cwd = os.fsdecode(os.fsencode(cwd)); self.started = time.monotonic()
        self.argv = [str(self.binary), *extra_argv] + ([] if config is None else ['--runtime-config', str(Path(config).absolute())])
        self.trace = self.output/'native.strace' if trace else None
        self.command = [str(Path(strace).absolute()), *TRACE_ARGS, '-o', str(self.trace), '--', *self.argv] if trace else self.argv
        self.environment = {'PATH': '', 'LC_ALL': 'C', **(fence or {})}
        need(set(self.environment) <= {'PATH', 'LC_ALL', *FENCE_KEYS}, 'undeclared process environment')
        self.streams = {name: Stream(self.output/(name+'.bin.gz')) for name in ('attempted-stdin', 'stdin', 'stdout', 'stderr')}
        self.pending = bytearray(); self.scan_from = 0; self.exchanges = []; self.eof = {'stdout': False, 'stderr': False}
        self.started_error = None; self.closed = False; self.process = None
        inherited = () if observer_fd is None else (observer_fd,)
        try:
            self.process = subprocess.Popen(self.command, cwd=self.cwd, env=self.environment, stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=inherited, start_new_session=True)
            for stream in (self.process.stdin, self.process.stdout, self.process.stderr): os.set_blocking(stream.fileno(), False)
        except BaseException as error:
            self.started_error = repr(error); self._save_failure(); raise
        dump(self.output/'started.json', {'command': self.command, 'native_argv': self.argv, 'cwd': self.cwd,
            'environment': self.environment, 'pid': self.process.pid, 'binary': file_pin(self.binary), 'observer_fd': observer_fd})

    def _save_failure(self):
        streams = {name: value.close() for name, value in self.streams.items()}
        dump(self.output/'start-failure.json', {'command': self.command, 'native_argv': self.argv, 'cwd': self.cwd,
            'environment': self.environment, 'start_error': self.started_error, 'streams': streams})

    def _lines(self):
        lines = []
        while True:
            end = self.pending.find(b'\n', self.scan_from)
            if end < 0: self.scan_from = len(self.pending); return lines
            lines.append(bytes(self.pending[:end+1])); del self.pending[:end+1]; self.scan_from = 0

    def _read(self, ready, key, responses):
        try: raw = os.read(key.fd, 65536)
        except BlockingIOError: return
        if not raw:
            self.eof[key.data] = True; ready.unregister(key.fileobj); return
        self.streams[key.data].write(raw)
        if key.data == 'stdout': self.pending.extend(raw); responses.extend(self._lines())

    def exchange(self, request, *, response_count=1):
        need(not self.closed and type(request) is bytes and request.endswith(b'\n'), 'actual complete request')
        need(type(response_count) is int and response_count in (0, 1), 'declared notification/request shape')
        begin = time.monotonic(); attempted_at = self.streams['attempted-stdin'].size; stdin_at = self.streams['stdin'].size
        stdout_at = self.streams['stdout'].size; stderr_at = self.streams['stderr'].size; self.streams['attempted-stdin'].write(request)
        written = 0; replies = []; error = None; timed_out = False; transport = None
        try:
            with selectors.DefaultSelector() as ready:
                ready.register(self.process.stdin, selectors.EVENT_WRITE, 'stdin')
                for name in ('stdout', 'stderr'):
                    if not self.eof[name]: ready.register(getattr(self.process, name), selectors.EVENT_READ, name)
                while written < len(request) or len(replies) < response_count:
                    remaining = 60-(time.monotonic()-begin)
                    if remaining <= 0: timed_out = True; raise TimeoutError('actual public exchange exceeded 60 seconds')
                    events = ready.select(remaining)
                    if not events: timed_out = True; raise TimeoutError('actual public exchange exceeded 60 seconds')
                    # Consume already-visible EOF before accepting another input
                    # chunk. This changes no application bytes or expected reply.
                    events.sort(key=lambda item: item[0].data == 'stdin')
                    for key, _ in events:
                        if key.data != 'stdin': self._read(ready, key, replies); continue
                        try: count = os.write(key.fd, memoryview(request)[written:written+65536])
                        except BlockingIOError: continue
                        except BrokenPipeError as failure:
                            error = {'type': type(failure).__name__, 'errno': failure.errno, 'message': str(failure)}
                            transport = 'write-error'; ready.unregister(self.process.stdin); break
                        need(count > 0, 'actual stdin made no progress')
                        self.streams['stdin'].write(memoryview(request)[written:written+count]); written += count
                        if written == len(request): ready.unregister(self.process.stdin)
                    if transport == 'write-error': break
                    if self.eof['stdout'] and len(replies) < response_count: transport = 'eof'; break
                if transport is None: transport = 'notification' if response_count == 0 else 'response'
                need(len(replies) <= response_count, 'unexpected extra native response')
                if transport == 'response': need(len(replies) == response_count and written == len(request), 'incomplete successful public exchange')
                if transport in ('write-error', 'eof'): need(not replies, 'transport closed after a partial declared reply')
        except BaseException as failure:
            error = {'type': type(failure).__name__, 'message': str(failure), 'errno': getattr(failure, 'errno', None)}
            transport = 'execution-failure'; raise
        finally:
            record = {'index': len(self.exchanges), 'deadline_seconds': 60, 'elapsed_seconds': time.monotonic()-begin,
                'timed_out': timed_out, 'transport': transport, 'error': error,
                'attempted_input': {'offset': attempted_at, 'bytes': len(request), 'sha256': sha(request)},
                'accepted_input': {'offset': stdin_at, 'bytes': written, 'sha256': sha(request[:written])},
                'stdout_range': {'offset': stdout_at, 'bytes': self.streams['stdout'].size-stdout_at},
                'stderr_range': {'offset': stderr_at, 'bytes': self.streams['stderr'].size-stderr_at},
                'responses': [{'bytes': len(value), 'sha256': sha(value)} for value in replies],
                'stdout_eof': self.eof['stdout'], 'stderr_eof': self.eof['stderr']}
            self.exchanges.append(record)
            (self.output/'exchanges.json').write_bytes(canonical(self.exchanges))
        return record, replies

    def close(self, *, failed=False):
        need(not self.closed, 'double process finalization'); self.closed = True; begin = time.monotonic(); timed = False
        wait_timed_out = False; cleanup_error = None; code = None; killed_at = None
        def terminate():
            nonlocal killed_at
            if killed_at is None: killed_at = time.monotonic()
            try: os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
        try: self.process.stdin.close()
        except (BrokenPipeError, OSError): pass
        if failed and self.process.poll() is None: terminate()
        try:
            with selectors.DefaultSelector() as ready:
                for name in ('stdout', 'stderr'):
                    if not self.eof[name]: ready.register(getattr(self.process, name), selectors.EVENT_READ, name)
                while ready.get_map():
                    # A failed deadline remains a failure. After killing the
                    # owned process group, retain bytes already in its pipes.
                    remaining = (60-(time.monotonic()-begin)) if killed_at is None else (5-(time.monotonic()-killed_at))
                    if remaining <= 0:
                        if killed_at is not None: break
                        timed = True; terminate(); continue
                    events = ready.select(remaining)
                    if not events:
                        if killed_at is not None: break
                        timed = True; terminate(); continue
                    for key, _ in events:
                        try: raw = os.read(key.fd, 65536)
                        except BlockingIOError: continue
                        if not raw: self.eof[key.data] = True; ready.unregister(key.fileobj); continue
                        self.streams[key.data].write(raw)
                        if key.data == 'stdout': self.pending.extend(raw)
            try: code = self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                wait_timed_out = True; terminate()
                try: code = self.process.wait(timeout=5)
                except subprocess.TimeoutExpired: cleanup_error = 'owned process did not exit after SIGKILL within five seconds'
        except BaseException as error:
            cleanup_error = repr(error); terminate()
            try: code = self.process.wait(timeout=5)
            except subprocess.TimeoutExpired: wait_timed_out = True
        finally:
            self.process.stdout.close(); self.process.stderr.close()
            streams = {name: value.close() for name, value in self.streams.items()}
        receipt = {'command': self.command, 'native_argv': self.argv, 'cwd': self.cwd, 'environment': self.environment,
            'pid': self.process.pid, 'exit_code': code, 'timed_out': timed, 'drain_deadline_seconds': 60,
            'drain_elapsed_seconds': time.monotonic()-begin, 'elapsed_seconds': time.monotonic()-self.started,
            'failure_cleanup_requested': failed, 'start_error': None, 'exchanges': len(self.exchanges), 'streams': streams,
            'wait_deadline_seconds': 5, 'wait_timed_out': wait_timed_out, 'cleanup_error': cleanup_error,
            'kill_cleanup_deadline_seconds': 5, 'kill_requested': killed_at is not None, 'pipe_eof': dict(self.eof),
            'unconsumed_stdout': {'bytes': len(self.pending), 'sha256': sha(self.pending)}, 'binary': file_pin(self.binary)}
        if self.trace is not None and self.trace.exists(): receipt['trace'] = {'path': str(self.trace), **file_pin(self.trace)}
        dump(self.output/'process.json', receipt)
        need(not timed and not wait_timed_out and cleanup_error is None, 'actual process termination deadline/failure')
        need(all(self.eof.values()), 'actual capture ended without complete pipe EOF')
        need(failed or code == 0, 'actual public process nonzero exit')
        need(failed or not self.pending, 'native process returned unclaimed stdout')
        return receipt


class OwnedFixture:
    """Only the newly allocated fixture tree is mutable; saved evidence is outside it."""
    def __init__(self, root, *, create=False):
        self.root = Path(root).absolute()
        if create: self.root.mkdir(mode=0o700, parents=True, exist_ok=False)
        need(self.root.is_dir() and not self.root.is_symlink(), 'owned fixture root')
        self.identity = (self.root.stat().st_dev, self.root.stat().st_ino, self.root.stat().st_uid)

    def owned(self, raw, *, allow_root=False):
        path = Path(os.fsdecode(raw)); need(path.is_absolute() and '..' not in path.parts and path.is_relative_to(self.root), 'fixture path escape')
        need(allow_root or path != self.root, 'operation would remove fixture root')
        need((self.root.stat().st_dev, self.root.stat().st_ino, self.root.stat().st_uid) == self.identity, 'fixture root identity changed')
        current = self.root
        for part in path.relative_to(self.root).parts[:-1]:
            current /= part
            if current.exists() or current.is_symlink(): need(stat.S_ISDIR(current.lstat().st_mode) and not current.is_symlink(), 'fixture action through symlink/nondirectory parent')
        return path

    def actions(self, actions):
        records = []
        for action in actions:
            path = self.owned(bytes_path(action['path_hex'])); kind = action['kind']; started = time.monotonic()
            if kind == 'mkdir': path.mkdir(mode=0o777, parents=True, exist_ok=True)
            elif kind == 'write': path.write_bytes(bytes.fromhex(action['data_hex']))
            elif kind == 'symlink': os.symlink(bytes_path(action['target_hex']), os.fsencode(path))
            elif kind == 'hardlink': os.link(self.owned(bytes_path(action['target_hex'])), path)
            elif kind == 'chmod': need(not path.is_symlink(), 'fixture chmod symlink'); path.chmod(action['mode'])
            elif kind == 'remove_file': path.unlink()
            elif kind == 'remove_dir': path.rmdir()
            elif kind == 'rename': path.rename(self.owned(bytes_path(action['target_hex'])))
            elif kind == 'fifo': os.mkfifo(path, 0o600)
            else: raise ValueError('undeclared fixture action '+kind)
            records.append({'action': action, 'status': 'EXECUTED', 'elapsed_seconds': time.monotonic()-started})
        return records

    def remove_tree(self, raw):
        path = self.owned(raw); removed = []
        def remove(current):
            metadata = current.lstat()
            need(metadata.st_uid == self.identity[2] and metadata.st_dev == self.identity[0], 'foreign fixture entry in cleanup')
            if stat.S_ISDIR(metadata.st_mode):
                current.chmod(stat.S_IMODE(metadata.st_mode) | 0o700)
                with os.scandir(current) as entries: children = sorted((Path(entry.path) for entry in entries), key=os.fsencode)
                for child in children: remove(child)
                current.rmdir()
            else: current.unlink()
            removed.append({'path_hex': os.fsencode(current).hex(), 'device': metadata.st_dev, 'inode': metadata.st_ino, 'mode': metadata.st_mode})
        if path.exists() or path.is_symlink(): remove(path)
        return removed

    def snapshot(self, roots):
        result = []
        def walk(path, base, rows):
            row = {'relative_hex': os.fsencode(path.relative_to(base)).hex() if path != base else ''}
            try: meta = path.lstat()
            except OSError as error: row['errno'] = error.errno; rows.append(row); return
            row.update(device=meta.st_dev, inode=meta.st_ino, mode=meta.st_mode, uid=meta.st_uid, gid=meta.st_gid,
                links=meta.st_nlink, size=meta.st_size, mtime=[meta.st_mtime_ns//1_000_000_000, meta.st_mtime_ns%1_000_000_000],
                ctime=[meta.st_ctime_ns//1_000_000_000, meta.st_ctime_ns%1_000_000_000])
            if stat.S_ISLNK(meta.st_mode):
                try: row['target_hex'] = os.fsencode(os.readlink(path)).hex()
                except OSError as error: row['readlink_errno'] = error.errno
            elif stat.S_ISREG(meta.st_mode):
                try: row['content_hex'] = path.read_bytes().hex()
                except OSError as error: row['read_errno'] = error.errno
            if stat.S_ISDIR(meta.st_mode):
                try:
                    with os.scandir(path) as entries: children = sorted((Path(entry.path) for entry in entries), key=os.fsencode)
                except OSError as error: row['readdir_errno'] = error.errno
                else:
                    rows.append(row)
                    for child in children: walk(child, base, rows)
                    return
            rows.append(row)
        for raw in roots:
            path = self.owned(bytes_path(raw), allow_root=True); rows = []; walk(path, path, rows); result.append({'root_hex': raw, 'nodes': rows})
        return result


def structural_snapshots(sequence):
    """Compare full state while retaining per-run object identity relationships.

    No path/string replacement occurs. Numeric inode identities and absolute
    timestamps cannot be equal across separately restored runs; all originals
    remain in the complete snapshots. First-observation identity labels retain
    hard links, moved objects and unchanged objects across the entire scenario.
    """
    identities = {}; result = []
    for trees in sequence:
        current = []
        for tree in trees:
            nodes = []
            for node in tree['nodes']:
                value = dict(node)
                if 'inode' in value:
                    identity = (value.pop('device'), value.pop('inode')); label = identities.setdefault(identity, len(identities))
                    value['identity'] = label; value.pop('mtime'); value.pop('ctime')
                    # Directory byte allocation is filesystem metadata; entry
                    # names, identity, permissions, links and content are exact.
                    if stat.S_ISDIR(value['mode']): value.pop('size')
                nodes.append(value)
            current.append({'root_hex': tree['root_hex'], 'nodes': nodes})
        result.append(current)
    return result

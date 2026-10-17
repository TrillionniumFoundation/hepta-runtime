# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Owned real pipes, durable output and DC line cursors; never replay a journal.

A previous manager's PID is historical evidence only. Its stdin/pipe ownership
cannot be recovered from disk and is never inferred from a matching PID.
"""
from __future__ import annotations
import asyncio
import codecs
import collections
import contextlib
import math
import fcntl
import json
import os
import pathlib
import re
import selectors
import shlex
import shutil
import signal
import stat
import subprocess
import threading
import time
import uuid
from .registry import ToolError, text_result

TOOL_NAMES = frozenset({'start_process', 'read_process_output', 'interact_with_process',
                       'force_terminate', 'list_sessions', 'list_processes', 'kill_process'})
PROMPT = re.compile(r'(?:>>>|>|\$|#)\s*$')
REPL_PROMPTS = ('>>> ', '... ', '> ', '+ ', 'julia> ', '       ', '$ ', '# ', '% ',
                'bash-', 'zsh-', 'mysql> ', '    -> ', '=# ', '-# ', 'redis> ')
MAX_BUFFER_CHARS = 50 * 1024 * 1024


def _detected_prompt(output):
    # Match DC's comprehensive last-line detection, including continuation
    # prompts which its immediate >/$/# pattern deliberately does not cover.
    if not output.strip(): return None
    last = output.rsplit('\n', 1)[-1]
    return next((prompt for prompt in REPL_PROMPTS if prompt in last), None)


def _ssh_command(command):
    if command.lstrip().startswith('ssh ') and ' -t' not in command:
        return re.sub(r'^(\s*)ssh ', r'\1ssh -t ', command, count=1)
    return command


class _Timing:
    """Per-call telemetry only; completed calls retain no live observers."""
    def __init__(self):
        self.started, self.events = time.monotonic(), []

    def record(self, text, source):
        if text:
            self.events.append((time.monotonic(), source, len(text), text[:50].replace('\n', '\\n')))

    def format(self, reason):
        reason = {'completed': 'process_exit', 'unknown': 'collection_unknown'}.get(reason, reason)
        message = '\n\n📊 Timing Information:\n'
        message += f'  Exit Reason: {reason}\n  Total Duration: {round((time.monotonic()-self.started)*1000)}ms\n'
        if self.events:
            message += f'  Time to First Output: {round((self.events[0][0]-self.started)*1000)}ms\n'
            message += f'  Output Window: {round((self.events[-1][0]-self.events[0][0])*1000)}ms\n'
            message += f'\n  Output Events ({len(self.events)} total):\n'
            for index, (at, source, length, snippet) in enumerate(self.events, 1):
                matched = ''
                if index == len(self.events) and reason.startswith('early_exit_'):
                    matched = ' | 🎯 ' + ('quick_pattern' if reason.endswith('quick_pattern') else 'periodic_check')
                message += f'    [{index}] +{round((at-self.started)*1000)}ms | {source} | {length}b{matched}\n       "{snippet}"\n'
        return message


def _integer(value, name, minimum=None, maximum=None):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or int(value) != value:
        raise ToolError(name + ' must be an integer')
    value = int(value)
    if minimum is not None and value < minimum or maximum is not None and value > maximum:
        raise ToolError(name + ' is outside the configured range')
    return value


def _stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)


def _private_root(path):
    path = pathlib.Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ToolError('process state must be an absolute private directory')
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open('/', os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for index, part in enumerate(path.parts[1:]):
            flags = os.O_RDONLY if index == len(path.parts) - 2 else os.O_PATH
            following = os.open(part, flags | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd); fd = following
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ToolError('process state must have owner-only mode 0700')
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read_file(directory, name, maximum):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1 or maximum is not None and before.st_size > maximum):
            raise ToolError('unsafe process journal member')
        raw = bytearray()
        while len(raw) < before.st_size:
            block = os.read(fd, min(65536, before.st_size - len(raw)))
            if not block: break
            raw.extend(block)
        if len(raw) != before.st_size or _stamp(before) != _stamp(os.fstat(fd)):
            raise ToolError('process journal changed during read')
        return bytes(raw)
    finally: os.close(fd)


def _publish(directory, name, value):
    raw = json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode()
    temporary = '.tmp-' + uuid.uuid4().hex
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
    try:
        with os.fdopen(fd, 'wb') as output:
            output.write(raw); output.flush(); os.fsync(output.fileno())
        os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        try: os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError: pass


class _Session:
    def __init__(self, journal_id, metadata, process=None):
        self.journal_id, self.metadata, self.process = journal_id, metadata, process
        self.condition = threading.Condition(threading.RLock())
        self.input_lock = threading.Lock()
        self.fragments, self.chars, self.total_chars = collections.deque(), 0, 0
        self.cursor, self.log_bytes, self.evicted_chars = 0, 0, 0
        self.last_output, self.first_output, self.collector = None, None, None
        self.responders = 1 if process is not None else 0
        self.stop_collect = threading.Event()
        self.observers = set()

    def append(self, text):
        if not text: return
        self.fragments.append(text); self.chars += len(text); self.total_chars += len(text)
        while self.chars > MAX_BUFFER_CHARS:
            excess = self.chars - MAX_BUFFER_CHARS
            first = self.fragments.popleft()
            if len(first) > excess:
                self.fragments.appendleft(first[excess:]); removed = excess
            else: removed = len(first)
            self.chars -= removed; self.evicted_chars += removed
        self.first_output = self.first_output or time.monotonic()
        self.last_output = time.monotonic()

    def text(self): return ''.join(self.fragments)

    def tail(self, length=4096):
        parts, used = [], 0
        for fragment in reversed(self.fragments):
            parts.append(fragment); used += len(fragment)
            if used >= length: break
        return ''.join(reversed(parts))[-length:]

    def observe(self, text, source):
        for observer in self.observers: observer.record(text, source)


class ProcessManager:
    tool_names = TOOL_NAMES

    def __init__(self, state_dir, cwd, *, config=None, shell=None):
        self.config, self.shell = config if config is not None else {}, shell
        self.cwd = pathlib.Path(cwd).resolve(strict=True)
        if not self.cwd.is_dir(): raise ToolError('process cwd must be a directory')
        self.state_dir = pathlib.Path(state_dir)
        self.directory = _private_root(self.state_dir)
        self.lock_fd = os.open('manager.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=self.directory)
        self.sessions, self.history, self.virtual = {}, {}, {}
        self._lock = threading.RLock()
        self._close_lock = threading.Lock()
        self._lifecycle = threading.Condition(threading.RLock())
        self._workers, self.closed, self._released = 0, False, False
        try:
            info = os.fstat(self.lock_fd)
            if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.getuid() or info.st_nlink != 1:
                raise ToolError('unsafe process owner lock')
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._load_history()
        except BaseException:
            os.close(self.lock_fd); os.close(self.directory); raise

    def _config(self, key, default): return self.config.get(key, default)

    @contextlib.contextmanager
    def _session_directory(self, identity):
        fd = os.open(identity, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.directory)
        try:
            info = os.fstat(fd)
            if stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid():
                raise ToolError('unsafe process journal directory')
            yield fd
        finally: os.close(fd)

    def _metadata(self, identity):
        with self._session_directory(identity) as fd:
            value = json.loads(_read_file(fd, 'metadata.json', None))
        if not isinstance(value, dict) or value.get('journal_id') != identity:
            raise ToolError('process journal identity mismatch')
        if (type(value.get('pid')) not in (int, type(None)) or not isinstance(value.get('started_at'), (int, float))
                or not math.isfinite(value['started_at'])):
            raise ToolError('invalid process metadata')
        return value

    def _load_history(self):
        # Build only a tiny PID lookup. Never load output or retain the command
        # for every historical job. There is no lifetime journal-count cutoff.
        for name in os.listdir(self.directory):
            if not re.fullmatch(r'[0-9a-f]{32}', name):
                if name in ('manager.lock', '.kill-intent.json') or name.startswith('.tmp-'): continue
                raise ToolError('unexpected process journal member')
            metadata = self._metadata(name)
            pid = metadata.get('pid')
            if type(pid) is int:
                old = self.history.get(pid)
                if old is None or metadata['started_at'] > old['started_at']:
                    self.history[pid] = {'journal_id': name, 'started_at': metadata['started_at']}

    def _publish_session(self, session):
        with self._session_directory(session.journal_id) as fd:
            _publish(fd, 'metadata.json', session.metadata)

    def _release_response(self, session):
        with session.condition:
            session.responders -= 1
            if not session.responders and session.metadata['state'] != 'running':
                session.fragments.clear(); session.chars = 0; session.evicted_chars = session.total_chars

    @contextlib.contextmanager
    def _response_buffer(self, session):
        with session.condition: session.responders += 1
        try: yield
        finally: self._release_response(session)

    @contextlib.contextmanager
    def _timing_observer(self, session, timing):
        with session.condition:
            if timing is not None: session.observers.add(timing)
        try: yield
        finally:
            with session.condition:
                if timing is not None: session.observers.discard(timing)

    def _prune_completed_memory(self):
        with self._lock:
            for pid, session in list(self.sessions.items()):
                if (session.metadata['state'] == 'completed' and session.responders == 0
                        and session.collector is not None and not session.collector.is_alive()):
                    self.history[pid] = {'journal_id': session.journal_id, 'started_at': session.metadata['started_at']}
                    del self.sessions[pid]

    def _new_session(self, command, shell):
        maximum = self._config('processOutputMaxBytes', None)
        if maximum is not None: maximum = _integer(maximum, 'processOutputMaxBytes', 0)
        identity = uuid.uuid4().hex
        os.mkdir(identity, 0o700, dir_fd=self.directory)
        metadata = {'journal_id': identity, 'pid': None, 'command': command, 'shell': shell,
                    'cwd': str(self.cwd), 'state': 'accepted', 'started_at': time.time(),
                    'automatic_replay': False, 'output_max_bytes': maximum}
        with self._session_directory(identity) as fd:
            for name in ('stdout.log', 'stderr.log', 'combined.log'):
                leaf = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
                os.close(leaf)
            _publish(fd, 'metadata.json', metadata)
        session = _Session(identity, metadata)
        session.responders = 1  # Claimed before a fast child can complete.
        return session

    @staticmethod
    def _write_all(fd, data):
        view = memoryview(data)
        while view:
            count = os.write(fd, view)
            if count <= 0: raise OSError('output journal write made no progress')
            view = view[count:]

    def _collect(self, session):
        process, selection = session.process, selectors.DefaultSelector()
        logs, decoders, durable_decoders = {}, {}, {}
        maximum = session.metadata['output_max_bytes']
        try:
            with self._session_directory(session.journal_id) as directory:
                for name in ('stdout', 'stderr', 'combined'):
                    fd = os.open(name + '.log', os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
                    info = os.fstat(fd)
                    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
                        os.close(fd); raise ToolError('unsafe process output member')
                    logs[name] = fd
            for source, pipe in (('stdout', process.stdout), ('stderr', process.stderr)):
                os.set_blocking(pipe.fileno(), False)
                selection.register(pipe, selectors.EVENT_READ, source)
                decoders[source] = codecs.getincrementaldecoder('utf-8')('replace')
                durable_decoders[source] = codecs.getincrementaldecoder('utf-8')('replace')
            interrupted = False
            while selection.get_map():
                for key, _ in selection.select(0.1):
                    raw = os.read(key.fd, 65536); source = key.data
                    if not raw:
                        # Persist the decoder's EOF replacement, including an
                        # incomplete UTF-8 codepoint, just like the live result.
                        tail = decoders[source].decode(b'', final=True)
                        durable_tail = durable_decoders[source].decode(b'', final=True)
                        self._write_all(logs['combined'], durable_tail.encode())
                        with session.condition:
                            session.append(tail); session.observe(tail, source); session.condition.notify_all()
                        selection.unregister(key.fileobj); key.fileobj.close(); continue
                    text = decoders[source].decode(raw)
                    retained = raw if maximum is None else raw[:max(0, maximum - session.log_bytes)]
                    self._write_all(logs[source], retained)
                    self._write_all(logs['combined'], durable_decoders[source].decode(retained).encode())
                    with session.condition:
                        session.append(text); session.log_bytes += len(retained)
                        session.observe(text, source)
                        if len(retained) != len(raw): session.metadata['durable_output_truncated'] = True
                        session.condition.notify_all()
                if session.stop_collect.is_set() and selection.get_map() and process.poll() is not None:
                    # The owned leader exited, but a background descendant may
                    # still hold inherited pipes. Do not infer signal ownership
                    # from an old numeric PID/group or hang shutdown forever.
                    interrupted = True
                    break
            returncode = process.wait()
            for fd in logs.values(): os.fsync(fd)
            with session.condition:
                session.metadata.update(state='unknown' if interrupted else 'completed', exit_code=returncode,
                                        finished_at=time.time(), durable_raw_bytes=session.log_bytes)
                if interrupted:
                    session.metadata.update(durable_output_incomplete=True,
                                            collection_error='inherited_pipe_eof_unavailable_during_shutdown')
                if not session.responders:
                    session.fragments.clear(); session.chars = 0; session.evicted_chars = session.total_chars
                self._publish_session(session); session.condition.notify_all()
            with session.input_lock:
                if process.stdin is not None: process.stdin.close()
        except BaseException as exc:
            with session.condition:
                session.metadata.update(state='unknown', collection_error=type(exc).__name__)
                try: self._publish_session(session)
                finally: session.condition.notify_all()
        finally:
            selection.close()
            for pipe in (process.stdout, process.stderr):
                try: pipe.close()
                except OSError: pass
            for fd in logs.values():
                try: os.fsync(fd)
                finally: os.close(fd)

    def _wait(self, session, timeout_ms, *, snapshot=None, require_new=False, until_exit=False):
        started = time.monotonic()
        deadline, periodic = started + timeout_ms / 1000, started + 0.1
        with session.condition:
            while session.metadata['state'] == 'running':
                available = session.total_chars if snapshot is None else session.total_chars - snapshot
                tail = session.tail(min(4096, available)) if available else ''
                if not until_exit:
                    if not require_new and tail and PROMPT.search(tail): return 'early_exit_quick_pattern'
                    if time.monotonic() >= periodic:
                        if not require_new and _detected_prompt(tail): return 'early_exit_periodic_check'
                        periodic = time.monotonic() + 0.1
                    if require_new and session.total_chars: return 'new_output'
                remaining = deadline - time.monotonic()
                if remaining <= 0: return 'timeout'
                session.condition.wait(min(remaining, 0.05))
            return session.metadata['state']

    def _find(self, pid):
        pid = _integer(pid, 'pid', 1)
        with self._lock:
            session = self.sessions.get(pid)
            reference = self.history.get(pid)
        if session is not None: return session
        if reference is None: raise ToolError('No session found for PID ' + str(pid))
        metadata = self._metadata(reference['journal_id'])
        if metadata.get('pid') != pid: raise ToolError('process history PID changed')
        if metadata.get('state') not in ('completed', 'spawn_failed'):
            metadata = dict(metadata, state='unknown', pipe_ownership='unavailable_after_restart', automatic_replay=False)
        return _Session(reference['journal_id'], metadata)

    def _spawn(self, command, shell, argv, *, timing=None):
        # close() and the entire admission-to-registration interval share this
        # lock, so a queued worker can never spawn after ownership is released.
        with self._lifecycle:
            if self.closed: raise ToolError('process manager is closing; no process started')
            self._prune_completed_memory()
            session = self._new_session(command, shell)
            if timing is not None: session.observers.add(timing)
            try:
                process = subprocess.Popen(argv, cwd=self.cwd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE, start_new_session=True,
                                           env=dict(os.environ, TERM='xterm-256color'), bufsize=0)
                session.process = process
                session.metadata.update(pid=process.pid, state='running', pipe_ownership='this_manager')
                self._publish_session(session)
                with self._lock: self.sessions[process.pid] = session
                session.collector = threading.Thread(target=self._collect, args=(session,), daemon=True)
                session.collector.start()
                return session
            except BaseException as exc:
                if session.process is not None:
                    try: os.killpg(session.process.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                    session.process.wait(); session.metadata['state'] = 'unknown'
                else: session.metadata['state'] = 'spawn_failed'
                self._publish_session(session)
                if session.process is not None:
                    raise ToolError('Process dispatch outcome unknown; never replay automatically') from exc
                raise

    def _start(self, args):
        command = args.get('command')
        if not isinstance(command, str) or not command: raise ToolError('command must be a nonempty string')
        timeout = _integer(args.get('timeout_ms'), 'timeout_ms', 0)
        shell = args.get('shell') or self.shell or self._config('defaultShell', os.environ.get('SHELL') or '/bin/sh')
        if not isinstance(shell, str) or not shell: raise ToolError('shell must be a string')
        validator = getattr(self.config, 'validate_command', None)
        if validator:
            if validator(command) is False: raise ToolError('Command not allowed: ' + command)
        else:
            words = shlex.split(command)
            if words and pathlib.PurePath(words[0]).name in set(self._config('blockedCommands', [])):
                raise ToolError('Command not allowed: ' + command)
        if command.strip() == 'node:local':
            node = shutil.which('node')
            if not node: raise ToolError('Independent system Node.js is unavailable')
            with self._lifecycle:
                if self.closed: raise ToolError('process manager is closing')
                with self._lock:
                    pid = min([-1000] + list(self.virtual)) - 1
                    self.virtual[pid] = {'node': node, 'timeout_ms': timeout}
            return text_result(f'Node.js session started with PID {pid} (independent execution)\nEach interact_with_process call runs as a FRESH script. State is NOT preserved between calls.')
        timing = _Timing() if args.get('verbose_timing', False) else None
        session = self._spawn(command, shell, [shell, '-lc' if pathlib.PurePath(shell).name in ('bash', 'zsh') else '-c', _ssh_command(command)], timing=timing)
        try:
            reason = self._wait(session, timeout)
            with session.condition:
                output = session.text()
                if len(output) > 2 * 1024 * 1024:
                    output = '[Initial output truncated; use read_process_output for the complete durable output]\n' + output[-1024 * 1024:]
                status = '\n⏳ Process is running. Use read_process_output to get more output.' if reason == 'timeout' else ''
                if session.metadata['state'] == 'completed': status = f"\n✅ Process completed with exit code {session.metadata['exit_code']}"
                if session.metadata['state'] == 'unknown': status = '\nProcess outcome or output collection is unknown; never replay automatically.'
                if reason.startswith('early_exit_'): status = '\n🔄 Process appears to be waiting for input.'
                if timing is not None: status += timing.format(reason)
                return text_result(f'Process started with PID {session.process.pid} (shell: {shell})\nInitial output:\n{output}{status}')
        finally:
            if timing is not None:
                with session.condition: session.observers.discard(timing)
            self._release_response(session)

    def _disk_page(self, session, offset, length):
        # Count and select from a single file descriptor and a fixed prefix.
        # Appends may continue; no page ever mixes two path/inode generations.
        with self._session_directory(session.journal_id) as directory:
            fd = os.open('combined.log', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
                raise ToolError('unsafe process output member')
            size, newlines, last = info.st_size, 0, b''
            position = 0
            while position < size:
                block = os.read(fd, min(65536, size - position))
                if not block: raise ToolError('process output was truncated during read')
                position += len(block); newlines += block.count(b'\n'); last = block[-1:]
            total = newlines + 1 if size else 0
            complete = session.metadata['state'] == 'completed'
            start = max(0, total + offset) if offset < 0 else (0 if complete else session.cursor) if offset == 0 else offset
            stop = min(total, start + length)
            os.lseek(fd, 0, os.SEEK_SET)
            chunks, position, line = [], 0, 0
            while position < size and line < stop:
                block = os.read(fd, min(65536, size - position)); position += len(block)
                if not block: raise ToolError('process output was truncated during read')
                beginning = 0
                for boundary in [match.start() for match in re.finditer(b'\n', block)]:
                    if start <= line < stop:
                        chunks.append(block[beginning:boundary])
                        if line + 1 < stop: chunks.append(b'\n')
                    line += 1; beginning = boundary + 1
                if start <= line < stop: chunks.append(block[beginning:])
            after = os.fstat(fd)
            if after.st_dev != info.st_dev or after.st_ino != info.st_ino or after.st_size < size:
                raise ToolError('process output identity or prefix changed')
            count = max(0, stop - start)
            return b''.join(chunks).decode('utf-8', 'replace'), total, start, count, max(0, total - start - count)
        finally: os.close(fd)

    def _read(self, args):
        started = time.monotonic()
        session = self._find(args.get('pid'))
        offset = _integer(args.get('offset', 0), 'offset')
        length = _integer(args.get('length', self._config('fileReadLineLimit', 1000)), 'length', 0)
        timeout = _integer(args.get('timeout_ms', 5000), 'timeout_ms', 0)
        if offset == 0 and session.process is not None and session.metadata['state'] == 'running':
            deadline = time.monotonic() + timeout / 1000
            with session.condition:
                while session.metadata['state'] == 'running':
                    _, total, _, _, _ = self._disk_page(session, 0, 0)
                    if total > session.cursor or time.monotonic() >= deadline: break
                    session.condition.wait(min(0.05, max(0, deadline - time.monotonic())))
        with session.condition:
            output, total, start, count, remaining = self._disk_page(session, offset, length)
            complete = session.metadata['state'] == 'completed'
            if offset == 0 and not complete: session.cursor = start + count
            if offset < 0: status = f'[Reading last {count} lines (total: {total} lines)]'
            elif offset == 0:
                status = f'[Reading {count} new lines' + (f' from line {start} (total: {total} lines, {remaining} remaining)]' if remaining else f' (total: {total} lines)]')
            else: status = f'[Reading {count} lines from line {start} (total: {total} lines, {remaining} remaining)]'
            if session.metadata.get('durable_output_truncated'):
                status += f'\n[WARNING: explicit processOutputMaxBytes={session.metadata.get("output_max_bytes")} quota was exceeded; durable output is incomplete]'
            if session.metadata.get('durable_output_incomplete'):
                status += '\n[WARNING: shutdown occurred before inherited output pipes reached EOF; durable output is an incomplete observed prefix]'
            suffix = f"\n✅ Process completed with exit code {session.metadata['exit_code']}" if complete else ''
            if not complete and session.process is not None and (PROMPT.search(session.tail()) or _detected_prompt(session.tail())):
                suffix += f'\n🔄 Process {session.metadata["pid"]} is waiting for input'
            if session.metadata['state'] == 'unknown': suffix += '\nProcess state unknown; previous stdin/pipe ownership is unavailable. Never replay automatically.'
            if args.get('verbose_timing', False): suffix += f'\n\n📊 Timing: {round((time.monotonic()-started)*1000)}ms'
            return text_result(status + '\n\n' + (output or '(No output in requested range)') + suffix)

    def _interact(self, args):
        pid = _integer(args.get('pid'), 'pid'); text = args.get('input')
        if not isinstance(text, str): raise ToolError('input must be a string')
        timeout = _integer(args.get('timeout_ms', 8000), 'timeout_ms', 0)
        with self._lock: virtual = self.virtual.get(pid)
        if virtual is not None:
            session = self._spawn('node:local script', virtual['node'], [virtual['node'], '--input-type=module', '-e', text])
            try:
                reason = self._wait(session, timeout, until_exit=True)
                if reason == 'timeout': self._force({'pid': session.process.pid})
                session.collector.join()
                output, _, _, _, _ = self._disk_page(session, 0, 2**63)
                return text_result(output or '(no output)', is_error=session.metadata.get('exit_code') != 0)
            finally:
                self._release_response(session)
        session = self._find(pid)
        timing = _Timing() if args.get('verbose_timing', False) else None
        with self._response_buffer(session), session.input_lock, self._timing_observer(session, timing):
            with session.condition:
                if session.process is None or session.process.poll() is not None or session.metadata['state'] != 'running':
                    raise ToolError(f'Failed to send input to process {pid}; live stdin ownership is unavailable')
                snapshot = session.total_chars
                session.metadata['last_input'] = {'id': uuid.uuid4().hex, 'bytes': len(text.encode()), 'state': 'intent'}
                self._publish_session(session)
            try:
                raw = (text if text.endswith('\n') else text + '\n').encode(); view = memoryview(raw)
                while view:
                    written = os.write(session.process.stdin.fileno(), view)
                    if written <= 0: raise OSError('stdin write made no progress')
                    view = view[written:]
            except OSError as exc:
                with session.condition:
                    session.metadata['last_input']['state'] = 'unknown_no_replay'; self._publish_session(session)
                raise ToolError('Input write outcome unknown; never replay automatically') from exc
            with session.condition:
                session.metadata['last_input']['state'] = 'written'; self._publish_session(session)
            if args.get('wait_for_prompt', True) is False:
                with session.condition:
                    if timing is not None: session.observers.discard(timing)
                    telemetry = timing.format('no_wait') if timing is not None else ''
                return text_result(f'✅ Input sent to process {pid}. Use read_process_output to get the response.{telemetry}')
            reason = self._wait(session, timeout, snapshot=snapshot)
            with session.condition:
                output = session.text()[max(0, snapshot - session.evicted_chars):]
                maximum = _integer(self._config('fileReadLineLimit', 1000), 'fileReadLineLimit', 1)
                lines = output.split('\n')
                if len(lines) > maximum: output = '\n'.join(lines[:maximum]) + '\n[Output truncated; use read_process_output with offset/length]'
                if snapshot < session.evicted_chars: output = '[Live response exceeded the 50MiB memory tail; full durable output remains readable]\n' + output
                status = '\n⏱️ Response may be incomplete (timeout reached)' if reason == 'timeout' else ''
                if reason.startswith('early_exit_'): status += f'\n🔄 Process {pid} is waiting for input'
                if timing is not None:
                    session.observers.discard(timing)
                    status += timing.format(reason)
                return text_result(f'✅ Input executed in process {pid}:\n\n📤 Output:\n{output or "(No output produced)"}{status}')

    def _force(self, args):
        pid = _integer(args.get('pid'), 'pid')
        with self._lock:
            if pid in self.virtual:
                del self.virtual[pid]; return text_result(f'Cleared virtual Node.js session {pid}')
            session = self.sessions.get(pid)
        if session is None or session.process is None or session.process.poll() is not None:
            return text_result(f'No active session found for PID {pid}')
        with session.condition:
            session.metadata['termination_intent'] = {'signal': 'SIGINT', 'at': time.time()}; self._publish_session(session)
        os.killpg(session.process.pid, signal.SIGINT)
        try: session.process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            if session.process.poll() is None: os.killpg(session.process.pid, signal.SIGKILL)
        return text_result(f'Successfully initiated termination of session {pid}')

    def _list_sessions(self):
        with self._lock:
            rows = [f'PID: {pid}, Blocked: {str(bool(PROMPT.search(session.tail()) or _detected_prompt(session.tail()))).lower()}, Runtime: {round(time.time()-session.metadata["started_at"])}s'
                    for pid, session in self.sessions.items() if session.process.poll() is None]
            rows.extend(f'PID: {pid} (node:local), Timeout: {session["timeout_ms"]}ms' for pid, session in self.virtual.items())
        return text_result('\n'.join(rows) if rows else 'No active sessions')

    def _list_processes(self):
        result = subprocess.run(['ps', 'aux'], capture_output=True, check=True, timeout=10, text=True)
        rows = []
        for line in result.stdout.splitlines()[1:]:
            fields = line.split(None, 10)
            if len(fields) == 11 and fields[1].isdigit(): rows.append(f'PID: {fields[1]}, Command: {fields[10]}, CPU: {fields[2]}, Memory: {fields[3]}')
        return text_result('\n'.join(rows))

    def _kill(self, args):
        pid = _integer(args.get('pid'), 'pid', 1)
        if pid == os.getpid(): raise ToolError('Refusing to terminate this compatibility server')
        _publish(self.directory, '.kill-intent.json', {'pid': pid, 'signal': 'SIGTERM', 'at': time.time(), 'state': 'intent_no_replay'})
        if hasattr(os, 'pidfd_open') and hasattr(signal, 'pidfd_send_signal'):
            fd = os.pidfd_open(pid)
            try: signal.pidfd_send_signal(fd, signal.SIGTERM)
            finally: os.close(fd)
        else: os.kill(pid, signal.SIGTERM)
        return text_result(f'Successfully sent termination signal to process {pid}')

    async def invoke(self, name, arguments):
        handlers = {'start_process': self._start, 'read_process_output': self._read, 'interact_with_process': self._interact,
                    'force_terminate': self._force, 'list_sessions': lambda _: self._list_sessions(),
                    'list_processes': lambda _: self._list_processes(), 'kill_process': self._kill}
        if name not in handlers: raise ToolError('Unknown process tool: ' + str(name))
        def run():
            with self._lifecycle:
                if self.closed: raise ToolError('process manager is closed')
                self._workers += 1
            try: return handlers[name](arguments)
            finally:
                with self._lifecycle: self._workers -= 1; self._lifecycle.notify_all()
        try: return await asyncio.to_thread(run)
        except (OSError, subprocess.SubprocessError) as exc:
            return text_result('Error: ' + type(exc).__name__ + ': ' + str(exc), is_error=True)

    def close(self):
        with self._close_lock:
            self._close()

    def _close(self):
        with self._lifecycle:
            if self._released: return
            self.closed = True
        with self._lock: sessions = list(self.sessions.values())
        for session in sessions:
            if session.process.poll() is None:
                try: self._force({'pid': session.process.pid})
                except OSError: pass
            session.stop_collect.set()
        with self._lifecycle:
            while self._workers: self._lifecycle.wait(0.05)
        for session in sessions:
            if session.collector is not None: session.collector.join()
            if session.process.stdin: session.process.stdin.close()
        self.virtual.clear()
        os.close(self.lock_fd); os.close(self.directory)
        self._released = True

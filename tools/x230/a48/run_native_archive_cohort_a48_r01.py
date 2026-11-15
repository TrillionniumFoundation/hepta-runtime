#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Source-bound native MCP archive cohort experiment; PREPARATION ONLY.

Four fresh private native controllers run A/B/B/A, eighty fixed measured slots
and thirty-two waves. One real host_list seed provides each stdio owner; all
other records are explicitly synthetic. Product metadata deadlines stay at 3s.
The candidate qualification and protocol bindings must be frozen before run.
No SSH, agent, Cargo, service change, hidden retry or direct index test entry.
"""

import argparse
import collections
import datetime
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import signal
import stat
import subprocess
import sys
import threading
import time
import types


DEV_ROOT = Path('/home/qian/hepta-runtime-optimization-20261023')
BASE = DEV_ROOT / 'a41-phase-timing-20261025-r01'
EXPECTED_OUT = BASE / 'a48-native-archive-cohort-r01'
SMALL_HELPER = BASE / 'tools/x230_small_archive_benchmark.py'
SMALL_SHA = '98413b4b177ec3bf68b7fe67de153376465374a9e74690c337633b3b4a912ffb'
NATIVE_DRIVER = BASE / 'tools/run_a41_native_validation_r07.py'
NATIVE_SHA = '6123660947b4b205d7f70d901c4e78b74395df065226a27937730b8c4cdd2ec9'
FINAL_BINDINGS_READY = True
PROTOCOL_SHA = '5a3c8e814b3614d1c6729d474a38571e517ef0bc603690a104288576ca3afd8e'
ENTRY_PATH = BASE / 'a48-page-fullscan-entry-r01/entry-report.json'
ENTRY_SHA = '871814ec2e5d3b870623fd6496a044626292efbc9b5658f488a6470e2a2cf851'
ENTRY_BYTES = 309398
ENTRY_SCHEMA = 'hepta-a48-page-fullscan-qualification-entry/v1'
WORKER_PATH = BASE / 'a48-page-fullscan-entry-r01/worker-report.json'
WORKER_SHA = '758785ba8ecbaef30818cb21e7daa62ce45f3b86c575436c870c1e5f52dea940'
WORKER_BYTES = 22281
WORKER_SCHEMA = 'hepta-a48-page-fullscan-guarded-qualifier-worker/v1'

QUALIFICATION_CHAIN = BASE / 'tools/load_a46_qualification_chain_r01.py'
QUALIFICATION_CHAIN_SHA = '55a19e9e5d5bd2d514025fefe2cdf037b9a21f0fae1ed3f750c6b9af086cf7e0'
ORDER = ('A', 'B', 'B', 'A')
ROWS = 65536
HOT = 512
OWNED = 16384
MAX_MESSAGE = 1024 * 1024
MAX_WIRE_BYTES = 16 * 1024 * 1024
CLIENT_SECONDS = 10
ROUND_SECONDS = 300
ID_RE = re.compile(r'[0-9a-f]{64}\Z')
BUSY_NAMES = ('cargo', 'cargo-clippy', 'clippy-driver', 'rustc', 'heptabao_server')
PERFORMANCE_ERRORS = (
    'archive metadata query total deadline exceeded; repeat only the metadata query',
    'archive index preparing or validation unavailable; repeat only this metadata query',
)
STOP_SIGNUM = None
LAUNCH_REGION = False
CLEANUP_REGION = False
PUBLIC_SCOPE = {
    'ownership_scope': 'native_mcp_session_only',
    'session_scope': 'native_mcp_session_only',
    'authenticated_chatgpt_caller_isolation': False,
    'credential_metadata_resume': False,
    'cross_session_resume': False,
}


class FatalExperiment(RuntimeError):
    pass


class ProductFailure(RuntimeError):
    pass


def need(value, message):
    if not value:
        raise FatalExperiment(message)


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def stop_requested(signum, frame):
    global STOP_SIGNUM
    if STOP_SIGNUM is not None:
        return
    STOP_SIGNUM = signum


def check_stop():
    if STOP_SIGNUM is not None:
        raise KeyboardInterrupt('native archive harness received signal ' + str(STOP_SIGNUM))


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def document(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(FatalExperiment('nonfinite JSON')))


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def exact(actual, expected):
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return actual.keys() == expected.keys() and all(exact(actual[k], v) for k, v in expected.items())
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(exact(a, b) for a, b in zip(actual, expected))
    return actual == expected


def direct(path, fresh=False):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts and path.resolve(strict=not fresh) == path,
         'direct absolute path required: ' + str(path))
    if fresh:
        need(path.parent.is_dir() and not os.path.lexists(path), 'fresh path required: ' + str(path))
    return path


def stamp(value):
    return [value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns]


def bytes_receipt(path, maximum=512 * 1024 * 1024, keep=False):
    path = direct(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= maximum,
             'bounded single-link regular input required: ' + str(path))
        digest, size, chunks = hashlib.sha256(), 0, []
        while True:
            block = os.read(fd, min(1024 * 1024, maximum + 1 - size))
            if not block:
                break
            size += len(block)
            need(size <= maximum, 'file exceeded bound during read')
            digest.update(block)
            if keep:
                chunks.append(block)
        need(size == before.st_size and stamp(before) == stamp(os.fstat(fd)) == stamp(path.lstat()),
             'input changed during complete read: ' + str(path))
        row = {'path': str(path), 'bytes': size, 'sha256': digest.hexdigest(), 'identity': stamp(before)}
        return (row, b''.join(chunks)) if keep else row
    finally:
        os.close(fd)


def create(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def save(path, value):
    temporary = path.with_name(path.name + '.next')
    create(temporary, canonical(value))
    os.replace(temporary, path)
    sync_directory(path.parent)


def pinned_module(name, path, expected):
    receipt, raw = bytes_receipt(path, maximum=1024 * 1024, keep=True)
    need(receipt['sha256'] == expected, 'frozen dependency SHA differs: ' + str(path))
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module, receipt, raw


def proc_snapshot(pid, birth=None):
    raw = Path('/proc', str(pid), 'stat').read_text()
    fields = raw.rsplit(') ', 1)[1].split()
    actual_birth = int(fields[19])
    need(fields[0] not in ('Z', 'X', 'x'), 'controller exited before process observation')
    need(birth is None or birth == actual_birth, 'controller generation changed')
    hz = os.sysconf('SC_CLK_TCK')
    result = {'monotonic_ns': time.monotonic_ns(), 'pid': pid, 'birth_ticks': actual_birth,
              'state': fields[0], 'utime_ticks': int(fields[11]), 'stime_ticks': int(fields[12]),
              'cutime_ticks': int(fields[13]), 'cstime_ticks': int(fields[14]),
              'cpu_tick_hz': hz, 'cpu_ticks': int(fields[11]) + int(fields[12]),
              'cpu_seconds': (int(fields[11]) + int(fields[12])) / hz,
              'rss_kib': None, 'hwm_kib': None, 'fd_count': None, 'thread_children': {}, 'errors': []}
    try:
        status = {}
        for line in Path('/proc', str(pid), 'status').read_text().splitlines():
            if ':' in line:
                key, value = line.split(':', 1)
                status[key] = value.strip()
        for field, key in (('rss_kib', 'VmRSS'), ('hwm_kib', 'VmHWM')):
            try:
                parts = status[key].split()
                need(len(parts) == 2 and parts[1] == 'kB', 'unexpected memory field unit')
                result[field] = int(parts[0])
            except Exception as error:
                result['errors'].append({'field': field, 'error': repr(error)})
    except Exception as error:
        result['errors'].append({'field': 'status', 'error': repr(error)})
    try:
        result['fd_count'] = len(list(Path('/proc', str(pid), 'fd').iterdir()))
    except Exception as error:
        result['errors'].append({'field': 'fd_count', 'error': repr(error)})
    try:
        for thread in sorted(Path('/proc', str(pid), 'task').iterdir()):
            try:
                result['thread_children'][thread.name] = [int(x) for x in (thread / 'children').read_text().split()]
            except FileNotFoundError:
                result['errors'].append({'field': 'thread_children', 'thread': thread.name,
                                         'error': 'thread disappeared during endpoint observation'})
    except Exception as error:
        result['errors'].append({'field': 'thread_children', 'error': repr(error)})
    return result


def host_gate(native):
    snapshot = native.host_load()
    busy = [row for row in snapshot['processes']
            if row['comm'] in BUSY_NAMES and row['state'] not in ('Z', 'X', 'x')]
    return {'clear': snapshot['required_fields_present'] and not snapshot['errors'] and not busy,
            'matching_live_processes': busy, 'snapshot': snapshot}


def disk_gate(path):
    value = os.statvfs(path)
    available = value.f_bavail * value.f_frsize
    inode_valid = value.f_files > 0 and value.f_favail >= 0
    return {'path': str(path), 'available_bytes': available, 'free_inodes': value.f_favail,
            'free_inode_field_valid': inode_valid, 'minimum_available_bytes': 2 * 1024**3,
            'minimum_free_inodes_when_valid': 300000,
            'clear': available >= 2 * 1024**3 and (not inode_valid or value.f_favail >= 300000)}


def controller_type(small):
    class NativeController(small.LocalController):
        """Frozen original wait4/close custody with a bounded four-ID dispatcher."""

        def __init__(self, binary, config, directory):
            self.directory, self.binary, self.config = directory, binary, config
            self.serial, self.pending = 0, {}
            self.lock = threading.Lock()
            self.reader_error, self.unmatched, self.reaped, self.shutdown = None, [], False, None
            self.received_ids, self.protocol_violations = set(), []
            self.reader_stop, self.reader_eof = None, False
            self.child, self.reader, self.birth = None, None, None
            self.reader_started = False
            self.wire_in = (directory / 'requests.jsonl').open('xb')
            self.wire_out = (directory / 'responses.jsonl').open('xb')
            self.stderr = (directory / 'stderr.log').open('xb')
            self.startup = {}

        def start(self):
            global LAUNCH_REGION
            need(STOP_SIGNUM is None, 'stop already requested; no new original controller')
            argv = [str(self.binary), 'mcp', '--runtime-config', str(self.config),
                    '--runtime-audit-group-commit']
            env = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'SHELL': '/bin/sh',
                   'TOKIO_WORKER_THREADS': '2', 'RUST_LOG': 'warn'}
            self.started_ns = time.monotonic_ns()
            self.startup = {'pid': None, 'argv': argv, 'environment': env,
                            'only_owned_controller_started': False, 'child_signal_mask_changed': False}
            launch_error = None
            LAUNCH_REGION = True
            try:
                self.child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                              stderr=self.stderr, cwd=self.directory, env=env,
                                              start_new_session=True)
                self.startup.update(pid=self.child.pid, only_owned_controller_started=True,
                                    popen_assigned_monotonic_ns=time.monotonic_ns())
            except BaseException as error:
                launch_error = error
                self.startup['launch_error'] = type(error).__name__ + ': ' + str(error)
                raise
            finally:
                LAUNCH_REGION = False
                self.startup['deferred_first_signal'] = STOP_SIGNUM
                if STOP_SIGNUM is not None and launch_error is None:
                    raise KeyboardInterrupt('first signal deferred until original Popen child was bound: ' + str(STOP_SIGNUM))
            os.set_blocking(self.child.stdin.fileno(), False)
            self.birth = proc_snapshot(self.child.pid)['birth_ticks']
            self.startup['birth_ticks'] = self.birth
            self.reader = threading.Thread(target=self.read_loop, daemon=True)
            self.reader.start()
            self.reader_started = True

        def read_loop(self):
            def violation(message, item, rpc_id=None):
                proof = {k: v for k, v in item.items() if k != 'reply'}
                proof.update(error=message, id=rpc_id)
                self.unmatched.append(proof)
                self.protocol_violations.append(proof)
                self.reader_error = self.reader_error or message
                need(len(self.protocol_violations) <= 64, 'protocol violation metadata bound exceeded; raw bytes retained')
            try:
                while True:
                    wire = self.child.stdout.readline(MAX_MESSAGE + 1)
                    received_ns = time.monotonic_ns()
                    if not wire:
                        self.reader_eof = True
                        break
                    offset = self.wire_out.tell()
                    self.wire_out.write(wire)
                    self.wire_out.flush()
                    item = {'wire_offset': offset, 'wire_bytes': len(wire), 'wire_sha256': sha(wire),
                            'received_monotonic_ns': received_ns}
                    need(self.wire_out.tell() <= MAX_WIRE_BYTES, 'response wire capture budget exceeded')
                    need(len(wire) <= MAX_MESSAGE and wire.endswith(b'\n'), 'native framing/size violation')
                    try:
                        reply = document(wire)
                        need(isinstance(reply, dict), 'native response is not an object')
                        need(reply.get('jsonrpc') == '2.0', 'native JSON-RPC version absent or invalid')
                        if 'id' not in reply:
                            need(isinstance(reply.get('method'), str) and bool(reply['method'])
                                 and 'result' not in reply and 'error' not in reply
                                 and set(reply) <= {'jsonrpc', 'method', 'params'}
                                 and ('params' not in reply or isinstance(reply['params'], (dict, list))),
                                 'native no-ID message is not a valid notification')
                    except Exception as error:
                        violation('complete-line native JSON/protocol error: ' + repr(error), item)
                        continue
                    item['reply'] = reply
                    if 'id' not in reply:
                        continue
                    with self.lock:
                        rpc_id = reply['id']
                        duplicate = type(rpc_id) is int and rpc_id in self.received_ids
                        waiter = self.pending.get(rpc_id) if type(rpc_id) is int else None
                        if waiter is not None and not duplicate:
                            self.received_ids.add(rpc_id)
                    if duplicate:
                        violation('duplicate original RPC response ID; second attribution refused', item, rpc_id)
                        continue
                    if waiter is None:
                        violation('native response ID has no original pending request', item, rpc_id)
                        continue
                    waiter.put_nowait(item)
            except Exception as error:
                self.reader_error = type(error).__name__ + ': ' + str(error)
            finally:
                with self.lock:
                    pending = [(rpc_id, waiter) for rpc_id, waiter in self.pending.items()
                               if rpc_id not in self.received_ids]
                self.reader_stop = {'monotonic_ns': time.monotonic_ns(), 'eof_observed': self.reader_eof,
                    'outstanding_original_rpc_ids': [rpc_id for rpc_id, _ in pending],
                    'remaining_slots_are_terminal_transport_unknown': bool(pending),
                    'all_remaining_slots_drained_claimed': False,
                    'reason': self.reader_error or ('native EOF' if self.reader_eof else 'capture ended')}
                if pending:
                    self.reader_error = self.reader_error or 'native stdio closed with original pending requests'
                for _, waiter in pending:
                    try:
                        waiter.put_nowait({'transport_error': self.reader_error or 'native stdio closed'})
                    except queue.Full:
                        pass

        def notify_initialized(self):
            wire = canonical({'jsonrpc': '2.0', 'method': 'notifications/initialized', 'params': {}})
            self.wire_in.write(wire)
            self.wire_in.flush()
            written = os.write(self.child.stdin.fileno(), wire)
            need(written == len(wire), 'partial notification write; no retry')

        def wave(self, specifications):
            check_stop()
            need(1 <= len(specifications) <= 4, 'only C1 or bounded C4 RPC waves admitted')
            need(not self.reader_error, 'response reader already failed')
            need(STOP_SIGNUM is None, 'stop requested; no new RPC wave')
            payload, pending = bytearray(), []
            with self.lock:
                need(not self.pending, 'previous RPC wave remains pending')
                for method, params, row in specifications:
                    self.serial += 1
                    rpc_id = self.serial
                    waiter = queue.Queue(maxsize=2)
                    self.pending[rpc_id] = waiter
                    wire = canonical({'jsonrpc': '2.0', 'id': rpc_id, 'method': method, 'params': params})
                    row.update(rpc_id=rpc_id, request_wire_offset=self.wire_in.tell() + len(payload),
                               request_wire_bytes=len(wire), request_wire_sha256=sha(wire),
                               write_attempts=0, sent=False, response_received=False, automatic_retry=False)
                    payload.extend(wire)
                    pending.append((rpc_id, waiter, row))
            # Each wave fits one atomic pipe write. Nonblocking delivery failure
            # is recorded once and never replayed, so client wait cannot hide a
            # blocking writer or silently split four requests into C1 dispatches.
            pipe_buf = os.fpathconf(self.child.stdin.fileno(), 'PC_PIPE_BUF')
            need(len(payload) <= pipe_buf, 'fixed wave exceeds atomic pipe write size')
            self.wire_in.write(payload)
            self.wire_in.flush()
            with self.lock:
                pending_ids_at_write = sorted(self.pending)
                registered_ns = time.monotonic_ns()
            need(pending_ids_at_write == sorted(rpc_id for rpc_id, _, _ in pending),
                 'actual client pending inventory differs before once-only wave write')
            started_ns = time.monotonic_ns()
            deadline_ns = started_ns + int(CLIENT_SECONDS * 1e9)
            write_error, written = None, 0
            for _, _, row in pending:
                row.update(start_monotonic_ns=started_ns, client_deadline_monotonic_ns=deadline_ns,
                           write_attempts=1, single_wave_os_write=True,
                           client_pending_ids_at_write=pending_ids_at_write,
                           client_pending_count_at_write=len(pending_ids_at_write),
                           client_pending_registered_monotonic_ns=registered_ns,
                           server_admission_or_cohort_timing_observed=False)
            try:
                written = os.write(self.child.stdin.fileno(), payload)
                need(written == len(payload), 'partial RPC wave write; delivery uncertain; never retried')
                for _, _, row in pending:
                    row['sent'] = True
            except Exception as error:
                write_error = type(error).__name__ + ': ' + str(error)
            results = []
            try:
                for rpc_id, waiter, row in pending:
                    item = None
                    try:
                        if write_error is not None and written == 0:
                            raise FatalExperiment(write_error)
                        remaining = max(0.0, (deadline_ns - time.monotonic_ns()) / 1e9)
                        item = waiter.get(timeout=remaining)
                        row.update({'response_' + k: v for k, v in item.items() if k != 'reply'})
                        if 'received_monotonic_ns' in item:
                            row['response_received'] = True
                            row['elapsed_ms'] = (item['received_monotonic_ns'] - started_ns) / 1e6
                        need('transport_error' not in item, item.get('transport_error', ''))
                        need(item['received_monotonic_ns'] <= deadline_ns, 'native response exceeded original 10s client deadline')
                        reply = item['reply']
                        need(type(reply.get('id')) is int and reply['id'] == rpc_id
                             and reply.get('jsonrpc') == '2.0', 'native response protocol/identity differs')
                        results.append(reply)
                    except Exception as error:
                        row.update(status='transport_failure', okay=False, error_type=type(error).__name__,
                                   error=str(error) or 'original 10s client deadline elapsed')
                        results.append(None)
                    finally:
                        row['caller_wall_ms'] = (time.monotonic_ns() - started_ns) / 1e6
                        if write_error is not None:
                            row['wave_write_error'] = write_error
                            row['wave_written_bytes'] = written
                            row['delivery_uncertain'] = written != 0
            finally:
                with self.lock:
                    for rpc_id, _, _ in pending:
                        self.pending.pop(rpc_id, None)
            return results

        def initialize(self):
            row = {'purpose': 'initialize', 'okay': False}
            self.startup['initialize'] = row
            reply = self.wave([('initialize', {'protocolVersion': '2025-03-26', 'capabilities': {},
                'clientInfo': {'name': 'hepta-a48-native-archive-cohort', 'version': '1'}}, row)])[0]
            need(reply is not None and 'result' in reply and 'error' not in reply,
                 'native initialize failed; original response retained')
            row.update(okay=True, status='succeeded')
            self.notify_initialized()
            self.startup['ready_ms'] = (time.monotonic_ns() - self.started_ns) / 1e6

        def close(self):
            global CLEANUP_REGION
            if self.shutdown is not None:
                return self.shutdown
            if self.child is None:
                for stream in (self.wire_in, self.wire_out, self.stderr):
                    stream.flush()
                    os.fsync(stream.fileno())
                    stream.close()
                self.shutdown = {'original_child_started': False, 'original_child_reaped': False,
                                 'waited': None, 'errors': [], 'reader_error': self.reader_error,
                                 'unmatched': self.unmatched}
                return self.shutdown
            if not self.reader_started:
                # Preserve original wait4 even if identity observation/thread
                # startup failed after Popen returned. The object is already
                # owned by run_controller before this fallible start method.
                self.reader_error = self.reader_error or 'reader never started; no RPC initialization was attempted'
                class NoReader:
                    def join(self, seconds):
                        return None
                    def is_alive(self):
                        return False
                self.reader = NoReader()
            CLEANUP_REGION = True
            try:
                value = small.LocalController.close(self)
            finally:
                CLEANUP_REGION = False
            value['frozen_helper_scope_text'] = value['cpu_scope']
            value['cpu_scope'] = ('Original wait4 controller whole life, including initialization, one native seed, '
                'synthetic-fixture exposure, one kickoff, fixed idle, one warmup, measured calls, '
                'final original verification, remaining blocking workers and shutdown; not pure query CPU.')
            value['received_response_ids'] = sorted(self.received_ids)
            value['protocol_violations'] = self.protocol_violations
            value['reader_stop'] = self.reader_stop
            value['raw_stdout_eof_captured'] = self.reader_eof
            value['first_termination_signal'] = STOP_SIGNUM
            return value
    return NativeController


def result_dto(reply):
    need(isinstance(reply, dict), 'RPC response unavailable')
    if 'error' in reply:
        error = reply['error']
        message = error.get('message') if isinstance(error, dict) else None
        if message in PERFORMANCE_ERRORS:
            raise ProductFailure(message)
        raise FatalExperiment('unexpected native RPC error: ' + json.dumps(error, sort_keys=True))
    result = reply.get('result')
    need(isinstance(result, dict), 'native CallToolResult absent')
    texts = [part['text'] for part in result.get('content', []) if isinstance(part, dict) and part.get('type') == 'text']
    need(len(texts) == 1 and len(result.get('content', [])) == 1, 'native result must contain one exact text block')
    if result.get('isError', False) is True:
        if texts[0] in PERFORMANCE_ERRORS:
            raise ProductFailure(texts[0])
        raise FatalExperiment('unexpected native tool error: ' + texts[0])
    need(result.get('isError', False) is False, 'invalid native isError value')
    value = document(texts[0])
    need(isinstance(value, dict), 'native DTO is not an object')
    return result, value


def synthetic_record(number, owners):
    need(1 <= number < ROWS, 'synthetic fixture number outside fixed range')
    state = ('unknown', 'completed', 'failed')[(number // 16) % 3]
    return {'request_id': f'{number % 256:02x}{number + 1:062x}', 'owner': owners[number % 4],
            'tool_name': ('host_list', 'host_health', 'file_info', 'effective_config')[(number // 4) % 4],
            'state': state, 'accepted_unix_ms': 1000000 + number,
            'elapsed_ms': None if state == 'unknown' else 1 + number % 1000}


def native_seed(state, seed_id):
    archive = state / 'request-archive-v11'
    hot = state / 'request-audit'
    need(not os.path.lexists(state / 'request-archive-v12'), 'unexpected sharded native seed layout')
    values, raw_values = [], []
    for directory in (archive, hot):
        direct(directory)
        need(sorted(x.name for x in directory.iterdir()) == [seed_id + '.json'],
             'real seed store does not contain exactly its one original record')
        _, raw = bytes_receipt(directory / (seed_id + '.json'), maximum=2048, keep=True)
        value = document(raw)
        need(set(value) == {'request_id', 'owner', 'tool_name', 'state', 'accepted_unix_ms', 'elapsed_ms'}
             and value['request_id'] == seed_id and ID_RE.fullmatch(value['owner'])
             and value['tool_name'] == 'host_list' and value['state'] == 'completed'
             and type(value['accepted_unix_ms']) is int and value['accepted_unix_ms'] > 1000000 + ROWS
             and type(value['elapsed_ms']) is int and value['elapsed_ms'] >= 0,
             'native seed record schema/identity differs')
        values.append(value)
        raw_values.append(raw)
    need(values[0] == values[1] and raw_values[0] == raw_values[1], 'native seed original hot/archive bytes differ')
    owners = [values[0]['owner']] + [sha(('hepta-a48-synthetic-owner-v1\0' + values[0]['owner'] + '\0' + str(i)).encode())
                                  for i in range(1, 4)]
    need(len(set(owners)) == 4, 'synthetic owners collided')
    seed = {'seed_id': seed_id, 'native_record': values[0], 'native_raw_hex': raw_values[0].hex(),
            'native_raw_sha256': sha(raw_values[0]), 'owners': owners,
            'real_native_admissions': 1, 'synthetic_archive_records': ROWS - 1,
            'synthetic_records_are_native_admissions': False}
    return seed


def seed_synthetic(state, seed, deadline):
    archive, hot = state / 'request-archive-v11', state / 'request-audit'
    descriptors = [os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                   for path in (archive, hot)]
    generated = hashlib.sha256()
    owners, seed_id = seed['owners'], seed['seed_id']
    owned = [seed['native_record']]
    try:
        for number in range(1, ROWS):
            if number % 256 == 0:
                check_stop()
                need(time.monotonic() < deadline, 'controller fixture setup budget elapsed')
            record = synthetic_record(number, owners)
            need(record['request_id'] != seed_id, 'synthetic ID collided with original native seed')
            raw = canonical(record)
            need(len(raw) <= 2048, 'synthetic record exceeded product schema byte bound')
            generated.update(canonical([number, sha(raw)]))
            for descriptor in descriptors[:2 if number >= ROWS - HOT + 1 else 1]:
                fd = os.open(record['request_id'] + '.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL
                             | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=descriptor)
                with os.fdopen(fd, 'wb') as stream:
                    need(stream.write(raw) == len(raw), 'partial synthetic fixture write')
                    stream.flush()
            if record['owner'] == owners[0]:
                owned.append(record)
        for descriptor in descriptors:
            os.fsync(descriptor)
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
    sync_directory(state)
    owned.sort(key=lambda row: (row['accepted_unix_ms'], row['request_id']))
    need(len(owned) == OWNED, 'owned fixture count differs')
    seed.update(synthetic_creation_fingerprint_sha256=generated.hexdigest(),
                archive_records=ROWS, hot_records=HOT, archive_per_owner=OWNED, hot_per_owner=HOT // 4,
                archive_layout='flat-v11', synthetic_file_fsync=False,
                synthetic_directories_fsynced=True, durability_or_power_loss_claim=False)
    return owned


def expected_record(request_id, seed):
    if request_id == seed['seed_id']:
        return seed['native_record'], bytes.fromhex(seed['native_raw_hex']), None
    need(ID_RE.fullmatch(request_id), 'fixture ID malformed')
    number = int(request_id[2:], 16) - 1
    record = synthetic_record(number, seed['owners'])
    need(record['request_id'] == request_id, 'unexpected synthetic fixture ID')
    return record, canonical(record), number


def fixture_witness(state, seed, deadline, map_path=None):
    started = time.monotonic_ns()
    identity_hash, content_hash = hashlib.sha256(), hashlib.sha256()
    counts, owner_counts, namespace = {}, {}, {}
    output = map_path.open('xb') if map_path is not None else None
    try:
        for group, directory in (('archive', state / 'request-archive-v11'), ('hot', state / 'request-audit')):
            direct(directory)
            before_names = sorted(x.name for x in directory.iterdir())
            expected_count = ROWS if group == 'archive' else HOT
            need(len(before_names) == expected_count, 'fixture namespace count differs: ' + group)
            seen, owners = set(), collections.Counter()
            for index, filename in enumerate(before_names):
                if index % 256 == 0:
                    check_stop()
                    need(time.monotonic() < deadline, 'fixture verification budget elapsed')
                need(filename.endswith('.json') and ID_RE.fullmatch(filename[:-5]), 'unexpected fixture filename')
                request_id = filename[:-5]
                record, expected_raw, number = expected_record(request_id, seed)
                need(group != 'hot' or number is None or number >= ROWS - HOT + 1,
                     'unexpected old synthetic record in hot fixture')
                need(request_id not in seen, 'duplicate fixture namespace ID')
                seen.add(request_id)
                receipt, raw = bytes_receipt(directory / filename, maximum=2048, keep=True)
                need(raw == expected_raw and exact(document(raw), record), 'fixture original bytes/record differ')
                need(receipt['identity'][2] & 0o7777 == 0o600
                     and receipt['identity'][3] == os.geteuid(), 'fixture file owner/mode differs')
                owners[record['owner']] += 1
                relative = str((directory / filename).relative_to(state))
                line = canonical([relative, receipt['sha256'], receipt['bytes'], receipt['identity']])
                identity_hash.update(line)
                content_hash.update(canonical([relative, receipt['sha256'], receipt['bytes']]))
                if output is not None:
                    output.write(line)
            need(sorted(x.name for x in directory.iterdir()) == before_names, 'fixture namespace changed during scan')
            need(set(owners) == set(seed['owners']) and set(owners.values()) == {expected_count // 4},
                 'fixture owner balance differs')
            counts[group], owner_counts[group] = len(seen), dict(owners)
            info = directory.lstat()
            need(stat.S_ISDIR(info.st_mode) and info.st_mode & 0o7777 == 0o700
                 and info.st_uid == os.geteuid(), 'fixture directory owner/type/mode differs')
            namespace[group] = {'path': str(directory), 'identity': stamp(info)}
        need(not os.path.lexists(state / 'request-archive-v12'), 'unexpected shard activation in fixed flat fixture')
        anchor = bytes_receipt(state / '.request-archive-v11-anchor.json', maximum=2048)
        value = {'counts': counts, 'owner_counts': owner_counts, 'directories': namespace,
                 'anchor': anchor, 'identity_map_sha256': identity_hash.hexdigest(),
                 'content_map_sha256': content_hash.hexdigest(), 'complete_record_body_reads': ROWS + HOT,
                 'elapsed_seconds': (time.monotonic_ns() - started) / 1e9,
                 'map_format': '[relative_path, sha256, bytes, stat9] newline compact JSON'}
    finally:
        if output is not None:
            output.flush()
            os.fsync(output.fileno())
            output.close()
    if map_path is not None:
        value['full_map_file'] = bytes_receipt(map_path, maximum=64 * 1024 * 1024)
    return value


def same_fixture(first, later):
    return all(first[key] == later[key] for key in (
        'counts', 'owner_counts', 'directories', 'anchor', 'identity_map_sha256', 'content_map_sha256'))


def query_variants(owned):
    return [
        {'name': 'first_1', 'arguments': {'limit': 1}},
        {'name': 'first_32', 'arguments': {'limit': 32}},
        {'name': 'quarter_16', 'arguments': {'limit': 16, 'after_id': owned[4095]['request_id']}},
        {'name': 'tail_32', 'arguments': {'limit': 32, 'after_id': owned[16381]['request_id']}},
    ]


def page_oracle(owned, arguments):
    start = 0
    if 'after_id' in arguments:
        matches = [index for index, record in enumerate(owned) if record['request_id'] == arguments['after_id']]
        need(len(matches) == 1, 'oracle cursor must resolve to one owned original')
        start = matches[0] + 1
    page = owned[start:start + arguments['limit']]
    public = [{key: value for key, value in record.items() if key != 'owner'} for record in page]
    return {'requests': public, 'next_after_id': page[-1]['request_id'] if start + len(page) < len(owned) else None,
            'total': len(owned), 'archive_retention': 'no_automatic_metadata_eviction',
            'history_is_live': True,
            'coverage': 'metadata_retained_at_archive_introduction_and_subsequent_admitted_requests',
            'contains_parameters_or_output': False, 'automatic_operation_retry': False, **PUBLIC_SCOPE}


def usage_oracle(owned):
    counts = collections.Counter(record['state'] for record in owned)
    return {'schema': 'hepta-private-usage-v1', 'total_requests': len(owned),
            'completed': counts['completed'], 'failed': counts['failed'], 'unknown': counts['unknown'],
            'active': 0, 'tool_counts': dict(collections.Counter(record['tool_name'] for record in owned)),
            'first_accepted_unix_ms': owned[0]['accepted_unix_ms'],
            'last_accepted_unix_ms': owned[-1]['accepted_unix_ms'],
            'retention': 'archive_metadata_not_evicted_with_hot_cache',
            'coverage': 'metadata_retained_at_archive_introduction_and_subsequent_admitted_requests',
            'semantics': 'dispatch_observation_not_transport_delivery_or_business_success',
            'contains_parameters_or_output': False, 'scope': 'same_verified_credential_or_native_session',
            **PUBLIC_SCOPE}


def journal_row(journal, row):
    need(not row.get('journaled'), 'attempt journal row would be duplicated')
    row['journaled'] = True
    journal.write(canonical(row))


def retain_interrupted_rows(journal, rows):
    for row in rows:
        if row.get('write_attempts') == 1 and not row.get('journaled'):
            row.update(okay=False, status='interrupted_unknown',
                       error='Original once-only RPC attempt interrupted before complete response/oracle attribution; wire retained, never replayed')
            journal_row(journal, row)
    journal.flush()


def plan_slots():
    slots, waves = [], []
    for controller, arm in enumerate(ORDER):
        for wave in range(8):
            kinds = [wave] if wave < 4 else [(wave - 4 + position) % 4 for position in range(4)]
            ids = []
            for position, query in enumerate(kinds):
                row = {'slot': len(slots), 'controller': controller, 'block': controller // 2,
                       'arm': arm, 'wave': wave, 'position': position, 'query_variant': query,
                       'concurrency': len(kinds), 'purpose': 'measured', 'tool': 'request_archive',
                       'status': 'unexecuted', 'okay': False, 'write_attempts': 0,
                       'sent': False, 'response_received': False, 'automatic_retry': False}
                ids.append(row['slot'])
                slots.append(row)
            waves.append({'controller': controller, 'block': controller // 2, 'arm': arm, 'wave': wave,
                          'concurrency': len(kinds), 'slot_ids': ids, 'status': 'unexecuted'})
    need(len(slots) == 80 and len(waves) == 32, 'fixed inventory differs')
    return slots, waves


def observe_wave(controller, rows, journal, expected=None, small=None, setup_tool=None):
    specs = [('tools/call', {'name': row['tool'], 'arguments': row['arguments']}, row) for row in rows]
    started = time.monotonic_ns()
    replies = controller.wave(specs)
    values, fatal = [], False
    for index, (row, reply) in enumerate(zip(rows, replies)):
        value = None
        try:
            need(reply is not None, row.get('error', 'original reply unavailable'))
            result, dto = result_dto(reply)
            row['dto_sha256'] = sha(canonical(dto))
            if setup_tool == 'host_list':
                value = small.validate_seed(result, dto)
                row['native_request_id'] = value
            else:
                need(exact(dto, expected[index]), 'complete native DTO differs from independent owner/cursor oracle')
                value = dto
            row.update(okay=True, status='succeeded')
        except ProductFailure as error:
            row.update(okay=False, status='product_failure', error_type='ProductFailure', error=str(error))
        except Exception as error:
            if row.get('status') != 'transport_failure':
                row.update(okay=False, status='validation_failure', error_type=type(error).__name__, error=str(error))
            fatal = True
        values.append(value)
        journal_row(journal, row)
    journal.flush()
    ended = time.monotonic_ns()
    fatal = fatal or bool(controller.protocol_violations) or bool(controller.reader_error)
    return {'start_monotonic_ns': started, 'end_monotonic_ns': ended,
            'wall_seconds': (ended - started) / 1e9,
            'scope': 'whole client wave including once-only delivery, all response waits, full DTO oracle and journal flush',
            'attempted': sum(row.get('write_attempts') == 1 for row in rows),
            'client_pending_count_at_write': rows[0].get('client_pending_count_at_write'),
            'client_pending_ids_at_write': rows[0].get('client_pending_ids_at_write'),
            'server_cohort_membership_observed': False,
            'all_original_wave_replies_received': all(row.get('response_received') is True for row in rows),
            'terminal_transport_unknown_slot_ids': [row.get('slot', row.get('purpose')) for row in rows
                if row.get('status') == 'transport_failure' and not row.get('response_received')],
            'protocol_violations': list(controller.protocol_violations),
            'successes': sum(row['okay'] for row in rows), 'failures': sum(not row['okay'] for row in rows),
            'fatal': fatal}, values


def scope_cpu(start, end=None, waited=None):
    hz = start['cpu_tick_hz']
    need(hz > 0, 'invalid process clock tick rate')
    if waited is not None:
        observed = waited['total_cpu_seconds'] - start['cpu_seconds']
        margin = 2 / hz + 0.000002
        scope = 'original wait4 whole-life CPU minus this /proc cumulative endpoint; includes remaining work, final verification and shutdown'
    else:
        need(end['cpu_tick_hz'] == hz and end['birth_ticks'] == start['birth_ticks'], 'CPU endpoint identity/rate changed')
        observed = end['cpu_seconds'] - start['cpu_seconds']
        margin = 4 / hz
        scope = 'process CPU endpoint difference; conservative two ticks at each endpoint'
    need(observed >= -margin, 'negative CPU interval exceeds quantization allowance')
    return {'observed_seconds': observed, 'lower_seconds': max(0.0, observed - margin),
            'upper_seconds': max(0.0, observed + margin), 'quantization_margin_seconds': margin,
            'clock_tick_hz': hz, 'scope': scope}


def run_controller(index, arm, bundle, out, report, slots, waves, native, small, Controller, journal, checkpoint):
    directory = out / ('controller-' + str(index) + '-' + arm)
    direct(directory, fresh=True)
    current = {'index': index, 'block': index // 2, 'arm': arm, 'version': bundle['version'],
               'release_sha256': bundle['binary']['sha256'], 'status': 'preparing', 'started_utc': utc(),
               'setup': [], 'errors': [], 'candidate_cohort_instrumentation_claimed': False}
    report['controllers'].append(current)
    controller, state, seed, initial, owned = None, None, None, None, None
    deadline = time.monotonic() + ROUND_SECONDS
    try:
        config, state = small.make_fixture(directory)
        current['directory'] = str(directory)
        controller = Controller(Path(bundle['binary']['path']), config, directory)
        controller.start()
        controller.initialize()
        current['startup'] = controller.startup
        row = {'purpose': 'native_seed', 'controller': index, 'arm': arm, 'tool': 'host_list',
               'arguments': {}, 'okay': False, 'status': 'unexecuted'}
        current['setup'].append(row)
        outcome, values = observe_wave(controller, [row], journal, small=small, setup_tool='host_list')
        need(not outcome['fatal'] and row['okay'], 'one original native host_list seed failed; no replacement')
        seed = native_seed(state, values[0])
        owned = seed_synthetic(state, seed, deadline)
        current['fixture'] = seed
        create(directory / 'fixture-generation.json', canonical(seed))
        variants = query_variants(owned)
        expected = [page_oracle(owned, variant['arguments']) for variant in variants]
        current['queries'] = variants
        create(directory / 'independent-page-oracles.json', canonical(expected))
        initial = fixture_witness(state, seed, deadline, directory / 'fixture-original-map.jsonl')
        current['fixture_after_generation'] = initial
        checkpoint()

        kickoff = {'purpose': 'index_kickoff', 'controller': index, 'arm': arm, 'tool': 'usage_stats',
                   'arguments': {}, 'okay': False, 'status': 'unexecuted'}
        current['setup'].append(kickoff)
        outcome, _ = observe_wave(controller, [kickoff], journal, expected=[usage_oracle(owned)])
        need(not outcome['fatal'], 'fixed index kickoff failed outside declared product errors')
        idle_start = time.monotonic_ns()
        current['fixed_idle'] = {'planned_seconds': 60, 'start_monotonic_ns': idle_start,
                                 'polls': 0, 'queries_during_idle': 0}
        checkpoint()
        idle_deadline = idle_start + 60 * 1000000000
        while time.monotonic_ns() < idle_deadline:
            check_stop()
            time.sleep(min(1.0, max(0.0, (idle_deadline - time.monotonic_ns()) / 1e9)))
        check_stop()
        current['fixed_idle'].update(end_monotonic_ns=time.monotonic_ns(),
            elapsed_seconds=(time.monotonic_ns() - idle_start) / 1e9)
        need(time.monotonic() < deadline, 'controller setup budget expired during fixed idle')
        warm = {'purpose': 'archive_warmup', 'controller': index, 'arm': arm, 'tool': 'request_archive',
                'arguments': variants[0]['arguments'], 'okay': False, 'status': 'unexecuted'}
        current['setup'].append(warm)
        outcome, _ = observe_wave(controller, [warm], journal, expected=[expected[0]])
        need(not outcome['fatal'] and warm['okay'], 'one fixed archive warmup failed; no readiness retry')
        current['fixture_before_measurement'] = fixture_witness(state, seed, deadline)
        need(same_fixture(initial, current['fixture_before_measurement']), 'setup changed original fixture')
        gate = host_gate(native)
        create(directory / 'host-before-measured.json', canonical(gate))
        current['host_before_measured'] = bytes_receipt(directory / 'host-before-measured.json')
        current['host_before_measured_clear'] = gate['clear']
        need(gate['clear'], 'busy/incomplete immediate pre-measurement host gate')
        current['status'] = 'measuring'
        current['process_before_c1'] = proc_snapshot(controller.child.pid, controller.birth)
        checkpoint()
        for wave in [row for row in waves if row['controller'] == index]:
            check_stop()
            need(time.monotonic() < deadline, 'original controller experiment budget elapsed')
            if wave['wave'] == 4:
                current['process_before_c4'] = proc_snapshot(controller.child.pid, controller.birth)
                current['c1_process_cpu'] = scope_cpu(current['process_before_c1'], current['process_before_c4'])
                current['c1_all_successful_before_c4'] = all(
                    row['okay'] for row in slots if row['controller'] == index and row['concurrency'] == 1)
            rows = [slots[slot] for slot in wave['slot_ids']]
            for row in rows:
                row['arguments'] = variants[row['query_variant']]['arguments']
                row['query_name'] = variants[row['query_variant']]['name']
            wave.update(status='running', started_utc=utc())
            checkpoint()
            outcome, _ = observe_wave(controller, rows, journal,
                                      expected=[expected[row['query_variant']] for row in rows])
            wave.update(outcome, status='complete_with_failures' if outcome['failures'] else 'succeeded', finished_utc=utc())
            checkpoint()
            need(not outcome['fatal'], 'fixed wave had transport/identity/oracle failure; later slots unexecuted')
        current['process_after_c4_responses'] = proc_snapshot(controller.child.pid, controller.birth)
        current['c4_response_window_process_cpu'] = scope_cpu(current['process_before_c4'], current['process_after_c4_responses'])
        current['fixture_after_measurement'] = fixture_witness(state, seed, deadline)
        need(same_fixture(initial, current['fixture_after_measurement']), 'measured queries changed original fixture')
        current['status'] = 'workload_complete'
    except BaseException as error:
        current['status'] = 'failed'
        current['errors'].append({'where': 'controller', 'error': type(error).__name__ + ': ' + str(error)})
    finally:
        retain_interrupted_rows(journal, current['setup'] + [row for row in slots if row['controller'] == index])
        if controller is not None:
            current['startup'] = controller.startup
            try:
                current['shutdown'] = controller.close()
                shutdown = current['shutdown']
                need(shutdown.get('original_child_reaped') is True and shutdown.get('waited') is not None
                     and shutdown['waited']['exit_code'] == 0 and not shutdown.get('errors')
                     and shutdown.get('reader_error') is None and not shutdown.get('unmatched'),
                     'original controller shutdown/custody/wire completion failed')
                if 'process_before_c4' in current:
                    current['c4_inclusive_cpu'] = scope_cpu(current['process_before_c4'], waited=shutdown['waited'])
                if 'process_before_c1' in current:
                    current['all_measured_plus_tail_cpu'] = scope_cpu(current['process_before_c1'], waited=shutdown['waited'])
            except BaseException as error:
                current['status'] = 'failed'
                current['errors'].append({'where': 'shutdown', 'error': type(error).__name__ + ': ' + str(error)})
        if initial is not None:
            try:
                final = fixture_witness(state, seed, time.monotonic() + 120)
                current['fixture_after_shutdown'] = final
                need(same_fixture(initial, final), 'final original fixture differs')
                current['original_fixture_unchanged'] = True
            except BaseException as error:
                current['status'] = 'failed'
                current['errors'].append({'where': 'final_fixture', 'error': type(error).__name__ + ': ' + str(error)})
        current['finished_utc'] = utc()
        if STOP_SIGNUM is not None:
            current['status'] = 'failed'
            current['errors'].append({'where': 'termination', 'first_signal': STOP_SIGNUM,
                                      'error': 'stop requested; no future controller or wave'})
        current['setup_requests_all_succeeded'] = len(current['setup']) == 3 and all(row['okay'] for row in current['setup'])
        current['performance_errors_retained'] = sum(row['status'] == 'product_failure'
            for row in slots if row['controller'] == index)
        if current['status'] == 'workload_complete' and not current['errors']:
            current['status'] = 'complete'
        checkpoint()
        print(json.dumps({'controller': index, 'arm': arm, 'status': current['status'],
                          'performance_errors': current['performance_errors_retained'],
                          'original_fixture_unchanged': current.get('original_fixture_unchanged', False)}), flush=True)
    return current['status'] == 'complete'


def summarize(report, slots, waves):
    summaries = {}
    for arm in ('A', 'B'):
        controllers = [value for value in report['controllers'] if value['arm'] == arm]
        modes = {}
        for concurrency in (1, 4):
            selected = [row for row in slots if row['arm'] == arm and row['concurrency'] == concurrency]
            selected_waves = [row for row in waves if row['arm'] == arm and row['concurrency'] == concurrency]
            attempted = sum(row.get('write_attempts') == 1 for row in selected)
            successes = sum(row['okay'] for row in selected)
            wall = sum(row.get('wall_seconds', 0.0) for row in selected_waves)
            cpu_key = 'c1_process_cpu' if concurrency == 1 else 'c4_inclusive_cpu'
            cpu_available = len(controllers) == 2 and all(cpu_key in item for item in controllers)
            cpu = {key: sum(item[cpu_key][key] for item in controllers) for key in (
                'observed_seconds', 'lower_seconds', 'upper_seconds')} if cpu_available else None
            modes['C' + str(concurrency)] = {'planned': len(selected), 'attempted': attempted,
                'successes': successes, 'failures': sum(row['status'] not in ('unexecuted', 'succeeded') for row in selected),
                'unexecuted': sum(row['status'] == 'unexecuted' for row in selected), 'wall_seconds': wall,
                'successful_calls_per_second': successes / wall if wall > 0 else None,
                'wall_seconds_per_attempt': wall / attempted if attempted else None,
                'cpu': cpu, 'cpu_seconds_per_attempt': cpu['observed_seconds'] / attempted if cpu and attempted else None,
                'cpu_seconds_per_success': cpu['observed_seconds'] / successes if cpu and successes else None}
        waits = [item['shutdown']['waited'] for item in controllers if item.get('shutdown', {}).get('waited') is not None]
        summaries[arm] = {'modes': modes, 'controllers': len(controllers),
            'wholelife_wait4_cpu_seconds': sum(item['total_cpu_seconds'] for item in waits),
            'wholelife_wait4_max_rss_kib': max((item['max_rss_kib'] for item in waits), default=None),
            'complete_wait_receipts': len(waits) == 2}

    a, b = summaries['A']['modes'], summaries['B']['modes']
    gates = {'complete_fixed_inventory': len(slots) == 80 and len(waves) == 32
        and all(row['status'] != 'unexecuted' and row.get('write_attempts') == 1 for row in slots)
        and all(row['status'] in ('succeeded', 'complete_with_failures') for row in waves),
        'all_controller_custody_and_fixture_proofs': len(report['controllers']) == 4 and all(
            item['status'] == 'complete' and item.get('original_fixture_unchanged') is True for item in report['controllers']),
        'all_host_gates_clear': report.get('all_host_gates_clear') is True,
        'all_qualified_inputs_unchanged': report.get('qualified_inputs_unchanged') is True,
        'candidate_c1_8_correct': b['C1']['successes'] == 8,
        'baseline_c1_8_correct_for_cpu_attribution': a['C1']['successes'] == 8,
        'candidate_c4_32_correct': b['C4']['successes'] == 32,
        'candidate_c4_successes_not_lower': b['C4']['successes'] >= a['C4']['successes']}
    gates['actual_client_pending_matches_each_fixed_wave'] = all(
        row.get('client_pending_count_at_write') == row['concurrency']
        and len(set(row.get('client_pending_ids_at_write', []))) == row['concurrency'] for row in waves)
    ratios = {}

    def ratio_gate(name, numerator, denominator, limit, minimum=False):
        if numerator is None or denominator is None or denominator <= 0:
            ratios[name] = None
            gates[name] = False
        else:
            value = numerator / denominator
            ratios[name] = value
            gates[name] = value >= limit if minimum else value <= limit

    ratio_gate('c1_wall_per_attempt_le_1_10', b['C1']['wall_seconds_per_attempt'], a['C1']['wall_seconds_per_attempt'], 1.10)
    for mode, denominator, gate in (('C1', 'attempted', 'c1_cpu_per_attempt_le_1_10'),
                                   ('C4', 'attempted', 'c4_inclusive_cpu_per_attempt_le_1_10'),
                                   ('C4', 'successes', 'c4_inclusive_cpu_per_success_le_1_10')):
        upper = b[mode]['cpu']['upper_seconds'] / b[mode][denominator] if b[mode]['cpu'] and b[mode][denominator] else None
        lower = a[mode]['cpu']['lower_seconds'] / a[mode][denominator] if a[mode]['cpu'] and a[mode][denominator] else None
        ratio_gate(gate, upper, lower, 1.10)
    ratio_gate('c4_successful_calls_per_second_ge_1_50', b['C4']['successful_calls_per_second'],
               a['C4']['successful_calls_per_second'], 1.50, minimum=True)
    baseline_rss = summaries['A']['wholelife_wait4_max_rss_kib']
    candidate_rss = summaries['B']['wholelife_wait4_max_rss_kib']
    rss_limit = max(baseline_rss * 1.10, baseline_rss + 4096) if baseline_rss is not None else None
    gates['wholelife_max_rss_regression_guard'] = (rss_limit is not None and candidate_rss is not None
        and summaries['A']['complete_wait_receipts'] and summaries['B']['complete_wait_receipts']
        and candidate_rss <= rss_limit)
    gates['no_observed_controller_children_or_reaped_child_cpu'] = len(report['controllers']) == 4 and all(
        all(point in item and item[point]['cutime_ticks'] == item[point]['cstime_ticks'] == 0
            and bool(item[point]['thread_children'])
            and not any(error['field'] == 'thread_children' for error in item[point]['errors'])
            and not any(item[point]['thread_children'].values()) for point in ('process_before_c1', 'process_before_c4', 'process_after_c4_responses'))
        for item in report['controllers'])
    return {'arms': summaries, 'numeric_gates': gates, 'ratios': ratios,
            'rss_limit_kib': rss_limit, 'candidate_performance_gates_passed': all(gates.values()),
            'baseline_zero_c4_success_cpu_per_success_undefined': a['C4']['successes'] == 0,
            'all_measured_queries_successful': all(row['okay'] for row in slots),
            'all_setup_queries_successful': len(report['controllers']) == 4 and all(item['setup_requests_all_succeeded'] for item in report['controllers']),
            'measurement_scope': 'fixed native client waves on private flat synthetic archive; not saturated-server or multi-host throughput',
            'tail_cpu_scope': 'inclusive allocation through original wait4, with conservative endpoint bounds; not exact pure-C4 CPU',
            'memory_scope': 'wholelife wait4 peak regression guard; no steady-state or soak claim'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--protocol', type=Path, required=True)
    parser.add_argument('--out', type=Path, default=EXPECTED_OUT)
    args = parser.parse_args()
    # Preparation artifacts are intentionally not executable experiments.
    need(FINAL_BINDINGS_READY and isinstance(PROTOCOL_SHA, str) and ID_RE.fullmatch(PROTOCOL_SHA)
         and isinstance(QUALIFICATION_CHAIN_SHA, str) and ID_RE.fullmatch(QUALIFICATION_CHAIN_SHA),
         'final candidate/protocol identities not frozen; no controller or fixture started')
    protocol_receipt, protocol_raw = bytes_receipt(args.protocol, maximum=1024 * 1024, keep=True)
    need(protocol_receipt['sha256'] == PROTOCOL_SHA, 'frozen protocol SHA differs')
    protocol = document(protocol_raw)
    need(protocol.get('bindings_ready') is True, 'protocol candidate bindings are not final')
    need(protocol['qualification_chain_loader_sha256'] == QUALIFICATION_CHAIN_SHA,
         'explicit qualification-chain validator binding differs')
    need(args.out == EXPECTED_OUT and protocol['out'] == str(EXPECTED_OUT), 'only fixed fresh experiment output is admitted')
    need(protocol['controller_order'] == list(ORDER) and protocol['planned_measured_calls'] == 80
         and protocol['planned_waves'] == 32 and protocol['product_query_budget_seconds'] == 3
         and protocol['client_query_budget_seconds'] == 10
         and protocol['setup']['fixed_idle_seconds_after_kickoff'] == 60, 'fixed protocol layout differs')
    need(sys.platform == 'linux', 'x230 Linux only')
    os.umask(0o077)
    out = direct(args.out, fresh=True)
    out.mkdir(mode=0o700)
    sync_directory(out.parent)
    create(out / 'protocol.original.json', protocol_raw)
    slots, waves = plan_slots()
    report = {'schema': 'hepta-a48-native-archive-cohort/v1', 'started_utc': utc(), 'phase': 'preflight',
              'complete': False, 'passed': False, 'performance_adopted': False, 'controllers': [],
              'slots': slots, 'waves': waves, 'blocks': [], 'errors': [], 'protocol': protocol_receipt,
              'native_mcp_wire': True, 'direct_index_test_entry': False, 'service_mutations': 0,
              'server_cohort_membership_observed': False,
              'server_admission_timestamps_observed': False,
              'native_C4_scope': 'four simultaneously pending client RPC IDs; server SDK scheduling and cohort membership are not instrumented or guaranteed',
              'ssh_or_agent_accesses': 0, 'automatic_retries': 0, 'synthetic_records_are_native_admissions': False,
              'planned_measured_calls': 80, 'planned_waves': 32, 'planned_real_native_seeds': 4,
              'planned_index_kickoffs': 4, 'planned_fixed_archive_warmups': 4,
              'prior_results_pooled': False, 'A40_in_new_performance_totals': False,
              'production_deployed': False, 'optimization_exhausted_claim': False}
    report_path = out / 'report.json'
    bundles, inputs = {}, [protocol_receipt]
    journal = (out / 'calls.jsonl').open('xb')

    def checkpoint():
        report['observed_measured_write_attempts'] = sum(row.get('write_attempts') == 1 for row in slots)
        report['observed_measured_successes'] = sum(row['okay'] for row in slots)
        report['unexecuted_measured_slots'] = [row['slot'] for row in slots if row['status'] == 'unexecuted']
        save(report_path, report)

    checkpoint()
    try:
        self_receipt, raw = bytes_receipt(Path(__file__).absolute(), maximum=1024 * 1024, keep=True)
        inputs.append(self_receipt)
        create(out / 'harness.original.py', raw)
        small, receipt, raw = pinned_module('frozen_small_for_a42_native_cohort', SMALL_HELPER, SMALL_SHA)
        inputs.append(receipt)
        create(out / 'small-helper.original.py', raw)
        native, receipt, raw = pinned_module('frozen_r07_for_a42_native_cohort', NATIVE_DRIVER, NATIVE_SHA)
        inputs.append(receipt)
        create(out / 'native-driver.original.py', raw)
        qualification_chain, receipt, raw = pinned_module('frozen_a43_explicit_qualification_chain',
                                                         QUALIFICATION_CHAIN, QUALIFICATION_CHAIN_SHA)
        inputs.append(receipt)
        create(out / 'qualification-chain-loader.original.py', raw)
        report['qualification_chain_loader'] = receipt
        report['frozen_inputs'] = inputs
        report['disk_gate'] = disk_gate(out)
        need(report['disk_gate']['clear'], 'insufficient available space/inodes for fixed private fixtures')
        entry_receipt, entry_raw = bytes_receipt(ENTRY_PATH, maximum=1024 * 1024, keep=True)
        worker_receipt, worker_raw = bytes_receipt(WORKER_PATH, maximum=1024 * 1024, keep=True)
        need(entry_receipt['sha256'] == ENTRY_SHA and worker_receipt['sha256'] == WORKER_SHA
             and len(entry_raw) == ENTRY_BYTES and len(worker_raw) == WORKER_BYTES, 'original A48 guardian pin differs')
        entry, worker = document(entry_raw), document(worker_raw)
        need(entry['schema'] == ENTRY_SCHEMA and entry['qualified'] is True
             and entry['passed'] is True and entry['guarded_qualification_complete'] is True
             and entry['parent_unchanged_after_attempt'] is True
             and entry['reused_dependencies_unchanged'] is True
             and not entry.get('error') and not entry.get('errors'), 'original A48 guardian is incomplete')
        need(worker['schema'] == WORKER_SCHEMA and worker['passed'] is True
             and worker['strict_fresh_artifacts_verified'] is True
             and worker['required_test_coverage_verified'] is True
             and worker['reused_dependencies_unchanged'] is True
             and not worker.get('error') and not worker.get('errors'), 'original A48 worker postchecks are incomplete')
        inputs.extend((entry_receipt, worker_receipt))
        create(out / 'qualification-entry.original.json', entry_raw)
        create(out / 'qualification-worker.original.json', worker_raw)
        report['qualification_entry'], report['qualification_worker'] = entry_receipt, worker_receipt
        for arm in ('A', 'B'):
            check_stop()
            binding = protocol['bindings'][arm]
            path = direct(Path(binding['qualification_path']))
            pinned, qualified_raw = bytes_receipt(path, keep=True)
            need(pinned['sha256'] == binding['qualification_sha256'], 'qualification identity differs: ' + arm)
            bundle = qualification_chain.load_qualification(native, path, arm, out)
            compact = json.dumps(bundle['source_map'], sort_keys=True, separators=(',', ':')).encode()
            need(bundle['qualification_schema'] == binding['qualification_schema']
                 and bundle['source_files'] == binding['source_files']
                 and sha(compact) == binding['source_map_compact_sha256']
                 and bundle['binary']['sha256'] == binding['release_sha256'], 'qualified source/release differs: ' + arm)
            need(not out.is_relative_to(Path(bundle['source'])), 'fixture would change qualified source')
            bundle['version'] = binding['version']
            if arm == 'B':
                need(qualification_chain.same_receipt(pinned, bundle['report']), 'loaded qualification receipt changed')
                prepared = document(qualified_raw)['source_input']
                need(set(prepared) == set(bundle['source_map'])
                     and qualification_chain.map_sha(prepared) == binding['prepared_source_map_compact_sha256'],
                     'prepared candidate source binding differs')
                for ref in (entry['qualification_report'], worker['qualifier_report'],
                            worker['strict_fresh_artifact_evidence']['qualification_report']):
                    need(qualification_chain.same_receipt(ref, bundle['report']), 'guardian qualification receipt differs')
                need(qualification_chain.same_receipt(entry['guarded_worker_report'], worker_receipt),
                     'guardian final worker receipt differs')
                if 'worker_report' in entry:
                    need(qualification_chain.same_receipt(entry['worker_report'], worker_receipt),
                         'guardian optional worker receipt differs')
                need(entry['source_after'] == bundle['source_map'], 'guardian/candidate source differs')
            bundles[arm] = bundle
        need(bundles['A']['binary']['sha256'] != bundles['B']['binary']['sha256'], 'distinct candidate release required')
        report['qualifications'] = bundles
        Controller = controller_type(small)
        for block, controllers in enumerate(((0, 1), (2, 3))):
            check_stop()
            current_block = {'index': block, 'controllers': list(controllers), 'status': 'checking_inputs', 'started_utc': utc()}
            report['blocks'].append(current_block)
            try:
                for bundle in bundles.values():
                    qualification_chain.assert_bundle_unchanged(native, bundle)
                for item in inputs:
                    need(bytes_receipt(Path(item['path'])) == item, 'frozen harness/protocol/helper changed')
                gate = host_gate(native)
                path = out / ('block-' + str(block) + '.host-before.json')
                create(path, canonical(gate))
                current_block['host_before'] = bytes_receipt(path)
                current_block['host_before_clear'] = gate['clear']
                need(gate['clear'], 'busy/incomplete before-block host gate')
                current_block['status'] = 'running'
                checkpoint()
                for index in controllers:
                    arm = ORDER[index]
                    report['phase'] = 'controller-' + str(index) + '-' + arm
                    need(run_controller(index, arm, bundles[arm], out, report, slots, waves,
                                        native, small, Controller, journal, checkpoint),
                         'controller setup/workload/integrity failed; future controllers unexecuted')
                current_block['status'] = 'complete'
            except BaseException as error:
                current_block['status'] = 'failed'
                current_block['error'] = type(error).__name__ + ': ' + str(error)
            finally:
                try:
                    gate = host_gate(native)
                    path = out / ('block-' + str(block) + '.host-after.json')
                    create(path, canonical(gate))
                    current_block['host_after'] = bytes_receipt(path)
                    current_block['host_after_clear'] = gate['clear']
                    need(gate['clear'], 'busy/incomplete after-block host gate')
                    for bundle in bundles.values():
                        qualification_chain.assert_bundle_unchanged(native, bundle)
                    current_block['qualified_inputs_unchanged'] = True
                except BaseException as error:
                    current_block['status'] = 'failed'
                    current_block.setdefault('final_errors', []).append(type(error).__name__ + ': ' + str(error))
                current_block['finished_utc'] = utc()
                checkpoint()
            need(current_block['status'] == 'complete', 'block failed; remaining block unexecuted')
        for item in inputs:
            need(bytes_receipt(Path(item['path'])) == item, 'frozen original changed at end')
        check_stop()
        report['qualified_inputs_unchanged'] = all(block.get('qualified_inputs_unchanged') is True for block in report['blocks'])
        report['all_host_gates_clear'] = len(report['blocks']) == 2 and all(
            block.get('host_before_clear') is True and block.get('host_after_clear') is True for block in report['blocks'])
        report['complete'] = True
        report['phase'] = 'complete'
    except BaseException as error:
        report['phase'] = 'failed'
        report['errors'].append(type(error).__name__ + ': ' + str(error))
    finally:
        retain_interrupted_rows(journal, slots)
        journal.flush()
        os.fsync(journal.fileno())
        journal.close()
        report['calls_file'] = bytes_receipt(out / 'calls.jsonl', maximum=16 * 1024 * 1024)
        for row in slots:
            if row['status'] == 'unexecuted':
                row['unexecuted_reason'] = 'fixed experiment not reached after setup, host, input, custody, transport or oracle failure; never retried'
        for wave in waves:
            if wave['status'] not in ('succeeded', 'complete_with_failures'):
                attempted = sum(slots[slot].get('write_attempts') == 1 for slot in wave['slot_ids'])
                wave['status'] = 'interrupted_unknown' if attempted else 'unexecuted'
                wave['original_write_attempts'] = attempted
        report['analysis'] = summarize(report, slots, waves)
        report['first_termination_signal'] = STOP_SIGNUM
        report['stop_requested'] = STOP_SIGNUM is not None
        if STOP_SIGNUM is not None:
            report['complete'] = False
            report['phase'] = 'failed'
            report['errors'].append('first termination signal retained: ' + str(STOP_SIGNUM))
        report['passed'] = (report['complete'] and report['analysis']['candidate_performance_gates_passed']
                            and STOP_SIGNUM is None)
        report['finished_utc'] = utc()
        checkpoint()
        print(json.dumps({'report': str(report_path), 'complete': report['complete'], 'passed': report['passed'],
                          'measured_write_attempts': report['observed_measured_write_attempts'],
                          'measured_successes': report['observed_measured_successes'],
                          'unexecuted': len(report['unexecuted_measured_slots']),
                          'all_native_setup_queries_successful': report['analysis']['all_setup_queries_successful']}), flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, stop_requested)
    signal.signal(signal.SIGINT, stop_requested)
    raise SystemExit(main())

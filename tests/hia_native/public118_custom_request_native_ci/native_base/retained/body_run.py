"""Capture real persistent Local text-body sequences and complete owned state."""
from __future__ import annotations
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import select
import signal
import stat
import struct
import subprocess
import sys
import time
import traceback

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import cases
import observations

DEADLINE = 60
ENVIRONMENT = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'TZ': 'UTC'}


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def dump(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def q(*values):
    return struct.pack('<' + 'Q' * len(values), *values)


def canonical(work, raw):
    return os.path.realpath(os.path.join(os.fsencode(work), raw)).decode('utf-8', 'replace').encode()


def requests(spec, work):
    result = [b'HVCACH01' + bytes(40), b'HHISTQ01' + bytes(56)]
    for path, value in spec['cache']:
        key = canonical(work, path); value = value.encode()
        result.append(b'HVCACH01' + q(2, 0, len(key), len(value), 0) + key + value)
    for path, value, cap in spec['history']:
        key = canonical(work, path); value = value.encode()
        result.append(b'HHISTQ01' + q(1, cap, len(key), len(value), 0, 0, 0) + key + value)
    if spec['cache_poison']:
        result.append(b'HVCACH01' + q(9, 0, 0, 0, 0))
    if spec['history_poison']:
        result.append(b'HHISTQ01' + q(3, 0, 0, 0, 0, 0, 0))
    setup_count = len(result)
    for index, operation in enumerate(spec['operations']):
        result.append(cases.request(operation, work, index + 1))
    return result, setup_count


def setup(spec, work):
    work.mkdir()
    root = os.fsencode(work)
    def target(name):
        if not name or name.startswith(b'/') or b'..' in name.split(b'/') or b'\0' in name:
            raise ValueError('setup path is outside the private ordinary fixture')
        return os.path.join(root, name)
    for name in spec['directories']:
        os.makedirs(target(name), mode=0o750, exist_ok=False)
    for name, content, mode in spec['files']:
        path = target(name); os.makedirs(os.path.dirname(path), mode=0o750, exist_ok=True)
        with open(path, 'xb') as stream:
            stream.write(content)
        os.chmod(path, mode)
    for name, original in spec['hardlinks']:
        os.link(target(original), target(name))
    for name, destination in spec['symlinks']:
        if destination.startswith(b'/') or b'..' in destination.split(b'/'):
            raise ValueError('symlink fixture escapes the work directory')
        os.symlink(destination, target(name))
    for name, mode in spec['directory_modes']:
        os.chmod(target(name), mode)


def blob(vault, raw):
    row = pin(raw); path = vault / (row['sha256'] + '.bin')
    if path.exists():
        if path.read_bytes() != raw:
            raise ValueError('content-addressed observation differs')
    else:
        path.write_bytes(raw)
    return dict(path=path.name, **row)


def tree_snapshot(work, vault):
    root = os.fsencode(work); nodes = []; groups = {}
    def visit(folder, prefix):
        for entry in sorted(os.scandir(folder), key=lambda value: value.name):
            name = prefix + entry.name; info = entry.stat(follow_symlinks=False)
            row = dict(path_hex=name.hex(), mode=stat.S_IMODE(info.st_mode), uid=info.st_uid,
                       gid=info.st_gid, links=info.st_nlink)
            if stat.S_ISREG(info.st_mode):
                try:
                    with open(entry.path, 'rb') as stream: raw = stream.read()
                except PermissionError:
                    # Quiescent fixture capture only: restore the exact original mode
                    # before the next actual tool operation; no runtime policy lives here.
                    os.chmod(entry.path, stat.S_IMODE(info.st_mode) | 0o400)
                    try:
                        with open(entry.path, 'rb') as stream: raw = stream.read()
                    finally:
                        os.chmod(entry.path, stat.S_IMODE(info.st_mode))
                if len(raw) != info.st_size or stat.S_IMODE(entry.stat(follow_symlinks=False).st_mode) != stat.S_IMODE(info.st_mode):
                    raise ValueError('ordinary file changed during its completed observation')
                row.update(kind='file', content=blob(vault, raw))
                groups.setdefault((info.st_dev, info.st_ino), []).append(name.hex())
            elif stat.S_ISDIR(info.st_mode):
                row['kind'] = 'directory'
            elif stat.S_ISLNK(info.st_mode):
                row.update(kind='symlink', target_hex=os.readlink(entry.path).hex())
            else:
                raise ValueError('ordinary fixture contains a special filesystem object')
            nodes.append(row)
            if row['kind'] == 'directory':
                visit(entry.path, name + b'/')
    visit(root, b'')
    return dict(nodes=sorted(nodes, key=lambda row: bytes.fromhex(row['path_hex'])),
                hardlink_groups=sorted(sorted(group) for group in groups.values() if len(group) > 1))


def remaining(deadline):
    value = deadline - time.monotonic()
    if value <= 0:
        raise TimeoutError('ordinary root process exceeded its original 60-second deadline')
    return value


def send(fd, raw, deadline, retained):
    offset = 0
    while offset < len(raw):
        _, writable, _ = select.select([], [fd], [], remaining(deadline))
        if not writable:
            raise TimeoutError('ordinary input write exceeded its original deadline')
        try:
            count = os.write(fd, raw[offset:offset + 65536])
        except BlockingIOError:
            continue
        if count <= 0:
            raise RuntimeError('ordinary input made no progress')
        retained.write(raw[offset:offset + count]); offset += count


def receive(fd, size, deadline, retained):
    raw = bytearray()
    while len(raw) < size:
        readable, _, _ = select.select([fd], [], [], remaining(deadline))
        if not readable:
            raise TimeoutError('ordinary output read exceeded its original deadline')
        try:
            part = os.read(fd, min(65536, size - len(raw)))
        except BlockingIOError:
            continue
        if not part:
            raise RuntimeError('ordinary response ended before the complete frame')
        raw.extend(part); retained.write(part)
    return bytes(raw)


def response(request, raw, expected):
    if request[:8] == b'HVCACH01':
        if raw != b'HVCAR001' + bytes(24):
            raise ValueError('cache setup response differs')
        return dict(kind='cache-fixture', **pin(raw))
    if request[:8] == b'HHISTQ01':
        if len(raw) != 64 or raw[:8] != b'HHISTR01':
            raise ValueError('history setup response differs')
        kind, body, total, snapshots, queue, poisoned, zero = observations.words(raw, 7, 8)
        if kind or body or zero or poisoned not in (0, 1):
            raise ValueError('history setup fields differ')
        return dict(kind='history-fixture', total_bytes=total, snapshots=snapshots,
                    queue=queue, poisoned=bool(poisoned), **pin(raw))
    if len(raw) < 32 or raw[:8] != b'HEXTRP01':
        raise ValueError('ordinary body response magic differs')
    op, kind, extent = observations.words(raw, 3, 8)
    if (op, kind, extent) != (expected['op'], expected['kind'], len(raw) - 32):
        raise ValueError('ordinary body result differs: ' + repr((expected, raw[32:1024])))
    raw[32:].decode('utf-8')
    return dict(kind='body', operation=op, result_kind=kind, message=pin(raw[32:]), **pin(raw))


def compact_observers(frames, vault):
    def state(value):
        if isinstance(value, bytes):
            return blob(vault, value)
        if isinstance(value, list):
            return [state(item) for item in value]
        if isinstance(value, dict):
            return {(key.hex() if isinstance(key, bytes) else key): state(item) for key, item in value.items()}
        return value
    return [dict(row, state=state(row['state'])) for row in frames]


def run_case(spec, binary, folder, vault):
    folder.mkdir()
    work = folder / 'work'; setup(spec, work)
    frames, setup_count = requests(spec, work)
    descriptors = [dict(row, generation=index+1) for index,row in enumerate(spec['operations'])]
    result = dict(schema='hepta.extract-lines.ordinary-case.v1', name=spec['name'],
                  status='RUNNING', operations=descriptors, setup_frames=setup_count,
                  input_frames=len(frames), command=[str(binary)], cwd=str(work),
                  environment=ENVIRONMENT, process_deadline_seconds=DEADLINE,
                  filesystem_before=tree_snapshot(work, vault), responses=[], files_after_body=[],
                  process_reaped=False, timed_out=False, exit_code=None)
    dump(folder / 'result.json', result)
    process = None; began = time.monotonic(); deadline = began + DEADLINE
    with (folder / 'stdin.bin').open('wb') as retained_input, \
            (folder / 'stdout.bin').open('wb') as retained_output, \
            (folder / 'stderr.bin').open('wb') as retained_error:
        try:
            process = subprocess.Popen([str(binary)], cwd=work, env=ENVIRONMENT,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=retained_error,
                start_new_session=True, close_fds=True, bufsize=0)
            result['pid'] = process.pid
            os.set_blocking(process.stdin.fileno(), False)
            os.set_blocking(process.stdout.fileno(), False)
            for index, frame in enumerate(frames):
                send(process.stdin.fileno(), q(len(frame)) + frame, deadline, retained_input)
                header = receive(process.stdout.fileno(), 8, deadline, retained_output)
                size, = struct.unpack('<Q', header)
                if not 8 <= size <= 134217728:
                    raise ValueError('ordinary response exceeds its admitted frame domain')
                raw = receive(process.stdout.fileno(), size, deadline, retained_output)
                expected = spec['operations'][index - setup_count] if index >= setup_count else None
                result['responses'].append(response(frame, raw, expected))
                if expected is not None:
                    result['files_after_body'].append(dict(generation=index - setup_count + 1,
                        snapshot=tree_snapshot(work, vault)))
                dump(folder / 'result.json', result)
            process.stdin.close()
            process.wait(timeout=remaining(deadline))
            result['process_reaped'] = True
            extra = bytearray()
            while True:
                try:
                    chunk = os.read(process.stdout.fileno(), 65536)
                except BlockingIOError:
                    select.select([process.stdout.fileno()], [], [], remaining(deadline))
                    continue
                if not chunk:
                    break
                extra.extend(chunk); retained_output.write(chunk)
            if process.returncode != 0 or extra:
                raise ValueError('ordinary original did not complete its exact response stream')
            retained_input.flush(); retained_output.flush(); retained_error.flush()
            decoded = observations.decode((folder / 'stderr.bin').read_bytes(), spec['operations'])
            result['observations'] = compact_observers(decoded, vault)
            result.update(status='PASS', process_reaped=True)
        except BaseException as error:
            result.update(status='FAIL', error=repr(error), traceback=traceback.format_exc(),
                          timed_out=isinstance(error, (TimeoutError, subprocess.TimeoutExpired)))
            if process is not None:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
                result['process_reaped'] = True
                if process.stdin and not process.stdin.closed:
                    process.stdin.close()
                while True:
                    try:
                        chunk = os.read(process.stdout.fileno(), 65536)
                    except BlockingIOError:
                        select.select([process.stdout.fileno()], [], [], .1)
                        continue
                    if not chunk:
                        break
                    retained_output.write(chunk)
            raise
        finally:
            result['exit_code'] = process.returncode if process is not None else None
            result['elapsed_seconds'] = time.monotonic() - began
            retained_input.flush(); retained_output.flush(); retained_error.flush()
            result['streams'] = {name: pin((folder / (name + '.bin')).read_bytes())
                                 for name in ('stdin', 'stdout', 'stderr')}
            if process is not None and process.stdout:
                process.stdout.close()
            dump(folder / 'result.json', result)
    return result


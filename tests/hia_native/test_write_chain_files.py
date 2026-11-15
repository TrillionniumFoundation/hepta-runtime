"""Execute real history/undo owners and retain complete filesystem observations.

The same absolute fixture directory and exact request bytes are reused for the
HIA executable and the unchanged Rust owners. TIDs alone are transport metadata.
Large file contents are streamed into retained gzip transcripts, never replaced
by an expected-output model or a shortened semantic input.
"""
from __future__ import annotations
import argparse
import ctypes
import gzip
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import signal
import stat
import struct
import subprocess
import time


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def packet(op, path, context=1):
    return b'HFWRT001' + struct.pack('<QQQ', op, context, len(path)) + bytes(32) + path


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def exact(pipe, size, deadline):
    result = bytearray()
    while len(result) < size:
        left = deadline - time.monotonic()
        if left <= 0 or not select.select([pipe], [], [], left)[0]:
            raise TimeoutError('actual owner response deadline')
        raw = os.read(pipe.fileno(), min(65536, size - len(result)))
        if not raw:
            raise EOFError(('actual owner response ended', size, len(result)))
        result.extend(raw)
    return bytes(result)


def snapshot(fixture, stream, ordinal):
    base = os.fsencode(fixture)
    paths = []
    for parent, directories, files in os.walk(base, followlinks=False):
        directories.sort(); files.sort()
        for name in directories + files:
            paths.append(os.path.join(parent, name))
    inventory = []
    for path in sorted(paths):
        metadata = os.lstat(path)
        kind = stat.S_IFMT(metadata.st_mode)
        entry = dict(path_hex=path[len(base) + 1:].hex(), kind=kind,
                     mode=stat.S_IMODE(metadata.st_mode), links=metadata.st_nlink)
        data = None
        if stat.S_ISLNK(metadata.st_mode):
            entry['link_hex'] = os.readlink(path).hex()
        elif stat.S_ISREG(metadata.st_mode):
            entry['bytes'] = metadata.st_size
            try:
                data = open(path, 'rb')
            except OSError as error:
                entry['read_errno'] = error.errno
        header = json_bytes(dict(ordinal=ordinal, **entry))
        stream.write(struct.pack('<QQ', len(header), metadata.st_size if data else 0))
        stream.write(header)
        if data:
            digest = hashlib.sha256(); count = 0
            with data:
                while raw := data.read(1 << 20):
                    stream.write(raw); digest.update(raw); count += len(raw)
            assert count == metadata.st_size
            entry['sha256'] = digest.hexdigest()
        inventory.append(entry)
    stream.write(struct.pack('<QQ', 0, ordinal))
    return inventory


def write_pattern(path, size, pattern=b'line one\r\nline two\n'):
    block = (pattern * ((1 << 20) // len(pattern) + 1))[:1 << 20]
    with open(path, 'wb') as handle:
        while size:
            part = block[:min(size, len(block))]
            handle.write(part); size -= len(part)


def execute(binary, fixture, destination, large):
    destination.mkdir()
    fixture.mkdir()
    root = os.fsencode(fixture)
    started = time.monotonic(); sequence = 0; failure = None
    requests = (destination / 'requests.bin').open('xb')
    output = (destination / 'stdout.bin').open('xb')
    normalized = (destination / 'normalized.bin').open('xb')
    events = (destination / 'events.jsonl').open('xb')
    observations = gzip.open(destination / 'filesystem.bin.gz', 'xb', compresslevel=1)
    stderr = (destination / 'stderr.bin').open('xb')
    owner = os.getpid()
    def parent_death():
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != owner:
            os._exit(75)
    process = subprocess.Popen([str(binary)], cwd=fixture, stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=stderr, env={'PATH': ''}, start_new_session=True,
        preexec_fn=parent_death)
    counts = {'save': 0, 'undo': 0, 'success': 0, 'original_error': 0, 'invalid_frames': 0,
              'large_boundary_calls': 0, 'observed_file_bytes': 0}

    def call(op, path, context=1, expected=None, label='', boundary=False):
        nonlocal sequence
        sequence += 1
        data = packet(op, path, context)
        wire = struct.pack('<QQ', len(data), sequence) + data
        requests.write(wire); requests.flush()
        process.stdin.write(wire); process.stdin.flush()
        deadline = min(started + 180, time.monotonic() + 60)
        header = exact(process.stdout, 20, deadline)
        tag, tid, code = struct.unpack('<QQI', header)
        assert tag == sequence and tid > 0
        assert 32 <= code < 0xffff0000, (label, code)
        response = exact(process.stdout, code, deadline)
        assert response[:8] == b'HFWTR001'
        rop, status, length = struct.unpack_from('<QQQ', response, 8)
        assert rop == op and status in (0, 1) and length == len(response) - 32
        if expected is not None:
            assert status == expected, (label, status, response)
        output.write(header + response)
        normalized.write(struct.pack('<QI', tag, code) + response)
        state = snapshot(fixture, observations, sequence)
        counts['save' if op == 1 else 'undo'] += 1
        counts['success' if status == 0 else 'original_error'] += 1
        counts['large_boundary_calls'] += int(boundary)
        counts['observed_file_bytes'] += sum(x.get('bytes', 0) for x in state if 'sha256' in x)
        events.write(json_bytes(dict(ordinal=sequence, label=label, operation=op, path_hex=path.hex(),
            context=context, response_sha256=sha(response), response_bytes=len(response),
            outcome=status, filesystem=state)))
        events.flush()
        return response[32:]

    try:
        # No lexical rewriting of raw Unix paths or lossy display strings.
        samples = [b'', b'a', b'\n', b'\r\n', b'a\r\nb\r\n', b'no newline', b'\0',
                   '汉字🙂\r\n'.encode(), bytes(range(128))]
        for i, content in enumerate(samples):
            path = root + b'/basic-' + str(i).encode()
            Path(os.fsdecode(path)).write_bytes(content)
            call(1, path, expected=0, label='basic-save')
            Path(os.fsdecode(path)).write_bytes(b'external change\n')
            call(2, path, context=1 + i % 2, expected=0, label='basic-undo')
            assert Path(os.fsdecode(path)).read_bytes() == content
            call(2, path, expected=1, label='basic-exhausted')
            os.unlink(path)
        path = root + b'/ten-levels'
        for i in range(12):
            Path(os.fsdecode(path)).write_bytes(('snapshot-%02d\r\n' % i).encode())
            call(1, path, expected=0, label='history-push-12')
        for i in range(11, 1, -1):
            call(2, path, expected=0, label='history-pop-10')
            assert Path(os.fsdecode(path)).read_bytes() == ('snapshot-%02d\r\n' % i).encode()
        call(2, path, expected=1, label='history-per-file-exhausted'); os.unlink(path)

        for name in [b'\xff', b'\xfe\xff', b'\xed\xa0\x80', b'line\nbreak', b'tab\tname',
                     '原始路径🙂'.encode(), b'a' * 255]:
            path = root + b'/' + name
            with open(path, 'wb') as handle: handle.write(b'kept\r\n')
            call(1, path, expected=0, label='raw-path-save')
            with open(path, 'wb') as handle: handle.write(b'changed')
            if len(name) == 255:
                call(2, path, expected=1, label='temp-name-overflow')
            else:
                call(2, path, expected=0, label='raw-path-undo')
                assert open(path, 'rb').read() == b'kept\r\n'
            os.unlink(path)
        for path in [b'', b'a\0b', b'\0', b'.', root + b'/', root + b'/missing',
                     root + b'/' + b'a' * 256, root + b'/' + b'x' * 4096]:
            call(1, path, label='missing-directory-invalid-path-save')
            call(2, path, expected=1, label='missing-directory-invalid-path-undo')
        for invalid in [b'\xff', b'\xed\xa0\x80', b'good\n\xc0\x80', b'\xf4\x90\x80\x80']:
            path = root + b'/bad-utf8'
            with open(path, 'wb') as handle: handle.write(invalid)
            call(1, path, expected=1, label='strict-utf8-save')
            call(2, path, expected=1, label='invalid-read-not-saved'); os.unlink(path)

        path, alias = root + b'/real', root + b'/alias'
        with open(path, 'wb') as handle: handle.write(b'symlink-before')
        os.symlink(b'real', alias)
        call(1, b'./alias', expected=0, label='symlink-save')
        with open(path, 'wb') as handle: handle.write(b'real-after')
        call(2, alias, expected=0, label='symlink-undo-replaces-alias')
        assert not os.path.islink(alias) and open(alias, 'rb').read() == b'symlink-before'
        assert open(path, 'rb').read() == b'real-after'
        call(2, path, expected=1, label='canonical-history-consumed'); os.unlink(path); os.unlink(alias)
        with open(path, 'wb') as handle: handle.write(b'hard-before')
        os.link(path, alias)
        call(1, path, expected=0, label='hard-link-save')
        with open(alias, 'wb') as handle: handle.write(b'hard-after')
        call(2, alias, expected=1, label='hard-link-distinct-canonical-key')
        call(2, path, expected=0, label='hard-link-original-key-undo')
        assert open(alias, 'rb').read() == b'hard-after'
        os.unlink(path); os.unlink(alias)

        for mode in [0o400, 0o644, 0o751, 0o6751, 0o7777]:
            path = root + b'/mode'
            with open(path, 'wb') as handle: handle.write(b'permissions-before')
            call(1, path, expected=0, label='permissions-save')
            with open(path, 'wb') as handle: handle.write(b'after')
            os.chmod(path, mode)
            call(2, path, expected=0, label='permissions-undo')
            assert stat.S_IMODE(os.stat(path).st_mode) == mode
            assert open(path, 'rb').read() == b'permissions-before'
            os.unlink(path)
        path = root + b'/denied'
        with open(path, 'wb') as handle: handle.write(b'not-readable')
        os.chmod(path, 0)
        call(1, path, expected=1, label='read-permission-error')
        call(2, path, expected=1, label='failed-read-has-no-history'); os.unlink(path)

        path, temp = root + b'/failure', root + b'/.octofs_tmp_failure.tmp'
        for target_kind in ['temp-directory', 'target-directory', 'target-missing', 'temp-symlink']:
            with open(path, 'wb') as handle: handle.write(b'failure-before')
            call(1, path, expected=0, label=target_kind + '-save')
            with open(path, 'wb') as handle: handle.write(b'after')
            if target_kind == 'temp-directory': os.mkdir(temp)
            elif target_kind == 'target-directory': os.unlink(path); os.mkdir(path)
            elif target_kind == 'target-missing': os.unlink(path)
            else:
                with open(root + b'/temp-target', 'wb') as handle: handle.write(b'other')
                os.symlink(b'temp-target', temp)
            call(2, path, expected=int(target_kind.endswith('directory')), label=target_kind + '-undo')
            call(2, path, expected=1, label=target_kind + '-consumed-history')
            if os.path.isdir(temp): os.rmdir(temp)
            if os.path.lexists(temp): os.unlink(temp)
            if os.path.isdir(path): os.rmdir(path)
            elif os.path.lexists(path): os.unlink(path)
            if os.path.exists(root + b'/temp-target'): os.unlink(root + b'/temp-target')

        parent = root + b'/gone'; os.mkdir(parent); path = parent + b'/target'
        with open(path, 'wb') as handle: handle.write(b'parent-before')
        call(1, path, expected=0, label='parent-removed-save')
        os.unlink(path); os.rmdir(parent)
        call(2, path, expected=1, label='parent-removed-write-error')
        os.mkdir(parent)
        call(2, path, expected=1, label='parent-removed-consumed-history'); os.rmdir(parent)

        if large:
            for size in [8191, 8192, 8193, 5 << 20, 64 << 20, (64 << 20) + 1]:
                path = root + b'/large-' + str(size).encode()
                write_pattern(path, size)
                expected_hash = hashlib.sha256()
                with open(path, 'rb') as handle:
                    while raw := handle.read(1 << 20): expected_hash.update(raw)
                call(1, path, expected=0, label='full-size-save-' + str(size), boundary=True)
                with open(path, 'wb') as handle: handle.write(b'changed')
                call(2, path, expected=0, label='full-size-undo-' + str(size), boundary=True)
                actual = hashlib.sha256()
                with open(path, 'rb') as handle:
                    while raw := handle.read(1 << 20): actual.update(raw)
                assert os.stat(path).st_size == size and actual.digest() == expected_hash.digest()
                call(2, path, expected=1, label='full-size-consumed-' + str(size), boundary=True)
                os.unlink(path)
            a, b = root + b'/budget-a', root + b'/budget-b'
            for path in (a, b):
                write_pattern(path, (32 << 20) + 1)
                call(1, path, expected=0, label='global-budget-save', boundary=True)
            call(2, a, expected=1, label='global-budget-oldest-evicted', boundary=True)
            call(2, b, expected=0, label='global-budget-latest-retained', boundary=True)
            os.unlink(a); os.unlink(b)
            # An old queue event for the same key can remove a newly pushed
            # oversized snapshot. Preserve that real original behavior instead
            # of turning its explanatory comment into a different algorithm.
            path = root + b'/stale-same-key'
            with open(path, 'wb') as handle: handle.write(b'old')
            call(1, path, expected=0, label='stale-queue-first-save', boundary=True)
            call(2, path, expected=0, label='stale-queue-first-pop', boundary=True)
            write_pattern(path, (64 << 20) + 1)
            call(1, path, expected=0, label='stale-queue-oversized-save', boundary=True)
            call(2, path, expected=1, label='stale-queue-removes-newest', boundary=True)
            os.unlink(path)
        process.stdin.close()
        assert process.wait(timeout=max(1, started + 180 - time.monotonic())) == 0
    except BaseException as error:
        failure = repr(error)
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL); process.wait()
    finally:
        for handle in (requests, output, normalized, events, observations, stderr): handle.close()
    result = dict(schema='hepta.runtime.write-chain-files.v1', status='PASS' if failure is None else 'FAIL',
        failure=failure, executable=str(binary), binary_sha256=sha(binary.read_bytes()),
        fixture=str(fixture), elapsed_seconds=time.monotonic() - started, exit_code=process.returncode,
        actual_processes=1, actual_requests=sequence, counts=counts, full_size_domain=large,
        pid=process.pid, reaped=process.returncode is not None, timeout_seconds=180,
        raw_stdout_includes_tids=True, normalized_excludes_only_tid=True,
        files={path.name: dict(bytes=path.stat().st_size, sha256=sha(path.read_bytes()))
               for path in destination.iterdir() if path.is_file()})
    (destination / 'result.json').write_bytes(json_bytes(result))
    return result


def equal_streams(a, b, compressed=False):
    opening = gzip.open if compressed else open
    digest = hashlib.sha256(); count = 0
    with opening(a, 'rb') as left, opening(b, 'rb') as right:
        while True:
            raw = left.read(1 << 20); other = right.read(1 << 20)
            assert raw == other, ('complete retained transcript differs', a.name, count)
            if not raw: break
            count += len(raw); digest.update(raw)
    return dict(bytes=count, sha256=digest.hexdigest())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--native', required=True, type=Path)
    parser.add_argument('--original', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--large', action='store_true')
    args = parser.parse_args()
    source_identity = sha(Path(__file__).read_bytes())
    args.output.mkdir()
    fixture = args.output / 'fixture'
    native = execute(args.native.resolve(), fixture, args.output / 'native', args.large)
    result = dict(status='FAIL', native=native, original_status='PENDING', test_sha256=source_identity)
    try:
        assert native['status'] == 'PASS', native['failure']
        if args.original:
            shutil.rmtree(fixture)
            original = execute(args.original.resolve(), fixture, args.output / 'original', args.large)
            result['original'] = original
            assert original['status'] == 'PASS', original['failure']
            compared = {}
            for name in ('requests.bin', 'normalized.bin', 'events.jsonl', 'filesystem.bin.gz'):
                compared[name] = equal_streams(args.output / 'native' / name,
                    args.output / 'original' / name, name.endswith('.gz'))
            result.update(status='PASS', original_status='PASS', compared=compared)
        else:
            result['status'] = 'NATIVE_PASS'
        assert sha(Path(__file__).read_bytes()) == source_identity
    except BaseException as error:
        result['failure'] = repr(error)
    (args.output / 'result.json').write_bytes(json_bytes(result))
    print(json.dumps({k: v for k, v in result.items() if k not in ('native', 'original')}, sort_keys=True))
    if result['status'] == 'FAIL': raise SystemExit(1)


if __name__ == '__main__':
    main()

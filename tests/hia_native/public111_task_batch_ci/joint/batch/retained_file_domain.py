"""Complete published 926-file corpus over the new serial callable fixture.

No case or deadline is removed. Python expectations are development evidence;
fresh current original Rust comparison is a separate required gate.
"""
from __future__ import annotations
import argparse
import ctypes
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import stat
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent
REFERENCE = ROOT / 'corpus/reference'
HERE = REFERENCE / 'tests/hia_native'
sys.dont_write_bytecode = True
os.environ['HIA_REFERENCE_RUNTIME'] = str(REFERENCE)
os.environ['HIA_RUNTIME_REPO'] = str(REFERENCE)
sys.path.insert(0, str(ROOT / 'runtime_support/scripts'))
sys.path.insert(0, str(HERE))
from test_batch_write_controller import load, root_packet, expected, cases
import batch_render_reference as render

sha = lambda raw: hashlib.sha256(raw).hexdigest()


def exact(pipe, size, deadline):
    result = bytearray()
    while len(result) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([pipe], [], [], remaining)[0]:
            raise TimeoutError('batch owner response exceeded the actual deadline')
        chunk = os.read(pipe.fileno(), min(65536, size - len(result)))
        if not chunk: raise EOFError(('batch owner exited before complete response', size, len(result)))
        result += chunk
    return bytes(result)


def inventory(fixture, stream, ordinal):
    base = os.fsencode(fixture)
    names = []
    for parent, directories, files in os.walk(base, followlinks=False):
        directories.sort(); files.sort()
        names.extend(os.path.join(parent, name) for name in directories + files)
    rows, full_bytes = [], 0
    for name in sorted(names):
        info = os.lstat(name)
        row = {'path_hex': name[len(base) + 1:].hex(), 'kind': stat.S_IFMT(info.st_mode),
               'mode': stat.S_IMODE(info.st_mode), 'links': info.st_nlink}
        data = None
        if stat.S_ISLNK(info.st_mode): row['link_hex'] = os.readlink(name).hex()
        elif stat.S_ISREG(info.st_mode):
            row['bytes'] = info.st_size
            try: data = open(name, 'rb')
            except OSError as error: row['read_errno'] = error.errno
        header = json.dumps({'ordinal': ordinal, **row}, sort_keys=True, separators=(',', ':')).encode() + b'\n'
        stream.write(struct.pack('<QQ', len(header), info.st_size if data else 0)); stream.write(header)
        if data:
            digest = hashlib.sha256(); size = 0
            with data:
                while chunk := data.read(1 << 20):
                    digest.update(chunk); stream.write(chunk); size += len(chunk)
            assert size == info.st_size
            row['sha256'] = digest.hexdigest(); full_bytes += size
        rows.append(row)
    stream.write(struct.pack('<QQ', 0, ordinal))
    return rows, full_bytes


def execute(binary, reference, fixture, output, *, large=False):
    fixture = fixture.absolute(); fixture.mkdir()
    output.mkdir()
    reference = reference.resolve(strict=True)
    sys.path.insert(0, str(reference / 'tests/hia_native'))
    plan = load('_files_batch_plan_reference', reference / 'tests/hia_native/test_batch_plan.py')
    apply = render.load_apply(reference)
    stderr = (output / 'stderr.bin').open('xb')
    owner = os.getpid()
    def lifetime():
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != owner: os._exit(75)
    process = subprocess.Popen([str(binary.resolve(strict=True))], cwd=fixture, env={'PATH': ''},
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr,
                               preexec_fn=lifetime)
    assert os.getpgid(process.pid) == os.getpgrp()
    requests = gzip.open(output / 'requests.bin.gz', 'xb', compresslevel=1)
    responses = gzip.open(output / 'stdout.bin.gz', 'xb', compresslevel=1)
    normalized = gzip.open(output / 'normalized.bin.gz', 'xb', compresslevel=1)
    files = gzip.open(output / 'filesystem.bin.gz', 'xb', compresslevel=1)
    events = gzip.open(output / 'events.jsonl.gz', 'xb', compresslevel=1)
    report = {'schema': 'hepta.runtime.rebuilt-batch-callable-files.v1', 'status': 'RUNNING',
              'fixture': str(fixture),
              'binary_sha256': sha(binary.read_bytes()), 'binary_bytes': binary.stat().st_size,
              'process_id': process.pid, 'process_group': os.getpgrp(), 'requests': 0,
              'effective_uid': os.geteuid(),
              'outcomes': {'success': 0, 'original_error': 0}, 'observed_file_bytes': 0,
              'domains': {}, 'inherits_outer_process_group': True, 'outer_timeout_seconds': 180,
              'body_requests': 926, 'setup_frames': [], 'native_thread_identity_claimed': False,
              'fresh_current_original_compared': False, 'public_batch_qualified': False,
              'full_async_cancellation_qualified': False}
    started = time.monotonic()
    def call(label, ops, path, raw=None, *, resolved=None, context=1, model=True, display=...):
        report['requests'] += 1
        ordinal = report['requests']
        resolved = os.fsencode(path) if resolved is None else resolved
        display = str(path) if display is ... else display
        wire = root_packet(plan, ops, display, resolved, context)
        packet = struct.pack('<Q', len(wire)) + wire
        requests.write(packet); process.stdin.write(packet); process.stdin.flush()
        deadline = min(started + 180, time.monotonic() + 60)
        header = exact(process.stdout, 8, deadline)
        code, = struct.unpack('<Q', header)
        tag = ordinal
        assert 32 <= code < 0xffff0000, (label, ordinal, code)
        response = exact(process.stdout, code, deadline)
        assert response[:8] == b'HFBWR001'
        kind, count, zero = struct.unpack_from('<3Q', response, 8)
        assert kind in (0, 1) and count == code - 32 and zero == 0
        if model:
            want, changed = expected(plan, apply, raw, ops, display)
            assert response == want, (label, response[:512], want[:512])
            if changed: assert Path(path).read_bytes() == changed[2]
            else: assert Path(path).read_bytes() == raw
        responses.write(header + response)
        normalized.write(struct.pack('<QI', tag, code) + response)
        snapshot, size = inventory(fixture, files, ordinal)
        report['observed_file_bytes'] += size
        report['outcomes']['success' if kind == 0 else 'original_error'] += 1
        report['domains'][label] = report['domains'].get(label, 0) + 1
        events.write(json.dumps({'ordinal': ordinal, 'domain': label, 'request_sha256': sha(wire),
                                 'request_bytes': len(wire), 'response_sha256': sha(response),
                                 'response_bytes': len(response), 'outcome': kind,
                                 'filesystem': snapshot}, sort_keys=True, separators=(',', ':')).encode() + b'\n')
        return kind, response[32:]
    def setup(magic, count, result_magic, expected_size):
        wire = magic + bytes(count * 8)
        packet = struct.pack('<Q', len(wire)) + wire
        requests.write(packet); process.stdin.write(packet); process.stdin.flush()
        deadline = min(started + 180, time.monotonic() + 60)
        header = exact(process.stdout, 8, deadline)
        size, = struct.unpack('<Q', header)
        assert size == expected_size
        response = exact(process.stdout, size, deadline)
        responses.write(header + response)
        assert response[:8] == result_magic and response[8:] == bytes(size - 8)
        report['setup_frames'].append({'input_hex': wire.hex(), 'output_hex': response.hex()})
    try:
        setup(b'HVCACH01', 5, b'HVCAR001', 32)
        setup(b'HHISTQ01', 7, b'HHISTR01', 64)
        path = fixture / 'target'
        path.write_bytes(b'before')
        for display in (None, '', str(path), 'target'):
            for count in (0, 1, 50, 51):
                operations = [None] * count
                resolved = os.fsencode(fixture) + b'/' if display == '' else os.fsencode(path)
                kind, body = call('early_admission', operations, path, b'before',
                                  display=display, resolved=resolved,
                                  model=isinstance(display, str) and display != '')
                if display is None:
                    want, _ = expected(plan, apply, b'before', operations, display)
                    assert kind == 1 and body == want[32:]
                elif display == '':
                    if count in (0, 51):
                        want, _ = expected(plan, apply, b'before', operations, display)
                        assert kind == 1 and body == want[32:]
                    else:
                        assert kind == 1 and body.startswith(b"Failed to read file '': Failed to read '")
                assert path.read_bytes() == b'before'
        for label, raw, ops, display in cases(plan, apply):
            # Public caller path and resolved source are separate owners. This
            # complete body domain fixes an actual absolute Local string.
            if label == 'early_admission': continue
            path.write_bytes(raw)
            call(label, ops, path, raw)
            assert not (fixture / '.octofs_tmp_target.tmp').exists()
        inserts = [{'operation': 'insert', 'start': 0, 'content': 'new'}]
        for mode in (0o000, 0o600, 0o640, 0o755, 0o4755, 0o6750, 0o7777):
            path.write_bytes(b'old\r\n'); os.chmod(path, mode)
            readable = os.geteuid() == 0 or bool(mode & 0o400)
            kind, body = call('existing_mode', inserts, path, b'old\r\n', model=readable)
            if not readable:
                want = f"Failed to read file '{path}': Failed to read '{path}': Permission denied (os error 13)".encode()
                assert kind == 1 and body == want
            assert stat.S_IMODE(path.stat().st_mode) == mode
            os.chmod(path, 0o600)
        path.unlink()
        for name in ('missing', 'missing/child', 'bad\0name'):
            kind, body = call('missing_path', inserts, fixture / name, model=False)
            assert kind == 1 and body == b'File not found: ' + str(fixture / name).encode()
        directory = fixture / 'directory'; directory.mkdir()
        kind, body = call('read_directory', inserts, directory, model=False)
        assert kind == 1 and b'Failed to read file' in body
        directory.rmdir()
        path.write_bytes(b'\xff\xfe')
        kind, body = call('strict_invalid_utf8', inserts, path, model=False)
        assert kind == 1 and b'Failed to read file' in body and path.read_bytes() == b'\xff\xfe'
        path.write_bytes(b'a\r\nb\r\n')
        alias = fixture / 'alias'; alias.symlink_to('target')
        call('symlink_replaced_after_followed_read', inserts, alias, b'a\r\nb\r\n')
        assert not alias.is_symlink() and path.read_bytes() == b'a\r\nb\r\n'
        alias.unlink(); path.unlink()
        path = fixture / ('x' * 255); path.write_bytes(b'old')
        kind, body = call('temporary_name_too_long', inserts, path, model=False)
        assert kind == 1 and body.startswith(b'Atomic write failed for ') and path.read_bytes() == b'old'
        path.unlink()
        path = fixture / 'target'
        path.write_bytes(b'old')
        temporary = fixture / '.octofs_tmp_target.tmp'; temporary.mkdir()
        kind, body = call('temporary_is_directory', inserts, path, model=False)
        assert kind == 1 and body.startswith(b'Atomic write failed for ') and temporary.is_dir()
        temporary.rmdir()
        if large:
            raw = b'old\r\n' + b'x' * ((5 << 20) - 5)
            path.write_bytes(raw)
            call('full_five_mib_file', [{'operation': 'replace', 'start': render.line_id(1, b'old').decode(), 'content': 'new'}], path, raw)
            raw = b'a\nb\nc\n'; path.write_bytes(raw)
            call('full_five_mib_content', [{'operation': 'replace', 'start': render.line_id(2, b'b').decode(), 'content': 'x' * (5 << 20)}], path, raw)
        process.stdin.close()
        remaining = started + 180 - time.monotonic()
        assert remaining > 0
        report['exit_code'] = process.wait(timeout=remaining)
        assert report['exit_code'] == 0
        assert process.stdout.read() == b''
        assert large and report['requests'] == 926
        report['status'] = 'PASS'
    except BaseException as error:
        report.update(status='FAIL', failure=repr(error))
        raise
    finally:
        if process.poll() is None: process.kill(); process.wait()
        report['exit_code'] = process.returncode
        for stream in (requests, responses, normalized, files, events, stderr): stream.close()
        report['elapsed_seconds'] = time.monotonic() - started
        for name in ('requests.bin.gz', 'stdout.bin.gz', 'normalized.bin.gz', 'filesystem.bin.gz', 'events.jsonl.gz', 'stderr.bin'):
            report[name] = {'bytes': (output / name).stat().st_size, 'sha256': sha((output / name).read_bytes())}
        (output / 'result.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--native', type=Path, required=True)
    parser.add_argument('--reference', type=Path, default=REFERENCE)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--large', action='store_true')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    result = execute(args.native.absolute(), args.reference, args.output / 'fixture', args.output / 'native', large=True)
    print(json.dumps(result, sort_keys=True))

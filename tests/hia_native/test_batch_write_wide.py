"""Complete 50 by 5 MiB batch body, retained and compared as byte streams.

The expected diff uses the original layout and an independent affine jump
over uniform FNV-1a bytes. No huge result is copied into a Python object.
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
import signal
import struct
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from batch_render_reference import line_id

COUNT, SIZE = 50, 5 << 20
CHUNK = 1 << 20
sha = lambda data: hashlib.sha256(data).hexdigest()
Q = lambda *values: struct.pack('<' + 'Q' * len(values), *values)


def uniform_hash(value, count):
    """Jump one complete low-byte cycle; the high bits follow an affine map."""
    seed, prime, mask = 2166136261, 16777619, (1 << 32) - 1
    state, period = seed, 0
    while True:
        state = ((state ^ value) * prime) & mask
        period += 1
        if state & 255 == seed & 255: break
        assert period <= 256
    multiplier = pow(prime, period, 1 << 32)
    offset = (state - multiplier * seed) & mask
    times, tail = divmod(count, period)
    state = seed
    while times:
        if times & 1: state = (multiplier * state + offset) & mask
        offset = (multiplier * offset + offset) & mask
        multiplier = (multiplier * multiplier) & mask
        times >>= 1
    for _ in range(tail): state = ((state ^ value) * prime) & mask
    folded = (state >> 16) ^ (state & 65535)
    return ((folded >> 8) ^ (folded & 255)) & 255


def verify_uniform_hash():
    count = 0
    for value in range(256):
        for size in (0, 1, 2, 7, 255, 256, 257, 513, 1025):
            actual = int(line_id(1, bytes([value]) * size).split(b':')[1], 16)
            assert uniform_hash(value, size) == actual
            count += 1
    return count


def content(index, size=SIZE):
    block = bytes([64 + index]) * min(CHUNK, size)
    while size:
        part = block[:min(len(block), size)]
        yield part
        size -= len(part)


def headers(path):
    raw_path = os.fsencode(path)
    records = []
    for index in range(1, COUNT + 1):
        anchor = line_id(index, ('old-' + str(index)).encode())
        endpoint = b'HIAEP001' + Q(2, len(anchor), 0) + anchor
        record = Q(1, 1, 1, 0, 1, 7, len(endpoint), 0, SIZE) + b'replace' + endpoint
        records.append(record)
    size = sum(len(record) + SIZE for record in records)
    prefix = b'HFBWT001' + Q(1, len(raw_path), len(raw_path), COUNT, size, 1, 0) + raw_path * 2
    return prefix, records, len(prefix) + size


def request_segments(path):
    prefix, records, _ = headers(path)
    yield prefix
    for index, record in enumerate(records, 1):
        yield record
        yield from content(index)


def diff_lines(index):
    before, after = max(1, index - 2), min(COUNT, index + 2)
    if before > 1: yield b'...'
    for number in range(before, index): yield (b'', number)
    yield b'-' + line_id(index, ('old-' + str(index)).encode()) + b' (1 line)'
    yield (b'+', index)
    for number in range(index + 1, after + 1): yield (b'', number)
    if after < COUNT: yield b'...'


def diff_segments():
    identifiers = {index: f'{index}:{uniform_hash(64 + index, SIZE):02x}|'.encode()
                   for index in range(1, COUNT + 1)}
    for index in range(1, COUNT + 1):
        if index != 1: yield b'\n---\n'
        for line, item in enumerate(diff_lines(index)):
            if line: yield b'\n'
            if isinstance(item, bytes): yield item
            else:
                prefix, number = item
                yield prefix + identifiers[number]
                yield from content(number)


def diff_length():
    total, full_lines = 5 * (COUNT - 1), 0
    for index in range(1, COUNT + 1):
        lines = list(diff_lines(index))
        total += len(lines) - 1
        for item in lines:
            if isinstance(item, bytes): total += len(item)
            else:
                prefix, number = item
                total += len(prefix) + len(str(number)) + 4 + SIZE
                full_lines += 1
    assert full_lines == 5 * COUNT - 6
    return total, full_lines


class Expected:
    def __init__(self, segments):
        self.segments, self.pending = iter(segments), memoryview(b'')
    def consume(self, actual):
        at = 0
        while at < len(actual):
            if not self.pending: self.pending = memoryview(next(self.segments))
            size = min(len(self.pending), len(actual) - at)
            assert actual[at:at + size] == self.pending[:size], 'complete wide body differs'
            self.pending = self.pending[size:]; at += size
    def finish(self):
        assert not self.pending and next(self.segments, None) is None


def execute(binary, fixture, output, *, role='native'):
    assert role in ('native', 'original')
    output.mkdir(); fixture.mkdir()
    target = fixture / 'target'
    target.write_bytes(b''.join(('old-' + str(i)).encode() + b'\r\n' for i in range(1, COUNT + 1)))
    _, _, input_size = headers(target)
    body_size, full_lines = diff_length()
    assert (1 << 30) < body_size + 32 < (2 << 30) < 0xffff0000
    stderr = (output / 'stderr.bin').open('xb')
    parent = os.getpid()
    def lifetime():
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent: os._exit(75)
    process = subprocess.Popen([str(binary.resolve(strict=True))], cwd=fixture, env={'PATH': ''},
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr, preexec_fn=lifetime)
    assert os.getpgid(process.pid) == os.getpgrp()
    started = time.monotonic(); deadline = started + 180
    report = {'schema': 'hepta.runtime.batch-write-wide.v1', 'status': 'RUNNING',
        'native_or_original_binary_sha256': sha(binary.read_bytes()), 'requests': 1,
        'binary_role': role, 'fixture_target': str(target),
        'test_sha256': sha(Path(__file__).read_bytes()),
        'operations': COUNT, 'content_bytes_per_operation': SIZE, 'input_bytes': input_size,
        'expected_output_bytes': body_size + 32, 'full_content_lines_in_diff': full_lines,
        'original_rust_comparison': 'PENDING', 'outer_timeout_seconds': 180,
        'inherits_outer_process_group': True, 'process_group': os.getpgrp(), 'process_id': process.pid}
    writers = {name: gzip.open(output / (name + '.bin.gz'), 'xb', compresslevel=1)
               for name in ('request', 'stdout', 'normalized', 'file')}
    digests = {name: hashlib.sha256() for name in writers}; sizes = {name: 0 for name in writers}
    def retain(name, data):
        writers[name].write(data); digests[name].update(data); sizes[name] += len(data)
    def receive(size):
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([process.stdout], [], [], remaining)[0]:
            raise TimeoutError('complete wide body exceeded unchanged 180 second deadline')
        data = os.read(process.stdout.fileno(), size)
        if not data: raise EOFError('complete wide body ended early')
        return data
    try:
        os.set_blocking(process.stdin.fileno(), False)
        first = struct.pack('<QQ', input_size, 1)
        assert os.write(process.stdin.fileno(), first) == len(first)
        retain('request', first)
        for part in request_segments(target):
            view = memoryview(part)
            while view:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not select.select([], [process.stdin], [], remaining)[1]:
                    raise TimeoutError('complete wide input exceeded unchanged deadline')
                count = os.write(process.stdin.fileno(), view)
                retain('request', view[:count]); view = view[count:]
        process.stdin.close()
        header = bytearray()
        while len(header) < 20: header += receive(20 - len(header))
        retain('stdout', header)
        tag, tid, code = struct.unpack('<QQI', header)
        assert tag == 1 and tid > 0 and code == body_size + 32, (tag, tid, code, body_size + 32)
        retain('normalized', struct.pack('<QI', tag, code))
        outer = bytearray()
        while len(outer) < 32: outer += receive(32 - len(outer))
        assert outer == b'HFBWR001' + Q(0, body_size, 0)
        retain('stdout', outer); retain('normalized', outer)
        expected = Expected(diff_segments())
        remaining = body_size
        while remaining:
            data = receive(min(CHUNK, remaining))
            expected.consume(data); retain('stdout', data); retain('normalized', data)
            remaining -= len(data)
        expected.finish()
        report['exit_code'] = process.wait(timeout=max(0.001, deadline - time.monotonic()))
        assert report['exit_code'] == 0 and process.stdout.read() == b''
        assert not (fixture / '.octofs_tmp_target.tmp').exists()
        def written():
            for index in range(1, COUNT + 1):
                yield from content(index)
                yield b'\r\n'
        expected = Expected(written())
        with target.open('rb') as handle:
            while data := handle.read(CHUNK):
                expected.consume(data); retain('file', data)
        expected.finish()
        assert sizes['file'] == COUNT * (SIZE + 2)
        report['status'] = role.upper() + '_RESPONSE_AND_FULL_FILE_PASS'
    except BaseException as error:
        report.update(status='FAIL', failure=repr(error))
        raise
    finally:
        if process.poll() is None: process.kill(); process.wait()
        report['exit_code'] = process.returncode
        for writer in writers.values(): writer.close()
        stderr.close()
        report['elapsed_seconds'] = time.monotonic() - started
        report['streams'] = {name: {'raw_bytes': sizes[name], 'raw_sha256': digests[name].hexdigest(),
            'gzip_bytes': (output / (name + '.bin.gz')).stat().st_size,
            'gzip_sha256': sha((output / (name + '.bin.gz')).read_bytes())} for name in writers}
        report['stderr'] = {'bytes': (output / 'stderr.bin').stat().st_size,
                            'sha256': sha((output / 'stderr.bin').read_bytes())}
        (output / 'result.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    return report


def compare_streams(left, right):
    digest = hashlib.sha256(); size = 0
    with gzip.open(left, 'rb') as a, gzip.open(right, 'rb') as b:
        while True:
            first, second = a.read(CHUNK), b.read(CHUNK)
            assert first == second, ('complete paired wide stream differs', left.name, size)
            if not first: break
            size += len(first); digest.update(first)
    return {'raw_bytes': size, 'raw_sha256': digest.hexdigest(), 'complete_bytes_equal': True}


def execute_pair(native, original, output):
    output = output.absolute(); fixture = output / 'fixture'
    before = sha(Path(__file__).read_bytes()); started = time.monotonic()
    result = {'schema': 'hepta.runtime.batch-write-wide-original.v1', 'status': 'RUNNING',
              'actual_native_requests': 0, 'actual_original_requests': 0,
              'outer_timeout_seconds': 180, 'test_sha256': before}
    try:
        n = execute(native, fixture, output / 'native')
        assert n['status'] == 'NATIVE_RESPONSE_AND_FULL_FILE_PASS'
        result['actual_native_requests'] = 1
        assert sorted(p.name for p in fixture.iterdir()) == ['target']
        # execute() has just streamed every final byte into the retained gzip,
        # compared it and recorded its complete hash. Only this owned expanded
        # fixture is retired, so the original receives the identical path.
        retirement = {'raw_path': str(fixture / 'target'), **n['streams']['file'],
                      'complete_bytes_verified_before_unlink': True,
                      'retained_gzip': str(output / 'native/file.bin.gz')}
        (output / 'native-fixture-retirement.json').write_text(json.dumps(retirement, sort_keys=True, indent=2) + '\n')
        (fixture / 'target').unlink(); fixture.rmdir()
        r = execute(original, fixture, output / 'original', role='original')
        assert r['status'] == 'ORIGINAL_RESPONSE_AND_FULL_FILE_PASS'
        summary = json.loads((output / 'original/stderr.bin').read_bytes())
        assert summary == {'status': 'PASS', 'original_owner_calls': 1, 'responses': 1, 'canceled': 0}
        assert (output / 'native/stderr.bin').read_bytes() == b''
        result['actual_original_requests'] = 1
        compared = {name: compare_streams(output / 'native' / (name + '.bin.gz'),
                                         output / 'original' / (name + '.bin.gz'))
                    for name in ('request', 'normalized', 'file')}
        assert n['fixture_target'] == r['fixture_target']
        assert n['operations'] == r['operations'] == 50 and n['content_bytes_per_operation'] == r['content_bytes_per_operation'] == SIZE
        assert compared['normalized']['raw_bytes'] == 1279265842 and compared['file']['raw_bytes'] == 262144100
        result.update(status='PASS', native_binary_sha256=n['native_or_original_binary_sha256'],
            original_binary_sha256=r['native_or_original_binary_sha256'], compared=compared,
            original_summary=summary, native_result_sha256=sha((output / 'native/result.json').read_bytes()),
            original_result_sha256=sha((output / 'original/result.json').read_bytes()),
            native_elapsed_seconds=n['elapsed_seconds'], original_elapsed_seconds=r['elapsed_seconds'],
            exact_same_fixture_path=True, operations=50, content_bytes_per_operation=SIZE)
        assert sha(Path(__file__).read_bytes()) == before
    except BaseException as error:
        result.update(status='FAIL', failure=repr(error))
        raise
    finally:
        result['elapsed_seconds'] = time.monotonic() - started
        (output / 'result.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--native', type=Path, required=True)
    parser.add_argument('--original', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    controls = {'status': 'PASS', 'independent_uniform_hash_controls': verify_uniform_hash(),
                'test_sha256': sha(Path(__file__).read_bytes())}
    (args.output / 'algorithm-controls.json').write_text(json.dumps(controls, sort_keys=True) + '\n')
    result = (execute_pair(args.native.absolute(), args.original.absolute(), args.output)
              if args.original is not None else
              execute(args.native.absolute(), args.output.absolute() / 'fixture', args.output / 'native'))
    print(json.dumps(result, sort_keys=True))

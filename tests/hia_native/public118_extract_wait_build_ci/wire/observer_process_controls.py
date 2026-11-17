"""Exercise real Python child cleanup and full stream custody, without HIA/Rust.

This is a regression control for the observation transport. Its explicitly
test-owned child is not a protocol implementation, native host, or oracle.
The actual public native corpus still requires its separately admitted graph.
"""
from __future__ import annotations

import argparse
import errno
import gzip
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import capture_stdio as transport


CASES = (
    'complete-streams', 'attempted-input-enospc', 'accepted-input-enospc',
    'exchange-journal-enospc', 'startup-receipt-enospc', 'stream-close-enospc',
    'occupied-owned-fd3', 'unexpected-eof-output', 'incomplete-response',
    'extra-response',
)

FIXTURE = '''import os, sys
trailing = False
for raw in sys.stdin.buffer:
    os.write(3, b'CONTROL1' + len(raw).to_bytes(8, 'little'))
    if raw == b'NOTE\\n':
        continue
    if raw == b'TRAIL\\n':
        trailing = True
        continue
    if raw == b'PARTIAL\\n':
        sys.stdout.buffer.write(b'partial')
        sys.stdout.buffer.flush()
        break
    if raw == b'PAIR\\n':
        sys.stdout.buffer.write(b'one\\ntwo\\n')
    else:
        sys.stdout.buffer.write(raw)
    sys.stderr.buffer.write(b'observed:' + len(raw).to_bytes(8, 'little'))
    sys.stderr.buffer.flush()
    sys.stdout.buffer.flush()
if trailing:
    sys.stdout.buffer.write(b'undeclared\\n')
    sys.stdout.buffer.flush()
'''


def put(path, value):
    raw = value if type(value) is bytes else transport.encoded(value)
    with path.open('xb') as stream:
        assert stream.write(raw) == len(raw)


def absent_group(pid):
    try:
        os.killpg(pid, 0)
    except ProcessLookupError:
        return True
    return False


def one(name, output, binary):
    assert name in CASES
    output.mkdir(mode=0o700)
    process_output = output / 'process'
    process_output.mkdir(mode=0o700)
    config = output / 'config.json'
    put(config, {})
    actual_open, actual_write, actual_close = Path.open, transport.Stream.write, transport.Stream.close
    actual_popen = transport.subprocess.Popen
    spawned = []
    native = None
    initialized = False
    failure = None
    receipt = None
    occupied = None
    started = time.monotonic_ns()

    def start(*args, **kwargs):
        process = actual_popen(*args, **kwargs)
        spawned.append(process)
        return process

    def opening(path, mode='r', *args, **kwargs):
        if name == 'startup-receipt-enospc' and path.name == 'started.json' and mode == 'xb':
            raise OSError(errno.ENOSPC, 'owned startup-receipt fault')
        if name == 'exchange-journal-enospc' and path.name == 'exchanges.jsonl' and mode == 'ab':
            raise OSError(errno.ENOSPC, 'owned exchange-journal fault')
        return actual_open(path, mode, *args, **kwargs)

    def writing(stream, raw):
        if name == 'attempted-input-enospc' and stream.path.name == 'attempted-stdin.bin.gz':
            raise OSError(errno.ENOSPC, 'owned attempted-input fault')
        if name == 'accepted-input-enospc' and stream.path.name == 'stdin.bin.gz':
            raise OSError(errno.ENOSPC, 'owned accepted-input fault')
        return actual_write(stream, raw)

    def closing(stream):
        result = actual_close(stream)
        if name == 'stream-close-enospc' and stream.path.name == 'stdin.bin.gz':
            raise OSError(errno.ENOSPC, 'owned stream-close fault')
        return result

    try:
        if name == 'occupied-owned-fd3':
            occupied = os.open(output / 'occupied.bin', os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
            assert occupied == 3
        transport.subprocess.Popen = start
        Path.open = opening
        transport.Stream.write = writing
        transport.Stream.close = closing
        native = transport.NativeStdio.__new__(transport.NativeStdio)
        native.__init__(binary, transport.file_pin(binary), output, config, process_output)
        initialized = True
        if name == 'complete-streams':
            rows = [(b'NOTE\n', 0), (b'A' * (1024 * 1024 + 37) + b'\n', 1), (b'PAIR\n', 2)]
        elif name == 'unexpected-eof-output':
            rows = [(b'TRAIL\n', 0)]
        elif name == 'incomplete-response':
            rows = [(b'PARTIAL\n', 1)]
        elif name == 'extra-response':
            rows = [(b'PAIR\n', 1)]
        else:
            rows = [(b'actual-owned-input\n', 1)]
        responses = []
        for index, (wire, count) in enumerate(rows):
            declared = {'sequence': index, 'session': 0, 'opcode': 1,
                        'frames': count, 'wire': transport.pin(wire)}
            body, _ = native.exchange(declared, wire)
            responses.append(body)
        receipt = native.close()
        if name == 'complete-streams':
            assert responses == [b'', rows[1][0], b'one\ntwo\n']
            expected = {'attempted-stdin': b''.join(row[0] for row in rows),
                        'stdin': b''.join(row[0] for row in rows),
                        'stdout': b''.join(responses),
                        'stderr': b''.join(b'observed:' + len(row[0]).to_bytes(8, 'little')
                                           for row in rows[1:])}
            for stream_name, raw in expected.items():
                observed = gzip.decompress((process_output / (stream_name + '.bin.gz')).read_bytes())
                assert observed == raw
                assert receipt['streams'][stream_name]['uncompressed'] == transport.pin(raw)
            expected_journal = b''.join(b'CONTROL1' + len(row[0]).to_bytes(8, 'little') for row in rows)
            assert (process_output / 'host-journal.bin').read_bytes() == expected_journal
    except BaseException as error:
        failure = transport.NativeStdio.error(error)
    finally:
        try:
            if initialized and not native.closed:
                try:
                    receipt = native.close(failed=True)
                except BaseException as error:
                    if failure is None:
                        failure = transport.NativeStdio.error(error)
        finally:
            Path.open = actual_open
            transport.Stream.write = actual_write
            transport.Stream.close = actual_close
            transport.subprocess.Popen = actual_popen
            if occupied is not None:
                assert os.fstat(occupied).st_size == 0
                os.close(occupied)
    finished = time.monotonic_ns()
    assert all(process.poll() is not None and absent_group(process.pid) for process in spawned)
    if native is not None:
        assert native.journal_fd is None
        assert all(stream.file.closed and stream.output.closed for stream in native.streams.values())
    if name == 'complete-streams':
        assert failure is None and receipt['returncode'] == 0
    else:
        assert failure is not None, 'the declared capture/transport failure was accepted'
        if name == 'occupied-owned-fd3':
            assert not spawned and failure == {'type': 'AssertionError',
                'message': 'fixed owned journal FD3 is unavailable', 'errno': None}
        elif name == 'startup-receipt-enospc':
            assert len(spawned) == 1 and failure['errno'] == errno.ENOSPC
        if name == 'accepted-input-enospc':
            row = json.loads((process_output / 'exchanges.jsonl').read_bytes())
            assert row['accepted_input']['bytes'] > 0 and row['ranges']['stdin']['bytes'] == 0
            assert row['error']['errno'] == errno.ENOSPC
        if name == 'exchange-journal-enospc':
            assert native.failure['errno'] == errno.ENOSPC
    result = {'status': 'OWNED_PYTHON_OBSERVER_CONTROL_PASS', 'case': name,
        'failure': failure, 'elapsed_ns': finished - started,
        'spawned': [{'pid': process.pid, 'returncode': process.returncode,
                     'owned_group_absent': True} for process in spawned],
        'all_owned_streams_closed': True, 'actual_native_or_rust_executed': False,
        'public_native_qualified': False}
    put(output / 'CONTROL.json', result)
    print(json.dumps(result, sort_keys=True))


def all_cases(output):
    output.mkdir(mode=0o700)
    binary = output / 'owned-python-stdio'
    put(binary, ('#!' + sys.executable + '\n' + FIXTURE).encode())
    binary.chmod(0o700)
    results = []
    for name in CASES:
        command = [sys.executable, '-B', str(Path(__file__).resolve()),
                   '--one', name, '--binary', str(binary), '--output', str(output / name)]
        started = time.monotonic_ns()
        process = subprocess.run(command, capture_output=True, timeout=30, check=False)
        finished = time.monotonic_ns()
        put(output / (name + '.stdout'), process.stdout)
        put(output / (name + '.stderr'), process.stderr)
        actual = {'command': command, 'returncode': process.returncode,
                  'elapsed_ns': finished - started, 'timeout_seconds': 30,
                  'stdout': transport.pin(process.stdout), 'stderr': transport.pin(process.stderr)}
        put(output / (name + '.process.json'), actual)
        assert process.returncode == 0 and process.stderr == b'', (name, actual)
        row = json.loads(process.stdout)
        assert row == json.loads((output / name / 'CONTROL.json').read_bytes())
        results.append(row)
    result = {'status': 'COMPLETE_OBSERVER_PROCESS_CONTROLS_PASS', 'cases': results,
        'sources': {name: transport.file_pin(ROOT / name)
                    for name in ('capture_stdio.py', Path(__file__).name)},
        'fixture': transport.file_pin(binary),
        'original_native_deadline_seconds': transport.PROCESS_SECONDS,
        'original_exchange_deadline_seconds': transport.EXCHANGE_SECONDS,
        'actual_native_or_rust_executed': False, 'public_native_qualified': False}
    put(output / 'CONTROLS.json', result)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--binary', type=Path)
    parser.add_argument('--one', choices=CASES)
    args = parser.parse_args()
    destination = args.output.absolute()
    if args.one:
        assert args.binary is not None
        one(args.one, destination, args.binary.resolve(strict=True))
    else:
        assert args.binary is None
        all_cases(destination)

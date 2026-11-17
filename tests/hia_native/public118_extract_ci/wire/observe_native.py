"""Capture all unchanged public Bellman inputs from two real native stdio hosts.

This is a mechanical observer, not a qualifier. The final reader additionally
requires the frozen native graph, full host journal, and current SDK original
recipe. Each actual process keeps the original 180-second lifetime deadline
and each exchange keeps 60 seconds. There is no cross-process pool claim.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import sys
import time
import traceback

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
REFERENCE = ROOT / 'reference'
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(REFERENCE))
from capture_stdio import NativeStdio, encoded, file_pin, pin
from wire_compare import native_frame
from wire_cases import rows, frame

REFERENCE_MANIFEST = '1939142e41e1e7e9c62e7a1a886388ebeed4a5daff76cc9c7e8b712e0bcea730'


def put(path, value):
    with path.open('xb') as stream:
        raw = value if type(value) is bytes else encoded(value)
        assert stream.write(raw) == len(raw)


def source_pin():
    raw = (REFERENCE / 'package-manifest.json').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == REFERENCE_MANIFEST
    reference = json.loads(raw)
    actual = {p.relative_to(REFERENCE).as_posix() for p in REFERENCE.rglob('*') if p.is_file()}
    assert actual == set(reference['files']) | {'package-manifest.json'}
    for name, expected in reference['files'].items():
        assert not (REFERENCE / name).is_symlink()
        assert file_pin(REFERENCE / name) == expected
    own = {name: file_pin(ROOT / name) for name in
           ('capture_stdio.py', 'observe_native.py', 'wire_compare.py')}
    return {'reference_manifest_sha256': REFERENCE_MANIFEST, 'observer_sources': own}


def prepare_inputs(output):
    frozen = json.loads((REFERENCE / 'wire-domain.json').read_bytes())
    assert frozen['records'] == 1394 and frozen['public_cases'] == 1366
    assert frozen['public_process_deadline_seconds'] == 180
    assert frozen['exchange_deadline_seconds'] == 60
    index = []
    with (output / 'inputs.bin').open('xb') as stream:
        for number, (row, wire) in enumerate(rows()):
            assert row == frozen['rows'][number] and row['sequence'] == number
            raw = frame(row, wire)
            index.append({'sequence': number, 'session': row['session'],
                          'offset': stream.tell(), **pin(raw)})
            assert stream.write(raw) == len(raw)
    assert len(index) == frozen['records']
    put(output / 'input-index.json', index)
    return frozen, index


def snapshot(root):
    """Record every owned fixture byte before startup and after process exit."""
    result = []
    for path in [root, *sorted(root.rglob('*'))]:
        value = path.lstat()
        assert stat.S_ISREG(value.st_mode) or stat.S_ISDIR(value.st_mode)
        row = {'path': path.relative_to(root).as_posix(), 'mode': value.st_mode,
               'dev': value.st_dev, 'ino': value.st_ino, 'uid': value.st_uid,
               'gid': value.st_gid, 'nlink': value.st_nlink,
               'mtime_ns': value.st_mtime_ns, 'ctime_ns': value.st_ctime_ns}
        if stat.S_ISREG(value.st_mode):
            raw = path.read_bytes()
            row.update(content_hex=raw.hex(), **pin(raw))
        result.append(row)
    return result


def fixture(output):
    root = output / 'fixture'
    root.mkdir(mode=0o700)
    work = root / 'workspace'
    state = root / 'controller-state'
    work.mkdir(mode=0o700)
    state.mkdir(mode=0o700)
    config = root / 'runtime.json'
    value = {'state_dir': str(state), 'controller_workspace_roots': [str(work)],
             'hosts': {'owned': {'ssh_target': 'not-contacted-owned-fixture',
                                 'remote_state_dir': '/unused-state'}}}
    put(config, value)
    config.chmod(0o600)
    put(output / 'fixture-before.json', snapshot(root))
    return root, work, config


def capture_session(binary, binary_pin, output, corpus, frozen, index, session):
    output.mkdir(mode=0o700)
    root, work, config = fixture(output)
    process_output = output / 'process'
    process_output.mkdir(mode=0o700)
    native = None
    failure = None
    recorded = 0
    receipt = None
    try:
        # Open the fixed FD3 journal before any persistent observation handle.
        native = NativeStdio(binary, binary_pin, work, config, process_output)
        with corpus.open('rb') as inputs, (output / 'responses.bin').open('xb') as responses:
            for at, declared in zip(index, frozen['rows'], strict=True):
                if declared['session'] != session:
                    continue
                inputs.seek(at['offset'])
                raw = inputs.read(at['bytes'])
                assert pin(raw) == {key: at[key] for key in ('bytes', 'sha256')}
                assert raw[:8] == b'HBPOREQ1' and len(raw) >= 64
                header = struct.unpack_from('<7Q', raw, 8)
                wire = raw[64:]
                assert header == (declared['sequence'], declared['opcode'], session,
                                  len(wire), declared['frames'], 0, 0)
                assert pin(wire) == declared['wire']
                if declared['opcode'] == 1:
                    observed, record = native.exchange(declared, wire)
                    encoded_frame = native_frame(declared, observed,
                        record['before_ns'], record['after_ns'],
                        record['journal_before'], record['journal_after'], native.process.pid)
                else:
                    assert declared['kind'] == 'close' and wire == b''
                    before = time.monotonic_ns()
                    journal_before = native.journal_size()
                    receipt = native.close()
                    encoded_frame = native_frame(declared, b'', before,
                        receipt['finished_ns'], journal_before,
                        receipt['journal']['bytes'], native.process.pid)
                assert responses.write(encoded_frame) == len(encoded_frame)
                recorded += 1
        assert recorded == sum(row['session'] == session for row in frozen['rows'])
        assert native.closed and receipt is not None
    except BaseException as error:
        failure = {'type': type(error).__name__, 'message': str(error),
                   'traceback': traceback.format_exc()}
        raise
    finally:
        # No receipt or snapshot write can prevent an owned live child from
        # being killed and reaped after a prior capture or transport failure.
        try:
            if native is not None and not native.closed:
                native.close(failed=True)
        finally:
            put(output / 'fixture-after.json', snapshot(root))
            if failure is not None:
                put(output / 'FAILURE.json', failure)
    result = {'status': 'ACTUAL_NATIVE_STDIO_BYTES_CAPTURED_READER_REQUIRED',
              'session': session, 'records': recorded,
              'process': receipt, 'output': file_pin(output / 'responses.bin'),
              'native_graph_admitted_by_this_observer': False,
              'public_handler_qualified': False, 'cross_session_pool_qualified': False}
    put(output / 'CAPTURE.json', result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', type=Path, required=True)
    parser.add_argument('--binary-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    binary = args.native.resolve(strict=True)
    binary_pin = file_pin(binary)
    assert binary_pin['sha256'] == args.binary_sha256
    assert stat.S_ISREG(binary.stat().st_mode) and binary.stat().st_mode & 0o111
    output = args.output.absolute()
    output.mkdir(mode=0o700)
    sources = source_pin()
    put(output / 'observer-source.json', sources)
    frozen, index = prepare_inputs(output)
    results = []
    for session in (0, 1):
        results.append(capture_session(binary, binary_pin,
            output / ('session-' + str(session)), output / 'inputs.bin',
            frozen, index, session))
    assert sum(row['records'] for row in results) == 1394
    result = {'status': 'COMPLETE_NATIVE_STDIO_OBSERVATION_READER_REQUIRED',
              'sources': sources, 'binary': binary_pin,
              'producer_pid': os.getpid(), 'producer_parent_pid': os.getppid(),
              'command': [sys.executable, *sys.argv],
              'records': 1394, 'public_cases': 1366, 'sessions': results,
              'inputs': file_pin(output / 'inputs.bin'),
              'process_deadline_seconds': 180, 'exchange_deadline_seconds': 60,
              'actual_native_processes': 2, 'actual_sessions_per_process': 1,
              'original_reference_processes': 1, 'original_sessions_per_process': 2,
              'cross_session_pool_qualified': False,
              'native_graph_admitted_by_this_observer': False,
              'public_handler_qualified': False, 'whole_runtime_replaced': False}
    put(output / 'CAPTURE.json', result)
    print(json.dumps({key: value for key, value in result.items()
                      if key not in ('sources', 'sessions')}, sort_keys=True))


if __name__ == '__main__':
    main()

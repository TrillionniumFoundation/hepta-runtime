"""Native controller refusal atomicity and actual fixed-thread transport controls."""
from __future__ import annotations
import argparse
import ctypes
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
for path in (ROOT / 'scripts', Path(__file__).resolve().parent):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))
from hia_native_file_lock_service_build import inspect_bundle, IMAGES, read, sha, file_record
from hia_native_loader import NativeModule
from test_file_lock_service import request

INVALID, CAPACITY, STATE, GROW, CALL = 0xffffffff, 0xfffffffe, 0xfffffff9, 0xffffffef, 0xfffffff0


def put(raw, at, value):
    struct.pack_into('<Q', raw, at, value)


def controller(manifest):
    records = []
    good = request(1, kind=1, path=b'.')
    with NativeModule(manifest, manifest_sha256=sha(read(manifest))) as module:
        assert module.metadata['image_sha256'] == IMAGES['controller']
        invalid = [good[:size] for size in range(64)] + [b'BADMAGIC' + good[8:]]
        for at, value in ((8, 0), (8, 8), (8, 9), (16, 1), (24, 0), (24, 3),
                          (32, 0), (32, 2), (40, 1), (48, 1), (56, 1)):
            wire = bytearray(good); put(wire, at, value); invalid.append(bytes(wire))
        invalid += [request(1, kind=2, path=b'\xff'), request(1, kind=2, host=b'\xff'),
                    request(1, kind=2, port=65536), request(7, 1)]
        invalid += [request(op) for op in range(2, 7)]
        invalid += [request(6, 1, kind=1), request(6, 1, path=b'x'), request(7, port=1)]
        for wire in invalid:
            code, output, work = module.invoke_raw(wire, output_capacity=64, workspace_capacity=1024,
                output_fill=0xa5, workspace_fill=0x5a)
            assert code == INVALID and output == b'\xa5' * 64 and work == b'\x5a' * 1024
            records.append({'domain': 'frame', 'input_hex': wire.hex(), 'code': code,
                'output_sha256': sha(output), 'workspace_sha256': sha(work), 'mutated': False})
        for out, worksize in ((0, 1024), (1, 1024), (63, 1024), (64, 0), (64, 319)):
            code, output, work = module.invoke_raw(good, output_capacity=out, workspace_capacity=worksize,
                output_fill=0xa5, workspace_fill=0x5a)
            assert code == CAPACITY and output == b'\xa5' * out and work == b'\x5a' * worksize
            records.append({'domain': 'capacity', 'output_capacity': out, 'workspace_capacity': worksize,
                'code': code, 'mutated': False})
        large = request(1, kind=1, path=b'x' * 1024)
        code, output, work = module.invoke_raw(large, output_capacity=64, workspace_capacity=320, output_fill=0xa5)
        expected = bytearray(320); put(expected, 24, 256 + len(large))
        assert code == GROW and output == b'\xa5' * 64 and work == expected
        records.append({'domain': 'growth', 'input_hex': large.hex(), 'code': code, 'workspace_hex': work.hex()})
        with module.session(output_capacity=64, workspace_capacity=1024) as session:
            ctypes.memset(session._output, 0xa5, 64)
            code, output, pending = session.invoke_raw(good)
            assert code == CALL and output == b'\xa5' * 64
            assert struct.unpack_from('<8s6Q', pending, 64) == (b'HFLCKCAL', 1, 1, 256, len(good), 288, 736)
            records.append({'domain': 'key_request', 'code': code, 'workspace_hex': pending.hex()})
            complete = bytearray(pending)
            key = struct.pack('<8s3Q', b'HRLKY001', 1, 1, 0) + b'.'
            complete[288:288 + len(key)] = key
            put(complete, 120, len(key)); put(complete, 128, len(key)); put(complete, 136, 1)
            changes = [(0, 0), (0, 3), (8, len(good) + 1), (16, 2), (24, 1), (64, 0),
                (72, 2), (80, 2), (88, 257), (96, len(good) + 1), (104, 289), (120, 34),
                (128, 31), (136, 0), (136, 2), (144, 1), (152, 1), (160, 1), (168, 1),
                (176, 1), (184, 1), (288, 0), (296, 2), (304, 2), (312, 1)]
            for at, value in changes:
                altered = bytearray(complete); put(altered, at, value)
                if at == 0 and value == 0:
                    # A reused fresh phase with nonzero lifecycle words is a
                    # state error, not an authorized restart.
                    assert struct.unpack_from('<Q', altered, 8)[0] != 0
                ctypes.memmove(session._workspace, bytes(altered), 1024)
                ctypes.memset(session._output, 0xa5, 64)
                code, output, after = session.invoke_raw(good)
                assert code == STATE and output == b'\xa5' * 64 and after == altered, (at, value, code)
                records.append({'domain': 'key_completion_refusal', 'offset': at, 'value': value,
                    'code': code, 'before_sha256': sha(altered), 'after_sha256': sha(after), 'mutated': False})
            altered = bytearray(complete); altered[320] = 0xff
            ctypes.memmove(session._workspace, bytes(altered), 1024)
            code, output, after = session.invoke_raw(good)
            assert code == STATE and output == b'\xa5' * 64 and after == altered
            records.append({'domain': 'key_utf8_refusal', 'code': code, 'mutated': False})
            ctypes.memmove(session._workspace, bytes(complete), 1024)
            code, output, pending_state = session.invoke_raw(good)
            assert code == CALL and output == b'\xa5' * 64
            assert struct.unpack_from('<8s6Q', pending_state, 64) == (b'HFLCKCAL', 2, 2, 256, 65, 256, 768)
            assert pending_state[256:321] == struct.pack('<8s7Q', b'HRFLOCK1', 1, 0, 1, 0, 0, 0, 0) + b'.'
            records.append({'domain': 'state_request', 'code': code, 'workspace_hex': pending_state.hex()})
            terminal = bytearray(pending_state)
            answer = struct.pack('<8s7Q', b'HRFLKR01', 1, 0, 1, 1, 1, 2, 0)
            terminal[256:320] = answer
            put(terminal, 120, 64); put(terminal, 128, 64); put(terminal, 136, 1)
            for at, value in ((0, 1), (104, 288), (120, 63), (128, 63), (128, 65),
                              (256, 0), (264, 2), (272, 1), (272, 2)):
                altered = bytearray(terminal); put(altered, at, value)
                ctypes.memmove(session._workspace, bytes(altered), 1024)
                code, output, after = session.invoke_raw(good)
                assert code == STATE and output == b'\xa5' * 64 and after == altered
                records.append({'domain': 'state_completion_refusal', 'offset': at, 'value': value,
                    'code': code, 'before_sha256': sha(altered), 'after_sha256': sha(after), 'mutated': False})
            ctypes.memmove(session._workspace, bytes(terminal), 1024)
            code, output, after = session.invoke_raw(good)
            assert code == 64 and output == answer and struct.unpack_from('<Q', after)[0] == 100
            records.append({'domain': 'synthetic_completion', 'code': code, 'answer_hex': output.hex(),
                'actual_original_calls': 0})
            ctypes.memset(session._output, 0xa5, 64)
            code, output, work = session.invoke_raw(good)
            assert code == STATE and work == after and output == b'\xa5' * 64
            records.append({'domain': 'terminal_reentry_refusal', 'code': code, 'mutated': False})
    return records


def transport(bundle, out):
    executable = bundle.parent / 'file-lock-service.elf'
    records = []
    frames = [('eof', [], b'', 0, False), ('argv', ['unexpected'], b'', 64, False),
        ('partial-prefix', [], b'123456789012345', 74, False),
        ('partial-payload', [], struct.pack('<QQ', 4, 1) + b'12', 74, False),
        ('invalid-continue', [], struct.pack('<QQQQ', 0, 1, 0, 2), 0, True),
        ('overflow-allocation', [], struct.pack('<QQ', (1 << 64) - 1, 1), 71, False)]
    for name, args, incoming, expected, dynamic in frames:
        started = time.monotonic()
        process = subprocess.run([str(executable), *args], input=incoming, capture_output=True, timeout=10)
        assert process.returncode == expected and process.stderr == b'', (name, process.returncode)
        if dynamic:
            assert len(process.stdout) == 40
            rows = [struct.unpack_from('<QQI', process.stdout, at) for at in (0, 20)]
            assert {row[0] for row in rows} == {1, 2} and all(row[1] > 0 and row[2] == INVALID for row in rows)
        else:
            assert process.stdout == b''
        records.append({'domain': 'transport', 'name': name, 'command': [str(executable), *args],
            'input_hex': incoming.hex(), 'stdout_hex': process.stdout.hex(), 'stderr_hex': '',
            'exit_code': process.returncode, 'timeout_seconds': 10, 'elapsed': time.monotonic() - started,
            'executable_sha256': sha(read(executable))})
    incoming = struct.pack('<QQ', 64, 1) + request(7)
    read_fd, write_fd = os.pipe(); os.close(read_fd)
    started = time.monotonic()
    try:
        child = subprocess.run([str(executable)], input=incoming, stdout=write_fd, stderr=subprocess.PIPE, timeout=10)
    finally:
        os.close(write_fd)
    assert child.returncode == 74 and child.stderr == b''
    records.append({'domain': 'transport', 'name': 'broken-stdout', 'input_hex': incoming.hex(),
        'exit_code': child.returncode, 'stderr_hex': '', 'timeout_seconds': 10,
        'elapsed': time.monotonic() - started, 'executable_sha256': sha(read(executable))})
    # Invalid flat return values are qualification fixtures.  The production
    # builder rejects every image substitution before returning its manifest.
    with NativeModule(bundle.parent / 'packer.json', manifest_sha256=sha(read(bundle.parent / 'packer.json'))) as packer:
        for kind in ('controller', 'key', 'state'):
            for name, bad in (('unknown-return', bytes.fromhex('b807000000c3')),
                              ('dirty-upper-return', bytes.fromhex('48b84000000001000000c3'))):
                images = [bad if item == kind else read(bundle.parent / (item + '.image.bin'))
                    for item in ('controller', 'key', 'state')]
                frame = b'HFLKSPK1' + struct.pack('<3Q', *map(len, images)) + b''.join(images)
                elf = packer.invoke(frame, output_capacity=1 << 20, workspace_capacity=0)
                path = out / (kind + '-' + name + '.elf'); path.write_bytes(elf); path.chmod(0o500)
                wire = request(1, kind=1, path=b'.')
                incoming = struct.pack('<QQ', len(wire), 1) + wire
                started = time.monotonic()
                child = subprocess.run([str(path)], input=incoming, capture_output=True, timeout=10)
                assert child.returncode == 70 and child.stdout == b'' and child.stderr == b''
                records.append({'domain': 'invalid_image_fixture', 'kind': kind, 'name': name,
                    'image_hex': bad.hex(), 'packed_elf': file_record(path), 'input_hex': incoming.hex(),
                    'packer_image_sha256': IMAGES['packer'], 'exit_code': child.returncode,
                    'stdout_hex': '', 'stderr_hex': '', 'timeout_seconds': 10,
                    'elapsed': time.monotonic() - started, 'actual_native_pack_calls': 1})
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, default=os.environ.get('HIA_FILE_LOCK_SERVICE_MANIFEST'))
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(); assert args.bundle is not None
    args.bundle = args.bundle.resolve(strict=True); args.output.mkdir(mode=0o700)
    artifacts = inspect_bundle(args.bundle, source_root=ROOT)
    names = ('tests/hia_native/test_file_lock_service_contract.py', 'tests/hia_native/test_file_lock_service.py',
        'scripts/hia_native_loader.py', 'scripts/hia_native_file_lock_service_build.py')
    sources = {name: file_record(ROOT / name) for name in names}
    report = {'schema': 'hepta.runtime.file-lock-service-contract.v1', 'status': 'RUNNING', 'groups': 3,
        'bundle_artifacts': artifacts, 'source_files': sources, 'actual_original_calls': 0}
    started = time.monotonic()
    try:
        report['controller'] = controller(args.bundle.parent / 'controller.json')
        report['transport'] = transport(args.bundle, args.output)
        report['direct_native_calls'] = len(report['controller'])
        report['actual_native_pack_calls'] = sum(row.get('actual_native_pack_calls', 0) for row in report['transport'])
        report['actual_elf_processes'] = len(report['transport'])
        assert inspect_bundle(args.bundle, source_root=ROOT) == artifacts
        assert {name: file_record(ROOT / name) for name in names} == sources
        report['status'] = 'PASS'
    except BaseException as error:
        report.update(status='FAIL', failure=repr(error)); raise
    finally:
        report['elapsed'] = time.monotonic() - started
        (args.output / 'result.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    summary = {name: report[name] for name in ('status', 'groups', 'elapsed', 'direct_native_calls',
        'actual_native_pack_calls', 'actual_elf_processes', 'actual_original_calls')}
    summary['result'] = file_record(args.output / 'result.json')
    print(json.dumps(summary))


if __name__ == '__main__':
    main()

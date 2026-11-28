"""Actual canonical ELF corpus, typed refusals and fixed-boundary controls."""
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
for entry in (ROOT / 'scripts', Path(__file__).resolve().parent):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))
from hia_native_file_lock_build import inspect_bundle, IMAGES, PREFIX, sha, read, file_record
from hia_native_loader import NativeModule
from file_lock_key_cases import request
from file_lock_fixture import retire
from run_file_lock_key import run as bulk

INVALID, CAPACITY, STATE = 0xffffffff, 0xfffffffe, 0xfffffff9
EFFECT, OUTPUT_GROW = 0xfffffff0, 0xffffffee
WORK = 1056768

def admission(manifest):
    records = []
    with NativeModule(manifest, manifest_sha256=sha(read(manifest))) as module:
        assert module.metadata['image_sha256'] == IMAGES['key']
        good = request(b'.')
        invalid = [good[:size] for size in range(64)]
        invalid += [b'BADMAGIC' + good[8:]]
        for offset, value in ((8, 0), (8, 3), (16, 2), (24, 1), (32, 1), (40, 1), (48, 1), (56, 1)):
            wire = bytearray(good)
            struct.pack_into('<Q', wire, offset, value)
            invalid.append(bytes(wire))
        invalid += [request(b'\xff', b'host'), request(b'ok', b'\xff'), request(b'ok', b'host', 65536)]
        with module.session(output_capacity=128, workspace_capacity=WORK) as state:
            for wire in invalid:
                ctypes.memset(state._workspace, 0x5a, WORK)
                for at in (0, 176):
                    ctypes.memmove(ctypes.addressof(state._workspace) + at, bytes(8), 8)
                before = ctypes.string_at(state._workspace, WORK)
                ctypes.memset(state._output, 0xa5, 128)
                code, output, after = state.invoke_raw(wire)
                assert code == INVALID and output == b'\xa5' * 128 and after == before
                records.append({'domain': 'frame', 'input_hex': wire.hex(), 'code': code,
                    'workspace_before_sha256': sha(before), 'workspace_after_sha256': sha(after),
                    'output_sha256': sha(output), 'output_bytes': len(output)})
        for capacity in (0, 1, 1024, 1053695):
            code, output, after = module.invoke_raw(good, output_capacity=128, workspace_capacity=capacity,
                output_fill=0xa5, workspace_fill=0x5a)
            assert code == CAPACITY and output == b'\xa5' * 128 and after == b'\x5a' * capacity
            records.append({'domain': 'capacity', 'input_hex': good.hex(), 'workspace_bytes': capacity, 'code': code})
        with module.session(output_capacity=128, workspace_capacity=WORK) as state:
            ctypes.memset(state._output, 0xa5, 128)
            code, output, work = state.invoke_raw(good)
            assert code == EFFECT and output == b'\xa5' * 128
            records.append({'domain': 'effect_creation', 'input_hex': good.hex(), 'code': code,
                'header_hex': work[:640].hex(), 'output_sha256': sha(output)})
            assert struct.unpack_from('<8s6Q', work, 512) == (b'HFLKEYFX', 1, 1, 2048, 1024, 0, 0)
            changes = [(0, 99), (8, len(good) + 1), (16, 129), (24, WORK + 1), (32, 512), (176, 2),
                (512, 0), (520, 2), (528, 2), (608, 0), (608, 2), (624, 1), (632, 1),
                (576, 4096), (584, 1), (592, 1), (600, 1), (616, 1)]
            for at, value in changes:
                incoming = bytearray(work)
                struct.pack_into('<Q', incoming, 608, 1)
                struct.pack_into('<Q', incoming, at, value)
                ctypes.memmove(state._workspace, bytes(incoming), WORK)
                ctypes.memset(state._output, 0xa5, 128)
                code, output, after = state.invoke_raw(good)
                assert code == STATE and output == b'\xa5' * 128 and after == incoming, (at, value, code)
                records.append({'domain': 'completion', 'offset': at, 'value': value, 'code': code,
                    'workspace_before_sha256': sha(incoming), 'workspace_after_sha256': sha(after),
                    'output_sha256': sha(output)})
        wire = request('🙂'.encode(), b'host', 65535)
        wanted = b'host:65535' + '🙂'.encode()
        with module.session(output_capacity=0, workspace_capacity=WORK) as state:
            code, output, work = state.invoke_raw(wire)
            assert code == OUTPUT_GROW and output == b''
            assert struct.unpack_from('<Q', work, 48)[0] == 32 + len(wanted)
        with module.session(output_capacity=32 + len(wanted), workspace_capacity=WORK) as state:
            ctypes.memmove(state._workspace, work, WORK)
            answer = state.invoke(wire)
            assert answer == struct.pack('<8s3Q', b'HRLKY001', 2, len(wanted), 0) + wanted
            records.append({'domain': 'output_growth', 'input_hex': wire.hex(), 'continuation': code,
                'actual_native_calls': 2, 'required_bytes': len(answer), 'answer_hex': answer.hex()})
    return records

def transport(bundle, output):
    records = []
    directory = bundle.parent
    for kind in ('state', 'key'):
        binary = directory / ('file-lock-' + kind + '.elf')
        frames = [('eof', [], b'', 0, b''), ('argv', ['unexpected'], b'', 64, b''),
            ('partial-prefix', [], b'1234567', 74, b''),
            ('partial-payload', [], struct.pack('<Q', 4) + b'12', 74, b''),
            ('invalid-continue', [], struct.pack('<Q', 0) * 2, 0, struct.pack('<II', INVALID, INVALID)),
            ('overflow-allocation', [], struct.pack('<Q', (1 << 64) - 1), 71, b'')]
        for name, args, incoming, expected_code, expected_output in frames:
            started = time.monotonic()
            process = subprocess.run([str(binary), *args], input=incoming, capture_output=True, timeout=10)
            assert process.returncode == expected_code and process.stdout == expected_output and process.stderr == b'', (kind, name)
            records.append({'domain': 'transport', 'kind': kind, 'name': name, 'command': [str(binary), *args],
                'input_hex': incoming.hex(), 'stdout_hex': process.stdout.hex(), 'stderr_hex': process.stderr.hex(),
                'exit_code': process.returncode, 'timeout_seconds': 10, 'elapsed': time.monotonic() - started,
                'executable_sha256': sha(read(binary))})
        # A deliberately invalid flat-image return is a boundary fixture, not
        # an alternative implementation of a production operation.
        bad = {'unknown-return': bytes.fromhex('b807000000c3'),
            'dirty-upper-return': bytes.fromhex('48b84000000001000000c3')}
        manifest = directory / (kind + '-packer.json')
        with NativeModule(manifest, manifest_sha256=sha(read(manifest))) as packer:
            for name, image in bad.items():
                frame = PREFIX[kind][2] + struct.pack('<Q', len(image)) + image
                elf = packer.invoke(frame, output_capacity=1 << 20, workspace_capacity=0)
                path = output / (kind + '-' + name + '.elf')
                path.write_bytes(elf)
                path.chmod(0o500)
                process = subprocess.run([str(path)], input=struct.pack('<Q', 0), capture_output=True, timeout=10)
                assert process.returncode == 70 and process.stdout == b'' and process.stderr == b''
                records.append({'domain': 'invalid_image_fixture', 'kind': kind, 'name': name,
                    'image_hex': image.hex(), 'packed_elf': file_record(path), 'packer_image_sha256': IMAGES[kind + '-packer'],
                    'exit_code': process.returncode, 'stdout_hex': '', 'stderr_hex': '', 'actual_native_pack_calls': 1})
    return records

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, default=os.environ.get('HIA_FILE_LOCK_MANIFEST'))
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert args.bundle is not None
    args.bundle = args.bundle.resolve(strict=True)
    args.output.mkdir(mode=0o700)
    artifacts = inspect_bundle(args.bundle, source_root=ROOT)
    started = time.monotonic()
    report = {'schema': 'hepta.runtime.file-lock-key-native.v1', 'status': 'RUNNING', 'groups': 4,
        'bundle_artifacts': artifacts, 'actual_original_calls': 0, 'original_rust_status': 'PENDING'}
    source_names = ('tests/hia_native/test_file_lock_key.py', 'tests/hia_native/file_lock_key_cases.py',
        'tests/hia_native/file_lock_fixture.py', 'tests/hia_native/run_file_lock_key.py', 'scripts/hia_native_loader.py')
    report['source_files'] = {name: file_record(ROOT / name) for name in source_names}
    try:
        result = bulk(args.bundle.parent / 'file-lock-key.elf', args.output / 'bulk')
        report['bulk'] = result
        report['fixture'] = retire(args.output / 'bulk/fixture', args.output / 'bulk/fixture.json.gz')
        report['admission'] = admission(args.bundle.parent / 'key.json')
        report['transport'] = transport(args.bundle, args.output)
        assert inspect_bundle(args.bundle, source_root=ROOT) == artifacts
        assert report['source_files'] == {name: file_record(ROOT / name) for name in source_names}
        report['status'] = 'PASS'
    except BaseException as error:
        report.update(status='FAIL', failure=repr(error))
        raise
    finally:
        report['elapsed'] = time.monotonic() - started
        (args.output / 'result.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'groups': report['groups'], 'elapsed': report['elapsed'],
        'bulk_actual_elf_requests': result['actual_elf_requests'], 'admission_records': len(report['admission']),
        'transport_processes': len(report['transport']), 'result': file_record(args.output / 'result.json')}, sort_keys=True))

if __name__ == '__main__':
    main()

"""Execute real HIA session state, full path boundaries and static ELF sessions."""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from pathlib import Path
import argparse
import ctypes
import gzip
import hashlib
import json
import os
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = Path(os.environ.get('HIA_REFERENCE_RUNTIME', ROOT))
sys.path[:0] = [str(ROOT / 'tests/hia_native'), str(ROOT / 'scripts'), str(REFERENCE / 'scripts')]
from hia_native_loader import NativeModule
from session_workdir_cases import PATH_BYTES, WORK_BYTES, Reference, packet, response, small_cases, large_cases, transport_cases

INVALID, CAPACITY = 0xffffffff, 0xfffffffe
sha = lambda raw: hashlib.sha256(raw).hexdigest()

def source_pins():
    names = ['native/session_workdir.hepta', 'native/session_workdir_composition.json',
             'native/session_workdir_abi.md', 'scripts/hia_native_session_build.py',
             'tests/hia_native/session_workdir_cases.py', 'tests/hia_native/test_session_workdir.py',
             'tests/hia_native/session_workdir_original.py',
             'tests/hia_native/compare_session_workdir_original.py']
    references = ['scripts/hia_native_build.py', 'scripts/hia_native_loader.py',
                  'scripts/hia_native_composition_build.py', 'native/composition_packer.hepta',
                  'tests/hia_native/view_cache_hex_transport.hepta', 'native/text_budget.hepta',
                  'src/mcp/server.rs']
    return {'owner': {n: sha((ROOT / n).read_bytes()) for n in names},
            'reference': {n: sha((REFERENCE / n).read_bytes()) for n in references}}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bundle', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    started = time.monotonic()
    out = a.output.resolve(); out.mkdir(parents=True, exist_ok=False, mode=0o700)
    before = source_pins()
    bundle_path = a.bundle.resolve(strict=True)
    bundle_raw = bundle_path.read_bytes(); bundle = json.loads(bundle_raw)
    assert bundle['schema'] == 'hepta.runtime.session-workdir-bundle.v1'
    assert bundle['source_sha256'] == before['owner']['native/session_workdir.hepta']
    build = bundle_path.parents[2]
    module_path = build / bundle['module']; fixture_path = build / bundle['fixture']
    assert sha(module_path.read_bytes()) == bundle['module_sha256']
    assert sha(fixture_path.read_bytes()) == bundle['fixture_sha256']
    fixture = json.loads(fixture_path.read_bytes())
    elf = fixture_path.parent / fixture['executable']
    assert sha(elf.read_bytes()) == fixture['executable_sha256']
    counts = {'native_image_calls': 0, 'reference_rows': 0, 'frame_refusals': 0,
              'capacity_refusals': 0, 'state_refusals': 0, 'actual_elf_processes': 0,
              'actual_elf_frames': 0, 'serialized_latch_calls': 0}
    streams = {}
    with ExitStack() as stack:
        for name in ['input.bin', 'native-output.bin', 'rows.jsonl']:
            streams[name] = stack.enter_context(gzip.GzipFile(filename=str(out / (name + '.gz')), mode='wb', mtime=0))
        module = stack.enter_context(NativeModule(module_path, manifest_sha256=bundle['module_sha256']))
        sessions = {}
        model = Reference()
        for sid, wire in list(small_cases()) + list(large_cases()):
            if sid not in sessions:
                sessions[sid] = stack.enter_context(module.session(
                    workspace_capacity=WORK_BYTES, output_capacity=PATH_BYTES + 32 if sid == 8 else 1024))
            actual = sessions[sid].invoke(wire)
            expected = model.apply(sid, wire)
            assert actual == expected, (sid, wire[:32], actual[:64], expected[:64])
            counts['native_image_calls'] += 1; counts['reference_rows'] += 1
            streams['input.bin'].write(struct.pack('<II', sid, len(wire)) + wire)
            streams['native-output.bin'].write(struct.pack('<I', len(actual)) + actual)
            streams['rows.jsonl'].write(json.dumps({'ordinal': counts['reference_rows'],
                'session': sid, 'operation': struct.unpack_from('<Q', wire, 8)[0],
                'request_sha256': sha(wire), 'response_sha256': sha(actual)}, sort_keys=True).encode() + b'\n')
        # State sanitation after shrinking/resetting is separate from result parity.
        with module.session(workspace_capacity=WORK_BYTES, output_capacity=1024) as state:
            for wire in [packet(1, b'/root'), packet(3, b'x' * 1024), packet(3, b'y')]:
                state.invoke(wire); counts['native_image_calls'] += 1
            assert ctypes.string_at(ctypes.addressof(state._workspace) + PATH_BYTES + 64, 1024) == b'y' + b'\0' * 1023
            state.invoke(packet(4)); counts['native_image_calls'] += 1
            assert ctypes.string_at(ctypes.addressof(state._workspace) + PATH_BYTES + 64, 1024) == bytes(1024)
            def refuse(wire, code, kind):
                original = state._workspace.raw[:WORK_BYTES]
                ctypes.memset(state._output, 0xa5, state.output_capacity)
                got, output, after = state.invoke_raw(wire)
                counts['native_image_calls'] += 1
                assert got == code and after == original and output == b'\xa5' * state.output_capacity
                counts[kind] += 1
            for size in range(32):
                refuse(packet(2)[:size], INVALID, 'frame_refusals')
            for offset, value in [(0, 0), (8, 0), (8, 7), (8, 2**64-1), (16, 1), (16, 2**64-1), (24, 1)]:
                raw = bytearray(packet(2)); struct.pack_into('<Q', raw, offset, value)
                refuse(bytes(raw), INVALID, 'frame_refusals')
            for op in [2, 4, 5, 6]:
                refuse(packet(op, b'x'), INVALID, 'frame_refusals')
            refuse(packet(2) + b'\0', INVALID, 'frame_refusals')
            refuse(packet(1, b'/second'), INVALID, 'state_refusals')
            refuse(packet(3, b'x' * (PATH_BYTES + 1)), CAPACITY, 'capacity_refusals')
            saved = state._workspace.raw[:64]
            for offset, value in [(0, 0), (8, PATH_BYTES+1), (16, PATH_BYTES+1),
                                  (16, 1), (24, 2), (32, 2), (40, 2), (48, 0), (56, 1)]:
                ctypes.memmove(ctypes.addressof(state._workspace) + offset, struct.pack('<Q', value), 8)
                refuse(packet(2), INVALID, 'state_refusals')
                ctypes.memmove(state._workspace, saved, len(saved))
        for output, workspace, wire in [(31, WORK_BYTES, packet(1, b'r')),
                (32, WORK_BYTES-1, packet(1, b'r')), (32, 0, packet(2))]:
            code, actual, after = module.invoke_raw(wire, output_capacity=output,
                workspace_capacity=workspace, output_fill=0xa5, workspace_fill=0)
            counts['native_image_calls'] += 1
            assert code == CAPACITY and actual == b'\xa5' * output and after == bytes(workspace)
            counts['capacity_refusals'] += 1
        with module.session(workspace_capacity=WORK_BYTES, output_capacity=PATH_BYTES+31) as state:
            state.invoke(packet(1, b'x' * PATH_BYTES)); counts['native_image_calls'] += 1
            before_state = state._workspace.raw[:WORK_BYTES]
            ctypes.memset(state._output, 0xa5, state.output_capacity)
            code, actual, after = state.invoke_raw(packet(2)); counts['native_image_calls'] += 1
            assert code == CAPACITY and after == before_state and actual == b'\xa5' * state.output_capacity
            counts['capacity_refusals'] += 1
        # NativeSession supplies the required trusted per-operation serialization;
        # this is a qualification driver, not an HTTP transport implementation.
        with module.session(workspace_capacity=WORK_BYTES, output_capacity=32) as state:
            state.invoke(packet(1, b'/first')); counts['native_image_calls'] += 1
            with ThreadPoolExecutor(max_workers=16) as pool:
                answers = list(pool.map(lambda _: state.invoke(packet(5)), range(64)))
            assert answers.count(response(2, 1)) == 1 and answers.count(response(2, 0)) == 63
            counts['serialized_latch_calls'] = 64; counts['native_image_calls'] += 64
    elf_records = []
    for sid in range(8):
        requests = list(transport_cases(sid))
        wire = b'\n'.join(raw.hex().encode() for raw in requests) + b'\n'
        command = [str(elf), '--local-read-profile', '/session-fixture']
        prefix = 'elf-' + str(sid)
        try:
            done = subprocess.run(command, input=wire, capture_output=True, timeout=30,
                                  env={'PATH': '', 'LANG': 'C'})
        except subprocess.TimeoutExpired as exc:
            for suffix, raw in [('stdin', wire), ('stdout', exc.stdout or b''), ('stderr', exc.stderr or b'')]:
                (out / (prefix + '.' + suffix + '.gz')).write_bytes(gzip.compress(raw, mtime=0))
            (out / (prefix + '.process.json')).write_text(json.dumps({
                'command': command, 'timeout_seconds': 30, 'exit_code': None, 'timed_out': True}, sort_keys=True) + '\n')
            raise
        for suffix, raw in [('stdin', wire), ('stdout', done.stdout), ('stderr', done.stderr)]:
            (out / (prefix + '.' + suffix + '.gz')).write_bytes(gzip.compress(raw, mtime=0))
        (out / (prefix + '.process.json')).write_text(json.dumps({
            'command': command, 'timeout_seconds': 30, 'exit_code': done.returncode,
            'stdin_sha256': sha(wire), 'stdout_sha256': sha(done.stdout),
            'stderr_sha256': sha(done.stderr)}, sort_keys=True) + '\n')
        assert done.returncode == 0 and not done.stderr
        lines = done.stdout.splitlines(); assert len(lines) == len(requests)
        reference = Reference()
        for request, line in zip(requests, lines, strict=True):
            code, encoded = line.split(b':', 1)
            actual = bytes.fromhex(encoded.decode())
            assert int(code, 16) == len(actual) and actual == reference.apply(sid, request)
        elf_records.append({'session': sid, 'exit_code': done.returncode, 'frames': len(lines),
            'stdin_sha256': sha(wire), 'stdout_sha256': sha(done.stdout), 'stderr_sha256': sha(done.stderr)})
        counts['actual_elf_processes'] += 1; counts['actual_elf_frames'] += len(lines)
    identities = {}
    for path in sorted(out.glob('*.gz')):
        raw_hash, raw_size = hashlib.sha256(), 0
        with gzip.open(path, 'rb') as stream:
            while raw := stream.read(1 << 20):
                raw_hash.update(raw); raw_size += len(raw)
        identities[path.name] = {'gzip_sha256': sha(path.read_bytes()), 'gzip_bytes': path.stat().st_size,
                                  'raw_sha256': raw_hash.hexdigest(), 'raw_bytes': raw_size}
    assert source_pins() == before and bundle_path.read_bytes() == bundle_raw
    result = {'schema': 'hepta.runtime.session-workdir-native-tests.v1', 'status': 'PASS',
        'counts': counts, 'streams': identities, 'elf_records': elf_records, 'source_pins': before,
        'source_unchanged': True, 'bundle_sha256': sha(bundle_raw), 'test_groups': 6,
        'actual_original_comparison_completed': False, 'public_workdir_handler_complete': False,
        'first_capabilities_policy_and_os_checks_complete': False, 'production_activated': False,
        'static_wire_domain_is_full_state_corpus': False,
        'whole_runtime_replaced': False, 'elapsed_seconds': time.monotonic() - started}
    (out / 'result.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps(result, sort_keys=True))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())

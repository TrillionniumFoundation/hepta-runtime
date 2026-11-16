"""Capture every actual HIA call and all four full mutable-buffer observations."""
from pathlib import Path
import argparse
import ctypes
import gzip
import hashlib
import json
import os
import struct
import sys
import time

ROOT = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'scripts'))
from build import verify_source, pin
from cases import domain, controls, index, encoded
from hia_native_loader import NativeModule

GROW = 0xffffffd0


def physical(session):
    return (ctypes.string_at(session._output, session.output_capacity),
            ctypes.string_at(session._workspace, session.workspace_capacity))


def run(build, output):
    source = verify_source()
    fixed = json.loads((ROOT / 'DOMAIN.json').read_bytes())
    assert index() == fixed
    planned = domain()
    planned_raw = encoded(planned)
    private = controls()
    assert pin(planned_raw) == fixed['complete_domain']
    assert pin(encoded(private)) == {key: fixed['private_controls'][key] for key in ('bytes', 'sha256')}
    output.mkdir(parents=True, exist_ok=False)
    (output / 'complete-domain.json.gz').write_bytes(gzip.compress(planned_raw, mtime=0))
    (output / 'complete-controls.json').write_bytes(encoded(private))
    (output / 'source-manifest.json').write_bytes((ROOT / 'SOURCE_MANIFEST.json').read_bytes())
    built = json.loads((build / 'BUILD.json').read_bytes())
    assert built['source_manifest_sha256'] == source
    manifest = build / built['module']
    assert pin(manifest.read_bytes()) == built['module_manifest']
    started = time.monotonic_ns()
    counts = dict(semantic_calls=0, private_controls=0, actual_calls=0, growth_calls=0, physical_bytes=0)
    passed = False
    try:
        with NativeModule(manifest, manifest_sha256=pin(manifest.read_bytes())['sha256']) as module, \
             gzip.open(output / 'complete-buffers.bin.gz', 'xb') as buffers, \
             (output / 'calls.jsonl').open('xb') as ledger:
            def call(session, wire, scenario, ordinal, kind):
                before_o, before_w = physical(session)
                result, after_o, after_w = session.invoke_raw(wire)
                pieces = (wire, before_o, after_o, before_w, after_w)
                buffers.write(struct.pack('<6Q', result, *(len(value) for value in pieces)))
                for value in pieces:
                    buffers.write(value)
                row = dict(call=counts['actual_calls'] + 1, scenario=scenario, ordinal=ordinal,
                           kind=kind, result=result, pid=os.getpid(),
                           buffers={name:pin(value) for name,value in zip(
                               ('input','output_before','output_after','workspace_before','workspace_after'),pieces)})
                ledger.write((json.dumps(row, sort_keys=True, separators=(',', ':')) + '\n').encode())
                counts['actual_calls'] += 1
                counts['physical_bytes'] += sum(map(len, pieces))
                return result, before_o, after_o, before_w, after_w
            for scenario in planned['scenarios']:
                session = module.session(output_capacity=128, workspace_capacity=scenario['initial_workspace'])
                try:
                    for ordinal, row in enumerate(scenario['rows']):
                        if 'workspace_patch' in row:
                            patch = row['workspace_patch']
                            raw = bytes.fromhex(patch['data_hex'])
                            assert patch['offset'] + len(raw) <= session.workspace_capacity
                            ctypes.memmove(ctypes.addressof(session._workspace) + patch['offset'], raw, len(raw))
                            continue
                        wire = bytes.fromhex(row['request_hex'])
                        while True:
                            result, before_o, after_o, before_w, after_w = call(
                                session, wire, scenario['name'], ordinal, 'semantic')
                            if result != GROW:
                                break
                            magic, kind, needed, reserved = struct.unpack('<8s3Q', after_o[:32])
                            assert magic == b'HGRWS002' and kind == 1 and reserved == 0
                            assert before_w == after_w and before_o[32:] == after_o[32:]
                            assert session.workspace_capacity < needed <= module.metadata['workspace_capacity']
                            capacity = max(needed, session.workspace_capacity * 2)
                            assert capacity <= module.metadata['workspace_capacity']
                            replacement = module.session(output_capacity=128, workspace_capacity=capacity)
                            ctypes.memmove(replacement._workspace, before_w, len(before_w))
                            session.close()
                            session = replacement
                            counts['growth_calls'] += 1
                        expected_state = bytes.fromhex(row['state_hex'])
                        assert result == row['result'] == 128, (scenario['name'], ordinal, result)
                        assert after_o == bytes.fromhex(row['output_hex']), (scenario['name'], ordinal, 'output')
                        assert after_w == expected_state + bytes(len(after_w) - len(expected_state)), (scenario['name'], ordinal, 'state')
                        counts['semantic_calls'] += 1
                finally:
                    session.close()
            for ordinal, row in enumerate(private):
                state = bytes.fromhex(row['state_hex'])
                with module.session(output_capacity=row['output_capacity'], workspace_capacity=len(state)) as session:
                    ctypes.memmove(session._workspace, state, len(state))
                    ctypes.memset(session._output, 0xa6, session.output_capacity)
                    result, before_o, after_o, before_w, after_w = call(
                        session, bytes.fromhex(row['request_hex']), row['name'], ordinal, 'private-control')
                    assert result == row['expected_result'], (row['name'], result)
                    assert before_o == after_o and before_w == after_w, row['name']
                    counts['private_controls'] += 1
        assert counts['semantic_calls'] == fixed['semantic_calls']
        assert counts['private_controls'] == fixed['private_controls']['cases']
        assert verify_source() == source
        passed = True
    finally:
        report = dict(schema='hepta.runtime.audit-store-queue.native-capture.v1',
                      status='COMPLETE_PRIVATE_NATIVE_CAPTURE' if passed else 'FAILED_PRIVATE_NATIVE_CAPTURE',
                      source_manifest_sha256=source, source_unchanged=verify_source()==source,
                      elapsed_seconds=(time.monotonic_ns()-started)/1e9, counts=counts,
                      files={p.name:pin(p.read_bytes()) for p in sorted(output.iterdir()) if p.is_file()},
                      original_reference_comparison_pass=False, concurrent_native_lock_qualified=False,
                      public_audit_qualified=False, whole_runtime_replaced=False)
        (output / 'CAPTURE.json').write_bytes(encoded(report))
        print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    run(args.build.resolve(), args.output.resolve())

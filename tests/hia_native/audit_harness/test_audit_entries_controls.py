"""Check raw borrowed-buffer rejection and persistent receipt binding.

These controls synthesize completion receipts only. Real filesystem equivalence
is established separately by the original/native process comparisons.
"""
from pathlib import Path
import argparse
import ctypes
import hashlib
import json
import struct
import sys

SHA = lambda raw: hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('manifest', 'runtime', 'output'):
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    sys.path[:0] = [str(args.runtime.resolve(strict=True) / 'scripts'), str(Path(__file__).resolve().parent)]
    from hia_native_loader import NativeModule
    from audit_entries_cases import request
    manifest = args.manifest.resolve(strict=True)
    manifest_raw = manifest.read_bytes()
    wire = request(1)
    output = args.output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    rows = []
    with NativeModule(manifest, manifest_sha256=SHA(manifest_raw)) as module:
        for name, raw, capacity, workspace, expected in [
                ('workspace-one-short', wire, 1024, (4 << 20) - 1, 0xfffffffe),
                ('output-one-short', wire, 31, 4 << 20, 0xfffffffe),
                ('bad-magic', b'BADMAGIC' + wire[8:], 1024, 4 << 20, 0xffffffff),
                ('short-header', wire[:15], 1024, 4 << 20, 0xffffffff),
                ('maximum-out-of-domain', request(513), 1 << 20, 4 << 20, 0xffffffff),
                ('preflight-one-short', wire, 551, 4 << 20, 0xfffffffe)]:
            code, received, state = module.invoke_raw(raw, output_capacity=capacity,
                workspace_capacity=workspace, output_fill=0xa7)
            assert code == expected and received == b'\xa7' * capacity
            rows.append(dict(name=name, code=code, output_untouched=True, state_sha256=SHA(state)))
        faults = [
            ('bad-action-magic', 256, 0), ('action-sequence', 264, 2),
            ('missing-acknowledgement', 320, 0), ('wrong-acknowledgement', 320, 2),
            ('action-kind', 272, 2), ('descriptor-slot', 280, 5),
            ('component-span', 288, 4096), ('component-count', 296, 133),
            ('action-argument', 304, 1), ('child-capacity', 312, 1),
            ('errno-out-of-range', 336, 4096), ('reserved-completion', 344, 1),
            ('state-sequence', 16, 2), ('persistent-source-length', 24, len(wire) + 1),
            ('persistent-output-length', 32, 1023), ('persistent-workspace-length', 40, (4 << 20) - 1),
            ('state-magic', 0, 1),
        ]
        for name, offset, value in faults:
            with module.session(output_capacity=1024, workspace_capacity=4 << 20) as session:
                ctypes.memset(session._output, 0xa7, 1024)
                code, received, state = session.invoke_raw(wire)
                assert code == 0xfffffff0 and received == b'\xa7' * 1024
                assert struct.unpack_from('<6Q', state, 272) == (10, 3, 4928, 1, 0, 0)
                struct.pack_into('<Q', session._workspace, 320, 1)
                struct.pack_into('<Q', session._workspace, 328, 0)
                struct.pack_into('<Q', session._workspace, 336, 5)
                struct.pack_into('<Q', session._workspace, offset, value)
                code, received, state = session.invoke_raw(wire)
                assert code == 0xffffffff and received == b'\xa7' * 1024, name
                rows.append(dict(name=name, code=code, output_untouched=True, state_sha256=SHA(state)))
        for name, changed, mixed in [('changed-suspended-input', request(0), False),
                ('error-with-nonzero-result', wire, True)]:
            with module.session(output_capacity=1024, workspace_capacity=4 << 20) as session:
                ctypes.memset(session._output, 0xa7, 1024)
                assert session.invoke_raw(wire)[0] == 0xfffffff0
                struct.pack_into('<Q', session._workspace, 320, 1)
                struct.pack_into('<Q', session._workspace, 328, 0)
                struct.pack_into('<Q', session._workspace, 336, 5)
                if mixed:struct.pack_into('<Q', session._workspace, 328, 3)
                code, received, state = session.invoke_raw(changed)
                assert code == 0xffffffff and received == b'\xa7' * 1024
                rows.append(dict(name=name, code=code, output_untouched=True, state_sha256=SHA(state)))
        with module.session(output_capacity=1024, workspace_capacity=4 << 20) as session:
            assert session.invoke_raw(wire)[0] == 0xfffffff0
            struct.pack_into('<Q', session._workspace, 320, 1)
            struct.pack_into('<Q', session._workspace, 328, 0)
            struct.pack_into('<Q', session._workspace, 336, 5)
            code, received, state = session.invoke_raw(wire)
            assert code == 32 and received[:32] == b'HRAER001' + struct.pack('<3Q', 23, 5, 0)
            assert struct.unpack_from('<Q', state, 8)[0] == 0
            assert struct.unpack_from('<Q', state, 56)[0] == 0
            rows.append(dict(name='synthetic-scan-open-error-completion', code=code,
                no_real_filesystem_effects=True, state_reset=True))
    assert manifest.read_bytes() == manifest_raw
    report = dict(schema='hepta.request-audit.bounded-entries-controls.v1', status='PASS',
        checks=len(rows), rejection_controls=25, synthetic_completion_controls=1, cases=rows,
        manifest_sha256=SHA(manifest_raw), original_executed=False, real_filesystem_effects=False,
        whole_runtime_replaced=False, production_activated=False)
    assert len(rows) == 26
    (output / 'result.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({k: v for k, v in report.items() if k != 'cases'}, sort_keys=True))


if __name__ == '__main__':
    main()

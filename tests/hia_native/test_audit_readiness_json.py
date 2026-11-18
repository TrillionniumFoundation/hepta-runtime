# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Capture the full actual audit JSON projection and all original buffer controls.

The fresh original recipe later consumes the complete same input and compares
every output byte. This phase does not count a retained result as execution.
"""
from pathlib import Path
import argparse
import json
import sys
import time
import traceback

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE / 'audit_harness'), str(HERE)]
from test_audit_json import process, SHA, INVALID, CAPACITY, WORK
from audit_json_cases import BASES, cases, frame, encoded


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('manifest', 'runtime', 'output'):
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args();out = args.output.resolve();out.mkdir(mode=0o700, parents=True)
    sys.path.insert(0, str(args.runtime.resolve(strict=True) / 'scripts'))
    from hia_native_loader import NativeModule, NativeRejected, NativeCapacityError
    manifest = args.manifest.resolve(strict=True);manifest_raw = manifest.read_bytes()
    report = {'schema': 'hepta.audit-readiness.native-json-capture.v1', 'status': 'RUNNING',
        'cases': [], 'controls': [], 'processes': [], 'native_entries': 0,
        'actual_original_requests': 0, 'semantic_reference_comparison_complete': False,
        'whole_runtime_replaced': False, 'production_activated': False,
        'old_stack_removal_qualified': False, 'result_storage_closed': False,
        'audit_storage_closed': False, 'public_request_dispatch_qualified': False}
    save = lambda: (out / 'result.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    started = time.monotonic();save()
    try:
        # Labels describe families and intentionally repeat in the original
        # corpus. The ordinal and complete request bytes identify every case.
        rows = list(cases());assert len(rows) == 3390
        incoming = b''.join(wire.hex().encode() + b'\n' for _, wire in rows)
        (out / 'reference.stdin').write_bytes(incoming)
        report['reference_input'] = {'bytes': len(incoming), 'sha256': SHA(incoming)}
        replies = []
        with NativeModule(manifest, manifest_sha256=SHA(manifest_raw)) as module:
            report['module'] = module.metadata
            with module.session(output_capacity=WORK, workspace_capacity=WORK) as session:
                with (out / 'native.stdout').open('xb') as stream:
                    for ordinal, (label, wire) in enumerate(rows):
                        report['native_entries'] += 1
                        try:
                            raw = session.invoke(wire);code = len(raw)
                        except (NativeRejected, NativeCapacityError) as error:
                            code, raw = error.code, b''
                        line = f'{code:08x}:'.encode() + raw.hex().encode()
                        replies.append(line);stream.write(line + b'\n')
                        report['cases'].append({'ordinal': ordinal, 'label': label,
                            'input_bytes': len(wire), 'input_sha256': SHA(wire), 'code': code,
                            'output_bytes': len(raw), 'output_sha256': SHA(raw)})
            for kind, base in enumerate(BASES, 1):
                wire = frame(kind, encoded(base))
                expected = next(replies[i] for i, (_, value) in enumerate(rows) if value == wire)
                raw_expected = bytes.fromhex(expected.split(b':')[1].decode())
                assert raw_expected
                for capacity in (0, 1, 255, len(raw_expected) - 1, len(raw_expected)):
                    code, output, _ = module.invoke_raw(wire, output_capacity=capacity,
                        workspace_capacity=WORK, output_fill=0x69, workspace_fill=0xa7)
                    report['native_entries'] += 1
                    passed = (code == CAPACITY and output == b'\x69' * capacity) if capacity < len(raw_expected) else (
                        code == len(raw_expected) and output == raw_expected)
                    row = {'name': 'output-capacity', 'kind': kind, 'capacity': capacity, 'code': code, 'passed': passed}
                    report['controls'].append(row);assert passed, row
                code, output, workspace = module.invoke_raw(wire, output_capacity=WORK,
                    workspace_capacity=WORK - 1, output_fill=0x69, workspace_fill=0xa7)
                report['native_entries'] += 1
                passed = code == CAPACITY and output == b'\x69' * WORK and workspace == b'\xa7' * (WORK - 1)
                row = {'name': 'workspace-capacity', 'kind': kind, 'passed': passed}
                report['controls'].append(row);assert passed, row
                code, output, _ = module.invoke_raw(frame(kind, b'{'), output_capacity=WORK,
                    workspace_capacity=WORK, output_fill=0x69, workspace_fill=0xa7)
                report['native_entries'] += 1
                passed = code == INVALID and output == b'\x69' * WORK
                row = {'name': 'invalid-output-untouched', 'kind': kind, 'passed': passed}
                report['controls'].append(row);assert passed, row
                executable = manifest.parent / module.metadata['standalone']['path']
                import os
                actual, receipt = process([executable], wire, out, 'native-elf-' + str(kind),
                    env=dict(os.environ, PATH=''))
                assert actual == raw_expected
                report['processes'].append(receipt)
        assert manifest.read_bytes() == manifest_raw
        assert report['native_entries'] == 3418 and len(report['controls']) == 28
        report.update(status='PASS', cases_executed=len(rows), controls_passed=28,
            native_standalone_processes=4, accepted=sum(row['code'] != INVALID for row in report['cases']),
            elapsed_seconds=time.monotonic() - started)
    except BaseException as error:
        report.update(status='FAIL', error=repr(error), elapsed_seconds=time.monotonic() - started)
        (out / 'failure.txt').write_text(traceback.format_exc());raise
    finally:
        save()
    print(json.dumps({key: report[key] for key in ('schema', 'status', 'cases_executed', 'native_entries',
        'controls_passed', 'native_standalone_processes', 'accepted', 'actual_original_requests',
        'semantic_reference_comparison_complete', 'elapsed_seconds')}, sort_keys=True))


if __name__ == '__main__':
    main()

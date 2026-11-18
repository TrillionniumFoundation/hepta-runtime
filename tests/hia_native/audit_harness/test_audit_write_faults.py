"""Compare actual original and HIA publication failures, held files and namespace races."""
from pathlib import Path
import argparse
import hashlib
import json
import struct
import sys
import time
import traceback
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_audit_write import run_one, SHA, ENCODE


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('native', 'oracle', 'output'):parser.add_argument('--' + key, required=True, type=Path)
    args = parser.parse_args();out = args.output.resolve();out.mkdir(mode=0o700, parents=True, exist_ok=False)
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from audit_write_fault_cases import cases
    report = dict(schema='hepta.request-audit.record-write-kernel-comparison.v1', status='FAIL', cases=[],
        production_activated=False, whole_runtime_replaced=False, old_stack_removal_qualified=False,
        result_storage_closed=False, archive_anchoring_closed=False, audit_storage_closed=False,
        public_request_dispatch_qualified=False, exact_serde_diagnostics_qualified=False)
    save = lambda: (out / 'result.json').write_bytes(ENCODE(report))
    save();started = time.monotonic()
    try:
        native, oracle = args.native.resolve(strict=True), args.oracle.resolve(strict=True)
        images = {str(path): dict(bytes=path.stat().st_size, sha256=SHA(path.read_bytes())) for path in (native, oracle)}
        report['executables'] = images
        definitions = list(cases());assert len({r['name'] for r in definitions}) == len(definitions)
        (out / 'cases.json').write_bytes(ENCODE(definitions))
        requests = 0
        for index, row in enumerate(definitions):
            directory = out / f'{index:04d}';directory.mkdir(mode=0o700)
            wire = b''.join(struct.pack('<Q', len(bytes.fromhex(raw))) + bytes.fromhex(raw) for raw in row['operations'])
            (directory / 'stdin.bin').write_bytes(wire)
            original, old_bytes = run_one(oracle, directory / 'original/fixture', directory / 'original', row, wire)
            actual, new_bytes = run_one(native, directory / 'native/fixture', directory / 'native', row, wire)
            equal = old_bytes == new_bytes and original['before'] == actual['before'] and original['after'] == actual['after'] and original['observations'] == actual['observations'] and original['selected_kernel_holding'] == actual['selected_kernel_holding']
            record = dict(index=index, name=row['name'], passed=equal, requests=len(row['operations']),
                original=original, native=actual)
            report['cases'].append(record);save();assert equal, (index, row['name'])
            requests += len(row['operations'])
        assert images == {str(path): dict(bytes=path.stat().st_size, sha256=SHA(path.read_bytes())) for path in (native, oracle)}
        report.update(status='PASS', compared_cases=len(definitions), original_requests=requests,
            native_requests=requests, actual_native_processes=len(definitions), actual_original_processes=len(definitions),
            complete_output_bytes_equal=True, all_selected_faults_reached=True, selected_kernel_held_files_equal=True, actual_held_descriptors_verified=True,
            observations_per_implementation=requests, metadata_contents_links_and_inode_changes_equal=True,
            elapsed_seconds=time.monotonic() - started, executables_unchanged=True)
    except BaseException as error:
        report['error'] = repr(error);(out / 'failure.txt').write_text(traceback.format_exc());raise
    finally:save()
    print(json.dumps({key: value for key, value in report.items() if key not in ('cases', 'executables')}, sort_keys=True))


if __name__ == '__main__':
    main()

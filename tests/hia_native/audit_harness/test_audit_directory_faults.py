"""Compare real directory syscalls, failure cleanup and retained leases."""
from pathlib import Path
import argparse
import json
import sys
import time
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parent))
from audit_directory_fault_cases import cases
from test_audit_directory import run, SHA, ENCODE


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('native', 'oracle', 'output'):
        parser.add_argument('--' + key, required=True, type=Path)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    report = dict(schema='hepta.request-audit.directory-kernel-comparison.v1', status='FAIL', cases=[],
        whole_runtime_replaced=False, production_activated=False, result_storage_closed=False,
        audit_storage_closed=False, public_request_dispatch_qualified=False,
        old_stack_removal_qualified=False, semantic_emulation=False)
    save = lambda: (out / 'result.json').write_bytes(ENCODE(report))
    started = time.monotonic()
    save()
    try:
        native, oracle = args.native.resolve(strict=True), args.oracle.resolve(strict=True)
        binaries = {str(p): SHA(p.read_bytes()) for p in (native, oracle)}
        definitions = list(cases())
        assert len(definitions) == len({r['name'] for r in definitions}) == 23
        (out / 'cases.json').write_bytes(ENCODE(definitions))
        for index, definition in enumerate(definitions):
            directory = out / f'{index:03d}'
            directory.mkdir(mode=0o700)
            original, expected = run(oracle, definition, directory / 'original')
            actual, received = run(native, definition, directory / 'native')
            equal = original == actual and expected == received
            matched = original['responses'][0].get('diagnostic') == definition['expected_first_diagnostic']
            item = dict(name=definition['name'], passed=equal, specified_diagnostic_matched=matched,
                original=original, native=actual)
            report['cases'].append(item)
            save()
            assert equal and matched, definition['name']
        assert binaries == {str(p): SHA(p.read_bytes()) for p in (native, oracle)}
        report.update(status='PASS', compared_cases=len(definitions), processes_per_implementation=len(definitions),
            requests_per_implementation=sum(len(r['actions']) for r in definitions),
            all_selected_faults_reached=True, actual_kernel_held_descriptors_verified=True,
            response_bytes_equal_after_verified_device_inode_projection=True,
            metadata_and_path_effects_equal=True, executable_bytes_unchanged=True,
            elapsed_seconds=time.monotonic() - started)
    except BaseException as error:
        report['error'] = repr(error)
        (out / 'failure.txt').write_text(traceback.format_exc())
        raise
    finally:
        save()
    print(json.dumps({k: v for k, v in report.items() if k != 'cases'}, sort_keys=True))


if __name__ == '__main__':
    main()

"""Run actual original/native archive-store failures under owned-child seccomp notification."""
from pathlib import Path
import argparse
import json
import sys
import time
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_prepare import run, SHA, ENCODE
from prepare_fault_cases import cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('native', 'oracle', 'output'):parser.add_argument('--' + key, required=True, type=Path)
    args = parser.parse_args();out = args.output.resolve();out.mkdir(mode=0o700, parents=True, exist_ok=False)
    report = dict(schema='hepta.request-archive.prepare-kernel-comparison.v1', status='FAIL', cases=[],
        whole_runtime_replaced=False, production_activated=False, result_storage_closed=False,
        archive_anchoring_closed=False, audit_storage_closed=False, public_request_dispatch_qualified=False,
        initialization_mutex_contention_qualified=False, initialization_mutex_poisoning_qualified=False)
    save = lambda: (out / 'result.json').write_bytes(ENCODE(report))
    started = time.monotonic();save()
    try:
        native, oracle = args.native.resolve(strict=True), args.oracle.resolve(strict=True)
        pins = {str(p): SHA(p.read_bytes()) for p in (native, oracle)}
        definitions = list(cases());assert len({r['name'] for r in definitions}) == len(definitions)
        with (out / 'cases.jsonl').open('xb') as corpus:
            for index, definition in enumerate(definitions):
                corpus.write(json.dumps(definition, sort_keys=True).encode() + b'\n');corpus.flush()
                directory = out / f'{index:03d}';directory.mkdir(mode=0o700)
                expected, old, _ = run(oracle, definition, directory / 'original')
                actual, new, _ = run(native, definition, directory / 'native')
                passed = expected == actual and old == new
                actual_diagnostics = [observation['response']['diagnostic'] for observation in expected['observations'] if 'response' in observation]
                wanted = definition['expected_diagnostics']
                correct_diagnostic = actual_diagnostics[:len(wanted)] == wanted
                row = dict(index=index, name=definition['name'], passed=passed,
                    specified_diagnostic_matched=correct_diagnostic, output_bytes=len(new),
                    output_sha256=SHA(new))
                report['cases'].append(row);save()
                if not passed or not correct_diagnostic:
                    (directory / 'mismatch.json').write_bytes(ENCODE(dict(original=expected, native=actual)))
                    raise AssertionError(row)
        assert pins == {str(p): SHA(p.read_bytes()) for p in (native, oracle)}
        report.update(status='PASS', compared_cases=len(definitions), processes_per_implementation=len(definitions),
            requests_per_implementation=sum(len(row['operations']) for row in definitions),
            all_selected_faults_reached=True, complete_response_bytes_equal=True, filesystem_equal_after_verified_identity_and_digest_projection=True,
            every_reply_verified_no_retained_fixture_descriptors=True, root_lifetime_assertions_checked=True, semantic_emulation=False,
            executable_bytes_unchanged=True, elapsed_seconds=time.monotonic() - started)
    except BaseException as error:
        report['error'] = repr(error);(out / 'failure.txt').write_text(traceback.format_exc());raise
    finally:save()
    print(json.dumps({key: value for key, value in report.items() if key != 'cases'}, sort_keys=True))


if __name__ == '__main__':main()

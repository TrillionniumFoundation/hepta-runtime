# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Fresh original normal calls against this invocation's complete native captures."""
from pathlib import Path
import gzip
import json
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[3]
sys.path[:0] = [str(ROOT/'scripts'), str(Path(__file__).resolve().parent)]
from public_lifecycle_registry import encoded, require
from public_lifecycle_retained import FOLDER, pin, obj, admit
from normal_runner import run, retire_fixture
from normal_evidence import verify_capture


def fixtures():
    values = json.loads(gzip.decompress(Path(__file__).with_name('normal.json.gz').read_bytes()))
    require(len(values) == 64 and sum(len(x['case']['events']) for x in values) == 359,
            'complete original fixture domain changed')
    return values


def execute(admission, expected, invocation, manifest, original, output):
    admission, manifest, original = (Path(p).resolve(strict=True) for p in (admission, manifest, original))
    output = Path(output).absolute()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    before = admit(admission, expected, invocation, ROOT, manifest, execution=True)
    native_folder = admission.parent/FOLDER
    native_report = obj(native_folder/'result.json')
    native = manifest.parent/obj(manifest)['executable']
    report = dict(schema='hepta.public-lifecycle.retained-normal.v1', status='RUNNING',
        admission=pin(admission), invocation=invocation, retained_native=before,
        original_binary=pin(original), original_binary_path=str(original),
        native_processes=0, retained_native_processes=64, original_processes=0,
        retained_native_requests=359, original_requests=0, processes=[], completed=[],
        actual_paired_filesystem_comparison=True, fault_injection=False,
        syscall_interception=False, external_host_operations=0,
        production_activated=False, whole_runtime_replaced=False)
    started = time.monotonic()
    def save():
        report['elapsed_seconds'] = time.monotonic()-started
        (output/'result.json').write_bytes(encoded(report))
    save()
    try:
        for index, fixture in enumerate(fixtures()):
            case, name = fixture['case'], 'case-%03d'%index
            retained = native_folder/name
            answer = verify_capture(retained/'native', case, native_report['processes'][index], native, False)
            require(answer[0].hex() == fixture['wire_hex'], 'native wire differs from the exact original corpus')
            directory = output/name
            directory.mkdir(mode=0o700)
            (directory/'case.json').write_bytes(encoded(case))
            row = {}
            report['processes'].append(row)
            def update(value):
                row.clear(); row.update(value); save()
            actual = run(original, 'original', directory, case, update, retained_common=retained/'common')
            require(actual == answer, 'complete native/original wire or filesystem differs: '+case['name'])
            retire_fixture(directory/'original')
            report['original_processes'] += 1
            report['original_requests'] += len(case['events'])
            report['completed'].append(native_report['completed'][index])
            save()
        require(admit(admission, expected, invocation, ROOT, manifest, execution=True) == before,
                'native captures changed while original calls executed')
        require(pin(original) == report['original_binary'], 'actual original binary changed')
        report['status'] = 'PASS'
    except BaseException as error:
        report.update(status='FAIL', error=repr(error), traceback=traceback.format_exc())
        raise
    finally:
        save()
    return verify(output, original, admission, expected, invocation, manifest)


def verify(folder, original, admission, expected, invocation, manifest):
    folder, original, admission, manifest = (Path(p).resolve(strict=True)
        for p in (folder, original, admission, manifest))
    before = admit(admission, expected, invocation, ROOT, manifest)
    report = obj(folder/'result.json')
    require(report['schema'] == 'hepta.public-lifecycle.retained-normal.v1' and report['status'] == 'PASS'
        and report['admission'] == pin(admission) and report['invocation'] == invocation
        and report['retained_native'] == before and report['native_processes'] == 0
        and report['retained_native_processes'] == report['original_processes'] == 64
        and report['retained_native_requests'] == report['original_requests'] == 359
        and report['original_binary'] == pin(original) and report['original_binary_path'] == str(original)
        and report['actual_paired_filesystem_comparison'] is True
        and report['external_host_operations'] == 0
        and all(report[k] is False for k in ('fault_injection','syscall_interception',
            'production_activated','whole_runtime_replaced')),
        'original retained capture identity or domain differs')
    native_folder = admission.parent/FOLDER
    native_report = obj(native_folder/'result.json')
    native = manifest.parent/obj(manifest)['executable']
    require(len(report['processes']) == len(report['completed']) == 64, 'original process domain incomplete')
    for index, fixture in enumerate(fixtures()):
        name, case = 'case-%03d'%index, fixture['case']
        require(obj(folder/name/'case.json') == case, 'original fixture changed')
        retained = native_folder/name
        left = verify_capture(retained/'native', case, native_report['processes'][index], native, False)
        right = verify_capture(folder/name/'original', case, report['processes'][index], original, True,
                               retained_common=retained/'common')
        require(left == right and left[0].hex() == fixture['wire_hex'], 'complete paired captures differ')
        require(report['completed'][index] == native_report['completed'][index], 'paired case completion changed')
    return dict(report=pin(folder/'result.json'), native_processes=0, retained_native_processes=64,
        original_processes=64, requests_per_implementation=359, new_executions_in_admission=0,
        full_raw_projections_reconstructed=True)


if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser(description=__doc__)
    for key in ('admission','build','original','output'):
        p.add_argument('--'+key, type=Path, required=True)
    p.add_argument('--admission-sha256', required=True)
    p.add_argument('--invocation', required=True)
    a = p.parse_args()
    print(json.dumps(execute(a.admission, a.admission_sha256, a.invocation, a.build, a.original, a.output), sort_keys=True))

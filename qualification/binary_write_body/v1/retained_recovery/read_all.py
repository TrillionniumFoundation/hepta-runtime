#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Read all 101 retained inputs, with the original 180-second per-reader budget."""
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import hashlib
import json
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent


def require(value, message):
    if not value:
        raise ValueError(message)


def read_case(groups, output, row):
    group, case = row
    folder = groups / str(group)
    stdout, stderr = output / (str(case) + '.json'), output / (str(case) + '.stderr')
    command = [sys.executable, '-I', '-S', '-B', str(HERE / 'read_retained.py'),
               '--source', str(folder / 'source'), '--work', str(folder / 'run'),
               '--case', str(case)]
    started = time.monotonic()
    timed_out = False
    with stdout.open('xb') as out, stderr.open('xb') as err:
        try:
            process = subprocess.run(command, stdout=out, stderr=err, timeout=180,
                                     start_new_session=True)
            returncode = process.returncode
        except subprocess.TimeoutExpired:
            returncode = None
            timed_out = True
    record = dict(group=group, case=case, command=command, returncode=returncode,
                  seconds=time.monotonic() - started, timed_out=timed_out, timeout_seconds=180,
                  stdout_bytes=stdout.stat().st_size, stderr_bytes=stderr.stat().st_size,
                  stdout_sha256=hashlib.sha256(stdout.read_bytes()).hexdigest(),
                  stderr_sha256=hashlib.sha256(stderr.read_bytes()).hexdigest(), status='FAIL')
    if returncode == 0:
        value = json.loads(stdout.read_bytes())
        require(value['status'] == 'READONLY_PASS' and value['before'] == value['after'],
                'complete before/after source and capture equality')
        require(len(value['probes']) == 11 and all(row['rejected'] for row in value['probes']),
                'all original read-only denial probes')
        require(value['evidence']['status'] == 'COMPLETE_ORIGINAL_NATIVE_WRITE_PASS',
                'full original/native comparison')
        require(all(value[key] == 0 for key in ('new_original_application_calls',
                    'new_native_application_calls', 'new_compiler_calls')), 'no application replay')
        record.update(status='PASS', guard_probes=11, entries=value['entries'],
                      evidence=value['evidence'], recovery_reader=value['recovery_reader'])
    (output / (str(case) + '.process.json')).write_text(json.dumps(record, sort_keys=True, indent=2) + '\n')
    print(json.dumps({key: record[key] for key in ('group', 'case', 'status', 'seconds')}), flush=True)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--groups', type=Path, required=True,
                        help='parent of materialized group directories 0 through 34')
    parser.add_argument('--output', type=Path, required=True, help='new report directory')
    parser.add_argument('--jobs', type=int, default=3, choices=range(1, 4))
    args = parser.parse_args()
    groups = args.groups.resolve(strict=True)
    require(not args.output.exists(), 'keep earlier reports; choose a new output directory')
    args.output.mkdir(parents=True)
    domain = json.loads((groups / '19/source/DOMAIN.json').read_bytes())
    cases = [(group['id'], case) for group in domain['groups'] for case in group['cases']]
    require(len(cases) == 101 and {case for _, case in cases} == set(range(101))
            and {group for group, _ in cases} == set(range(35)), 'complete frozen domain')
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        records = [future.result() for future in as_completed(
            [pool.submit(read_case, groups, args.output, row) for row in cases])]
    records.sort(key=lambda row: row['case'])
    summary = dict(schema='hepta.runtime.locked-write.retained-reader-recovery.v1',
                   status='PASS' if all(row['status'] == 'PASS' for row in records) else 'FAIL',
                   input_cases=len(records), passed=sum(row['status'] == 'PASS' for row in records),
                   groups=35, original_run=44196697861,
                   source_commit='ecc2076ab7537e2a637480769c7e3bb1403941e0',
                   original_invocations=sum(row.get('evidence', {}).get('entry_invocations', 0)
                                            for row in records),
                   native_invocations=sum(row.get('evidence', {}).get('entry_invocations', 0)
                                          for row in records),
                   guard_probes=sum(row.get('guard_probes', 0) for row in records),
                   largest_reader_seconds=max(row['seconds'] for row in records),
                   unchanged_reader_budget_seconds=180, new_original_application_calls=0,
                   new_native_application_calls=0, new_compiler_calls=0,
                   whole_runtime_replaced=False, production_activated=False,
                   old_stack_removal_qualified=False, cases=records)
    (args.output / 'SUMMARY.json').write_text(json.dumps(summary, sort_keys=True, indent=2) + '\n')
    print(json.dumps({key: value for key, value in summary.items() if key != 'cases'}), flush=True)
    return 0 if summary['status'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())

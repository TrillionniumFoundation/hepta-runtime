#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Independent arithmetic and raw-byte verification; never starts a workload."""
from pathlib import Path
import hashlib
import json
import math
import statistics

base = Path(__file__).resolve().parent
run_dir = base / 'a27-observation-probe-run-r02'
raw = (run_dir / 'run.json').read_bytes()
run = json.loads(raw)
analysis = json.loads((run_dir / 'analysis.json').read_bytes())
assert hashlib.sha256(raw).hexdigest() == 'c38f7190bf2f040cb20fa8999f377228cbb35957cea589c1c96d282fe3c99174'
assert run['completed'] and run['error'] is None and run['retries'] == 0
assert run['input_receipts_before'] == run['input_receipts_after']
assert run['inputs_unchanged'] and not run['input_fence_errors']
assert run['binaries_unchanged'] and not run['binary_fence_errors']
assert {row['path']: row for row in run['binary_receipts'].values()} == run['binary_receipts_after']
build_raw = (base / 'a27-observation-probe-build-r02/build.json').read_bytes()
build = json.loads(build_raw)
assert hashlib.sha256(build_raw).hexdigest() == run['build']['sha256'] == 'acbed08436eec71a6f6aa2615dcad2038f0bc9cc3d66d0eb25e31034804aed70'
assert build['inputs_before'] == build['inputs_after'] == run['input_receipts_before']
assert build['prepared'] and build['compiled']
assert len(run['cells']) == 32 and len(run['semantics']) == 2
remote = Path('/home/qian/hepta-runtime-optimization-20261023/a27-observation-probe-run-r02')
for child in run['cells'] + run['semantics']:
    assert child['returncode'] == 0 and child['stderr_bytes'] == 0 and child['parse_error'] is None
    assert not child['interrupted'] and not child['signal_forwarded']
    for name in ('stdout.json', 'stderr.log'):
        receipt = child[name]
        data = (run_dir / Path(receipt['path']).relative_to(remote)).read_bytes()
        assert len(data) == receipt['bytes'] and hashlib.sha256(data).hexdigest() == receipt['sha256']
        if name == 'stdout.json':
            assert json.loads(data) == child['record']
    assert child['record']['passed']
for sequence, cell in enumerate(run['cells']):
    assert (cell['sequence'], cell['block'], cell['position'], cell['variant']) == (
        sequence, sequence // 4, sequence % 4, 'ABBA'[sequence % 4])
    rows = cell['record']['rows']
    assert len(rows) == 68
    # The frozen probe numbers each phase independently, as declared before timing.
    assert [(row['phase'], row['index']) for row in rows] == (
        [('warmup', index) for index in range(4)] + [('measured', index) for index in range(64)])
    assert all(row['attempted'] and row['passed'] and not row['stop_cancelled']
               and row['clock_error'] is None and row['validation_error'] is None for row in rows)
metrics = {}
for name in ('process_cpu_ns', 'owner_thread_cpu_ns', 'wall_ns'):
    gains = []
    for block in range(8):
        totals = {arm: sum(row[name] for cell in run['cells']
                          if cell['block'] == block and cell['variant'] == arm
                          for row in cell['record']['rows'] if row['phase'] == 'measured')
                  for arm in 'AB'}
        gains.append(100 * (totals['A'] - totals['B']) / totals['A'])
    median = statistics.median(gains)
    mad = statistics.median(abs(value - median) for value in gains)
    metrics[name] = {'median_improvement_percent': median, 'mad_percentage_points': mad,
                     'positive_blocks': sum(value > 0 for value in gains),
                     'paired_improvements_percent': gains}
    assert math.isclose(median, analysis['summaries'][name]['median_improvement_percent'], abs_tol=1e-12)
    assert math.isclose(mad, analysis['summaries'][name]['median_absolute_deviation_percent'], abs_tol=1e-12)
cpu, wall = metrics['process_cpu_ns'], metrics['wall_ns']
gates = {
    'median_process_cpu_at_least_3_percent': cpu['median_improvement_percent'] >= 3,
    'at_least_7_of_8_process_cpu_blocks_improve': cpu['positive_blocks'] >= 7,
    'median_process_cpu_strictly_above_2_mad': cpu['median_improvement_percent'] > 2 * cpu['mad_percentage_points'],
    'median_wall_regression_at_most_2_percent': wall['median_improvement_percent'] >= -2,
}
assert gates == analysis['gates'] and not all(gates.values())
assert analysis['valid_complete_experiment'] and not analysis['eligible_for_runtime_candidate']
result = {
    'schema': 'hepta-x230-a27-owner-root-recomputation/v1',
    'verified_raw_experiment': True, 'child_stdout_stderr_receipts_verified': 68,
    'measured_operations': 2048, 'warmup_operations': 128,
    'all_2176_operations_attempted_and_passed': True, 'no_retry': True,
    'input_and_binary_receipts_unchanged': True,
    'raw_run_sha256': hashlib.sha256(raw).hexdigest(),
    'raw_build_sha256': hashlib.sha256(build_raw).hexdigest(),
    'raw_analysis_sha256': hashlib.sha256((run_dir / 'analysis.json').read_bytes()).hexdigest(),
    'initial_root_check_correction': 'initial ad-hoc validator expected one 0..67 index sequence; frozen probe numbers warmup and measured phases separately; corrected validator only; workload not rerun',
    'metrics': metrics, 'gates': gates, 'adopted': False,
    'decision': 'retain A26 path implementation',
}
target = base / 'ROOT_RECOMPUTATION.json'
with target.open('x') as output:
    json.dump(result, output, sort_keys=True, indent=2)
    output.write('\n')
print(json.dumps({'verified': True, 'measured': 2048, 'warmups': 128, 'gates': gates,
                  'receipt_sha256': hashlib.sha256(target.read_bytes()).hexdigest()}))

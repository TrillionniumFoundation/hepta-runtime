#!/usr/bin/env python3
"""Offline-only audit of the received fixed 4 KiB request-hash probe evidence."""
import argparse
from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path
import statistics
import tomllib

CASES = [('small_176', 100000, 256), ('escaped_small', 50000, 256),
         ('plain_64k', 512, 8), ('escaped_64k', 128, 4),
         ('plain_1mib', 32, 2), ('escaped_1mib', 8, 2)]
REPORT_SHA = 'c8b96746a42c7a70f332be0afd1263093e6e6528d9cc9a2e7275245505dafde1'
BUNDLE_SHA = '646122205a408311e52555c944e3650079eebe3824605e5eb43deeca7ae7b55b'
BASELINE_SHA = 'c9080de8aa9a35f7495aa2822a1495d297903900ae0f0de26d7b0c86d043d3c9'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(path):
    raw = path.read_bytes()
    return {'bytes': len(raw), 'sha256': sha(raw)}


def document(path):
    return json.loads(path.read_bytes())


def close(a, b):
    return math.isfinite(a) and math.isfinite(b) and math.isclose(a, b, rel_tol=2e-12, abs_tol=2e-10)


def canonical_fixture(name):
    params = {'args': [], 'cpu_quota_percent': None, 'cwd': None, 'env': {},
              'executable': '/usr/bin/true', 'host': 'x230-host', 'memory_max_bytes': None,
              'nice': None, 'stdin': None, 'timeout_seconds': None}
    if name == 'escaped_small':
        params.update(args=['quote"slash\\', 'NUL\0\n\t\r', 'λ雪🦀'], cwd='/tmp/雪\\"',
                      env={'A': '雪\n"', 'Z': 'x\\'}, stdin='"\\\0\nλ雪🦀' * 2)
    elif name in ('plain_64k', 'plain_1mib'):
        params['stdin'] = 'x' * (65536 if name == 'plain_64k' else 1048576)
    elif name in ('escaped_64k', 'escaped_1mib'):
        params['stdin'] = '"\\\0\n' * ((65536 if name == 'escaped_64k' else 1048576) // 4)
    return json.dumps(params, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    evidence = args.evidence.absolute()
    probe, bundle = evidence / 'probe', evidence / 'bundle'
    checks = {}

    def check(name, value):
        if type(value) is not bool or not value:
            raise ValueError('check failed: ' + name)
        checks[name] = True

    report = document(probe / 'report.json')
    protocol = document(probe / 'protocol.json')
    freeze = document(probe / 'freeze.json')
    manifest = document(bundle / 'bundle-manifest.json')
    export = document(evidence / 'export-manifest.json')
    check('actual_report_sha', identity(probe / 'report.json')['sha256'] == REPORT_SHA)
    check('actual_bundle_sha', identity(bundle / 'bundle-manifest.json')['sha256'] == BUNDLE_SHA)
    check('report_success_scope', report['schema'] == 'hepta-r20-request-hash-report/v1'
          and report['passed'] is report['source_stable'] is True and report['automatic_retries'] == 0)
    check('all_archived_source_hashes', all(identity(evidence / name) == {k: row[k] for k in ('bytes', 'sha256')}
          for name, row in export['files'].items()) and len(export['files']) == 332)
    check('all_bundle_inputs_match', all(identity(bundle / name) == row for name, row in manifest['files'].items()))
    check('protocol_fixed_cells', protocol['blocks'] == 4 and protocol['order'] == list('ABBA')
          and protocol['cases'] == [list(row) for row in CASES] and protocol['cells'] == 96)
    check('protocol_original_screens', protocol['small_regression_screen_percent'] == 2.0
          and protocol['plain_large_regression_screen_percent'] == 2.0
          and protocol['escaped_large_improvement_screen_percent'] == 5.0
          and protocol['escaped_large_all_four_blocks_must_improve'] is True
          and protocol['screen_is_not_production_adoption'] is True)
    check('protocol_sources_and_buffer', protocol['source_files'] == manifest['files']
          and protocol['candidate'] == 'one fixed 4096-byte stack buffer, same sha2 and serde_json')
    check('explicit_offline_two_jobs_arena1_no_wrappers', protocol['environment']['CARGO_NET_OFFLINE'] == 'true'
          and protocol['environment']['CARGO_BUILD_JOBS'] == '2'
          and protocol['environment']['MALLOC_ARENA_MAX'] == '1'
          and all(key not in protocol['environment'] for key in (
              'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'CARGO_BUILD_RUSTC_WRAPPER', 'CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER')))
    check('actual_compiled_project_sources', all(identity(probe / 'project' / name) == value
          for name, value in manifest['files'].items() if name in ('Cargo.toml', 'rustfmt.toml') or name.startswith('src/')))
    baseline = (evidence / 'baseline/jobs.rs').read_bytes()
    check('baseline_identity', sha(baseline) == BASELINE_SHA == freeze['source_sha256'] == report['baseline_jobs_sha256'])
    start = baseline.index(b'// Keep the alphabetical key order of the original serde_json::Value map.')
    end = baseline.index(b'// Retain the old prefix only', start)
    check('exact_baseline_function_excerpt', baseline[start:end] == (bundle / 'src/baseline.inc.rs').read_bytes())
    lock_path = probe / 'project/Cargo.lock'
    check('resolved_lock_hash', identity(lock_path) == freeze['resolved_cargo_lock'] == report['resolved_cargo_lock'])
    package_id = lambda row: tuple(row.get(key) for key in ('name', 'version', 'source', 'checksum'))
    old_packages = tomllib.loads((bundle / 'r19-Cargo.lock').read_text())['package']
    packages = tomllib.loads(lock_path.read_text())['package']
    external = [row for row in packages if row['name'] != 'hepta-r20-request-hash-probe']
    allowed = {package_id(row) for row in old_packages}
    check('resolved_dependencies_subset_r19', len(packages) == 23 and len(external) == 22
          and all(package_id(row) in allowed for row in external) and packages == freeze['resolved_packages'])
    check('freeze_metadata_identity', identity(probe / '03-metadata.stdout') == freeze['metadata_stdout']
          and freeze['manifest'] == BUNDLE_SHA and freeze['all_external_packages_in_r19_lock'] is True)
    elf = export['actual_probe_binary_excluded']
    check('actual_remote_elf_hash_witness', {key: elf[key] for key in ('bytes', 'sha256')} == report['binary']
          and elf['observed_link_count'] == 2 and export['compiled_target_files_archived'] is False)

    stages = report['stages']
    expected_prefix = ['01-cargo-version', '02-rustc-version', '03-metadata', '04-build', '05-tests', '06-check']
    expected_names = list(expected_prefix)
    expected_cells = []
    for block in range(4):
        for name, iterations, warmup in CASES:
            for slot, arm in enumerate('ABBA'):
                index = len(expected_cells)
                expected_names.append(f'cell-{index:03d}-{block}-{name}-{slot}-{arm}')
                expected_cells.append((block, name, iterations, warmup, slot, arm))
    check('exact_102_stage_order', len(stages) == 102 and [row['name'] for row in stages] == expected_names)
    check('all_stage_receipts_streams_and_reap', all(
        document(probe / (row['name'] + '.stage.json')) == row and type(row['returncode']) is int and row['returncode'] == 0
        and row['waited_and_reaped'] is True and row['automatic_retries'] == 0 and row['pid'] > 1
        and all(identity(probe / row[stream]['path']) == {key: row[stream][key] for key in ('bytes', 'sha256')}
                and row[stream]['path'] == row['name'] + '.' + stream for stream in ('stdout', 'stderr'))
        for row in stages))
    check('fixed_prepare_commands', [row['argv'] for row in stages[:5]] == [
        ['cargo', '+1.95.0', '--version'], ['rustc', '+1.95.0', '--version'],
        ['cargo', '+1.95.0', 'metadata', '--offline', '--format-version', '1'],
        ['cargo', '+1.95.0', 'build', '--release', '--offline', '--locked'],
        ['cargo', '+1.95.0', 'test', '--release', '--offline', '--locked']])
    check('fixed_timeouts', [row['timeout_seconds'] for row in stages[:6]] == [30, 30, 180, 900, 180, 60]
          and all(row['timeout_seconds'] == 60 for row in stages[6:]))
    check('two_actual_tests_pass', 'test result: ok. 2 passed; 0 failed;' in (probe / '05-tests.stdout').read_text())
    semantic = document(probe / '06-check.stdout')
    fixtures = {row['case']: row for row in semantic['fixtures']}
    check('actual_semantics_and_seven_boundaries', semantic == report['fixtures']
          and semantic['passed'] is True and semantic['buffer_bytes'] == 4096 and semantic['boundary_cases'] == 7
          and set(fixtures) == {row[0] for row in CASES}
          and all(row['canonical_bytes_equal'] is row['serialized_stream_equal'] is row['full_hash_equal'] is True
                  for row in fixtures.values()))
    canonical = {name: canonical_fixture(name) for name, _, _ in CASES}
    check('independent_python_fixture_hashes', all(sha(raw) == fixtures[name]['sha256']
          and len(raw) == fixtures[name]['serialized_bytes'] for name, raw in canonical.items())
          and len(canonical['small_176']) == 176)
    raw = (probe / 'raw-cells.jsonl').read_bytes()
    check('actual_raw_hash', {'bytes': len(raw), 'sha256': sha(raw)} == report['raw_cells'])
    cells = [json.loads(line) for line in raw.splitlines()]
    check('96_cell_count', len(cells) == report['cells'] == len(expected_cells) == 96)
    binary_path = '/home/qian/hepta-runtime-optimization-20261105-r20/request-hash-probe-01/target/release/hepta-r20-request-hash-probe'
    for index, (cell, expected) in enumerate(zip(cells, expected_cells)):
        block, name, iterations, warmup, slot, arm = expected
        stage = stages[index + 6]
        stream = probe / stage['stdout']['path']
        actual = document(stream)
        check(f'cell_{index:03d}_original_and_protocol', {key: value for key, value in cell.items()
              if key not in ('block', 'slot', 'stdout', 'binary')} == actual
              and (cell['block'], cell['case'], cell['iterations'], cell['warmup'], cell['slot'], cell['arm']) == expected
              and cell['stdout'] == identity(stream) and cell['binary'] == report['binary']
              and cell['schema'] == 'hepta-r20-request-hash-cell/v1' and cell['all_hashes_equal'] is True
              and cell['expected_sha256'] == fixtures[name]['sha256']
              and stage['argv'] == [binary_path, 'worker', arm, name, str(iterations), str(warmup), fixtures[name]['sha256']])
        check(f'cell_{index:03d}_raw_cpu_wall_units', type(cell['cpu_ns']) is type(cell['wall_ns']) is int
              and cell['cpu_ns'] > 0 and cell['wall_ns'] > 0
              and close(cell['cpu_ns_per_call'], cell['cpu_ns'] / iterations)
              and close(cell['wall_ns_per_call'], cell['wall_ns'] / iterations)
              and all(type(cell[when][metric]) is int and cell[when][metric] > 0
                      for when in ('before', 'after') for metric in ('rss_bytes', 'lifetime_maxrss_bytes')))
    rows = []
    for name, iterations, _ in CASES:
        scene = [cell for cell in cells if cell['case'] == name]
        block_rows = []
        for block in range(4):
            means = {arm: sum(Fraction(cell['cpu_ns'], cell['iterations']) for cell in scene
                     if cell['block'] == block and cell['arm'] == arm) / 2 for arm in 'AB'}
            change = float((means['B'] / means['A'] - 1) * 100)
            block_rows.append({'block': block, 'A_mean_cpu_ns_per_call': float(means['A']),
                               'B_mean_cpu_ns_per_call': float(means['B']), 'B_vs_A_percent': change})
        changes = [row['B_vs_A_percent'] for row in block_rows]
        median_change = statistics.median(changes)
        arm_rows = {arm: {'cpu_ns_per_call_median': float(statistics.median(Fraction(cell['cpu_ns'], iterations)
                    for cell in scene if cell['arm'] == arm)),
                    'wall_ns_per_call_median': float(statistics.median(Fraction(cell['wall_ns'], iterations)
                    for cell in scene if cell['arm'] == arm)),
                    'rss_before_bytes': [cell['before']['rss_bytes'] for cell in scene if cell['arm'] == arm],
                    'rss_after_bytes': [cell['after']['rss_bytes'] for cell in scene if cell['arm'] == arm],
                    'lifetime_maxrss_bytes': [cell['after']['lifetime_maxrss_bytes'] for cell in scene if cell['arm'] == arm]}
                    for arm in 'AB'}
        claimed = next(row for row in report['summary'] if row['case'] == name)
        check(name + '_all_report_block_statistics', all(close(a, b) for a, b in
              zip(changes, claimed['cpu_paired_block_change_percent']))
              and len(claimed['cpu_paired_block_change_percent']) == 4
              and close(median_change, claimed['cpu_paired_block_change_median_percent'])
              and all(close(arm_rows[arm][metric], claimed['arms'][arm][metric]) for arm in 'AB'
                      for metric in ('cpu_ns_per_call_median', 'wall_ns_per_call_median'))
              and all(arm_rows[arm][metric] == claimed['arms'][arm][metric] for arm in 'AB'
                      for metric in ('rss_before_bytes', 'rss_after_bytes', 'lifetime_maxrss_bytes')))
        escaped = name in ('escaped_64k', 'escaped_1mib')
        passed = median_change <= (-5 if escaped else 2) and (all(value < 0 for value in changes) if escaped else True)
        rows.append({'case': name, 'blocks': block_rows, 'paired_block_median_change_percent': median_change,
                     'arms': arm_rows, 'screen_passed': passed,
                     'screen': 'median <= -5%, all four blocks < 0%' if escaped else 'median <= +2%'})
    screen = all(row['screen_passed'] for row in rows)
    check('reported_screen_recomputed', screen is report['mechanism_screen_passed'] is False)
    check('exact_rejected_scenes', [row['case'] for row in rows if not row['screen_passed']]
          == ['small_176', 'escaped_small', 'plain_64k'])
    hwm = sorted({cell[when]['lifetime_maxrss_bytes'] for cell in cells for when in ('before', 'after')})
    result = {'schema': 'hepta-r20-request-hash-independent-review/v1', 'verified': True,
        'evidence_report': identity(probe / 'report.json'), 'raw_cells': identity(probe / 'raw-cells.jsonl'),
        'bundle_manifest': identity(bundle / 'bundle-manifest.json'), 'resolved_cargo_lock': identity(lock_path),
        'remote_elf_hash_witness': elf, 'cells': len(cells), 'stages': len(stages),
        'prepare_stages': 6, 'worker_stages': 96, 'actual_cargo_tests_passed': 2,
        'separate_check_boundary_cases': 7, 'canonical_fixture_count': 6,
        'check_count': len(checks), 'checks': checks, 'scenes': rows,
        'mechanism_screen_passed': screen, 'production_integration_prepared': False,
        'decision': 'reject this fixed 4096-byte candidate under its preregistered screen',
        'memory': {'all_observed_lifetime_hwm_values_bytes': hwm,
                   'per_call_allocation_measured': False, 'rss_improvement_established': False},
        'measurement_scope': 'CLOCK_PROCESS_CPUTIME_ID for timed digest loop including equal full-hash check; startup/fixture/warmup/resource samples excluded',
        'limits': ['This component is not full-chain status/read or start throughput.',
                  'Block changes are ratios of within-block A/B means; their median differs from ratio of pooled arm medians.',
                  'Every worker HWM is the same; high-water causality was not separately diagnosed and supports no RSS gain claim.',
                  'Four finite ABBA blocks are not a significance or global optimum proof.',
                  'Actual ELF was hashed remotely and excluded from the archive; offline audit cannot independently regenerate it.',
                  'The 64-byte follow-up tests a stack/initialization-cost hypothesis; this rejection does not establish that cause.']}
    with args.output.open('x') as stream:
        json.dump(result, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write('\n')
    print(json.dumps({'verified': True, 'checks': len(checks), 'cells': 96, 'stages': 102,
                      'mechanism_screen_passed': screen, 'output': str(args.output),
                      'output_sha256': identity(args.output)['sha256']}))


if __name__ == '__main__':
    main()

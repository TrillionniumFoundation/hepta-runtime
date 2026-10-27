#!/usr/bin/env python3
"""Offline field and decimal arithmetic audit; deliberately not the raw audit."""
import hashlib
import json
import math
from decimal import Decimal as D
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOC = ROOT / 'runtime-resume/docs/experiments/x230/a53'
FROZEN = ROOT / 'ci-audit/a53-r02/frozen-r01'
PINS = {
    'small-report.original.json': (134076, '7484d98191b7c8be3cd39f7d65e5c42840dbe5be3892aeb8799206da4f16824d'),
    'small-analysis.original.json': (22085, '12c534872769e6cc81715db4c3a58080b60065defdaebfac8147b8b75488920e'),
    'qualification-r02.original.json': (62012, 'ab3a37ceb97667694c201d9b62556398e04e805010c8492af6a8f6f51486a72b'),
}
PROTOCOL_SHA = 'f36f7f9f2deed6e9e9d1e94cbafc7369d3291828d8fc022bf289dba28654760d'
ELFS = {'r07': '7ab8d93d00f964e7e479ee7df7d25f40ede8e364f3914d30b9fa4b7b2ff867eb',
        'A53': '5855f6fb044745eba0bf0885b0430bc5a5bb03f68310cce50d961947925c03c6'}
checks = []


def need(value, name):
    if not value:
        raise ValueError(name)
    checks.append(name)


def main():
    inputs = {}
    values = {}
    for name, (size, sha) in PINS.items():
        raw = (DOC / name).read_bytes()
        need(len(raw) == size and hashlib.sha256(raw).hexdigest() == sha, name + ': exact original')
        inputs[name] = {'bytes': size, 'sha256': sha}
        values[name] = json.loads(raw)
    raw = (FROZEN / 'small-archive-a53-r01.protocol.json').read_bytes()
    need(hashlib.sha256(raw).hexdigest() == PROTOCOL_SHA, 'actual frozen protocol')
    p = json.loads(raw)
    r, a, q = [values[k] for k in PINS]
    need(a['original_report_pin'] == PINS['small-report.original.json'][1], 'evaluation binds original report')
    need(a['original_protocol_pin'] == PROTOCOL_SHA, 'evaluation binds actual protocol')
    need(r['passed'] and r['complete'] and r['phase'] == 'complete', 'complete producer report')
    need(r['new_measured_calls'] == r['observed_measured_calls'] == 8192, 'all 8192 measured calls retained')
    need(r['new_total_tool_calls'] == 8848 and not r['unexecuted'] and not r['measured_count_unknown_stages'], 'all 8848 tool calls and no unknown stage')
    need(a['passed'] and a['report_evaluation_complete'] and a['numeric_gates_passed'] and not a['errors'], 'complete original numeric evaluation')
    need(a['all_purpose_counts'] == {'seed': 512, 'preflight': 40, 'warmup': 64, 'measured': 8192, 'postflight': 40}, 'all purpose counts')
    need(a['measured_calls'] == 8192 and a['total_tool_calls'] == 8848, 'evaluation complete counts')
    need(a['benchmark_or_runtime_executions'] == 0 and a['report_edits'] == 0 and not a['historical_results_pooled'], 'offline evaluator and no pooled history')
    need(len(r['stages']) == 2 and len(a['rounds']) == 8, 'exact two blocks and eight rounds')
    controller_pids = []
    for block, stage in enumerate(r['stages']):
        plan = p['blocks'][block]
        need(stage['name'] == plan['name'] and stage['actual_order'] == plan['actual_order'], f'block {block}: opposite fixed ABBA')
        need(stage['cli_order'] == ['A', 'B', 'B', 'A'] and stage['execution_count'] == 1, f'block {block}: one attempt')
        need(stage['executed'] and stage['status'] == 'passed' and stage['returncode'] == 0 and not stage['timed_out'], f'block {block}: complete success')
        need(stage['original_child_reaped'] and stage['custody_retained_until_reap'] and stage['pidfd_opened'], f'block {block}: original helper custody report')
        need(stage['actual_waitpid'] == stage['helper_pid'] > 0 and stage['raw_wait_status'] == 0 and stage['signals'] == [], f'block {block}: original helper waitpid raw zero')
        need(stage['budget_seconds'] == 300 and stage['cleanup_grace_seconds'] == 60 and stage['forced_reap_grace_seconds'] == 10, f'block {block}: unchanged budgets')
        need(stage['host_before_clear'] and stage['host_after_clear'] and stage['qualified_inputs_unchanged_after_block'], f'block {block}: reported gates and input fence')
        need(stage['observed_calls']['total'] == 4424 and stage['observed_calls']['measured'] == 4096 and stage['observed_calls']['all_failures'] == 0, f'block {block}: full correct journal report')
        need(stage['original_artifact_count'] == 827 and stage['journal_coverage_exact'], f'block {block}: expected raw inventory reported')
        for index, actual in enumerate(stage['actual_rounds']):
            row = a['rounds'][block * 4 + index]
            arm = plan['actual_order'][index]
            need(row['block'] == block and row['round'] == index and row['version'] == arm == actual['version'], f'round {block}/{index}: actual arm')
            need(row['cli_arm'] == actual['cli_arm'] == ['A', 'B', 'B', 'A'][index], f'round {block}/{index}: CLI arm')
            need(actual['release_sha256'] == ELFS[arm], f'round {block}/{index}: release SHA')
            need(D(row['wall_seconds']) == D(str(actual['measured_wall_seconds'])), f'round {block}/{index}: all measured wall')
            # The producer display subtracts binary floats; the evaluator uses
            # exact integer ticks. Compare only that representational error.
            cpu_display = actual['measured_controller_cpu_seconds']
            need(abs(float(row['cpu_observed_seconds']) - cpu_display) <= 2 * math.ulp(cpu_display), f'round {block}/{index}: observed CPU display within two floating point ULPs')
            need(D(row['cpu_interval_margin_seconds']) == D(4) / D(row['cpu_tick_hz']), f'round {block}/{index}: original tick uncertainty')
            need(D(row['cpu_lower_seconds']) == max(D(0), D(row['cpu_observed_seconds']) - D(row['cpu_interval_margin_seconds'])) and D(row['cpu_upper_seconds']) == D(row['cpu_observed_seconds']) + D(row['cpu_interval_margin_seconds']), f'round {block}/{index}: CPU interval bounds')
            waited = actual['whole_round_wait4']
            need(waited['exit_code'] == 0 and waited['pid'] > 0, f'round {block}/{index}: reported original controller wait4')
            controller_pids.append(waited['pid'])
            need(D(row['whole_round_wait4_cpu_seconds']) == D(str(waited['total_cpu_seconds'])) and row['whole_round_wait4_max_rss_kib'] == waited['max_rss_kib'], f'round {block}/{index}: wholelife CPU and RSS')
            need(row['measured_calls'] == 1024 and row['fd_endpoints'] == ([20, 20] if arm == 'r07' else [24, 24]), f'round {block}/{index}: calls and FD endpoints')
    need(len(set(controller_pids)) == 8, 'eight distinct original controller PIDs')
    for arm, count in [('r07', 165), ('A53', 175)]:
        bundle = r['qualifications'][arm]
        need(bundle['source_files'] == count == len(bundle['source_map']), arm + ': exact source inventory size')
        need(r['final_source_maps'][arm] == bundle['source_map'], arm + ': reported before/after source map equality')
        need(hashlib.sha256(json.dumps(bundle['source_map'], sort_keys=True, separators=(',', ':')).encode()).hexdigest() == p['bindings'][arm]['source_map_compact_sha256'], arm + ': map bound to actual protocol')
        need(bundle['binary']['sha256'] == ELFS[arm], arm + ': actual qualified ELF receipt')
        rows = [x for x in a['rounds'] if x['version'] == arm]
        total = a['arms'][arm]
        need(total['rounds'] == len(rows) == 4 and total['measured_calls'] == sum(x['measured_calls'] for x in rows) == 4096, arm + ': all four rounds included')
        for key in ['wall_seconds', 'cpu_observed_seconds', 'cpu_interval_margin_seconds', 'cpu_lower_seconds', 'cpu_upper_seconds', 'whole_round_wait4_cpu_seconds']:
            need(D(total[key]) == sum((D(x[key]) for x in rows), D(0)), arm + ': sum ' + key)
        need(total['whole_round_wait4_max_rss_kib'] == max(x['whole_round_wait4_max_rss_kib'] for x in rows), arm + ': maximum wholelife RSS')
        need(D(total['successful_calls_per_second']) == D(4096) / D(total['wall_seconds']), arm + ': complete C1 rate')
    need(q['qualified'] and q['source_tested'] == q['source_after'] == r['final_source_maps']['A53'], 'actual A53 qualification 175 source map')
    qualified_binary = r['qualifications']['A53']['binary']
    need(all(q['binary'][key] == qualified_binary[key] for key in ['path', 'sha256', 'compiler_source']), 'actual A53 qualification path SHA and compiler source binding')
    need(q['binary']['cached'] is False and qualified_binary['fresh'] is False and qualified_binary['compiler_profile'] == {'debug_assertions': False, 'debuginfo': 0, 'opt_level': '3', 'overflow_checks': False, 'test': False}, 'reported actual release compiler profile and noncached build')
    baseline, candidate = a['arms']['r07'], a['arms']['A53']
    ratios = {
        'wall_candidate_over_baseline': D(candidate['wall_seconds']) / D(baseline['wall_seconds']),
        'cpu_observed_candidate_over_baseline': D(candidate['cpu_observed_seconds']) / D(baseline['cpu_observed_seconds']),
        'cpu_candidate_upper_over_baseline_lower': D(candidate['cpu_upper_seconds']) / D(baseline['cpu_lower_seconds']),
        'rss_candidate_limit_kib': max(D(baseline['whole_round_wait4_max_rss_kib']) * D('1.10'), D(baseline['whole_round_wait4_max_rss_kib']) + D(4096)),
    }
    need(all(D(a['ratios'][k]) == v for k, v in ratios.items()), 'independently recomputed all numeric ratios')
    need(ratios['wall_candidate_over_baseline'] <= D('1.10') and ratios['cpu_candidate_upper_over_baseline_lower'] <= D('1.10') and D(candidate['whole_round_wait4_max_rss_kib']) <= ratios['rss_candidate_limit_kib'], 'three original numeric thresholds')
    need(len(a['gates']) == 6 and all(value is True for value in a['gates'].values()), 'all six original numeric gates reported true')
    need(not a['performance_adoption_authorized'] and not a['raw_wire_and_fixture_originals_independently_audited'] and not a['qualified_binary_bodies_rehashed'] and not a['qualified_source_bodies_rehashed'], 'original independent audit limitations remain explicit')
    result = {
        'schema': 'hepta-a53-small-report-field-arithmetic-audit/v1',
        'passed': True,
        'scope': 'Exact original report/evaluator/actual qualification/protocol fields and independent Decimal sums; raw fixture/wire evidence is not yet captured or independently verified by this audit.',
        'inputs': inputs, 'protocol_sha256': PROTOCOL_SHA,
        'checks': checks, 'check_count': len(checks),
        'arms': a['arms'], 'ratios': a['ratios'], 'gates': a['gates'],
        'all_purpose_counts': a['all_purpose_counts'],
        'original_controller_pids': controller_pids,
        'raw_wire_fixture_custody_audit_complete': False,
        'qualified_source_binary_bodies_rehashed_by_this_audit': False,
        'performance_adoption_authorized': False,
        'benchmark_or_remote_executions': 0,
        'required_next_evidence': 'Capture the two fixed 827-member artifact inventories and their fixed original companion files; verify all 8848 request/reply lines, 1024 authoritative records and eight original controller custody chains, plus source/ELF full-byte fences.',
        'interpretation': [
            'The fixed C1 total wall decreased about 1.055%; the observed CPU decreased about 0.951%.',
            'Conservative candidate CPU upper / baseline lower is above 1, so the CPU observation is not separated from endpoint quantization.',
            'RSS is whole-controller-lifetime wait4 peak; all A53 FD endpoints are 24 versus baseline 20, with no endpoint increase within an individual round.',
            'No saturated throughput, continuous memory/FD soak, C4, multi-host or overall adoption conclusion is supplied by this audit.',
        ],
    }
    output = DOC / 'small-report-field-audit.json'
    encoded = (json.dumps(result, indent=2, sort_keys=True) + '\n').encode()
    with output.open('xb') as handle:
        handle.write(encoded)
    print(json.dumps({'path': str(output), 'bytes': len(encoded), 'sha256': hashlib.sha256(encoded).hexdigest(), 'checks': len(checks), 'passed': True}))


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Offline field and decimal arithmetic audit; deliberately not the raw audit."""
import hashlib
import json
import math
from decimal import Decimal as D
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOC = ROOT / 'runtime-resume/docs/experiments/x230/a54'
FROZEN = ROOT / 'ci-audit/a54/frozen-r01'
PINS = {
    'small-report.original.json': (133839, '9cc15059cc1fc61fcb22a46becd6ad3868229137e9f5f48c68a2d199bfaf7ba0'),
    'small-analysis.original.json': (22087, '7d29e78fc6dbd78854fe3c5e5120475b0663865f15244459cafc1b0797a78afa'),
    'qualification-r01.original.json': (61986, '49b0019ece7405d455ace8cb638080a203a24fca01c6985a6cdda6d51180a51c'),
}
PROTOCOL_SHA = '02183d4edd86e01d309c2c2fc12b02e12c05662600a69d2220bef423d5477378'
ELFS = {'r07': '7ab8d93d00f964e7e479ee7df7d25f40ede8e364f3914d30b9fa4b7b2ff867eb',
        'A54': 'd2134c1b2b1999f46f0808b0d523ae51f54821c09afa6ecbf8188c883bbf3d70'}
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
    raw = (FROZEN / 'small-archive-a54-r01.protocol.json').read_bytes()
    need(hashlib.sha256(raw).hexdigest() == PROTOCOL_SHA, 'actual frozen protocol')
    p = json.loads(raw)
    r, a, q = [values[k] for k in PINS]
    need(r['schema'] == 'hepta-a54-small-archive-comparison/v1' and a['schema'] == 'hepta-a54-small-ordinary-report-numeric-evaluation/v1' and p['schema'] == 'hepta-a54-small-archive-comparison-protocol/v1', 'exact actual A54 schemas')
    need(r['protocol']['sha256'] == PROTOCOL_SHA and r['protocol']['bytes'] == 8542 and r['regression_gates'] == p['regression_gates'], 'original complete protocol and fixed regression policy')
    need(p['bindings_ready'] is True and p['concurrency'] == 1 and p['workers'] == 2 and p['seed_records_per_round'] == 64 and p['measured_per_round'] == 1024 and p['helper_budget_seconds'] == 300, 'original C1 worker fixture and helper budgets')
    need(p['planned_new_rounds'] == 8 and p['planned_new_measured_calls'] == r['planned_new_measured_calls'] == 8192 and p['planned_new_total_tool_calls'] == 8848, 'complete original planned counts')
    need(p['automatic_retry'] is False and type(r['automatic_retries']) is int and r['automatic_retries'] == 0 and r['product_deadlines_modified'] is False and r['ssh_or_agent_used'] is False and r['historical_call_rows_included_in_new_totals'] is False, 'no retry deadline change SSH or historical calls')
    need(r['originals_unchanged'] is True and a['all_read_inputs_unchanged_at_end'] is True, 'both original reports retain complete input fences')
    need(r['performance_adoption_claimed'] is False and r['a54_multihost_validation_performed'] is False and r['multihost_acceptance_established'] is False, 'original producer scope is unchanged')
    need(a['actual_outer_state'] == {k: r[k] for k in ('complete', 'measured_count_unknown_stages', 'observed_measured_calls', 'passed', 'phase', 'unexecuted')} | {'error': None}, 'evaluator outer-state projection equals original producer')
    need(r['driver']['sha256'] == p['frozen_native_driver_sha256'] and r['helper']['sha256'] == p['frozen_small_helper_sha256'] and r['qualification_chain_loader']['sha256'] == a['qualification_chain_validator_sha256'] == p['qualification_chain_loader_sha256'], 'original helper driver and qualification loader bindings')
    driver_raw = (FROZEN / 'run_small_archive_a54_r01.py').read_bytes()
    need(len(driver_raw) == r['confirmation_driver']['bytes'] == 26632 and hashlib.sha256(driver_raw).hexdigest() == r['confirmation_driver']['sha256'] == 'f9ddacd3113360983445ba9505942c11dd5190e2fce411815f9403c863420dc6', 'actual frozen producer bytes and reported identity')
    for kind, receipt_key, sha in [('entry', 'qualification_entry', 'a98b564f5db07c64b497b68098902192f71f7be6884e687e68b38e9e41f3e6c3'), ('worker', 'qualification_worker', 'b7ee93502f5ba0a3861e4578da8301ebac9af8ceb9e1b535ad2e5a8c6af73a90')]:
        body = (DOC / (kind + '-r01.original.json')).read_bytes()
        need(hashlib.sha256(body).hexdigest() == r[receipt_key]['sha256'] == sha and len(body) == r[receipt_key]['bytes'], 'actual original qualification ' + kind + ' binding')
    need(r['qualifications']['A54']['report']['sha256'] == PINS['qualification-r01.original.json'][1], 'actual original qualification report identity')
    chain = a['qualification_chain_verification']['A54']
    need(chain['composition_used'] is False and chain['original_successful_stages'] == 6 and all(chain[k] is True for k in ('original_qualification_worker_custody_verified', 'separate_guardian_receipt_verified', 'six_guarded_stages_and_report_binding_verified', 'six_original_qualification_admission_gates_verified')), 'reported original six-stage custody and admission verification')
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
    for arm, count in [('r07', 165), ('A54', 175)]:
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
    need(q['qualified'] and q['source_tested'] == q['source_after'] == r['final_source_maps']['A54'], 'actual A54 qualification 175 source map')
    qualified_binary = r['qualifications']['A54']['binary']
    need(all(q['binary'][key] == qualified_binary[key] for key in ['path', 'sha256', 'compiler_source']), 'actual A54 qualification path SHA and compiler source binding')
    need(q['binary']['cached'] is False and qualified_binary['fresh'] is False and qualified_binary['compiler_profile'] == {'debug_assertions': False, 'debuginfo': 0, 'opt_level': '3', 'overflow_checks': False, 'test': False}, 'reported actual release compiler profile and noncached build')
    baseline, candidate = a['arms']['r07'], a['arms']['A54']
    ratios = {
        'wall_candidate_over_baseline': D(candidate['wall_seconds']) / D(baseline['wall_seconds']),
        'cpu_observed_candidate_over_baseline': D(candidate['cpu_observed_seconds']) / D(baseline['cpu_observed_seconds']),
        'cpu_candidate_upper_over_baseline_lower': D(candidate['cpu_upper_seconds']) / D(baseline['cpu_lower_seconds']),
        'rss_candidate_limit_kib': max(D(baseline['whole_round_wait4_max_rss_kib']) * D('1.10'), D(baseline['whole_round_wait4_max_rss_kib']) + D(4096)),
    }
    need(all(D(a['ratios'][k]) == v for k, v in ratios.items()), 'independently recomputed all numeric ratios')
    need(ratios['wall_candidate_over_baseline'] <= D('1.10') and ratios['cpu_candidate_upper_over_baseline_lower'] <= D('1.10') and D(candidate['whole_round_wait4_max_rss_kib']) <= ratios['rss_candidate_limit_kib'], 'three original numeric thresholds')
    independently_recomputed_gates = {
        'both_opposite_order_blocks_complete': len(r['stages']) == 2 and all(s['status'] == 'passed' and s['actual_order'] == p['blocks'][i]['actual_order'] for i, s in enumerate(r['stages'])),
        'all_8848_reported_and_journaled_calls_correct': r['new_total_tool_calls'] == 8848 and all(s['journal_coverage_exact'] and s['observed_calls']['all_failures'] == 0 and s['observed_calls']['total'] == 4424 for s in r['stages']),
        'both_actual_arms_4096_measured': all(a['arms'][arm]['measured_calls'] == 4096 for arm in ('r07', 'A54')),
        'wall_ratio_at_most_1_10': ratios['wall_candidate_over_baseline'] <= D('1.10'),
        'cpu_candidate_upper_over_baseline_lower_at_most_1_10': ratios['cpu_candidate_upper_over_baseline_lower'] <= D('1.10'),
        'wholelife_wait4_peak_rss_guard': D(candidate['whole_round_wait4_max_rss_kib']) <= ratios['rss_candidate_limit_kib'],
    }
    need(a['gates'] == independently_recomputed_gates and len(a['gates']) == 6 and all(value is True for value in a['gates'].values()), 'all six original named gates independently recomputed from report fields')
    need(not a['performance_adoption_authorized'] and not a['raw_wire_and_fixture_originals_independently_audited'] and not a['qualified_binary_bodies_rehashed'] and not a['qualified_source_bodies_rehashed'], 'original independent audit limitations remain explicit')
    result = {
        'schema': 'hepta-a54-small-report-field-arithmetic-audit/v1',
        'passed': True,
        'scope': 'Exact original report/evaluator/actual qualification/protocol fields and independent Decimal sums; raw fixture/wire evidence is not yet captured or independently verified by this audit.',
        'inputs': inputs, 'protocol_sha256': PROTOCOL_SHA,
        'checks': checks, 'check_count': len(checks),
        'arms': a['arms'], 'ratios': a['ratios'], 'gates': a['gates'],
        'independently_recomputed_gates': independently_recomputed_gates,
        'all_purpose_counts': a['all_purpose_counts'],
        'original_controller_pids': controller_pids,
        'raw_wire_fixture_custody_audit_complete': False,
        'qualified_source_binary_bodies_rehashed_by_this_audit': False,
        'performance_adoption_authorized': False,
        'benchmark_or_remote_executions': 0,
        'required_next_evidence': 'Capture the two fixed 827-member artifact inventories and their fixed original companion files; verify all 8848 request/reply lines, 1024 authoritative records and eight original controller custody chains, plus source/ELF full-byte fences.',
        'interpretation': [
            f"The fixed C1 total wall changed by {(ratios['wall_candidate_over_baseline'] - D(1)) * D(100):.6f}%; the observed CPU changed by {(ratios['cpu_observed_candidate_over_baseline'] - D(1)) * D(100):.6f}%.",
            f"Conservative candidate CPU upper / baseline lower is {ratios['cpu_candidate_upper_over_baseline_lower']}; it is below 1 in these fixed rounds, including the original endpoint quantization margin. This is not a general statistical or saturation claim.",
            'RSS is whole-controller-lifetime wait4 peak; all A54 FD endpoints are 24 versus baseline 20, with no endpoint increase within an individual round.',
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

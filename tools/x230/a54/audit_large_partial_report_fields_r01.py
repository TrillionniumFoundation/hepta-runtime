#!/usr/bin/env python3
"""Audit the exact incomplete A54 large result without filling missing work.

Only original report fields and four SHA-pinned pure producer definitions are
read. No runtime, benchmark, transport, collector or child process is executed.
This is not the complete-workload or original-wire/fixture audit.
"""
import ast
import hashlib
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOC = ROOT / 'runtime-resume/docs/experiments/x230/a54'
FROZEN = ROOT / 'ci-audit/a54/frozen-r01'
PINS = {
    'large-report.original.json': (144184, '6cc6ba6c22db109ee10fe84a741ab88ebb2d39e53ce6233e60c70561e7a78c30'),
    'qualification-r01.original.json': (61986, '49b0019ece7405d455ace8cb638080a203a24fca01c6985a6cdda6d51180a51c'),
    'entry-r01.original.json': (59536, 'a98b564f5db07c64b497b68098902192f71f7be6884e687e68b38e9e41f3e6c3'),
    'worker-r01.original.json': (8109, 'b7ee93502f5ba0a3861e4578da8301ebac9af8ceb9e1b535ad2e5a8c6af73a90'),
}
DRIVER_SHA = '9f03083dcb6754952ea27ae531dd5f353119704257ffb56e43dcb180052eafc1'
PROTOCOL_SHA = '8f2dcc021dbfdb46317c9c28f1abd5d9b61ccb7a6601e9ae71a5d0e5946c0a3a'
MAPS = {'A': '4da4bae757abb1e31b250efb406e62fab32a6a0bd537f9642911ddf8b4d3000d',
        'B': '7d4143971feeb9b1fcbf1f3e567ba367c36770cdf050fe496b1e2778a1025176'}
ELFS = {'A': '7ab8d93d00f964e7e479ee7df7d25f40ede8e364f3914d30b9fa4b7b2ff867eb',
        'B': 'd2134c1b2b1999f46f0808b0d523ae51f54821c09afa6ecbf8188c883bbf3d70'}
ERRORS = ('archive metadata query total deadline exceeded; repeat only the metadata query',
          'archive index preparing or validation unavailable; repeat only this metadata query')
FAILURES = [5, 6, 7, 8, 9, 10, 13, 14, 15, 17, 18, 19]
REASON = 'fixed experiment not reached after setup, host, input, custody, transport or oracle failure; never retried'
checks = []


def need(value, name):
    if not value:
        raise ValueError(name)
    checks.append(name)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def exact(left, right):
    if type(left) is not type(right):
        return False
    if isinstance(right, dict):
        return left.keys() == right.keys() and all(exact(left[k], v) for k, v in right.items())
    if isinstance(right, list):
        return len(left) == len(right) and all(exact(a, b) for a, b in zip(left, right))
    return left == right


def document(raw):
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise ValueError('duplicate JSON key')
            out[key] = value
        return out
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def attempt(row, label):
    need(row['write_attempts'] == 1 and type(row['write_attempts']) is int
         and all(row[k] is True for k in ('sent', 'response_received', 'journaled', 'single_wave_os_write'))
         and row['automatic_retry'] is False, label + ': one original complete attempt')
    need(type(row['okay']) is bool and row['status'] in ('succeeded', 'product_failure')
         and row['okay'] == (row['status'] == 'succeeded'), label + ': original terminal result')
    names = ('client_pending_registered_monotonic_ns', 'start_monotonic_ns',
             'response_received_monotonic_ns', 'client_deadline_monotonic_ns')
    registered, started, ended, deadline = [row[k] for k in names]
    need(all(type(row[k]) is int and row[k] > 0 for k in names)
         and registered <= started <= ended < deadline and deadline - started == 10_000_000_000
         and row['elapsed_ms'] == (ended - started) / 1e6
         and math.isfinite(row['caller_wall_ms']) and row['caller_wall_ms'] >= row['elapsed_ms'],
         label + ': original exact 10-second client window and latency')
    need(type(row['client_pending_count_at_write']) is int
         and row['client_pending_count_at_write'] == len(row['client_pending_ids_at_write'])
         and row['server_admission_or_cohort_timing_observed'] is False, label + ': client pending scope')
    for prefix in ('request', 'response'):
        need(type(row[prefix + '_wire_offset']) is int and row[prefix + '_wire_offset'] >= 0
             and type(row[prefix + '_wire_bytes']) is int and row[prefix + '_wire_bytes'] > 0
             and len(row[prefix + '_wire_sha256']) == 64
             and all(c in '0123456789abcdef' for c in row[prefix + '_wire_sha256']), label + ': ' + prefix + ' original wire receipt')
    if row['okay']:
        need('error' not in row and 'error_type' not in row and len(row['dto_sha256']) == 64,
             label + ': successful DTO receipt retained')
    else:
        need(row['error_type'] == 'ProductFailure' and row['error'] in ERRORS and 'dto_sha256' not in row,
             label + ': original product failure retained')


def main():
    originals = {}
    for name, (size, digest) in PINS.items():
        raw = (DOC / name).read_bytes()
        need(len(raw) == size and sha(raw) == digest, name + ': exact original bytes')
        originals[name] = document(raw)
    report = originals['large-report.original.json']
    q = originals['qualification-r01.original.json']
    driver = (FROZEN / 'run_native_archive_cohort_a54_r01.py').read_bytes()
    protocol_raw = (FROZEN / 'native-archive-cohort-a54-r01.protocol.json').read_bytes()
    need(len(driver) == 83584 and sha(driver) == DRIVER_SHA, 'fixed actual driver bytes')
    need(len(protocol_raw) == 11065 and sha(protocol_raw) == PROTOCOL_SHA == report['protocol']['sha256'], 'fixed actual protocol bytes')
    protocol = document(protocol_raw)
    tree = ast.parse(driver)
    allowed = {'scope_cpu', 'summarize', 'plan_slots', 'same_fixture'}
    definitions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in allowed]
    need(len(definitions) == 4 and {n.name for n in definitions} == allowed, 'only four pinned pure definitions selected')
    ns = {'need': need, 'ORDER': ('A', 'B', 'B', 'A')}
    exec(compile(ast.Module(body=definitions, type_ignores=[]), '<fixed-pure-report-definitions>', 'exec'), ns)
    planned_slots, planned_waves = ns['plan_slots']()
    slots, waves = report['slots'], report['waves']
    need(report['schema'] == 'hepta-a54-native-archive-cohort/v1' and report['complete'] is False
         and report['passed'] is False and report['phase'] == 'failed' and report['performance_adopted'] is False,
         'actual incomplete failed outcome remains unchanged')
    need(report['errors'] == ['FatalExperiment: block failed; remaining block unexecuted']
         and report['first_termination_signal'] is None and report['stop_requested'] is False, 'actual failure and no termination signal')
    need(report['planned_measured_calls'] == len(slots) == 80 and report['planned_waves'] == len(waves) == 32
         and report['planned_real_native_seeds'] == report['planned_index_kickoffs'] == report['planned_fixed_archive_warmups'] == 4,
         'complete original planned inventory is retained')
    need(report['automatic_retries'] == report['ssh_or_agent_accesses'] == report['service_mutations'] == 0
         and all(report[k] is False for k in ('prior_results_pooled', 'A40_in_new_performance_totals',
             'production_deployed', 'optimization_exhausted_claim', 'direct_index_test_entry',
             'server_cohort_membership_observed', 'server_admission_timestamps_observed')),
         'no retries history pooling service mutation or added claims')
    need(len(report['frozen_inputs']) == 13 and report['frozen_inputs'][0]['sha256'] == PROTOCOL_SHA
         and report['frozen_inputs'][1]['sha256'] == DRIVER_SHA, 'all thirteen original frozen input receipts remain')
    for name, key in [('entry', 'qualification_entry'), ('worker', 'qualification_worker')]:
        size, digest = PINS[name + '-r01.original.json']
        need(report[key]['sha256'] == digest and report[key]['bytes'] == size, 'actual qualification ' + name + ' identity')
    need(set(report['qualifications']) == {'A', 'B'}, 'exact two qualified arm identities')
    for arm, count in [('A', 165), ('B', 175)]:
        bundle = report['qualifications'][arm]
        need(bundle['source_files'] == len(bundle['source_map']) == count
             and sha(json.dumps(bundle['source_map'], sort_keys=True, separators=(',', ':')).encode()) == MAPS[arm]
             and bundle['binary']['sha256'] == ELFS[arm], arm + ': exact qualified source map and ELF receipt')
    need(q['qualified'] is True and q['source_tested'] == q['source_after'] == report['qualifications']['B']['source_map']
         and report['qualifications']['B']['report']['sha256'] == PINS['qualification-r01.original.json'][1],
         'actual successful A54 qualification identity remains distinct from failed large workload')
    fixed_keys = ('slot', 'controller', 'block', 'arm', 'wave', 'position', 'query_variant', 'concurrency', 'purpose', 'tool', 'automatic_retry')
    for row, plan in zip(slots, planned_slots):
        label = 'slot ' + str(plan['slot'])
        need(all(exact(row[k], plan[k]) for k in fixed_keys), label + ': original fixed identity')
        if plan['slot'] < 20:
            attempt(row, label)
            expected_ids = [row['rpc_id']] if row['concurrency'] == 1 else list(range(9 + (row['wave'] - 4) * 4, 13 + (row['wave'] - 4) * 4))
            need(row['rpc_id'] == row['slot'] + 5 and row['client_pending_ids_at_write'] == expected_ids,
                 label + ': exact original fixed RPC pending membership')
        else:
            need(exact(row, dict(plan, unexecuted_reason=REASON)), label + ': exact unexecuted original with no invented observation')
    need(report['observed_measured_write_attempts'] == sum(s['write_attempts'] for s in slots) == 20
         and report['observed_measured_successes'] == sum(s['okay'] for s in slots) == 8
         and [s['slot'] for s in slots if s['status'] == 'product_failure'] == FAILURES
         and report['unexecuted_measured_slots'] == [s['slot'] for s in slots if s['status'] == 'unexecuted'] == list(range(20, 80)),
         'all 20 attempts eight successes twelve failures and sixty unexecuted slots accounted exactly')
    for number, (wave, plan) in enumerate(zip(waves, planned_waves)):
        need(all(exact(wave[k], plan[k]) for k in ('controller', 'block', 'arm', 'wave', 'concurrency', 'slot_ids')),
             'wave %d: fixed original schedule' % number)
        rows = [slots[i] for i in wave['slot_ids']]
        if number < 8:
            need(wave['attempted'] == wave['concurrency'] == len(rows)
                 and wave['successes'] == sum(row['okay'] for row in rows)
                 and wave['failures'] == sum(not row['okay'] for row in rows)
                 and wave['fatal'] is False and wave['status'] == ('complete_with_failures' if wave['failures'] else 'succeeded')
                 and wave['client_pending_ids_at_write'] == [row['rpc_id'] for row in rows],
                 'wave %d: all actual responses and original failure costs retained' % number)
        else:
            need(exact(wave, dict(plan, original_write_attempts=0)), 'wave %d: exact unexecuted original wave' % number)
    need([c['index'] for c in report['controllers']] == [0, 1] and [c['arm'] for c in report['controllers']] == ['A', 'B'],
         'only two actually started controllers exist')
    controller_summaries, setup_failures = [], []
    for index, controller in enumerate(report['controllers']):
        label = 'controller ' + str(index)
        need(controller['status'] == ('complete' if index == 0 else 'failed')
             and controller['errors'] == ([] if index == 0 else [{'where': 'controller', 'error': 'FatalExperiment: one fixed archive warmup failed; no readiness retry'}]), label + ': exact original terminal state')
        need(controller['release_sha256'] == ELFS[controller['arm']]
             and controller['candidate_cohort_instrumentation_claimed'] is False, label + ': actual qualified arm and observation scope')
        need([s['purpose'] for s in controller['setup']] == ['native_seed', 'index_kickoff', 'archive_warmup'], label + ': exactly three fixed setup attempts')
        for rpc_id, row in enumerate(controller['setup'], 2):
            attempt(row, label + ' setup ' + row['purpose'])
            need(row['controller'] == index and row['arm'] == controller['arm'] and row['rpc_id'] == rpc_id
                 and row['client_pending_ids_at_write'] == [rpc_id], label + ': exact setup identity')
            if not row['okay']:
                setup_failures.append(row)
        need([s['okay'] for s in controller['setup']] == ([True, False, True] if index == 0 else [True, False, False])
             and controller['setup_requests_all_succeeded'] is False, label + ': all original setup outcomes retained')
        idle = controller['fixed_idle']
        need(idle['planned_seconds'] == 60 and idle['elapsed_seconds'] >= 60
             and idle['end_monotonic_ns'] - idle['start_monotonic_ns'] >= 60_000_000_000
             and idle['polls'] == idle['queries_during_idle'] == 0, label + ': original fixed unpolled idle')
        initial = controller['fixture_after_generation']
        need(initial['counts'] == {'archive': 65536, 'hot': 512}
             and ns['same_fixture'](initial, controller['fixture_after_shutdown'])
             and controller['original_fixture_unchanged'] is True, label + ': complete reported original fixture final fence')
        shutdown, startup = controller['shutdown'], controller['startup']
        waited = shutdown['waited']
        need(startup['only_owned_controller_started'] is True and type(startup['pid']) is int and startup['pid'] > 1
             and waited['pid'] == startup['pid'] and type(waited['exit_code']) is int and waited['exit_code'] == 0
             and shutdown['original_child_reaped'] is True and shutdown['method'] == 'stdin_eof'
             and shutdown['errors'] == shutdown['unmatched'] == shutdown['protocol_violations'] == []
             and shutdown['reader_error'] is None and shutdown['first_termination_signal'] is None,
             label + ': reported original wait4 and clean EOF shutdown')
        need(shutdown['raw_stdout_eof_captured'] is True and shutdown['reader_stop']['eof_observed'] is True
             and shutdown['reader_stop']['outstanding_original_rpc_ids'] == []
             and shutdown['received_response_ids'] == list(range(1, 25 if index == 0 else 5)),
             label + ': all actually sent RPC IDs and EOF accounted')
        need(waited['total_cpu_seconds'] == waited['user_cpu_seconds'] + waited['system_cpu_seconds']
             and waited['total_cpu_seconds'] > 0 and type(waited['max_rss_kib']) is int and waited['max_rss_kib'] > 0,
             label + ': all original wholelife CPU and peak RSS retained')
        if index == 0:
            need(controller['host_before_measured_clear'] is True and controller['performance_errors_retained'] == 12
                 and ns['same_fixture'](initial, controller['fixture_before_measurement'])
                 and ns['same_fixture'](initial, controller['fixture_after_measurement']), label + ': actual measured fixture and host fields')
            for key, value in {
                'c1_process_cpu': ns['scope_cpu'](controller['process_before_c1'], controller['process_before_c4']),
                'c4_response_window_process_cpu': ns['scope_cpu'](controller['process_before_c4'], controller['process_after_c4_responses']),
                'c4_inclusive_cpu': ns['scope_cpu'](controller['process_before_c4'], waited=waited),
                'all_measured_plus_tail_cpu': ns['scope_cpu'](controller['process_before_c1'], waited=waited),
            }.items():
                need(exact(controller[key], value), label + ': independently recomputed ' + key)
        else:
            need(controller['performance_errors_retained'] == 0 and all(k not in controller for k in (
                'fixture_before_measurement', 'fixture_after_measurement', 'host_before_measured', 'host_before_measured_clear',
                'process_before_c1', 'process_before_c4', 'process_after_c4_responses', 'c1_process_cpu',
                'c4_response_window_process_cpu', 'c4_inclusive_cpu', 'all_measured_plus_tail_cpu')),
                label + ': preparation failure has no invented measured CPU fixture or host observations')
        controller_summaries.append({'controller': index, 'arm': controller['arm'], 'status': controller['status'],
            'measured_attempts': sum(s['write_attempts'] for s in slots if s['controller'] == index),
            'setup_attempts': 3, 'original_wait4': waited, 'actual_response_ids': shutdown['received_response_ids'],
            'wholelife_counters_are_not_query_phase_attribution': True})
    need(len(setup_failures) == 3 and [s['purpose'] for s in setup_failures] == ['index_kickoff', 'index_kickoff', 'archive_warmup']
         and all(s['error'] == ERRORS[0] for s in setup_failures), 'both kickoffs and the actual candidate warmup deadline failures retained')
    need(len(report['original_controller_custody_adapter']) == 2, 'two original custody adapter receipts')
    for index, custody in enumerate(report['original_controller_custody_adapter']):
        need(custody['controller'] == index and custody['arm'] == ('A', 'B')[index] and custody['fallback_used'] is False
             and all(custody[k] is True for k in ('close_attempted', 'close_attempted_before_fallback', 'close_returned',
                 'original_child_reaped', 'original_child_reaped_before_fallback', 'original_child_started', 'shutdown_receipt_present')),
             'controller %d: original once-only custody completed without fallback' % index)
    need(len(report['blocks']) == 1 and report['blocks'][0]['index'] == 0
         and report['blocks'][0]['controllers'] == [0, 1] and report['blocks'][0]['status'] == 'failed'
         and report['blocks'][0]['host_before_clear'] is True and report['blocks'][0]['host_after_clear'] is True
         and report['blocks'][0]['qualified_inputs_unchanged'] is True,
         'one failed original block retains its observed host and source postchecks')
    recalculated = ns['summarize'](report, slots, waves)
    need(exact(recalculated, report['analysis']), 'complete partial analysis exactly recomputed with unchanged fixed summarizer')
    need(len(recalculated['numeric_gates']) == 16 and all(v is False for v in recalculated['numeric_gates'].values())
         and recalculated['candidate_performance_gates_passed'] is False
         and all(v is None for v in recalculated['ratios'].values()), 'all original sixteen gates fail and comparison ratios remain undefined')
    need(all(mode['cpu'] is None for arm in recalculated['arms'].values() for mode in arm['modes'].values()),
         'incomplete arm CPU aggregation is not reconstructed from one controller')
    result = {'schema': 'hepta-a54-large-partial-failure-report-field-audit/v1', 'passed': True,
        'scope': 'Integrity and arithmetic of the exact original incomplete report; the complete 80-call/32-wave performance gate remains failed. No raw wire or fixture body audit is supplied.',
        'original_report': {'bytes': PINS['large-report.original.json'][0], 'sha256': PINS['large-report.original.json'][1]},
        'driver_sha256': DRIVER_SHA, 'protocol_sha256': PROTOCOL_SHA,
        'checks': checks, 'check_count': len(checks), 'complete_original_workload': False,
        'original_performance_passed': False, 'performance_adoption_authorized': False,
        'raw_wire_fixture_independent_audit_complete': False, 'benchmark_or_remote_executions': 0,
        'planned_measured_calls': 80, 'planned_waves': 32, 'actual_measured_attempts': 20,
        'actual_measured_successes': 8, 'actual_measured_product_failures': 12, 'unexecuted_measured_slots': list(range(20, 80)),
        'actual_setup_attempts': 6, 'actual_tool_attempts_including_setup': 26,
        'actual_rpc_requests_including_initialize': 28, 'actual_initialized_notifications': 2,
        'actually_started_controllers': controller_summaries, 'setup_product_failures': setup_failures,
        'all_actual_measured_failure_slots': [s for s in slots if s['status'] == 'product_failure'],
        'candidate_measured_attempts': 0, 'candidate_warmup_failure': report['controllers'][1]['setup'][2],
        'analysis': recalculated,
        'interpretation': ['Candidate controller 1 failed its single fixed archive warmup with the original three-second total-deadline product error after the fixed unpolled 60-second idle.',
            'No candidate C1 or C4 measured request was attempted. The remaining 60 original planned slots are unexecuted; no comparison or performance improvement is inferred.',
            'Both actual original controller wait4 receipts, clean EOF states, all setup failures, all 12 baseline measured failures and their costs remain retained.',
            'The report fields do not identify which internal scan or I/O phase consumed the candidate warmup deadline. Wholelife wait4 I/O and CPU are not phase attribution.',
            'The existing complete-workload auditor and its original 80-call/32-wave admission remain unchanged and reject this incomplete result.']}
    out = DOC / 'large-partial-report-field-audit.json'
    encoded = (json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()
    with out.open('xb') as stream:
        stream.write(encoded)
    print(json.dumps({'path': str(out), 'bytes': len(encoded), 'sha256': sha(encoded), 'checks': len(checks),
                      'audit_passed': True, 'original_performance_passed': False, 'original_workload_complete': False}))


if __name__ == '__main__':
    main()

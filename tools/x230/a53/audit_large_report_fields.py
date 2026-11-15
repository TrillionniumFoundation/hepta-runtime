#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Recompute every fixed A53 large slot/wave/CPU/gate from the actual report.

This is a report-field audit, explicitly separate from the full original
wire/fixture body audit. It never executes the driver, benchmark or runtime.
"""
import ast
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOC = ROOT / 'runtime-resume/docs/experiments/x230/a53'
FROZEN = ROOT / 'ci-audit/a53-r02/frozen-r01'
REPORT_SHA = 'ca0e32f9fda71643c12e99d1aed0b604d858af726217d5862d4054e34ab573bf'
DRIVER_SHA = '0ec4a7a9f4d0121262c1a4c7ce2fff6e8632b0be5e3d3a666a852e185b28c0c2'
PROTOCOL_SHA = '6bf7b83fb32318f3ac1df3f2abd4f0db868a007bc576ad8e0f78cd4da62e8215'
checks = []


def need(value, message):
    if not value:
        raise ValueError(message)
    checks.append(message)


def main():
    raw = (DOC / 'large-report.original.json').read_bytes()
    need(len(raw) == 251642 and hashlib.sha256(raw).hexdigest() == REPORT_SHA, 'actual complete failed report identity')
    report = json.loads(raw)
    driver_raw = (FROZEN / 'run_native_archive_cohort_a53_r01.py').read_bytes()
    need(hashlib.sha256(driver_raw).hexdigest() == DRIVER_SHA, 'actual frozen large driver identity')
    protocol_raw = (FROZEN / 'native-archive-cohort-a53-r01.protocol.json').read_bytes()
    need(hashlib.sha256(protocol_raw).hexdigest() == PROTOCOL_SHA == report['protocol']['sha256'], 'actual frozen protocol identity')
    tree = ast.parse(driver_raw)
    allowed = {'scope_cpu', 'summarize', 'plan_slots', 'same_fixture'}
    definitions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in allowed]
    need({node.name for node in definitions} == allowed and len(definitions) == 4, 'exact four pure definitions selected')
    namespace = {'need': need, 'ORDER': ('A', 'B', 'B', 'A')}
    exec(compile(ast.Module(body=definitions, type_ignores=[]), '<fixed-pure-large-report-definitions>', 'exec'), namespace)
    planned_slots, planned_waves = namespace['plan_slots']()
    slots, waves = report['slots'], report['waves']
    need(report['complete'] is True and report['passed'] is False and report['performance_adopted'] is False
         and report['errors'] == [] and report['unexecuted_measured_slots'] == []
         and report['observed_measured_write_attempts'] == 80 and report['observed_measured_successes'] == 54,
         'complete 80-attempt failed experiment retained')
    need(len(slots) == 80 and len(waves) == 32 and len(report['controllers']) == 4, 'all fixed slots waves controllers retained')
    for actual, planned in zip(slots, planned_slots):
        keys = ['slot', 'controller', 'block', 'arm', 'wave', 'position', 'query_variant', 'concurrency', 'purpose', 'tool', 'automatic_retry']
        need(all(actual[key] == planned[key] for key in keys), 'slot %d fixed identity and schedule' % actual['slot'])
        need(actual['write_attempts'] == 1 and actual['sent'] is True and actual['response_received'] is True
             and actual['journaled'] is True and actual['single_wave_os_write'] is True
             and actual['status'] in ('succeeded', 'product_failure')
             and actual['okay'] == (actual['status'] == 'succeeded'), 'slot %d once-only complete response' % actual['slot'])
        need(actual['client_deadline_monotonic_ns'] - actual['start_monotonic_ns'] == 10_000_000_000
             and actual['response_received_monotonic_ns'] < actual['client_deadline_monotonic_ns'], 'slot %d original client deadline and response' % actual['slot'])
        need(actual['elapsed_ms'] == (actual['response_received_monotonic_ns'] - actual['start_monotonic_ns']) / 1e6, 'slot %d original complete-line latency' % actual['slot'])
        current = report['controllers'][actual['controller']]
        query = current['queries'][actual['query_variant']]
        need(actual['arguments'] == query['arguments'] and actual['query_name'] == query['name'], 'slot %d original query/cursor' % actual['slot'])
        if not actual['okay']:
            need(actual['error_type'] == 'ProductFailure' and type(actual['error']) is str and actual['error'], 'slot %d retained actual product failure text' % actual['slot'])
    for actual, planned in zip(waves, planned_waves):
        keys = ['controller', 'block', 'arm', 'wave', 'concurrency', 'slot_ids']
        name = 'wave %d/%d' % (actual['controller'], actual['wave'])
        need(all(actual[key] == planned[key] for key in keys), name + ' fixed inventory')
        rows = [slots[key] for key in planned['slot_ids']]
        need(actual['attempted'] == len(rows) and actual['successes'] == sum(row['okay'] for row in rows)
             and actual['failures'] == sum(not row['okay'] for row in rows), name + ' all success/failure counts')
        need(actual['all_original_wave_replies_received'] is True and actual['fatal'] is False
             and actual['protocol_violations'] == [] and actual['terminal_transport_unknown_slot_ids'] == [], name + ' complete original replies')
        ids = [row['rpc_id'] for row in rows]
        need(len(set(ids)) == len(rows) == actual['client_pending_count_at_write'] == actual['concurrency']
             and actual['client_pending_ids_at_write'] == ids
             and all(row['client_pending_ids_at_write'] == ids and row['client_pending_count_at_write'] == len(rows) for row in rows), name + ' actual pending set')
        need(actual['wall_seconds'] == (actual['end_monotonic_ns'] - actual['start_monotonic_ns']) / 1e9, name + ' complete wave wall cost')
    pids = set()
    setup_failures = []
    for index, current in enumerate(report['controllers']):
        prefix = 'controller %d' % index
        need(current['index'] == index and current['arm'] == ('A', 'B', 'B', 'A')[index]
             and current['status'] == 'complete' and current['errors'] == [] and current['original_fixture_unchanged'] is True, prefix + ' complete original round')
        need(current['fixed_idle']['planned_seconds'] == 60 and current['fixed_idle']['elapsed_seconds'] >= 60
             and current['fixed_idle']['polls'] == current['fixed_idle']['queries_during_idle'] == 0, prefix + ' fixed unpolled idle')
        initial = current['fixture_after_generation']
        for label in ['fixture_before_measurement', 'fixture_after_measurement', 'fixture_after_shutdown']:
            need(namespace['same_fixture'](initial, current[label]) and current[label]['complete_record_body_reads'] == 66048, prefix + ' reported ' + label + ' equality')
        need(initial['counts'] == {'archive': 65536, 'hot': 512} and initial['complete_record_body_reads'] == 66048, prefix + ' full original fixture count')
        startup, shutdown = current['startup'], current['shutdown']
        waited = shutdown['waited']
        need(startup['pid'] not in pids and waited['pid'] == startup['pid'] > 1 and waited['exit_code'] == 0
             and shutdown['original_child_reaped'] is True and shutdown['method'] == 'stdin_eof'
             and shutdown['errors'] == [] and shutdown['reader_error'] is None and shutdown['unmatched'] == []
             and shutdown['raw_stdout_eof_captured'] is True and shutdown['protocol_violations'] == [], prefix + ' original wait4 and stdout EOF')
        pids.add(startup['pid'])
        need(shutdown['received_response_ids'] == list(range(1, 25))
             and shutdown['reader_stop']['outstanding_original_rpc_ids'] == [], prefix + ' all 24 original RPC IDs')
        for endpoint in ['process_before_c1', 'process_before_c4', 'process_after_c4_responses']:
            point = current[endpoint]
            need(point['pid'] == startup['pid'] and point['birth_ticks'] == startup['birth_ticks']
                 and point['cpu_ticks'] == point['utime_ticks'] + point['stime_ticks']
                 and point['cpu_seconds'] == point['cpu_ticks'] / point['cpu_tick_hz'], prefix + ' actual CPU endpoint ' + endpoint)
        need(current['c1_process_cpu'] == namespace['scope_cpu'](current['process_before_c1'], current['process_before_c4']), prefix + ' exact C1 CPU interval')
        need(current['c4_inclusive_cpu'] == namespace['scope_cpu'](current['process_before_c4'], waited=waited), prefix + ' exact inclusive C4 CPU interval')
        need(current['c4_response_window_process_cpu'] == namespace['scope_cpu'](current['process_before_c4'], current['process_after_c4_responses']), prefix + ' exact C4 response CPU interval')
        need(current['all_measured_plus_tail_cpu'] == namespace['scope_cpu'](current['process_before_c1'], waited=waited), prefix + ' exact all-measured-plus-tail CPU interval')
        setup = current['setup']
        need(len(setup) == 3 and [row['purpose'] for row in setup] == ['native_seed', 'index_kickoff', 'archive_warmup']
             and [row['rpc_id'] for row in setup] == [2, 3, 4] and setup[0]['okay'] is True and setup[2]['okay'] is True
             and all(row['write_attempts'] == 1 and row['response_received'] is True for row in setup), prefix + ' exactly original seed kickoff warmup')
        setup_failures += [{'controller': index, **row} for row in setup if not row['okay']]
        need(current['release_sha256'] == report['qualifications'][current['arm']]['binary']['sha256']
             and startup['argv'][0] == report['qualifications'][current['arm']]['binary']['path'], prefix + ' actual qualified ELF binding')
    recalculated = namespace['summarize'](report, slots, waves)
    need(recalculated == report['analysis'], 'all original aggregate costs and sixteen gates exactly recomputed')
    need(len(recalculated['numeric_gates']) == 16 and [key for key, value in recalculated['numeric_gates'].items() if not value] == ['candidate_c4_32_correct'], 'exactly one original numeric gate failed')
    need(len(setup_failures) == 4 and all(row['purpose'] == 'index_kickoff' and row['status'] == 'product_failure' for row in setup_failures), 'all four original kickoff failures retained separately')
    candidate_failures = [row for row in slots if row['arm'] == 'B' and not row['okay']]
    need([row['slot'] for row in candidate_failures] == [53, 54], 'two exact candidate failed slots retained')
    need(all(row['error'] == 'archive metadata query total deadline exceeded; repeat only the metadata query' for row in candidate_failures), 'candidate original product total-deadline error text')
    output = {'schema': 'hepta-a53-large-report-field-audit/v1', 'passed': True,
              'scope': 'Complete actual report-field schedule, original process receipt, CPU interval and 16-gate recomputation. Full raw wire/fixture bytes not yet captured.',
              'original_report': {'bytes': len(raw), 'sha256': REPORT_SHA}, 'driver_sha256': DRIVER_SHA,
              'protocol_sha256': PROTOCOL_SHA, 'checks': checks, 'check_count': len(checks),
              'benchmark_or_runtime_executions': 0, 'complete_original_workload': True,
              'original_performance_passed': False, 'performance_adoption_authorized': False,
              'raw_wire_fixture_independent_audit_complete': False,
              'analysis': recalculated, 'candidate_failure_slots': candidate_failures,
              'all_measured_failure_slots': [row['slot'] for row in slots if not row['okay']],
              'setup_product_failures': setup_failures,
              'failure_wave': [row for row in waves if row['controller'] == 2 and row['wave'] == 6],
              'failure_wave_all_original_slots': [row for row in slots if row['controller'] == 2 and row['wave'] == 6],
              'interpretation': ['All 80 once-only writes and 32 client waves are included; no successful subset replaces the failed experiment.',
                                 'Candidate failures are two server product deadline responses near 3003 ms, within the original 10 s client window.',
                                 'Client pending membership does not reveal server cohort membership or admission timing; root cause is not established by these rows.',
                                 'Four original kickoff product failures are retained; the fixed setup policy allows the declared kickoff failure and still requires the one warmup to succeed.',
                                 'C4 CPU is inclusive through original wait4, including remaining work, final verification and shutdown; RSS is wholelife peak.']}
    encoded = (json.dumps(output, indent=2, sort_keys=True) + '\n').encode()
    path = DOC / 'large-report-field-audit.json'
    with path.open('xb') as stream:
        stream.write(encoded)
    print(json.dumps({'path': str(path), 'bytes': len(encoded), 'sha256': hashlib.sha256(encoded).hexdigest(), 'checks': len(checks), 'audit_passed': True, 'performance_passed': False}))


if __name__ == '__main__':
    main()

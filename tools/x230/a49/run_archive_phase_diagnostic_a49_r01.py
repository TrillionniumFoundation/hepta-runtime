#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""A49: one A48 candidate controller, with existing archive timing enabled.

Preparation artifact. Never call the old A48 main or its ABBA summarizer. Require
an independently reviewed, finished A48 report SHA on the command line. This
diagnostic neither retries an A48 slot nor replaces or pools its measurements.
"""

import argparse
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import time
import types


BASE = Path('/home/qian/hepta-runtime-optimization-20261023/a41-phase-timing-20261025-r01')
OUT = BASE / 'a49-archive-phase-diagnostic-r01'
REFERENCE = BASE / 'tools/run_native_archive_cohort_a48_r01.py'
REFERENCE_SHA = 'f286a0200f1db34bba2ca0c68db8fa999193912ef9a7d0241304e1bfe118d1fe'
REFERENCE_BYTES = 73576
REFERENCE_PROTOCOL = BASE / 'tools/native-archive-cohort-a48-r01.protocol.json'
REFERENCE_PROTOCOL_SHA = '5a3c8e814b3614d1c6729d474a38571e517ef0bc603690a104288576ca3afd8e'
PROTOCOL_SHA = '542a5ff01d2a580d1fd50b369fae39e79fd6ac2d8d76e4bcf1e18ff4ddcae52d'
PRIOR_REPORT = BASE / 'a48-native-archive-cohort-r01/report.json'
WORK_SECONDS = 600
OUTER_SECONDS = 900
INDEX, ARM = 1, 'B'
TRACE_KEY, TRACE_VALUE = 'HEPTA_ARCHIVE_INDEX_TRACE', '1'
BASE_ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'SHELL': '/bin/sh',
            'TOKIO_WORKER_THREADS': '2', 'RUST_LOG': 'warn'}
HEX = re.compile(r'[0-9a-f]{64}\Z')


def require(value, message):
    if not value:
        raise RuntimeError(message)


def load_reference():
    """Read one pinned direct regular file before executing its definitions."""
    require(REFERENCE.resolve(strict=True) == REFERENCE, 'reference path is not direct')
    fd = os.open(REFERENCE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_size == REFERENCE_BYTES, 'reference file size/type differs')
        parts, count = [], 0
        while count <= REFERENCE_BYTES:
            block = os.read(fd, REFERENCE_BYTES + 1 - count)
            if not block:
                break
            parts.append(block)
            count += len(block)
        raw = b''.join(parts)
        identity = lambda value: [value.st_dev, value.st_ino, value.st_mode,
            value.st_uid, value.st_gid, value.st_nlink, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns]
        require(identity(before) == identity(os.fstat(fd)) == identity(REFERENCE.lstat())
                and len(raw) == REFERENCE_BYTES
                and hashlib.sha256(raw).hexdigest() == REFERENCE_SHA,
                'reference bytes/identity changed')
    finally:
        os.close(fd)
    module = types.ModuleType('frozen_a48_for_a49_diagnostic')
    module.__file__ = str(REFERENCE)
    exec(compile(raw, str(REFERENCE), 'exec'), module.__dict__)
    receipt = {'path': str(REFERENCE), 'bytes': len(raw), 'sha256': REFERENCE_SHA,
               'identity': identity(before)}
    require(module.bytes_receipt(REFERENCE) == receipt, 'reference changed after definition load')
    return module, receipt, raw


def trace_controller(h, raw, small):
    """Only the exact fixed start() env literal changes; retain all other AST."""
    tree = ast.parse(raw, filename=str(REFERENCE))
    definitions = {node.name: node for node in tree.body
                   if isinstance(node, (ast.FunctionDef, ast.ClassDef))}
    original = definitions['controller_type']
    changed = copy.deepcopy(original)
    classes = [node for node in changed.body if isinstance(node, ast.ClassDef)]
    require(len(classes) == 1 and classes[0].name == 'NativeController', 'controller class shape differs')
    starts = [node for node in classes[0].body
              if isinstance(node, ast.FunctionDef) and node.name == 'start']
    require(len(starts) == 1, 'start definition ambiguous')
    assignments = [node for node in starts[0].body if isinstance(node, ast.Assign)
                   and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                   and node.targets[0].id == 'env']
    require(len(assignments) == 1 and isinstance(assignments[0].value, ast.Dict)
            and ast.literal_eval(assignments[0].value) == BASE_ENV,
            'the original fixed runtime environment differs')
    value = assignments[0].value
    value.keys.append(ast.Constant(TRACE_KEY))
    value.values.append(ast.Constant(TRACE_VALUE))
    normalized = copy.deepcopy(changed)
    normalized_start = next(node for node in normalized.body[0].body
                            if isinstance(node, ast.FunctionDef) and node.name == 'start')
    normalized_env = next(node.value for node in normalized_start.body
                          if isinstance(node, ast.Assign) and len(node.targets) == 1
                          and isinstance(node.targets[0], ast.Name) and node.targets[0].id == 'env')
    require(ast.literal_eval(normalized_env) == {**BASE_ENV, TRACE_KEY: TRACE_VALUE},
            'unexpected trace environment change')
    normalized_env.keys.pop()
    normalized_env.values.pop()
    dump = lambda node: ast.dump(node, include_attributes=False)
    require(dump(normalized) == dump(original), 'change extends beyond the one environment entry')
    preserved = {name: getattr(h, name) for name in definitions if name != 'controller_type'}
    replacement = ast.fix_missing_locations(ast.Module(body=[changed], type_ignores=[]))
    exec(compile(replacement, str(REFERENCE) + ':a49-trace-env-only', 'exec'), h.__dict__)
    require(all(getattr(h, name) is value for name, value in preserved.items()),
            'an original helper was rebound unexpectedly')
    proof = {'schema': 'hepta-a49-trace-binding/v1', 'reference_sha256': REFERENCE_SHA,
             'environment_before': BASE_ENV, 'environment_after': {**BASE_ENV, TRACE_KEY: TRACE_VALUE},
             'only_runtime_environment_entry_added': True,
             'controller_type_ast_sha256_before': h.sha(dump(original).encode()),
             'controller_type_ast_sha256_after': h.sha(dump(changed).encode()),
             'all_other_definition_objects_retained': True,
             'unchanged_definition_ast_sha256': {name: h.sha(dump(node).encode())
                 for name, node in definitions.items() if name != 'controller_type'},
             'original_main_called': False, 'original_summarize_called': False}
    return h.controller_type(small), proof


def finished_prior(h, expected_sha, slots, waves):
    receipt, raw = h.bytes_receipt(PRIOR_REPORT, maximum=16 * 1024 * 1024, keep=True)
    h.need(receipt['sha256'] == expected_sha, 'reviewed terminal A48 report SHA differs')
    value = h.document(raw)
    h.need(value.get('schema') == 'hepta-a48-native-archive-cohort/v1'
           and value.get('phase') in ('complete', 'failed')
           and isinstance(value.get('finished_utc'), str)
           and value.get('protocol', {}).get('sha256') == REFERENCE_PROTOCOL_SHA,
           'A48 prior report is not final and bound to the original protocol')
    old_slots, old_waves = value.get('slots'), value.get('waves')
    h.need(isinstance(old_slots, list) and len(old_slots) == 80
           and isinstance(old_waves, list) and len(old_waves) == 32,
           'A48 terminal inventory is incomplete')
    keys = ('slot', 'controller', 'block', 'arm', 'wave', 'position', 'query_variant',
            'concurrency', 'purpose', 'tool', 'automatic_retry')
    for old, planned in zip(old_slots, slots):
        h.need(all(old.get(key) == planned[key] for key in keys)
               and old.get('write_attempts') in (0, 1)
               and old.get('status') in ('succeeded', 'product_failure', 'validation_failure',
                                          'transport_failure', 'interrupted_unknown', 'unexecuted'),
               'A48 terminal slot differs from its frozen once-only plan')
        if old['status'] == 'unexecuted':
            h.need(old['write_attempts'] == 0 and bool(old.get('unexecuted_reason')),
                   'A48 unexecuted outcome has no final reason')
        else:
            h.need(old['write_attempts'] == 1, 'A48 terminal attempted outcome lacks its once-only write')
    for old, planned in zip(old_waves, waves):
        h.need(all(old.get(key) == planned[key]
                   for key in ('controller', 'block', 'arm', 'wave', 'concurrency', 'slot_ids'))
               and old.get('status') in ('succeeded', 'complete_with_failures',
                                          'interrupted_unknown', 'unexecuted'),
               'A48 wave is not terminal or differs from the original plan')
    controllers = value.get('controllers')
    h.need(isinstance(controllers, list), 'A48 terminal controller inventory missing')
    for controller in controllers:
        if controller.get('startup', {}).get('only_owned_controller_started'):
            shutdown = controller.get('shutdown', {})
            h.need(shutdown.get('original_child_reaped') is True and shutdown.get('waited') is not None,
                   'A48 original child completion is unknown; no diagnostic may start')
    summary = {'report': receipt, 'phase': value['phase'], 'finished_utc': value['finished_utc'],
               'complete': value.get('complete'), 'passed': value.get('passed'),
               'measured_write_attempts': value.get('observed_measured_write_attempts'),
               'measured_successes': value.get('observed_measured_successes'),
               'result_replaced_or_pooled': False, 'reviewed_terminal_sha_cli_required': True}
    return receipt, raw, summary


def load_candidate(h, protocol, native, chain, out, inputs, report):
    entry_receipt, entry_raw = h.bytes_receipt(h.ENTRY_PATH, maximum=1024 * 1024, keep=True)
    worker_receipt, worker_raw = h.bytes_receipt(h.WORKER_PATH, maximum=1024 * 1024, keep=True)
    h.need(entry_receipt['sha256'] == h.ENTRY_SHA and worker_receipt['sha256'] == h.WORKER_SHA
           and len(entry_raw) == h.ENTRY_BYTES and len(worker_raw) == h.WORKER_BYTES,
           'original A48 guardian pin differs')
    entry, worker = h.document(entry_raw), h.document(worker_raw)
    h.need(entry['schema'] == h.ENTRY_SCHEMA and entry['qualified'] is True
           and entry['passed'] is True and entry['guarded_qualification_complete'] is True
           and entry['parent_unchanged_after_attempt'] is True
           and entry['reused_dependencies_unchanged'] is True
           and not entry.get('error') and not entry.get('errors'), 'A48 guardian incomplete')
    h.need(worker['schema'] == h.WORKER_SCHEMA and worker['passed'] is True
           and worker['strict_fresh_artifacts_verified'] is True
           and worker['required_test_coverage_verified'] is True
           and worker['reused_dependencies_unchanged'] is True
           and not worker.get('error') and not worker.get('errors'), 'A48 worker incomplete')
    custody = entry['worker_custody']
    h.need(custody.get('original_child_reaped') is True and custody.get('raw_wait_status') == 0
           and custody.get('custody_retained_until_reap') is True,
           'A48 qualification original worker custody incomplete')
    inputs.extend((entry_receipt, worker_receipt))
    h.create(out / 'qualification-entry.original.json', entry_raw)
    h.create(out / 'qualification-worker.original.json', worker_raw)
    report['qualification_entry'], report['qualification_worker'] = entry_receipt, worker_receipt
    binding = protocol['bindings']['B']
    path = h.direct(Path(binding['qualification_path']))
    pinned, qualified_raw = h.bytes_receipt(path, keep=True)
    h.need(pinned['sha256'] == binding['qualification_sha256'], 'A48 qualification pin differs')
    bundle = chain.load_qualification(native, path, 'B', out)
    compact = json.dumps(bundle['source_map'], sort_keys=True, separators=(',', ':')).encode()
    h.need(bundle['qualification_schema'] == binding['qualification_schema']
           and bundle['source_files'] == binding['source_files'] == 168
           and h.sha(compact) == binding['source_map_compact_sha256']
           and bundle['binary']['sha256'] == binding['release_sha256']
           and bundle['binary']['fresh'] is False and bundle['test_binary']['fresh'] is False,
           'A48 qualified source/release differs')
    h.need(not out.is_relative_to(Path(bundle['source'])), 'fixture would change qualified source')
    bundle['version'] = binding['version']
    h.need(chain.same_receipt(pinned, bundle['report']), 'qualification receipt changed during load')
    prepared = h.document(qualified_raw)['source_input']
    h.need(set(prepared) == set(bundle['source_map'])
           and chain.map_sha(prepared) == binding['prepared_source_map_compact_sha256'],
           'A48 prepared source map differs')
    for ref in (entry['qualification_report'], worker['qualifier_report'],
                worker['strict_fresh_artifact_evidence']['qualification_report']):
        h.need(chain.same_receipt(ref, bundle['report']), 'guardian qualification receipt differs')
    h.need(chain.same_receipt(entry['guarded_worker_report'], worker_receipt)
           and ('worker_report' not in entry or chain.same_receipt(entry['worker_report'], worker_receipt))
           and entry['source_after'] == bundle['source_map'], 'guardian/source/worker binding differs')
    return bundle


def capture_trace(h, out, controllers):
    """Post-reap only; raw stderr remains authoritative, with no per-RPC guess."""
    h.need(len(controllers) == 1 and controllers[0]['index'] == INDEX,
           'trace requires the one selected controller')
    current = controllers[0]
    shutdown = current.get('shutdown', {})
    h.need(shutdown.get('original_child_reaped') is True, 'trace cannot be finalized before original reap')
    path = out / 'controller-1-B/stderr.log'
    receipt, raw = h.bytes_receipt(path, maximum=64 * 1024 * 1024, keep=True)
    closed = shutdown.get('files', {}).get('stderr.log', {})
    h.need(closed.get('bytes') == receipt['bytes'] and closed.get('sha256') == receipt['sha256']
           and closed.get('identity') == receipt['identity'][:4] + receipt['identity'][5:],
           'stderr differs from the original close receipt')
    names = ('steady_stage', 'start_unix_ms', 'end_unix_ms', 'elapsed_us', 'input_rows',
             'durable', 'outcome', 'claim_pending_us', 'store_lock_wait_us', 'state_us',
             'begin_write_us', 'update_rows_us', 'commit_us', 'size_read_us',
             'snapshot_read_us', 'seal_us', 'other_us')
    text_names = {'steady_stage', 'durable', 'outcome'}
    parsed, errors, offset = [], [], 0
    for number, line in enumerate(raw.splitlines(keepends=True), 1):
        if b'archive_index steady_stage=' in line:
            try:
                text = line.decode('ascii').rstrip('\r\n')
                h.need(text.startswith('archive_index steady_stage='), 'steady trace has an unexpected prefix')
                fields = [part.split('=', 1) for part in text.split(' ')[1:]]
                h.need(all(len(part) == 2 for part in fields)
                       and tuple(part[0] for part in fields) == names, 'steady trace field layout differs')
                row = {name: (value if name in text_names else int(value)) for name, value in fields}
                h.need(all(row[name] >= 0 for name in names if name not in text_names),
                       'steady trace contains negative numeric fields')
                row.update(stderr_line=number, stderr_byte_offset=offset, raw_line_sha256=h.sha(line))
                parsed.append(row)
            except Exception as error:
                errors.append({'stderr_line': number, 'stderr_byte_offset': offset,
                               'raw_line_sha256': h.sha(line), 'error': str(error)})
        offset += len(line)
    groups = {}
    for row in parsed:
        group = groups.setdefault(row['steady_stage'], {'count': 0, 'outcomes': {},
            'max_elapsed_us': 0, 'max_store_lock_wait_us': 0, 'max_snapshot_read_us': 0})
        group['count'] += 1
        group['outcomes'][row['outcome']] = group['outcomes'].get(row['outcome'], 0) + 1
        for field in ('elapsed_us', 'store_lock_wait_us', 'snapshot_read_us'):
            group['max_' + field] = max(group['max_' + field], row[field])
    result = {'schema': 'hepta-a49-existing-steady-trace/v1', 'stderr': receipt,
              'parsed_steady_trace_count': len(parsed), 'parse_errors': errors,
              'groups': groups, 'rows': parsed,
              'scope': 'All retained controller stderr, including setup, idle, measured work and shutdown. Existing SteadyTrace emits only durations above 100 ms; absence is not proof of zero work. No RPC ID or per-wave attribution is supplied; concurrent/background stages may overlap. Other existing archive trace formats remain in original stderr.'}
    h.create(out / 'steady-trace.json', h.canonical(result))
    return {'artifact': h.bytes_receipt(out / 'steady-trace.json'), 'stderr': receipt,
            'steady_trace_observed': bool(parsed), 'parsed_steady_trace_count': len(parsed),
            'parse_error_count': len(errors), 'groups': groups,
            'capture_after_original_reap': True, 'per_rpc_or_cohort_attribution_claimed': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--protocol', type=Path, required=True)
    parser.add_argument('--out', type=Path, default=OUT)
    parser.add_argument('--completed-a48-report-sha256', required=True)
    args = parser.parse_args()
    require(sys.platform == 'linux' and hasattr(os, 'wait4'), 'Linux original wait4 required')
    require(HEX.fullmatch(args.completed_a48_report_sha256), 'reviewed terminal A48 SHA required')
    require(args.out == OUT, 'only the fixed new A49 output is admitted')
    h, harness_receipt, harness_raw = load_reference()
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM):
        signal.signal(signum, h.stop_requested)
    started_ns = time.monotonic_ns()
    signal.setitimer(signal.ITIMER_REAL, WORK_SECONDS)
    protocol_receipt, protocol_raw = h.bytes_receipt(args.protocol, maximum=1024 * 1024, keep=True)
    h.need(protocol_receipt['sha256'] == PROTOCOL_SHA, 'A49 frozen protocol SHA differs')
    protocol = h.document(protocol_raw)
    h.need(protocol['schema'] == 'hepta-a49-archive-phase-diagnostic-protocol/v1'
           and protocol['out'] == str(OUT)
           and protocol['work_budget_seconds'] == WORK_SECONDS
           and protocol['outer_operator_budget_seconds'] == OUTER_SECONDS,
           'A49 protocol layout/budgets differ')
    old_protocol_receipt, old_protocol_raw = h.bytes_receipt(REFERENCE_PROTOCOL, maximum=1024 * 1024, keep=True)
    h.need(old_protocol_receipt['sha256'] == REFERENCE_PROTOCOL_SHA == h.PROTOCOL_SHA,
           'A48 source protocol differs')
    old_protocol = h.document(old_protocol_raw)
    h.need(old_protocol['bindings_ready'] is True and h.FINAL_BINDINGS_READY
           and old_protocol['bindings']['B'] == protocol['qualification_binding']
           and old_protocol['qualification_chain_loader_sha256'] == h.QUALIFICATION_CHAIN_SHA,
           'A48 original candidate or loader binding differs')
    h.need(h.ORDER == ('A', 'B', 'B', 'A') and h.ROWS == 65536 and h.HOT == 512
           and h.OWNED == 16384 and h.CLIENT_SECONDS == 10 and h.ROUND_SECONDS == 300,
           'original experiment constants differ')
    all_slots, all_waves = h.plan_slots()
    slots = [row for row in all_slots if row['controller'] == INDEX]
    waves = [row for row in all_waves if row['controller'] == INDEX]
    h.need(len(slots) == 20 and [row['slot'] for row in slots] == list(range(20, 40))
           and len(waves) == 8 and all(row['arm'] == ARM for row in slots),
           'selected original controller plan differs')
    prior_receipt, prior_raw, prior_summary = finished_prior(
        h, args.completed_a48_report_sha256, all_slots, all_waves)
    h.check_stop()
    os.umask(0o077)
    out = h.direct(OUT, fresh=True)
    out.mkdir(mode=0o700)
    h.sync_directory(out.parent)
    for name, raw in (('protocol.original.json', protocol_raw),
                      ('a48-protocol.original.json', old_protocol_raw),
                      ('a48-harness.original.py', harness_raw),
                      ('a48-terminal-report.original.json', prior_raw)):
        h.create(out / name, raw)
    report = {'schema': 'hepta-a49-archive-phase-diagnostic/v1', 'started_utc': h.utc(),
              'phase': 'preflight', 'complete': False, 'diagnostic_complete': False,
              'diagnostic_only': True, 'instrumentation_changed': True,
              'runtime_environment_delta': {TRACE_KEY: TRACE_VALUE},
              'performance_adopted': False, 'numeric_gates_evaluated': False,
              'arms_compared': False, 'prior_results_pooled': False,
              'replaces_a48_result': False, 'optimization_exhausted_claim': False,
              'native_mcp_wire': True, 'direct_index_test_entry': False,
              'service_mutations': 0, 'ssh_or_agent_accesses': 0, 'automatic_retries': 0,
              'planned_measured_calls': 20, 'planned_waves': 8, 'planned_real_native_seeds': 1,
              'planned_index_kickoffs': 1, 'planned_fixed_archive_warmups': 1,
              'selected_original_controller': INDEX, 'selected_original_arm': ARM,
              'selected_original_global_slot_ids': list(range(20, 40)),
              'internal_global_plan_length': 80, 'unselected_controllers_started': False,
              'server_cohort_membership_observed': False,
              'server_admission_timestamps_observed': False,
              'synthetic_records_are_native_admissions': False,
              'protocol': protocol_receipt, 'prior_a48_terminal_result': prior_summary,
              'work_budget_seconds': WORK_SECONDS, 'outer_operator_budget_seconds': OUTER_SECONDS,
              'work_budget_signal': 'SIGALRM records first stop; original safe control points and original cleanup apply',
              'slots': slots, 'waves': waves, 'controllers': [], 'errors': []}
    inputs = [protocol_receipt, harness_receipt, old_protocol_receipt, prior_receipt]
    report['frozen_inputs'] = inputs
    report_path = out / 'report.json'
    journal = (out / 'calls.jsonl').open('xb')
    bundle, native, chain, block_started = None, None, None, False
    owned = []

    def checkpoint():
        report['observed_measured_write_attempts'] = sum(row.get('write_attempts') == 1 for row in slots)
        report['observed_measured_successes'] = sum(row['okay'] for row in slots)
        report['unexecuted_measured_slots'] = [row['slot'] for row in slots if row['status'] == 'unexecuted']
        h.save(report_path, report)

    def input_fence():
        chain.assert_bundle_unchanged(native, bundle)
        for item in inputs:
            h.need(h.bytes_receipt(Path(item['path'])) == item, 'frozen original input changed')

    checkpoint()
    try:
        receipt, raw = h.bytes_receipt(Path(__file__).absolute(), maximum=1024 * 1024, keep=True)
        inputs.append(receipt)
        h.create(out / 'harness.original.py', raw)
        loaded = []
        for label, path, pin, name in (
            ('small', h.SMALL_HELPER, h.SMALL_SHA, 'small-helper.original.py'),
            ('native', h.NATIVE_DRIVER, h.NATIVE_SHA, 'native-driver.original.py'),
            ('qualification_chain', h.QUALIFICATION_CHAIN, h.QUALIFICATION_CHAIN_SHA,
             'qualification-chain-loader.original.py')):
            module, receipt, raw = h.pinned_module('frozen_a49_' + label, path, pin)
            loaded.append(module)
            inputs.append(receipt)
            h.create(out / name, raw)
        small, native, chain = loaded
        report['disk_gate'] = h.disk_gate(out)
        h.need(report['disk_gate']['clear'], 'insufficient available space/inodes for the fixed fixture')
        bundle = load_candidate(h, old_protocol, native, chain, out, inputs, report)
        report['qualification'] = bundle
        Controller, proof = trace_controller(h, harness_raw, small)
        def registered_controller(*arguments):
            controller = Controller(*arguments)
            state = {'controller': controller, 'close_attempted': False,
                     'close_returned': False, 'fallback_used': False}
            owned.append(state)  # Before the original run_controller calls start.
            original_close = controller.close

            def close_once():
                if state['close_attempted']:
                    h.need(controller.shutdown is not None,
                           'original cleanup was already attempted; no renewed wait or signal budget')
                    return controller.shutdown
                state['close_attempted'] = True
                value = original_close()
                state['close_returned'] = True
                return value

            controller.close = close_once
            return controller

        proof['external_custody_adapter'] = ('Register the original controller before start; '
            'call its unchanged close at most once. Outer fallback only covers a skipped close; '
            'an attempted/incomplete close is not retried and no wait4 result is reconstructed.')
        h.create(out / 'binding-proof.json', h.canonical(proof))
        report['binding_proof'] = h.bytes_receipt(out / 'binding-proof.json')
        h.check_stop()
        input_fence()
        report['inputs_unchanged_before_controller'] = True
        gate = h.host_gate(native)
        h.create(out / 'host-before.json', h.canonical(gate))
        report['host_before'], report['host_before_clear'] = h.bytes_receipt(out / 'host-before.json'), gate['clear']
        h.need(gate['clear'], 'busy/incomplete before-controller host gate')
        block_started = True
        report['phase'] = 'controller-1-B'
        checkpoint()
        report['controller_completed'] = h.run_controller(INDEX, ARM, bundle, out, report,
            all_slots, waves, native, small, registered_controller, journal, checkpoint)
        h.need(report['controller_completed'], 'diagnostic controller setup/workload/integrity failed')
        h.check_stop()
        report['phase'] = 'controller_complete'
    except BaseException as error:
        report['phase'] = 'failed'
        report['errors'].append(type(error).__name__ + ': ' + str(error))
    finally:
        # The original run_controller writes its journal before close. Keep a
        # reference outside it so a journal exception cannot skip an unattempted
        # close. Never repeat a close that consumed any original cleanup budget.
        report['original_controller_custody_adapter'] = []
        for state in owned:
            controller = state['controller']
            cleanup = {'close_attempted_before_fallback': state['close_attempted'],
                       'original_child_started': controller.child is not None,
                       'original_child_reaped_before_fallback': controller.reaped,
                       'fallback_used': False}
            if not state['close_attempted'] and not controller.reaped:
                state['fallback_used'] = cleanup['fallback_used'] = True
                try:
                    value = controller.close()
                    if len(report['controllers']) == 1:
                        report['controllers'][0]['startup'] = controller.startup
                        report['controllers'][0]['shutdown'] = value
                except BaseException as error:
                    cleanup['error'] = type(error).__name__ + ': ' + str(error)
                    report['errors'].append('fallback_close: ' + cleanup['error'])
            cleanup.update(close_attempted=state['close_attempted'],
                           close_returned=state['close_returned'],
                           original_child_reaped=controller.reaped,
                           shutdown_receipt_present=controller.shutdown is not None)
            report['original_controller_custody_adapter'].append(cleanup)
            if (controller.child is not None and (not controller.reaped
                    or controller.shutdown is None or controller.shutdown.get('waited') is None)):
                report['errors'].append('original controller custody/evidence incomplete; no repeated cleanup or reconstructed wait4')
        # Each operation records its own error so evidence failures do not skip
        # the independent original-input and host postchecks.
        if block_started:
            try:
                gate = h.host_gate(native)
                h.create(out / 'host-after.json', h.canonical(gate))
                report['host_after'], report['host_after_clear'] = h.bytes_receipt(out / 'host-after.json'), gate['clear']
                h.need(gate['clear'], 'busy/incomplete after-controller host gate')
            except BaseException as error:
                report['errors'].append('host_after: ' + type(error).__name__ + ': ' + str(error))
        if bundle is not None:
            try:
                input_fence()
                report['inputs_unchanged_after_controller'] = True
            except BaseException as error:
                report['errors'].append('input_after: ' + type(error).__name__ + ': ' + str(error))
        try:
            h.retain_interrupted_rows(journal, slots)
            journal.flush()
            os.fsync(journal.fileno())
        except BaseException as error:
            report['errors'].append('journal: ' + type(error).__name__ + ': ' + str(error))
        finally:
            try:
                journal.close()
            except BaseException as error:
                report['errors'].append('journal_close: ' + type(error).__name__ + ': ' + str(error))
        try:
            report['calls_file'] = h.bytes_receipt(out / 'calls.jsonl', maximum=16 * 1024 * 1024)
        except BaseException as error:
            report['errors'].append('journal_receipt: ' + type(error).__name__ + ': ' + str(error))
        for row in slots:
            if row['status'] == 'unexecuted':
                row['unexecuted_reason'] = 'diagnostic not reached after setup, host, input, custody, transport or oracle failure; no retry'
        for wave in waves:
            if wave['status'] not in ('succeeded', 'complete_with_failures'):
                attempted = sum(all_slots[slot].get('write_attempts') == 1 for slot in wave['slot_ids'])
                wave.update(status='interrupted_unknown' if attempted else 'unexecuted',
                            original_write_attempts=attempted)
        if report['controllers']:
            try:
                report['trace'] = capture_trace(h, out, report['controllers'])
                h.need(report['trace']['parse_error_count'] == 0, 'some existing steady trace lines were not parsed; original stderr retained')
            except BaseException as error:
                report['errors'].append('trace: ' + type(error).__name__ + ': ' + str(error))
        report['mode_counts'] = {f'C{concurrency}': {
            'planned': sum(row['concurrency'] == concurrency for row in slots),
            'attempted': sum(row['concurrency'] == concurrency and row.get('write_attempts') == 1 for row in slots),
            'succeeded': sum(row['concurrency'] == concurrency and row['okay'] for row in slots),
            'failed': sum(row['concurrency'] == concurrency and row['status'] not in ('unexecuted', 'succeeded') for row in slots),
            'unexecuted': sum(row['concurrency'] == concurrency and row['status'] == 'unexecuted' for row in slots)
        } for concurrency in (1, 4)}
        report['all_measured_queries_successful'] = all(row['okay'] for row in slots)
        report['all_setup_queries_successful'] = (len(report['controllers']) == 1
            and report['controllers'][0].get('setup_requests_all_succeeded') is True)
        # End the soft work-budget observation before taking final snapshots.
        # Otherwise its alarm could fire inside final report fsync after a
        # successful result had already been serialized. The outer 900 s owner
        # budget still covers the final report/print and process completion.
        signal.setitimer(signal.ITIMER_REAL, 0)
        report['work_budget_observation_end_monotonic_ns'] = time.monotonic_ns()
        report['work_budget_observation_scope'] = ('Definition binding, qualification/source reads, '
            'controller, original cleanup, post-fences and trace parsing; ends before final report serialization')
        report['first_termination_signal'] = h.STOP_SIGNUM
        report['stop_requested'] = h.STOP_SIGNUM is not None
        report['elapsed_seconds'] = (time.monotonic_ns() - started_ns) / 1e9
        report['diagnostic_complete'] = (not report['errors'] and h.STOP_SIGNUM is None
            and report.get('controller_completed') is True
            and report.get('inputs_unchanged_before_controller') is True
            and report.get('inputs_unchanged_after_controller') is True
            and report.get('host_before_clear') is True and report.get('host_after_clear') is True
            and all(row.get('write_attempts') == 1 and row['status'] != 'unexecuted' for row in slots)
            and all(row['status'] in ('succeeded', 'complete_with_failures') for row in waves)
            and report.get('trace', {}).get('capture_after_original_reap') is True)
        report['complete'] = report['diagnostic_complete']
        report['phase'] = 'complete' if report['diagnostic_complete'] else 'failed'
        report['finished_utc'] = h.utc()
        checkpoint()
        if h.STOP_SIGNUM is not None and not report['stop_requested']:
            report.update(complete=False, diagnostic_complete=False, phase='failed',
                          stop_requested=True, first_termination_signal=h.STOP_SIGNUM)
            report['errors'].append('first termination signal arrived during final report persistence')
            checkpoint()
        print(json.dumps({'report': str(report_path), 'diagnostic_complete': report['diagnostic_complete'],
                          'numeric_gates_evaluated': False, 'prior_results_pooled': False,
                          'measured_write_attempts': report['observed_measured_write_attempts'],
                          'measured_successes': report['observed_measured_successes'],
                          'trace': report.get('trace'), 'errors': report['errors']}), flush=True)
    return 0 if report['diagnostic_complete'] and h.STOP_SIGNUM is None else 1


if __name__ == '__main__':
    raise SystemExit(main())

#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""One fresh native diagnostic controller; no retries or performance adoption.

Use A50's exact seed, 65536-record fixture, 60s idle, warmup, four C1 and
four C4 waves, oracles and original wait4 cleanup. Only the controller's
explicit environment gains metadata/index trace flags. All failed and
unexecuted requests remain present. This is a separately identified diagnostic.
"""
import argparse
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import types

BASE = Path('/home/qian/hepta-runtime-optimization-20261023/a41-phase-timing-20261025-r01')
REFERENCE = BASE / 'tools/run_native_archive_cohort_a50_r01.py'
REFERENCE_SHA = '70d3a44fead9f5e21416994dd4462cbd2b25365630324521fd673420f4fad8e1'
OUT = BASE / 'a51-metadata-diagnostic-r01'
QUALIFICATION = BASE / 'qualification-a51-metadata-trace-r01/report.json'
ENTRY = BASE / 'a51-metadata-trace-entry-r01/entry-report.json'
WORKER = ENTRY.parent / 'worker-report.json'
BASE_ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'SHELL': '/bin/sh',
            'TOKIO_WORKER_THREADS': '2', 'RUST_LOG': 'warn'}
TRACE_ENV = {'HEPTA_METADATA_TRACE': '1', 'HEPTA_ARCHIVE_INDEX_TRACE': '1'}


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def traced_controller(h, raw, small):
    tree = ast.parse(raw)
    original = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                    and node.name == 'controller_type')
    changed = copy.deepcopy(original)
    start = next(node for node in changed.body[0].body
                 if isinstance(node, ast.FunctionDef) and node.name == 'start')
    env = next(node.value for node in start.body if isinstance(node, ast.Assign)
               and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
               and node.targets[0].id == 'env')
    require(ast.literal_eval(env) == BASE_ENV, 'original controller environment differs')
    for name, value in TRACE_ENV.items():
        env.keys.append(ast.Constant(name))
        env.values.append(ast.Constant(value))
    normalized = copy.deepcopy(changed)
    start2 = next(node for node in normalized.body[0].body
                  if isinstance(node, ast.FunctionDef) and node.name == 'start')
    env2 = next(node.value for node in start2.body if isinstance(node, ast.Assign)
                and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id == 'env')
    require(ast.literal_eval(env2) == {**BASE_ENV, **TRACE_ENV}, 'trace environment differs')
    del env2.keys[-2:]
    del env2.values[-2:]
    require(ast.dump(normalized, include_attributes=False) == ast.dump(original, include_attributes=False),
            'controller changed beyond two explicit diagnostic flags')
    code = ast.fix_missing_locations(ast.Module(body=[changed], type_ignores=[]))
    exec(compile(code, str(REFERENCE) + ':a51-trace-flags', 'exec'), h.__dict__)
    return h.controller_type(small), {'original_sha256': REFERENCE_SHA,
        'environment_before': BASE_ENV, 'environment_after': {**BASE_ENV, **TRACE_ENV},
        'only_two_environment_entries_changed': True,
        'original_main_called': False, 'original_performance_summary_called': False}


def source_fence(h, report):
    root = Path(report['source'])
    found = sorted(str(p.relative_to(root)) for p in root.rglob('*') if p.is_file())
    require(found == sorted(report['source_after']), 'source inventory differs')
    receipts = {}
    for name, expected in report['source_after'].items():
        row = h.bytes_receipt(root / name)
        require(row['sha256'] == expected, 'qualified source changed: ' + name)
        receipts[name] = row
    return receipts


def capture(h, report):
    current = report['controllers'][0]
    shutdown = current.get('shutdown', {})
    require(shutdown.get('original_child_reaped') is True, 'trace requires original wait4 reap')
    receipt, raw = h.bytes_receipt(OUT / 'controller-0-B/stderr.log', maximum=8 * 1024 * 1024, keep=True)
    closed = shutdown.get('files', {}).get('stderr.log', {})
    require(closed.get('sha256') == receipt['sha256'] and closed.get('bytes') == receipt['bytes'],
            'original closed stderr receipt differs')
    events, errors, dropped, offset = [], [], 0, 0
    for line_number, line in enumerate(raw.splitlines(keepends=True), 1):
        marker = line.find(b'hepta_metadata_trace ')
        if marker >= 0:
            try:
                value = json.loads(line[marker + len(b'hepta_metadata_trace '):])
                if 'dropped_events' in value:
                    dropped += value['dropped_events']
                else:
                    require(set(value) == {'sequence', 'call', 'tool', 'phase', 'kind', 'at_us',
                            'call_us', 'remaining_us', 'cohort', 'value', 'limit', 'cursor'},
                            'trace event schema differs')
                    value.update(stderr_line=line_number, stderr_byte_offset=offset,
                                 raw_line_sha256=sha(line))
                    events.append(value)
            except Exception as error:
                errors.append({'line': line_number, 'offset': offset, 'error': str(error)})
        offset += len(line)
    events.sort(key=lambda event: event['sequence'])
    sequence_complete = [row['sequence'] for row in events] == list(range(1, len(events) + 1))
    calls, cohorts = {}, {}
    for event in events:
        calls.setdefault(str(event['call']), []).append(event)
        if event['cohort']:
            cohorts.setdefault(str(event['cohort']), []).append(event)
    result = {'schema': 'hepta-a51-correlated-metadata-trace/v1', 'stderr': receipt,
              'events': events, 'calls': calls, 'cohorts': cohorts, 'parse_errors': errors,
              'dropped_events': dropped, 'sequence_complete': sequence_complete,
              'complete_capture': bool(events) and not errors and dropped == 0 and sequence_complete,
              'scope': 'Local numeric call/cohort IDs and unique limit/cursor shapes in this fixed fixture; no general RPC identity claim; opt-in flush perturbs scheduling and is not a performance comparison.'}
    h.create(OUT / 'metadata-trace.json', h.canonical(result))
    return {'artifact': h.bytes_receipt(OUT / 'metadata-trace.json'),
            'complete_capture': result['complete_capture'], 'event_count': len(events),
            'call_count': len(calls), 'cohort_count': len(cohorts),
            'dropped_events': dropped, 'parse_errors': errors, 'sequence_complete': sequence_complete}


def main(args):
    raw = REFERENCE.read_bytes()
    require(len(raw) == 78248 and sha(raw) == REFERENCE_SHA, 'frozen A50 driver differs')
    h = types.ModuleType('a51_frozen_native_driver')
    h.__file__ = str(REFERENCE)
    exec(compile(raw, str(REFERENCE), 'exec'), h.__dict__)
    h.direct(OUT, fresh=True)
    OUT.mkdir(mode=0o700)
    os.umask(0o077)
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, h.stop_requested)
    slots, waves = h.plan_slots()
    slots, waves = slots[:20], waves[:8]
    for row in slots:
        row.update(arm='B', purpose='diagnostic')
    for row in waves:
        row['arm'] = 'B'
    report = {'schema': 'hepta-a51-metadata-diagnostic/v1', 'started_utc': h.utc(),
              'complete': False, 'product_passed': False, 'performance_adopted': False,
              'controllers': [], 'slots': slots, 'waves': waves, 'errors': [],
              'planned_calls': 20, 'planned_waves': 8, 'fixed_idle_seconds': 60,
              'automatic_retries': 0, 'original_deadlines_preserved': True,
              'prior_results_pooled': False, 'baseline_comparison': False,
              'service_changes': False, 'ssh_or_agent_accesses': 0, 'custody_adapter': []}
    journal = (OUT / 'calls.jsonl').open('xb')
    owned = []

    def checkpoint():
        path = OUT / 'report.next.json'
        h.create(path, h.canonical(report))
        os.replace(path, OUT / 'report.json')

    def registered(*arguments):
        controller = Controller(*arguments)
        state = {'controller': controller, 'close_attempted': False, 'close_returned': False}
        owned.append(state)
        close = controller.close
        def close_once():
            require(not state['close_attempted'] or state['close_returned'],
                    'original close already attempted; no renewed cleanup deadline')
            if state['close_returned']:
                return state['result']
            state['close_attempted'] = True
            state['result'] = close()
            state['close_returned'] = True
            return state['result']
        controller.close = close_once
        return controller

    try:
        h.create(OUT / 'driver.original.py', Path(__file__).read_bytes())
        h.create(OUT / 'reference.original.py', raw)
        qreceipt, qraw = h.bytes_receipt(QUALIFICATION, keep=True)
        require(qreceipt['sha256'] == args.qualification_sha, 'qualification receipt differs')
        q = json.loads(qraw)
        require(q['qualified'] is True and q['source_after'] == q['source_tested']
                and q['binary']['cached'] is False and q['test_binary']['cached'] is False,
                'candidate is not completely source-qualified')
        ereceipt, eraw = h.bytes_receipt(ENTRY, keep=True)
        wreceipt, wraw = h.bytes_receipt(WORKER, keep=True)
        require(ereceipt['sha256'] == args.entry_sha and wreceipt['sha256'] == args.worker_sha,
                'entry/worker receipt differs')
        entry, worker = json.loads(eraw), json.loads(wraw)
        require(entry['qualified'] is True and worker['passed'] is True
                and entry['worker_custody']['original_child_reaped']
                and entry['worker_custody']['group_quiet_before_reap']
                and all(row['gate_clear'] and row['returncode'] == 0 for row in worker['stages'])
                and len(worker['stages']) == 6, 'qualification custody/stages incomplete')
        for name, body in [('qualification.original.json', qraw), ('entry.original.json', eraw),
                           ('worker.original.json', wraw)]:
            h.create(OUT / name, body)
        report['source_before'] = source_fence(h, q)
        binary = h.bytes_receipt(Path(q['binary']['path']))
        require(binary['sha256'] == q['binary']['sha256'], 'qualified ELF changed')
        report['binary_before'] = binary
        small, _, _ = h.pinned_module('a51_original_small_fixture', h.SMALL_HELPER, h.SMALL_SHA)
        native, _, _ = h.pinned_module('a51_original_host_load', h.NATIVE_DRIVER, h.NATIVE_SHA)
        Controller, report['trace_binding'] = traced_controller(h, raw, small)
        report['host_before'] = h.host_gate(native)
        require(report['host_before']['clear'] and h.disk_gate(OUT)['clear'], 'host/disk gate refused')
        checkpoint()
        controller_complete = h.run_controller(
            0, 'B', {'version': 'a51-metadata-trace', 'binary': binary},
            OUT, report, slots, waves, native, small, registered, journal, checkpoint)
        report['original_controller_complete'] = controller_complete
        report['trace'] = capture(h, report)
        report['host_after'] = h.host_gate(native)
        require(report['host_after']['clear'], 'post-controller host gate refused')
        report['source_after'] = source_fence(h, q)
        report['binary_after'] = h.bytes_receipt(Path(q['binary']['path']))
        require(report['binary_after'] == report['binary_before'], 'qualified ELF changed during diagnostic')
        require(report['source_after'] == report['source_before'], 'qualified sources changed during diagnostic')
        current = report['controllers'][0]
        report['all_setup_successful'] = all(row['okay'] for row in current['setup'])
        report['all_diagnostic_calls_correct'] = all(row['okay'] for row in slots)
        report['complete'] = (controller_complete and not current['errors']
                              and current.get('original_fixture_unchanged') is True
                              and all(row['write_attempts'] == 1 for row in slots)
                              and report['trace']['complete_capture'])
        report['product_passed'] = (report['complete'] and report['all_setup_successful']
                                    and report['all_diagnostic_calls_correct'])
    except BaseException as error:
        report['errors'].append(type(error).__name__ + ': ' + str(error))
    finally:
        for state in owned:
            controller = state['controller']
            fallback = not state['close_attempted']
            if fallback:
                report['complete'] = False
                report['errors'].append('outer custody used the original first close after skipped cleanup')
                try:
                    controller.close()
                except BaseException as error:
                    report['errors'].append('first close: ' + type(error).__name__ + ': ' + str(error))
            report['custody_adapter'].append({'fallback_used': fallback,
                'close_attempted': state['close_attempted'], 'close_returned': state['close_returned'],
                'original_child_reaped': controller.reaped})
            if not state['close_returned'] or (controller.child is not None and not controller.reaped):
                report['complete'] = False
                report['errors'].append('original controller custody incomplete')
        journal.flush()
        os.fsync(journal.fileno())
        journal.close()
        report['attempted'] = sum(row['write_attempts'] == 1 for row in slots)
        report['successful'] = sum(row['okay'] for row in slots)
        report['failed'] = report['attempted'] - report['successful']
        report['unexecuted'] = 20 - report['attempted']
        report['finished_utc'] = h.utc()
        if report['errors']:
            report['complete'] = report['product_passed'] = False
        checkpoint()
        print(json.dumps({key: report[key] for key in ['complete', 'product_passed', 'attempted',
              'successful', 'failed', 'unexecuted', 'errors']}), flush=True)
    return 0 if report['complete'] else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--qualification-sha', required=True)
    parser.add_argument('--entry-sha', required=True)
    parser.add_argument('--worker-sha', required=True)
    raise SystemExit(main(parser.parse_args()))

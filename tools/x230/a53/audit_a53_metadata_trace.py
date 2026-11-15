#!/usr/bin/env python3
"""Pure local audit of actual A53 diagnostic originals; starts no child."""
import collections
import hashlib
import json
import os
from pathlib import Path
import stat

ROOT = Path(__file__).resolve().parents[1]
ORIGINALS = ROOT / 'multihost-review/a53-metadata-diagnostic-download-r01/originals'
DOCS = ROOT / 'runtime-resume/docs/experiments/x230/a53'
PINS = {
    'report.json': (255639, 'fc41dfdd6a7433434030a0352b7da1866faa166b7f8f5ed01d818b79120e6f73'),
    'metadata-trace.json': (2071992, '89698d9cb246335ff1ecfeb07a68ca8b08b8f6135649e2633479e9a6ed329e4a'),
    'stderr.log': (697965, '0b2ebfeda7d2933719088434594a9eeb5d04c6996eab560eab83312f58861be0'),
}
Q_SHA = 'ab3a37ceb97667694c201d9b62556398e04e805010c8492af6a8f6f51486a72b'
MAP_SHA = '91962e89b203621686cfa0d77567b13bd246092a99345681674bbafd46388c35'
ELF_SHA = '5855f6fb044745eba0bf0885b0430bc5a5bb03f68310cce50d961947925c03c6'


def need(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def document(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda text: (_ for _ in ()).throw(ValueError(text)))


def original(path, expected):
    need(path.resolve(strict=True) == path, 'direct local original required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and before.st_size == expected[0], 'original file identity/type/size differs')
        raw = stream.read(expected[0] + 1)
        after = os.fstat(stream.fileno())
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
                  'st_size', 'st_mtime_ns', 'st_ctime_ns')
        need(all(getattr(before, key) == getattr(after, key) == getattr(path.lstat(), key)
                 for key in fields), 'local original changed while reading')
    need(len(raw) == expected[0] and sha(raw) == expected[1], 'full original SHA differs')
    return raw


def once(events, phase):
    selected = [row for row in events if row['phase'] == phase]
    need(len(selected) == 1, 'exactly one ' + phase + ' required')
    return selected[0]


def stages(events):
    opened, closed = {}, collections.defaultdict(list)
    for event in events:
        phase = event['phase']
        if event['kind'] == 'begin':
            need(phase not in opened, 'nested duplicate trace phase')
            opened[phase] = event
        elif event['kind'] == 'end':
            start = opened.pop(phase, None)
            need(start is not None and event['at_us'] >= start['at_us'], 'unpaired/negative trace stage')
            closed[phase].append({'begin': start, 'end': event,
                                  'recorded_elapsed_us': event['value'],
                                  'boundary_elapsed_us': event['at_us'] - start['at_us']})
        else:
            need(event['kind'] == 'event', 'unknown trace event kind')
    need(not opened, 'unclosed trace stages')
    return dict(closed)


def main():
    bodies = {name: original(ORIGINALS / name, pin) for name, pin in PINS.items()}
    report, trace = document(bodies['report.json']), document(bodies['metadata-trace.json'])
    qualification_raw = original(DOCS / 'qualification-r02.original.json', (62012, Q_SHA))
    qualification = document(qualification_raw)
    need(qualification['qualified'] is True and len(qualification['source_after']) == 175
         and qualification['source_tested'] == qualification['source_after'], 'actual A53 qualification differs')
    need(sha(json.dumps(qualification['source_after'], sort_keys=True, separators=(',', ':')).encode()) == MAP_SHA,
         'actual 175-source map differs')
    need(report['source_before'] == report['source_after'] and len(report['source_before']) == 175
         and {key: row['sha256'] for key, row in report['source_before'].items()} == qualification['source_after'],
         'reported original source fences differ')
    need(report['binary_before'] == report['binary_after']
         and report['binary_before']['sha256'] == qualification['binary']['sha256'] == ELF_SHA,
         'reported actual qualified ELF fences differ')
    need(report['input_receipts_before'] == report['input_receipts_after']
         and len(report['input_receipts_before']) == 7, 'seven original input fences differ')
    need(report['complete'] is True and report['product_passed'] is False
         and report['attempted'] == 20 and report['successful'] == 19
         and report['failed'] == 1 and report['unexecuted'] == 0 and report['errors'] == [],
         'actual diagnostic outcome differs')
    need(report['automatic_retries'] == 0 and report['fixed_idle_seconds'] == 60
         and report['original_deadlines_preserved'] is True and report['performance_adopted'] is False,
         'diagnostic limits/scope differ')
    current = report['controllers'][0]
    need(len(report['controllers']) == 1 and current['status'] == 'complete'
         and current['original_fixture_unchanged'] is True, 'original controller/fixture witness incomplete')
    shutdown = current['shutdown']
    need(shutdown['original_child_reaped'] is True and shutdown['waited']['exit_code'] == 0
         and shutdown['errors'] == [] and shutdown['reader_error'] is None
         and shutdown['unmatched'] == [] and shutdown['method'] == 'stdin_eof'
         and shutdown['raw_stdout_eof_captured'] is True, 'original wait4/EOF custody incomplete')
    receipt = trace['stderr']
    need(shutdown['files']['stderr.log'] == {'bytes': receipt['bytes'], 'sha256': receipt['sha256'],
         'identity': receipt['identity'][:4] + receipt['identity'][5:]}
         and (receipt['bytes'], receipt['sha256']) == PINS['stderr.log'], 'closed original stderr differs')
    need((report['trace']['artifact']['bytes'], report['trace']['artifact']['sha256']) == PINS['metadata-trace.json'],
         'original trace artifact differs from report receipt')
    keys = {'sequence', 'call', 'tool', 'phase', 'kind', 'at_us', 'call_us',
            'remaining_us', 'cohort', 'value', 'limit', 'cursor'}
    events, offset, dropped = [], 0, 0
    for line_number, line in enumerate(bodies['stderr.log'].splitlines(keepends=True), 1):
        marker = line.find(b'hepta_metadata_trace ')
        if marker >= 0:
            value = document(line[marker + len(b'hepta_metadata_trace '):])
            if 'dropped_events' in value:
                need(set(value) == {'dropped_events'} and type(value['dropped_events']) is int,
                     'drop event schema differs')
                dropped += value['dropped_events']
            else:
                need(set(value) == keys and type(value['cursor']) is bool
                     and all(type(value[key]) is int for key in keys - {'tool', 'phase', 'kind', 'cursor'}),
                     'trace event schema/types differ')
                value.update(stderr_line=line_number, stderr_byte_offset=offset, raw_line_sha256=sha(line))
                events.append(value)
        offset += len(line)
    events.sort(key=lambda event: event['sequence'])
    need([row['sequence'] for row in events] == list(range(1, len(events) + 1))
         and len(events) == 3173 and dropped == 0 and events == trace['events'],
         'independent stderr reparse/sequence/drops differ')
    calls, cohorts = {}, {}
    for event in events:
        calls.setdefault(str(event['call']), []).append(event)
        if event['cohort']:
            cohorts.setdefault(str(event['cohort']), []).append(event)
    need(calls == trace['calls'] and cohorts == trace['cohorts'] and len(calls) == 22 and len(cohorts) == 9
         and trace['complete_capture'] is True and trace['sequence_complete'] is True
         and trace['dropped_events'] == 0 and trace['parse_errors'] == [], 'original correlated capture differs')
    stage_map = {call: stages(rows) for call, rows in calls.items()}
    correlated, next_call, prior_end = [], 3, once(calls['2'], 'caller_scope_end')['at_us']
    for wave in report['waves']:
        rows = [report['slots'][index] for index in wave['slot_ids']]
        wave_calls = list(range(next_call, next_call + len(rows)))
        next_call += len(rows)
        by_shape = {}
        for call in wave_calls:
            api = once(calls[str(call)], 'api_enter')
            need(api['tool'] == 'request_archive' and api['at_us'] > prior_end, 'fixed sequential wave attribution differs')
            shape = (api['limit'], api['cursor'])
            need(shape not in by_shape, 'ambiguous in-wave diagnostic shape')
            by_shape[shape] = call
        need(len(by_shape) == len(rows), 'trace wave coverage differs')
        for row in rows:
            shape = (row['arguments']['limit'], 'after_id' in row['arguments'])
            need(shape in by_shape, 'fixed RPC shape has no trace call')
            call = by_shape.pop(shape)
            call_events = calls[str(call)]
            outcome = once(call_events, 'caller_result_ready')
            need(outcome['value'] == int(not row['okay']) and row['write_attempts'] == 1
                 and row['sent'] is True and row['response_received'] is True, 'trace/report original outcome differs')
            registrations = [event for event in call_events if event['phase'] in ('cohort_leader', 'cohort_follower')]
            need(len(registrations) == 1, 'one observed cohort registration required')
            group = registrations[0]['cohort']
            frozen = once(cohorts[str(group)], 'cohort_frozen')
            summary = {name: {'count': len(values), 'sum_recorded_us': sum(x['recorded_elapsed_us'] for x in values),
                             'max_recorded_us': max(x['recorded_elapsed_us'] for x in values)}
                       for name, values in stage_map[str(call)].items()}
            correlated.append({'slot': row['slot'], 'wave': row['wave'], 'rpc_id': row['rpc_id'],
                'query': row['query_name'], 'trace_call': call, 'cohort': group,
                'cohort_members': frozen['value'], 'registration': registrations[0],
                'api_enter': once(call_events, 'api_enter'), 'caller_result_ready': outcome,
                'client_elapsed_ms': row['elapsed_ms'], 'status': row['status'],
                'stage_summary': summary})
        prior_end = max(once(calls[str(call)], 'caller_scope_end')['at_us'] for call in wave_calls)
    need(next_call == 23 and len(correlated) == 20, 'all fixed measured calls required')
    failed = [row for row in correlated if row['status'] != 'succeeded']
    need(len(failed) == 1 and failed[0]['trace_call'] == 18 and failed[0]['rpc_id'] == 19
         and failed[0]['slot'] == 14 and failed[0]['wave'] == 6, 'failed original attribution differs')
    first = once(cohorts['13'], 'cohort_frozen')
    later = once(calls['18'], 'api_enter')
    wait = max(stage_map['18']['store_lock_wait'], key=lambda row: row['recorded_elapsed_us'])
    incomplete_validation = stage_map['18']['complete_original_verification'][0]
    need(first['value'] == 3 and later['at_us'] > first['at_us']
         and once(cohorts['16'], 'cohort_frozen')['value'] == 1
         and wait['recorded_elapsed_us'] == 2159223
         and incomplete_validation['begin']['remaining_us'] == 839130
         and incomplete_validation['end']['remaining_us'] < 0
         and 'page_or_usage_projection' not in stage_map['18']
         and 'snapshot_final_fences' not in stage_map['18'], 'observed split/wait/deadline boundary differs')
    result = {'schema': 'hepta-a53-diagnostic-independent-trace-audit/v1', 'passed': True,
        'operator_job_id': '1a1787ff36a-96a-123b', 'original_pins': PINS,
        'actual_qualification_sha256': Q_SHA, 'actual_source_map_sha256': MAP_SHA,
        'actual_source_files': 175, 'actual_release_sha256': ELF_SHA,
        'full_stderr_and_capture_sha256_verified': True, 'independent_stderr_event_reparse_equal': True,
        'event_count': len(events), 'dropped_events': dropped, 'sequence_complete': True,
        'original_controller_custody': shutdown, 'fixture_witnesses_verified_from_report_only': True,
        'diagnostic_complete': True, 'diagnostic_product_passed': False, 'performance_adopted': False,
        'planned_calls': 20, 'successful': 19, 'failed': 1, 'unexecuted': 0,
        'correlated_measured_calls': correlated,
        'frozen_cohorts': [row for row in events if row['phase'] == 'cohort_frozen'],
        'failure_boundary': {'earlier_cohort': 13, 'earlier_members': 3, 'later_cohort': 16,
            'later_members': 1, 'later_api_after_earlier_freeze_us': later['at_us'] - first['at_us'],
            'earlier_full_validation': stage_map['15']['complete_original_verification'][0],
            'later_store_wait': wait, 'later_validation_until_error': incomplete_validation,
            'failed_call_events': calls['18'], 'earlier_group_events': cohorts['13']},
        'scope': ['This diagnosis uses the same qualified A53 ELF and its opt-in local trace.',
                  'A complete original stderr independently proves a 3+1 cohort split in this diagnostic wave and the later group store wait consuming its original deadline.',
                  'RPC attribution uses one fixed sequential diagnostic wave and its four unique limit/cursor shapes; trace call numbers are not RPC IDs.',
                  'Raw request/reply files were not downloaded by this three-original audit; their offsets and hashes remain the pinned report claims.',
                  'The later verification stage ended in error at deadline. Its 839147us duration is an incomplete verification, not a full-scan performance sample.',
                  'Trace can perturb scheduling. No claim that this diagnoses the untraced large comparison failures or estimates their frequency.',
                  'No retry, timeout/window change, result reuse, omitted original validation or new remote execution occurred.']}
    body = (json.dumps(result, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
    path = DOCS / 'metadata-diagnostic.independent-audit.json'
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(body)
    print(json.dumps({'path': str(path), 'bytes': len(body), 'sha256': sha(body),
                      'passed': True, 'failed_trace_call': 18, 'failed_rpc_id': 19,
                      'split': [3, 1], 'store_wait_us': wait['recorded_elapsed_us']}, sort_keys=True))


if __name__ == '__main__':
    main()

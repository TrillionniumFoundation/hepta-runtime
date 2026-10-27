#!/usr/bin/env python3
"""Reconcile all A55 diagnostic stderr events and the fixed original schedule.

Offline only. The three captured originals do not contain the RPC wire bodies
or every fixture body; those scopes remain explicitly outside this trace audit.
"""
import base64
from collections import defaultdict
import gzip
import hashlib
import io
import json
from pathlib import Path
import stat

WORKSPACE = Path(__file__).resolve().parent.parent
DOCS = WORKSPACE / 'runtime-resume/docs/experiments/x230/a55'
REMOTE = '/home/qian/hepta-runtime-optimization-20261023/a41-phase-timing-20261025-r01'
TRACE_ROOT = REMOTE + '/a55-metadata-diagnostic-r01'
ARCHIVE_SHA = 'ba2865c5066b42ab52d5b648814852a9e15f2bc3d3238de9a24c11d3452ee166'
EXPANDED_SHA = 'c7350e3f45255f76313c1e9a5b4a0b64b0c9b85a80027d37b807058acf07a4df'
PINS = {'report.json': (252970, 'f68d9e041dfedbbcee2428a2e91a9d8261e71da52c44e778c70c68671518c1c7'), 'metadata-trace.json': (2281630, 'c87694a39753ac382cbbc8821929310069a235a832f236e698ee24f34a442a69'), 'controller-0-B/stderr.log': (770538, '1ccc5766467d3c3578dd9beaa1e628a5d0a301cbbe637587a0bc62a36a0e973a')}
QUALIFICATION_SHA = '67abac1fa0c3a0b496b0101a551ce828e697d43fd94b9de82ecc5875d9f16688'
ELF_SHA = 'e78eae3e563ef4112f1639cc833a4023e91c6b27a26b02e93b2a541a95f34014'
MAP_SHA = '03537b606d582b5c1cd85e5a24d3ff99044e258ac3cebc1c5abb16c04affa447'

ACTUAL_TRACE = {'archive_bytes': 776727, 'expanded_bytes': 4408601, 'event_count': 3483, 'cohort_count': 11, 'diagnostic_job': '1a179d51c68-96a-13ef', 'transport_job': '1a179db1c4f-96a-13f9', 'failed_slots': [9, 10, 13, 14, 17, 18], 'setup_okay': [True, False, True]}
PHASE_KERNEL_SHA = 'b6cc6d091de52c2ce062aac1e2abb7fdf1645ecc21d04c205ced5aba6c7d6f19'


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read_pin(path, digest, size=None):
    before = path.stat()
    raw = path.read_bytes()
    after = path.stat()
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
              'st_size', 'st_mtime_ns', 'st_ctime_ns')
    need(all(getattr(before, k) == getattr(after, k) for k in fields)
         and sha(raw) == digest and (size is None or len(raw) == size), 'pinned local input changed')
    return raw


def trace_bindings_ready():
    keys = {'archive_bytes', 'expanded_bytes', 'event_count', 'cohort_count',
            'diagnostic_job', 'transport_job', 'failed_slots', 'setup_okay'}
    if type(ACTUAL_TRACE) is not dict or set(ACTUAL_TRACE) != keys:
        return False
    if any(type(value) is not str or len(value) != 64
           or any(c not in '0123456789abcdef' for c in value)
           for value in (ARCHIVE_SHA, EXPANDED_SHA)):
        return False
    if any(type(ACTUAL_TRACE[key]) is not int or not 0 < ACTUAL_TRACE[key] <= 8 * 1024 * 1024
           for key in ('archive_bytes', 'expanded_bytes', 'event_count', 'cohort_count')):
        return False
    if ACTUAL_TRACE['cohort_count'] > 22:
        return False
    slots, setup = ACTUAL_TRACE['failed_slots'], ACTUAL_TRACE['setup_okay']
    if (type(slots) is not list or len(slots) != 6
            or any(type(n) is not int or not 0 <= n < 20 for n in slots)
            or sorted(set(slots)) != slots or type(setup) is not list or len(setup) != 3
            or any(type(value) is not bool for value in setup) or not setup[0] or not setup[2]):
        return False
    return (ACTUAL_TRACE['diagnostic_job'] == '1a179d51c68-96a-13ef'
            and type(ACTUAL_TRACE['transport_job']) is str and bool(ACTUAL_TRACE['transport_job']))


def main():
    need(trace_bindings_ready(), 'actual completed A55 transport and trace outcome bindings required before any file access')
    packed = read_pin(DOCS / 'metadata-diagnostic-originals.transport.json.gz', ARCHIVE_SHA, ACTUAL_TRACE['archive_bytes'])
    with gzip.GzipFile(fileobj=io.BytesIO(packed)) as stream:
        expanded = stream.read(8 * 1024 * 1024 + 1)
        need(stream.read(1) == b'', 'transport expansion exceeds cap')
    need(len(expanded) == ACTUAL_TRACE['expanded_bytes'] and sha(expanded) == EXPANDED_SHA, 'transport expansion differs')
    bundle = json.loads(expanded)
    need(bundle['schema'] == 'hepta-a55-diagnostic-three-originals-transport/v1'
         and bundle['root'] == TRACE_ROOT and set(bundle['files']) == set(PINS)
         and bundle['semantic_trace_acceptance_evaluated'] is False, 'transport scope differs')
    originals = {}
    for name, (size, digest) in PINS.items():
        row = bundle['files'][name]
        raw = base64.b64decode(row['base64'], validate=True)
        identity = row['stat9']
        need(len(raw) == row['bytes'] == size and sha(raw) == row['sha256'] == digest
             and row['path'] == TRACE_ROOT + '/' + name, 'captured original bytes differ')
        need(len(identity) == 9 and all(type(v) is int for v in identity)
             and identity[2] == 1000 and stat.S_ISREG(identity[4]) and not identity[4] & 0o077
             and identity[5] == 1 and identity[6] == size
             and row['version'] == ':'.join(str(identity[i]) for i in (0, 1, 6, 7, 8)),
             'captured private original identity differs')
        originals[name] = raw
    need(sum(map(len, originals.values())) == 3305138, 'original byte count differs')

    def receipt(name, expected, with_path=True, without_gid=False):
        row = bundle['files'][name]
        # Transport: dev,ino,uid,gid,mode,nlink,size,mtime,ctime.
        # Original diagnostic driver: dev,ino,mode,uid,gid,nlink,size,mtime,ctime.
        value = [row['stat9'][i] for i in (0, 1, 4, 2, 3, 5, 6, 7, 8)]
        if without_gid:
            value = value[:4] + value[5:]
        need(expected['bytes'] == row['bytes'] and expected['sha256'] == row['sha256']
             and expected['identity'] == value
             and (not with_path or expected['path'] == row['path']), 'original report receipt differs')

    report = json.loads(originals['report.json'])
    trace = json.loads(originals['metadata-trace.json'])
    stderr = originals['controller-0-B/stderr.log']
    need(report['schema'] == 'hepta-a55-metadata-diagnostic/v1'
         and report['complete'] is True and report['product_passed'] is False
         and report['attempted'] == report['planned_calls'] == 20 and report['planned_waves'] == 8
         and report['successful'] == 14 and report['failed'] == 6 and report['unexecuted'] == 0
         and report['errors'] == [] and report['automatic_retries'] == 0
         and report['performance_adopted'] is report['baseline_comparison']
         is report['prior_results_pooled'] is report['service_changes'] is False
         and report['original_deadlines_preserved'] is True and report['ssh_or_agent_accesses'] == 0,
         'actual diagnostic scope/outcome differs')
    receipt('metadata-trace.json', report['trace']['artifact'])
    receipt('controller-0-B/stderr.log', trace['stderr'])
    need(len(report['controllers']) == 1 and report['original_controller_complete'] is True,
         'one original controller required')
    controller = report['controllers'][0]
    need(controller['index'] == 0 and controller['arm'] == 'B' and controller['status'] == 'complete'
         and controller['errors'] == [] and controller['original_fixture_unchanged'] is True,
         'original diagnostic controller differs')
    receipt('controller-0-B/stderr.log', controller['shutdown']['files']['stderr.log'], False, True)
    setup = controller['setup']
    need([r['purpose'] for r in setup] == ['native_seed', 'index_kickoff', 'archive_warmup']
         and [r['rpc_id'] for r in setup] == [2, 3, 4]
         and [r['okay'] for r in setup] == ACTUAL_TRACE['setup_okay']
         and report['all_setup_successful'] == all(ACTUAL_TRACE['setup_okay']), 'setup success/failure changed')
    shutdown = controller['shutdown']
    need(shutdown['original_child_reaped'] is True and shutdown['method'] == 'stdin_eof'
         and shutdown['waited']['exit_code'] == 0
         and shutdown['waited']['pid'] == controller['startup']['pid']
         and shutdown['reader_error'] is None and shutdown['reader_stop']['eof_observed'] is True
         and shutdown['raw_stdout_eof_captured'] is True
         and shutdown['reader_stop']['outstanding_original_rpc_ids'] == []
         and shutdown['received_response_ids'] == list(range(1, 25))
         and shutdown['unmatched'] == shutdown['protocol_violations'] == shutdown['errors'] == []
         and shutdown['first_termination_signal'] is None
         and report['custody_adapter'] == [{'close_attempted': True, 'close_returned': True,
              'fallback_used': False, 'original_child_reaped': True}], 'original custody differs')
    witnesses = [controller[k] for k in ('fixture_after_generation', 'fixture_before_measurement',
                                        'fixture_after_measurement', 'fixture_after_shutdown')]
    for field in ('anchor', 'counts', 'directories', 'identity_map_sha256', 'content_map_sha256', 'owner_counts'):
        need(all(w[field] == witnesses[0][field] for w in witnesses), 'reported original fixture changed')
    need(all(type(w['complete_record_body_reads']) is int and w['complete_record_body_reads'] == 66048
             and w['counts'] == {'archive': 65536, 'hot': 512} for w in witnesses),
         'reported body witness incomplete')

    qualification = json.loads(read_pin(WORKSPACE / 'ci-audit/a55/qualification-actual-r01/qualification.original.json', QUALIFICATION_SHA, 61968))
    need(qualification['qualified'] is True and qualification['source_tested'] == qualification['source_after']
         and len(qualification['source_tested']) == 175
         and sha(json.dumps(qualification['source_tested'], sort_keys=True,
                            separators=(',', ':')).encode()) == MAP_SHA
         and qualification['binary']['sha256'] == ELF_SHA, 'actual qualification differs')
    need(report['source_before'] == report['source_after']
         and set(report['source_before']) == set(qualification['source_tested'])
         and all(row['sha256'] == qualification['source_tested'][name]
                 for name, row in report['source_before'].items())
         and report['binary_before'] == report['binary_after']
         and report['binary_before']['sha256'] == controller['release_sha256'] == ELF_SHA
         and report['input_receipts_before'] == report['input_receipts_after']
         and len(report['input_receipts_before']) == 7,
         'source/release/input before-after fences differ')
    need([r['sha256'] for r in report['input_receipts_before'][:5]] == [
        '7f9b13773c6ea5e143e6b7d0484b5af840e152d68cb0801600feb4f95266b9f9',
        '43d1dfe9b173b0eba620fe9b5fd4140666aa66359f4e4845398ac484a4644bfb',
        QUALIFICATION_SHA, '50c8272612c8f923b496279aff37da51f75eb4b50de789f283840064d425dd3b',
        '3256f99182d1d3b73c6e289cbe634bf84ff33b4f60694c65c59db5c84a735a8a'],
        'actual diagnostic inputs differ')
    binding = report['trace_binding']
    base_env = {'LANG': 'C', 'PATH': '/usr/bin:/bin', 'RUST_LOG': 'warn',
                'SHELL': '/bin/sh', 'TOKIO_WORKER_THREADS': '2'}
    expected_env = {**base_env, 'HEPTA_METADATA_TRACE': '1', 'HEPTA_ARCHIVE_INDEX_TRACE': '1'}
    need(binding['environment_before'] == base_env and binding['environment_after'] == expected_env
         and controller['startup']['environment'] == expected_env
         and binding['only_two_environment_entries_changed'] is True
         and binding['original_main_called'] is binding['original_performance_summary_called'] is False,
         'trace environment scope differs')
    phase_sources = {}
    inherited = WORKSPACE / 'ci-audit/a53-r02/small-original-audit-local-r01/evidence/source-a53-bounded-direct-ssh-r02'
    for name in ('request_metadata_trace.rs', 'request_archive_batch.rs', 'request_archive_index.rs',
                 'request_archive_content.rs'):
        relative = 'src/mcp/runtime/' + name
        path = (inherited if name == 'request_archive_batch.rs' else WORKSPACE / 'runtime-a55-qualified') / relative
        raw = read_pin(path, qualification['source_tested'][relative])
        phase_sources[relative] = {'bytes': len(raw), 'sha256': sha(raw), 'local_path': str(path)}

    events, dropped, offset = [], 0, 0
    fields = {'sequence', 'call', 'tool', 'phase', 'kind', 'at_us', 'call_us',
              'remaining_us', 'cohort', 'value', 'limit', 'cursor'}
    for number, line in enumerate(stderr.splitlines(keepends=True), 1):
        marker = line.find(b'hepta_metadata_trace ')
        if marker >= 0:
            value = json.loads(line[marker + len(b'hepta_metadata_trace '):])
            if 'dropped_events' in value:
                need(set(value) == {'dropped_events'} and type(value['dropped_events']) is int,
                     'dropped marker differs')
                dropped += value['dropped_events']
            else:
                need(set(value) == fields and type(value['cursor']) is bool
                     and value['kind'] in ('event', 'begin', 'end')
                     and all(type(value[k]) is int for k in fields - {'tool', 'phase', 'kind', 'cursor'})
                     and value['call'] > 0 and value['sequence'] > 0, 'closed trace event differs')
                value.update(stderr_line=number, stderr_byte_offset=offset, raw_line_sha256=sha(line))
                events.append(value)
        offset += len(line)
    events.sort(key=lambda v: v['sequence'])
    need(len(events) == ACTUAL_TRACE['event_count'] and dropped == 0
         and [r['sequence'] for r in events] == list(range(1, len(events) + 1)),
         'complete diagnostic event sequence required')
    calls, cohorts = defaultdict(list), defaultdict(list)
    for event in events:
        calls[event['call']].append(event)
        if event['cohort']:
            cohorts[event['cohort']].append(event)
    need(events == trace['events'] and {str(k): v for k, v in calls.items()} == trace['calls']
         and {str(k): v for k, v in cohorts.items()} == trace['cohorts']
         and trace['parse_errors'] == [] and trace['dropped_events'] == 0
         and trace['sequence_complete'] is trace['complete_capture'] is True
         and report['trace']['event_count'] == len(events) and report['trace']['call_count'] == 22
         and report['trace']['cohort_count'] == ACTUAL_TRACE['cohort_count'] and report['trace']['complete_capture'] is True,
         'independently reconstructed trace differs from original capture')
    need(set(calls) == set(range(1, 23)) and len(cohorts) == ACTUAL_TRACE['cohort_count'],
         'fixed call inventory differs')

    def one(call, phase, kind='event'):
        found = [v for v in calls[call] if v['phase'] == phase and v['kind'] == kind]
        need(len(found) == 1, 'expected one event: ' + str(call) + '/' + phase)
        return found[0]

    stage_pairs = {}
    for call, rows in calls.items():
        stacks, finished = defaultdict(list), defaultdict(list)
        for row in rows:
            if row['kind'] == 'begin':
                stacks[row['phase']].append(row)
            elif row['kind'] == 'end':
                need(stacks[row['phase']], 'stage end without a begin')
                begin = stacks[row['phase']].pop()
                need(begin['sequence'] < row['sequence'] and row['at_us'] - begin['at_us'] >= row['value'] >= 0,
                     'stage timing order differs')
                finished[row['phase']].append({'begin': begin, 'end': row, 'elapsed_us': row['value']})
        need(not any(stacks.values()), 'unclosed trace stage')
        stage_pairs[call] = finished

    def shape(arguments):
        return arguments['limit'], 'after_id' in arguments

    def caller_success(call):
        ready = one(call, 'caller_result_ready')
        late = [v for v in calls[call] if v['phase'] == 'caller_late_result']
        need(ready['value'] in (0, 1) and len(late) <= 1, 'caller outcome markers differ')
        if late:
            need(ready['value'] == 0 and late[0]['kind'] == 'event' and late[0]['value'] == 1
                 and late[0]['sequence'] > ready['sequence'] and late[0]['remaining_us'] <= 0,
                 'late caller result must follow ready success at the original deadline')
        return ready['value'] == 0 and not late

    need(one(1, 'api_enter')['tool'] == 'usage_stats'
         and caller_success(1) == ACTUAL_TRACE['setup_okay'][1]
         and one(2, 'api_enter')['tool'] == 'request_archive' and caller_success(2),
         'kickoff/warmup trace result differs')
    need(len(report['slots']) == 20 and len(report['waves']) == 8, 'fixed diagnostic schedule differs')
    correlated, group_members = [], defaultdict(list)
    next_call, prior_result = 3, one(2, 'caller_result_ready')['at_us']
    for wave_index, wave in enumerate(report['waves']):
        rows = [report['slots'][slot] for slot in wave['slot_ids']]
        count = 1 if wave_index < 4 else 4
        window = list(range(next_call, next_call + count))
        next_call += count
        need(wave['wave'] == wave_index and wave['attempted'] == wave['concurrency'] == count
             and wave['all_original_wave_replies_received'] is True
             and wave['protocol_violations'] == wave['terminal_transport_unknown_slot_ids'] == []
             and wave['fatal'] is False and len(rows) == count, 'whole original wave differs')
        need(prior_result < min(one(call, 'api_enter')['at_us'] for call in window),
             'trace windows do not follow the original closed waves')
        prior_result = max(one(call, 'caller_result_ready')['at_us'] for call in window)
        by_shape = {(one(call, 'api_enter')['limit'], one(call, 'api_enter')['cursor']): call for call in window}
        need(len(by_shape) == count and len({shape(row['arguments']) for row in rows}) == count,
             'ambiguous diagnostic query shape')
        for row in rows:
            call = by_shape[shape(row['arguments'])]
            api, ready = one(call, 'api_enter'), one(call, 'caller_result_ready')
            groups = {v['cohort'] for v in calls[call] if v['cohort']}
            need(len(groups) == 1 and row['rpc_id'] == row['slot'] + 5
                 and row['write_attempts'] == 1 and row['sent'] is row['response_received'] is True
                 and row['automatic_retry'] is False and row['single_wave_os_write'] is True
                 and row['client_pending_ids_at_write'] == wave['client_pending_ids_at_write']
                 and row['tool'] == api['tool'] == 'request_archive'
                 and caller_success(call) == row['okay'],
                 'unique fixed-fixture call/result correspondence differs')
            group = groups.pop()
            group_members[group].append(call)
            queues = [v for v in calls[call] if v['phase'] == 'blocking_submitted']
            correlated.append({'slot': row['slot'], 'wave': wave_index, 'position': row['position'],
                'rpc_id_from_original_report': row['rpc_id'], 'query_name': row['query_name'],
                'trace_call': call, 'cohort': group, 'okay': row['okay'], 'original_error': row.get('error'),
                'api_enter': api, 'caller_result_ready': ready,
                'caller_late_result': [v for v in calls[call] if v['phase'] == 'caller_late_result'],
                'permit_wait_us': one(call, 'permit_acquired')['at_us'] - one(call, 'permit_wait')['at_us'],
                'blocking_queue_us': (one(call, 'blocking_entered')['at_us'] - queues[0]['at_us']) if queues else None,
                'stage_totals_us': {k: {'count': len(v), 'sum': sum(p['elapsed_us'] for p in v),
                                       'maximum': max(p['elapsed_us'] for p in v)}
                                    for k, v in stage_pairs[call].items()}})
    correlated.sort(key=lambda r: r['slot'])
    need([r['slot'] for r in correlated] == list(range(20))
         and [r['slot'] for r in correlated if not r['okay']] == ACTUAL_TRACE['failed_slots']
         and sum(r['okay'] for r in correlated) == report['successful'] == 14
         and report['all_diagnostic_calls_correct'] is False, 'six actual failed slots differ')
    groups = {}
    for group, members in group_members.items():
        frozen = [v for v in cohorts[group] if v['phase'] == 'cohort_frozen']
        complete = [v for v in cohorts[group] if v['phase'] == 'cohort_complete']
        need(len(frozen) == len(complete) == 1 and frozen[0]['value'] == len(members), 'cohort size/terminal differs')
        leader = frozen[0]['call']
        need(leader in members and one(leader, 'cohort_leader')['cohort'] == group,
             'frozen cohort leader differs')
        own = [r for r in correlated if r['cohort'] == group]
        need(len(own) == len(members) and len({r['wave'] for r in own}) == 1,
             'diagnostic cohort crosses a closed client wave')
        groups[group] = {'cohort': group, 'leader_call': leader, 'members': sorted(members),
                         'slots': sorted(r['slot'] for r in own), 'wave': own[0]['wave'],
                         'all_successful': all(r['okay'] for r in own), 'frozen': frozen[0],
                         'complete': complete[0], 'leader_stages': dict(stage_pairs[leader])}

    # Record only timing boundaries actually proved by the original events.
    # The number/size of newly observed cohorts is not borrowed from A54.
    boundaries = []
    failed_groups = [v for v in groups.values() if not v['all_successful']]
    for late in sorted(failed_groups, key=lambda v: (v['wave'], v['frozen']['at_us'])):
        late_scans = late['leader_stages'].get('complete_original_verification', [])
        waits = late['leader_stages'].get('store_lock_wait', [])
        if len(late_scans) != 1 or not waits:
            continue
        late_scan = late_scans[0]
        wait = max(waits, key=lambda v: v['elapsed_us'])
        if late_scan['end']['remaining_us'] >= 0 or 'page_or_usage_projection' in late['leader_stages']:
            continue
        candidates = sorted([v for v in groups.values() if v['wave'] == late['wave']
            and v['frozen']['at_us'] < late['frozen']['at_us']], key=lambda v: v['frozen']['at_us'])
        for early in candidates:
            early_scans = early['leader_stages'].get('complete_original_verification', [])
            early_finals = early['leader_stages'].get('snapshot_final_fences', [])
            if len(early_scans) != 1 or len(early_finals) != 1 or not early['all_successful']:
                continue
            earlier_api = early['frozen']['at_us']
            later_api = min(one(call, 'api_enter')['at_us'] for call in late['members'])
            early_scan, final = early_scans[0], early_finals[0]
            if not (later_api > earlier_api and wait['begin']['at_us'] < early_scan['end']['at_us']
                    and wait['end']['at_us'] > final['end']['at_us']):
                continue
            boundaries.append({'wave': late['wave'], 'early_cohort': early['cohort'],
                'late_cohort': late['cohort'], 'early_members': early['members'],
                'late_members': late['members'],
                'failed_slots': sorted(r['slot'] for r in correlated
                                      if r['cohort'] == late['cohort'] and not r['okay']),
                'later_api_after_earlier_freeze_us': later_api - earlier_api,
                'earlier_full_validation': early_scan, 'later_store_wait': wait,
                'earlier_final_fences': final, 'later_validation_until_error': late_scan,
                'later_scan_remaining_at_begin_us': late_scan['begin']['remaining_us'],
                'later_complete': late['complete']})

    kernel_path = WORKSPACE / 'multihost-review/a55_content_phase_audit_pending.py'
    kernel_raw = read_pin(kernel_path, PHASE_KERNEL_SHA, 7396)
    kernel = {'__name__': 'a55_verified_pure_phase_kernel'}
    exec(compile(kernel_raw, str(kernel_path), 'exec'), kernel)
    successful_calls = {call for call in calls if caller_success(call)}
    aggregate = kernel['audit_aggregate_events'](events, stage_pairs, successful_calls, 65536)
    accounted_groups = {v['late_cohort'] for v in boundaries}
    unclassified_failure_groups = [g['cohort'] for g in failed_groups if g['cohort'] not in accounted_groups]

    result = {'schema': 'hepta-a55-diagnostic-independent-trace-audit/v1', 'passed': True,
        'original_operator_job_id': ACTUAL_TRACE['diagnostic_job'],
        'transport_operator_job_id': ACTUAL_TRACE['transport_job'],
        'diagnostic_complete': True, 'diagnostic_product_passed': False, 'performance_adopted': False,
        'planned_calls': 20, 'successful': 14, 'failed': 6, 'unexecuted': 0,
        'full_transport_and_all_three_original_hashes_verified': True,
        'independent_stderr_event_reparse_equal': True, 'event_count': len(events),
        'call_count': len(calls), 'cohort_count': len(cohorts), 'dropped_events': dropped,
        'sequence_complete': True, 'all_stage_begin_end_pairs_closed': True,
        'actual_qualification_sha256': QUALIFICATION_SHA, 'actual_release_sha256': ELF_SHA,
        'actual_source_map_sha256': MAP_SHA, 'actual_source_files': 175,
        'original_pins': PINS, 'phase_semantic_source_pins': phase_sources,
        'original_controller_custody': shutdown, 'correlated_measured_calls': correlated,
        'cohorts': list(groups.values()), 'failure_boundaries': boundaries,
        'failure_cohorts_without_proven_prior_scan_wait_boundary': unclassified_failure_groups,
        'aggregate_phase_audit': aggregate,
        'aggregate_kernel': {'bytes': len(kernel_raw), 'sha256': sha(kernel_raw)},
        'kickoff_stage_totals_us': {k: {'count': len(v), 'sum': sum(p['elapsed_us'] for p in v)}
                                   for k, v in stage_pairs[1].items()},
        'warmup_full_validation': stage_pairs[2]['complete_original_verification'][0],
        'fixture_witnesses_verified_from_report_only': True,
        'scope': [
            'All three original bytes and every stderr trace event are independently reconciled.',
            'Call/RPC correspondence uses this complete fixed report schedule, closed client waves, and unique limit/cursor shapes; no general RPC identity is inferred.',
            'The three-file capture does not contain RPC wire bodies or full fixture bodies; their original report receipts are not relabeled as independent body audits.',
            'Source/ELF and all fixture before-after witnesses are checked against the original report and actual qualification; the four local phase-semantic sources are physically SHA-pinned.',
            'Each listed failure boundary independently proves overlap with an earlier full scan/final fence followed by deadline expiry during the late cohort own fresh validation. Unclassified cohorts are not assigned this cause.',
            'The separately reviewed serial kernel adds fifteen wall-time phase totals and attempted/verified/complete counters per scan. These are aggregate phase measurements, not per-record samples, CPU time or allocation counts.',
            'A complete serial kernel can still be followed by projection, final-fence or caller deadline failure. No full-scan success is substituted for actual RPC success.',
            'Why the later calls entered API after the earlier freeze is outside this trace; executor or ingress causation is not inferred.',
            'Trace flush perturbs scheduling. This A55 diagnostic neither proves uninstrumented throughput nor rewrites the earlier failed A54 large attempt or diagnostic.',
        ]}
    output = DOCS / 'metadata-diagnostic.independent-audit.json'
    encoded = (json.dumps(result, indent=2, sort_keys=True) + '\n').encode()
    need(not output.exists(), 'fresh audit output required')
    output.write_bytes(encoded)
    print(json.dumps({'passed': True, 'path': str(output), 'bytes': len(encoded), 'sha256': sha(encoded),
                      'events': len(events), 'calls': len(calls), 'failed_slots': ACTUAL_TRACE['failed_slots'],
                      'aggregate_scans': aggregate['aggregate_scan_count']}, sort_keys=True))


if __name__ == '__main__':
    main()

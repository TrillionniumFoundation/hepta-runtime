#!/usr/bin/env python3
"""Reconcile all A54 diagnostic stderr events and the fixed original schedule.

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
DOCS = WORKSPACE / 'runtime-resume/docs/experiments/x230/a54'
REMOTE = '/home/qian/hepta-runtime-optimization-20261023/a41-phase-timing-20261025-r01'
TRACE_ROOT = REMOTE + '/a54-metadata-diagnostic-r01'
ARCHIVE_SHA = 'c9b50b7d398250fe8dec9385f3dae018f6ae4723b7ddd7bfb99d8d2b3ba3d0df'
EXPANDED_SHA = '8813aef3bdcf04111134729aa6b7adcebc02e3d3c8897db5ca4c2d581a16a1a0'
PINS = {
    'report.json': (253563, 'c70f16ffff603b61066c54fe1072e6be90eaf623a49dd5b4c082108c9caeba90'),
    'metadata-trace.json': (2094395, '95d9d4950c7dde03fab4bf35ad1247f2b94d1b91e8e625101d0d91c3f199673e'),
    'controller-0-B/stderr.log': (705729, '5a213203bd0fa9fb426c9f08de7e81cac11923ab8609b3aa9271bbdcb3912e65'),
}
QUALIFICATION_SHA = '49b0019ece7405d455ace8cb638080a203a24fca01c6985a6cdda6d51180a51c'
ELF_SHA = 'd2134c1b2b1999f46f0808b0d523ae51f54821c09afa6ecbf8188c883bbf3d70'
MAP_SHA = '7d4143971feeb9b1fcbf1f3e567ba367c36770cdf050fe496b1e2778a1025176'


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


def main():
    packed = read_pin(DOCS / 'metadata-diagnostic-originals.transport.json.gz', ARCHIVE_SHA, 718166)
    with gzip.GzipFile(fileobj=io.BytesIO(packed)) as stream:
        expanded = stream.read(8 * 1024 * 1024 + 1)
        need(stream.read(1) == b'', 'transport expansion exceeds cap')
    need(len(expanded) == 4073329 and sha(expanded) == EXPANDED_SHA, 'transport expansion differs')
    bundle = json.loads(expanded)
    need(bundle['schema'] == 'hepta-a54-diagnostic-three-originals-transport/v1'
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
    need(sum(map(len, originals.values())) == 3053687, 'original byte count differs')

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
    need(report['schema'] == 'hepta-a54-metadata-diagnostic/v1'
         and report['complete'] is True and report['product_passed'] is False
         and report['attempted'] == report['planned_calls'] == 20 and report['planned_waves'] == 8
         and report['successful'] == 16 and report['failed'] == 4 and report['unexecuted'] == 0
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
         and [r['okay'] for r in setup] == [True, False, True]
         and report['all_setup_successful'] is False, 'setup success/failure changed')
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

    qualification = json.loads(read_pin(DOCS / 'qualification-r01.original.json', QUALIFICATION_SHA, 61986))
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
        '3515bf348ff803e7f43dda8ee43cfbfc9b0596150682213536c6502328c3535a',
        '9f03083dcb6754952ea27ae531dd5f353119704257ffb56e43dcb180052eafc1',
        QUALIFICATION_SHA, 'a98b564f5db07c64b497b68098902192f71f7be6884e687e68b38e9e41f3e6c3',
        'b7ee93502f5ba0a3861e4578da8301ebac9af8ceb9e1b535ad2e5a8c6af73a90'],
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
        path = (WORKSPACE / 'runtime-a54-qualified' if name == 'request_archive_content.rs' else inherited) / relative
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
    need(len(events) == 3206 and dropped == 0 and [r['sequence'] for r in events] == list(range(1, 3207)),
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
         and report['trace']['event_count'] == 3206 and report['trace']['call_count'] == 22
         and report['trace']['cohort_count'] == 10 and report['trace']['complete_capture'] is True,
         'independently reconstructed trace differs from original capture')
    need(set(calls) == set(range(1, 23)) and len(cohorts) == 10, 'fixed call inventory differs')

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

    need(one(1, 'api_enter')['tool'] == 'usage_stats' and one(1, 'caller_result_ready')['value'] == 1
         and one(2, 'api_enter')['tool'] == 'request_archive'
         and one(2, 'caller_result_ready')['value'] == 0, 'kickoff/warmup trace result differs')
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
                 and (ready['value'] == 0) == row['okay']
                 and not any(v['phase'] == 'caller_late_result' for v in calls[call]),
                 'unique fixed-fixture call/result correspondence differs')
            group = groups.pop()
            group_members[group].append(call)
            queues = [v for v in calls[call] if v['phase'] == 'blocking_submitted']
            correlated.append({'slot': row['slot'], 'wave': wave_index, 'position': row['position'],
                'rpc_id_from_original_report': row['rpc_id'], 'query_name': row['query_name'],
                'trace_call': call, 'cohort': group, 'okay': row['okay'], 'original_error': row.get('error'),
                'api_enter': api, 'caller_result_ready': ready,
                'permit_wait_us': one(call, 'permit_acquired')['at_us'] - one(call, 'permit_wait')['at_us'],
                'blocking_queue_us': (one(call, 'blocking_entered')['at_us'] - queues[0]['at_us']) if queues else None,
                'stage_totals_us': {k: {'count': len(v), 'sum': sum(p['elapsed_us'] for p in v),
                                       'maximum': max(p['elapsed_us'] for p in v)}
                                    for k, v in stage_pairs[call].items()}})
    correlated.sort(key=lambda r: r['slot'])
    need([r['slot'] for r in correlated if not r['okay']] == [13, 14, 17, 18], 'four failures differ')
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

    boundaries = []
    for wave in (6, 7):
        pair = sorted([v for v in groups.values() if v['wave'] == wave], key=lambda v: v['frozen']['at_us'])
        need(len(pair) == 2 and all(len(g['members']) == 2 for g in pair)
             and pair[0]['all_successful'] is True and pair[1]['all_successful'] is False,
             'actual two-plus-two split differs')
        early, late = pair
        later_api = min(one(call, 'api_enter')['at_us'] for call in late['members'])
        early_scan = early['leader_stages']['complete_original_verification'][0]
        late_scan = late['leader_stages']['complete_original_verification'][0]
        wait = max(late['leader_stages']['store_lock_wait'], key=lambda v: v['elapsed_us'])
        final = early['leader_stages']['snapshot_final_fences'][0]
        need(later_api > early['frozen']['at_us'] and wait['begin']['at_us'] < early_scan['end']['at_us']
             and wait['end']['at_us'] > final['end']['at_us']
             and late_scan['end']['remaining_us'] < 0
             and 'page_or_usage_projection' not in late['leader_stages'], 'failure boundary differs')
        boundaries.append({'wave': wave, 'early_cohort': early['cohort'], 'late_cohort': late['cohort'],
            'early_members': early['members'], 'late_members': late['members'],
            'failed_slots': late['slots'], 'later_api_after_earlier_freeze_us': later_api - early['frozen']['at_us'],
            'earlier_full_validation': early_scan, 'later_store_wait': wait,
            'earlier_final_fences': final, 'later_validation_until_error': late_scan,
            'later_scan_remaining_at_begin_us': late_scan['begin']['remaining_us'],
            'later_complete': late['complete']})

    result = {'schema': 'hepta-a54-diagnostic-independent-trace-audit/v1', 'passed': True,
        'original_operator_job_id': '1a1799ea398-96a-1326',
        'transport_operator_job_id': '1a179a820fe-96a-1365',
        'diagnostic_complete': True, 'diagnostic_product_passed': False, 'performance_adopted': False,
        'planned_calls': 20, 'successful': 16, 'failed': 4, 'unexecuted': 0,
        'full_transport_and_all_three_original_hashes_verified': True,
        'independent_stderr_event_reparse_equal': True, 'event_count': len(events),
        'call_count': len(calls), 'cohort_count': len(cohorts), 'dropped_events': dropped,
        'sequence_complete': True, 'all_stage_begin_end_pairs_closed': True,
        'actual_qualification_sha256': QUALIFICATION_SHA, 'actual_release_sha256': ELF_SHA,
        'actual_source_map_sha256': MAP_SHA, 'actual_source_files': 175,
        'original_pins': PINS, 'phase_semantic_source_pins': phase_sources,
        'original_controller_custody': shutdown, 'correlated_measured_calls': correlated,
        'cohorts': list(groups.values()), 'failure_boundaries': boundaries,
        'kickoff_stage_totals_us': {k: {'count': len(v), 'sum': sum(p['elapsed_us'] for p in v)}
                                   for k, v in stage_pairs[1].items()},
        'warmup_full_validation': stage_pairs[2]['complete_original_verification'][0],
        'fixture_witnesses_verified_from_report_only': True,
        'scope': [
            'All three original bytes and every stderr trace event are independently reconciled.',
            'Call/RPC correspondence uses this complete fixed report schedule, closed client waves, and unique limit/cursor shapes; no general RPC identity is inferred.',
            'The three-file capture does not contain RPC wire bodies or full fixture bodies; their original report receipts are not relabeled as independent body audits.',
            'Source/ELF and all fixture before-after witnesses are checked against the original report and actual qualification; the four local phase-semantic sources are physically SHA-pinned.',
            'The trace proves these diagnostic late cohorts wait while an earlier cohort holds the store lock for full verification and projection, then expire during their own independent verification.',
            'No per-record ROW/ORDER/stat/open/read/JSON/allocation timings exist; the dominant internal scan cost remains unmeasured.',
            'Why the later calls entered API after the earlier freeze is outside this trace; executor or ingress causation is not inferred.',
            'Trace flush perturbs scheduling. This diagnostic neither proves uninstrumented throughput nor replaces the earlier failed A54 large warmup.',
        ]}
    output = DOCS / 'metadata-diagnostic.independent-audit.json'
    encoded = (json.dumps(result, indent=2, sort_keys=True) + '\n').encode()
    need(not output.exists(), 'fresh audit output required')
    output.write_bytes(encoded)
    print(json.dumps({'passed': True, 'path': str(output), 'bytes': len(encoded), 'sha256': sha(encoded),
                      'events': len(events), 'calls': len(calls), 'failed_slots': [13, 14, 17, 18]}, sort_keys=True))


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Offline independent reconciliation of the fixed A54 eight-job original bytes."""
import argparse
import base64
import gzip
import hashlib
import io
import json
from pathlib import Path
import stat

WORKSPACE = Path(__file__).resolve().parents[2]
DOCS = WORKSPACE / 'runtime-resume/docs/experiments/x230/a54'
BASE = '/home/qian/hepta-runtime-optimization-20261023/a41-phase-timing-20261025-r01'
REMOTE = '/home/qq/hepta-runtime-native-concurrency-a54-r01'
REPORT_SHA = '8ef92163507cb553704262a46afd6d5d3b4bb568234442bed4a7b07759c83ebb'
QUALIFICATION_SHA = '49b0019ece7405d455ace8cb638080a203a24fca01c6985a6cdda6d51180a51c'
ELF_SHA = 'd2134c1b2b1999f46f0808b0d523ae51f54821c09afa6ecbf8188c883bbf3d70'
SOURCE_SHA = '7d4143971feeb9b1fcbf1f3e567ba367c36770cdf050fe496b1e2778a1025176'
PLAN_SHA = '90d19bf8caf8d01e6c7d13449866c9bb48d8501171d5b51271bdc8ef1891ed77'
SELFCHECK_SHA = '121459f02c65addf66e391fd47eef8e47daf7714a277161c4ea54efb804e25d3'
EXITS = [0, 3, 0, 7, 0, 2, 0, 5]
INPUT = b'0123456789abcdef' * 256
NAMES = {'report.json', 'helper-bindings.stdout.original', 'helper-snapshot.stdout.original',
         'business-requests.original.json', 'rpc-mixed-status-and-read.json',
         'rpc-terminal-same-keys.json'}


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def pinned(path, expected):
    raw = path.read_bytes()
    need(sha(raw) == expected, 'local original SHA differs: ' + str(path))
    return raw, json.loads(raw)


def tool(reply):
    need(reply.get('jsonrpc') == '2.0' and 'error' not in reply
         and isinstance(reply.get('result'), dict) and not reply['result'].get('isError'),
         'RPC error or invalid envelope')
    texts = [v['text'] for v in reply['result'].get('content', []) if v.get('type') == 'text']
    need(len(texts) == 1, 'RPC text count differs')
    value = json.loads(texts[0])
    need(value.get('audit_recorded') is True and 'audit_warning' not in value,
         'durable audit acknowledgement absent')
    return value


def main(args):
    need(all(isinstance(value, str) and len(value) == 64
             and all(char in "0123456789abcdef" for char in value)
             for value in (REPORT_SHA, PLAN_SHA, SELFCHECK_SHA)),
         "all actual original evidence bindings are required before reading")
    packed = args.bundle.read_bytes()
    need(len(packed) < 8 * 1024 * 1024 and sha(packed) == args.bundle_sha256,
         'downloaded evidence bundle SHA differs')
    with gzip.GzipFile(fileobj=io.BytesIO(packed)) as source:
        expanded = source.read(16 * 1024 * 1024 + 1)
    need(len(expanded) <= 16 * 1024 * 1024, 'expanded evidence exceeds bound')
    bundle = json.loads(expanded)
    need(bundle['schema'] == 'hepta-a54-native-concurrency-r01-evidence/v1'
         and bundle['report_sha256'] == REPORT_SHA and bundle['automatic_retry'] is False
         and bundle['root'] == BASE + '/a54-native-concurrency-r01'
         and set(bundle['files']) == NAMES, 'capture schema/root/inventory differs')
    captured = {}
    for name, value in bundle['files'].items():
        raw = base64.b64decode(value['base64'], validate=True)
        stamp = value['stat9']
        need(len(raw) == value['bytes'] == stamp[6] and sha(raw) == value['sha256']
             and len(stamp) == 9 and stamp[2] == 1000 and stamp[5] == 1
             and stat.S_ISREG(stamp[4]) and not stamp[4] & 0o077
             and value['path'] == bundle['root'] + '/' + name, 'captured file receipt differs: ' + name)
        captured[name] = raw
    report_raw, report = pinned(DOCS / 'native-concurrency.report.original.json', REPORT_SHA)
    need(captured['report.json'] == report_raw, 'capture has a different original report')
    _, qualification = pinned(DOCS / 'qualification-r01.original.json', QUALIFICATION_SHA)
    plan_raw, plan = pinned(DOCS / 'native-concurrency-plan.original.json', PLAN_SHA)
    _, selfcheck = pinned(DOCS / 'native-concurrency-selfcheck.original.json', SELFCHECK_SHA)
    need(report['passed'] is True and report['errors'] == [] and report['native_phase_complete'] is True
         and report['frozen_inputs_unchanged'] is True and report['automatic_retries'] == 0
         and report['planned_jobs'] == 8, 'original acceptance is not successful')
    need(report['observation_pool_acceptance'] is False and report['performance_improvement_claim'] is False,
         'acceptance scope changed')
    need(report['bundle']['source_map'] == qualification['source_tested'] == qualification['source_after']
         and len(qualification['source_tested']) == report['bundle']['source_files'] == 175
         and sha(json.dumps(qualification['source_tested'], sort_keys=True, separators=(',', ':')).encode()) == SOURCE_SHA
         and sha(canonical(qualification['source_tested'])) == report['bundle']['source_map_sha256']
         == plan['source_map_sha256'], 'full qualified compiler source map differs')
    need(report['bundle']['source'] == BASE + '/source-a54-compact-view-r01'
         and report['bundle']['binary']['sha256'] == qualification['binary']['sha256'] == plan['elf_sha256'] == ELF_SHA
         and report['bundle']['qualification']['sha256'] == QUALIFICATION_SHA,
         'qualified source/ELF identity differs')
    need(selfcheck['passed'] is True and selfcheck['unexecuted'] == []
         and selfcheck['linux_child_custody_supported'] is True and len(selfcheck['checks']) == 9
         and selfcheck['remote_calls'] == selfcheck['business_launches'] == selfcheck['network_connections'] == 0
         and selfcheck['harness_sha256'] == plan['harness']['sha256']
         and selfcheck['base_harness_sha256'] == plan['base_harness']['sha256']
         and selfcheck['selfcheck_sha256'] == plan['selfcheck_source']['sha256'],
         'same-source local custody admission differs')
    inputs = {row['path']: row for row in report['inputs']}
    need(len(inputs) == len(report['inputs']) == 19, 'original input inventory differs')
    for name, expected in [('plan.frozen.json', PLAN_SHA), ('selfcheck-results.json', SELFCHECK_SHA)]:
        need(inputs[BASE + '/a54-native-concurrency-tools-r01/' + name]['sha256'] == expected,
             'plan/selfcheck input receipt differs')
    for name in ('helper-bindings.stdout.original', 'helper-snapshot.stdout.original', 'business-requests.original.json'):
        receipt = bundle['files'][name]
        matches = [r['stdout_receipt'] for r in report['ssh_helpers'] if r['stdout_receipt']['path'] == receipt['path']]
        if name == 'business-requests.original.json':
            matches = [inputs[receipt['path']]]
        need(len(matches) == 1, 'original receipt count differs')
        expected = matches[0]
        need(receipt['bytes'] == expected['bytes'] and receipt['sha256'] == expected['sha256']
             and receipt['stat9'][:3] + receipt['stat9'][4:] == expected['identity'],
             'captured source no longer matches original receipt')
    requests = json.loads(captured['business-requests.original.json'])
    bindings = json.loads(captured['helper-bindings.stdout.original'])
    snapshot = json.loads(captured['helper-snapshot.stdout.original'])
    mixed = json.loads(captured['rpc-mixed-status-and-read.json'])
    final_same = json.loads(captured['rpc-terminal-same-keys.json'])
    records = report['original_records']
    ids = [record['id'] for record in records]
    need(len(records) == len(set(ids)) == len(requests) == 8, 'eight original jobs/requests differ')
    verified_blobs = 0

    def nested(value):
        nonlocal verified_blobs
        raw = base64.b64decode(value['base64'], validate=True)
        stamp = value['stat']
        need(len(stamp) == 8 and len(raw) == value['bytes'] == stamp[5]
             and sha(raw) == value['sha256'] and stamp[2] == 1000 and stamp[4] == 1
             and stat.S_ISREG(stamp[3]) and not stamp[3] & 0o077, 'remote original file receipt differs')
        verified_blobs += 1
        return raw

    remote_plan_raw = nested(snapshot['fixture_plan'])
    remote_plan = json.loads(remote_plan_raw)
    need(nested(bindings['fixture_plan']) == remote_plan_raw == canonical(remote_plan)
         and remote_plan['frozen_local_plan_sha256'] == sha(plan_raw) == PLAN_SHA
         and remote_plan['nonce'] == plan['nonce']
         and remote_plan['remote_identity'] == plan['remote_identity'] == report['actual_remote_identity'],
         'remote fixture is not bound to the independently frozen plan')
    for value, mode in [(bindings, 'bindings'), (snapshot, 'snapshot')]:
        need(value['schema'] == 'hepta-eight-job-remote-fixture-result/v1' and value['mode'] == mode
             and value['business_launches_by_helper'] == value['signals_by_helper'] == 0
             and value['fixture_root'] == REMOTE and value['remote_identity'] == plan['remote_identity']
             and value['plan_sha256'] == sha(canonical(remote_plan))
             and sorted(value['jobs']) == sorted(ids), 'remote helper identity/scope differs')
    names = [f'{i:02}.json' for i in range(8)]
    need(sorted(snapshot['ready']) == sorted(snapshot['effects']) == names,
         'missing or extra ready/effect identity')
    need(report['remote_snapshot_summary'] == {'jobs': sorted(ids), 'ready': names, 'effects': names},
         'report snapshot summary differs from original bytes')
    need(len(mixed) == 16 and [r['id'] for r in mixed] == list(range(26, 42))
         and len(final_same) == 8 and [r['id'] for r in final_same] == list(range(42, 50)),
         'mixed/final same-key original RPC identities differ')
    need(all(len(report[key]) == 8 for key in ('initial_starts', 'early_same_keys', 'terminal_same_keys',
                                               'terminal_statuses', 'outputs', 'initial_attempt_ledger')),
         'original/duplicate/status/output result count differs')
    rows, effects = [], []
    for i, record in enumerate(records):
        job_id = ids[i]
        need(report['initial_starts'][i]['job'] == record and report['initial_starts'][i]['reused'] is False
             and report['initial_starts'][i]['launch']['backend'] == 'systemd', 'original start differs')
        for value in (report['early_same_keys'][i], report['terminal_same_keys'][i], tool(final_same[i])):
            need(value['job'] == record and value['reused'] is True and value['retried_launch'] is False
                 and value['launch'] is None and value['status']['job_id'] == job_id,
                 'same-key reconciliation relaunched or changed original job')
        need(tool(final_same[i]) == report['terminal_same_keys'][i], 'last same-key raw reply differs')
        need(requests[i]['host'] == 'ai395' and requests[i]['args'] == record['args']
             and requests[i]['executable'] == record['executable'] == '/usr/bin/python3'
             and requests[i]['idempotency_key'] == record['idempotency_key']
             and requests[i]['stdin'].encode() == INPUT and requests[i]['timeout_seconds'] == 30
             and requests[i]['memory_max_bytes'] == 64 * 1024 * 1024
             and requests[i]['nice'] == 10 and requests[i]['cwd'] == record['cwd'] == REMOTE,
             'original business request differs from fixed workload')
        files = snapshot['jobs'][job_id]['files']
        data = {name: nested(value) for name, value in files.items()}
        required = {'request.json', 'owner-intent.json', 'started.json', 'child.json', 'runner.py',
                    'launch.json', 'stdin.bin', 'stdout.log', 'stderr.log', 'exit.json', 'exit.witness.json'}
        need(required <= set(data), 'remote original terminal evidence missing')
        original_files = bindings['jobs'][job_id]['files']
        need(set(original_files) == {'request.json', 'owner-intent.json', 'started.json', 'child.json',
                                     'runner.py', 'launch.json', 'stdin.bin'}, 'initial binding inventory differs')
        for name, value in original_files.items():
            need(nested(value) == data[name] and value == files[name], 'original immutable remote binding changed')
        request = json.loads(data['request.json'])
        owner = json.loads(data['started.json'])
        child = json.loads(data['child.json'])
        terminal = json.loads(data['exit.json'])
        witness = json.loads(data['exit.witness.json'])
        need(request['job_id'] == job_id and request['request_fingerprint'] == record['request_digest']
             and request['args'] == requests[i]['args'] and request['executable'] == requests[i]['executable'],
             'native original request and remote request differ')
        need(owner == json.loads(data['owner-intent.json']) and owner['job_id'] == job_id
             and owner['launch_nonce'] == request['launch_nonce'] and owner['supervisor_uid'] == 1000
             and json.loads(data['launch.json'])['backend'] == 'systemd', 'original native owner binding differs')
        for value in (request, terminal, witness):
            need(type(value['terminal_publication_protocol']) is int and value['terminal_publication_protocol'] == 1
                 and value['job_id'] == job_id and value['launch_nonce'] == request['launch_nonce'],
                 'terminal publication identity/protocol differs')
        need(witness['exit_sha256'] == sha(data['exit.json']) and terminal['exit_code'] == EXITS[i]
             and terminal['timed_out'] is False and terminal['cancelled'] is False
             and terminal['output_complete'] is True and terminal['output_durable'] is True,
             'original terminal witness, exit or durable output differs')
        status = tool(mixed[2 * i + 1])
        output = tool(mixed[2 * (7 - i)])
        need(status == report['terminal_statuses'][i] and all(status[k] == v for k, v in terminal.items())
             and status['terminal_publication_confirmed'] is True and status['automatic_retry'] is False
             and status['state'] == ('succeeded' if EXITS[i] == 0 else 'failed')
             and output == report['outputs'][i] and output['job_id'] == job_id,
             'mixed raw status/output differs from original terminal')
        need(data['stdin.bin'] == INPUT, 'original stdin bytes differ')
        for stream, label in [('stdout', 'OUT'), ('stderr', 'ERR')]:
            expected = f'JOB {i:02} {label}\n'.encode()
            part = output[stream]
            need(data[stream + '.log'] == bytes.fromhex(part['bytes_hex']) == part['text'].encode() == expected
                 and part['offset'] == 0 and part['next_offset'] == part['size'] == len(expected)
                 and part['eof'] is True, 'raw log/output bytes or cursors differ')
        ready = json.loads(nested(snapshot['ready'][f'{i:02}.json']))
        effect = json.loads(nested(snapshot['effects'][f'{i:02}.json']))
        need(effect['slot'] == ready['slot'] == i and effect['nonce'] == ready['nonce'] == plan['nonce']
             and effect['native_job_id'] == ready['native_job_id'] == job_id
             and effect['pid'] == ready['pid'] == child['pid'] and effect['uid'] == ready['uid'] == 1000
             and child['identity'] == {'kind': 'proc_start_ticks', 'value': effect['boot_id'] + ':' + str(effect['birth_ticks'])}
             and effect['boot_id'] == plan['remote_identity']['boot_id']
             and effect['input_sha256'] == sha(INPUT) and effect['expected_exit'] == EXITS[i]
             and effect['barrier_slots'] == list(range(8)), 'exclusive effect is not the original native business')
        observations = snapshot['jobs'][job_id]['original_process_observations']
        need(set(observations) == {'owner', 'business'}
             and all(value['same_incarnation_active'] is False for value in observations.values()),
             'original remote owner or business remains active')
        effects.append(effect)
        rows.append({'slot': i, 'job_id': job_id, 'expected_exit': EXITS[i], 'actual_exit': terminal['exit_code'],
                     'unchanged_initial_remote_files': len(original_files), 'terminal_witness_exact': True,
                     'exact_stdout_stderr_and_cursors': True, 'one_exclusive_effect_file': True,
                     'mixed_read_and_status_successful': True, 'early_and_terminal_same_key_reused': True,
                     'original_remote_processes_not_active': True})
    starts = [value['started_monotonic_ns'] for value in effects]
    ends = [value['effect_monotonic_ns'] for value in effects]
    need(effects == report['reconciliation']['remote_effects'] and max(starts) < min(ends)
         and min(ends) - max(starts) == report['reconciliation']['eight_business_overlap_ns']
         and all(value['observed_ready_monotonic_ns'] == starts for value in effects)
         and all(0 < ends[i] - starts[i] < 30_000_000_000 for i in range(8)),
         'same-remote-boot business overlap/barrier differs')
    need(report['reconciliation']['jobs'] == report['reconciliation']['effects'] == 8
         and report['reconciliation']['same_remote_boot'] == plan['remote_identity']['boot_id']
         and report['reconciliation']['cross_machine_monotonic_subtraction'] is False,
         'remote lifetime scope differs')
    arrivals = report['rpc_arrivals']
    need(len(arrivals) == 49 and sorted(value['rpc_id'] for value in arrivals) == list(range(1, 50)),
         'original reply router lost or duplicated IDs')
    refs = [{'host': 'ai395', 'job_id': job_id} for job_id in ids]
    mixed_calls = []
    for i in range(8):
        mixed_calls.extend([('process_read', {**refs[7-i], 'stdout_offset': 0, 'stderr_offset': 0, 'limit': 16384}),
                            ('process_status', refs[i])])
    calls = [('initial-starts', [('process_start', req) for req in requests]),
             ('early-same-keys', [('process_start', req) for req in requests]),
             ('terminal-poll-00', [('process_status', ref) for ref in refs]),
             ('mixed-status-and-read', mixed_calls),
             ('terminal-same-keys', [('process_start', req) for req in requests])]
    need(len(report['rpc_batches']) == len(calls), 'fixed batch count differs')
    next_id = 2
    for batch, (label, batch_calls) in zip(report['rpc_batches'], calls):
        expected_ids = list(range(next_id, next_id + len(batch_calls)))
        next_id += len(batch_calls)
        need(batch['label'] == label and batch['ids'] == expected_ids
             and batch['all_ids_registered_before_first_write'] is True, 'fixed batch identity differs')
        packets, offset = [], 0
        for rpc_id, (name, arguments) in zip(expected_ids, batch_calls):
            packet = (json.dumps({'jsonrpc': '2.0', 'id': rpc_id, 'method': 'tools/call',
                      'params': {'name': name, 'arguments': arguments}}, separators=(',', ':')) + '\n').encode()
            packets.append({'rpc_id': rpc_id, 'byte_start': offset, 'byte_end': offset + len(packet)})
            offset += len(packet)
        observed = [value for value in arrivals if value['rpc_id'] in expected_ids]
        need(batch['packets'] == packets and batch['bytes'] == batch['bytes_written'] == offset == sum(batch['writes'])
             and all(type(count) is int and count > 0 for count in batch['writes'])
             and batch['reply_arrival_ids'] == [value['rpc_id'] for value in observed]
             and sorted(batch['reply_arrival_ids']) == expected_ids
             and batch['reply_order_differed_from_submission'] == (batch['reply_arrival_ids'] != expected_ids),
             'actual written packet boundaries or routed arrivals differ')
        for value in observed:
            need(value['registered_monotonic_ns'] <= batch['write_started_monotonic_ns']
                 <= batch['write_finished_monotonic_ns'] <= value['observed_monotonic_ns']
                 <= batch['finished_monotonic_ns'], 'batch write/registration/reply order differs')
    need(report['actual_out_of_order_reply_observed'] is True
         and any(batch['reply_order_differed_from_submission'] for batch in report['rpc_batches']),
         'actual out-of-order reply evidence absent')
    for i, ledger in enumerate(report['initial_attempt_ledger']):
        need(ledger['slot'] == i and ledger['packet'] == report['rpc_batches'][0]['packets'][i]
             and ledger['write_state'] == 'complete_request_written' and ledger['reply_decoded_before_cleanup'] is True
             and ledger['decoded_reply']['id'] == i + 2 and tool(ledger['decoded_reply']) == report['initial_starts'][i],
             'initial original attempt ledger differs')
    shutdown = report['controller_shutdown']
    need(shutdown['shutdown'] == 'stdin_eof' and shutdown['cleanup_complete'] is True
         and shutdown['cleanup_errors'] == shutdown['signals'] == shutdown['adopted_children'] == []
         and shutdown['stdout_eof'] is True and shutdown['unconsumed_reply_bytes'] == 0,
         'original controller cleanup incomplete')
    for child in [shutdown] + report['ssh_helpers']:
        need(child['original_wait4']['pid'] == child['identity']['pid']
             and child['original_wait4']['raw_status'] == child['original_wait4']['exit_code'] == 0
             and child['signals'] == [], 'original Popen wait4 receipt or cleanup signal differs')
    need(len(report['ssh_helpers']) == 4, 'independent SSH helper count differs')
    for helper in report['ssh_helpers']:
        need(helper['stdout_eof'] is helper['stderr_eof'] is True
             and helper['discarded_bytes'] == {'stdout': 0, 'stderr': 0}
             and helper['observed_bytes'] == {stream: helper[stream + '_receipt']['bytes'] for stream in ('stdout', 'stderr')}
             and helper['stderr_receipt']['bytes'] == 0, 'independent SSH output/custody incomplete')
    need(all(report[key] == [] for key in ('pending_rpc_ids_before_cleanup', 'launch_outcome_unknown_slots',
                                          'unattempted_business_slots', 'unreaped_independent_ssh_children', 'stop_signals'))
         and report['validated_original_job_slots'] == list(range(8))
         and report['wall_seconds'] == report['finished_monotonic'] - report['started_monotonic'] < 180,
         'unclosed original attempt or absolute budget exceeded')
    prior = WORKSPACE / 'runtime-resume/docs/experiments/x230/a52/native-concurrency-r01.report.original.json'
    _, failed_a52 = pinned(prior, '5fe38092e3cd49f8ad7171fb8649dc090bd94495be3bcbf1af90d3bfae2f2080')
    need(failed_a52['passed'] is False, 'prior A52 failure must remain failed')
    result = {
        'schema': 'hepta-a54-native-concurrency-independent-raw-audit/v1',
        'independent_raw_reconciliation_passed': True, 'original_acceptance_passed': True,
        'report_sha256': REPORT_SHA, 'qualification_sha256': QUALIFICATION_SHA,
        'qualified_elf_sha256': ELF_SHA, 'source_files': 175, 'source_map_compact_sha256': SOURCE_SHA,
        'evidence': {'path': str(args.bundle), 'bytes': len(packed), 'sha256': sha(packed),
                     'expanded_bytes': len(expanded), 'expanded_sha256': sha(expanded), 'files': len(captured),
                     'capture_scope': bundle.get('capture_scope'),
                     'capture_producer': bundle.get('capture_producer', 'fixed remote pack script')},
        'verified_remote_file_receipts': verified_blobs, 'original_local_wait4_receipts': 5,
        'same_source_local_custody_selfchecks': 9, 'initial_new_jobs': 8, 'early_same_key_reuses': 8,
        'terminal_same_key_reuses': 8, 'mixed_read_successes': 8, 'mixed_status_successes': 8,
        'unique_routed_replies_including_initialize': 49, 'automatic_retries': 0,
        'same_remote_boot_business_overlap_ns': min(ends) - max(starts),
        'wall_seconds': report['wall_seconds'], 'rows': rows,
        'source_final_fence_scope': 'original frozen harness re-read all 175 source hashes; this audit independently matches its map to the actual qualification',
        'remote_custody_scope': 'original remote owner/business identity observations are not local wait4 receipts',
        'performance_improvement_claim': False, 'observation_pool_acceptance': False,
        'preserved_a52_original_acceptance_passed': False,
        'preserved_a52_report_sha256': sha(prior.read_bytes()),
    }
    raw = canonical(result)
    with args.output.open('xb') as destination:
        destination.write(raw)
    print(json.dumps({'passed': True, 'audit': str(args.output), 'bytes': len(raw), 'sha256': sha(raw),
                      'verified_remote_file_receipts': verified_blobs, 'jobs': 8, 'mixed_successes': 16},
                     sort_keys=True))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--bundle-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    main(parser.parse_args())

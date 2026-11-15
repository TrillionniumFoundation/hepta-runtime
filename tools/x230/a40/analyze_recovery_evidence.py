#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Offline verification of the frozen A40 revision-02 recovery evidence.

No harness is imported, no workload is run and no host is contacted. Expected
archive size/SHA256 and executable digest are pinned to this checkpoint.

From the published repository root:
  python3 tools/x230/a40/analyze_recovery_evidence.py

For separate evidence/source/tool checkouts, use --evidence-dir, --source-dir
and --tools-dir; --archive and --out optionally override their default files.
"""
import argparse
import base64
import collections
import datetime
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tarfile

parser = argparse.ArgumentParser(description=__doc__)
repository = Path(__file__).resolve().parents[3]
parser.add_argument('--evidence-dir', type=Path, default=repository / 'docs/evidence/x230-a40')
parser.add_argument('--source-dir', type=Path, default=repository)
parser.add_argument('--tools-dir', type=Path, default=Path(__file__).resolve().parent)
parser.add_argument('--archive', type=Path)
parser.add_argument('--out', type=Path)
args = parser.parse_args()
EVIDENCE = args.evidence_dir
SOURCE = args.source_dir
TOOLS = args.tools_dir
ARCHIVE = args.archive or EVIDENCE / 'final-evidence.tar.gz'
ARCHIVE_SHA = '2fd95f6ab697ddda7d746752e5c3083eb96e2e23d9933a05ebf1093976c8a0e4'
ELF = '3238c9d4bb2f8dc4dbb86e591ce774bea70c6785c159cf27b70003f00623540c'
NATIVE = 'a40r02-inherited-pipe-native-r01'
SIX = 'a40r02-six-running-recovery-r01'
SERIES = 'a40-staggered-output-recovery-20261025-r02/validation-series-r01/report.json'
REMOTE_ROOT = PurePosixPath('/home/qian/hepta-runtime-optimization-20261023')
HOSTS = {'ai395', 'mac', 'main', 'pocket4', 'rog', 'x230'}
INPUT = b'0123456789abcdef' * 256
checks_total = 0
snapshot_files_checked = 0
archive_files_checked = set()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def need(value, message):
    global checks_total
    checks_total += 1
    if not value:
        raise ValueError(message)


archive_raw = ARCHIVE.read_bytes()
need(len(archive_raw) == 2612169, 'archive size')
need(sha(archive_raw) == ARCHIVE_SHA, 'archive SHA256')
archive = tarfile.open(ARCHIVE, 'r:gz')
members = archive.getmembers()
need(len({m.name for m in members}) == len(members), 'duplicate archive member')
member_map = {m.name: m for m in members}


def original(name):
    member = member_map[name]
    need(member.isfile() and member.size <= 2 * 1024 * 1024, 'nonregular or oversized evidence: ' + name)
    raw = archive.extractfile(member).read()
    need(len(raw) == member.size, 'short archive member: ' + name)
    archive_files_checked.add(name)
    return raw


def remote_member(path):
    name = str(PurePosixPath(path).relative_to(REMOTE_ROOT))
    need(name.startswith((NATIVE + '/', SIX + '/')), 'unexpected referenced path: ' + name)
    return name


def referenced(record):
    raw = original(remote_member(record['path']))
    need(sha(raw) == record['sha256'], 'referenced original SHA256: ' + record['path'])
    if 'bytes' in record:
        need(len(raw) == record['bytes'], 'referenced original length: ' + record['path'])
    return raw


def snapshot(files):
    global snapshot_files_checked
    result = {}
    for name, entry in files.items():
        if entry is None:
            result[name] = None
            continue
        raw = base64.b64decode(entry['base64'], validate=True)
        need(len(raw) == entry['bytes'] and sha(raw) == entry['sha256'], 'embedded original digest: ' + name)
        snapshot_files_checked += 1
        result[name] = raw
    return result


def native_payload(reply):
    need('error' not in reply and reply.get('jsonrpc') == '2.0', 'RPC error or protocol mismatch')
    result = reply['result']
    need(not result.get('isError', False), 'native error result')
    contents = [c['text'] for c in result.get('content', []) if c.get('type') == 'text']
    need(len(contents) == 1, 'native JSON content count')
    value = json.loads(contents[0])
    need(value.get('audit_recorded') is True and 'audit_warning' not in value, 'missing durable audit acknowledgement')
    return value


def terminal(files, status, job_id):
    request = json.loads(files['request.json'])
    receipt = json.loads(files['exit.json'])
    witness = json.loads(files['exit.witness.json'])
    nonce = request['launch_nonce']
    need(isinstance(nonce, str) and len(nonce) == 32 and all(c in '0123456789abcdef' for c in nonce), 'nonce format')
    for value in (request, receipt, witness):
        need(value['job_id'] == job_id and value['launch_nonce'] == nonce
             and type(value['terminal_publication_protocol']) is int
             and value['terminal_publication_protocol'] == 1, 'terminal/request identity')
    need(witness['exit_sha256'] == sha(files['exit.json']), 'exact terminal witness hash')
    need(all(status.get(k) == v for k, v in receipt.items()), 'status/original receipt disagreement')
    need(status['job_id'] == job_id and status['terminal_publication_confirmed'] is True
         and status['automatic_retry'] is False, 'confirmed terminal identity or no-retry flag')
    return request, receipt, witness


def output_check(output, files, expected, status, job_id):
    need(output['job_id'] == job_id and output['audit_recorded'] is True, 'read job identity')
    summary = {}
    for stream, raw in expected.items():
        part = output[stream]
        data = bytes.fromhex(part['bytes_hex'])
        need(data == raw == files[stream + '.log'], 'native/original/expected output: ' + stream)
        need(part['offset'] == 0 and part['next_offset'] == part['size'] == len(raw)
             and part['eof'] is True, 'native output cursor/EOF: ' + stream)
        need(status['log_bytes'][stream] == {'seen': len(raw), 'stored': len(raw)}, 'log byte counters')
        summary[stream] = {'bytes': len(raw), 'sha256': sha(raw), 'exact_original_and_native_match': True,
                           'offset': 0, 'next_offset': len(raw), 'eof': True}
    need(status['log_synced'] == {'stdout': True, 'stderr': True}, 'stream sync results')
    need(status['log_truncated'] == {'stdout': False, 'stderr': False}, 'stream truncation')
    return summary


def shutdown_check(value, expected_code, method):
    need(value['exit_code'] == expected_code and value['shutdown_method'] == method, 'controller wait outcome')
    need(value['observed_descendant_survivors'] == [] and value['reader_error'] is None
         and value['unmatched_responses'] == 0, 'controller shutdown observations')
    return {k: value[k] for k in ('exit_code', 'shutdown_method', 'observed_descendant_survivors',
                                  'reader_error', 'unmatched_responses')}


qualification_raw = (EVIDENCE / 'qualification.json').read_bytes()
qualification = json.loads(qualification_raw)
need(qualification['qualified'] is True and qualification['current_stage'] == 'complete', 'qualification incomplete')
need(all(s['returncode'] == 0 for s in qualification['stages']), 'qualification gate failure')
need(qualification['binary']['sha256'] == ELF and qualification['binary']['cached'] is False
     and qualification['test_binary']['cached'] is False, 'qualified executable identity/freshness')
need(qualification['binary']['compiler_source'] == qualification['test_binary']['compiler_source']
     == str(PurePosixPath(qualification['source']) / 'src/main.rs'), 'compiler source path binding')
need(qualification['source_tested'] == qualification['source_after']
     and len(qualification['source_tested']) == 165, 'formatted qualified source map')
source_deltas = [p for p in qualification['source_tested']
                 if qualification['source_input'][p] != qualification['source_tested'][p]]
need(source_deltas == ['src/mcp/runtime/jobs_output_durability_tests.rs'], 'unexpected preformat source delta')
for path, expected in qualification['source_tested'].items():
    need(sha((SOURCE / path).read_bytes()) == expected, 'local qualified source mismatch: ' + path)
test_results = next(s['results'] for s in qualification['stages'] if s['name'] == 'test')
top_level = []
for summary in test_results:
    match = re.fullmatch(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out; finished in [0-9.]+s', summary)
    need(match is not None, 'unrecognized test summary')
    counts = [int(n) for n in match.groups()]
    if counts[4] == 0:
        top_level.append(counts)
need(sorted(c[0] for c in top_level) == [8, 18, 1200]
     and sum(c[1] for c in top_level) == 0 and sum(c[2] for c in top_level) == 23, 'top-level qualification test counts')

series_raw = original(SERIES)
series = json.loads(series_raw)
need(series['binary_sha256'] == ELF and series['qualification_sha256'] == sha(qualification_raw), 'series source/executable binding')
need(series['passed'] is True and series['phase'] == 'complete' and series['binary_unchanged'] is True
     and series['qualification_unchanged'] is True and series['automatic_retries'] is False
     and series['production_services_changed'] is False, 'series completion or mutation flags')
expected_stages = ['small-archive-abba', 'inherited-pipe-canary', 'six-running-controller-recovery',
                   'file-pool-abba', 'file-pool-soak', 'file-pool-c16']
need([s['name'] for s in series['stages']] == [s['name'] for s in series['planned_stages']] == expected_stages
     and all(s['returncode'] == 0 and s['report_success'] is True for s in series['stages']), 'six-stage reported results')
for stage in series['planned_stages']:
    need(stage['argv'][stage['argv'].index('--candidate') + 1] == qualification['binary']['path'], 'series candidate argv')
stage_by_name = {s['name']: s for s in series['stages']}

native_raw = original(NATIVE + '/report.json')
native = json.loads(native_raw)
native_stage = stage_by_name['inherited-pipe-canary']
need(native_stage['report_sha256'] == sha(native_raw)
     and remote_member(native_stage['report_path']) == NATIVE + '/report.json', 'native original report/series binding')
need(native['candidate_sha256'] == ELF and native['binary_unchanged'] is True, 'native executable binding')
need(native['planned_cases'] == [[h, k] for h in ('x230', 'mac') for k in ('natural', 'staggered', 'timeout')]
     and len(native['cases']) == 6, 'native planned cases')
need(len({c['job_id'] for c in native['cases']}) == 6, 'native job uniqueness')
need(native['automatic_retries'] == native['harness_remote_signals'] == native['remote_deletions']
     == native['service_mutations'] == 0, 'native mutation/retry counts')
need(native['cancel_during_drain_requested'] is False, 'unexpected native cancellation scope')
native_calls = []
native_responses = {}
native_ssh = []
need(sorted(c['sequence'] for c in native['calls']) == list(range(1, len(native['calls']) + 1)), 'native ledger completeness')
for row in sorted(native['calls'], key=lambda x: x['sequence']):
    need(row['completed'] is True and row['automatic_retry'] is False and 'error' not in row, 'native ledger failure')
    raw = original(remote_member(row['request_path']))
    need(sha(raw) == row['request_sha256'], 'native saved request hash')
    request = json.loads(raw)
    if row['kind'] == 'native':
        reply = json.loads(referenced(row['response']))
        need(request['id'] == reply['id'] and request['jsonrpc'] == reply['jsonrpc'] == '2.0', 'native RPC identity')
        need(reply['id'] not in native_responses, 'duplicate native RPC reply ID')
        native_responses[reply['id']] = reply
        if request['method'] == 'tools/call':
            native_calls.append({'sequence': row['sequence'], 'id': request['id'],
                                 'tool': request['params']['name'], 'arguments': request['params']['arguments'],
                                 'result': native_payload(reply)})
        else:
            need(request['method'] == 'initialize', 'unexpected native RPC method')
    elif row['kind'] == 'notification':
        need(request['method'] == 'notifications/initialized' and 'id' not in request
             and row['response_expected'] is False, 'native notification')
    else:
        need(row['kind'] in ('ssh-prepare', 'ssh-inspect') and row['returncode'] == 0, 'native SSH case')
        stdout = referenced(row['stdout'])
        referenced(row['stderr'])
        proof = json.loads(stdout)
        need(proof['host'] == request['host'] and proof['nonce'] == native['nonce'], 'native independent helper binding')
        native_ssh.append((row['kind'], request, proof))

wire = referenced(native['shutdown']['wire_capture'])
need(native['shutdown']['wire_capture']['complete'] is True
     and native['shutdown']['wire_capture']['reader_error'] is None, 'incomplete native inbound capture')
wire_values = [json.loads(line) for line in wire.splitlines() if line.strip()]
wire_replies = [v for v in wire_values if 'id' in v]
need(len(wire_replies) == len(native_responses) and len({v['id'] for v in wire_replies}) == len(wire_replies), 'native wire reply counts')
need(all(native_responses.get(v['id']) == v for v in wire_replies), 'native wire/saved reply mismatch')
need(sum(c['tool'] == 'process_start' for c in native_calls) == 6
     and all(c['tool'] in ('process_start', 'process_status', 'process_read') for c in native_calls), 'native start count/tool set')
native_case_results = []
for case in native['cases']:
    host, kind, job_id = case['host'], case['case'], case['job_id']
    record, request = case['record'], case['request']
    files = snapshot(case['independent_proof']['files'])
    status = case['last_status']
    original_request, receipt, witness = terminal(files, status, job_id)
    starts = [c for c in native_calls if c['tool'] == 'process_start' and c['arguments'] == request]
    need(len(starts) == 1 and starts[0]['result']['reused'] is False
         and starts[0]['result']['job'] == record and starts[0]['result']['launch']['ok'] is True, 'native original launch/once')
    need(record['id'] == job_id and record['host'] == host and record['launch_state'] == 'launched'
         and record['idempotency_key'] == request['idempotency_key'], 'native original record binding')
    need(record['remote_job_dir'] == case['child_config']['fixture'] + '/jobs/' + job_id, 'native private job path')
    need(original_request['request_fingerprint'] == record['request_digest'], 'native request digest binding')
    for field in ('executable', 'args', 'cwd', 'env', 'timeout_seconds'):
        need(original_request[field] == request[field], 'native original submitted field: ' + field)
    need(sha(request['args'][4].encode()) == native['child_source_sha256'], 'native child code binding')
    need(json.loads(request['args'][5]) == case['child_config']
         and json.loads(files['canary-input.json']) == {**case['child_config'], 'job_id': job_id}, 'native input binding')
    need(files['execution-marker'] == b'EXECUTED\n', 'native execution marker count')
    child = json.loads(files['child.json'])
    descendant = json.loads(files['descendant.json'])
    leader = json.loads(files['leader-before-exit.json'])
    need(descendant['ppid'] == descendant['pgid'] == child['pid'] == leader['pid']
         and descendant['job_id'] == job_id and descendant['case'] == kind
         and descendant['self_exit_budget_seconds'] == 8, 'native original process/group relation')
    need(files['owner-intent.json'] == files['started.json'], 'native owner intent/start binding')
    owner = json.loads(files['started.json'])
    need(owner['job_id'] == job_id and owner['launch_nonce'] == original_request['launch_nonce'], 'native owner identity')
    expected = {'stdout': ('DESCENDANT BEGIN ' + kind + '\nLEADER EXIT ' + kind + '\n').encode(),
                'stderr': ('LEADER STDERR ' + kind + '\n').encode()}
    if kind in ('natural', 'staggered'):
        if kind == 'natural':
            expected['stdout'] += b'DESCENDANT EOF natural\n'
            need(files['descendant-finished'] == b'NATURAL EOF\n' and files['stdout-finished'] is None, 'native natural EOF marker')
        else:
            expected['stdout'] += b'DESCENDANT STDOUT EOF staggered\n'
            expected['stderr'] += b'DESCENDANT STDERR EOF staggered\n'
            need(files['stdout-finished'] == b'STAGGERED STDOUT EOF\n'
                 and files['descendant-finished'] == b'STAGGERED STDERR EOF\n', 'native staggered EOF markers')
        need(status['state'] == 'succeeded' and status['exit_code'] == 0
             and status['output_complete'] is True and status['output_durable'] is True
             and status.get('effect_outcome') != 'unknown' and 'child_group_signal' not in status
             and status['log_errors'] == {'stdout': None, 'stderr': None}, 'native natural outcome')
    else:
        error = 'output drain deadline exceeded after leader exit'
        need(kind == 'timeout' and files['descendant-finished'] is None and files['stdout-finished'] is None, 'native timeout marker')
        need(status['state'] == 'effect_unknown' and status['effect_outcome'] == 'unknown'
             and status['exit_code'] == 125 and status['child_exit_code'] == 0
             and status['child_pid'] == child['pid'] and status['child_spawned'] is True
             and status['child_reaped'] is True and status['child_group_signal'] == 'submitted'
             and status['child_group_signal_number'] == 9 and status['status_authoritative'] is False
             and status['output_complete'] is False and status['output_durable'] is False
             and status['supervisor_error'] == error and status['supervisor_cleanup_errors'] == []
             and status['log_errors'] == {'stdout': error, 'stderr': error}, 'native timeout outcome')
    need(status['cancelled'] is False and status['timed_out'] is False, 'native unintended cancel/task timeout')
    outputs = output_check(case['output'], files, expected, status, job_id)
    reads = [c for c in native_calls if c['tool'] == 'process_read'
             and c['arguments']['host'] == host and c['arguments']['job_id'] == job_id]
    statuses = [c for c in native_calls if c['tool'] == 'process_status'
                and c['arguments']['host'] == host and c['arguments']['job_id'] == job_id]
    need(len(reads) == 1 and reads[0]['result'] == case['output'] and statuses[-1]['result'] == status, 'native archived replies/case correspondence')
    matching_proofs = [proof for mode, req, proof in native_ssh if mode == 'ssh-inspect' and req['job_id'] == job_id]
    need(matching_proofs == [case['independent_proof']], 'native archived independent proof correspondence')
    observation = case['independent_proof']['descendant_observation']
    need(observation == {'present': False}, 'native descendant still observed')
    records = [r for r in native['controller_records'] if PurePosixPath(r['path']).name == job_id + '.json']
    need(len(records) == 1 and records[0]['original_bytes_unchanged'] is True
         and records[0]['sha256'] == case['controller_record_sha256'], 'native retained controller record digest')
    need(case['start_submitted_once'] is True and case['cleanup'] == {'remote_signals': 0}, 'native cleanup/replay')
    native_case_results.append({'host': host, 'case': kind, 'job_id': job_id, 'checks_passed': True,
                               'launch_rpc_id': starts[0]['id'], 'launch_request_count': 1,
                               'state': status['state'], 'exit_code': status['exit_code'],
                               'child_exit_code': status.get('child_exit_code'),
                               'execution_marker_count': 1, 'request_sha256': sha(files['request.json']),
                               'exit_sha256': sha(files['exit.json']), 'witness_sha256': sha(files['exit.witness.json']),
                               'witness_exact_exit_hash_matches': True, 'outputs': outputs,
                               'original_leader_pid': child['pid'], 'original_descendant_pid': descendant['pid'],
                               'descendant_observation': observation, 'reported_group_signal': status.get('child_group_signal_number'),
                               'controller_record_before_after_sha256': records[0]['sha256'],
                               'output_complete': status['output_complete'], 'output_durable': status['output_durable'],
                               'automatic_retry': status['automatic_retry'], 'harness_rescue_signals': 0})
native_shutdown = shutdown_check(native['shutdown'], 0, 'stdin_eof')
need(native['shutdown']['stdio_reader_alive'] is False, 'native stdio reader alive after close')
native_shutdown.update(stdio_reader_alive=False, inbound_wire_bytes=len(wire), inbound_wire_sha256=sha(wire),
                       inbound_wire_complete=True, saved_and_wire_replies=len(wire_replies))
need(native['exact_original_controller_records'] is True and native['source_records_unchanged'] is True
     and native['agent_unchanged'] is True and native['passed'] is True, 'native final assertions')

six_raw = original(SIX + '/report.json')
six = json.loads(six_raw)
six_stage = stage_by_name['six-running-controller-recovery']
need(six_stage['report_sha256'] == sha(six_raw)
     and remote_member(six_stage['report_path']) == SIX + '/report.json', 'six-host original report/series binding')
qualification_finished = datetime.datetime.fromisoformat(qualification['finished_utc']).timestamp()
need(qualification_finished < native['started_unix'] < native['finished_unix'] < six['started_unix'],
     'recovery experiments overlapped qualification or each other')
need(six['candidate_sha256'] == ELF and six['binary_unchanged'] is True, 'six-host executable binding')
need(set(six['hosts']) == HOSTS and len({h['job_id'] for h in six['hosts'].values()}) == 6, 'six-host original job set')
need(six['automatic_rpc_retries'] == six['remote_cleanup_operations'] == six['production_service_mutations'] == 0,
     'six-host retry/cleanup/mutation counts')
need(six['stdin_bytes'] == len(INPUT) and six['stdin_sha256'] == sha(INPUT), 'six-host input original')
six_calls = []
for row in six['native_calls']:
    raw = original(remote_member(row['reply_path']))
    need(sha(raw) == row['response_sha256'] and row['okay'] is True and row['automatic_retry'] is False
         and 'error' not in row, 'six-host archived reply/failure')
    reply = json.loads(raw)
    result = native_payload(reply)
    six_calls.append({**row, 'rpc_id': reply['id'], 'result': result})
need(len({r['sequence'] for r in six_calls}) == len(six_calls), 'six-host unique native ledger sequence')
for generation, phases in (('first', {'launch', 'before_crash_running'}), ('restarted', {'recover_same_original', 'terminal'})):
    ids = [r['rpc_id'] for r in six_calls if r['phase'] in phases]
    need(len(ids) == len(set(ids)), 'six-host duplicate native reply ID in ' + generation)
six_ssh = []
for row in six['ssh_calls']:
    need(row['okay'] is True and row['returncode'] == 0 and row['automatic_retry'] is False
         and 'error' not in row, 'six-host SSH failure')
    proof = json.loads(referenced(row['stdout']))
    referenced(row['stderr'])
    need(proof['host'] == row['host'] and proof['nonce'] == six['nonce'] and proof['mode'] == row['mode'], 'six-host helper binding')
    six_ssh.append({**row, 'proof': proof})
need(collections.Counter(r['mode'] for r in six_ssh) == {'inspect': 18, 'prepare': 6, 'release': 6}, 'six-host helper operation counts')
six_case_results = []
for host in sorted(HOSTS):
    h = six['hosts'][host]
    job_id = h['job_id']
    request_raw = original(SIX + '/' + host + '-request.json')
    request = json.loads(request_raw)
    need(sha(request_raw) == h['request_sha256'] and canonical(request) == request_raw, 'six-host saved original request')
    record = h['launch']['job']
    need(request['host'] == host and request['idempotency_key'] == h['idempotency_key']
         == 'six-running-' + six['nonce'] + '-' + host, 'six-host request key')
    need(request['executable'] == h['executable'] and request['cwd'] == h['fixture']
         and request['env'] == {} and request['stdin'].encode() == INPUT
         and request['timeout_seconds'] == 240 and request['args'] == record['args'], 'six-host workload request')
    need(sha(request['args'][4].encode()) == six['workload_sha256'], 'six-host fixed workload source')
    child_config = json.loads(request['args'][5])
    need(child_config == {'host': host, 'fixture': h['fixture'], 'fixture_identity': h['prepare']['fixture_identity'],
                          'stdin_sha256': sha(INPUT)}, 'six-host workload fixture binding')
    need(record['id'] == job_id and record['host'] == host and record['idempotency_key'] == h['idempotency_key']
         and record['launch_state'] == 'launched' and record['remote_job_dir'] == h['fixture'] + '/jobs/' + job_id,
         'six-host original registry binding')
    host_calls = [r for r in six_calls if r['host'] == host]
    starts = [r for r in host_calls if r['tool'] == 'process_start']
    need(len(starts) == 2 and {r['phase'] for r in starts} == {'launch', 'recover_same_original'}, 'six-host start/lookup counts')
    for call in host_calls:
        if call['tool'] == 'process_start':
            arguments = request
        elif call['tool'] == 'process_status':
            arguments = {'host': host, 'job_id': job_id}
        else:
            need(call['tool'] == 'process_read', 'unexpected six-host tool')
            arguments = {'host': host, 'job_id': job_id, 'stdout_offset': 0, 'stderr_offset': 0, 'limit': 16384}
        need(sha(canonical(arguments)) == call['arguments_sha256'], 'six-host request arguments digest')
        if call['tool'] != 'process_start':
            need(call['result']['job_id'] == job_id, 'six-host response job identity')
    launched = next(c for c in starts if c['phase'] == 'launch')
    reused = next(c for c in starts if c['phase'] == 'recover_same_original')
    need(launched['result']['reused'] is False and launched['result']['job'] == record
         and launched['result']['launch'] == h['launch']['launch']
         and h['launch']['launch']['ok'] is True, 'six-host original native start')
    same = h['recover_same_original']['same_key_reuse']
    need(reused['result'] == same and same['reused'] is True and same['retried_launch'] is False
         and same['launch'] is None and same['job'] == record and same['status']['job_id'] == job_id
         and same['status']['state'] == 'running', 'six-host no-relaunch reuse')
    before = h['before_crash_running']['status']
    after = h['recover_same_original']['first_status']
    need(before == after and before['state'] == 'running' and before['job_id'] == job_id, 'six-host original running identity across crash')
    need(any(c['phase'] == 'before_crash_running' and c['tool'] == 'process_status' and c['result'] == before for c in host_calls)
         and any(c['phase'] == 'recover_same_original' and c['tool'] == 'process_status' and c['result'] == after for c in host_calls),
         'six-host saved running replies')
    need(h['before_crash_running']['stdout_sha256'] == sha(('BEGIN ' + host + '\n').encode()), 'six-host running BEGIN prefix')
    before_files = snapshot(h['before_crash_independent']['proof']['files'])
    after_files = snapshot(h['after_crash_independent']['proof']['files'])
    final_files = snapshot(h['terminal']['independent_proof']['files'])
    for phase_files in (before_files, after_files):
        need(phase_files['execution-marker'] == b'EXECUTED\n' and phase_files['release-marker'] is None
             and phase_files['stdin.bin'] == INPUT and phase_files['exit.json'] is None
             and phase_files['exit.witness.json'] is None, 'six-host held original before release')
    need(before_files['request.json'] == after_files['request.json'] == final_files['request.json'], 'six-host unchanged original remote request')
    need(final_files['stdin.bin'] == INPUT and final_files['execution-marker'] == b'EXECUTED\n'
         and final_files['release-marker'] == b'RELEASE\n', 'six-host execution/release markers')
    status = h['terminal']['status']
    original_request, receipt, witness = terminal(final_files, status, job_id)
    need(h['before_crash_independent']['launch_nonce'] == h['after_crash_independent']['launch_nonce']
         == original_request['launch_nonce'], 'six-host original launch nonce across crash')
    need(original_request['request_fingerprint'] == record['request_digest'], 'six-host original request digest binding')
    for field in ('executable', 'args', 'cwd', 'env', 'timeout_seconds'):
        need(original_request[field] == request[field], 'six-host original submitted field: ' + field)
    need(status['state'] == 'succeeded' and status['exit_code'] == 0 and status['output_complete'] is True
         and status['output_durable'] is True and status['cancelled'] is False and status['timed_out'] is False
         and status['log_errors'] == {'stdout': None, 'stderr': None}, 'six-host final outcome')
    expected = {'stdout': ('BEGIN ' + host + '\nEND ' + host + ' ' + sha(INPUT) + '\n').encode(),
                'stderr': ('HEPTA-CANARY-STDERR ' + host + '\n').encode()}
    reads = [c for c in host_calls if c['phase'] == 'terminal' and c['tool'] == 'process_read']
    terminal_statuses = [c for c in host_calls if c['phase'] == 'terminal' and c['tool'] == 'process_status']
    need(len(reads) == 1 and terminal_statuses[-1]['result'] == status, 'six-host terminal raw replies')
    outputs = output_check(reads[0]['result'], final_files, expected, status, job_id)
    need(h['terminal']['outputs'] == {k: {'bytes': v['bytes'], 'sha256': v['sha256']} for k, v in outputs.items()}, 'six-host derived output summary')
    proofs = [c['proof'] for c in six_ssh if c['host'] == host and c['mode'] == 'inspect']
    expected_proofs = [h['before_crash_independent']['proof'], h['after_crash_independent']['proof'], h['terminal']['independent_proof']]
    need(collections.Counter(sha(canonical(p)) for p in proofs) == collections.Counter(sha(canonical(p)) for p in expected_proofs), 'six-host raw independent proofs')
    releases = [c for c in six_ssh if c['host'] == host and c['mode'] == 'release']
    need(len(releases) == 1 and h['release_attempted'] is True and releases[0]['proof'] == h['release'], 'six-host single create-only release')
    retained = [r for r in six['retained_controller_records'] if r['host'] == host]
    need(len(retained) == 1 and retained[0]['job_id'] == job_id and retained[0]['original_bytes_unchanged'] is True
         and retained[0]['sha256'] == h['launch']['record_sha256']
         and retained[0]['idempotency_key'] == h['idempotency_key'], 'six-host retained original registry digest')
    identity = ({'backend': 'detached', 'pid': before['pid'], 'identity': before['identity']}
                if before['backend'] == 'detached' else
                {'backend': 'systemd', 'pid': before['systemd']['ExecMainPID'],
                 'invocation_id': before['systemd']['InvocationID'], 'description': before['systemd']['Description']})
    six_case_results.append({'host': host, 'job_id': job_id, 'checks_passed': True,
                            'original_request_sha256': sha(request_raw), 'remote_request_sha256': sha(final_files['request.json']),
                            'fresh_start_count': 1, 'same_key_lookup_count': 1, 'reused': True, 'retried_launch': False,
                            'lookup_launch_is_null': True, 'original_running_identity_before_after': identity,
                            'execution_marker_count_before_crash': 1, 'execution_marker_count_after_crash': 1,
                            'execution_marker_count_at_terminal': 1, 'release_operation_count': 1,
                            'state': status['state'], 'exit_code': status['exit_code'], 'outputs': outputs,
                            'exit_sha256': sha(final_files['exit.json']), 'witness_sha256': sha(final_files['exit.witness.json']),
                            'witness_exact_exit_hash_matches': True, 'original_remote_request_bytes_unchanged': True,
                            'controller_record_before_after_sha256': retained[0]['sha256'],
                            'automatic_retry': False})

crash = shutdown_check(six['intentional_crash'], -9, 'already_exited')
restart = shutdown_check(six['shutdown'], 0, 'stdin_eof')
need(six['first_startup']['pid'] != six['restart_startup']['pid']
     and six['first_startup']['birth_ticks'] != six['restart_startup']['birth_ticks'], 'same controller incarnation reused')
need(six['new_start_call_count'] == six['same_key_lookup_call_count'] == 6, 'six-host published start counts')
need(sum(c['tool'] == 'process_start' for c in six_calls) == 12, 'six-host raw start/lookup count')
need(all(six[k] is True for k in ('controller_records_unchanged_after_shutdown', 'source_originals_unchanged',
                                 'current_agent_unchanged', 'distinct_reported_hostnames', 'passed'))
     and six['final_controller_record_errors'] == [], 'six-host final assertions')
need(len({h['prepare']['hostname'] for h in six['hosts'].values()}) == 6, 'distinct reported hostnames')

script_bindings = {}
for label, filename, expected in (
    ('native_driver', 'x230_inherited_pipe_canary_a40.py', native['source_hashes']['driver']),
    ('six_driver', 'x230_six_running_recovery_canary.py', six['script_sha256']),
    ('controller_helper', 'x230_observation_benchmark.py', six['benchmark_helper_sha256']),
):
    raw = (TOOLS / filename).read_bytes()
    need(sha(raw) == expected, 'local evidence harness source identity: ' + filename)
    script_bindings[label] = {'filename': filename, 'sha256': sha(raw)}

result = {
    'schema': 'hepta-a40-recovery-independent-analysis/v1',
    'passed': True,
    'analysis_scope': 'Offline verification of archived requests, replies and original-file snapshots for all 6 inherited-pipe cases and all 6 controller-recovery jobs; no new workloads or remote observations.',
    'analysis_script_sha256': sha(Path(__file__).read_bytes()),
    'archive': {'path': 'final-evidence.tar.gz', 'bytes': len(archive_raw), 'sha256': ARCHIVE_SHA},
    'qualification': {'report_sha256': sha(qualification_raw), 'qualified': True, 'current_stage': 'complete',
                      'binary_sha256': ELF, 'test_and_release_cached': False,
                      'formatted_source_files': 165,
                      'source_tested_equals_after_and_local_source': True,
                      'source_map_sha256': sha(json.dumps(qualification['source_tested'], sort_keys=True, separators=(',', ':')).encode()),
                      'preformat_delta_paths': source_deltas,
                      'top_level_tests_passed': sum(c[0] for c in top_level),
                      'existing_ignored': sum(c[2] for c in top_level)},
    'validation_series': {'member': SERIES, 'sha256': sha(series_raw),
                          'same_binary_and_qualification_bound': True,
                          'stages_reported_successful': 6,
                          'recovery_report_hashes_independently_matched': True,
                          'recovery_runs_started_after_qualification_completed': True},
    'native_inherited_pipe': {'report_member': NATIVE + '/report.json', 'report_sha256': sha(native_raw),
                             'report_bytes': len(native_raw), 'cases_checked': 6,
                             'natural_successes': 4, 'timeout_unknown_results': 2,
                             'default_cancel_case_executed': False,
                             'fresh_process_start_requests': 6,
                             'native_tool_calls': dict(collections.Counter(c['tool'] for c in native_calls)),
                             'saved_rpc_responses': len(native_responses),
                             'ssh_helper_calls': dict(collections.Counter(m for m, _, _ in native_ssh)),
                             'all_raw_rpc_request_ids_match_replies_and_inbound_wire': True,
                             'controller_shutdown': native_shutdown,
                             'harness_elapsed_seconds': native['finished_unix'] - native['started_unix'],
                             'driver_subprocess_elapsed_seconds': native_stage['seconds'],
                             'cases': native_case_results},
    'six_running_controller_recovery': {'report_member': SIX + '/report.json', 'report_sha256': sha(six_raw),
                                        'report_bytes': len(six_raw), 'hosts_checked': 6,
                                        'fresh_process_start_requests': 6, 'same_key_process_start_lookups': 6,
                                        'automatic_rpc_retries': 0,
                                        'native_reply_count': len(six_calls), 'ssh_helper_call_count': len(six_ssh),
                                        'original_controller': {'startup': six['first_startup'], 'waited_crash': crash},
                                        'restarted_controller': {'startup': six['restart_startup'], 'waited_shutdown': restart},
                                        'harness_elapsed_seconds': six['finished_unix'] - six['started_unix'],
                                        'driver_subprocess_elapsed_seconds': six_stage['seconds'],
                                        'timing_interpretation': 'Whole harness includes preparation, launch, deliberate hold/release, polling, verification and shutdown. It is not a recovery-time objective, a measured RTO, or a general failover deadline.',
                                        'cases': six_case_results},
    'harness_source_bindings': script_bindings,
    'verification_coverage': {'checks_completed': checks_total,
                              'embedded_original_file_snapshots_rehashed': snapshot_files_checked,
                              'distinct_archive_members_read': len(archive_files_checked)},
    'limitations': [
        'This is an offline audit of retained observations. It does not reread the remote original files or repeat an experiment.',
        'The same-ELF claim is a digest binding across qualification, validation-series and both recovery reports. The executable is excluded from the evidence archive and is not rehashed by this offline audit.',
        'Execution-once markers, retained original IDs, same-key no-relaunch replies and bounded request counts support these fixed workloads only; they do not prove general exactly-once external effects or universal transport delivery semantics.',
        'Original controller registry files are excluded from the evidence bundle. Their retained before/after digests and the reported equality checks agree; this audit cannot independently reread those excluded registry bytes.',
        'Native timeout receipts bind the original group/child metadata and report SIGKILL submission and child reap. Direct signal-before-reap event tracing belongs to the separate source-bound prequalification fixtures; these native cases do not independently hook kernel group-signal and wait events.',
        'All six native descendant observations report absent at the observation instant. Empty observed-controller-descendant survivor lists are limited to sampled identities and are not exhaustive process-tree proofs.',
        'The inherited-pipe report has a verified complete inbound stdio capture and an explicit ended stdio-reader flag. The six-running report retains individual native replies and shutdown wait outcomes but does not include that same raw-capture/end-thread instrumentation.',
        'The optional native cancellation-during-drain case was not requested in the six-case final inherited-pipe run; cancellation and read-error injection are covered by the separate prequalification fixtures and qualified tests.',
        'Controller SIGKILL while remote supervisors remain alive is not supervisor death, host reboot, abrupt power loss, escaped process-group recovery, WAN partition, or authoritative cleanup of ownerless socket roots.',
        'A matching witness proves the exact exit-receipt binding and the documented prior publication order; it does not certify witness-own final directory sync, log-file hashes, real power-cut durability, or external business effects.',
        'Native staged EOF markers do not independently timestamp actual EOF; no signal-delivery or recovery deadline is inferred from harness elapsed time.'
    ],
}

out = args.out or EVIDENCE / 'recovery-independent-analysis.json'
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
print(json.dumps({'output': str(out), 'bytes': out.stat().st_size, 'sha256': sha(out.read_bytes()),
                  'passed': result['passed'], 'checks': checks_total,
                  'native_cases': len(native_case_results), 'recovery_hosts': len(six_case_results),
                  'six_harness_elapsed_seconds': result['six_running_controller_recovery']['harness_elapsed_seconds'],
                  'archive_members': len(archive_files_checked)}, sort_keys=True))

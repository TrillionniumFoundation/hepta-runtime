#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Read the six original R23 fixture terminal receipts once, without lifecycle writes.

Invoked only by unchanged held_agent_campaign_02.py --launcher-sha256. The original
campaign and cancellation failure remain failed. No runtime controller is started,
no job is created/cancelled/released, and the original frozen helper receives only
inspect + terminal=True. Its receipts do not independently prove PID/group absence.
"""
import argparse
import base64
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
ROOT = Path('/home/qian/hepta-runtime-optimization-20261105-r23')
R16 = Path('/home/qian/hepta-runtime-optimization-20261104-r16')
TOOLS = R16 / 'measurement-tools'
OUT = ROOT / 'campaign-01/terminal-closure-01'
ORIGINAL = R16 / 'r23-cancel-recovery-01/report.json'
CAMPAIGN = ROOT / 'campaign-01/report.json'
PROFILE = Path('/home/qian/hepta-runtime-optimization-20261023/r11-native-observation-abba-20261103-02/profile/profile.json')
TOPOLOGY = R16 / 'benchmark-topology.json'
ORIGINAL_SHA = '04bccf0b9a38d7188521d7ed7d0c18ff4a28a4ab571333e4e84a80b3f12d1abf'
CAMPAIGN_SHA = '44b74c25cc429ccbb125b88a65778ef2030fe4fa742d17a63994f4f4ec48dfa8'
PROFILE_SHA = 'fe1e9551b5b8812ad6ed3da018c282b7261f7caeb2f49e4dcfefba7ff784ab08'
TOPOLOGY_SHA = '8c0767d3318131a7d470d9cde8e327a59ce18adf022c8bc1b1d5a0fa9a865287'
REMOTE_SHA = '1ed9ccbcd77a9ca9310995d985d7fafd22b08baf46c3055395d1ddbc226e58ef'
HOSTS = ('ai395', 'mac', 'main', 'pocket4', 'rog', 'x230')
HARNESS_FILES = {
    "allocator_environment.py": "f5c8e879c540b3f7cb1b7d3a7a0f5002c2f40c1a87963174b0b00470fa3a4525",
    "allocator_environment_audit.py": "4b082ce343ae3943e3098baa58af2f5def7198881b9c087d63d88360e9763727",
    "analyze_native_observation.py": "cc7f6884d581cd1ced430437350e808de51931c50d12441797205501b20cae66",
    "audit_native_evidence.py": "b69f6902d2de81eab41b21506f024c002d2f8264d60e86df6b1086623a77fd28",
    "observation_resources.py": "f3402d51cb37b2fe20f4351b3a81ec5990a9fdaff93a846d21c07ccd557cb894",
    "owned_ssh_interruption.py": "1989c57f0b944afae1ed759d6529b8f1cc26197e269e2c34c4fd49e43a32aa7b",
    "run_native_observation.py": "7606648c99b2ff2bbf0bba58384e8cab609ac3899f838c0b80ba54d6288d20bb",
    "run_six_host_cancel_recovery.py": "698eb7801cde3f2bd5ff202412c0833fc218fd7e912c3c949d2b37fde7a56a12",
    "test_native_harness.py": "2b450175b9e6122248ac1bcb51860aa8a6d3eff55f6ac8c877c0a905e3dd7d00",
    "verify_cancel_recovery.py": "0116652a0b489dc462f005e01d7c943feda9ba784563d7317c92bb5beb9a701c",
    "x230_observation_benchmark.py": "4d96f0bf2da2562e788f48be7c37589ab3a513be5f9d8b2d741afe5c08ea9eed",
    "x230_six_running_recovery_canary.py": "6219bc556b0ac6d142bd4c731466b959e8a410f0b4b55f3d8b303f8fdbfbaaf4"
}


def need(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def stamp(info):
    return tuple(getattr(info, k) for k in ('st_dev', 'st_ino', 'st_uid', 'st_mode',
                 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def read(path, expected=None, maximum=2 * 1024 * 1024):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path, 'indirect input: ' + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and 0 <= before.st_size <= maximum, 'unsafe input: ' + str(path))
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(maximum + 1)
        need(len(raw) == before.st_size and stamp(before) == stamp(os.fstat(fd)) == stamp(path.lstat()),
             'input changed while reading: ' + str(path))
    finally:
        os.close(fd)
    need(expected is None or digest(raw) == expected, 'SHA differs: ' + str(path))
    return raw


def create(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def save(report):
    pending = OUT / 'report.next'
    create(pending, canonical(report))
    os.replace(pending, OUT / 'report.json')
    fd = os.open(OUT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def directory_identity(path):
    need(path.resolve(strict=True) == path, 'indirect owned directory')
    info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
         and stat.S_IMODE(info.st_mode) == 0o700, 'directory is not private and owned')
    return (info.st_dev, info.st_ino, info.st_uid, info.st_mode)


def validate_terminal(host, item, old, proof, helper):
    before = item['before_crash_running']['proof']
    for field in ('host', 'nonce', 'fixture_identity', 'platform', 'hostname', 'uid'):
        need(proof[field] == before[field], 'independent identity differs: ' + field)
    need(proof['mode'] == 'inspect', 'unexpected helper mode')
    files = proof['files']
    need(helper.decoded(files, 'execution-marker') == helper.MARKER
         and helper.decoded(files, 'stdin.bin') == helper.INPUT
         and helper.decoded(files, 'release-marker', False) is None
         and helper.decoded(files, 'cancel-request.json', False) is None,
         'original execution, input, release or cancellation evidence differs')
    need(files['request.json'] == before['files']['request.json'], 'original request bytes changed')
    records = {name: json.loads(helper.decoded(files, name))
               for name in ('request.json', 'exit.json', 'exit.witness.json')}
    nonce = item['before_crash_running']['launch_nonce']
    for name, record in records.items():
        need(record['job_id'] == item['job_id'] and record['launch_nonce'] == nonce
             and type(record.get('terminal_publication_protocol')) is int
             and record['terminal_publication_protocol'] == 1, 'terminal identity differs: ' + name)
    request, terminal, witness = (records[name] for name in ('request.json', 'exit.json', 'exit.witness.json'))
    job = item['launch']['job']
    need(request['job_dir'] == job['remote_job_dir'] and request['unit'] == job['unit']
         and request['request_digest'] == job['request_digest'], 'original job binding differs')
    need(witness['exit_sha256'] == files['exit.json']['sha256'], 'terminal witness digest differs')
    need(type(terminal['exit_code']) is int and type(terminal['cancelled']) is bool
         and type(terminal['timed_out']) is bool and type(terminal['at_unix_ms']) is int
         and terminal['at_unix_ms'] >= job['created_unix_ms'], 'terminal fields invalid')
    need(terminal.get('output_complete') is True and terminal.get('output_durable') is True
         and terminal.get('log_synced') == {'stdout': True, 'stderr': True}
         and terminal.get('log_truncated') == {'stdout': False, 'stderr': False}
         and terminal.get('log_errors') == {'stdout': None, 'stderr': None}, 'terminal output not durable')
    logs = {stream: helper.decoded(files, stream + '.log') for stream in ('stdout', 'stderr')}
    need(terminal['log_bytes'] == {stream: {'seen': len(raw), 'stored': len(raw)}
                                  for stream, raw in logs.items()}, 'terminal log counters differ')
    need(logs['stdout'] == ('BEGIN ' + host + '\n').encode()
         and logs['stderr'].startswith(('HEPTA-CANARY-STDERR ' + host + '\n').encode()),
         'original fixture output differs')
    self_timeout = (terminal['exit_code'] == 1 and terminal['cancelled'] is False
                    and terminal['timed_out'] is False
                    and logs['stderr'] == ('HEPTA-CANARY-STDERR ' + host
                                          + '\nprivate release gate timed out\n').encode())
    return {'job_id': item['job_id'], 'remote_job_dir': job['remote_job_dir'],
            'launch_nonce': nonce, 'exit': terminal, 'witness': witness,
            'exit_sha256': files['exit.json']['sha256'], 'one_execution_marker': True,
            'original_request_unchanged': True, 'release_absent': True, 'cancel_request_absent': True,
            'fixture_release_gate_self_timeout': self_timeout,
            'terminal_publication_verified': True,
            'independent_pid_group_absence_verified': False,
            'outputs': {stream: {'bytes': len(raw), 'sha256': digest(raw)} for stream, raw in logs.items()}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--launcher-sha256', required=True)
    args = parser.parse_args()
    need(re.fullmatch(r'[0-9a-f]{64}', args.launcher_sha256) is not None, 'invalid launcher SHA')
    need(sys.platform == 'linux' and os.geteuid() != 0, 'non-root x230 Linux account required')
    directory_identity(OUT.parent)
    need(not os.path.lexists(OUT), 'closure output already exists; no retry/overwrite')
    OUT.mkdir(mode=0o700)
    directory_identity(OUT)
    report = {'schema': 'hepta-r23-terminal-closure/v1', 'passed': False,
              'started_unix': time.time(), 'launcher_sha256': args.launcher_sha256,
              'launcher_sha_source': 'unchanged held-agent caller input receipt',
              'original_lifecycle_passed': False, 'r23_adopted': False, 'gate_overridden': False,
              'new_jobs_started': 0, 'runtime_controllers_started': 0,
              'remote_fixture_mutations': 0, 'release_calls': 0, 'cancel_calls': 0,
              'automatic_retries': 0, 'hosts': {}, 'input_receipts': [],
              'original_report': str(ORIGINAL), 'original_report_sha256': ORIGINAL_SHA,
              'campaign_report': str(CAMPAIGN), 'campaign_report_sha256': CAMPAIGN_SHA,
              'evidence_directory_added': str(OUT),
              'directory_scope': 'New evidence child changes campaign directory metadata; original report files remain unchanged.',
              'not_covered': ['independent PID/group absence; original REMOTE has no process liveness probe'],
              'configuration_body_paths': ['profile/profile.json', 'profile/ssh_config', 'profile/known_hosts', 'bin/ssh']}
    pinned = {}
    agent_before = helper = bench = None
    socket_parent = socket_identity = None
    def pin(path, expected):
        raw = read(path, expected)
        pinned[str(path)] = expected
        report['input_receipts'].append({'path': str(path), 'bytes': len(raw), 'sha256': expected})
        return raw
    save(report)
    try:
        old = json.loads(pin(ORIGINAL, ORIGINAL_SHA))
        campaign = json.loads(pin(CAMPAIGN, CAMPAIGN_SHA))
        need(old['schema'] == 'hepta-six-host-cancel-recovery/v2' and old['passed'] is False
             and old['phase'] == 'after_transport_running'
             and old['nonce'] == '203ab6fcf4c166bcd69b31b0'
             and old['new_start_call_count'] == 6 and old['cancel_call_count'] == 0
             and old['same_key_lookup_call_count'] == 0 and old['remote_cleanup_operations'] == 0,
             'original failed lifecycle state differs')
        need(campaign['passed'] is False and campaign['adoption_passed'] is False,
             'original campaign acceptance state differs')
        need(set(old['hosts']) == set(HOSTS), 'original six-host set differs')
        topology = json.loads(pin(TOPOLOGY, TOPOLOGY_SHA))
        profile_template = json.loads(pin(PROFILE, PROFILE_SHA))
        for field in ('ssh_config', 'known_hosts'):
            pin(Path(profile_template[field]), profile_template[field + '_sha256'])
        for name, sha in HARNESS_FILES.items():
            pin(TOOLS / name, sha)
        sys.path.insert(0, str(TOOLS))
        helper = importlib.import_module('x230_six_running_recovery_canary')
        bench = helper.bench
        cancel = importlib.import_module('run_six_host_cancel_recovery')
        need(digest(cancel.REMOTE.encode()) == REMOTE_SHA == old['remote_helper_sha256'],
             'original remote helper changed')
        report['remote_helper_sha256'] = REMOTE_SHA
        records = old['controller_records']
        need(records['exact_original_set'] is True and not records['errors'] and len(records['records']) == 6,
             'original controller receipts incomplete')
        need({row['host'] for row in records['records']} == set(HOSTS), 'receipt host set differs')
        for row in records['records']:
            item = old['hosts'][row['host']]
            need(row['job_id'] == item['job_id'] and row['original_bytes_unchanged'] is True,
                 'controller receipt does not own fixture')
            raw = pin(Path(row['path']), row['sha256'])
            record = json.loads(raw)
            need(record == item['launch']['job'] and record['idempotency_key'] ==
                 'six-cancel-' + old['nonce'] + '-' + row['host'], 'original launch receipt differs')
        agent = os.environ.get('SSH_AUTH_SOCK', '')
        need(agent.startswith('/'), 'current held agent required')
        agent_before = bench.agent_identity(agent)
        report['current_agent_before'] = agent_before
        socket_parent = Path(tempfile.mkdtemp(prefix='h23t-', dir='/home/qian'))
        report['owned_socket_parent'] = {'path': str(socket_parent), 'removed': False}
        socket_identity = directory_identity(socket_parent)
        report['owned_socket_parent'].update(identity=socket_identity,
            use='fresh_profile path budget only; wrapper disables multiplexing')
        profile_path, receipt = bench.fresh_profile(PROFILE, OUT / 'profile', socket_parent, agent)
        profile = json.loads(read(profile_path))
        report['profile_receipt'] = receipt
        wrapper, wrapper_sha = helper.private_wrapper(profile, agent, OUT / 'bin')
        report['wrapper'] = {'path': str(wrapper), 'sha256': wrapper_sha}
        for path in (profile_path, Path(profile['ssh_config']), Path(profile['known_hosts']), wrapper):
            pin(path, digest(read(path)))
        for sequence, host in enumerate(HOSTS, 1):
            item = old['hosts'][host]
            row = {'ssh_target': item['ssh_target'], 'job_id': item['job_id'],
                   'mode': 'inspect', 'terminal': True, 'passed': False, 'started_unix': time.time()}
            report['hosts'][host] = row
            started = time.monotonic()
            stdout = stderr = b''
            try:
                need(item['ssh_target'] == item['launch']['job']['ssh_target']
                     and item['launch']['job']['remote_job_dir'] == item['fixture'] + '/jobs/' + item['job_id'],
                     'original host/job route differs')
                payload = {key: item[key] for key in ('base', 'name', 'source_job_id', 'source_record_sha256')}
                payload.update(host=host, nonce=old['nonce'], mode='inspect', terminal=True,
                               expected_platform='darwin' if topology['hosts'][host]['platform'] == 'macos' else 'linux',
                               fixture_identity=item['prepare']['fixture_identity'], job_id=item['job_id'])
                command = '/usr/bin/python3 -I -S - ' + shlex.quote(base64.b64encode(bench.canonical(payload)).decode())
                completed = subprocess.run([str(wrapper), '-T', item['ssh_target'], command],
                    input=cancel.REMOTE.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    timeout=20, check=False, env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'SSH_AUTH_SOCK': agent})
                stdout, stderr = completed.stdout, completed.stderr
                row['returncode'] = completed.returncode
                need(completed.returncode == 0 and len(stdout) <= helper.REMOTE_LIMIT and len(stderr) <= 65536,
                     'independent terminal inspect failed')
                proof = json.loads(stdout)
                row['terminal_receipt'] = validate_terminal(host, item, old, proof, helper)
                row['passed'] = True
            except subprocess.TimeoutExpired as error:
                stdout, stderr = error.stdout or b'', error.stderr or b''
                row['error'] = 'TimeoutExpired: original 20-second inspection bound; no retry'
            except Exception as error:
                row['error'] = type(error).__name__ + ': ' + str(error)[:1500]
            finally:
                for stream, raw in (('stdout', stdout), ('stderr', stderr)):
                    path = OUT / ('ssh-%02d-%s-inspect.%s' % (sequence, host, stream))
                    create(path, raw)
                    row[stream] = {'path': str(path), 'bytes': len(raw), 'sha256': digest(raw)}
                row['elapsed_ms'] = 1000 * (time.monotonic() - started)
                save(report)
        need(all(report['hosts'][host]['passed'] for host in HOSTS), 'one or more original fixtures lack validated terminal receipts')
        report['six_terminal_receipts_verified'] = True
        report['all_fixture_release_gate_self_timeouts'] = all(
            row['terminal_receipt']['fixture_release_gate_self_timeout'] for row in report['hosts'].values())
        report['passed'] = True
    except Exception as error:
        report['error'] = type(error).__name__ + ': ' + str(error)[:2000]
    finally:
        try:
            for path, sha in pinned.items():
                read(Path(path), sha)
            report['pinned_inputs_unchanged'] = True
            if agent_before is not None:
                report['current_agent_after'] = bench.agent_identity(agent)
                need(report['current_agent_after'] == agent_before, 'current held agent identity changed')
                report['current_agent_unchanged'] = True
        except Exception as error:
            report['passed'] = False
            report['final_input_check_error'] = type(error).__name__ + ': ' + str(error)[:2000]
        if socket_parent is not None:
            try:
                need(directory_identity(socket_parent) == socket_identity, 'owned empty socket parent identity changed')
                socket_parent.rmdir()
                report['owned_socket_parent']['removed'] = True
            except Exception as error:
                report['passed'] = False
                report['owned_socket_parent']['cleanup_error'] = type(error).__name__ + ': ' + str(error)[:1000]
        report['finished_unix'] = time.time()
        save(report)
    print(json.dumps({'passed': report['passed'], 'report': str(OUT / 'report.json'),
                      'original_lifecycle_passed': False, 'r23_adopted': False,
                      'error': report.get('error')}, sort_keys=True), flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())

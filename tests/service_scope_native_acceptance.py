#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Real six-host candidate checks using independent controller and HOME fixtures.

Never restarts installed services, reads the installed token, deletes unknown
fixtures, changes host policy, or replays an uncertain process launch. All
candidate controllers are direct children. Fixture files and logs are retained
for review. New processes are finite and recorded by their original job IDs.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
import pathlib
import secrets
import socket
import subprocess
import sys
import time
import traceback

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('operation_fixture', ROOT / 'tests/dc_functional_v10_operation_explicit_state_acceptance.py')
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def private_write(path, value):
    data = value.encode() if isinstance(value, str) else value
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def bounded_wait(test, seconds=60):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        result = test()
        if result:
            return result
        time.sleep(.15)
    raise TimeoutError('bounded candidate observation expired')


def text_payload(raw):
    assert raw.get('isError') is not True, 'retained native SDK result contains an error'
    return M.text_result(raw)


class ObservedClient(M.Client):
    """Retain refused native results privately, without logging credentials."""
    def __init__(self, url, token, evidence_root):
        self.evidence_root = evidence_root
        self.refusal_count = 0
        super().__init__(url, token)

    def call(self, tool, arguments):
        raw = self.raw_call(tool, arguments)
        if raw.get('isError') is True:
            self.refusal_count += 1
            private_write(self.evidence_root / ('native-refusal-%s-%d.json' % (secrets.token_hex(6), self.refusal_count)),
                          json.dumps({'tool': tool, 'result': raw}, ensure_ascii=False))
            raise RuntimeError('native tool refusal: ' + tool)
        return M.text_result(raw)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--binary', required=True)
    ap.add_argument('--binary-sha256', required=True)
    ap.add_argument('--run-root', required=True)
    ap.add_argument('--operator-config', required=True)
    ap.add_argument('--hosts', nargs='+', choices=['main', 'pocket4', 'rog', 'mac', 'x230', 'ai395'])
    args = ap.parse_args()
    binary = pathlib.Path(args.binary).resolve(strict=True)
    assert sha(binary) == args.binary_sha256
    base = pathlib.Path(args.run_root).absolute()
    base.mkdir(mode=0o700, parents=False, exist_ok=False)
    source = M.source_identity()
    report = {'schema': 'hepta-service-scope-six-host-native-v1', 'complete': False,
              'origin': 'local_http_candidate_real_configured_ssh_hosts',
              'model_origin_new_catalog_qualified': False,
              'full_dc_replacement_qualified': False,
              'production_activation': False, 'dc_stop_or_restart_requested': False,
              'binary_sha256': sha(binary), 'harness_sha256': sha(__file__),
              'source_fingerprint': source['source_code_fingerprint'],
              'base_commit': source['base_HEAD'], 'checks': [], 'hosts': {},
              'controller_instances': [], 'errors': []}
    report_path = base / 'report.json'
    private_write(base / 'harness.py', pathlib.Path(__file__).read_bytes())
    private_write(base / 'source-identity.json', json.dumps(source, sort_keys=True))
    config = copy.deepcopy(json.loads(pathlib.Path(args.operator_config).read_text()))
    all_names = ['main', 'pocket4', 'rog', 'mac', 'x230', 'ai395']
    assert set(config['hosts']) == set(all_names), 'requires reviewed six-host configuration'
    names = args.hosts or all_names
    assert names[0] == 'main' and len(names) == len(set(names)), 'main recovery control must be first; hosts must be unique'
    report['tested_hosts'] = names
    report['six_host_scope'] = set(names) == set(all_names)
    state = base / 'state'; state.mkdir(mode=0o700)
    workspace = base / 'workspace'; workspace.mkdir(mode=0o700)
    token = secrets.token_hex(32)
    token_path = base / 'token'; private_write(token_path, token)
    config['state_dir'] = str(state)
    config['controller_workspace_roots'] = [str(workspace)]
    runid = base.name
    roots = {}
    for name in all_names:
        host = config['hosts'][name]
        old_state = pathlib.PurePosixPath(host['remote_state_dir'])
        home = old_state.parents[2]
        assert str(home).startswith(('/home/', '/Users/'))
        fixture = home / ('.' + runid)
        roots[name] = {'home': str(home), 'fixture': str(fixture)}
        host['remote_state_dir'] = str(fixture / 'runtime')
        # File-tool scopes can be narrowed; arbitrary operator commands remain
        # governed by the same login OS authority, never a fictional cwd sandbox.
        host['allowed_read_path_prefixes'] = [str(fixture)]
        host['allowed_write_path_prefixes'] = [str(fixture)]
        # Preserve every other host field, including paired checkpoint pins.
        # This fixture neither invokes checkpoints nor privileged actions.
        if name in names:
            report['hosts'][name] = {'fixture': str(fixture), 'jobs': [], 'pty': None,
                                     'completed': False, 'operations': []}
    config_path = base / 'runtime.json'; private_write(config_path, json.dumps(config))
    contract = json.loads((ROOT / 'deploy/contracts/hepta-runtime-full-operator-v10.json').read_text())
    current = None
    logs = []
    client = None

    def save():
        report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n')
        report_path.chmod(0o600)

    def passed(check, detail=None):
        report['checks'].append({'check': check, 'passed': True, 'detail': detail})
        save()
        print('PASS', check, flush=True)

    def start_controller():
        nonlocal current
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
        log = (base / ('controller-%02d.log' % len(logs))).open('xb')
        os.chmod(log.name, 0o600); logs.append(log)
        current = subprocess.Popen([str(binary), 'mcp', '--path', str(workspace),
                                    '--bind', '127.0.0.1:' + str(port),
                                    '--runtime-config', str(config_path),
                                    '--auth-token-file', str(token_path)],
                                   stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        report['controller_instances'].append({'pid': current.pid, 'port': port})
        save()
        url = 'http://127.0.0.1:%d/mcp' % port
        def ready():
            assert current.poll() is None, 'owned candidate exited before readiness'
            try: return ObservedClient(url, token, base)
            except (OSError, RuntimeError): return None
        return bounded_wait(ready, 20)

    def stop_controller():
        if current is not None and current.poll() is None:
            current.terminate()
            try: current.wait(timeout=12)
            except subprocess.TimeoutExpired:
                current.kill(); current.wait(timeout=5)

    def job_start(host, code, key, timeout=60):
        params = {'host': host, 'executable': '/usr/bin/python3', 'args': ['-c', code],
                  'cwd': roots[host]['home'], 'idempotency_key': runid + '-' + key,
                  'timeout_seconds': timeout}
        # Exactly one launch request. If acknowledgement is lost, preserve the
        # key and request in private evidence rather than redispatching it.
        report['hosts'][host].setdefault('launch_intents', []).append({'key': params['idempotency_key']})
        save()
        result = client.call('process_start', params)
        identity = result['job']['id']
        report['hosts'][host]['jobs'].append(identity); save()
        return identity, params

    def job_wait(host, identity):
        result = client.call('process_wait', {'host': host, 'job_id': identity, 'timeout_seconds': 30})
        if result['state'] not in ('succeeded', 'failed', 'timed_out', 'cancelled'):
            result = client.call('process_wait', {'host': host, 'job_id': identity, 'timeout_seconds': 30})
        assert result['state'] == 'succeeded', 'owned fixture job did not succeed'
        return result

    save()
    try:
        client = start_controller()
        actual = client.rpc('tools/list', {})['tools']
        assert {x['name']: x for x in actual} == {x['name']: x for x in contract['tools']}
        passed('exact unchanged 66-tool V10 catalog', len(actual))
        scope = client.call('service_status', {'host': 'main', 'services': [
            'hepta-runtime-operator.service', 'desktop-commander-remote.service', 'ssh.service',
            'hepta-this-owned-fixture-does-not-exist.service']})
        for row in scope['services'][:2]:
            assert row['scope'] == 'user' and row['properties']['ActiveState'] == 'active'
            assert row['properties']['MainPID'] != '0'
        assert scope['services'][2]['scope'] == 'system'
        assert scope['services'][3]['resolution'] == 'not_found'
        report['fixed_service_observations'] = scope
        passed('actual active user units, system ssh and proven absence distinguished')
        marker = 'SCOPE_NATIVE_中文🙂'
        payload = (marker + '\n') * 1024
        expected_data = payload.encode()
        for host in names:
            print('HOST_BEGIN', host, flush=True)
            root = roots[host]['fixture']
            path = root + '/data/input.txt'
            code = (
                'import os,pathlib; p=pathlib.Path(' + repr(root) + '); '
                'd=p/"data"; d.mkdir(mode=0o700,parents=True,exist_ok=False); '
                'f=os.open(d/"input.txt",os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600); '
                'b=(' + repr(marker + '\n') + ').encode("utf-8")*1024; '
                'n=os.write(f,b); assert n==len(b); os.fsync(f); os.close(f); print("FIXTURE_READY")'
            )
            identity, params = job_start(host, code, host + '-setup')
            job_wait(host, identity)
            repeated = client.call('process_start', params)
            assert repeated['reused'] and repeated['job']['id'] == identity
            passed(host + ': same idempotency key returns original completed job')
            operations = [
                ('read_multiple_files', {'host': host, 'paths': [path], 'max_file_bytes': 65536, 'max_response_bytes': 262144}),
                ('file_info', {'host': host, 'path': path}),
                ('binary_read', {'host': host, 'path': path, 'limit': 65536}),
                ('process_status', {'host': host, 'job_id': identity}),
                ('process_read', {'host': host, 'job_id': identity}),
                ('process_wait', {'host': host, 'job_id': identity, 'timeout_seconds': 1}),
                ('process_list', {'host': host}),
                ('hardware_snapshot', {'host': host}),
                ('service_status', {'host': host, 'services': ['ssh.service'] if host != 'mac' else ['com.apple.logd']}),
                ('network_inspect', {'host': host}),
            ]
            for number, (tool, arguments) in enumerate(operations):
                started = M.start_operation(client, tool, arguments, runid + '-' + host + '-' + str(number))
                attempt = {'tool': tool, 'id': started['operation_id']}
                report['hosts'][host].setdefault('operation_attempts', []).append(attempt)
                save()
                status = M.settled(client, started['operation_id'])
                attempt['observed_status'] = status
                save()
                assert status['async_state'] == 'completed' and status['payload_available']
                recovered, meta = M.reconstructed(client, started['operation_id'])
                value = text_payload(recovered)
                if tool == 'read_multiple_files':
                    assert len(value['files']) == 1 and value['files'][0]['text'] == payload
                    assert value['files'][0]['sha256'] == hashlib.sha256(expected_data).hexdigest()
                if tool == 'file_info':
                    assert value['size'] == len(expected_data)
                    assert value['sha256'] == hashlib.sha256(expected_data).hexdigest()
                if tool == 'process_list':
                    assert identity in json.dumps(value)
                if tool == 'network_inspect':
                    assert value['interfaces' if host == 'mac' else 'links']['exit_code'] == 0
                if tool == 'binary_read':
                    import base64
                    assert base64.b64decode(value['data_base64'], validate=True) == expected_data
                if tool in ('process_status', 'process_wait'):
                    assert value['state'] == 'succeeded'
                if tool == 'process_read':
                    assert value['stdout']['text'].strip() == 'FIXTURE_READY'
                if tool == 'hardware_snapshot': assert value.get('hostname')
                report['hosts'][host]['operations'].append({'tool': tool, 'id': started['operation_id'], **meta})
                save()
            passed(host + ': ten native asynchronous result arms reconstructed and SHA256 verified', 10)
            started = client.call('search_start', {'host': host, 'root': root + '/data', 'query': 'input', 'kind': 'files'})
            search_id = started['search']['search_id']
            report['hosts'][host]['search_id'] = search_id; save()
            def search_done():
                value = client.call('search_results', {'search_id': search_id, 'limit': 7})
                return value if value['search']['state'] in ('completed', 'failed', 'cancelled', 'interrupted') else None
            searched = bounded_wait(search_done, 30)
            assert searched['search']['state'] == 'completed'
            assert searched['snapshot']['results'] == [{'path': 'input.txt'}]
            passed(host + ': native owned HOME search lifecycle')
            pty = client.call('pty_start', {'host': host, 'executable': '/usr/bin/python3',
                'args': ['-c', 'import sys; s=sys.stdin.readline(); print("PTY_SCOPE_OK:"+s.strip(),flush=True)'],
                'cwd': roots[host]['home'], 'idempotency_key': runid + '-' + host + '-pty'})
            sid = pty['session_id']; report['hosts'][host]['pty'] = sid; save()
            client.call('pty_write', {'host': host, 'session_id': sid, 'data': 'scope-input\n', 'request_id': runid+'-input-'+host})
            def pty_done():
                value = client.call('pty_read', {'host': host, 'session_id': sid})
                return value if value.get('status', {}).get('state') == 'exited' else None
            terminal = bounded_wait(pty_done, 20)
            assert 'PTY_SCOPE_OK:scope-input' in terminal['text']
            assert terminal.get('output_complete') is True
            client.call('pty_close', {'host': host, 'session_id': sid})
            report['hosts'][host]['completed'] = True
            passed(host + ': ordinary-user PTY input, complete archive, exit')
        # This crash/reconnect affects only the Popen-owned candidate, never a
        # production unit. The original host process and its key are reused.
        code = 'import time; print("BEFORE_RESTART",flush=True); time.sleep(6); print("AFTER_RESTART",flush=True)'
        identity, params = job_start('main', code, 'restart', timeout=60)
        retained = report['hosts']['main']['operations'][2]
        stop_controller()
        client = start_controller()
        repeated = client.call('process_start', params)
        assert repeated['reused'] and repeated['job']['id'] == identity
        job_wait('main', identity)
        output = client.call('process_read', {'host': 'main', 'job_id': identity})['stdout']['text']
        assert output.splitlines() == ['BEFORE_RESTART', 'AFTER_RESTART']
        _, restored_meta = M.reconstructed(client, retained['id'])
        assert restored_meta['sha256'] == retained['sha256']
        passed('owned controller restart preserves process ID, exact log and encrypted result bytes')
        assert M.source_identity() == source and sha(binary) == args.binary_sha256
        report['complete'] = True
        report['passed'] = len(report['checks'])
        save()
        print('CHECKS_PASSED_PENDING_FINAL_OBSERVATION', report['passed'], flush=True)
    except Exception as exc:
        report['errors'].append({'type': type(exc).__name__, 'frames': [
            {'file': pathlib.Path(f.filename).name, 'line': f.lineno, 'function': f.name}
            for f in traceback.extract_tb(exc.__traceback__)]})
        # Detailed exception text may contain host payloads; retain privately only.
        private_write(base / 'failure-private.txt', traceback.format_exc())
        save()
        print('FAIL', type(exc).__name__, flush=True)
    finally:
        # Read or close only identities actually acknowledged by this candidate.
        if client is not None:
            for host, row in report['hosts'].items():
                if row['pty']:
                    try:
                        value = client.call('pty_read', {'host': host, 'session_id': row['pty']})
                        if value.get('status', {}).get('state') != 'exited':
                            client.call('pty_close', {'host': host, 'session_id': row['pty']})
                        row['pty_final_state'] = client.call('pty_read', {'host': host, 'session_id': row['pty']}).get('status', {}).get('state')
                    except Exception: row['pty_final_state'] = 'unknown'
                row['job_final_states'] = {}
                for identity in row['jobs']:
                    try:
                        row['job_final_states'][identity] = client.call('process_status', {'host': host, 'job_id': identity})['state']
                    except Exception: row['job_final_states'][identity] = 'unknown'
        stop_controller()
        report['owned_controller_exit_confirmed'] = current is None or current.poll() is not None
        for log in logs: log.close()
        report['fixtures_retained_no_unknown_cleanup'] = True
        report['complete'] = report['complete'] and all(
            all(s == 'succeeded' for s in h.get('job_final_states', {}).values())
            and h.get('pty_final_state') == 'exited' for h in report['hosts'].values())
        save()
    print('ALL_PASS' if report['complete'] else 'INCOMPLETE', report.get('passed', 0), flush=True)
    return 0 if report['complete'] else 1


if __name__ == '__main__':
    sys.exit(main())

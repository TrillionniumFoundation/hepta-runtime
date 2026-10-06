#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Real SSH + MCP canary, isolated controller and disposable target workloads.
Does not install services, alter sudoers, access provider credentials or stop DC.
"""
import argparse
import json
import os
import pathlib
import re
import secrets
import shlex
import socket
import subprocess
import tempfile
import time
import uuid
from runtime_http_acceptance import Client


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--binary', required=True)
    ap.add_argument('--ssh-target', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--sudo-smoke', action='store_true')
    a = ap.parse_args()
    checks = []
    key = uuid.uuid4().hex
    target_dir = '/tmp/hepta-operator-canary-' + key
    controller = None
    log = None
    remote_pids = []

    def passed(name, detail=None):
        checks.append({'check': name, 'result': 'passed', 'detail': detail})
        pathlib.Path(a.out).write_text(json.dumps({'checks': checks, 'complete': False}, indent=2))
        print('PASS', name, flush=True)

    def ssh_python(code):
        p = subprocess.run(['ssh', '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'ForwardAgent=no', '-o', 'ConnectTimeout=8', a.ssh_target,
                            '/usr/bin/python3 -c ' + shlex.quote(code)], capture_output=True, text=True, timeout=25)
        if p.returncode:
            raise RuntimeError(p.stderr)
        return p.stdout.strip()

    def wait(c, job):
        for _ in range(10):
            r = c.call('process_wait', {'host': 'operator', 'job_id': job, 'timeout_seconds': 10})
            if r['state'] not in ('running', 'launching', 'pending'):
                return r
        raise AssertionError('test job did not finish')

    def pty_until(c, sid, marker, cursor=None):
        for _ in range(50):
            args = {'host': 'operator', 'session_id': sid}
            if cursor is not None:
                args['offset'] = cursor
            result = c.call('pty_read', args)
            if marker in result['text']:
                return result
            if result['status']['state'] != 'running':
                raise AssertionError(result)
            time.sleep(.15)
        raise AssertionError('PTY marker absent: ' + marker)

    try:
        meta = json.loads(ssh_python("import os,sys,json,pathlib; p=pathlib.Path("+repr(target_dir)+");p.mkdir(mode=0o700);print(json.dumps({'uid':os.getuid(),'platform':'linux' if sys.platform=='linux' else 'macos'}))"))
        passed('real SSH target account', meta)
        with tempfile.TemporaryDirectory(prefix='hepta-operator-controller-') as work:
            work = pathlib.Path(work)
            (work / 'workspace').mkdir()
            token = secrets.token_hex(32)
            (work / 'token').write_text(token)
            os.chmod(work / 'token', 0o600)
            host = {'ssh_target': a.ssh_target, 'platform': meta['platform'], 'remote_state_dir': target_dir, 'execution_mode': 'operator', 'allow_execute': True, 'allow_pty': True, 'allow_write': True, 'allow_job_network': True, 'allow_detached_fallback': True, 'allowed_read_path_prefixes': [target_dir], 'allowed_write_path_prefixes': [target_dir]}
            isolated = {**host, 'execution_mode': 'isolated', 'remote_state_dir': target_dir + '/isolated'}
            (work / 'runtime.json').write_text(json.dumps({'state_dir': str(work / 'state'), 'controller_workspace_roots': [str(work / 'workspace')], 'hosts': {'operator': host, 'isolated': isolated}}))
            with socket.socket() as s:
                s.bind(('127.0.0.1', 0))
                port = s.getsockname()[1]
            url = f'http://127.0.0.1:{port}/mcp'

            def connect():
                for _ in range(80):
                    if controller.poll() is not None:
                        raise RuntimeError((work / 'controller.log').read_text())
                    try:
                        return Client(url, token)
                    except (OSError, RuntimeError):
                        time.sleep(.1)
                raise RuntimeError('test controller did not become ready')

            def start_controller():
                nonlocal controller, log
                log = open(work / 'controller.log', 'ab')
                controller = subprocess.Popen([a.binary, 'mcp', '--path', str(work / 'workspace'), '--bind', f'127.0.0.1:{port}', '--runtime-config', str(work / 'runtime.json'), '--auth-token-file', str(work / 'token')], stdin=subprocess.DEVNULL, stdout=log, stderr=log)
                return connect()

            c = start_controller()
            names = {t['name'] for t in c.rpc('tools/list', {})['tools']}
            assert {'shell_start', 'host_processes', 'host_signal', 'sudo_start'} <= names
            assert 'shell' not in names
            caps = {h['name']: h for h in c.call('host_list', {})['hosts']}
            assert caps['operator']['operator_tools'] and not caps['isolated']['operator_tools']
            passed('real authenticated MCP discovery and explicit capability mode')
            c.call('shell_start', {'host': 'isolated', 'command': 'id'}, denied=True)
            c.call('process_start', {'host': 'isolated', 'executable': '/bin/bash'}, denied=True)
            c.call('sudo_start', {'host': 'isolated', 'executable': '/usr/bin/id'}, denied=True)
            c.call('host_signal', {'host': 'isolated', 'pid': 1, 'signal': 0}, denied=True)
            passed('all operator entry points rejected on isolated host without target execution')
            params = {'host': 'operator', 'command': "printf 'alpha\\nbeta\\n' | tail -n1 > canary.txt; cat canary.txt; printf '%s\\n' \"$PARITY_ENV\"; id -u", 'cwd': target_dir, 'env': {'PARITY_ENV': '中文 ; $() literal'}, 'idempotency_key': key+'-shell', 'timeout_seconds': 20}
            started = c.call('shell_start', params)
            job = started['job']['id']
            assert not started['job']['system_jobctl']
            assert wait(c, job)['state'] == 'succeeded'
            text = c.call('process_read', {'host': 'operator', 'job_id': job})['stdout']['text']
            assert 'beta\n' in text and '中文 ; $() literal' in text and str(meta['uid']) in text
            assert c.call('shell_start', params)['job']['id'] == job
            c.call('shell_start', {**params, 'command': 'echo DIFFERENT'}, denied=True)
            passed('shell pipes/redirects/env/Unicode/real UID/idempotency', {'backend': started['launch'], 'uid': meta['uid']})
            view = c.call('view', {'path': f'ssh://{a.ssh_target}{target_dir}/canary.txt'})
            assert 'beta' in str(view)
            passed('native remote file API sees the same operator-created file')
            page = c.call('host_processes', {'host': 'operator', 'limit': 2})
            assert len(page['processes']) <= 2
            passed('actual host PID pagination')
            # Created outside runtime: demonstrates signalling non-runtime-owned jobs.
            spawned = json.loads(ssh_python("import subprocess,sys,json; p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(90)'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True); print(json.dumps({'pid':p.pid}))"))
            pid = spawned['pid']
            page = c.call('host_processes', {'host': 'operator', 'after_pid': pid-1, 'limit': 1})
            row = page['processes'][0]
            assert row['pid'] == pid
            remote_pids.append((pid, row['identity']))
            sig = {'host': 'operator', 'pid': pid, 'expected_identity': row['identity'], 'signal': 0}
            assert c.call('host_signal', sig)['result'] == 'probe_succeeded'
            c.call('host_signal', {**sig, 'signal': 15, 'expected_identity': 'wrong-start-identity'}, denied=True)
            assert c.call('host_signal', sig)['result'] == 'probe_succeeded'
            sent = c.call('host_signal', {**sig, 'signal': 15})
            assert sent['result'] == 'signal_sent' and not sent['termination_confirmed']
            if meta['platform'] == 'linux':
                assert sent['atomic_identity']
            passed('external disposable PID: stale identity denied, actual signal delivered', sent)
            sid = c.call('pty_start', {'host': 'operator', 'executable': '/bin/sh', 'args': ['-i'], 'cwd': target_dir})['session_id']
            c.call('pty_write', {'host': 'operator', 'session_id': sid, 'data': "printf 'PTY_%s\\n' OK\n"})
            pty_until(c, sid, 'PTY_OK')
            c.call('pty_write', {'host': 'operator', 'session_id': sid, 'data': 'sleep 30\n'})
            time.sleep(.2)
            c.call('pty_write', {'host': 'operator', 'session_id': sid, 'data': '\x03'})
            c.call('pty_write', {'host': 'operator', 'session_id': sid, 'data': "printf 'CTRL_%s\\n' OK\n"})
            pty_until(c, sid, 'CTRL_OK')
            c.call('pty_write', {'host': 'operator', 'session_id': sid, 'data': 'exit\n'})
            c.call('pty_close', {'host': 'operator', 'session_id': sid})
            passed('real SSH PTY shell input/output/Ctrl-C/close')
            if a.sudo_smoke:
                sid = c.call('sudo_start', {'host': 'operator', 'executable': '/usr/bin/id', 'args': ['-u'], 'non_interactive': True})['session_id']
                result = pty_until(c, sid, '0\r\n')
                c.call('pty_close', {'host': 'operator', 'session_id': sid})
                passed('temporary sudo PTY real uid=0 using existing authorization only')
                p = {'host': 'operator', 'executable': '/usr/bin/sudo', 'args': ['-n', '--', '/usr/bin/id', '-u'], 'cwd': target_dir, 'timeout_seconds': 15}
                j = c.call('process_start', p)['job']['id']
                assert wait(c, j)['state'] == 'succeeded'
                assert c.call('process_read', {'host': 'operator', 'job_id': j})['stdout']['text'].strip() == '0'
                passed('durable operator backend does not accidentally block existing sudo')
                root_sid = c.call('sudo_start', {'host': 'operator', 'executable': '/usr/bin/python3', 'args': ['-c', "import os,time;print('ROOT_PID='+str(os.getpid()),flush=True);time.sleep(40)"], 'non_interactive': True})['session_id']
                root_text = pty_until(c, root_sid, 'ROOT_PID=')['text']
                root_pid = int(re.search(r'ROOT_PID=(\d+)', root_text).group(1))
                root_row = c.call('host_processes', {'host': 'operator', 'after_pid': root_pid-1, 'limit': 1})['processes'][0]
                assert root_row['pid'] == root_pid and root_row['uid'] == 0
                root_sig = {'host': 'operator', 'pid': root_pid, 'expected_identity': root_row['identity'], 'signal': 0}
                if meta['uid'] != 0:
                    c.call('host_signal', root_sig, denied=True)
                delivered = c.call('host_signal', {**root_sig, 'signal': 15, 'sudo': True})
                assert delivered['effective_uid'] == 0 and delivered['result'] == 'signal_sent'
                c.call('pty_close', {'host': 'operator', 'session_id': root_sid})
                passed('real root-owned disposable PID: user permission denied, explicit existing sudo signal works')
            resume = {**params, 'command': "printf x >> once; printf 'START\\n'; sleep 10; printf 'COUNT='; wc -c < once", 'idempotency_key': key+'-restart', 'timeout_seconds': 30}
            j = c.call('shell_start', resume)['job']['id']
            controller.terminate()
            controller.wait(timeout=10)
            log.close()
            c = start_controller()
            assert c.call('shell_start', resume)['job']['id'] == j
            assert wait(c, j)['state'] == 'succeeded'
            text = c.call('process_read', {'host': 'operator', 'job_id': j})['stdout']['text']
            assert 'COUNT=1' in text.replace(' ', '')
            passed('actual test-controller restart: same job, logs, once-only side effect')
            controller.terminate()
            controller.wait(timeout=10)
            log.close()
            controller = None
        pathlib.Path(a.out).write_text(json.dumps({'checks': checks, 'complete': True, 'passed': len(checks), 'ssh_target': a.ssh_target, 'target_test_directory': target_dir, 'password_prompt_tested': False, 'chatgpt_tunnel_tested': False}, indent=2))
        print('ALL_PASS', len(checks), flush=True)
    finally:
        if controller is not None and controller.poll() is None:
            controller.terminate()
            controller.wait(timeout=10)
        if log is not None:
            log.close()
        # Test metadata is deliberately retained for evidence; external sleeps
        # self-expire after 90 seconds. No generic PID cleanup can hit a reused PID.


if __name__ == '__main__':
    main()

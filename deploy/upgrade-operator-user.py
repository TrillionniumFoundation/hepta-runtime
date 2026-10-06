#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Upgrade only the existing user operator controller, with checked rollback.
Never changes DC, target sudoers/PAM, runtime config, token, or tunnel settings.
"""
import argparse
import datetime
import fcntl
import hashlib
import json
import os
import pathlib
import secrets
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICE = 'hepta-runtime-operator.service'
DC = 'desktop-commander-remote.service'
URL = 'http://127.0.0.1:8790/mcp'
sys.path.insert(0, str(ROOT / 'tests'))
from runtime_http_acceptance import Client


def run(args):
    p = subprocess.run(args, check=True, text=True, capture_output=True, timeout=40)
    return p.stdout.strip()


def sha(path):
    with pathlib.Path(path).open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def atomic(path, content, mode=0o600):
    temp = path.with_name(path.name + '.new-' + secrets.token_hex(6))
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
    finally:
        if temp.exists(): temp.unlink()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--binary', required=True)
    ap.add_argument('--matrix', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--sudo-smoke', action='store_true')
    ap.add_argument('--exercise-rollback', action='store_true', help='After starting a qualified candidate, inject a validation failure and verify restoration of the original release')
    a = ap.parse_args()
    if not __debug__:
        raise RuntimeError('qualification requires Python assertions enabled')
    if os.geteuid() == 0:
        raise RuntimeError('use the existing normal desktop login, not root')
    os.environ.setdefault('XDG_RUNTIME_DIR', f'/run/user/{os.getuid()}')
    os.environ.setdefault('DBUS_SESSION_BUS_ADDRESS', f'unix:path=/run/user/{os.getuid()}/bus')
    home = pathlib.Path.home()
    conf = home / '.config/hepta-runtime-operator'
    unit = home / '.config/systemd/user' / SERVICE
    manifest = json.loads((conf / 'manifest.json').read_text())
    matrix = json.loads(pathlib.Path(a.matrix).read_text())
    binary = pathlib.Path(a.binary).resolve(strict=True)
    digest = sha(binary)
    if not matrix.get('complete') or matrix.get('binary_sha256') != digest:
        raise RuntimeError('release has no matching successful real-host matrix')
    if manifest.get('endpoint') != URL or manifest.get('service') != SERVICE:
        raise RuntimeError('unexpected installation; no changes made')
    hosts = manifest['hosts']
    if {x['host'] for x in matrix['results']} != set(hosts):
        raise RuntimeError('matrix does not cover the installed host set')
    if any(x['exit_code'] != 0 or not x['acceptance']['complete'] for x in matrix['results']):
        raise RuntimeError('incomplete host acceptance')
    token = (conf / 'token').read_text().strip()

    def connect():
        for _ in range(60):
            try: return Client(URL, token)
            except (OSError, RuntimeError): time.sleep(.2)
        raise RuntimeError('operator endpoint not ready')

    def pid(service):
        return int(run(['systemctl', '--user', 'show', service, '-p', 'MainPID', '--value']))

    checks = []
    def passed(name):
        checks.append(name)
        print('PASS', name, flush=True)

    with (conf / 'install.lock').open('a') as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        client = connect()
        if any(x['status']['state'] == 'running' for x in client.call('pty_list', {})['sessions']):
            raise RuntimeError('active PTY exists; upgrade would interrupt it')
        old_pid = pid(SERVICE)
        old_sha = sha(f'/proc/{old_pid}/exe')
        if old_sha != manifest['binary_sha256']:
            raise RuntimeError('running binary differs from installation manifest')
        dc_pid = pid(DC)
        if not dc_pid:
            raise RuntimeError('DC rescue service is not active')
        before = unit.read_text()
        old_path = manifest['binary']
        if before.count('"' + old_path + '"') != 1:
            raise RuntimeError('unit differs from expected immutable release layout')
        release = home / '.local/lib/hepta-runtime/releases' / ('operator-' + digest[:16])
        release.mkdir(parents=True, exist_ok=True)
        installed = release / 'hepta-runtime'
        if not installed.exists():
            temp = release / ('hepta-runtime.new-' + secrets.token_hex(6))
            shutil.copyfile(binary, temp)
            temp.chmod(0o755)
            if sha(temp) != digest: raise RuntimeError('copy checksum failed')
            os.replace(temp, installed)
        if sha(installed) != digest: raise RuntimeError('release checksum mismatch')
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        backup = conf / ('rollback-' + stamp + '.service')
        atomic(backup, before)
        atomic(conf / ('rollback-' + stamp + '.manifest.json'), json.dumps(manifest, indent=2))
        report = {'source_revision': matrix['source_revision'], 'binary_sha256': digest,
                  'previous_binary_sha256': old_sha, 'recorded_at': stamp,
                  'service': SERVICE, 'endpoint': URL, 'rollback_unit': str(backup),
                  'desktop_commander_pid_before': dc_pid, 'checks': checks,
                  'installed': False, 'chatgpt_tunnel_verified': False,
                  'password_prompt_tested': False, 'reboot_tested': False}
        try:
            atomic(unit, before.replace('"' + old_path + '"', '"' + str(installed) + '"'))
            run(['systemd-analyze', '--user', 'verify', str(unit)])
            run(['systemctl', '--user', 'daemon-reload'])
            run(['systemctl', '--user', 'restart', SERVICE])
            client = connect()
            names = {x['name']: x for x in client.call('host_list', {})['hosts']}
            assert set(names) == set(hosts) and all(h['execution_mode'] == 'operator' for h in names.values())
            passed('installed authenticated host discovery and operator modes')
            if a.exercise_rollback:
                raise RuntimeError('HEPTA_EXPECTED_ROLLBACK_DRILL')
            for name, metadata in hosts.items():
                j = client.call('process_start', {'host': name, 'executable': '/usr/bin/id', 'args': ['-u'], 'timeout_seconds': 15})['job']['id']
                status = client.call('process_wait', {'host': name, 'job_id': j, 'timeout_seconds': 20})
                assert status['state'] == 'succeeded' and status['output_complete'], (name, status)
                text = client.call('process_read', {'host': name, 'job_id': j})['stdout']['text'].strip()
                assert text == str(metadata['uid']), (name, text)
                passed('installed UID and complete durable output: ' + name)
                if a.sudo_smoke:
                    sid = client.call('sudo_start', {'host': name, 'executable': '/usr/bin/id', 'args': ['-u'], 'non_interactive': True})['session_id']
                    for _ in range(60):
                        part = client.call('pty_read', {'host': name, 'session_id': sid})
                        if part['status']['state'] != 'running': break
                        time.sleep(.1)
                    assert part['output_complete'] and '0\r\n' in part['text'], (name, part)
                    client.call('pty_close', {'host': name, 'session_id': sid})
                    passed('installed existing sudo UID 0: ' + name)
            sid = client.call('pty_start', {'host': 'main', 'executable': '/usr/bin/python3', 'args': ['-c', "print('中文α🦀',end='')"]})['session_id']
            text, cursor = '', 0
            for _ in range(200):
                part = client.call('pty_read', {'host': 'main', 'session_id': sid, 'offset': cursor, 'limit': 1})
                assert not part['text_is_lossy'], part
                text += part['text']; cursor = part['next_offset']
                if part['status']['state'] != 'running' and cursor == part['available_end']: break
                time.sleep(.01)
            assert '中文α🦀' in text and part['output_complete'], part
            raw = client.call('pty_read', {'host': 'main', 'session_id': sid, 'offset': 0, 'limit': 1, 'raw_bytes': True})
            assert raw['next_offset'] == 1
            client.call('pty_close', {'host': 'main', 'session_id': sid})
            passed('installed real Unicode text pages and exact raw-byte compatibility')
            try:
                urllib.request.urlopen(urllib.request.Request(URL, data=b'{}', headers={'Content-Type': 'application/json'}), timeout=5)
                raise AssertionError('unauthenticated endpoint request accepted')
            except urllib.error.HTTPError as error:
                assert error.code == 401
            passed('installed endpoint rejects missing token')
            key = secrets.token_hex(12)
            params = {'host': 'main', 'command': f"printf x >> once-{key}; sleep 5; printf 'COUNT='; wc -c < once-{key}",
                      'cwd': str(home / '.local/share/hepta-runtime-operator/workspace'), 'idempotency_key': key, 'timeout_seconds': 20}
            job = client.call('shell_start', params)['job']['id']
            run(['systemctl', '--user', 'restart', SERVICE]); client = connect()
            assert client.call('shell_start', params)['job']['id'] == job
            status = client.call('process_wait', {'host': 'main', 'job_id': job, 'timeout_seconds': 20})
            assert status['state'] == 'succeeded' and status['output_complete']
            text = client.call('process_read', {'host': 'main', 'job_id': job})['stdout']['text']
            assert 'COUNT=1' in text.replace(' ', '')
            passed('installed controller restart preserves once-only durable job')
            actual_pid = pid(SERVICE)
            assert sha(f'/proc/{actual_pid}/exe') == digest
            assert pid(DC) == dc_pid
            assert run(['systemctl', '--user', 'is-active', SERVICE]) == 'active'
            passed('actual running binary checksum and unchanged DC PID')
            report.update({'installed': True, 'verified': True, 'pid': actual_pid,
                           'binary': str(installed), 'active': 'active',
                           'enabled': run(['systemctl', '--user', 'is-enabled', SERVICE]),
                           'desktop_commander_pid_after': pid(DC), 'desktop_commander_changed': False})
            new_manifest = {**manifest, **report, 'binary_source_revision': matrix['source_revision'],
                            'deployment_source_revision': run(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'])}
            atomic(conf / 'manifest.json', json.dumps(new_manifest, indent=2) + '\n')
            atomic(pathlib.Path(a.out), json.dumps(report, indent=2) + '\n')
            print('UPGRADE_VERIFIED', digest, flush=True)
        except BaseException as error:
            atomic(conf / 'manifest.json', json.dumps(manifest, indent=2) + '\n')
            atomic(unit, before)
            run(['systemctl', '--user', 'daemon-reload'])
            run(['systemctl', '--user', 'restart', SERVICE])
            connect()
            report.update({'rolled_back': sha(f'/proc/{pid(SERVICE)}/exe') == old_sha,
                           'error': type(error).__name__ + ': ' + str(error)})
            report['desktop_commander_pid_after'] = pid(DC)
            report['original_unit_restored'] = unit.read_text() == before
            report['original_manifest_restored'] = json.loads((conf / 'manifest.json').read_text()) == manifest
            expected = a.exercise_rollback and str(error) == 'HEPTA_EXPECTED_ROLLBACK_DRILL'
            report['rollback_drill_passed'] = bool(expected and report['rolled_back'] and report['original_unit_restored'] and report['original_manifest_restored'] and pid(DC) == dc_pid)
            atomic(pathlib.Path(a.out), json.dumps(report, indent=2) + '\n')
            if report['rollback_drill_passed']:
                print('ROLLBACK_DRILL_VERIFIED', old_sha, flush=True)
                return
            raise


if __name__ == '__main__':
    main()

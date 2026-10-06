#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Install a separate loopback-only operator controller as the current user.
Never alters Desktop Commander, sudoers, existing runtime units or SSH credentials.
Refuses to overwrite an existing installation; preserve it for explicit upgrades.
"""
import argparse
import fcntl
import hashlib
import json
import os
import pathlib
import re
import secrets
import shlex
import shutil
import socket
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICE = 'hepta-runtime-operator.service'


def run(args, **kwargs):
    try:
        return subprocess.run(args, check=True, text=True, capture_output=True, timeout=40, **kwargs)
    except subprocess.CalledProcessError as error:
        raise RuntimeError(f"{args[0]} exited {error.returncode}: {error.stderr.strip()}") from None


def digest(path):
    with pathlib.Path(path).open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def atomic_write(path, content, mode=0o600):
    path = pathlib.Path(path)
    tmp = path.with_name(path.name + '.new-' + secrets.token_hex(6))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, 'w') as f:
        f.write(content)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def unit_quote(value):
    return '"' + str(value).replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%') + '"'


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--binary')
    ap.add_argument('--host', action='append', required=True, help='runtime-name=existing-SSH-alias; repeat for each explicitly trusted host')
    ap.add_argument('--port', type=int, default=8790)
    ap.add_argument('--check-only', action='store_true')
    ap.add_argument('--out', required=True, help='Non-secret installation/inspection report')
    a = ap.parse_args()
    if not a.check_only and os.geteuid() == 0:
        raise RuntimeError("install this controller as the normal desktop login, not root")
    os.environ.setdefault('XDG_RUNTIME_DIR', f'/run/user/{os.getuid()}')
    os.environ.setdefault('DBUS_SESSION_BUS_ADDRESS', f"unix:path=/run/user/{os.getuid()}/bus")
    if not 1024 <= a.port <= 65535:
        ap.error('use an unprivileged port in 1024..65535')
    hosts, meta = {}, {}
    for item in a.host:
        name, sep, alias = item.partition('=')
        if not sep or not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', name) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', alias) or name.startswith('-') or alias.startswith('-'):
            ap.error('host must be a simple name=existing-SSH-alias, not a raw user/port override')
        if name in hosts:
            ap.error('duplicate host name')
        code = "import json,os,pathlib,platform,sys;print(json.dumps({'hostname':platform.node(),'uid':os.getuid(),'home':str(pathlib.Path.home()),'platform':'linux' if sys.platform=='linux' else 'macos' if sys.platform=='darwin' else sys.platform}))"
        p = run(['ssh', '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'ForwardAgent=no', '-o', 'ConnectTimeout=8', alias, '/usr/bin/python3 -c ' + shlex.quote(code)])
        m = json.loads(p.stdout)
        if m['platform'] not in ('linux', 'macos') or not m['home'].startswith('/'):
            raise RuntimeError('unsupported or unresolved target platform/home: ' + name)
        meta[name] = m
        hosts[name] = {'ssh_target': alias, 'platform': m['platform'], 'execution_mode': 'operator',
                       'remote_state_dir': m['home'] + '/.local/state/hepta-runtime-operator-host',
                       'allow_execute': True, 'allow_pty': True, 'allow_write': True,
                       'allow_job_network': True, 'allow_detached_fallback': True,
                       'allowed_read_path_prefixes': ['/'], 'allowed_write_path_prefixes': ['/']}
    report = {'hosts': meta, 'operator_authority': 'configured SSH login and its existing OS/sudo permissions', 'installed': False}
    if a.check_only:
        pathlib.Path(a.out).write_text(json.dumps(report, indent=2))
        print(json.dumps(report, indent=2))
        return
    if not a.binary:
        ap.error('--binary is required to install')
    binary = pathlib.Path(a.binary).resolve(strict=True)
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise RuntimeError('binary is not an executable file')
    revision = run(['git', 'rev-parse', 'HEAD'], cwd=ROOT).stdout.strip()
    run(['git', 'diff', '--quiet', 'HEAD', '--'], cwd=ROOT)
    sha = digest(binary)
    home = pathlib.Path.home()
    conf = home / '.config/hepta-runtime-operator'
    state = home / '.local/state/hepta-runtime-operator'
    workspace = home / '.local/share/hepta-runtime-operator/workspace'
    unit = home / '.config/systemd/user' / SERVICE
    release = home / '.local/lib/hepta-runtime/releases' / ('operator-' + sha[:16])
    for folder in [conf, state, workspace]:
        folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (conf / 'install.lock').open('a') as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        if unit.exists() or (conf / 'runtime.json').exists() or (conf / 'token').exists():
            raise RuntimeError('operator installation already exists; nothing overwritten; use a reviewed explicit upgrade')
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', a.port))
        release.mkdir(parents=True, exist_ok=True)
        installed = release / 'hepta-runtime'
        if installed.exists():
            if digest(installed) != sha:
                raise RuntimeError('existing immutable release hash mismatch')
        else:
            shutil.copy2(binary, installed)
            installed.chmod(0o755)
        if digest(installed) != sha:
            raise RuntimeError('installed binary verification failed')
        token = secrets.token_hex(32)
        atomic_write(conf / 'token', token + '\n', 0o400)
        cfg = {'state_dir': str(state), 'controller_workspace_roots': ['/'], 'hosts': hosts}
        atomic_write(conf / 'runtime.json', json.dumps(cfg, indent=2) + '\n')
        unit.parent.mkdir(parents=True, exist_ok=True)
        command = [installed, 'mcp', '--path', workspace, '--bind', f'127.0.0.1:{a.port}', '--runtime-config', conf / 'runtime.json', '--auth-token-file', conf / 'token']
        content = '[Unit]\nDescription=Hepta Runtime trusted operator controller\nStartLimitIntervalSec=60\nStartLimitBurst=5\n\n[Service]\nType=simple\nExecStart=' + ' '.join(map(unit_quote, command)) + '\nWorkingDirectory=' + str(workspace).replace('%', '%%') + '\nEnvironment=PATH=/usr/local/bin:/usr/bin:/bin\nNoNewPrivileges=yes\nUMask=0077\nRestart=on-failure\nRestartSec=3\nTimeoutStopSec=15\nKillMode=control-group\n\n[Install]\nWantedBy=default.target\n'
        atomic_write(unit, content)
        url = f'http://127.0.0.1:{a.port}/mcp'
        try:
            run(['systemd-analyze', '--user', 'verify', str(unit)])
            run(['systemctl', '--user', 'daemon-reload'])
            run(['systemctl', '--user', 'enable', '--now', SERVICE])
            sys.path.insert(0, str(ROOT / 'tests'))
            from runtime_http_acceptance import Client
            client = None
            for _ in range(60):
                try:
                    client = Client(url, token)
                    break
                except (OSError, RuntimeError):
                    time.sleep(.2)
            if client is None:
                raise RuntimeError('installed endpoint did not become ready')
            listed = client.call('host_list', {})['hosts']
            assert {h['name'] for h in listed} == set(hosts)
            assert all(h['execution_mode'] == 'operator' for h in listed)
            for name in hosts:
                j = client.call('process_start', {'host': name, 'executable': '/usr/bin/id', 'args': ['-u'], 'timeout_seconds': 15})['job']['id']
                status = client.call('process_wait', {'host': name, 'job_id': j, 'timeout_seconds': 20})
                assert status['state'] == 'succeeded', (name, status)
                value = client.call('process_read', {'host': name, 'job_id': j})['stdout']['text'].strip()
                assert value == str(meta[name]['uid']), (name, value)
            run(['systemctl', '--user', 'is-active', SERVICE])
            report.update({'installed': True, 'source_revision': revision, 'binary_sha256': sha,
                           'binary': str(installed), 'service': SERVICE, 'endpoint': url,
                           'token_file': str(conf / 'token'), 'config_file': str(conf / 'runtime.json'),
                           'chatgpt_tunnel_verified': False, 'desktop_commander_changed': False})
            atomic_write(conf / 'manifest.json', json.dumps(report, indent=2) + '\n')
            pathlib.Path(a.out).write_text(json.dumps(report, indent=2))
            print(json.dumps(report, indent=2))
        except Exception:
            # Roll back only the new unit created by this invocation. Preserve
            # immutable binary, config and evidence; never touch another service.
            subprocess.run(['systemctl', '--user', 'disable', '--now', SERVICE], capture_output=True, timeout=30)
            raise


if __name__ == '__main__':
    main()

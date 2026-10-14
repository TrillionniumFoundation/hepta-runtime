#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Create-only local successor canary; never switches existing transports.

Requires a complete native main/recovery receipt. Installs a separately named,
loopback-only, main-host-only user service with fresh private credentials and
state. Does not enable it at boot, change the installed operator/DC units,
modify their tokens, or touch their task/session state.
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
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('native_scope', ROOT / 'tests/service_scope_native_acceptance.py')
N = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(N)
UNIT = 'hepta-runtime-successor-canary.service'
PORT = 8791


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--receipt', required=True)
    ap.add_argument('--binary', required=True)
    ap.add_argument('--operator-config', required=True)
    ap.add_argument('--output', required=True)
    args = ap.parse_args()
    evidence = json.loads(pathlib.Path(args.receipt).read_text())
    binary = pathlib.Path(args.binary).resolve(strict=True)
    assert evidence['complete'] and evidence['owned_controller_exit_confirmed']
    assert evidence['hosts']['main']['completed']
    assert len(evidence['hosts']['main']['operations']) == 10
    assert any(c['passed'] and c['check'].startswith('owned controller restart preserves') for c in evidence['checks'])
    assert N.sha(binary) == evidence['binary_sha256']
    assert N.M.source_identity()['source_code_fingerprint'] == evidence['source_fingerprint']
    assert not pathlib.Path(args.output).exists()
    installed = json.loads(pathlib.Path(args.operator_config).read_text())
    main_host = copy.deepcopy(installed['hosts']['main'])
    assert main_host['ssh_target'] == 'localhost'
    home = pathlib.Path.home()
    root = home / '.local/share/hepta-runtime-successor-canary-20261014'
    unit_path = home / '.config/systemd/user' / UNIT
    assert not root.exists() and not unit_path.exists(), 'create-only: existing canary is never replaced'
    with socket.socket() as sock: sock.bind(('127.0.0.1', PORT))
    root.mkdir(mode=0o700)
    for name in ('state', 'workspace', 'host-state'):
        (root / name).mkdir(mode=0o700)
    executable = root / 'hepta-runtime'
    N.private_write(executable, binary.read_bytes()); executable.chmod(0o500)
    token = secrets.token_hex(32); N.private_write(root / 'token', token)
    main_host['remote_state_dir'] = str(root / 'host-state')
    config = {'state_dir': str(root / 'state'),
              'controller_workspace_roots': installed['controller_workspace_roots'],
              'hosts': {'main': main_host}}
    N.private_write(root / 'runtime.json', json.dumps(config))
    for path in (root, executable):
        assert not any(c in str(path) for c in '\n\r"'), 'unit path requires safe quoting'
    unit = ('[Unit]\nDescription=Hepta Runtime local successor canary (not production cutover)\n'
            'StartLimitIntervalSec=30\nStartLimitBurst=3\n\n[Service]\nType=simple\n'
            f'ExecStart="{executable}" mcp --path "{root / "workspace"}" --bind 127.0.0.1:{PORT} '
            f'--runtime-config "{root / "runtime.json"}" --auth-token-file "{root / "token"}"\n'
            f'WorkingDirectory={root / "workspace"}\n'
            'Restart=on-failure\nRestartSec=3\nUMask=0077\n\n[Install]\nWantedBy=default.target\n')
    N.private_write(unit_path, unit)
    env = dict(os.environ, XDG_RUNTIME_DIR='/run/user/' + str(os.getuid()),
               DBUS_SESSION_BUS_ADDRESS='unix:path=/run/user/' + str(os.getuid()) + '/bus')
    receipt = {'schema': 'hepta-local-scope-canary-install-v1', 'complete': False,
               'service': UNIT, 'bind': '127.0.0.1:' + str(PORT),
               'hosts': ['main'], 'root': str(root), 'binary_sha256': N.sha(executable),
               'unit_sha256': hashlib.sha256(unit.encode()).hexdigest(),
               'source_fingerprint': evidence['source_fingerprint'],
               'autostart_enabled_by_installer': False, 'existing_transport_repointed': False,
               'full_dc_replacement_qualified': False, 'native_receipt_sha256': N.sha(args.receipt)}
    try:
        subprocess.run(['systemd-analyze', '--user', 'verify', str(unit_path)], env=env, check=True,
                       timeout=20, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        subprocess.run(['systemctl', '--user', 'daemon-reload'], env=env, check=True, timeout=20,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        subprocess.run(['systemctl', '--user', 'start', UNIT], env=env, check=True, timeout=20,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        def ready():
            try: return N.ObservedClient('http://127.0.0.1:%d/mcp' % PORT, token, root)
            except OSError: return None
        client = N.bounded_wait(ready, 20)
        tools = client.rpc('tools/list', {})['tools']
        frozen = json.loads((ROOT / 'deploy/contracts/hepta-runtime-full-operator-v10.json').read_text())['tools']
        assert {v['name']:v for v in tools} == {v['name']:v for v in frozen}
        old = evidence['fixed_service_observations']['services'][:2]
        after = client.call('service_status', {'host': 'main', 'services': [v['name'] for v in old] + [UNIT]})['services']
        fields = ['MainPID', 'InvocationID', 'ActiveState']
        unchanged = all(a['scope'] == b['scope'] == 'user' and
                        all(a['properties'][key] == b['properties'][key] for key in fields)
                        for a,b in zip(old, after[:2]))
        receipt['existing_service_identities_unchanged'] = unchanged
        receipt['existing_services_before'] = old
        receipt['services_after'] = after
        assert unchanged, 'existing service identity changed during this interval'
        assert after[2]['scope'] == 'user' and after[2]['properties']['ActiveState'] == 'active'
        receipt['canary_pid'] = int(after[2]['properties']['MainPID'])
        assert N.sha('/proc/%d/exe' % receipt['canary_pid']) == receipt['binary_sha256']
        receipt['tool_count'] = len(tools)
        receipt['complete'] = True
    except Exception as exc:
        receipt['error_type'] = type(exc).__name__
        # A failure may only stop the exact unit this invocation created.
        if N.sha(unit_path) == receipt['unit_sha256']:
            stopped = subprocess.run(['systemctl', '--user', 'stop', UNIT], env=env, timeout=20,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            receipt['owned_failed_canary_stop_exit_code'] = stopped.returncode
        raise
    finally:
        N.private_write(pathlib.Path(args.output), json.dumps(receipt, indent=2))
    print(json.dumps({k:receipt[k] for k in ['complete','service','bind','canary_pid','binary_sha256','tool_count','existing_service_identities_unchanged','autostart_enabled_by_installer','full_dc_replacement_qualified']}))


if __name__ == '__main__':
    main()

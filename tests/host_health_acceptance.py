#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Native MCP six-host health qualification using a disposable controller.

Only fixed read-only SSH health challenges reach targets. No installed service,
DC agent, host policy or target file is changed. This is native client evidence,
not ChatGPT model-origin evidence or a Desktop Commander cutover qualification.
"""
import argparse
import hashlib
import json
import os
import pathlib
import secrets
import socket
import subprocess
import tempfile
import time

from runtime_http_acceptance import Client


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True)
    parser.add_argument('--runtime-config', required=True)
    parser.add_argument('--out', required=True)
    parser.add_argument('--hosts', nargs='+', default=['main', 'rog', 'pocket4', 'ai395', 'x230', 'mac'])
    args = parser.parse_args()
    checks = []
    current = 'prepare disposable native controller'
    receipt = {
        'schema': 'hepta-host-health-native-acceptance-v1',
        'origin': 'native_python_mcp_client',
        'binary_sha256': hashlib.sha256(pathlib.Path(args.binary).read_bytes()).hexdigest(),
        'checks': checks,
        'complete': False,
        'full_dc_replacement_qualified': False,
        'installed_service_changes': False,
        'dc_stopped': False,
    }

    def save():
        pathlib.Path(args.out).write_text(json.dumps(receipt, indent=2) + '\n')

    def passed(name, detail=None):
        checks.append({'check': name, 'result': 'passed', 'detail': detail})
        save()
        print('PASS', name, flush=True)

    save()
    try:
        source = json.loads(pathlib.Path(args.runtime_config).read_text())
        assert len(args.hosts) == len(set(args.hosts)), 'duplicate host selection'
        assert set(args.hosts) <= source['hosts'].keys(), 'required configured host absent'
        with tempfile.TemporaryDirectory(prefix='hepta-health-native-') as directory:
            root = pathlib.Path(directory)
            workspace = root / 'workspace'
            workspace.mkdir()
            token = secrets.token_hex(32)
            token_file = root / 'token'
            token_file.write_text(token)
            os.chmod(token_file, 0o600)
            # Retain only administrator-pinned destinations; intentionally grant
            # no model execution, PTY, file write or privileged capabilities.
            hosts = {
                name: {
                    'ssh_target': source['hosts'][name]['ssh_target'],
                    'platform': source['hosts'][name].get('platform', 'linux'),
                    'remote_state_dir': source['hosts'][name]['remote_state_dir'],
                    'allow_execute': False, 'allow_pty': False, 'allow_write': False,
                }
                for name in args.hosts
            }
            config_file = root / 'runtime.json'
            config_file.write_text(json.dumps({
                'state_dir': str(root / 'state'),
                'controller_workspace_roots': [str(workspace)],
                'hosts': hosts,
            }))
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                port = sock.getsockname()[1]
            url = f'http://127.0.0.1:{port}/mcp'
            with open(root / 'controller.log', 'wb') as log:
                controller = subprocess.Popen([
                    str(pathlib.Path(args.binary).resolve()), 'mcp', '--path', str(workspace),
                    '--bind', f'127.0.0.1:{port}', '--runtime-config', str(config_file),
                    '--auth-token-file', str(token_file),
                ], stdin=subprocess.DEVNULL, stdout=log, stderr=log)
                try:
                    for attempt in range(80):
                        if controller.poll() is not None:
                            raise RuntimeError('disposable controller exited')
                        try:
                            client = Client(url, token)
                            break
                        except (OSError, RuntimeError):
                            time.sleep(.1)
                    else:
                        raise RuntimeError('disposable controller readiness deadline')
                    current = 'read-only schema and exact bounded arguments'
                    tools = {item['name']: item for item in client.rpc('tools/list', {})['tools']}
                    tool = tools['host_health']
                    assert tool['annotations']['readOnlyHint'] is True
                    schema = tool['inputSchema']
                    assert set(schema['properties']) == {'host'}
                    assert schema['additionalProperties'] is False
                    passed(current)
                    current = 'health cannot enable execution, PTY or writes'
                    caps = client.call('host_list', {})['hosts']
                    assert all(not h['allow_execute'] and not h['allow_pty'] and not h['allow_write'] for h in caps)
                    passed(current)
                    current = 'caller target and command overrides rejected'
                    error = client.call('host_health', {'host': 'unknown-private-destination'}, denied=True)
                    assert 'unknown-private-destination' not in error
                    client.call('host_health', {'host': '127.0.0.1'}, denied=True)
                    for name, value in [('address', '127.0.0.1'), ('command', 'id'), ('timeout_seconds', 3600)]:
                        client.call('host_health', {'host': args.hosts[0], name: value}, denied=True)
                    passed(current)
                    for name in args.hosts:
                        current = name + ' authenticated fixed SSH health roundtrip'
                        result = client.call('host_health', {'host': name})
                        assert result['schema'] == 'hepta-host-health-v1'
                        assert result['host'] == name and result['status'] == 'healthy'
                        assert result['reachable'] and result['authenticated']
                        assert result['transport'] == 'ssh' and result['timeout_ms'] == 10000
                        assert 0 <= result['ssh_roundtrip_ms'] < 11000
                        assert 'not ICMP RTT' in result['measurement']
                        assert result['diagnostics_redacted'] is True
                        assert set(result) == {
                            'schema', 'host', 'platform', 'transport', 'status', 'reachable',
                            'authenticated', 'ssh_roundtrip_ms', 'timeout_ms', 'measurement',
                            'diagnostics_redacted',
                        }
                        passed(current, result)
                    current = 'new authenticated client reconnect retains health capability'
                    client = Client(url, token)
                    assert client.call('host_health', {'host': args.hosts[0]})['status'] == 'healthy'
                    passed(current)
                finally:
                    controller.terminate()
                    try:
                        controller.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        controller.kill()
                        controller.wait(timeout=5)
        receipt['complete'] = True
        receipt['passed'] = len(checks)
        receipt['at_unix'] = time.time()
        save()
        print('ALL_PASS', len(checks), flush=True)
    except Exception as error:
        # Native controller/config diagnostics can contain destinations. Retain
        # the failed check and exception type without publishing those values.
        receipt['failure'] = {'check': current, 'exception_type': type(error).__name__}
        save()
        print('FAILED', current, type(error).__name__, flush=True)
        raise SystemExit(1) from None


if __name__ == '__main__':
    main()

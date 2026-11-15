#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Fresh v6 candidate regression on six SSH hosts and disposable workloads.

Historical v4 pins and harnesses remain untouched. Existing operator canaries
cover shells, PTYs and controller restart; separate canaries add durable stdin,
independent output cursors and owned-job cancellation. This native evidence
does not qualify model-origin approval, deployment or a Desktop Commander stop.
"""
import argparse
import concurrent.futures
import datetime
import hashlib
import json
import os
import pathlib
import secrets
import socket
import stat
import subprocess
import sys
import tempfile
import time

from dc_parity_release_six_host_acceptance import HOSTS, ROOT, digest, services, test_host
from dc_successor_contract import ADDITIONS as V5_ADDITIONS, AUDIT_CONFIG_ADDITIONS, verify_successor
ADDITIONS=V5_ADDITIONS|AUDIT_CONFIG_ADDITIONS
from runtime_http_acceptance import Client


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def source_identity():
    paths = set(ROOT.glob('src/**/*.rs')) | set(ROOT.glob('src/**/*.py'))
    paths.update([ROOT / 'Cargo.toml', ROOT / 'Cargo.lock'])
    entries = {}
    for path in sorted(paths, key=lambda item: item.relative_to(ROOT).as_posix()):
        if path.is_symlink() or not path.is_file():
            raise ValueError('source fingerprint requires regular non-symlink files')
        raw = path.read_bytes()
        entries[path.relative_to(ROOT).as_posix()] = {
            'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
        }
    head = subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip()
    dirty = subprocess.check_output([
        'git', '-C', str(ROOT), 'status', '--porcelain', '--untracked-files=all',
        '--', 'src', 'Cargo.toml', 'Cargo.lock',
    ], text=True)
    return {
        'base_HEAD': head,
        'dirty_source': bool(dirty.strip()),
        'source_fingerprint_algorithm': 'sha256(canonical sorted relative path -> byte-count and sha256 map)',
        'source_code_fingerprint': hashlib.sha256(canonical(entries)).hexdigest(),
        'source_files': entries,
    }


def supplement_host(name, ssh, binary, directory, contract, previous):
    path = directory / f'{name}.supplement.json'
    log_path = directory / f'{name}.supplement.log'
    old = json.loads(pathlib.Path(previous['receipt']).read_text())
    target = old['target_test_directory']
    report = {
        'schema': 'hepta-dc-v6-operator-supplement-v1',
        'host': name, 'origin': 'native_python_mcp_client',
        'binary_sha256': digest(binary),
        'contract_sha256': digest(contract),
        'checks': [], 'complete': False,
    }

    def save():
        path.write_text(json.dumps(report, indent=2) + '\n')

    def passed(check, detail=None):
        report['checks'].append({'check': check, 'result': 'passed', 'detail': detail})
        save()
        print('PASS', name, check, flush=True)

    save()

    def dispatch(name, params):
        report['dispatch_phase'] = name
        report['dispatch_params'] = params
        save()
        try:
            return client.call(name, params)
        except Exception as error:
            report.setdefault('native_error', {
                'phase': name, 'params': params,
                'exception_type': type(error).__name__,
                'message': str(error)[:65536],
                'message_sha256': hashlib.sha256(str(error).encode()).hexdigest(),
            })
            save()
            raise

    try:
        with tempfile.TemporaryDirectory(prefix='hepta-v6-operator-controller-') as work:
            work = pathlib.Path(work)
            workspace = work / 'workspace'
            workspace.mkdir()
            token = secrets.token_hex(32)
            token_file = work / 'token'
            token_file.write_text(token)
            os.chmod(token_file, 0o600)
            host = {
                'ssh_target': ssh, 'platform': 'macos' if name == 'mac' else 'linux',
                'remote_state_dir': target, 'execution_mode': 'operator',
                'allow_execute': True, 'allow_pty': False, 'allow_write': False,
                'allow_job_network': True, 'allow_detached_fallback': True,
            }
            config = work / 'runtime.json'
            config.write_text(json.dumps({
                'state_dir': str(work / 'state'), 'controller_workspace_roots': [str(workspace)],
                'hosts': {'operator': host},
            }))
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                port = sock.getsockname()[1]
            url = f'http://127.0.0.1:{port}/mcp'
            with log_path.open('xb') as log:
                controller = subprocess.Popen([
                    str(binary), 'mcp', '--path', str(workspace), '--bind', f'127.0.0.1:{port}',
                    '--runtime-config', str(config), '--auth-token-file', str(token_file),
                ], stdin=subprocess.DEVNULL, stdout=log, stderr=log)
                cancel_job = None
                client = None
                try:
                    for _ in range(80):
                        if controller.poll() is not None:
                            raise RuntimeError('disposable supplemental controller exited')
                        try:
                            client = Client(url, token)
                            break
                        except (OSError, RuntimeError):
                            time.sleep(.1)
                    else:
                        raise RuntimeError('supplemental controller readiness deadline')
                    tools = client.rpc('tools/list', {})['tools']
                    projected = verify_successor(tools, contract)
                    assert len(projected) == 50
                    passed('exact reviewed v6 catalog and unchanged original 50 definitions')
                    text = 'INPUT 中文 α\n'
                    params = {
                        'host': 'operator', 'executable': '/usr/bin/python3',
                        'args': ['-c', "import sys;b=sys.stdin.buffer.read();sys.stdout.buffer.write(b'OUT:'+b);sys.stderr.buffer.write(b'ERR:'+b)"],
                        'stdin': text, 'cwd': target, 'timeout_seconds': 20,
                    }
                    job = dispatch('process_start', params)['job']['id']
                    status = dispatch('process_wait', {'host': 'operator', 'job_id': job, 'timeout_seconds': 25})
                    assert status['state'] == 'succeeded', status
                    expected = {'stdout': b'OUT:' + text.encode(), 'stderr': b'ERR:' + text.encode()}
                    cursor = {'stdout': 0, 'stderr': 0}
                    actual = {'stdout': b'', 'stderr': b''}
                    # Read only stdout first, then stderr. The caller's two byte
                    # cursors must remain independent through every one-byte page.
                    for stream in ('stdout', 'stderr'):
                        for _ in range(len(expected[stream]) + 2):
                            value = dispatch('process_read', {
                                'host': 'operator', 'job_id': job,
                                'stdout_offset': cursor['stdout'], 'stderr_offset': cursor['stderr'], 'limit': 1,
                            })[stream]
                            part = bytes.fromhex(value['bytes_hex'])
                            assert value['offset'] == cursor[stream]
                            assert value['next_offset'] == cursor[stream] + len(part)
                            actual[stream] += part
                            cursor[stream] = value['next_offset']
                            if value['eof']:
                                break
                        else:
                            raise AssertionError('one-byte cursor did not reach archive EOF')
                        assert actual[stream] == expected[stream]
                    passed('real Unicode stdin and independent exact stdout/stderr byte cursors', {
                        'job_id': job, 'stdout_bytes': len(actual['stdout']), 'stderr_bytes': len(actual['stderr']),
                    })
                    cancel_launch = dispatch('process_start', {
                        'host': 'operator', 'executable': '/usr/bin/python3',
                        'args': ['-c', "import time;print('CANCEL_READY',flush=True);time.sleep(90)"],
                        'cwd': target, 'timeout_seconds': 30,
                    })
                    cancel_job = cancel_launch['job']['id']
                    report['cancel_launch'] = cancel_launch
                    save()
                    for _ in range(50):
                        ready = dispatch('process_read', {'host': 'operator', 'job_id': cancel_job})
                        if 'CANCEL_READY' in ready['stdout']['text']:
                            break
                        time.sleep(.1)
                    else:
                        raise AssertionError('owned cancel fixture did not start')
                    pre_status = dispatch('process_status', {'host': 'operator', 'job_id': cancel_job})
                    report['cancel_pre_status'] = pre_status
                    save()
                    assert pre_status['state'] == 'running', pre_status
                    result = dispatch('process_cancel', {'host': 'operator', 'job_id': cancel_job})
                    report['cancel_response'] = result
                    save()
                    backend = cancel_launch['launch']['backend']
                    expected_result = {'systemd': {'stop_requested'}, 'detached': {'term_sent', 'kill_sent'}}
                    assert backend in expected_result and result['result'] in expected_result[backend], result
                    status = dispatch('process_wait', {'host': 'operator', 'job_id': cancel_job, 'timeout_seconds': 20})
                    report['cancel_terminal_status'] = status
                    save()
                    assert status['state'] == 'cancelled' and status['cancelled'] is True, status
                    assert status['output_complete'] is True, status
                    output = dispatch('process_read', {'host': 'operator', 'job_id': cancel_job})
                    report['cancel_retained_output'] = output
                    save()
                    assert 'CANCEL_READY' in output['stdout']['text']
                    passed('owned disposable job cancellation and retained actual output', {
                        'job_id': cancel_job, 'terminal_state': status['state'],
                    })
                    cancel_job = None
                    report['complete'] = True
                    report['passed'] = len(report['checks'])
                    save()
                finally:
                    if client is not None and cancel_job is not None:
                        try:
                            dispatch('process_cancel', {'host': 'operator', 'job_id': cancel_job})
                        except Exception:
                            report['cleanup_owned_job_cancel_failed'] = True
                            save()
                    controller.terminate()
                    try:
                        controller.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        controller.kill()
                        controller.wait(timeout=5)
    except Exception as error:
        report['failure_exception_type'] = type(error).__name__
        report['failure_phase'] = report.get('dispatch_phase', 'controller initialization or contract verification')
        report['failure_message'] = str(error)[:65536]
        report['failure_message_sha256'] = hashlib.sha256(str(error).encode()).hexdigest()
        save()
        raise
    return {
        'supplement_receipt': str(path), 'supplement_receipt_sha256': digest(path),
        'supplement_log_sha256': digest(log_path), 'supplement_complete': report['complete'],
        'supplement_passed': report['passed'],
    }


def run_host(name, ssh, binary, directory, contract):
    result = {}
    try:
        result = test_host(name, ssh, binary, directory)
        result['receipt_sha256'] = digest(pathlib.Path(result['receipt']))
        if result['exit'] == 0 and result['complete']:
            result.update(supplement_host(name, ssh, binary, directory, contract, result))
        return result
    except Exception as error:
        # Individual stdout/stderr receipts stay intact; avoid destinations and
        # credential-related exception strings in the matrix summary.
        return {**result, 'host': name, 'exit': result.get('exit', -1),
                'complete': result.get('complete', False), 'supplement_complete': False,
                'failure_exception_type': type(error).__name__}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True)
    parser.add_argument('--contract', required=True)
    parser.add_argument('--out', required=True)
    parser.add_argument('--receipt-dir', required=True)
    parser.add_argument('--expected-head')
    args = parser.parse_args()
    supplied = pathlib.Path(args.binary)
    if supplied.is_symlink():
        raise ValueError('candidate executable may not be a symlink')
    binary = supplied.resolve(strict=True)
    if not stat.S_ISREG(binary.stat().st_mode) or not os.access(binary, os.X_OK):
        raise ValueError('real executable candidate required')
    contract = pathlib.Path(args.contract).resolve(strict=True)
    contract_data = json.loads(contract.read_text())
    verify_successor(contract_data['tools'], contract)
    identity = source_identity()
    if args.expected_head and (identity['base_HEAD'] != args.expected_head or identity['dirty_source']):
        raise ValueError('expected-head mode requires exact committed source')
    directory = pathlib.Path(args.receipt_dir)
    directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    destination = pathlib.Path(args.out)
    if destination.exists():
        raise ValueError('refusing to overwrite prior matrix evidence')
    baseline = services()
    if any(value.get('ActiveState') != 'active' or value.get('MainPID') == '0' for value in baseline.values()):
        raise RuntimeError('protected controller services must be active')
    report = {
        'schema': 'hepta-dc-v6-six-host-operator-candidate-v1',
        'recorded_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        **identity,
        'expected_head': args.expected_head,
        'uncommitted_source_allowed': not bool(args.expected_head),
        'source_head_is_compiled_code_claim': False,
        'harness_sha256': digest(pathlib.Path(__file__)),
        'binary_path': str(binary), 'binary_sha256': digest(binary),
        'contract_sha256': digest(contract), 'catalog_sha256': contract_data['catalog_sha256'],
        'candidate_tool_count': 58, 'reviewed_additions': sorted(ADDITIONS),
        'original_50_definitions_unchanged': True,
        'installed_50_tool_catalog_changed': False,
        'origin': 'native_python_mcp_client', 'model_origin': False,
        'full_dc_replacement_qualified': False, 'dc_stopped': False,
        'installed_services_changed': False, 'public_gateway_started': False,
        'protected_service_identity_scope': 'controller PROTECTED units imported from historical six-host harness',
        'protected_services_before': baseline, 'max_workers': 2,
        'coordination': 'main completes first; remaining five bounded to two workers; SSH auth burst resilience is not qualified',
        'results': [], 'complete': False,
    }

    def save():
        destination.write_text(json.dumps(report, indent=2) + '\n')

    save()
    try:
        main_host = next((name, ssh) for name, ssh in HOSTS if name == 'main')
        report['main_phase_started_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        result = run_host(*main_host, binary, directory, contract)
        report['results'].append(result)
        report['main_phase_completed_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        save()
        if not (result['exit'] == 0 and result['complete'] and result.get('supplement_complete')):
            raise RuntimeError('main host qualification failed; other five not launched')
        report['remaining_phase_started_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            jobs = {executor.submit(run_host, name, ssh, binary, directory, contract): name for name, ssh in HOSTS if name != 'main'}
            for future in concurrent.futures.as_completed(jobs):
                result = future.result()
                report['results'].append(result)
                save()
                print('TARGET', result['host'], 'exit', result['exit'],
                      'original_checks', result.get('passed'), 'supplement_checks', result.get('supplement_passed'), flush=True)
    finally:
        try:
            report['protected_services_after'] = services()
            report['service_identity_stable'] = report['protected_services_after'] == baseline
        except Exception as error:
            report['protected_services_after_error_type'] = type(error).__name__
            report['service_identity_stable'] = False
        after = source_identity()
        report['source_after'] = after
        report['source_fingerprint_stable'] = after['source_code_fingerprint'] == identity['source_code_fingerprint']
        report['expected_committed_head_stable'] = (
            not args.expected_head or (after['base_HEAD'] == args.expected_head and not after['dirty_source'])
        )
        report['binary_sha256_after'] = digest(binary)
        report['binary_identity_stable'] = report['binary_sha256_after'] == report['binary_sha256']
        report['contract_sha256_after'] = digest(contract)
        report['contract_identity_stable'] = report['contract_sha256_after'] == report['contract_sha256']
        report['results'].sort(key=lambda row: next(i for i, host in enumerate(HOSTS) if host[0] == row['host']))
        report['complete'] = (
            len(report['results']) == len(HOSTS)
            and all(row['exit'] == 0 and row['complete'] and row.get('supplement_complete') for row in report['results'])
            and report['service_identity_stable'] and report['source_fingerprint_stable']
            and report['expected_committed_head_stable']
            and report['binary_identity_stable'] and report['contract_identity_stable']
        )
        save()
        print('MATRIX_COMPLETE', report['complete'], flush=True)
    if not report['complete']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()

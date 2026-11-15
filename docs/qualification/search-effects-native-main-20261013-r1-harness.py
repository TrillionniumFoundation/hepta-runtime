#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Disposable localhost native search effect faults, never a production outage.

The child controller alone gets a private SSH PATH shim. Real /usr/bin/ssh runs
its fixed worker before acknowledgement loss or local publication faults. An
explicit diagnostic fork observer records the second real fork return PID and
start identity; observer errors are suppressed and the original fork result is
returned unchanged. It neither holds nor schedules workers. No live config,
PATH, credentials, services, Desktop Commander or production process is changed.
"""
import argparse, hashlib, json, os, pathlib, secrets, shutil, socket, subprocess
import sys, tempfile, time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy"))
from mcp_tool_contract import ToolContract
from runtime_http_acceptance import Client
TERMINAL = {"completed", "limited", "cancelled", "failed", "interrupted"}

def digest(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

def wait_for(predicate, seconds=15):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        result = predicate()
        if result:
            return result
        time.sleep(.03)
    raise AssertionError("owned fixture observation deadline exceeded")

def process_identity(pid):
    try:
        stat = pathlib.Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
        return pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip() + ":" + stat[19]
    except (FileNotFoundError, ProcessLookupError):
        return None

def write_json(path, value):
    path.write_text(json.dumps(value)); path.chmod(0o600)

SHIM = r'''#!/usr/bin/python3
import json, os, pathlib, shlex, subprocess, sys
root = pathlib.Path(ROOT_LITERAL)
data = sys.stdin.buffer.read()
try: request = json.loads(data)
except Exception: request = {}
action, sid = request.get('action'), request.get('search_id')
argv = sys.argv[1:]
# Observe only the fixed diagnostic search worker; do not instrument any other command.
if action == 'start':
    words = shlex.split(argv[-1])
    if len(words) != 3 or words[1] != '-c' or "__name__ = 'hepta_search_worker'" not in words[2]:
        raise SystemExit(87)
    hook = r"""
_fixture_original_fork = os.fork
_fixture_fork_depth = 0
def _fixture_observe_fork():
    global _fixture_fork_depth
    _fixture_fork_depth += 1
    result = _fixture_original_fork()
    try:
        if _fixture_fork_depth == 2 and result > 0:
            ticks = pathlib.Path('/proc/%s/stat' % result).read_text().rsplit(') ', 1)[1].split()[19]
            boot = pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
            path = pathlib.Path(q['state_dir']) / 'search' / q['search_id'] / 'fixture-worker.json'
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'w') as writer:
                json.dump({'pid': result, 'start_identity': boot + ':' + ticks,
                           'search_id': q['search_id'], 'observer': 'second_original_fork_return'}, writer)
    except BaseException:
        pass
    return result
os.fork = _fixture_observe_fork
"""
    code = words[2]
    point = "print(json.dumps({'search_id':q['search_id']"
    if code.count(point) != 1: raise SystemExit(88)
    code = code.replace(point, hook + '\n' + point, 1)
    argv[-1] = shlex.join([words[0], words[1], code])
completed = subprocess.run(['/usr/bin/ssh', *argv], input=data, capture_output=True, timeout=20)
if action and sid:
    with (root / 'rpc-count.jsonl').open('a') as log:
        log.write(json.dumps({'action': action, 'search_id': sid, 'remote_returncode': completed.returncode}) + '\n')
mode = (root / 'fault').read_text() if (root / 'fault').exists() else ''
if completed.returncode == 0 and mode == action + '-save-failure':
    directory = root / 'controller-state' / 'search'
    directory.rename(root / 'retained-intent')
    directory.write_bytes(b'controller-local fixture publication obstruction')
    directory.chmod(0o600)
if completed.returncode == 0 and mode == action + '-drop-ack':
    sys.stderr.buffer.write(b'diagnostic controller-local acknowledgement discarded after real worker RPC\n')
    raise SystemExit(0)
sys.stdout.buffer.write(completed.stdout); sys.stderr.buffer.write(completed.stderr)
raise SystemExit(completed.returncode)
'''

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True)
    parser.add_argument('--contract', required=True)
    parser.add_argument('--contract-sha256', required=True)
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    if sys.platform != 'linux': raise SystemExit('Linux localhost identity fixture required')
    binary = pathlib.Path(args.binary).resolve(strict=True)
    contract = ToolContract.load(args.contract, args.contract_sha256)
    output = pathlib.Path(args.out)
    if output.exists(): raise SystemExit('Never overwrite prior evidence')
    output.parent.mkdir(parents=True, exist_ok=True)
    root = pathlib.Path(tempfile.mkdtemp(prefix='hepta-search-effect-native-'))
    root.chmod(0o700)
    token = secrets.token_hex(32)
    controller = None; searches = {}; cleanup = False
    report = {'schema': 'hepta-search-effects-native-localhost-v1', 'complete': False,
        'origin': 'native_python_mcp_client', 'binary_sha256': digest(binary),
        'contract_sha256': args.contract_sha256, 'harness_sha256': digest(__file__), 'checks': [],
        'target': 'real fixed localhost SSH worker', 'diagnostic_instrumentation':
        'controller-private SSH shim inserts a non-scheduling observer around the original os.fork; source files are unchanged',
        'fault_scope': 'controller-local ACK discard after RPC and disposable controller publication obstruction',
        'production_target_outage_claimed': False, 'live_configuration_changed': False,
        'dc_stopped': False, 'installed_service_changed': False, 'model_origin_qualified': False,
        'six_host_qualified': False, 'full_dc_replacement_qualified': False}
    def save():
        output.write_text(json.dumps(report, indent=2) + '\n'); output.chmod(0o600)
    def passed(name, detail=None):
        report['checks'].append({'check': name, 'result': 'passed', 'detail': detail}); save()
        print('PASS', name, flush=True)
    def count(sid, action):
        path = root / 'rpc-count.jsonl'
        rows = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
        return sum(row['search_id'] == sid and row['action'] == action for row in rows)
    def set_fault(value):
        (root / 'fault').write_text(value); (root / 'fault').chmod(0o600)
    def restore_publication():
        target = root / 'controller-state' / 'search'
        if target.is_file(): target.unlink(); (root / 'retained-intent').rename(target)
    def owned_observer(sid):
        path = root / 'remote-state' / 'search' / sid / 'fixture-worker.json'
        value = wait_for(lambda: json.loads(path.read_text()) if path.exists() else None)
        assert value['search_id'] == sid and value['observer'] == 'second_original_fork_return'
        assert type(value['pid']) is int and value['pid'] > 1
        searches[sid] = {'observer': value, 'observer_sha256': digest(path)}
        return value
    def terminal(sid):
        target = root / 'remote-state' / 'search' / sid / 'record.json'
        value = wait_for(lambda: json.loads(target.read_text()) if target.exists() and
                         json.loads(target.read_text())['state'] in TERMINAL else None, 15)
        observer = searches[sid]['observer']
        wait_for(lambda: process_identity(observer['pid']) != observer['start_identity'], 10)
        assert digest(target.parent / 'fixture-worker.json') == searches[sid]['observer_sha256']
        assert count(sid, 'start') == 1
        searches[sid]['terminal_state'] = value['state']
        searches[sid]['terminal_receipt_sha256'] = digest(target)
        searches[sid]['same_observer_retained'] = True
        searches[sid]['owned_identity_no_longer_live'] = True
        return value
    try:
        workspace = root / 'workspace'; workspace.mkdir(mode=0o700)
        # Short-line scanning keeps disposable workers observable without a scheduling hook.
        for i in range(64):
            (workspace / f'fixture-{i:03}.txt').write_bytes(b'n\n' * (128 * 1024))
        cfg = {'state_dir': str(root / 'controller-state'), 'controller_workspace_roots': [str(workspace)],
               'hosts': {'main': {'ssh_target': 'localhost', 'platform': 'linux', 'execution_mode': 'operator',
               'allow_execute': True, 'allow_write': True, 'allow_pty': True,
               'remote_state_dir': str(root / 'remote-state'), 'allowed_read_path_prefixes': [str(workspace)],
               'allowed_write_path_prefixes': [str(workspace)]}}}
        config = root / 'runtime.json'; write_json(config, cfg)
        tokenfile = root / 'token'; tokenfile.write_text(token); tokenfile.chmod(0o600)
        bindir = root / 'bin'; bindir.mkdir(mode=0o700)
        shim = bindir / 'ssh'; shim.write_text(SHIM.replace('ROOT_LITERAL', repr(str(root)))); shim.chmod(0o700)
        env = dict(os.environ); env['PATH'] = str(bindir) + ':' + env.get('PATH', '')
        with socket.socket() as sock: sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
        logfile = root / 'controller.log'
        with logfile.open('xb') as writer:
            logfile.chmod(0o600)
            controller = subprocess.Popen([str(binary), 'mcp', '--path', str(workspace), '--bind',
                f'127.0.0.1:{port}', '--runtime-config', str(config), '--auth-token-file', str(tokenfile)],
                env=env, stdin=subprocess.DEVNULL, stdout=writer, stderr=writer)
        def ready():
            if controller.poll() is not None: raise AssertionError('Disposable controller exited')
            try: return Client(f'http://127.0.0.1:{port}/mcp', token)
            except (OSError, RuntimeError): return None
        client = wait_for(ready)
        contract.verify(client.rpc('tools/list', {})['tools'])
        params = {'host': 'main', 'root': str(workspace), 'query': 'absent-fixture-needle', 'kind': 'content',
                  'max_results': 10, 'max_entries': 10000, 'max_bytes': 64 * 1024 * 1024, 'timeout_seconds': 3}
        directory = root / 'controller-state' / 'search'
        directory.parent.mkdir(mode=0o700, exist_ok=True); directory.write_bytes(b'pre-intent obstruction')
        raw = client.rpc('tools/call', {'name': 'search_start', 'arguments': params})
        assert raw.get('isError') is True
        assert not (root / 'rpc-count.jsonl').exists()
        assert not (root / 'remote-state' / 'search').exists()
        directory.unlink()
        passed('pre-intent failure dispatches zero real SSH workers')

        for fault in ['start-drop-ack', 'start-save-failure']:
            set_fault(fault)
            value = client.call('search_start', params); sid = value['search']['search_id']
            assert value['automatic_retry'] is False
            if fault == 'start-drop-ack':
                assert value['effect_outcome'] == 'start_unknown' and value['outcome'] == 'unknown'
            else:
                assert value['effect_outcome'] == 'start_acknowledged'
                assert value['observed_state'] == 'running' and value['metadata_durability_confirmed'] is False
            owned_observer(sid); restore_publication(); set_fault('')
            assert sid in {row['search_id'] for row in client.call('search_list', {})['searches']}
            wait_for(lambda: client.call('search_results', {'search_id': sid}).get('snapshot', {}).get('snapshot_ready'))
            terminal(sid)
            passed(fault + ' retains one worker same ID and reconciles without replay',
                   {'search_id': sid, 'start_rpc_count': count(sid, 'start'), 'worker_identity_recorded': True})

        for fault in ['stop-drop-ack', 'stop-save-failure']:
            set_fault(''); started = client.call('search_start', params); sid = started['search']['search_id']
            observed = owned_observer(sid)
            assert process_identity(observed['pid']) == observed['start_identity'], 'Worker was not live before stop fixture'
            set_fault(fault); value = client.call('search_stop', {'search_id': sid})
            assert value['search']['search_id'] == sid and value['automatic_retry'] is False
            assert value['termination_confirmed'] is False
            if fault == 'stop-drop-ack':
                assert value['effect_outcome'] == 'cancel_unknown' and value['outcome'] == 'unknown'
                assert value.get('stop_requested') is None
            else:
                assert value['effect_outcome'] == 'cancel_requested' and value['stop_requested'] is True
                assert value['metadata_durability_confirmed'] is False
            assert (root / 'remote-state' / 'search' / sid / 'cancel').exists(), 'Real cancellation marker was not accepted'
            restore_publication(); set_fault('')
            wait_for(lambda: client.call('search_results', {'search_id': sid}).get('snapshot', {}).get('snapshot_ready'))
            terminal(sid)
            assert count(sid, 'stop') == 1
            passed(fault + ' retains same worker identity and accepted cancellation without replay',
                   {'search_id': sid, 'start_rpc_count': count(sid, 'start'), 'stop_rpc_count': count(sid, 'stop')})
        assert len(list((root / 'remote-state' / 'search').glob('[0-9a-f]' * 64))) == len(searches) == 4
        controller.terminate(); controller.wait(timeout=10)
        cleanup = True
        report.update(complete=True, owned_cleanup_confirmed=True, searches=searches,
                      controller_log_sha256=digest(logfile), owned_controller_exit=controller.returncode)
        assert token not in json.dumps(report)
        save(); shutil.rmtree(root)
    except Exception as error:
        detail = str(error).replace(token, '[redacted]')
        report['failure'] = {'type': type(error).__name__, 'detail': detail[:2048]}
        report['fixture_retained_for_owned_recovery'] = str(root)
        report['owned_cleanup_confirmed'] = False
        save(); raise
    finally:
        if controller is not None and controller.poll() is None:
            controller.terminate(); controller.wait(timeout=10)
        if not cleanup:
            # Unknown effects are never blindly killed by a PID. Preserve fixtures
            # until their cooperative markers and bounded target receipts reconcile.
            report['owned_controller_exit'] = controller.returncode if controller else None
            save()

if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""One reviewed same-owner native rollout; no effect submission or state recovery.

Run on main as the existing service user. --check-only and --apply both reserve
new receipts; an existing output prefix is never resumed or overwritten.
The core result and dependent-service restoration are recorded separately;
restoring a control entry point never triggers another native rollback.
"""
import argparse
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time

ROOT = Path('/home/qian-qi/.local/state/hepta-runtime-optimization-20261017-0940')
sys.path.insert(0, str(Path(__file__).resolve().parent))
from native_benchmark import Client, Receipt, PROTOCOL, canonical, catalog_summary, parse_endpoint, utc_now

OPERATOR = 'hepta-runtime-operator.service'
SUCCESSOR = 'hepta-runtime-successor-canary.service'
V11 = 'hepta-runtime-v11.service'
FRONT = 'hepta-computer-http-unlimited.service'
BRIDGE = 'hepta-chatgpt-bridge.service'
TUNNEL = 'hepta-openai-full-operator.service'
CONTROL_DEPENDENCIES = {BRIDGE: {OPERATOR}, TUNNEL: {OPERATOR, FRONT}}
CONTROL_GRAPH_FIELDS = ('Requires', 'Wants', 'BindsTo', 'PartOf', 'After')
ORDER = (SUCCESSOR, OPERATOR, V11)
CATALOG = '61ffd5277dd653cab0f22674b6f3860f7f596291463cf6d761b2b0fef0ac3616'
OLD_BINARY = '6d4d182b2fa50cc79f921f1a8fb3b7da0dc1456d8d5feddf14d031fb044a079f'
HISTORIC = '7dcbf6ebcbb878c9d0c146e0c704c8feeb9041e30bfa52c83cc7071e735a5a5f'
NAMESPACES = {'request_status': 'request-async-v9', 'operation_status': 'request-operations-v10'}
AUDIT_JOBS = dict(main='1a1492acc63-1123a8-3625', rog='1a1492ad75e-1123a8-3626',
    ai395='1a1492ae266-1123a8-3627', mac='1a1492aea57-1123a8-3628',
    pocket4='1a1492af269-1123a8-3629', x230='1a1492afbc5-1123a8-362a')
R = None
RECOVERING = False


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def event(phase, **data):
    R.data['events'].append(dict(phase=phase, at_utc=utc_now(), **data))
    try:
        R.update()
    except Exception as error:
        if not RECOVERING:
            raise
        R.data.setdefault('receipt_write_errors', []).append(str(error)[:500])


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path, private=False, maximum=256 * 1024 * 1024):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_size <= maximum, 'invalid file: ' + str(path))
        if private:
            require(before.st_uid == os.getuid() and not before.st_mode & 0o077 and before.st_nlink == 1,
                    'file is not private: ' + str(path))
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink')
        stamp = lambda s: [getattr(s, key) for key in fields]
        require(len(raw) == before.st_size and stamp(before) == stamp(after) == stamp(os.lstat(path)),
                'file changed while reading: ' + str(path))
        return raw, before


def document(path):
    return json.loads(read(path)[0])


def option(argv, key):
    require(argv.count(key) == 1 and argv.index(key) + 1 < len(argv), 'ambiguous option: ' + key)
    return argv[argv.index(key) + 1]


def system(*args, timeout=220):
    command = ['systemctl', '--user', *args]
    event('command_intent', command=command)
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    event('command_result', command=command, returncode=result.returncode, output_tail=(result.stdout + result.stderr)[-3000:])
    require(result.returncode == 0, 'systemctl failed: ' + ' '.join(args))
    return result.stdout.strip()


def props(unit):
    keys = ('MainPID', 'ActiveState', 'SubState', 'DropInPaths')
    return dict(line.split('=', 1) for line in system('show', unit, *['--property=' + k for k in keys], timeout=10).splitlines())


def control_props(name):
    keys = ('Id', 'LoadState', 'MainPID', 'ActiveState', 'SubState', 'FragmentPath', 'DropInPaths', *CONTROL_GRAPH_FIELDS)
    value = dict(line.split('=', 1) for line in system('show', name, *['--property=' + k for k in keys], timeout=10).splitlines())
    require(value.get('Id') == name and value.get('LoadState') == 'loaded'
            and value.get('MainPID', '').isdigit(), 'control service unavailable: ' + name)
    return value


def control_snapshot(name):
    value = control_props(name)
    active = value['ActiveState'] == 'active'
    require((active and value['SubState'] == 'running' and int(value['MainPID']) > 0)
            or (value['ActiveState'] in ('inactive', 'failed') and int(value['MainPID']) == 0),
            'control service is transitioning: ' + name)
    graph = {key: sorted(value.get(key, '').split()) for key in CONTROL_GRAPH_FIELDS}
    dependencies = {unit for key in ('Requires', 'Wants', 'BindsTo') for unit in graph[key] if unit.endswith('.service')}
    require(dependencies == CONTROL_DEPENDENCIES[name], 'control service dependencies changed: ' + name)
    paths = [value['FragmentPath'], *value['DropInPaths'].split()]
    require(all(Path(path).is_absolute() for path in paths), 'control service file path is invalid')
    return dict(was_active=active, properties=value, graph=graph,
                files={path: digest(read(path)[0]) for path in paths})


def restore_control_services(before):
    """Restore only previously running, unchanged entry points; never restart."""
    restored, errors = {}, []
    for name in (BRIDGE, TUNNEL):
        if not before[name]['was_active']:
            restored[name] = 'not_previously_active'
            continue
        try:
            current = control_snapshot(name)
            require(current['files'] == before[name]['files'] and current['graph'] == before[name]['graph'],
                    'control service configuration changed: ' + name)
            if current['was_active']:
                restored[name] = 'already_active_no_restart'
                continue
            for dependency in sorted(CONTROL_DEPENDENCIES[name]):
                value = props(dependency)
                require(value['ActiveState'] == 'active' and value['SubState'] == 'running'
                        and int(value['MainPID']) > 0, 'control dependency is not running: ' + dependency)
            system('start', name, timeout=45)
            deadline = time.monotonic() + 30
            while True:
                value = control_props(name)
                if value['ActiveState'] == 'active' and value['SubState'] == 'running' and int(value['MainPID']) > 0:
                    break
                require(time.monotonic() < deadline, 'control service did not become active: ' + name)
                time.sleep(0.5)
            restored[name] = 'started_original_service'
            event('control_service_restored', unit=name, main_pid=int(value['MainPID']))
        except Exception as error:
            restored[name] = 'restore_failed'
            errors.append(name + ': ' + str(error)[:700])
            event('control_service_restore_failed', unit=name, error_type=type(error).__name__)
    return dict(restored=not errors, units=restored, errors=errors, external_mcp_verified=False)


def identity(unit, binary=None, original_pid=False, expected_argv=None):
    value = props(unit['unit'])
    pid = int(value['MainPID'])
    require(pid > 0 and value['ActiveState'] == 'active' and value['SubState'] == 'running', 'service not running: ' + unit['unit'])
    if original_pid:
        require(pid == int(unit['MainPID']) and value['DropInPaths'] == unit['DropInPaths'], 'reviewed service identity changed')
    argv = [item.decode() for item in Path('/proc', str(pid), 'cmdline').read_bytes().split(b'\0') if item]
    require(argv == (unit['argv'] if expected_argv is None else expected_argv), 'service argv changed: ' + unit['unit'])
    sha = digest(Path('/proc', str(pid), 'exe').read_bytes())
    require(sha == (unit['exe_sha256'] if binary is None else binary), 'running binary hash mismatch')
    if unit['unit'] != FRONT:
        config = Path(option(argv, '--runtime-config'))
        raw = read(config)[0]
        require(str(config) == unit['config_path'] and digest(raw) == unit['config_sha256'], 'runtime config changed')
        require(json.loads(raw)['state_dir'] == unit['state_dir'], 'state root changed in config')
    ticks = int(Path('/proc', str(pid), 'stat').read_text().rsplit(')', 1)[1].split()[19])
    boot = next(int(line.split()[1]) for line in Path('/proc/stat').read_text().splitlines() if line.startswith('btime '))
    return dict(pid=pid, exe_sha256=sha, start_unix=boot + ticks / os.sysconf('SC_CLK_TCK'))


def roots(units):
    result = {}
    for unit in units:
        for path in (Path(unit['state_dir']), Path(unit['state_dir']) / 'jobs'):
            info = path.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and not info.st_mode & 0o022, 'unsafe state directory: ' + str(path))
            result[str(path)] = [info.st_dev, info.st_ino, info.st_uid, info.st_mode]
    return result


def release(path, expected=None):
    path = Path(path)
    require(path.is_absolute() and path.resolve() == path, 'release must be an absolute real directory')
    manifest = document(path / 'release-manifest.json')
    files = manifest['files']
    closure = digest(json.dumps(files, sort_keys=True, separators=(',', ':')).encode())
    require(closure == manifest['closure_sha256'] and (expected is None or closure == expected), 'release closure mismatch')
    for name, sha in files.items():
        leaf = path / name
        require(not Path(name).is_absolute() and '..' not in Path(name).parts and leaf.resolve().is_relative_to(path), 'unsafe release member')
        require(re.fullmatch('[0-9a-f]{64}', sha) and digest(read(leaf)[0]) == sha, 'release member hash mismatch: ' + name)
    return files


def api(client, method, params, phase, notification=False):
    # A shared receipt must not get duplicate IDs from independent Clients.
    client.sequence = len(R.data['calls'])
    return client.single(method, params, phase, notification=notification)


def tool(client, name, arguments, phase):
    require(name in ('host_list', 'request_status', 'operation_status', 'process_status'), 'rollout permits observation tools only')
    return api(client, 'tools/call', {'name': name, 'arguments': arguments}, phase)


def connect(unit, phase):
    token = Path(option(unit['argv'], '--auth-token-file')).read_text().strip()
    require(bool(token), 'empty auth token file')
    R.add_secret(token)
    client = Client(parse_endpoint('http://' + option(unit['argv'], '--bind') + '/mcp'), token, R)
    init = api(client, 'initialize', {'protocolVersion': PROTOCOL, 'capabilities': {}, 'clientInfo': {'name': 'hepta-native-rollout', 'version': '1'}}, phase + '_initialize')
    require(init['ok'] and init['payload'].get('protocolVersion') == PROTOCOL and client.sid, 'MCP initialization failed')
    require(api(client, 'notifications/initialized', None, phase + '_initialized', True)['ok'], 'MCP initialization notification failed')
    listed = api(client, 'tools/list', {}, phase + '_catalog')
    require(listed['ok'] and not listed['payload'].get('nextCursor'), 'incomplete native catalog')
    summary = catalog_summary(listed['payload']['tools'])
    require(summary['count'] == 69 and summary['canonicalcatalogSHA'] == CATALOG, 'native catalog changed')
    require(tool(client, 'host_list', {}, phase + '_host_list')['ok'], 'host_list failed')
    return client


def inventory(unit, expected):
    result = {}
    for kind, namespace in NAMESPACES.items():
        expected_ids = {item['id'] for item in expected['items'] if item['kind'] == kind}
        for leaf in ('.intents', '.outcomes'):
            directory = Path(unit['state_dir']) / namespace / leaf
            items = {}
            if directory.exists():
                for path in sorted(directory.iterdir()):
                    require(re.fullmatch(r'[0-9a-f]{64}\.json', path.name), 'unexpected async metadata member')
                    raw, info = read(path, private=True, maximum=2 * 1024 * 1024)
                    items[path.stem] = [digest(raw), info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns]
            require(set(items) == expected_ids if leaf == '.intents' else set(items) <= expected_ids, 'async ID set changed')
            require(len(items) == unit['async'][namespace]['intent_count' if leaf == '.intents' else 'outcome_count'], 'async metadata count changed')
            result[namespace + '/' + leaf] = items
    return result


def historic_quiescent(unit, process):
    namespace = Path(unit['state_dir']) / 'request-operations-v10'
    values, stamps = [], []
    for leaf in ('.intents', '.outcomes'):
        raw, info = read(namespace / leaf / (HISTORIC + '.json'), private=True, maximum=1024 * 1024)
        values.append(json.loads(raw)); stamps.append(info)
    fields = ('request_id', 'owner', 'tool_name', 'request_hash', 'policy_binding', 'accepted_unix_ms', 'key_hash', 'ledger_identity')
    require(all(key in values[0] and key in values[1] and values[0][key] == values[1][key] for key in fields), 'historical operation binding mismatch')
    require(values[0]['request_id'] == HISTORIC and values[1]['state'] == 'completed', 'historical operation is not completed')
    accepted = values[0]['accepted_unix_ms']
    require(type(accepted) is int and 0 <= accepted / 1000 < process['start_unix'], 'historical acceptance is not older than controller')
    require(all(max(s.st_mtime_ns, s.st_ctime_ns) / 1e9 < process['start_unix'] for s in stamps), 'historical metadata is newer than controller')
    anchor = json.loads(read(Path(unit['state_dir']) / '.request-operations-v10-anchor.json', private=True)[0])
    lockpath = namespace / '.controller.lock'
    raw, lock = read(lockpath, private=True, maximum=1)
    ns = namespace.lstat()
    require(not raw and stat.S_ISDIR(ns.st_mode) and anchor['device'] == ns.st_dev and anchor['inode'] == ns.st_ino
            and anchor['controller_lock_device'] == lock.st_dev and anchor['controller_lock_inode'] == lock.st_ino, 'async anchor or controller lock identity mismatch')
    holders = []
    for line in Path('/proc/locks').read_text().splitlines():
        parts = line.split(); offset = 2 if len(parts) > 1 and parts[1] == '->' else 1
        require(len(parts) >= offset + 7, 'cannot parse /proc/locks')
        major, minor, inode = parts[offset + 4].split(':')
        ident = (int(major, 16), int(minor, 16), int(inode))
        owner = int(parts[offset + 3])
        if ident == (os.major(lock.st_dev), os.minor(lock.st_dev), lock.st_ino):
            require(offset == 1, 'another controller is waiting on historical namespace')
            holders.append(owner)
    require(not holders or set(holders) == {process['pid']}, 'foreign async controller holds historical namespace')
    event('historical_scope_refusal_quiescent', unit=unit['unit'], operation_id=HISTORIC,
          binding_fields_equal=True, terminal='completed', predates_current_pid=True,
          controller_lock_identity=[lock.st_dev, lock.st_ino], controller_lock_holders=holders,
          proc_locks_read_and_parsed=True, authorization_unchanged=True)


def observe(unit, expected, phase, process, baseline=None, jobs=False):
    before = inventory(unit, expected)
    if baseline is not None:
        require(before == baseline, 'async registry changed since initial preflight')
    client = connect(unit, phase)
    for item in expected['items']:
        name, ident = item['kind'], item['id']
        key = 'request_id' if name == 'request_status' else 'operation_id'
        answer = tool(client, name, {key: ident}, phase + '_' + name)
        if unit['unit'] == SUCCESSOR and ident == HISTORIC:
            require(not answer['ok'] and answer['payload'] == {'error_text': 'async request unavailable to this scope or current policy'}, 'historical policy boundary changed')
            historic_quiescent(unit, process)
        else:
            payload = answer['payload'] or {}
            require(answer['ok'] and payload.get(key) == ident and payload.get('owned_future_active') is False
                    and payload.get('async_state') == item['payload']['async_state']
                    and payload['async_state'] in ('completed', 'unknown'), 'async state is not quiescent or changed')
    if jobs:
        for host, ident in AUDIT_JOBS.items():
            answer = tool(client, 'process_status', {'host': host, 'job_id': ident}, phase + '_v4_job')
            payload = answer['payload'] or {}
            require(answer['ok'] and payload.get('job_id') == ident and payload.get('state') == 'succeeded'
                    and payload.get('exit_code') == 0 and payload.get('status_authoritative') is not False,
                    'original V4 job status changed')
    require(inventory(unit, expected) == before, 'async registry changed during observation')
    event(phase, unit=unit['unit'], process=process, async_inventory=before)
    return before


def atomic(path, raw, exclusive=False, published=None):
    fd, temporary = tempfile.mkstemp(prefix=path.name + '.', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        if exclusive:
            os.link(temporary, path)
        else:
            os.replace(temporary, path)
        if published is not None:
            published()
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def stop(unit):
    before = props(unit)
    old_pid = int(before['MainPID'])
    old_stat = Path('/proc', str(old_pid), 'stat')
    old_identity = old_stat.read_text().rsplit(')', 1)[1].split()[19] if old_pid and old_stat.exists() else None
    system('stop', unit, timeout=220)
    value = props(unit)
    require(value['ActiveState'] == 'inactive' and int(value['MainPID']) == 0, 'service has not fully stopped: ' + unit)
    require(not old_identity or not old_stat.exists()
            or old_stat.read_text().rsplit(')', 1)[1].split()[19] != old_identity,
            'original service process survived stop: ' + unit)


def wait(unit, argv, binary=None, timeout=100):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            process = identity(unit, binary=binary, expected_argv=argv)
            port = option(argv, '--bind').rsplit(':', 1)[1]
            output = subprocess.check_output(['ss', '-H', '-ltnp', 'sport = :' + port], text=True, timeout=5)
            require(set(map(int, re.findall(r'pid=(\d+)', output))) == {process['pid']}, 'service does not exclusively own listener')
            if unit['unit'] == FRONT:
                connection = http.client.HTTPConnection('127.0.0.1', int(port), timeout=3)
                try:
                    token = Path(option(argv, '--auth-token-file')).read_text().strip(); R.add_secret(token)
                    connection.request('GET', '/health', headers={'X-Hepta-Runtime-Token': token})
                    response = connection.getresponse(); data = response.read(65537)
                    require(response.status == 200 and len(data) <= 65536, 'frontend health unavailable')
                    event('frontend_health', health=json.loads(data), process=process)
                finally:
                    connection.close()
            return process
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
            time.sleep(0.5)
    raise RuntimeError('healthy expected listener deadline exceeded: ' + unit['unit'])


def main():
    global R, RECOVERING
    RECOVERING = False
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--check-only', action='store_true'); mode.add_argument('--apply', action='store_true')
    parser.add_argument('--output-prefix', required=True)
    options = parser.parse_args()
    require(re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,79}', options.output_prefix), 'invalid output prefix')
    prefix = options.output_prefix + ('-check' if options.check_only else '-apply')
    lock = os.open(ROOT / '.native-rollout-20261017.lock', os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    R = Receipt(ROOT / (prefix + '.json'), {'schema': 'hepta-native-rollout-v1', 'mode': 'check-only' if options.check_only else 'apply', 'started_utc': utc_now(), 'calls': [], 'batches': [], 'events': [], 'passed': False}, '')
    touched, created, frontend_stopped, front_changed = [], {}, False, False
    control_before = None
    front = front_drop = front_raw = new_front_raw = None
    try:
        preflight = document(ROOT / 'native-rollout-preflight.json')
        units = {u['unit']: u for u in preflight['units']}
        require(set(units) == set(ORDER) | {FRONT}, 'unexpected preflight units')
        expected = {e['unit']: e for e in document(ROOT / 'native-async-preflight.json')['endpoints']}
        require({u: len(expected[u]['items']) for u in ORDER} == {OPERATOR: 0, SUCCESSOR: 4, V11: 11}, 'unexpected async scope')
        require(all(item['kind'] in NAMESPACES and re.fullmatch('[0-9a-f]{64}', item['id'])
                    for value in expected.values() for item in value['items']), 'invalid async observation specification')
        target = document(ROOT / 'native-release-current.json'); target_path = Path(target['release_path'])
        require(re.fullmatch('[0-9a-f]{40}', target['source_commit']), 'invalid source commit')
        files = release(target_path, target['closure_sha256'])
        require(files['hepta-runtime'] == target['binary_sha256'] != OLD_BINARY, 'candidate binary missing or unchanged')
        require(os.access(target_path / 'hepta-runtime', os.X_OK), 'candidate binary is not executable')
        front = units[FRONT]; old_release = Path(front['argv'][2]).parent
        require(old_release.name == 'r22-pager65k-shared-rebind-c1da232ee930ecfa-20261017', 'unexpected current frontend release')
        old_files = release(old_release)
        require(all(files.get(name) == sha for name, sha in old_files.items() if name != 'hepta-runtime'), 'candidate changed an existing frontend asset')
        front_drop = Path(front['DropInPaths'])
        require(front_drop.name == '90-runtime-pager65k-20261017.conf', 'unexpected frontend override')
        front_raw = read(front_drop, private=True)[0]
        require(str(old_release).encode() in front_raw, 'frontend override lacks reviewed release')
        new_front_raw = front_raw.replace(str(old_release).encode(), str(target_path).encode())
        before_roots = roots([units[u] for u in ORDER]); baselines = {}
        identity(front, original_pid=True)
        for name in ORDER:
            unit = units[name]
            require(unit['exe_sha256'] == OLD_BINARY, 'unexpected original native hash')
            drop = Path(unit['FragmentPath'] + '.d') / '91-native-throughput-20261017.conf'
            require(not drop.exists() and not drop.is_symlink(), 'rollout override already exists')
            process = identity(unit, original_pid=True)
            baselines[name] = observe(unit, expected[name], 'preflight', process, jobs=name == OPERATOR)
        control_before = {name: control_snapshot(name) for name in (BRIDGE, TUNNEL)}
        R.update(target=target, root_identities=before_roots, original_front_override_sha256=digest(front_raw),
                 original_control_services=control_before, external_mcp_verified=False, preflight_passed=True)
        if options.check_only:
            R.update(passed=True); return 0
        acceptance_path = ROOT / (prefix + '-pager-acceptance.json')
        require(not acceptance_path.exists(), 'pager acceptance output exists')
        backup = ROOT / (prefix + '-frontend-original.conf')
        fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(front_raw); stream.flush(); os.fsync(stream.fileno())
        identity(front, original_pid=True)
        frontend_stopped = True; stop(FRONT)
        require(roots([units[u] for u in ORDER]) == before_roots, 'state root identity changed')
        for name in ORDER:
            observe(units[name], expected[name], 'drained', identity(units[name], original_pid=True), baselines[name])
        for name in ORDER:
            unit = units[name]; identity(unit, original_pid=True)
            touched.append(name); stop(name)
            argv = [str(target_path / 'hepta-runtime'), *unit['argv'][1:]]
            quote = lambda item: json.dumps(item, ensure_ascii=False).replace('%', '%%').replace('$', '$$')
            content = ('[Service]\nExecStart=\nExecStart=' + ' '.join(quote(arg) for arg in argv) + '\n').encode()
            drop = Path(unit['FragmentPath'] + '.d') / '91-native-throughput-20261017.conf'
            drop.parent.mkdir(mode=0o700, exist_ok=True)
            atomic(drop, content, exclusive=True,
                   published=lambda: created.__setitem__(name, (drop, content, (drop.stat().st_dev, drop.stat().st_ino))))
            event('native_override_written', unit=name, path=str(drop), sha256=digest(content))
            system('daemon-reload'); system('start', name)
            process = wait(unit, argv, target['binary_sha256'])
            require(process['pid'] != int(unit['MainPID']), 'native PID did not change')
            require(roots([units[u] for u in ORDER]) == before_roots, 'state root identity changed after native switch')
            observe(unit, expected[name], 'candidate', process, baselines[name], jobs=name == OPERATOR)
        require(read(front_drop)[0] == front_raw, 'frontend override changed externally')
        atomic(front_drop, new_front_raw); front_changed = True
        system('daemon-reload'); system('start', FRONT)
        wait(front, [arg.replace(str(old_release), str(target_path)) for arg in front['argv']])
        command = ['/usr/bin/python3', '-B', str(Path(__file__).resolve().with_name('pager_acceptance.py')),
                   '--port', '8795', '--output', str(acceptance_path)]
        event('pager_acceptance_intent', command=command)
        result = subprocess.run(command, capture_output=True, text=True, timeout=480)
        acceptance = document(acceptance_path)
        event('pager_acceptance_result', returncode=result.returncode, report=acceptance)
        require(result.returncode == 0 and acceptance['passed'], 'frontend pagination acceptance failed')
        require(roots([units[u] for u in ORDER]) == before_roots, 'final state root identity changed')
        final_native = {name: identity(units[name], target['binary_sha256'],
                                      expected_argv=[str(target_path / 'hepta-runtime'), *units[name]['argv'][1:]]) for name in ORDER}
        R.update(passed=True, activated=True, final_native_identities=final_native); return 0
    except Exception as exc:
        RECOVERING = True
        R.data['passed'] = False
        R.data.pop('activated', None)
        event('failure', error_type=type(exc).__name__, error=str(exc)[:3000])
        rollback_errors = []
        if frontend_stopped:
            try:
                stop(FRONT)
            except Exception as error:
                rollback_errors.append('frontend stop: ' + str(error))
            for name in reversed(touched):
                try:
                    stop(name)
                    if name in created:
                        drop, content, file_identity = created[name]
                        raw, info = read(drop)
                        require(raw == content and (info.st_dev, info.st_ino) == file_identity,
                                'owned native override changed externally')
                        drop.unlink()
                    system('daemon-reload'); system('start', name)
                    wait(units[name], units[name]['argv'], OLD_BINARY)
                except Exception as error:
                    rollback_errors.append(name + ': ' + str(error))
            try:
                current_front = read(front_drop)[0]
                require(current_front in (front_raw, new_front_raw), 'owned frontend override changed externally')
                if current_front != front_raw:
                    atomic(front_drop, front_raw)
                system('daemon-reload'); system('start', FRONT); wait(front, front['argv'])
            except Exception as error:
                rollback_errors.append('frontend restore: ' + str(error))
            R.data.update(rolled_back=not rollback_errors, rollback_errors=rollback_errors)
        return 1
    finally:
        if frontend_stopped and control_before is not None:
            # Once an entry point is restored, new requests may arrive.  Its
            # failure must not unwind the already completed core transaction.
            RECOVERING = True
            if R.data['passed'] or R.data.get('rolled_back') is True:
                control_result = restore_control_services(control_before)
            else:
                control_result = dict(restored=False, units={}, external_mcp_verified=False,
                                      errors=['core restoration incomplete; dependent services left unchanged'])
            R.data.update(dependent_services_restored=control_result['restored'],
                          control_service_restoration=control_result)
        R.data.update(finished_utc=utc_now())
        try:
            R.update()
        except Exception as error:
            R.data.setdefault('receipt_write_errors', []).append(str(error)[:500])
        try:
            print(json.dumps({'passed': R.data['passed'], 'mode': R.data['mode'], 'receipt': str(R.path),
                              'rolled_back': R.data.get('rolled_back'),
                              'dependent_services_restored': R.data.get('dependent_services_restored'),
                              'external_mcp_verified': False,
                              'receipt_write_errors': R.data.get('receipt_write_errors', [])}, sort_keys=True), flush=True)
        finally:
            os.close(lock)


if __name__ == '__main__':
    raise SystemExit(main())

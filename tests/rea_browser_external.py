#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Opt-in same-host qualification: native job -> private Chrome -> HAR -> REA.

Only authored fixtures and call-owned loopback listeners are used. No browser
installation, service changes, user-browser attachment or shared-filesystem
assumption is made. Capture effects use existing MCP native process jobs.
A fixed harness fetches resource bytes; input HTML/JS is never evaluated.
This qualifies HTTP observations and saved HAR representations, not complete
application behavior or process-level network isolation.
"""
import argparse
from contextlib import contextmanager
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import threading
import time
from urllib.parse import urlsplit

from rea_java_external import Mcp, digest, private_write, set_fence
from rea_browser_environment import ChromeEnvironmentObserver, expected_environment


def fixture(root, name, *, slow=False):
    directory = root / name; directory.mkdir(mode=0o700)
    values = {'before.txt': b'HEPTA_LOCAL_BEFORE\n', 'after.txt': b'HEPTA_LOCAL_AFTER\n',
              'empty.txt': b'', 'binary.bin': b'\0\xff\xfe\x80HEPTA', 'truncated.txt': b'partial authored response'}
    for filename, data in values.items(): private_write(directory / filename, data)
    def source(filename): return dict(file=filename, sha256=digest(directory / filename))
    resources = [dict(url_path='/text', mime_type='text/plain; charset=utf-8', before=source('before.txt'), after=source('after.txt')),
                 dict(url_path='/empty', mime_type='text/plain; charset=utf-8', before=source('empty.txt')),
                 dict(url_path='/binary', mime_type='application/octet-stream', before=source('binary.bin')),
                 dict(url_path='/missing', mime_type='text/plain; charset=utf-8', before=source('truncated.txt'), delivery='truncated')]
    if slow: resources[0]['delay_ms'] = 2000
    value = dict(schema='hepta.rea.local-browser-capture.v1', resources=resources,
                 requests=['/text'] * 32 if slow else ['/text', '/text', '/empty', '/binary', '/missing'], timeout_seconds=60)
    manifest = directory / 'fixture.json'; private_write(manifest, value)
    return manifest, directory / 'capture'


def original_output(server, job_id):
    positions = dict(stdout_offset=0, stderr_offset=0)
    chunks = dict(stdout=[], stderr=[])
    for _ in range(16):
        page = server.call('process_read', dict(host='local', job_id=job_id, limit=16384, **positions))
        for stream in chunks:
            chunks[stream].append(bytes.fromhex(page[stream]['bytes_hex']))
            positions[stream + '_offset'] = page[stream]['next_offset']
        if page['stdout']['eof'] and page['stderr']['eof']:
            return {name: b''.join(parts).decode('utf-8') for name, parts in chunks.items()}
    raise ValueError('Qualification job output exceeds the evidence budget')


def terminal(server, job_id, timeout=100):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = server.call('process_status', dict(host='local', job_id=job_id))
        if value.get('state') in ('succeeded', 'failed', 'cancelled', 'timed_out'):
            assert value.get('output_complete') is True, value
            return value
        time.sleep(.5)
    raise TimeoutError('Original capture job has no confirmed terminal state')


def browser_start(server, job_id):
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        output = original_output(server, job_id)
        lines = output['stdout'].splitlines()
        if not output['stdout'].endswith('\n'): lines = lines[:-1]
        for line in lines:
            value = json.loads(line)
            if value.get('phase') == 'browser_started': return value
        state = server.call('process_status', dict(host='local', job_id=job_id))
        if state.get('state') in ('succeeded', 'failed', 'cancelled', 'timed_out'):
            raise AssertionError(('capture ended before browser-start evidence', state, output))
        time.sleep(.25)
    raise TimeoutError('No browser-start evidence from the original job')


def no_owned_browser(profile, process_group):
    marker = ('--user-data-dir=' + profile).encode()
    found = []
    for directory in Path('/proc').iterdir():
        if not directory.name.isdigit(): continue
        try:
            arguments = (directory / 'cmdline').read_bytes().split(b'\0')
            fields = (directory / 'stat').read_text().rsplit(')', 1)[1].split()
            state, group = fields[0], int(fields[2])
        except (PermissionError, FileNotFoundError, ProcessLookupError): continue
        if state not in ('Z', 'X') and (marker in arguments or group == process_group): found.append(int(directory.name))
    assert not found, ('own original private browser group still has live members', found)
    assert not Path(profile).parent.exists(), ('own private profile was not removed', profile)


def file_version(value):
    return dict(device=value.st_dev, inode=value.st_ino, size=value.st_size,
                mode=value.st_mode, uid=value.st_uid, gid=value.st_gid, links=value.st_nlink,
                mtime_ns=value.st_mtime_ns, ctime_ns=value.st_ctime_ns)


def hash_regular_descriptor(descriptor):
    before = os.fstat(descriptor)
    assert stat.S_ISREG(before.st_mode) and 0 < before.st_size <= 1024 * 1024 * 1024
    hasher, total = hashlib.sha256(), 0
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk: break
        total += len(chunk)
        assert total <= before.st_size, 'Executable grew while recording its identity'
        hasher.update(chunk)
    assert total == before.st_size and file_version(os.fstat(descriptor)) == file_version(before)
    return dict(sha256=hasher.hexdigest(), **file_version(before))


def installed_chrome_identity():
    """Pin the fixed system launcher separately from the executable it dispatches."""
    launcher = Path('/usr/bin/google-chrome')
    resolved = launcher.resolve(strict=True)
    paths = dict(launcher=launcher, executable=resolved.parent / 'chrome')
    identity = {}
    for kind, path in paths.items():
        realpath = path.resolve(strict=True)
        descriptor = os.open(realpath, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            value = hash_regular_descriptor(descriptor)
            assert value['mode'] & 0o111, 'Chrome component is not executable'
            assert file_version(realpath.lstat()) == file_version(os.fstat(descriptor))
            assert path.resolve(strict=True) == realpath
            identity[kind] = dict(invocation_path=str(path), realpath=str(realpath), **value)
        finally:
            os.close(descriptor)
    assert identity['launcher']['realpath'] != identity['executable']['realpath']
    return identity


def original_browser_identity(started, installation, environment_observer=None):
    """Bind the original live Chrome; exec environment needs its own observation."""
    pid, group = started['browser_pid'], started['browser_pgid']
    assert isinstance(pid, int) and pid > 0 and group == pid
    profile = Path(started['profile'])
    assert profile.is_absolute() and profile.resolve(strict=True) == profile
    expected = expected_environment(profile)
    directory = os.open('/proc/' + str(pid), os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY)
    def read_bounded(name, limit):
        descriptor = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory)
        try:
            chunks, size = [], 0
            while True:
                chunk = os.read(descriptor, min(65536, limit + 1 - size))
                if not chunk: return b''.join(chunks)
                chunks.append(chunk); size += len(chunk)
                assert size <= limit, 'Original browser observation exceeded its bound'
        finally:
            os.close(descriptor)
    def process_identity():
        value = read_bounded('stat', 16384).decode('utf-8')
        fields = value.rsplit(')', 1)[1].split()
        assert int(value.split('(', 1)[0]) == pid and fields[0] not in ('Z', 'X')
        assert int(fields[2]) == group
        return dict(pid=pid, parent_pid=int(fields[1]), pgid=group, start_ticks=int(fields[19]))
    try:
        original = process_identity()
        expected_executable = installation['executable']
        deadline = time.monotonic() + 5
        while os.readlink('exe', dir_fd=directory) != expected_executable['realpath']:
            assert process_identity() == original, 'Original Chrome process identity changed'
            assert time.monotonic() < deadline, 'Original launcher did not exec the pinned Chrome executable'
            time.sleep(.01)
        executable = os.open('exe', os.O_RDONLY | os.O_CLOEXEC, dir_fd=directory)
        try:
            actual_executable = hash_regular_descriptor(executable)
        finally:
            os.close(executable)
        assert actual_executable == {key: expected_executable[key] for key in actual_executable}
        raw = read_bounded('environ', 1024 * 1024)
        selected = {}
        for item in raw.split(b'\0'):
            key, separator, value = item.partition(b'=')
            if key in (b'HOME', b'XDG_DATA_HOME', b'XDG_CONFIG_HOME', b'XDG_CACHE_HOME'):
                name = key.decode('ascii')
                assert separator and name not in selected, 'Repeated private environment key'
                selected[name] = value.decode('utf-8')
        # Chromium moves the strings addressed by libc environ, then may reuse
        # the initial stack region for its process title. Never certify getenv
        # from an empty /proc selection or infer it from the parent's config.
        fields = read_bounded('stat', 16384).decode('utf-8').rsplit(')', 1)[1].split()
        environment_offset = int(fields[47]) - int(fields[45])
        command_line = read_bounded('cmdline', 1024 * 1024)
        tail_matches = (0 <= environment_offset < len(command_line)
                        and bool(raw.rstrip(b'\0'))
                        and raw.rstrip(b'\0') == command_line[environment_offset:].rstrip(b'\0'))
        observation = dict(bytes=len(raw), nul_bytes=raw.count(b'\0'),
            selected_private_values=selected, matches_expected=selected == expected,
            matches_rewritten_command_line_tail=tail_matches,
            scope='mutable initial /proc environment memory; not a current getenv attestation')
        evidence = environment_observer.verify_live(original, expected) if environment_observer else None
        directories = {}
        for key, path in expected.items():
            value = Path(path).lstat()
            assert stat.S_ISDIR(value.st_mode) and stat.S_IMODE(value.st_mode) == 0o700
            assert value.st_uid == os.getuid() and Path(path).resolve(strict=True) == Path(path)
            directories[key] = dict(path=path, **file_version(value))
        assert process_identity() == original
        assert os.readlink('exe', dir_fd=directory) == expected_executable['realpath']
        return dict(**original, executable=dict(realpath=expected_executable['realpath'], **actual_executable),
                    proc_initial_environment=observation, private_directories=directories,
                    exec_environment_verified=evidence is not None, exec_environment_evidence=evidence,
                    scope=('same instrumented Chrome PID at constructor exec boundary and before cancellation'
                           if evidence else 'uninstrumented original Chrome identity and directories; getenv not attested'))
    finally:
        os.close(directory)


@contextmanager
def replay_sentinels(origins):
    """Observe connections and every HTTP method at only these two known origins."""
    servers, threads, counts, lock = [], [], {}, threading.Lock()
    class Server(ThreadingHTTPServer):
        def get_request(self):
            connection, address = super().get_request()
            with lock: counts[self.server_port]['accepted_connections'] += 1
            return connection, address
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args): pass
        def parse_request(self):
            accepted = super().parse_request()
            if accepted:
                # Count before do_METHOD dispatch, including unsupported methods
                # that BaseHTTPRequestHandler subsequently rejects with 501.
                with lock:
                    value = counts[self.server.server_port]
                    value['http_requests'] += 1
                    value['methods'][self.command] = value['methods'].get(self.command, 0) + 1
            return accepted
        def do_GET(self):
            body = b'OFFLINE_REPLAY_MUST_NEVER_FETCH_THIS'
            self.send_response(200); self.send_header('Content-Length', str(len(body))); self.end_headers()
            self.wfile.write(body)
    try:
        for origin in origins:
            parsed = urlsplit(origin)
            assert parsed.scheme == 'http' and parsed.hostname == '127.0.0.1' and parsed.port is not None
            server = Server(('127.0.0.1', parsed.port), Handler)
            server.daemon_threads = True
            counts[server.server_port] = dict(accepted_connections=0, http_requests=0, methods={})
            thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .05}, daemon=True)
            servers.append(server); threads.append(thread); thread.start()
            control = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=2)
            try:
                control.request('GET', '/sentinel-control')
                assert control.getresponse().read() == b'OFFLINE_REPLAY_MUST_NEVER_FETCH_THIS'
            finally:
                control.close()
            with lock:
                assert counts[server.server_port] == dict(accepted_connections=1, http_requests=1, methods={'GET': 1})
                counts[server.server_port] = dict(accepted_connections=0, http_requests=0, methods={})
        yield counts
    finally:
        for server in servers: server.shutdown(); server.server_close()
        for thread in threads: thread.join(timeout=2)
    assert not any(value['accepted_connections'] or value['http_requests'] for value in counts.values()), (
        'offline REA contacted one of the two known captured origins', counts)


def python_identity(path):
    # Resolving a venv launcher to its base executable changes interpreter
    # semantics. Keep the absolute invocation spelling and pin its target apart.
    invocation = path.absolute()
    resolved = invocation.resolve(strict=True)
    if not resolved.is_file() or not os.access(invocation, os.X_OK):
        raise ValueError('Qualification Python is not an executable regular file')
    return invocation, dict(invocation_path=str(invocation), realpath=str(resolved), sha256=digest(resolved))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime', type=Path, required=True)
    capture_mode = parser.add_mutually_exclusive_group(required=True)
    capture_mode.add_argument('--capture-helper', type=Path)
    capture_mode.add_argument('--native-capture', action='store_true')
    parser.add_argument('--python', type=Path)
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--allow-owned-browser', action='store_true')
    parser.add_argument('--allow-local-ssh', action='store_true')
    args = parser.parse_args()
    assert args.allow_owned_browser and args.allow_local_ssh, 'Explicit real-browser and localhost SSH qualification flags are required'
    assert sys.platform == 'linux', 'This qualification is Linux/main/same-host only'
    source_runtime = args.runtime.resolve(strict=True)
    helper = args.capture_helper.resolve(strict=True) if args.capture_helper else None
    if not args.native_capture and args.python is None:
        parser.error('--python is required with --capture-helper')
    python, interpreter_pin = python_identity(args.python) if args.python else (None, None)
    root = args.workspace.absolute(); root.mkdir(mode=0o700, parents=False, exist_ok=False)
    runtime = root / 'hepta-runtime-qualified'
    shutil.copyfile(source_runtime, runtime); runtime.chmod(0o500)
    for name in ('controller-state', 'jobs', 'authority'): (root / name).mkdir(mode=0o700)
    private_write(root / 'authority/.owner.lock', b''); set_fence(root, 'admitting')
    config = dict(state_dir=str(root / 'controller-state'), controller_workspace_roots=[str(root)],
        hosts=dict(local=dict(ssh_target='localhost', platform='linux', execution_mode='operator',
            remote_state_dir=str(root / 'jobs'), allow_execute=True, allow_write=True, allow_job_network=True,
            allow_detached_fallback=False, allowed_cwd_prefixes=[], allowed_read_path_prefixes=[str(root)],
            allowed_write_path_prefixes=[str(root)])))
    private_write(root / 'config.json', config)
    source_files = (sorted((Path(__file__).resolve().parents[1] / 'src/mcp').glob('rea_browser*.rs')) if args.native_capture
                    else [helper, helper.parent / 'dc_compat/chromium_capture.py', helper.parent / 'dc_compat/chromium_pdf.py'])
    assert source_files, 'Native capture qualification requires its source files'
    if args.native_capture:
        source_files += [Path(__file__).resolve(), Path(__file__).resolve().parent / 'rea_browser_environment.py',
                         Path(__file__).resolve().parent / 'fixtures/rea_browser_env_observer.c']
    source_pins = {str(path): digest(path) for path in source_files}
    result = dict(schema='hepta.rea.local-browser-qualification.v1', workspace=str(root), qualified=False,
                  runtime_sha256=digest(runtime), helper_sources=source_pins, python=interpreter_pin,
                  host_scope='Linux main; controller and native worker on the same host',
                  execution_mode='operator', process_level_network_isolation=False, checks=[],
                  capture_implementation='native-rust' if args.native_capture else 'python-reference')
    result.update(capture_scope='fixed_owned_harness_http_resource_observation',
                  input_application_scripts_executed=False, input_page_dom_inspected=False,
                  complete_application_behavior_recording=False, general_browser_state_replay=False,
                  rea_replay_scope='saved HAR content.text representation; no network replay')
    server, active = None, []
    try:
        if args.native_capture:
            result['browser_installation'] = installed_chrome_identity()
            environment_observer = ChromeEnvironmentObserver(root, result['browser_installation'])
            result['environment_observer'] = environment_observer.binding
            result['environment_negative_controls'] = environment_observer.negative_controls()
            result['checks'].append('eight_actual_chrome_exec_missing_and_non_private_environment_controls_rejected')
        server = Mcp(runtime, root)
        names = {tool['name'] for tool in server.request('tools/list', {})['tools']}
        assert {'process_start', 'process_status', 'process_read', 'process_cancel',
                'rea_inspect_web_capture', 'rea_compare_web_captures', 'rea_replay_web_entry'} <= names
        def request(manifest, output, key):
            executable = runtime if args.native_capture else python
            prefix = ['rea-browser-capture'] if args.native_capture else [str(helper)]
            return dict(host='local', executable=str(executable), args=prefix + ['--manifest', str(manifest),
                '--expected-sha256', digest(manifest), '--output-directory', str(output)], cwd=str(root),
                env={} if args.native_capture else dict(PYTHONUNBUFFERED='1'), timeout_seconds=100, idempotency_key=key,
                nice=10, cpu_quota_percent=100, memory_max_bytes=1024 * 1024 * 1024)
        tamper_manifest, tamper_output = fixture(root, 'tamper-fixture')
        tamper_request = request(tamper_manifest, tamper_output, 'owned-browser-tamper')
        tamper_request_path = root / 'tamper-request.json'
        private_write(tamper_request_path, tamper_request)
        tamper_pins = dict(manifest_sha256=digest(tamper_manifest), request_file_sha256=digest(tamper_request_path))
        resource = tamper_manifest.parent / 'before.txt'
        tamper_pins['declared_resource_sha256'] = digest(resource)
        resource.write_bytes(b'OWNED_RESOURCE_CHANGED_AFTER_MANIFEST_AND_REQUEST_PINNING\n')
        tamper_pins['changed_resource_sha256'] = digest(resource)
        assert tamper_pins['declared_resource_sha256'] != tamper_pins['changed_resource_sha256']
        assert digest(tamper_manifest) == tamper_pins['manifest_sha256']
        private_write(root / 'tamper-pins.json', tamper_pins)
        tamper_admission = server.call('process_start', tamper_request)
        tamper_job = tamper_admission['job']['id']; active.append(tamper_job)
        private_write(root / 'tamper-admission.json', tamper_admission)
        tamper_terminal = terminal(server, tamper_job)
        active.remove(tamper_job)
        tamper_logs = original_output(server, tamper_job)
        private_write(root / 'tamper-terminal.json', dict(status=tamper_terminal, output=tamper_logs))
        assert tamper_terminal['state'] == 'failed' and tamper_terminal['exit_code'] != 0, (tamper_terminal, tamper_logs)
        assert 'resource SHA-256 mismatch' in tamper_logs['stderr'], tamper_logs
        tamper_events = [json.loads(line) for line in tamper_logs['stdout'].splitlines()]
        assert not any(value.get('phase') in ('browser_started', 'complete') for value in tamper_events), tamper_logs
        assert not tamper_output.exists(), 'Refused resource must not produce a capture directory or receipt'
        assert not list(tamper_manifest.parent.glob('.hepta-private-capture-*'))
        tamper_reuse = server.call('process_start', tamper_request)
        assert tamper_reuse['reused'] is True and tamper_reuse['job']['id'] == tamper_job
        assert original_output(server, tamper_job) == tamper_logs
        assert digest(tamper_manifest) == tamper_pins['manifest_sha256']
        assert digest(tamper_request_path) == tamper_pins['request_file_sha256']
        private_write(root / 'tamper-reused.json', tamper_reuse)
        result.update(tamper_job_id=tamper_job, tamper_identity=tamper_pins)
        result['checks'].append('unchanged_manifest_and_request_refuse_changed_resource_before_browser_and_same_key_reuses_failed_job')
        manifest, output = fixture(root, 'capture-fixture')
        original = request(manifest, output, 'owned-browser-capture')
        private_write(root / 'capture-request.json', original)
        admitted = server.call('process_start', original); job = admitted['job']['id']; active.append(job)
        private_write(root / 'capture-admission.json', admitted)
        duplicate = server.call('process_start', original)
        assert duplicate['reused'] is True and duplicate['job']['id'] == job
        completed = terminal(server, job)
        active.remove(job)
        logs = original_output(server, job)
        private_write(root / 'capture-terminal.json', dict(status=completed, output=logs))
        assert completed['state'] == 'succeeded' and completed['exit_code'] == 0, (completed, logs)
        lines = [json.loads(line) for line in logs['stdout'].splitlines()]
        starts = [line for line in lines if line.get('phase') == 'browser_started']
        assert len(starts) == 1, lines
        no_owned_browser(starts[0]['profile'], starts[0]['browser_pgid'])
        final = next(line for line in lines if line.get('phase') == 'complete')
        receipt_path = Path(final['receipt_path'])
        assert digest(receipt_path) == final['receipt_sha256']
        receipt = json.loads(receipt_path.read_text())
        if args.native_capture:
            assert receipt['implementation'] == 'native-rust'
            assert receipt['native_worker_sha256'] == result['runtime_sha256']
            assert receipt['cdp']['transport'] == 'native-cdp-pipe-asciiz'
            publication = receipt['publication']
            assert publication['har_files_fsynced'] is True and publication['har_directory_fsynced'] is True
            assert publication['receipt_directory_fsync_confirmation'] == 'original_job_succeeded_with_complete_event'
            assert 'directory_fsynced' not in publication, 'Receipt must not attest its own later directory sync'
            assert final['receipt_directory_fsynced'] is True
            result['checks'].append('receipt_durability_confirmed_by_original_success_and_post_sync_complete_event')
        assert receipt['loopback']['negative_probe_control_requests'] == 1
        assert receipt['loopback']['negative_probe_browser_requests'] == 0
        assert receipt['process_level_network_isolation'] is False
        assert receipt['original_process_group_no_live_members'] is True
        assert receipt['changed_session_descendants_covered'] is False
        result.update(capture_job_id=job, capture_receipt=final, observed_browser=receipt['browser_version'])
        result['checks'].extend(['original_native_job_and_same_key_single_browser', 'reachable_second_loopback_origin_received_zero_browser_requests',
                                 'private_chrome_and_profile_removed_after_success'])
        sources = {phase: dict(path=entry['path'], sha256=entry['sha256']) for phase, entry in receipt['artifacts'].items()}
        for source in sources.values(): assert digest(Path(source['path'])) == source['sha256']
        raw_har = json.loads(Path(sources['before']['path']).read_text())
        entries = raw_har['log']['entries']
        states = {entry['_hepta']['body_state'] for entry in entries}
        assert {'complete', 'empty', 'base64', 'missing'} <= states, states
        assert len([entry for entry in entries if entry['request']['url'].endswith('/text')]) == 2
        assert any(entry['request']['url'].endswith('/missing') and entry['_hepta']['body_state'] == 'missing' for entry in entries)
        result['checks'].append('real_complete_empty_base64_missing_and_repeated_request_observations')
        with replay_sentinels([receipt['loopback']['origin'], receipt['loopback']['negative_probe_origin']]) as network_counts:
            inspected = server.call('rea_inspect_web_capture', dict(path=sources['before']['path'], expected_sha256=sources['before']['sha256'], limit=64))
            compared = server.call('rea_compare_web_captures', dict(before=sources['before'], after=sources['after'], limit=64))
            assert compared['counts']['added'] == 0 and compared['counts']['removed'] == 0, compared
            assert compared['counts']['changed'] == 2, compared
            private_write(root / 'capture-inspected.json', inspected)
            private_write(root / 'capture-compared.json', compared)
            server.close(); server = Mcp(runtime, root)
            recovered = server.call('process_start', original)
            assert recovered['reused'] is True and recovered['job']['id'] == job
            assert original_output(server, job) == logs
            assert server.call('rea_inspect_web_capture', dict(path=sources['before']['path'], expected_sha256=sources['before']['sha256'], limit=64)) == inspected
            replays = []
            for index, entry in enumerate(entries):
                replay = server.call('rea_replay_web_entry', dict(source=sources['before'], entry_index=index, body_length=65536))
                content = entry['response']['content']
                assert replay['network_requests'] == 0
                if 'text' in content:
                    assert replay['body']['recorded'] is True
                    assert bytes.fromhex(replay['body']['bytes_hex']) == content['text'].encode('utf-8')
                    assert replay['body']['har_encoding'] == content.get('encoding')
                else:
                    assert replay['body']['recorded'] is False
                replays.append(replay)
            private_write(root / 'capture-replayed.json', replays)
        result['offline_replay_origin_observations'] = dict(network_counts)
        result['offline_replay_observed_origins'] = [receipt['loopback']['origin'], receipt['loopback']['negative_probe_origin']]
        result['offline_replay_observation_scope'] = 'accepted connections and all HTTP methods at these two owned origins only'
        result['checks'].extend(['same_origin_before_after_has_two_true_response_changes',
                                 'mcp_restart_same_job_same_har_sha_without_browser_restart',
                                 'saved_representation_replay_exact_bytes_and_zero_requests_to_live_sentinels'])
        changed = dict(original, timeout_seconds=99)
        assert server.raw('process_start', changed).get('isError') is True
        changed_source = root / 'changed.har'
        private_write(changed_source, Path(sources['before']['path']).read_bytes() + b' ')
        assert server.raw('rea_inspect_web_capture', dict(path=str(changed_source), expected_sha256=sources['before']['sha256'])).get('isError') is True
        result['checks'].append('changed_original_request_and_saved_har_identity_refused')
        slow_manifest, slow_output = fixture(root, 'cancel-fixture', slow=True)
        cancellation = request(slow_manifest, slow_output, 'owned-browser-cancel')
        private_write(root / 'cancel-request.json', cancellation)
        cancel_admission = server.call('process_start', cancellation)
        cancel_job = cancel_admission['job']['id']; active.append(cancel_job)
        started = browser_start(server, cancel_job)
        if args.native_capture:
            observed = original_browser_identity(started, result['browser_installation'])
            result['original_browser_identity'] = observed
            private_write(root / 'capture-original-browser-identity.json', observed)
            assert observed['exec_environment_verified'] is False
            result['checks'].append('uninstrumented_original_chrome_executable_and_private_directories_verified')
        before_cancel = server.call('process_status', dict(host='local', job_id=cancel_job))
        assert before_cancel.get('state') not in ('succeeded', 'failed', 'cancelled', 'timed_out'), before_cancel
        cancel = server.call('process_cancel', dict(host='local', job_id=cancel_job, grace_seconds=10))
        stopped = terminal(server, cancel_job)
        active.remove(cancel_job)
        assert stopped['state'] in ('cancelled', 'failed') and stopped['exit_code'] != 0, stopped
        no_owned_browser(started['profile'], started['browser_pgid'])
        assert not slow_output.exists()
        old_cancelled = server.call('process_start', cancellation)
        assert old_cancelled['reused'] is True and old_cancelled['job']['id'] == cancel_job
        cancelled_logs = original_output(server, cancel_job)
        assert sum(json.loads(line).get('phase') == 'browser_started' for line in cancelled_logs['stdout'].splitlines()) == 1
        private_write(root / 'capture-cancelled.json', dict(admission=cancel_admission, browser=started,
            cancel=cancel, terminal=stopped, output=cancelled_logs))
        result.update(cancel_job_id=cancel_job, cancel_terminal=stopped['state'])
        result['checks'].append('original_job_cancel_confirmed_and_no_owned_browser_profile_or_relaunch')
        if args.native_capture:
            env_manifest, env_output = fixture(root, 'environment-fixture', slow=True)
            env_request = request(env_manifest, env_output, 'owned-browser-environment')
            env_request['env'] = dict(LD_PRELOAD=str(environment_observer.library))
            private_write(root / 'environment-request.json', env_request)
            env_admission = server.call('process_start', env_request)
            env_job = env_admission['job']['id']; active.append(env_job)
            env_started = browser_start(server, env_job)
            env_identity = original_browser_identity(
                env_started, result['browser_installation'], environment_observer)
            assert env_identity['exec_environment_verified'] is True
            private_write(root / 'environment-original-browser-identity.json', env_identity)
            env_cancel = server.call('process_cancel', dict(host='local', job_id=env_job, grace_seconds=10))
            env_stopped = terminal(server, env_job)
            active.remove(env_job)
            assert env_stopped['state'] in ('cancelled', 'failed') and env_stopped['exit_code'] != 0
            no_owned_browser(env_started['profile'], env_started['browser_pgid'])
            assert not env_output.exists()
            env_reused = server.call('process_start', env_request)
            assert env_reused['reused'] is True and env_reused['job']['id'] == env_job
            env_logs = original_output(server, env_job)
            assert sum(json.loads(line).get('phase') == 'browser_started'
                       for line in env_logs['stdout'].splitlines()) == 1
            private_write(root / 'environment-cancelled.json', dict(
                admission=env_admission, browser=env_started, cancel=env_cancel,
                terminal=env_stopped, output=env_logs, identity=env_identity))
            environment_observer.verify_closure()
            result['environment_observation'] = dict(
                uninstrumented_capture_job_id=job, uninstrumented_cancel_job_id=cancel_job,
                instrumented_environment_job_id=env_job, instrumented_identity=env_identity,
                uninstrumented_environment_qualified=False,
                instrumented_exec_environment_qualified=True,
                no_claim_about_current_getenv_after_constructor=True,
                original_proc_failure_reclassified=False)
            result['checks'].append(
                'separate_instrumented_original_chrome_exec_four_private_keys_and_cancel_cleanup')
        assert {str(path): digest(path) for path in source_files} == source_pins
        assert digest(runtime) == result['runtime_sha256']
        if args.native_capture:
            assert installed_chrome_identity() == result['browser_installation']
        if python is not None: assert python_identity(python)[1] == interpreter_pin
        result['qualified'] = True
    except BaseException as error:
        result['failure'] = repr(error)
        raise
    finally:
        if server is not None:
            for job in active:
                try:
                    status = server.call('process_status', dict(host='local', job_id=job))
                    if status.get('state') not in ('succeeded', 'failed', 'cancelled', 'timed_out'):
                        server.call('process_cancel', dict(host='local', job_id=job, grace_seconds=10))
                        terminal(server, job)
                except Exception as error:
                    result.setdefault('cleanup_unknown', []).append(dict(job_id=job, error=repr(error)))
            try: server.close()
            except Exception as error:
                result['qualified'] = False
                result.setdefault('cleanup_unknown', []).append(dict(controller_close_error=repr(error)))
        private_write(root / 'qualification.json', result)
        print(json.dumps(result, indent=2), flush=True)


if __name__ == '__main__':
    main()

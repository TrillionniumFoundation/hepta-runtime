"""Run the frozen public FS inputs through actual native executables first.

This producer has no Rust executable or original-response input. The observed
layer uses the private, two-session carrier around the production HIA frontend
and publisher. A separate ordinary-stdio layer covers every one-session
scenario, including real pipe closure. Neither layer substitutes for the other.
The same owned absolute paths are reset before the later unchanged Rust replay.
"""
from pathlib import Path
import argparse
import importlib.util
import json
import os
import signal
import stat
import subprocess
import sys
import time
import traceback
sys.dont_write_bytecode = True

FROZEN_READER = {'bytes': 63637, 'sha256': 'cbf0848f546425a0b825ac7dbe9741e891e7c78b7c932a5b6e7ce602443e3c4d'}


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value


def main():
    parser = argparse.ArgumentParser()
    for name in ('reference-source', 'reference-reader', 'native-source', 'native-build-result', 'fixture-build', 'public-build',
                 'fixture-binary', 'public-binary', 'output', 'strace'):
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    for name, value in vars(args).items(): setattr(args, name, value.absolute())
    here = Path(__file__).absolute().parent
    common = load(here / 'capture_common.py', '_filesystem_sdk_native_common')
    carrier = load(here / 'capture_fixture.py', '_filesystem_sdk_native_carrier')
    started = time.monotonic(); started_ns = time.monotonic_ns(); os.umask(0o077)
    args.output.mkdir(mode=0o700)
    common.dump(args.output / 'remote-process.json', {'pid': os.getpid(), 'cgroup': Path('/proc/self/cgroup').read_text(), 'argv': sys.argv})
    tracer = common.capture_tool(args.strace, args.output, 'strace')
    command = [str(args.strace), '-V']; environment = {'PATH': '', 'LC_ALL': 'C'}
    begin = time.monotonic(); timed_out = False; process = None; start_error = None
    out, err = args.output/'strace-version.stdout', args.output/'strace-version.stderr'
    try:
        with out.open('xb') as stdout, err.open('xb') as stderr:
            try: process = subprocess.Popen(command, cwd=here, env=environment, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, start_new_session=True)
            except BaseException as error: start_error = repr(error); raise
            try: process.wait(timeout=180)
            except subprocess.TimeoutExpired:
                timed_out = True; os.killpg(process.pid, signal.SIGKILL); process.wait()
    finally:
        common.dump(args.output/'tool-processes.json', [{'name': 'strace-version', 'command': command, 'cwd': str(here),
            'environment': environment, 'pid': None if process is None else process.pid, 'exit_code': None if process is None else process.returncode,
            'timeout_seconds': 180, 'timed_out': timed_out, 'start_error': start_error, 'elapsed_seconds': time.monotonic()-begin,
            'stdin': None, 'stdout': {'path': str(out), **common.file_pin(out)}, 'stderr': {'path': str(err), **common.file_pin(err)}}])
    common.need(start_error is None and not timed_out and process.returncode == 0 and out.read_bytes().startswith(b'strace -- version ') and not err.read_bytes(), 'actual selected tracer version process')
    reader_pin = common.file_pin(args.reference_reader)
    common.need(reader_pin == FROZEN_READER, 'frozen input-source reader')
    reference = load(args.reference_reader, '_filesystem_sdk_native_input_source')
    original_source = reference.Binder(args.reference_source)
    for name, (size, digest) in reference.SOURCES.items(): original_source.file(name, {'bytes': size, 'sha256': digest})
    cases = load(original_source.file('cases.py'), '_filesystem_sdk_native_cases')
    fixture = common.OwnedFixture(args.output / 'fixtures', create=True)
    corpus = cases.materialized(fixture.root)
    common.need(corpus['counts'] == {'groups': 12, 'scenarios': 28, 'steps': 332, 'public_calls': 323, 'private_controls': 9}, 'frozen complete native input domains')
    common.dump(args.output / 'INPUTS.json', corpus)
    driver_names = ('native_capture.py', 'capture_common.py', 'capture_fixture.py')
    driver_pins = {name: common.file_pin(here / name) for name in driver_names}
    binary_pins = {kind: {'path': str(getattr(args, kind + '_binary')), **common.file_pin(getattr(args, kind + '_binary'))}
                   for kind in ('fixture', 'public')}
    build_result_raw = args.native_build_result.read_bytes()
    build_result = reference.strict_json(build_result_raw)
    native_source_files = build_result['source_binding']['files']
    common.need(type(native_source_files) is dict and native_source_files, 'complete declared graph source table')
    for name, pin in native_source_files.items():
        relative = Path(name)
        common.need(not relative.is_absolute() and '..' not in relative.parts, 'declared graph source path escape')
        common.need(common.file_pin(args.native_source / relative) == pin, 'native graph source bytes: ' + name)
    (args.output / 'build-result.json').write_bytes(build_result_raw)
    builds = {}
    for kind in ('fixture', 'public'):
        path = getattr(args, kind + '_build'); raw = path.read_bytes()
        common.need(type(json.loads(raw)) is dict, 'actual native build manifest object')
        (args.output / (kind + '-build.json')).write_bytes(raw)
        builds[kind] = {'path': str(path), **common.file_pin(path)}
        declared = build_result['executables'][kind]
        common.need(declared['manifest'] == str(path) and declared['manifest_sha256'] == builds[kind]['sha256'], 'actual build manifest binding: ' + kind)
        common.need(declared['elf'] == binary_pins[kind]['path'] and declared['elf_bytes'] == binary_pins[kind]['bytes'] and
                    declared['elf_sha256'] == binary_pins[kind]['sha256'], 'actual built ELF binding: ' + kind)
    # The independent admission binds all child manifests, compiler receipts,
    # boundaries and source bytes. This capture only records their actual roots.
    common.dump(args.output / 'SOURCE.json', {'schema': 'hepta.runtime.filesystem-sdk-native-source.v1',
        'reference_source_root': str(args.reference_source), 'reference_source_files': original_source.artifacts,
        'reference_reader': {'path': str(args.reference_reader), **reader_pin}, 'driver_source_root': str(here),
        'driver_sources': driver_pins, 'native_source_root': str(args.native_source), 'native_source_files': native_source_files,
        'build_result': {'path': str(args.native_build_result), **common.file_pin(args.native_build_result)}, 'builds': builds,
        'binaries': binary_pins, 'strace': tracer,
        'original_response_inputs': [], 'original_executions': 0})
    common.dump(args.output / 'HOST.json', {'uid': os.getuid(), 'euid': os.geteuid(), 'gid': os.getgid(), 'egid': os.getegid(),
        'uname': list(os.uname()), 'status': Path('/proc/self/status').read_text(), 'cwd': os.getcwd(),
        'fixture_identity': list(fixture.identity), 'monotonic_started_ns': started_ns,
        'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip()})
    common.dump(args.output / 'COMMON-SETUP.json', fixture.actions(corpus['common_setup']))
    scenes = [scene for group in corpus['groups'] for scene in group['scenarios']]
    processes = []; scenarios = []; completed = []; active = []

    def descriptors(session):
        """Read only the exact child of this owned strace process."""
        wrapper = session.process.pid
        try:
            children = Path('/proc/%d/task/%d/children' % (wrapper, wrapper)).read_text().split()
        except FileNotFoundError:
            children = []
        common.need(all(value.isdecimal() for value in children) and len(children) <= 1, 'owned strace child identity')
        if not children:
            return {'wrapper_pid': wrapper, 'child_pid': None, 'entries': [], 'process_exited': session.process.poll() is not None}
        child = int(children[0]); entries = []
        try:
            names = sorted(Path('/proc/%d/fd' % child).iterdir(), key=lambda path: int(path.name))
        except FileNotFoundError:
            return {'wrapper_pid': wrapper, 'child_pid': child, 'entries': [], 'process_exited': True}
        for path in names:
            try:
                target = os.readlink(os.fsencode(path)); metadata = path.stat()
            except FileNotFoundError:
                return {'wrapper_pid': wrapper, 'child_pid': child, 'entries': [], 'process_exited': True}
            entries.append({'fd': int(path.name), 'target_hex': os.fsencode(target).hex(),
                            'device': metadata.st_dev, 'inode': metadata.st_ino, 'mode': metadata.st_mode})
        return {'wrapper_pid': wrapper, 'child_pid': child, 'entries': entries, 'process_exited': False}

    def reset(scene, directory):
        before = fixture.snapshot(scene['observed_roots']); removed = []
        for raw in scene['observed_roots']: removed.extend(fixture.remove_tree(common.bytes_path(raw)))
        after = fixture.snapshot(scene['observed_roots'])
        common.dump(directory / 'reset.json', {'before': before, 'removed': removed, 'after': after,
            'scope': 'only this scenario owned fixture roots; earlier native processes have terminated'})
        common.dump(directory / 'setup.json', fixture.actions(scene['setup']))
        roots = {session['root_hex'] for session in scene['sessions']}
        common.need(len(roots) == 1, 'declared sessions share the actual process cwd')
        cwd = fixture.owned(common.bytes_path(next(iter(roots))))
        common.need(cwd.is_dir() and not cwd.is_symlink(), 'declared native cwd was actually created')
        policy = corpus['policies'][scene['policy_id']]
        policy_path = directory / 'policy.json'; common.dump(policy_path, policy)
        return cwd, None if policy is None else policy_path

    def save_record(stream, row):
        raw = common.canonical(row); stream.write(raw); stream.flush()

    def all_states(session, selectors):
        result = {}
        for identifier, index in selectors.items():
            exchange, body, _, _ = session.observe(index)
            result[identifier] = {'exchange': exchange['index'], 'body': exchange['body'],
                                  'projection': carrier.state_projection(body)}
        return result

    def record_process(layer, scenario_id, session, failed=False):
        receipt = session.close(failed=failed)
        row = {'layer': layer, 'scenario_id': scenario_id,
               'path': str(session.output.relative_to(args.output)), 'receipt': receipt}
        processes.append(row); (args.output / 'processes.json').write_bytes(common.canonical(processes))
        active.remove(session)
        return row

    def observed(scene):
        directory = args.output / 'observed' / ('scenario-%03d' % scene['scenario_id']); directory.mkdir(mode=0o700, parents=True)
        cwd, config = reset(scene, directory)
        session = carrier.RecordedFixtureProcess(directory / 'process', args.fixture_binary, cwd,
            strace=args.strace, config=config, fence=corpus['fence_environments'][scene['fence_id']])
        active.append(session); selectors = {item['id']: index for index, item in enumerate(scene['sessions'])}
        common.need(len(selectors) == len(scene['sessions']) and 1 <= len(selectors) <= 2, 'complete native session selectors')
        row_count = 0
        with (directory / 'records.jsonl').open('xb') as records:
            handshakes = []
            for item in scene['sessions']:
                exchanges = []
                for message in item['initial_messages']:
                    exchange, _ = session.public(selectors[item['id']], common.wire({'kind': 'public', 'message': message}))
                    exchanges.append(exchange['index'])
                handshakes.append({'session': item['id'], 'exchanges': exchanges})
            state = all_states(session, selectors)
            save_record(records, {'kind': 'scenario_start', 'scenario_id': scene['scenario_id'], 'layer': 'observed',
                'name': scene['name'], 'policy_id': scene['policy_id'], 'fence_id': scene['fence_id'],
                'selectors': selectors, 'handshakes': handshakes, 'states': state,
                'filesystem': fixture.snapshot(scene['observed_roots']), 'fds': descriptors(session)})
            row_count += 1
            for step in scene['steps']:
                before = all_states(session, selectors); before_tree = fixture.snapshot(scene['observed_roots']); before_fds = descriptors(session)
                action = step['action']; index = selectors[step['session']]
                if action['kind'] == 'public':
                    exchange, _ = session.public(index, common.wire(action))
                    result = {'kind': 'actual_frontend_publisher', 'exchange': exchange['index'],
                              'mode': exchange['header']['mode'], 'closed': exchange['header']['closed'],
                              'public_stdio_transport': False}
                elif action['kind'] == 'cache_seed':
                    exchange, _ = session.seed(index, action['entries'])
                    result = {'kind': 'actual_scope_cache_seed', 'exchange': exchange['index']}
                elif action['kind'] == 'filesystem':
                    result = {'kind': 'private_owned_fixture_actions', 'actions': fixture.actions(action['actions'])}
                else:
                    raise ValueError('undeclared frozen native action ' + str(action['kind']))
                after = all_states(session, selectors)
                save_record(records, {'kind': 'case', 'scenario_id': scene['scenario_id'], 'case_id': step['case_id'],
                    'name': step['name'], 'domain': step['domain'], 'session': step['session'], 'result': result,
                    'states_before': before, 'states_after': after, 'filesystem_before': before_tree,
                    'filesystem_after': fixture.snapshot(scene['observed_roots']),
                    'fds_before': before_fds, 'fds_after': descriptors(session)})
                completed.append(step['case_id']); row_count += 1
            save_record(records, {'kind': 'scenario_end', 'scenario_id': scene['scenario_id'],
                'states': all_states(session, selectors), 'filesystem': fixture.snapshot(scene['observed_roots']),
                'fds': descriptors(session)})
            row_count += 1
        record_process('observed', scene['scenario_id'], session)
        scenarios.append({'layer': 'observed', 'scenario_id': scene['scenario_id'], 'directory': str(directory.relative_to(args.output)),
                          'records': row_count, 'sessions_in_frozen_inputs': len(selectors), 'actual_allocated_sessions': 2,
                          'steps': len(scene['steps'])})

    def public_stdio(scene):
        common.need(len(scene['sessions']) == 1, 'ordinary transport has one actual native session')
        directory = args.output / 'public' / ('scenario-%03d' % scene['scenario_id']); directory.mkdir(mode=0o700, parents=True)
        cwd, config = reset(scene, directory)
        session = common.RecordedPublicProcess(directory / 'process', args.public_binary, cwd,
            strace=args.strace, config=config, fence=corpus['fence_environments'][scene['fence_id']])
        active.append(session); item = scene['sessions'][0]; row_count = 0
        with (directory / 'records.jsonl').open('xb') as records:
            exchanges = []
            for message in item['initial_messages']:
                exchange, _ = session.exchange(common.wire({'kind': 'public', 'message': message}), response_count=int('id' in message))
                exchanges.append(exchange['index'])
            save_record(records, {'kind': 'scenario_start', 'scenario_id': scene['scenario_id'], 'layer': 'public',
                'name': scene['name'], 'policy_id': scene['policy_id'], 'fence_id': scene['fence_id'],
                'session': item['id'], 'handshakes': exchanges,
                'filesystem': fixture.snapshot(scene['observed_roots']), 'fds': descriptors(session)})
            row_count += 1
            for step in scene['steps']:
                common.need(step['session'] == item['id'], 'ordinary native session routing')
                action = step['action']; before_tree = fixture.snapshot(scene['observed_roots']); before_fds = descriptors(session)
                if action['kind'] == 'public':
                    request = common.wire(action); parsed = json.loads(request)
                    exchange, _ = session.exchange(request, response_count=int('id' in parsed))
                    result = {'kind': 'actual_public_stdio', 'exchange': exchange['index'], 'transport': exchange['transport']}
                elif action['kind'] == 'filesystem':
                    result = {'kind': 'private_owned_fixture_actions', 'actions': fixture.actions(action['actions'])}
                else:
                    raise ValueError('ordinary public transport cannot inject private cache state')
                save_record(records, {'kind': 'case', 'scenario_id': scene['scenario_id'], 'case_id': step['case_id'],
                    'name': step['name'], 'domain': step['domain'], 'session': step['session'], 'result': result,
                    'filesystem_before': before_tree, 'filesystem_after': fixture.snapshot(scene['observed_roots']),
                    'fds_before': before_fds, 'fds_after': descriptors(session)})
                row_count += 1
            save_record(records, {'kind': 'scenario_end', 'scenario_id': scene['scenario_id'],
                'filesystem': fixture.snapshot(scene['observed_roots']), 'fds': descriptors(session)})
            row_count += 1
        record_process('public', scene['scenario_id'], session)
        scenarios.append({'layer': 'public', 'scenario_id': scene['scenario_id'], 'directory': str(directory.relative_to(args.output)),
                          'records': row_count, 'sessions_in_frozen_inputs': 1, 'actual_allocated_sessions': 1,
                          'steps': len(scene['steps'])})

    try:
        for scene in scenes:
            observed(scene)
            if len(scene['sessions']) == 1: public_stdio(scene)
            (args.output / 'SCENARIOS.json').write_bytes(common.canonical(scenarios))
        common.need(sorted(completed) == list(range(70000, 70332)), 'actual complete native attempt coverage')
        common.need(not active, 'native process ownership remains before original replay')
        common.need({name: common.file_pin(here / name) for name in driver_names} == driver_pins, 'native producer changed while running')
        for kind, info in binary_pins.items(): common.need({'path': info['path'], **common.file_pin(info['path'])} == info, 'executed native binary changed')
        for kind, info in builds.items(): common.need({'path': info['path'], **common.file_pin(info['path'])} == info, 'bound build manifest changed')
        common.need(args.native_build_result.read_bytes() == build_result_raw, 'actual build result changed')
        common.need({name: common.file_pin(args.native_source / name) for name in native_source_files} == native_source_files, 'native source graph changed while running')
        common.need({name: common.file_pin(args.reference_source / name) for name in reference.SOURCES} == original_source.artifacts, 'frozen input source changed')
        common.check_tool(tracer)
        artifacts = {}
        # Do not stat live fixture links while inventorying evidence. Declared
        # inputs include looping/dangling symlinks and FIFOs.
        for parent, directories, files in os.walk(args.output, topdown=True, followlinks=False):
            parent = Path(parent)
            directories[:] = sorted(name for name in directories if parent / name != fixture.root)
            for name in directories:
                common.need(not (parent / name).is_symlink(), 'evidence directory symlink')
            for name in sorted(files):
                path = parent / name
                common.need(stat.S_ISREG(path.lstat().st_mode), 'evidence file is not an owned regular file')
                artifacts[str(path.relative_to(args.output))] = common.file_pin(path)
        ordinary = [scene for scene in scenes if len(scene['sessions']) == 1]
        report = {'schema': 'hepta.runtime.filesystem-sdk-native-capture.v1', 'status': 'NATIVE_EXECUTION_COMPLETE',
            'counts': corpus['counts'], 'fixture_root': str(fixture.root), 'completed_case_ids': completed,
            'original_replayed': False, 'original_comparison_complete': False, 'all_processes_terminated': True,
            'observed_layer': {'scenarios': len(scenes), 'public_attempts': 323, 'private_controls': 9,
                'actual_allocated_sessions': 2 * len(scenes),
                'same_process_two_session_scenarios': [scene['scenario_id'] for scene in scenes if len(scene['sessions']) == 2],
                'private_session_selector': True, 'actual_public_frontend_and_publisher': True,
                'mode3_is_os_broken_pipe': False},
            'public_stdio_layer': {'scenarios': len(ordinary), 'public_attempts': sum(step['action']['kind'] == 'public' for scene in ordinary for step in scene['steps']),
                'private_fixture_actions': sum(step['action']['kind'] == 'filesystem' for scene in ordinary for step in scene['steps']),
                'excludes_two_session_cache_injection': True},
            'actual_native_processes': len(processes), 'actual_tool_version_processes': 1, 'new_rust_processes': 0, 'fresh_compiles': 0,
            'monotonic_started_ns': started_ns, 'monotonic_finished_ns': time.monotonic_ns(), 'elapsed_seconds': time.monotonic() - started,
            'artifacts': artifacts, 'semantic_parity_status': 'NOT_RUN'}
        common.dump(args.output / 'NATIVE.json', report)
        print(json.dumps({key: value for key, value in report.items() if key not in ('artifacts', 'completed_case_ids')}, sort_keys=True), flush=True)
    except BaseException:
        failure = traceback.format_exc(); cleanup = []
        for session in list(active):
            try:
                cleanup.append({'path': str(session.output.relative_to(args.output)), 'receipt': session.close(failed=True)})
            except BaseException:
                cleanup.append({'path': str(session.output.relative_to(args.output)), 'error': traceback.format_exc()})
        common.dump(args.output / 'FAILURE.json', {'traceback': failure, 'cleanup': cleanup, 'completed_case_ids': completed,
            'actual_terminated_processes': len(processes), 'elapsed_seconds': time.monotonic() - started})
        raise


if __name__ == '__main__': main()

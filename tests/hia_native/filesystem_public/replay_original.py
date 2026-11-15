"""Fresh unchanged Rust replay after a completed native capture.

The frozen reference v3 is read-only. Every scenario reuses the exact native
absolute fixture paths and cwd after an observed owned-tree reset. This module
executes the original; it never manufactures an expected tool response.
"""
from pathlib import Path
import argparse
import gzip
import hashlib
import importlib.util
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import traceback
sys.dont_write_bytecode = True


def local_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path); result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result); return result


def main():
    p = argparse.ArgumentParser()
    for name in ('reference-source', 'reference-reader', 'native-capture', 'native-admission', 'output', 'cargo', 'rustc', 'strace'):
        p.add_argument('--'+name, type=Path, required=True)
    a = p.parse_args()
    for key, value in vars(a).items(): setattr(a, key, value.absolute())
    here = Path(__file__).absolute().parent; common = local_module(here/'capture_common.py', '_filesystem_sdk_capture_common')
    a.output.mkdir(mode=0o700); os.umask(0o077); started = time.monotonic(); started_ns = time.monotonic_ns(); processes = []
    common.dump(a.output/'remote-process.json', {'pid': os.getpid(), 'cgroup': Path('/proc/self/cgroup').read_text(), 'argv': sys.argv})
    driver_sources = {name: common.file_pin(here/name) for name in ('capture_common.py', 'replay_original.py', 'strict_original.py')}
    reader_pin = common.file_pin(a.reference_reader)
    common.need(reader_pin == {'bytes': 63585, 'sha256': '98a52accc1b5c740221effde1895535a9cb9c2d719bad0f46d4f9fc02d2906ca'}, 'frozen original reference reader identity')
    q = local_module(a.reference_reader, '_frozen_filesystem_sdk_reference')
    admission_reader = local_module(here/'strict_original.py', '_filesystem_sdk_followup_portable_reader')
    binder = q.Binder(a.reference_source)
    for name, (size, digest) in q.SOURCES.items(): binder.file(name, {'bytes': size, 'sha256': digest})
    factory = local_module(binder.file('oracle/verify_sources.py'), '_frozen_filesystem_sdk_assembler')
    cases = local_module(binder.file('cases.py'), '_frozen_filesystem_sdk_input_generator')
    native_manifest_path = a.native_capture/'NATIVE.json'
    native_inputs_path = a.native_capture/'INPUTS.json'; native_manifest = q.strict_json(native_manifest_path.read_bytes())
    q.same(native_manifest.get('schema'), 'hepta.runtime.filesystem-sdk-native-capture.v1', 'native producer schema')
    q.same(native_manifest.get('status'), 'NATIVE_EXECUTION_COMPLETE', 'native must execute before original replay')
    q.same(native_manifest.get('original_replayed'), False, 'native producer depended on original result')
    fixture_root = Path(native_manifest['fixture_root'])
    admission_reader.absolute(q,str(fixture_root),'owned native fixture origin')
    common.need(fixture_root.name == 'fixtures', 'owned native fixture layout')
    inputs = cases.materialized(fixture_root); q.same(q.strict_json(native_inputs_path.read_bytes()), inputs, 'complete frozen input regeneration')
    q.same(native_manifest['counts'], inputs['counts'], 'complete native input-domain count')
    q.same(sorted(native_manifest['completed_case_ids']), list(range(70000, 70332)), 'all native cases before original')
    common.need(native_manifest['all_processes_terminated'] is True, 'native processes still own fixture')
    native_finished = q.uint(native_manifest['monotonic_finished_ns'], 'native completion time')
    native_host = q.strict_json((a.native_capture/'HOST.json').read_bytes())
    boot_id = admission_reader.boot_evidence(q,Path('/proc/sys/kernel/random/boot_id').read_text().strip())
    native_boot = admission_reader.boot_evidence(q,native_host['boot_id'])
    common.need(native_finished > 0 and (native_boot != boot_id or native_finished < started_ns), 'same-boot native completion before original execution')
    before_native = {name: common.file_pin(q.inside(a.native_capture,name)) for name in ('NATIVE.json', *sorted(native_manifest['artifacts']))}
    for name,pin in native_manifest['artifacts'].items(): q.same(before_native[name],pin,'complete native predecessor artifact '+name)
    admitted_raw = a.native_admission.read_bytes(); admitted = q.strict_json(admitted_raw)
    q.same(admitted.get('schema'),'hepta.runtime.filesystem-sdk-native-evidence.v1','native predecessor admission schema')
    common.need(admitted.get('status') == 'PASS' and admitted.get('native_execution_complete') is True and
        admitted.get('original_comparison_complete') is False and admitted.get('original_capture_read') is False,
        'complete native-only admission required before fresh original replay')
    q.same(admitted['fixture_origin'],str(fixture_root),'admitted fixture origin')
    expected_native = {'native-capture/'+name:pin['sha256'] for name,pin in before_native.items()}
    q.same({name:pin for name,pin in admitted['artifact_sha256'].items() if name.startswith('native-capture/')},expected_native,'all native predecessor streams/source/build-input hashes')
    for name,pin in admitted['admission_source_files'].items(): q.same(common.file_pin(q.inside(here,name)),pin,'native admission source identity before replay')
    with (a.output/'NATIVE-ADMISSION.json').open('xb') as stream: stream.write(admitted_raw)
    native_admission_pin = {'path':str(a.native_admission),**common.file_pin(a.native_admission)}
    fixture = common.OwnedFixture(fixture_root)
    tools_before = {name: common.capture_tool(path,a.output,name) for name,path in
        (('rustc',a.rustc),('cargo',a.cargo),('strace',a.strace))}
    common.dump(a.output/'HOST.json', {'uid': os.getuid(), 'euid': os.geteuid(), 'gid': os.getgid(), 'egid': os.getegid(),
        'uname': list(os.uname()), 'status': Path('/proc/self/status').read_text(), 'cwd': os.getcwd(),
        'USER': os.environ.get('USER'), 'fixture_identity': list(fixture.identity), 'monotonic_started_ns': started_ns,'boot_id':boot_id})
    common.dump(a.output/'INPUTS.json', inputs)
    common.dump(a.output/'SOURCE.json', {'schema': 'hepta.runtime.filesystem-sdk-followup-original-source.v1',
        'reference_source_root': str(a.reference_source), 'source_files': binder.artifacts, 'reference_reader': {'path': str(a.reference_reader), **reader_pin},
        'driver_source_root': str(here), 'driver_sources': driver_sources, 'tool_executables': tools_before,
        'native_capture_root': str(fixture_root.parent), 'native_capture_read_root':str(a.native_capture), 'native_predecessor': before_native,
        'native_admission':native_admission_pin,'native_admission_artifact_sha256':admitted['artifact_sha256'],
        'native_admission_is_separate': True, 'original_sources_unchanged': True})

    def record(name, command, cwd, stdin=None, fence=None):
        out, err = a.output/(name+'.stdout'), a.output/(name+'.stderr'); env = dict(os.environ)
        controls = {'RUSTC': str(a.rustc), 'CARGO_TARGET_DIR': str(a.output/'target'), 'CARGO_BUILD_JOBS': '2',
            'PATH': str(a.rustc.parent)+os.pathsep+os.environ.get('PATH', ''), 'LC_ALL': 'C', **dict.fromkeys(common.FENCE_KEYS), **(fence or {})}
        for key, value in controls.items():
            if value is None: env.pop(key, None)
            else: env[key] = value
        begin = time.monotonic(); timed_out = False; process = None; startup_error = None
        incoming = stdin.open('rb') if stdin is not None else subprocess.DEVNULL
        try:
            with out.open('xb') as stdout, err.open('xb') as stderr:
                try: process = subprocess.Popen(command, cwd=cwd, stdin=incoming, stdout=stdout, stderr=stderr, env=env, start_new_session=True)
                except BaseException as error: startup_error = repr(error); raise
                try: process.wait(timeout=180)
                except subprocess.TimeoutExpired: timed_out = True; os.killpg(process.pid, signal.SIGKILL); process.wait()
        finally:
            if stdin is not None: incoming.close()
            receipt = {'name': name, 'command': command, 'cwd': os.fsdecode(os.fsencode(cwd)), 'controlled_env': controls,
                'pid': None if process is None else process.pid, 'exit_code': None if process is None else process.returncode,
                'start_error': startup_error, 'timeout_seconds': 180, 'timed_out': timed_out, 'elapsed_seconds': time.monotonic()-begin,
                'stdin': None if stdin is None else {'path': str(stdin), **common.file_pin(stdin)},
                'stdout': {'path': str(out), **common.file_pin(out)}, 'stderr': {'path': str(err), **common.file_pin(err)}}
            processes.append(receipt); (a.output/'processes.json').write_bytes(common.canonical(processes))
        common.need(startup_error is None and not timed_out and process.returncode == 0, 'actual original process failure: '+name)
        return out.read_bytes()

    try:
        materialized, proof = factory.assemble(a.reference_source/'oracle'); crate = a.output/'crate'
        for name, raw in materialized.items():
            path = crate/name; path.parent.mkdir(mode=0o700, parents=True, exist_ok=True); path.write_bytes(raw)
        common.dump(a.output/'ORIGINAL-SOURCE.json', proof)
        rustc = record('rustc-version', [str(a.rustc), '-Vv'], crate); cargo = record('cargo-version', [str(a.cargo), '-Vv'], crate)
        common.need(rustc.startswith(b'rustc 1.95.0 (59807616e 2026-04-14)\n') and b'host: x86_64-unknown-linux-gnu\n' in rustc, 'actual original Rust 1.95 toolchain')
        common.need(cargo.startswith(b'cargo 1.95.0 '), 'actual Cargo 1.95 toolchain')
        record('strace-version', [str(a.strace), '-V'], crate)
        record('locked-build', [str(a.cargo), 'build', '--release', '--locked', '--manifest-path', str(crate/'Cargo.toml')], crate)
        common.need((crate/'Cargo.lock').read_bytes() == materialized['Cargo.lock'], 'actual locked source changed')
        sysroot = admission_reader.compiler_sysroot(q,q.strict_json((a.output/'target/.rustc_info.json').read_bytes()),rustc)
        binary = a.output/'target/release/hepta-filesystem-sdk-original'; binary_pin = common.file_pin(binary)
        originals = []; totals = {}; common_setup = fixture.actions(inputs['common_setup'])
        common.dump(a.output/'COMMON-SETUP.json', common_setup)
        scenes = [scene for group in inputs['groups'] for scene in group['scenarios']]
        for scene in scenes:
            ident = 'scenario-%03d'%scene['scenario_id']; reset_before = fixture.snapshot(scene['observed_roots']); removal = []
            for raw in scene['observed_roots']: removal += fixture.remove_tree(common.bytes_path(raw))
            reset_after = fixture.snapshot(scene['observed_roots'])
            common.dump(a.output/(ident+'.reset.json'), {'before': reset_before, 'removed': removal, 'after': reset_after,
                'scope': 'only this scenario owned native fixture roots; native processes have terminated'})
            # The unchanged Rust scenario performs its own original setup. Cwd
            # must exist before exec; create only the exact declared session root.
            session_roots = {item['root_hex'] for item in scene['sessions']}
            common.need(len(session_roots) == 1, 'same-cwd reference requires declared common session root')
            cwd = fixture.owned(common.bytes_path(next(iter(session_roots)))); cwd.mkdir(mode=0o700, parents=True)
            input_path = a.output/(ident+'.input.jsonl'); policy_path = a.output/(ident+'.policy.json')
            input_path.write_bytes(cases.canonical(scene)); policy_path.write_bytes(cases.canonical(inputs['policies'][scene['policy_id']]))
            trace_path = a.output/(ident+'.strace')
            raw = record(ident, [str(a.strace), *common.TRACE_ARGS, '-o', str(trace_path), '--', str(binary), str(fixture_root), str(policy_path)],
                cwd, input_path, inputs['fence_environments'][scene['fence_id']])
            common.need(not (a.output/(ident+'.stderr')).read_bytes(), 'actual original replay stderr')
            rows = q.parse_output(raw); semantic = q.rows_evidence(rows, [scene], raw, inputs['policies'][scene['policy_id']] is not None)
            trace = q.trace_evidence(trace_path.read_bytes(), rows, raw, b'', fixture_root, binary, policy_path)
            q.same(trace['markers'], semantic['markers'], 'actual original complete marker binding')
            (a.output/(ident+'.observations.jsonl')).write_bytes(b''.join(common.canonical(row) for row in rows))
            common.dump(a.output/(ident+'.admission.json'), {'semantics': semantic, 'trace': trace})
            for suffix in ('input.jsonl', 'stdout', 'strace'):
                path = a.output/(ident+'.'+suffix)
                with path.open('rb') as source, (a.output/(path.name+'.gz')).open('xb') as target:
                    with gzip.GzipFile(filename='', fileobj=target, mode='wb', compresslevel=6, mtime=0) as packed: shutil.copyfileobj(source, packed)
            for key, value in semantic['counts'].items(): totals[key] = totals.get(key, 0)+value
            originals.append({'scenario_id': scene['scenario_id'], 'name': ident, 'cwd_hex': os.fsencode(cwd).hex(),
                'policy_id': scene['policy_id'], 'fence_id': scene['fence_id'], 'original_counts': semantic['counts'],
                'markers': semantic['markers'], 'complete_stdout': common.file_pin(a.output/(ident+'.stdout')), 'complete_trace': common.file_pin(trace_path)})
            (a.output/'SCENARIOS.json').write_bytes(common.canonical(originals))
        q.same({name: common.file_pin(a.reference_source/name) for name in q.SOURCES}, binder.artifacts, 'frozen reference source changed during actual replay')
        q.same({name: common.file_pin(a.native_capture/name) for name in before_native}, before_native, 'native captured inputs/proof changed during original replay')
        q.same(common.file_pin(binary), binary_pin, 'actual original ELF changed')
        q.same({name: common.file_pin(here/name) for name in driver_sources}, driver_sources, 'replay driver changed during execution')
        for tool in tools_before.values(): common.check_tool(tool)
        common.need(a.native_admission.read_bytes()==admitted_raw,'native admission changed during original replay')
        artifacts = {path.name: common.file_pin(path) for path in sorted(a.output.iterdir()) if path.is_file()}
        result = {'schema': 'hepta.runtime.filesystem-sdk-followup-original-capture.v1', 'status': 'ORIGINAL_EXECUTION_COMPLETE',
            'reference_source_root': str(a.reference_source), 'native_capture_root': str(fixture_root.parent),
            'native_capture_read_root':str(a.native_capture), 'fixture_root': str(fixture_root),
            'original_scenarios': len(originals), 'original_counts': totals, 'actual_processes': len(processes), 'fresh_locked_builds': 1,
            'version_processes': 3, 'actual_rust_replays': len(originals), 'elapsed_seconds': time.monotonic()-started,
            'monotonic_started_ns': started_ns, 'monotonic_finished_ns': time.monotonic_ns(),
            'all_paths_equal_to_native_inputs': True, 'response_path_string_substitutions': 0, 'native_comparison_executed': False,
            'native_producer_admission_is_separate': True, 'binary': {'path': str(binary), **binary_pin},
            'rustc_executable': tools_before['rustc'], 'cargo_executable': tools_before['cargo'],
            'strace_executable': tools_before['strace'], 'target_rustc_info': common.file_pin(a.output/'target/.rustc_info.json'),
            'compiler_sysroot':sysroot,'native_admission':native_admission_pin,
            'artifacts': artifacts, 'new_native_calls': 0}
        common.dump(a.output/'ORIGINAL.json', result); print(json.dumps({key: value for key, value in result.items() if key != 'artifacts'}, sort_keys=True))
    except BaseException:
        common.dump(a.output/'FAILURE.json', {'traceback': traceback.format_exc(), 'actual_processes': len(processes), 'elapsed_seconds': time.monotonic()-started}); raise


if __name__ == '__main__': main()

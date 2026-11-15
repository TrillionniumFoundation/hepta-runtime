#!/usr/bin/python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Run the unchanged fifteen Python CI gates once on a fresh qualified A53 copy.

The pinned A44 parent owns one worker session, GO pipe, pidfd and raw waitpid.
Test children stay in that session. Original qualification/source files are
read-only; all test files, temporary directories and logs belong to this attempt.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import sys
import types
import zlib

BASE = Path('/home/qian/hepta-runtime-optimization-20261023/a41-phase-timing-20261025-r01')
CORE = BASE / 'tools/prepare_qualify_a44_owner_barrier_r01.py'
CORE_SHA = '84e5fc48a688f83987425ff357428230083948703d419db4be1227d6b1ed8113'
BUNDLE = BASE / 'tools/a52-control-plane-gates-source-r01.json.gz'
QUALIFICATION = BASE / 'qualification-a53-bounded-direct-ssh-r02/report.json'
QUAL_ENTRY = BASE / 'a53-bounded-direct-ssh-entry-r02/entry-report.json'
QUAL_WORKER = BASE / 'a53-bounded-direct-ssh-entry-r02/worker-report.json'
SOURCE = BASE / 'source-a53-bounded-direct-ssh-r02'
OUT = BASE / 'a53-control-plane-gates-r01'
COPY = OUT / 'source'
FINAL_BINDINGS_READY = True
ACTUAL_QUALIFICATION_SHA256 = 'ab3a37ceb97667694c201d9b62556398e04e805010c8492af6a8f6f51486a72b'
ACTUAL_QUALIFICATION_ENTRY_SHA256 = '9f888ba1399bb23453e40ee6f8544b11584b8bfcc5c97245dedec40ece1fcc78'
ACTUAL_QUALIFICATION_WORKER_SHA256 = '9cf2c2e61b8257061954ddc410c71e61516b74081f16c4f68eb04d0fdbc5ebbc'
ACTUAL_RELEASE_SHA256 = '5855f6fb044745eba0bf0885b0430bc5a5bb03f68310cce50d961947925c03c6'
ACTUAL_TESTED_MAP_COMPACT_SHA256 = '91962e89b203621686cfa0d77567b13bd246092a99345681674bbafd46388c35'
PREPARED_MAP_COMPACT_SHA256 = 'e1c8b4afe2a3180438ccfde5b7c297ba397acf356f4092b6637e39a1ae0150b6'
SUPPLEMENT_SHA256 = '2011e4e7d08962c8cffdeffb80cde6a0994e65d281e25f02c884951869f0f4c0'
TESTS = (
    'tests/file_capabilities.py',
    'tests/runtime_registry_page_tests.py',
    'tests/chatgpt_v11_layered_read_tests.py',
    'tests/chatgpt_v11_process_start_concurrency_tests.py',
    'tests/chatgpt_v11_v4_session_binding_tests.py',
    'tests/runtime_workflow_owner_tests.py',
    'tests/chatgpt_v10_single_v4_effect_tests.py',
    'tests/chatgpt_v10_stream_custody_tests.py',
    'tests/test_computer_http.py',
    'tests/full_operator_facade_tests.py',
    'tests/full_operator_cancel_tests.py',
    'tests/chatgpt_request_identity_tests.py',
    'tests/full_operator_session_recovery_tests.py',
    'deploy/maintenance_20261017/native_rollout_tests.py',
    'deploy/maintenance_20261017/recover_control_channel_tests.py',
)
PRECHECK = ['-B', '-c', 'from jsonschema import Draft7Validator; import fcntl, sqlite3; '
            'print("control-plane Python dependencies available")']
COMMANDS = [['/usr/bin/python3', *PRECHECK]] + [
    ['/usr/bin/python3', *([] if index == 0 else ['-B']), name]
    for index, name in enumerate(TESTS)]


def need(value, message):
    if not value:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def require_bindings(args):
    need(FINAL_BINDINGS_READY is True, 'actual A53 qualification bindings pending; no fixture or worker admitted')
    for label, value in (('qualification', ACTUAL_QUALIFICATION_SHA256),
                         ('qualification entry', ACTUAL_QUALIFICATION_ENTRY_SHA256),
                         ('qualification worker', ACTUAL_QUALIFICATION_WORKER_SHA256),
                         ('release', ACTUAL_RELEASE_SHA256), ('tested source map', ACTUAL_TESTED_MAP_COMPACT_SHA256)):
        need(type(value) is str and re.fullmatch(r'[0-9a-f]{64}', value), 'actual A53 SHA missing: ' + label)
    need(args.qualification_sha == ACTUAL_QUALIFICATION_SHA256
         and args.qualification_entry_sha == ACTUAL_QUALIFICATION_ENTRY_SHA256
         and args.qualification_worker_sha == ACTUAL_QUALIFICATION_WORKER_SHA256
         and args.bundle_sha == SUPPLEMENT_SHA256, 'actual A53 qualification or original supplement differs')


def load_core():
    need(CORE.resolve(strict=True) == CORE, 'indirect guarded core refused')
    raw = CORE.read_bytes()
    need(len(raw) == 49453 and sha(raw) == CORE_SHA, 'pinned guarded core differs')
    core = types.ModuleType('a53_control_plane_guarded_core')
    core.__file__ = str(CORE)
    exec(compile(raw, str(CORE), 'exec'), core.__dict__)
    core.PREP = OUT
    return core


def supplement(core, expected):
    raw, receipt = core.original(BUNDLE, expected, 2 * 1024 * 1024)
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    plain = decoder.decompress(raw, 2 * 1024 * 1024)
    need(decoder.eof and not decoder.unconsumed_tail and not decoder.unused_data,
         'bounded single gzip member required')
    value = json.loads(plain)
    need(value['schema'] == 'hepta-a52-control-plane-gates-source/v1', 'supplement schema differs')
    manifest_raw = base64.b64decode(value['manifest_base64'], validate=True)
    need(sha(manifest_raw) == value['manifest_sha256'], 'original manifest SHA differs')
    manifest = json.loads(manifest_raw)
    need(manifest['source_commit'] == '17d01dda7bd75b9bb9c0c5f1f90f84bddbfb54cb'
         and manifest['all_bytes_equal_base_and_pr72'] is True
         and len(manifest['files']) == 43, 'reviewed supplement inventory differs')
    contents = {}
    for item in manifest['files']:
        name = item['path']; path = Path(name)
        need(str(path) == name and not path.is_absolute() and '..' not in path.parts
             and name not in contents, 'unsafe/duplicate supplement path')
        data = base64.b64decode(value['files'][name], validate=True)
        need(len(data) == item['bytes'] and sha(data) == item['sha256'], 'supplement bytes differ: ' + name)
        contents[name] = data
    need(set(contents) == set(value['files']) and sum(map(len, contents.values())) == 1005059,
         'supplement contents/count differs')
    command_raw = base64.b64decode(value['commands_base64'], validate=True)
    need(sha(command_raw) == value['commands_sha256'], 'original command list differs')
    original = [shlex.split(line) for line in command_raw.decode().splitlines() if line.startswith('python3 ')]
    need(original == [['python3', *command[1:]] for command in COMMANDS], 'original fifteen commands differ')
    workflow_raw = base64.b64decode(value['workflow_base64'], validate=True)
    need(sha(workflow_raw) == value['workflow_sha256'], 'reviewed workflow differs')
    workflow_lines = [line.strip().removeprefix('run: ') for line in workflow_raw.decode().splitlines()]
    workflow_commands = [shlex.split(line) for line in workflow_lines if line.startswith('/usr/bin/python3 ')]
    need(workflow_commands == COMMANDS[1:], 'CI workflow Python commands differ')
    return contents, receipt, {'manifest.original.json': manifest_raw,
            'run-after-rust.original.sh': command_raw, 'ci.original.yml': workflow_raw}


def qualification(core, native, args):
    qraw, qreceipt = core.original(QUALIFICATION, args.qualification_sha)
    eraw, ereceipt = core.original(QUAL_ENTRY, args.qualification_entry_sha)
    wraw, wreceipt = core.original(QUAL_WORKER, args.qualification_worker_sha)
    q, entry, worker = map(json.loads, (qraw, eraw, wraw))
    need(q['binary']['sha256'] == ACTUAL_RELEASE_SHA256
         and sha(json.dumps(q['source_tested'], sort_keys=True, separators=(',', ':')).encode()) == ACTUAL_TESTED_MAP_COMPACT_SHA256
         and sha(json.dumps(q['source_input'], sort_keys=True, separators=(',', ':')).encode()) == PREPARED_MAP_COMPACT_SHA256,
         'actual A53 release/tested/prepared source binding differs')
    need(entry['parent_and_input_fence_unchanged'] is True and entry['retained_parent_git_blobs_verified'] is True
         and entry['repository_base_commit'] == '06c18da77a3433a34773c0ed690833cd44db5715'
         and entry['repository_base_tree'] == 'ec46f79fd27948d98aa1ffd60fc2602a8684fb76',
         'actual A53 parent publication/source fence differs')
    need(q['schema'] == 'runtime-candidate-qualification/v1' and q['qualified'] is True
         and q['current_stage'] == 'complete' and not q.get('error') and q['source'] == str(SOURCE)
         and q['source_tested'] == q['source_after'] and len(q['source_tested']) == 175
         and set(q['source_input']) == set(q['source_tested']), 'actual A53 qualification incomplete')
    need(entry['schema'] == 'hepta-a53-bounded-direct-ssh-qualification-entry/v1'
         and entry['qualified'] is True and entry['errors'] == []
         and entry['candidate_source'] == str(SOURCE)
         and entry['candidate_source_map'] == q['source_input'], 'A53 qualification entry differs')
    need(worker['schema'] == 'hepta-a53-bounded-direct-ssh-qualification-worker/v1'
         and worker['passed'] is True and not worker.get('error')
         and worker['qualifier_report'] == qreceipt and worker['stage_umask'] == '022',
         'A53 qualification worker/report binding differs')
    custody = entry['worker_custody']; pid = custody['pid']
    need(type(pid) is int and pid > 1 and custody['actual_waitpid'] == pid
         and custody['raw_wait_status'] == custody['returncode'] == 0
         and custody['execution_count'] == 1 and custody['executed'] is True
         and custody['pidfd_opened'] is True and custody['original_child_reaped'] is True
         and custody['custody_known'] is True and custody['custody_unknown'] is False
         and custody['custody_retained_until_reap'] is True and custody['group_quiet_before_reap'] is True
         and custody['worker_permit_sent'] is True and custody['signals'] == []
         and not custody.get('outer_work_budget_exceeded') and not custody.get('error')
         and not custody.get('cleanup_errors'), 'A53 original qualification custody incomplete')
    initial, terminal = custody['original_identity'], custody['terminal_group_snapshot']
    terminal_original = [row for row in terminal['members'] if row['pid'] == pid]
    need(initial['pid'] == initial['pgrp'] == initial['session'] == pid
         and terminal['errors'] == [] and terminal['live'] == [] and len(terminal_original) == 1
         and terminal_original[0]['state'] in ('Z', 'X', 'x')
         and terminal_original[0]['start_ticks'] == initial['start_ticks']
         and terminal_original[0]['pgrp'] == terminal_original[0]['session'] == pid,
         'original qualification worker birth/session/quiet snapshot differs')
    need(len(q['stages']) == len(worker['stages']) == 6, 'six original qualification stages required')
    for qstage, wstage, (name, tail) in zip(q['stages'], worker['stages'], core.STAGES):
        argv = [core.CARGO, '+1.95.0', *tail]
        need(qstage['name'] == wstage['name'] == name and qstage['command'] == wstage['argv'] == argv
             and qstage['returncode'] == wstage['returncode'] == 0
             and wstage['executed'] is True and wstage['execution_count'] == 1
             and wstage['gate_clear'] is True, 'original successful qualification stage differs: ' + name)
    bound = native.load_qualification(QUALIFICATION, 'A53', OUT)
    need(bound['report'] == qreceipt and bound['source_files'] == 175, 'qualification changed during load')
    references = [qreceipt, ereceipt, wreceipt, bound['binary'], bound['test_binary'], *bound['logs'].values()]
    core.create(OUT / 'qualification-entry.original.json', eraw)
    core.create(OUT / 'qualification-worker.original.json', wraw)
    return bound, references


def environment(core):
    env, receipt = core.clean_environment()
    removed = sorted(key for key in env if key.startswith('HEPTA_'))
    for key in removed:
        env.pop(key, None)
    fixed = {'PATH': '/usr/bin:/bin', 'TMPDIR': str(OUT / 'tmp'),
             'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONNOUSERSITE': '1'}
    env.update(fixed)
    receipt['removed_names_only'] = sorted(set(receipt['removed_names_only']) | set(removed))
    receipt['fixed_values'].update(fixed)
    receipt.update(stage_umask='022', metadata_trace_enabled=False)
    return env, receipt


def fence(core, native, inputs):
    original_map, original_receipts, _ = core.source(SOURCE)
    copy_map, copy_receipts, _ = core.source(COPY)
    need(original_map == inputs['qualified']['source_map']
         and original_receipts == inputs['source_receipts'], 'original qualified source changed')
    need(copy_map == inputs['copy_map'] and copy_receipts == inputs['copy_receipts'], 'test source copy changed')
    for reference in inputs['original_inputs']:
        # Qualified artifacts also retain compiler evidence; compare every
        # original file-receipt field without discarding that separate proof.
        expected = {key: reference[key] for key in ('path', 'bytes', 'sha256', 'identity')}
        need(native.receipt(Path(reference['path'])) == expected, 'original input changed: ' + reference['path'])


def host_gate(core, native, path):
    snapshot = native.host_load()
    matching = [row for row in snapshot['processes'] if row['comm'] in core.BUSY_NAMES
                and row['state'] not in ('Z', 'X', 'x')]
    memory = re.findall(r'^MemAvailable:\s+(\d+)\s+kB\s*$', snapshot.get('meminfo', ''), re.MULTILINE)
    filesystem = os.statvfs(BASE)
    disk = filesystem.f_bavail * filesystem.f_frsize
    available = int(memory[0]) if len(memory) == 1 else None
    gate = {'snapshot': snapshot, 'matching_live_processes': matching,
            'mem_available_kib': available, 'disk_available_bytes': disk,
            'resource_thresholds': {'mem_available_kib_min': core.MEM_MIN_KIB,
                                    'disk_available_bytes_min': core.DISK_MIN_BYTES},
            'scope': 'point-in-time admission; root must schedule this separately from benchmarks/builds'}
    gate['clear'] = bool(snapshot['required_fields_present'] and not snapshot['errors'] and not matching
                         and available is not None and available >= core.MEM_MIN_KIB and disk >= core.DISK_MIN_BYTES)
    receipt = core.create(path, core.canonical(gate))
    return gate['clear'], receipt


def run_command(core, row, env, save):
    child = None
    path = OUT / ('command-%02d' % row['index'])
    # The one outer owner retains this session until all its members settle.
    # No test child gets a separate session or process group from this wrapper.
    with path.with_suffix('.stdout').open('xb', buffering=0) as stdout, \
            path.with_suffix('.stderr').open('xb', buffering=0) as stderr:
        try:
            # Only this single-threaded supervisor uses preexec_fn. Its child
            # must not inherit the parent's short launch-custody signal mask:
            # one original regression exercises real SIGTERM graceful exit.
            threads = list(Path('/proc/self/task').iterdir())
            need(len(threads) == 1, 'single-threaded launch supervisor required')
            mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
            try:
                child = subprocess.Popen(row['argv'], cwd=COPY, env=env, stdin=subprocess.DEVNULL,
                                         stdout=stdout, stderr=stderr, umask=0o022,
                                         preexec_fn=lambda: signal.pthread_sigmask(signal.SIG_SETMASK, mask))
                row.update(executed=True, execution_count=1, pid=child.pid, started_utc=core.utc(),
                           parent_thread_count_at_launch=1, child_signal_mask_restored_before_exec=True)
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, mask)
            save()
            row['returncode'] = child.wait(timeout=row['timeout_seconds'])
        except BaseException as error:
            row['error'] = type(error).__name__ + ': ' + str(error)
            row['timed_out'] = isinstance(error, subprocess.TimeoutExpired)
            if child is not None and child.returncode is None:
                try:
                    child.kill()
                    row['returncode'] = child.wait(timeout=10)
                except BaseException as cleanup:
                    row['cleanup_error'] = type(cleanup).__name__ + ': ' + str(cleanup)
            raise
        finally:
            row['original_child_reaped'] = child is not None and child.returncode is not None
            row['finished_utc'] = core.utc()
            for stream, name in ((stdout, 'stdout'), (stderr, 'stderr')):
                try:
                    os.fsync(stream.fileno())
                    _, row[name] = core.original(Path(stream.name))
                except BaseException as capture:
                    row.setdefault('output_errors', []).append(name + ': ' + type(capture).__name__ + ': ' + str(capture))
            save()
            if row.get('output_errors') and not row.get('error'):
                raise RuntimeError('original command output capture incomplete: ' + row['name'])


def worker(args, core):
    require_bindings(args)
    need(args.permit_fd is not None, 'original parent GO missing')
    try:
        need(os.read(args.permit_fd, 2) == b'G', 'original parent did not admit worker')
    finally:
        os.close(args.permit_fd)
    need(os.getpid() == os.getpgrp() == os.getsid(0), 'worker session differs')
    core.original(Path(__file__).absolute(), args.runner_sha)
    need(type(args.inputs_sha) is str and re.fullmatch(r'[0-9a-f]{64}', args.inputs_sha), 'worker input pin missing')
    raw, _ = core.original(OUT / 'inputs.json', args.inputs_sha)
    inputs = json.loads(raw)
    native_raw, _ = core.original(core.NATIVE, core.NATIVE_SHA)
    native = core.module('a53_control_plane_native_worker', core.NATIVE, native_raw)
    env, _ = environment(core)
    need(env == dict(os.environ), 'worker environment differs')
    report = {'schema': 'hepta-a53-control-plane-gates-worker/v1', 'started_utc': core.utc(),
              'passed': False, 'errors': [], 'automatic_retry': False, 'commands': [
                  {'index': index, 'name': 'dependency-precheck' if index == 0 else TESTS[index - 1],
                   'argv': argv, 'timeout_seconds': 30 if index == 0 else 300,
                   'executed': False, 'execution_count': 0, 'status': 'unexecuted', 'returncode': None}
                  for index, argv in enumerate(COMMANDS)]}

    def save():
        report['unexecuted'] = [row['name'] for row in report['commands'] if not row['executed']]
        core.checkpoint(OUT / 'worker-report.json', report)

    save()
    try:
        fence(core, native, inputs)
        report['inputs_unchanged_before'] = True
        for row in report['commands']:
            clear, receipt = host_gate(core, native, OUT / ('command-%02d.host-gate.json' % row['index']))
            row.update(host_gate=receipt, gate_clear=clear)
            save()
            need(clear, 'host gate refused; no test launched: ' + row['name'])
            row['status'] = 'running'
            run_command(core, row, env, save)
            need(row['returncode'] == 0 and row['original_child_reaped'], 'Python gate failed: ' + row['name'])
            if row['index']:
                stderr, _ = core.original(Path(row['stderr']['path']))
                summaries = re.findall(rb'^Ran (\d+) tests? in [^\n]+$', stderr, re.MULTILINE)
                endings = re.findall(rb'^OK(?: \(([^\n]*)\))?$', stderr, re.MULTILINE)
                need(len(summaries) == len(endings) == 1 and int(summaries[0]) > 0,
                     'positive original unittest summary missing: ' + row['name'])
                skipped = re.search(rb'\bskipped=(\d+)\b', endings[0])
                row['unittest'] = {'reported_tests': int(summaries[0]),
                                   'reported_skips': int(skipped[1]) if skipped else 0,
                                   'result_detail': endings[0].decode()}
            row['status'] = 'passed'
            save()
        report['passed'] = True
    except BaseException as error:
        report['errors'].append(type(error).__name__ + ': ' + str(error))
    finally:
        try:
            fence(core, native, inputs)
            report['inputs_unchanged_after'] = True
        except BaseException as error:
            report['passed'] = False
            report['errors'].append('input fence: ' + type(error).__name__ + ': ' + str(error))
        for row in report['commands']:
            if row['status'] == 'running':
                row['status'] = 'failed'
        report['finished_utc'] = core.utc()
        report['tests_reported'] = sum(row.get('unittest', {}).get('reported_tests', 0) for row in report['commands'])
        report['skips_reported'] = sum(row.get('unittest', {}).get('reported_skips', 0) for row in report['commands'])
        save()
    return 0 if report['passed'] else 1


def main(args, core):
    require_bindings(args)
    os.umask(0o077)
    core.fresh(OUT)
    core.mkdir_new(OUT)
    report = {'schema': 'hepta-a53-control-plane-gates-entry/v1', 'started_utc': core.utc(),
              'passed': False, 'errors': [], 'automatic_retry': False, 'service_changes': False,
              'remote_calls': 0, 'rust_commands': 0, 'planned_test_commands': 15,
              'precheck_counted_as_test': False, 'source_writes_requested': 0,
              'unexecuted': ['dependency-precheck', *TESTS],
              'worker_custody': {'executed': False, 'execution_count': 0,
                                 'original_child_reaped': False, 'signals': [], 'custody_unknown': False}}
    inputs = native = None
    core.checkpoint(OUT / 'entry-report.json', report)
    try:
        self_raw, self_receipt = core.original(Path(__file__).absolute(), args.runner_sha)
        _, core_receipt = core.original(CORE, CORE_SHA)
        native_raw, native_receipt = core.original(core.NATIVE, core.NATIVE_SHA)
        native = core.module('a53_control_plane_native_entry', core.NATIVE, native_raw)
        extra, extra_receipt, originals = supplement(core, args.bundle_sha)
        bound, references = qualification(core, native, args)
        original_map, source_receipts, bodies = core.source(SOURCE, keep_bytes=True)
        need(original_map == bound['source_map'], 'qualified source changed before copy')
        need(set(original_map) & set(extra) == {'Cargo.toml', 'src/mcp/runtime/fileio.py'}, 'source overlap differs')
        for name, data in extra.items():
            need(name not in bodies or bodies[name] == data, 'qualified/supplement overlap conflicts: ' + name)
            bodies[name] = data
        need(len(bodies) == 216, 'combined test inventory differs')
        core.mkdir_new(COPY)
        core.mkdir_new(OUT / 'tmp')
        core.create(OUT / 'runner.original.py', self_raw)
        for name, data in originals.items():
            core.create(OUT / name, data)
        for name, data in sorted(bodies.items()):
            current = COPY
            for part in Path(name).parent.parts:
                current = current / part
                if not current.exists():
                    core.mkdir_new(current)
            core.create(COPY / name, data)
        copy_map, copy_receipts, _ = core.source(COPY)
        need(copy_map == {name: sha(data) for name, data in bodies.items()}, 'fresh copy readback differs')
        env, environment_receipt = environment(core)
        inputs = {'qualified': bound, 'source_receipts': source_receipts, 'copy_map': copy_map,
                  'copy_receipts': copy_receipts, 'environment': environment_receipt,
                  'original_inputs': [self_receipt, core_receipt, native_receipt, extra_receipt, *references]}
        inputs_receipt = core.create(OUT / 'inputs.json', core.canonical(inputs))
        report.update(inputs=inputs_receipt, environment=environment_receipt,
                      qualified_source_files=175, supplemental_source_files=43, combined_source_files=216,
                      interpreter='/usr/bin/python3', subprocess_python3_path='/usr/bin/python3')
        fence(core, native, inputs)
        argv = ['/usr/bin/python3', '-B', str(Path(__file__).absolute()), '--worker',
                '--runner-sha', args.runner_sha, '--bundle-sha', args.bundle_sha,
                '--qualification-sha', args.qualification_sha,
                '--qualification-entry-sha', args.qualification_entry_sha,
                '--qualification-worker-sha', args.qualification_worker_sha,
                '--inputs-sha', inputs_receipt['sha256']]
        code = core.own_worker(argv, env, report)
        raw, worker_receipt = core.original(OUT / 'worker-report.json')
        completed = json.loads(raw)
        report['worker_report'] = worker_receipt
        report['commands'] = completed['commands']
        report['unexecuted'] = completed['unexecuted']
        report['tests_reported'] = completed['tests_reported']
        report['skips_reported'] = completed['skips_reported']
        need(code == 0 and completed['passed'] is True and completed['errors'] == []
             and len(completed['commands']) == 16 and all(row['status'] == 'passed' for row in completed['commands']),
             'guarded Python gate worker did not complete all fifteen commands')
        custody = report['worker_custody']
        need(custody['original_child_reaped'] and custody['group_quiet_before_reap']
             and custody['custody_known'] and not custody['custody_unknown'] and custody['signals'] == []
             and not custody.get('error') and not custody.get('cleanup_errors'), 'original worker custody incomplete')
        report['passed'] = True
    except BaseException as error:
        report['errors'].append(type(error).__name__ + ': ' + str(error))
    finally:
        # Retain a partial worker journal even when the outer custody function
        # throws. Final log receipts are taken after its bounded group cleanup,
        # so output written by late descendants is never silently discarded.
        capture_errors = []
        if (OUT / 'worker-report.json').exists():
            try:
                raw, receipt = core.original(OUT / 'worker-report.json')
                observed = json.loads(raw)
                report['worker_report'] = receipt
                for key in ('commands', 'unexecuted', 'tests_reported', 'skips_reported'):
                    if key in observed:
                        report[key] = observed[key]
            except BaseException as error:
                capture_errors.append('worker journal: ' + type(error).__name__ + ': ' + str(error))
        report['final_output_receipts'] = {}
        for name in ['qualifier-worker.stdout', 'qualifier-worker.stderr', *[
                'command-%02d.%s' % (index, stream)
                for index in range(16) for stream in ('stdout', 'stderr')]]:
            try:
                path = OUT / name
                if path.exists():
                    _, receipt = core.original(path)
                    report['final_output_receipts'][name] = receipt
            except BaseException as error:
                capture_errors.append(name + ': ' + type(error).__name__ + ': ' + str(error))
        for row in report.get('commands', []):
            if row['status'] == 'passed':
                unchanged = all(report['final_output_receipts'].get('command-%02d.%s' % (row['index'], stream))
                                == row.get(stream) and row.get(stream) is not None for stream in ('stdout', 'stderr'))
                row['final_output_unchanged'] = unchanged
                if not unchanged:
                    capture_errors.append('late output change after command exit: ' + row['name'])
        custody = report['worker_custody']
        report['output_writers_settled'] = bool(custody.get('original_child_reaped')
                                               and custody.get('group_quiet_before_reap'))
        if capture_errors:
            report['passed'] = False
            report['errors'].extend('final output capture: ' + error for error in capture_errors)
        if inputs is not None and native is not None:
            try:
                fence(core, native, inputs)
                report['inputs_unchanged_after'] = True
            except BaseException as error:
                report['passed'] = False
                report['errors'].append('final input fence: ' + type(error).__name__ + ': ' + str(error))
        report['finished_utc'] = core.utc()
        core.checkpoint(OUT / 'entry-report.json', report)
        print(json.dumps({'passed': report['passed'], 'report': str(OUT / 'entry-report.json'),
                          'errors': report['errors']}), flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('runner-sha', 'bundle-sha', 'qualification-sha', 'qualification-entry-sha', 'qualification-worker-sha'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--worker', action='store_true')
    parser.add_argument('--permit-fd', type=int)
    parser.add_argument('--inputs-sha')
    args = parser.parse_args()
    for name in ('runner_sha', 'bundle_sha', 'qualification_sha', 'qualification_entry_sha', 'qualification_worker_sha'):
        need(re.fullmatch(r'[0-9a-f]{64}', getattr(args, name)), 'complete pinned SHA required: ' + name)
    signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGINT, signal.SIGTERM})

    def interrupted(signum, _frame):
        raise KeyboardInterrupt('gate runner interrupted by signal ' + str(signum))

    signal.signal(signal.SIGINT, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    require_bindings(args)
    core = load_core()
    sys.exit(worker(args, core) if args.worker else main(args, core))

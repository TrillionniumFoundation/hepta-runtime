#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Qualify one R21 candidate on X230, then run the independent verifier once.

All outputs are new attempt-01 paths. The unchanged original qualifier owns its
eight build/test stages; this controller retains its own child identities and
full streams. Only --self-test is suitable for a local non-X230 invocation.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import create_component_chain_01 as component_chain_policy

DEFAULT_ROOT = Path('/home/qian/hepta-runtime-optimization-20261105-r21')
BASELINE = Path('/home/qian/hepta-runtime-optimization-20261104-r19/source')
CARGO_HOME = Path('/home/qian/hepta-runtime-optimization-20261023/cargo-home-a32-a33-r02')
QUALIFIER_SHA256 = '95717717fd5421f2e31dbce24e2f8821696f57d779ce93e988ed66764159552d'
BASELINE_JOBS_SHA256 = 'c9080de8aa9a35f7495aa2822a1495d297903900ae0f0de26d7b0c86d043d3c9'
JOBCTL_SOURCE_SHA256 = 'c22fdcd5bafad3a2123d5817c27fd73e7b5c26001bf1a8bdd6f8dbacabc8b562'
JOBCTL_BINARY_SHA256 = '61c90260057a405626a24a36ad43303c632f72d2d97929296acdffd748b79d62'
BASELINE_PINS = {
    'source-freeze-02.json': '31f90b50d22ff8c8ac3a188f1bad47c844b4e2e68784277a87a671c916f7cb6a',
    'qualification-02/report.json': '44a352c14bb83d093058ccbbc2c99fab913ef9af0b3400b00750dc46ad69cc16',
    'independent-acceptance-02.json': '374d6bf3e7201522f8145b105a10c372eaedc5bba9099ca92857367637b65ea9',
    'qualification-02/hepta-runtime': 'adab5f27f89b3cac6adaec916110a48d80697db9667e3bd7ee0fc713fe770a09',
    'qualification-02/hepta-runtime-jobctl': JOBCTL_BINARY_SHA256,
    'qualification-02/native_process_driver': '51165c1e38409248f5fdb7da2036ebe5e05eec7576035e95bd4b8e2a5c675530',
}
TOOL_NAMES = {'qualify_candidate_01.py', 'verify_qualification_01.py', 'create_component_chain_01.py'}
JOBS_PATH = 'src/mcp/runtime/jobs.rs'
MINIMUM_FREE_BYTES = 16 * 1024 ** 3
HEX = re.compile(r'[0-9a-f]{64}\Z')


def need(value, message):
    if not value:
        raise ValueError(message)


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def stamp(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def identity(path):
    path = Path(path)
    need(path.absolute() == path.resolve(), 'symlink in input path: ' + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'non-regular or shared file: ' + str(path))
        h, count = hashlib.sha256(), 0
        while True:
            block = os.read(fd, 1 << 20)
            if not block:
                break
            h.update(block)
            count += len(block)
        need(count == before.st_size and stamp(before) == stamp(os.fstat(fd)) == stamp(path.lstat()),
             'file changed while hashing: ' + str(path))
        return {'size': count, 'sha256': h.hexdigest()}
    finally:
        os.close(fd)


def sha(path):
    return identity(path)['sha256']


def document(path):
    before = identity(path)
    raw = Path(path).read_bytes()
    need(len(raw) == before['size'] and hashlib.sha256(raw).hexdigest() == before['sha256']
         and identity(path) == before, 'JSON input changed: ' + str(path))
    return json.loads(raw)


def full_map(root):
    need(root.is_dir() and root.resolve() == root.absolute(), 'invalid source directory')
    result = {}
    for base, directories, files in os.walk(root, followlinks=False):
        for name in directories:
            need(stat.S_ISDIR(os.lstat(Path(base) / name).st_mode), 'non-directory source entry')
        for name in files:
            path = Path(base) / name
            result[path.relative_to(root).as_posix()] = identity(path)
    return dict(sorted(result.items()))


def compile_map(files):
    return {p: row['sha256'] for p, row in files.items()
            if p in ('Cargo.toml', 'Cargo.lock', 'rustfmt.toml') or p.startswith(('src/', 'examples/'))}


def preparation_map(preparation):
    result = {}
    for row in preparation['files']:
        path = row['path']
        need(isinstance(path, str) and path == Path(path).as_posix() and not Path(path).is_absolute()
             and '..' not in Path(path).parts and path not in ('', '.') and path not in result, 'invalid preparation path')
        need(type(row['size']) is int and row['size'] >= 0 and HEX.fullmatch(row['sha256']), 'invalid preparation identity')
        result[path] = {'size': row['size'], 'sha256': row['sha256']}
    return dict(sorted(result.items()))


def validate_sources(baseline, candidate, expected):
    need(len(baseline) == len(candidate) == 281 and set(baseline) == set(candidate), 'full source inventory differs')
    need(len(compile_map(candidate)) == 219, 'compile input count differs from 219')
    need([p for p in baseline if baseline[p] != candidate[p]] == [JOBS_PATH], 'changes extend beyond jobs.rs')
    need(baseline[JOBS_PATH]['sha256'] == BASELINE_JOBS_SHA256, 'baseline jobs.rs identity differs')
    need(candidate[JOBS_PATH]['sha256'] == expected, 'candidate jobs.rs identity differs')
    need(candidate['src/bin/jobctl.rs']['sha256'] == JOBCTL_SOURCE_SHA256, 'jobctl source identity differs')


def component_chain_evidence(path, expected_hash, expected_jobs):
    return component_chain_policy.validate_chain(path, expected_hash, expected_jobs, DEFAULT_ROOT)


def tool_manifest(root, expected_hash):
    path = root / 'tools/qualification-tools-manifest-01.json'
    need(sha(path) == expected_hash, 'qualification tools manifest identity differs')
    value = document(path)
    need(value.get('schema') == 'hepta-x230-qualification-tools/v1' and set(value['files']) == TOOL_NAMES,
         'unexpected qualification tool set')
    actual = {name: identity(root / 'tools' / name) for name in sorted(TOOL_NAMES)}
    need(actual == value['files'], 'qualification tool bytes differ')
    need(Path(__file__).absolute() == root / 'tools/qualify_candidate_01.py', 'launcher must be installed under root/tools')
    return {'path': str(path), **identity(path), 'files': actual}


def cargo_configs(source):
    # Hash only Cargo configuration candidates. Never open credentials or dump env.
    paths = {base / '.cargo' / name for base in (source, *source.parents) for name in ('config', 'config.toml')}
    paths.update(CARGO_HOME / name for name in ('config', 'config.toml'))
    return {str(path): identity(path) if os.path.lexists(path) else None for path in sorted(paths)}


def clean_environment():
    # Absence is intentional: empty Cargo workspace-wrapper changes crate metadata.
    return {'HOME': '/home/qian', 'USER': 'qian', 'LOGNAME': 'qian',
            'PATH': '/home/qian/.cargo/bin:/usr/local/bin:/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
            'RUSTUP_HOME': '/home/qian/.rustup', 'RUSTUP_AUTO_INSTALL': '0', 'CARGO_HOME': str(CARGO_HOME),
            'CARGO_NET_OFFLINE': 'true', 'CARGO_INCREMENTAL': '0', 'CARGO_BUILD_JOBS': '2',
            'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONNOUSERSITE': '1', 'TOKIO_WORKER_THREADS': '2'}


def save(path, value, replace=False):
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    if replace:
        temporary = path.with_name(path.name + '.next')
        with temporary.open('xb') as stream:
            stream.write(raw)
        os.replace(temporary, path)
    else:
        with path.open('xb') as stream:
            stream.write(raw)


def start_ticks(pid):
    return int(Path('/proc', str(pid), 'stat').read_text().rsplit(')', 1)[1].split()[19])


def group_absent(pgid):
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return True
    return False


def interrupted(signum, _frame):
    raise InterruptedError('received ' + signal.Signals(signum).name)


def stop_owned(child, row):
    row['cleanup_signals'] = []
    # start_new_session makes this exact direct child the owner of this PGID.
    for signum, grace in ((signal.SIGTERM, 10), (signal.SIGKILL, 5)):
        if group_absent(child.pid):
            break
        try:
            os.killpg(child.pid, signum)
            row['cleanup_signals'].append(signum.name)
        except ProcessLookupError:
            break
        deadline = time.monotonic() + grace
        while time.monotonic() < deadline:
            child.poll()
            if group_absent(child.pid):
                break
            time.sleep(0.1)
    child.wait(timeout=5)


def self_test():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / 'src').mkdir()
        p = root / 'src/file.rs'
        p.write_bytes(b'one')
        old = full_map(root)
        p.write_bytes(b'two')
        need(full_map(root) != old, 'mutation was not observed')
        os.link(p, root / 'hardlink')
        try:
            full_map(root)
        except ValueError:
            pass
        else:
            raise AssertionError('hardlink accepted')
        (root / 'hardlink').unlink()
        (root / 'link').symlink_to(p)
        try:
            full_map(root)
        except ValueError:
            pass
        else:
            raise AssertionError('symlink accepted')
    need(not any('WRAPPER' in key for key in clean_environment()), 'wrapper key must be absent')
    need(len(clean_environment()) == 15, 'allowlist changed')
    print(json.dumps({'self_test': True, 'compilation_started': False}))
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=DEFAULT_ROOT)
    parser.add_argument('--expected-jobs-sha256')
    parser.add_argument('--component-chain', type=Path)
    parser.add_argument('--expected-component-chain-sha256')
    parser.add_argument('--expected-tools-manifest-sha256')
    parser.add_argument('--stage-timeout', type=int, default=3600)
    parser.add_argument('--qualification-timeout', type=int, default=7200)
    parser.add_argument('--verification-timeout', type=int, default=300)
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    for key in ('expected_jobs_sha256', 'expected_component_chain_sha256', 'expected_tools_manifest_sha256'):
        if not HEX.fullmatch(getattr(args, key) or ''):
            parser.error('--' + key.replace('_', '-') + ' must be lowercase SHA256')
    if args.component_chain is None:
        parser.error('--component-chain is required')
    signal.signal(signal.SIGTERM, interrupted)
    root, chain_path = args.root.absolute(), args.component_chain.absolute()
    source, target, out = root / 'source', root / 'target-fresh-01', root / 'qualification-01'
    control, progress = root / 'qualification-control-01', root / 'progress-01.json'
    launch_path, exit_path = root / 'qualification-launch-01.json', root / 'qualification-exit-01.json'
    report = {'schema': 'hepta-x230-qualification-control/v1', 'root': str(root), 'attempt': 1,
              'started_utc': now(), 'passed': False, 'automatic_retries': 0, 'stages': [], 'toolchain_probes': []}
    owned = None
    admitted = False

    def persist():
        save(control / 'report.json', report, replace=True)

    def child_stage(name, argv, timeout, env, rows, on_start=None, observe=None):
        nonlocal owned
        row = {'name': name, 'argv': argv, 'cwd': str(source), 'timeout_seconds': timeout,
               'started_utc': now(), 'returncode': None, 'timed_out': False, 'automatic_retries': 0}
        rows.append(row)
        report['current_stage'] = name
        persist()
        stdout_path, stderr_path = control / (name + '.stdout'), control / (name + '.stderr')
        began = time.monotonic()
        try:
            with stdout_path.open('xb') as stdout, stderr_path.open('xb') as stderr:
                owned = subprocess.Popen(argv, cwd=source, env=env, stdin=subprocess.DEVNULL,
                                         stdout=stdout, stderr=stderr, start_new_session=True)
                row.update(pid=owned.pid, start_ticks=start_ticks(owned.pid), process_group=owned.pid)
                if on_start:
                    on_start(row)
                persist()
                while owned.poll() is None:
                    if observe:
                        observe(row)
                    if time.monotonic() - began >= timeout:
                        row['timed_out'] = True
                        raise TimeoutError(name + ' timed out')
                    time.sleep(1)
                owned.wait()
                row.update(returncode=owned.returncode, waited_and_reaped=True,
                           proc_absent=not Path('/proc', str(owned.pid)).exists(),
                           process_group_absent=group_absent(owned.pid))
                need(row['returncode'] == 0 and row['proc_absent'] and row['process_group_absent'], name + ' failed or retained its owned group')
        except BaseException as error:
            row['error'] = type(error).__name__ + ': ' + str(error)
            if owned is not None:
                try:
                    stop_owned(owned, row)
                except BaseException as cleanup_error:
                    row['cleanup_error'] = type(cleanup_error).__name__ + ': ' + str(cleanup_error)
                row.update(returncode=owned.returncode, waited_and_reaped=owned.returncode is not None,
                           proc_absent=not Path('/proc', str(owned.pid)).exists(),
                           process_group_absent=group_absent(owned.pid))
            raise
        finally:
            primary_error = sys.exc_info()[0] is not None
            finalization_errors = []
            row['finished_utc'], row['seconds'] = now(), time.monotonic() - began
            for stream, path in (('stdout', stdout_path), ('stderr', stderr_path)):
                try:
                    if path.exists():
                        row[stream] = {'path': str(path), **identity(path)}
                except BaseException as metadata_error:
                    finalization_errors.append(stream + ': ' + type(metadata_error).__name__ + ': ' + str(metadata_error))
            if finalization_errors:
                row['finalization_errors'] = finalization_errors
            try:
                persist()
            except BaseException as persistence_error:
                finalization_errors.append('receipt: ' + type(persistence_error).__name__ + ': ' + str(persistence_error))
                print(json.dumps({'stage': name, 'original_error': row.get('error'), 'finalization_errors': finalization_errors}), file=sys.stderr, flush=True)
            owned = None
            if finalization_errors and not primary_error:
                raise RuntimeError(name + ' receipt finalization failed: ' + '; '.join(finalization_errors))
        return row

    try:
        need(pwd.getpwuid(os.getuid()).pw_name == 'qian', 'must run as qian on X230')
        need(root == DEFAULT_ROOT and root.is_dir() and root.resolve() == root, 'candidate root must be the reserved R21 directory')
        need(60 <= args.stage_timeout <= 14400 and 60 <= args.qualification_timeout <= 14400
             and 30 <= args.verification_timeout <= 1800, 'invalid timeout')
        names = ['target-fresh-01', 'qualification-01', 'qualification-control-01', 'qualification-01.reserved',
                 'source-freeze-01.json', 'source-middle-01.json', 'source-after-01.json', 'qualification-launch-01.json',
                 'qualification-exit-01.json', 'independent-acceptance-01.json', 'qualification-failure-01.json', 'progress-01.json']
        need(all(not os.path.lexists(root / name) for name in names), 'attempt-01 path already exists')
        (root / 'qualification-01.reserved').mkdir(mode=0o700)
        admitted = True
        control.mkdir(mode=0o700)
        tools = tool_manifest(root, args.expected_tools_manifest_sha256)
        chain_binding = component_chain_evidence(chain_path, args.expected_component_chain_sha256, args.expected_jobs_sha256)
        prep = document(root / 'preparation.json')
        need(prep['source'] == str(BASELINE) and prep['candidate_root'] == str(root), 'preparation targets differ')
        original, frozen = preparation_map(prep), full_map(source)
        baseline_bindings = {name: identity(BASELINE.parent / name) for name in BASELINE_PINS}
        need(all(row['sha256'] == BASELINE_PINS[name] for name, row in baseline_bindings.items()), 'accepted baseline evidence changed')
        baseline_freeze = document(BASELINE.parent / 'source-freeze-02.json')
        baseline_acceptance = document(BASELINE.parent / 'independent-acceptance-02.json')
        need(full_map(BASELINE) == original == baseline_freeze['source_full_before'], 'baseline source differs from accepted freeze')
        need(baseline_acceptance.get('accepted') is True and all(v is True for v in baseline_acceptance['checks'].values()), 'baseline acceptance failed')
        validate_sources(original, frozen, args.expected_jobs_sha256)
        qualifier = source / 'tools/x230/20261028/qualify.py'
        need(sha(qualifier) == QUALIFIER_SHA256, 'original qualifier identity differs')
        free = shutil.disk_usage(root).free
        need(free >= MINIMUM_FREE_BYTES, 'less than 16 GiB free')
        environment, configs = clean_environment(), cargo_configs(source)
        report.update(component_chain=chain_binding, tools_manifest=tools, baseline_bindings=baseline_bindings,
                      expected_jobs_sha256=args.expected_jobs_sha256, free_bytes_before=free)
        versions = {}
        for program in ('cargo', 'rustc'):
            row = child_stage('toolchain-' + program, ['/home/qian/.cargo/bin/' + program, '+1.95.0', '--version'],
                              30, environment, report['toolchain_probes'])
            versions[program] = Path(row['stdout']['path']).read_text().strip()
            need(versions[program].startswith(program + ' 1.95.0 '), 'unexpected Rust toolchain version')
        need(full_map(source) == frozen and full_map(BASELINE) == original and cargo_configs(source) == configs,
             'source or Cargo configuration changed during preflight')
        freeze = {'schema': 'hepta-x230-source-freeze/v2', 'attempt': 1, 'created_utc': now(),
                  'source': str(source), 'baseline_source': str(BASELINE), 'preparation_sha256': sha(root / 'preparation.json'),
                  'source_full_before': frozen, 'source_inputs_before': compile_map(frozen),
                  'expected_jobs_sha256': args.expected_jobs_sha256, 'qualifier_sha256': QUALIFIER_SHA256,
                  'baseline_jobctl_binary': {'path': str(BASELINE.parent / 'qualification-02/hepta-runtime-jobctl'), 'sha256': JOBCTL_BINARY_SHA256},
                  'baseline_bindings': baseline_bindings, 'component_chain': chain_binding, 'tools_manifest': tools, 'cargo_configurations': configs}
        save(root / 'source-freeze-01.json', freeze)
        target.mkdir(mode=0o700)
        need(not any(target.iterdir()), 'target was not created empty')
        argv = ['/usr/bin/python3', '-B', '-u', str(qualifier), '--source', str(source), '--output', str(out),
                '--target', str(target), '--cargo-home', str(CARGO_HOME), '--jobs', '2', '--stage-timeout', str(args.stage_timeout)]
        launch = {'schema': 'hepta-x230-qualification-launch/v2', 'attempt': 1, 'started_utc': now(),
                  'host': socket.gethostname(), 'user': 'qian', 'argv': argv, 'toolchain': versions,
                  'toolchain_probes': report['toolchain_probes'], 'target_asserted_nonexistent': True, 'target_created_empty': True,
                  'output_asserted_nonexistent': True, 'free_bytes_before': free, 'minimum_free_bytes': MINIMUM_FREE_BYTES,
                  'automatic_retries': 0, 'environment_policy': 'explicit-allowlist/v2-no-wrapper-keys', 'environment': environment,
                  'source_freeze_sha256': sha(root / 'source-freeze-01.json'), 'launcher_sha256': sha(Path(__file__).absolute()),
                  'qualifier_sha256': QUALIFIER_SHA256, 'tools_manifest': tools, 'component_chain': chain_binding, 'cargo_configurations': configs}
        save(launch_path, launch)
        middle = None

        def qualifier_started(row):
            launch.update(qualifier_pid=row['pid'], qualifier_start_ticks=row['start_ticks'], qualifier_process_group=row['process_group'])
            save(launch_path, launch, replace=True)

        def observe_qualifier(row):
            nonlocal middle
            current = {}
            try:
                current = json.loads((out / 'report.json').read_bytes())
            except (FileNotFoundError, json.JSONDecodeError):
                pass
            if middle is None and current.get('source_tested') is not None:
                observed = full_map(source)
                need(observed == frozen and full_map(BASELINE) == original and current['source_tested'] == compile_map(frozen)
                     and cargo_configs(source) == configs, 'source/configuration changed before the build/test midpoint')
                middle = {'schema': 'hepta-x230-source-middle/v1', 'created_utc': now(), 'source': str(source),
                          'source_full': observed, 'source_inputs': compile_map(observed), 'baseline_full_unchanged': True,
                          'qualifier_pid': row['pid'], 'qualifier_start_ticks': row['start_ticks'],
                          'observed_during_qualifier': owned is not None and owned.poll() is None,
                          'observed_stage': current.get('current_stage'), 'cargo_configurations': configs}
                save(root / 'source-middle-01.json', middle)
            save(progress, {'schema': 'hepta-x230-qualification-progress/v1', 'updated_utc': now(), 'state': 'fresh-qualification',
                            'current_stage': current.get('current_stage'), 'completed_stages': sum(s.get('returncode') == 0 for s in current.get('stages', [])),
                            'qualifier_pid': row['pid']}, replace=True)

        qrow = child_stage('fresh-qualification', argv, args.qualification_timeout, environment, report['stages'],
                           qualifier_started, observe_qualifier)
        qualification = document(out / 'report.json')
        after = full_map(source)
        need(middle is not None and middle['observed_during_qualifier'] is True, 'missing live midpoint source snapshot')
        unchanged = after == frozen == middle['source_full'] and full_map(BASELINE) == original and cargo_configs(source) == configs
        maps_match = all(qualification.get(k) == compile_map(frozen) for k in ('source_input', 'source_tested', 'source_after'))
        need(qualification.get('qualified') is True and unchanged and maps_match, 'qualification or source identity failed')
        save(root / 'source-after-01.json', {'schema': 'hepta-x230-source-after/v1', 'created_utc': now(), 'source': str(source),
             'source_full': after, 'source_inputs': compile_map(after), 'baseline_full_unchanged': True, 'cargo_configurations': configs})
        outcome = {'schema': 'hepta-x230-qualification-exit/v2', 'attempt': 1, 'finished_utc': now(), 'success': True,
                   'qualifier_pid': qrow['pid'], 'qualifier_start_ticks': qrow['start_ticks'], 'qualifier_reaped': qrow['waited_and_reaped'],
                   'qualifier_returncode': qrow['returncode'], 'qualifier_proc_absent': qrow['proc_absent'],
                   'qualifier_process_group_absent': qrow['process_group_absent'], 'returncode': qrow['returncode'],
                   'source_full_before_after_equal': unchanged, 'source_full_before_middle_after_equal': unchanged,
                   'source_inputs_before_after_equal': maps_match, 'automatic_retries': 0,
                   'report_sha256': sha(out / 'report.json'), 'launcher_stdout_sha256': qrow['stdout']['sha256'],
                   'launcher_stderr_sha256': qrow['stderr']['sha256'], 'source_middle_sha256': sha(root / 'source-middle-01.json'),
                   'source_after_sha256': sha(root / 'source-after-01.json'), 'stage': qrow}
        save(exit_path, outcome)
        tool_manifest(root, args.expected_tools_manifest_sha256)
        component_chain_evidence(chain_path, args.expected_component_chain_sha256, args.expected_jobs_sha256)
        verifier = root / 'tools/verify_qualification_01.py'
        vargv = ['/usr/bin/python3', '-B', str(verifier), '--root', str(root), '--expected-jobs-sha256', args.expected_jobs_sha256,
                 '--component-chain', str(chain_path), '--expected-component-chain-sha256', args.expected_component_chain_sha256,
                 '--expected-tools-manifest-sha256', args.expected_tools_manifest_sha256]
        child_stage('independent-verification', vargv, args.verification_timeout, environment, report['stages'])
        acceptance = document(root / 'independent-acceptance-01.json')
        need(acceptance.get('accepted') is True and bool(acceptance['checks']) and all(v is True for v in acceptance['checks'].values()),
             'independent verifier did not accept')
        need(full_map(source) == frozen and full_map(BASELINE) == original and cargo_configs(source) == configs,
             'source/configuration changed after independent verification')
        tool_manifest(root, args.expected_tools_manifest_sha256)
        component_chain_evidence(chain_path, args.expected_component_chain_sha256, args.expected_jobs_sha256)
        need(all(identity(BASELINE.parent / name) == row for name, row in baseline_bindings.items()), 'baseline evidence changed')
        report.update(passed=True, current_stage='completed', source_full_before_middle_after_equal=True,
                      qualification_report={'path': str(out / 'report.json'), **identity(out / 'report.json')},
                      independent_acceptance={'path': str(root / 'independent-acceptance-01.json'), **identity(root / 'independent-acceptance-01.json')},
                      binaries=acceptance['binaries'], test_counts=acceptance['test_counts'])
    except BaseException as error:
        report.update(error=type(error).__name__ + ': ' + str(error), current_stage='failed')
        if admitted:
            try:
                save(root / 'qualification-failure-01.json', {'schema': 'hepta-x230-qualification-failure/v1',
                     'created_utc': now(), 'error': report['error'], 'automatic_retries': 0, 'stages': report['stages'],
                     'toolchain_probes': report['toolchain_probes']})
            except OSError as save_error:
                report['failure_receipt_error'] = type(save_error).__name__ + ': ' + str(save_error)
    finally:
        report['finished_utc'] = now()
        if admitted and control.is_dir():
            try:
                persist()
                save(progress, {'schema': 'hepta-x230-qualification-progress/v1', 'state': report['current_stage'],
                                'updated_utc': now(), 'passed': report['passed'], 'error': report.get('error')}, replace=True)
            except BaseException as finalization_error:
                report['passed'] = False
                report['finalization_error'] = type(finalization_error).__name__ + ': ' + str(finalization_error)
                print(json.dumps({'original_error': report.get('error'), 'finalization_error': report['finalization_error']}), file=sys.stderr, flush=True)
        print(json.dumps({'passed': report['passed'], 'report': str(control / 'report.json'), 'error': report.get('error')}), flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())

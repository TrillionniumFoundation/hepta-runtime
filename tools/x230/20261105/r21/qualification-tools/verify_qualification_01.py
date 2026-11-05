#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Independently verify R21 source, fresh artifacts, raw logs and release copies.

This program does not import the launcher, rerun tests, compile, repair evidence,
or accept qualification solely because its report says qualified=true.
"""
import argparse
import collections
import datetime
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import create_component_chain_01 as component_chain_policy

DEFAULT_ROOT = Path('/home/qian/hepta-runtime-optimization-20261105-r21')
BASELINE = Path('/home/qian/hepta-runtime-optimization-20261104-r19/source')
CARGO_HOME = '/home/qian/hepta-runtime-optimization-20261023/cargo-home-a32-a33-r02'
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
STAGES = ['format', 'fmt-check', 'harness-tests', 'clippy', 'test-build', 'isolated-tests', 'audit-isolated-tests', 'release']


def require(value, message):
    if not value:
        raise ValueError(message)


def fingerprint(path, single_link=False):
    """An independent reader: validate type, complete byte count and stability."""
    path = Path(path)
    require(path.absolute() == path.resolve(), 'symlink in evidence path: ' + str(path))
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    fd = os.open(path, flags)
    try:
        initial = os.fstat(fd)
        require(stat.S_ISREG(initial.st_mode) and (not single_link or initial.st_nlink == 1), 'invalid evidence file: ' + str(path))
        h, size = hashlib.sha256(), 0
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
            size += len(chunk)
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        expected = tuple(getattr(initial, key) for key in fields)
        require(size == initial.st_size and all(tuple(getattr(s, key) for key in fields) == expected
                for s in (os.fstat(fd), path.lstat())), 'evidence changed while reading: ' + str(path))
        return {'size': size, 'sha256': h.hexdigest()}
    finally:
        os.close(fd)


def read_tree(root):
    require(root.is_dir() and root.absolute() == root.resolve(), 'invalid source directory')
    result = {}
    for path in sorted(root.rglob('*')):
        mode = path.lstat().st_mode
        require(stat.S_ISDIR(mode) or stat.S_ISREG(mode), 'unsupported source entry: ' + str(path))
        if stat.S_ISREG(mode):
            result[path.relative_to(root).as_posix()] = fingerprint(path, single_link=True)
    return result


def inputs(tree):
    return {path: row['sha256'] for path, row in tree.items()
            if path in {'Cargo.toml', 'Cargo.lock', 'rustfmt.toml'} or path.startswith(('src/', 'examples/'))}


def cargo_configuration_paths(source):
    found = set()
    directory = source
    while True:
        for name in ('config', 'config.toml'):
            found.add(directory / '.cargo' / name)
        if directory == directory.parent:
            break
        directory = directory.parent
    found.update(Path(CARGO_HOME) / name for name in ('config', 'config.toml'))
    return sorted(found)


def same_bytes(left, right):
    with Path(left).open('rb') as a, Path(right).open('rb') as b:
        while True:
            x, y = a.read(1024 * 1024), b.read(1024 * 1024)
            if x != y:
                return False
            if not x:
                return True


def validate_root_artifacts(events, source, target):
    manifest = str(source / 'Cargo.toml')
    roots = [e for e in events if e.get('reason') == 'compiler-artifact' and e.get('manifest_path') == manifest]
    require(bool(roots) and all(e.get('fresh') is False for e in roots), 'root crate artifacts were reused')
    tests = [e for e in events if e.get('reason') == 'compiler-artifact' and e.get('profile', {}).get('test') and e.get('executable')]
    require(len(tests) == 5 and len({e['executable'] for e in tests}) == 5, 'expected five unique test executables')
    for event in tests:
        require(event.get('manifest_path') == manifest and event.get('fresh') is False, 'test does not belong to newly built root crate')
        require(Path(event['executable']).is_absolute() and Path(event['executable']).is_relative_to(target / 'debug'), 'test artifact outside fresh target')
        require(Path(event['target']['src_path']).is_relative_to(source), 'test source outside candidate')
    finished = [e for e in events if e.get('reason') == 'build-finished']
    require(len(finished) == 1 and finished[0].get('success') is True, 'test build did not finish successfully')
    return roots, tests


def stage_commands(source, out):
    cargo = ['/home/qian/.cargo/bin/cargo', '+1.95.0']
    harness = source / 'tools/x230/20261028'
    return [cargo + ['fmt', '--all'], cargo + ['fmt', '--all', '--', '--check'],
            ['/usr/bin/python3', '-B', '-m', 'unittest', 'discover', '-s', str(harness), '-p', '*_tests.py', '-v'],
            cargo + ['clippy', '--offline', '--locked', '--all-targets', '--all-features', '--', '-D', 'warnings'],
            cargo + ['test', '--offline', '--locked', '--all-targets', '--all-features', '--no-run', '--message-format=json'],
            ['/usr/bin/python3', str(harness / 'run_isolated_tests.py'), '--artifacts', str(out / 'retained-artifacts.jsonl'),
             '--source-manifest', str(out / 'source-map.json'), '--output', str(out / 'isolated-tests'), '--timeout', '180'],
            ['/usr/bin/python3', str(harness / 'audit_isolated_tests.py'), '--evidence', str(out / 'isolated-tests'),
             '--output', str(out / 'isolated-tests.audit.json')],
            cargo + ['build', '--offline', '--locked', '--all-features', '--release', '--bins', '--examples']]


def verify(root, expected_jobs, chain_path, chain_hash, manifest_hash):
    source, target, out = root / 'source', root / 'target-fresh-01', root / 'qualification-01'
    evidence, checks = {}, {}
    receipt = {'schema': 'hepta-x230-independent-acceptance/v2', 'attempt': 1, 'accepted': False, 'checks': checks,
               'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'root': str(root)}

    def digest(path):
        path = Path(path)
        row = fingerprint(path)
        previous = evidence.setdefault(str(path), row)
        require(previous == row, 'evidence changed between reads: ' + str(path))
        return row['sha256']

    def document(path):
        expected = digest(path)
        raw = Path(path).read_bytes()
        require(hashlib.sha256(raw).hexdigest() == expected, 'JSON changed during read: ' + str(path))
        return json.loads(raw)

    def json_lines(path):
        expected = digest(path)
        raw = Path(path).read_bytes()
        require(hashlib.sha256(raw).hexdigest() == expected, 'JSONL changed during read: ' + str(path))
        return [json.loads(line) for line in raw.decode().splitlines() if line.strip()]

    def check(name, value):
        checks[name] = bool(value)
        require(value, name)

    try:
        require(root == DEFAULT_ROOT and root.is_dir() and root.resolve() == root.absolute(), 'invalid reserved R21 root')
        prep = document(root / 'preparation.json')
        freeze = document(root / 'source-freeze-01.json')
        launch = document(root / 'qualification-launch-01.json')
        outcome = document(root / 'qualification-exit-01.json')
        report = document(out / 'report.json')
        middle = document(root / 'source-middle-01.json')
        after = document(root / 'source-after-01.json')
        tool_path = root / 'tools/qualification-tools-manifest-01.json'
        tools = document(tool_path)
        tool_identities = {name: fingerprint(root / 'tools' / name, single_link=True) for name in sorted(TOOL_NAMES)}
        check('three_protected_tools_and_manifest_bound', digest(tool_path) == manifest_hash
              and tools.get('schema') == 'hepta-x230-qualification-tools/v1' and tools.get('files') == tool_identities
              and set(tools['files']) == TOOL_NAMES
              and freeze['tools_manifest'] == launch['tools_manifest'] == {'path': str(tool_path), **fingerprint(tool_path), 'files': tool_identities}
              and Path(__file__).absolute() == root / 'tools/verify_qualification_01.py')
        for name, row in tool_identities.items():
            require(digest(root / 'tools' / name) == row['sha256'], 'tool changed during binding')
        chain_binding = component_chain_policy.validate_chain(chain_path, chain_hash, expected_jobs, root)
        check('component_chain_sources_and_producers_bound', digest(chain_path) == chain_hash
              and freeze['component_chain'] == launch['component_chain'] == chain_binding
              and chain_binding['baseline_source_sha256'] == BASELINE_JOBS_SHA256
              and chain_binding['final_source_sha256'] == expected_jobs
              and chain_binding['producer_chain_verified'] is True
              and chain_binding['final_was_directly_coldprocess_tested'] is False
              and chain_binding['independent_raw_audits_required_before_adoption'] is True)
        for row in chain_binding['referenced_files']:
            path = Path(row['path'])
            require(fingerprint(path, single_link=True) == {'size': row['size'], 'sha256': row['sha256']}
                    and digest(path) == row['sha256'], 'component-chain reference changed')
        baseline_bindings = {name: fingerprint(BASELINE.parent / name) for name in BASELINE_PINS}
        check('accepted_baseline_evidence_and_three_binaries_bound', all(digest(BASELINE.parent / name) == expected for name, expected in BASELINE_PINS.items())
              and baseline_bindings == freeze['baseline_bindings'])
        baseline_freeze = document(BASELINE.parent / 'source-freeze-02.json')
        baseline_report = document(BASELINE.parent / 'qualification-02/report.json')
        baseline_acceptance = document(BASELINE.parent / 'independent-acceptance-02.json')
        check('baseline_acceptance_and_source_maps_valid', baseline_acceptance.get('accepted') is True
              and bool(baseline_acceptance['checks']) and all(v is True for v in baseline_acceptance['checks'].values())
              and baseline_acceptance['qualified_report_sha256'] == BASELINE_PINS['qualification-02/report.json']
              and baseline_acceptance['source_freeze_sha256'] == BASELINE_PINS['source-freeze-02.json']
              and baseline_report.get('qualified') is True and baseline_report['source'] == str(BASELINE)
              and baseline_report['source_input'] == baseline_report['source_tested'] == baseline_report['source_after'] == baseline_freeze['source_inputs_before'])
        check('preparation_and_freeze_bound', prep['source'] == freeze['baseline_source'] == str(BASELINE)
              and prep['candidate_root'] == str(root) and freeze['source'] == str(source)
              and freeze['preparation_sha256'] == digest(root / 'preparation.json')
              and launch['source_freeze_sha256'] == digest(root / 'source-freeze-01.json'))
        expected_baseline = {}
        for row in prep['files']:
            path = row['path']
            require(isinstance(path, str) and not Path(path).is_absolute() and '..' not in Path(path).parts
                    and path == Path(path).as_posix() and path not in ('', '.') and path not in expected_baseline, 'invalid preparation entry')
            expected_baseline[path] = {'size': row['size'], 'sha256': row['sha256']}
        baseline, actual = read_tree(BASELINE), read_tree(source)
        actual_inputs = inputs(actual)
        check('baseline_full_tree_281_preserved', len(baseline) == 281 and baseline == expected_baseline == baseline_freeze['source_full_before'])
        check('candidate_full_tree_281_frozen', len(actual) == 281 and actual == freeze['source_full_before'])
        check('actual_source_before_middle_after_identical', freeze.get('schema') == 'hepta-x230-source-freeze/v2'
              and middle.get('schema') == 'hepta-x230-source-middle/v1' and after.get('schema') == 'hepta-x230-source-after/v1'
              and middle['source'] == after['source'] == str(source) and actual == middle['source_full'] == after['source_full']
              and actual_inputs == middle['source_inputs'] == after['source_inputs']
              and middle.get('baseline_full_unchanged') is after.get('baseline_full_unchanged') is True
              and middle.get('observed_during_qualifier') is True
              and middle['qualifier_pid'] == launch['qualifier_pid'] and middle['qualifier_start_ticks'] == launch['qualifier_start_ticks']
              and outcome['source_middle_sha256'] == digest(root / 'source-middle-01.json')
              and outcome['source_after_sha256'] == digest(root / 'source-after-01.json')
              and outcome.get('source_full_before_middle_after_equal') is True)
        config_paths = cargo_configuration_paths(source)
        configurations = {str(path): fingerprint(path) if os.path.lexists(path) else None for path in config_paths}
        check('cargo_configuration_candidates_unchanged', configurations == freeze['cargo_configurations']
              == launch['cargo_configurations'] == middle['cargo_configurations'] == after['cargo_configurations'])
        for path in config_paths:
            if os.path.lexists(path):
                digest(path)
        changed = [p for p in sorted(set(actual) | set(baseline)) if actual.get(p) != baseline.get(p)]
        check('only_expected_jobs_rs_changed', set(actual) == set(baseline) and changed == ['src/mcp/runtime/jobs.rs']
              and actual['src/mcp/runtime/jobs.rs']['sha256'] == freeze['expected_jobs_sha256'] == expected_jobs
              and baseline['src/mcp/runtime/jobs.rs']['sha256'] == BASELINE_JOBS_SHA256)
        check('jobctl_source_preserved', actual['src/bin/jobctl.rs']['sha256'] == JOBCTL_SOURCE_SHA256)
        check('all_219_source_bindings_match', len(actual_inputs) == 219 and actual_inputs == freeze['source_inputs_before']
              == report['source_input'] == report['source_tested'] == report['source_after'] == document(out / 'source-map.json'))
        qualifier = source / 'tools/x230/20261028/qualify.py'
        check('original_qualifier_and_launcher_bound', digest(qualifier) == freeze['qualifier_sha256'] == launch['qualifier_sha256'] == QUALIFIER_SHA256
              and digest(root / 'tools/qualify_candidate_01.py') == launch['launcher_sha256'])
        expected_argv = ['/usr/bin/python3', '-B', '-u', str(qualifier), '--source', str(source), '--output', str(out),
                         '--target', str(target), '--cargo-home', CARGO_HOME, '--jobs', '2', '--stage-timeout']
        check('fresh_target_and_toolchain_bound', launch['argv'][:-1] == expected_argv and 60 <= int(launch['argv'][-1]) <= 14400
              and launch.get('target_asserted_nonexistent') is True and launch.get('target_created_empty') is True
              and launch.get('output_asserted_nonexistent') is True and launch.get('automatic_retries') == 0
              and launch.get('environment_policy') == 'explicit-allowlist/v2-no-wrapper-keys' and launch.get('user') == 'qian'
              and launch['minimum_free_bytes'] == 16 * 1024 ** 3 and launch['free_bytes_before'] >= 16 * 1024 ** 3
              and launch['toolchain']['cargo'].startswith('cargo 1.95.0 ') and launch['toolchain']['rustc'].startswith('rustc 1.95.0 '))
        expected_environment = {'HOME': '/home/qian', 'USER': 'qian', 'LOGNAME': 'qian',
            'PATH': '/home/qian/.cargo/bin:/usr/local/bin:/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
            'RUSTUP_HOME': '/home/qian/.rustup', 'RUSTUP_AUTO_INSTALL': '0', 'CARGO_HOME': CARGO_HOME,
            'CARGO_NET_OFFLINE': 'true', 'CARGO_INCREMENTAL': '0', 'CARGO_BUILD_JOBS': '2',
            'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONNOUSERSITE': '1', 'TOKIO_WORKER_THREADS': '2'}
        check('environment_and_qualifier_reaped', freeze.get('attempt') == launch.get('attempt') == outcome.get('attempt') == 1
              and launch.get('environment') == expected_environment
              and type(launch.get('qualifier_pid')) is int and launch['qualifier_pid'] > 1
              and type(launch.get('qualifier_start_ticks')) is int and launch['qualifier_start_ticks'] > 0
              and outcome.get('qualifier_pid') == launch['qualifier_pid']
              and outcome.get('qualifier_start_ticks') == launch['qualifier_start_ticks']
              and outcome.get('qualifier_reaped') is True and outcome.get('qualifier_returncode') == 0
              and outcome.get('qualifier_proc_absent') is True
              and outcome.get('qualifier_process_group_absent') is True
              and not Path('/proc', str(launch['qualifier_pid'])).exists())
        qstage = outcome['stage']
        check('owned_qualifier_stage_and_toolchain_probes_bound', qstage['name'] == 'fresh-qualification'
              and qstage['argv'] == launch['argv'] and qstage['cwd'] == str(source)
              and qstage['pid'] == qstage['process_group'] == launch['qualifier_pid']
              and qstage['start_ticks'] == launch['qualifier_start_ticks']
              and qstage['returncode'] == 0 and qstage.get('waited_and_reaped') is qstage.get('proc_absent') is qstage.get('process_group_absent') is True
              and qstage.get('timed_out') is False and qstage.get('automatic_retries') == 0
              and len(launch['toolchain_probes']) == 2)
        for stream in ('stdout', 'stderr'):
            expected_path = root / ('qualification-control-01/fresh-qualification.' + stream)
            require(qstage[stream] == {'path': str(expected_path), **fingerprint(expected_path)}
                    and digest(expected_path) == outcome['launcher_' + stream + '_sha256'], 'qualifier original stream differs')
        for program, probe in zip(('cargo', 'rustc'), launch['toolchain_probes']):
            require(probe['name'] == 'toolchain-' + program and probe['argv'] == ['/home/qian/.cargo/bin/' + program, '+1.95.0', '--version']
                    and probe['cwd'] == str(source) and probe['returncode'] == 0 and probe['timed_out'] is False
                    and probe['waited_and_reaped'] is probe['proc_absent'] is probe['process_group_absent'] is True
                    and type(probe['pid']) is int and probe['pid'] > 1 and type(probe['start_ticks']) is int and probe['start_ticks'] > 0,
                    'toolchain child receipt differs')
            for stream in ('stdout', 'stderr'):
                path = root / ('qualification-control-01/toolchain-' + program + '.' + stream)
                require(probe[stream] == {'path': str(path), **fingerprint(path)}, 'toolchain stream identity differs')
                digest(path)
            require(Path(probe['stdout']['path']).read_text().strip() == launch['toolchain'][program], 'toolchain version stream differs')
        check('qualifier_and_wrapper_exit_zero', report.get('qualified') is True and report['source'] == str(source) and report['jobs'] == 2
              and report.get('automatic_test_retries') == 0 and report.get('service_changes') is False
              and outcome.get('returncode') == 0 and outcome.get('success') is True
              and outcome.get('source_full_before_after_equal') is True and outcome.get('source_inputs_before_after_equal') is True
              and outcome.get('automatic_retries') == 0 and outcome['report_sha256'] == digest(out / 'report.json')
              and outcome['launcher_stdout_sha256'] == digest(root / 'qualification-control-01/fresh-qualification.stdout')
              and outcome['launcher_stderr_sha256'] == digest(root / 'qualification-control-01/fresh-qualification.stderr'))
        stages = report['stages']
        check('eight_exact_stage_commands_exit_zero', [s['name'] for s in stages] == STAGES
              and [s['command'] for s in stages] == stage_commands(source, out)
              and all(type(s.get('returncode')) is int and s['returncode'] == 0 for s in stages))
        for row in stages:
            name = row['name']
            stdout = out / ('cargo-no-run.jsonl' if name == 'test-build' else name + '.stdout')
            require(digest(stdout) == row['stdout_sha256'] and digest(out / (name + '.stderr')) == row['stderr_sha256'], 'stage log binding differs: ' + name)
        checks['all_original_stage_logs_match'] = True
        harness = {p.name: digest(p) for p in sorted((source / 'tools/x230/20261028').glob('*.py'))}
        check('harness_preserved', harness == report['harness_before'] == report['harness_after'])
        events = json_lines(out / 'cargo-no-run.jsonl')
        roots, tests = validate_root_artifacts(events, source, target)
        checks['all_root_artifacts_and_five_tests_fresh_false'] = True
        check('artifact_sources_are_frozen_inputs', all(Path(e['target']['src_path']).is_relative_to(source)
              and Path(e['target']['src_path']).relative_to(source).as_posix() in actual_inputs for e in roots))
        receipt['root_artifacts'] = [{'target': e['target']['name'], 'kind': e['target']['kind'], 'test': e['profile']['test'], 'fresh': e['fresh']} for e in roots]
        retained = json_lines(out / 'retained-artifacts.jsonl')
        transformed, binaries = [], {}
        for event in events:
            copy = dict(event)
            if event in tests:
                original = Path(event['executable'])
                kept = out / 'test-binaries' / original.name
                original_hash = digest(original)
                require(digest(kept) == original_hash and same_bytes(original, kept), 'retained test differs from fresh executable')
                copy['executable'] = str(kept)
                binaries[str(kept)] = {'sha256': original_hash, 'target': event['target']}
            transformed.append(copy)
        check('retained_events_and_test_binaries_bound', retained == transformed
              and {str(p) for p in (out / 'test-binaries').iterdir()} == set(binaries))
        isolated = out / 'isolated-tests'
        summary = document(isolated / 'summary.json')
        audit = document(out / 'isolated-tests.audit.json')
        rows = json_lines(isolated / 'tests.jsonl')
        commands = json_lines(isolated / 'commands.jsonl')
        check('isolated_summary_and_audit_success', summary.get('success') is True and audit.get('success') is True
              and not summary.get('enumeration_errors') and not summary.get('fatal_error') and not audit.get('errors')
              and summary.get('filter') == audit.get('expected_filter') == '' and summary.get('retries') == 0
              and summary['case_timeout_seconds'] == 180 and audit['evidence'] == str(isolated)
              and audit['auditor_sha256'] == digest(source / 'tools/x230/20261028/audit_isolated_tests.py'))
        check('isolated_input_files_bound', summary['artifacts_path'] == str(out / 'retained-artifacts.jsonl')
              and summary['source_manifest_path'] == str(out / 'source-map.json')
              and summary['artifacts_sha256'] == digest(out / 'retained-artifacts.jsonl') == digest(isolated / 'cargo-artifacts.jsonl')
              and summary['source_manifest_sha256'] == digest(out / 'source-map.json') == digest(isolated / 'source-manifest.input')
              and all(digest(isolated / name) == expected for name, expected in audit['input_sha256'].items())
              and set(audit['input_sha256']) == {'summary.json', 'cargo-artifacts.jsonl', 'source-manifest.input', 'commands.jsonl', 'tests.jsonl'})
        counts = collections.Counter(r['status'] for r in rows)
        check('complete_counts_no_failures_or_retries', set(counts) <= {'passed', 'ignored'} and counts['passed'] == 1637 and counts['ignored'] == 33
              and all(counts[k] == summary[k] == audit[k] for k in ('passed', 'failed', 'ignored'))
              and len(rows) == summary['selected'] == audit['selected'] == 1670 and audit['executed'] == counts['passed']
              and len({(r['binary'], r['name']) for r in rows}) == len(rows)
              and all(r.get('attempt') == (0 if r['status'] == 'ignored' else 1) and r.get('executed') is (r['status'] != 'ignored') for r in rows))
        receipt['test_counts'] = {k: summary[k] for k in ('passed', 'failed', 'ignored', 'selected')}
        check('five_summary_and_audit_binaries_bound', len(summary['binaries']) == len(audit['binaries']) == 5
              and {b['path'] for b in summary['binaries']} == {b['path'] for b in audit['binaries']} == set(binaries)
              and all(b['sha256'] == binaries[b['path']]['sha256'] and b['target'] == binaries[b['path']]['target'] for b in summary['binaries']))
        audited_binaries = {b['path']: b for b in audit['binaries']}
        for b in summary['binaries']:
            reviewed = audited_binaries[b['path']]
            require(reviewed['recorded_before_sha256'] == reviewed['current_after_sha256'] == b['sha256']
                    and reviewed['inventory_count'] == b['inventory_count'] and reviewed['ignored_names'] == b['ignored_names'], 'audited binary differs')
        # Independently decompress every stdout/stderr; bind actual bytes to the
        # auditor and inspect exact libtest verdicts and enumeration inventories.
        audited_commands = {c['stdout_gzip']: c for c in audit['commands']}
        require(len(audited_commands) == len(audit['commands']) == len(commands) == counts['passed'] + 10, 'command count or uniqueness differs')
        command_by_argv, inventories, ignored = {}, {}, {}
        for command in commands:
            argv = tuple(command['argv'])
            require(argv not in command_by_argv and argv[0] in binaries and command['exit_code'] == 0 and command['timed_out'] is False, 'invalid or repeated test command')
            command_by_argv[argv] = command
            reviewed = audited_commands[command['stdout_gzip']]
            plain = {}
            for stream in ('stdout', 'stderr'):
                name = command[stream + '_gzip']
                require(Path(name).name == name, 'log escapes evidence directory')
                gzip_hash = digest(isolated / name)
                with gzip.open(isolated / name, 'rb') as handle:
                    raw = handle.read(32 * 1024 * 1024 + 1)
                require(len(raw) <= 32 * 1024 * 1024, 'test log exceeds verification bound')
                proof = reviewed[stream]
                require(gzip_hash == proof['gzip_sha256'] and hashlib.sha256(raw).hexdigest() == proof['plain_sha256']
                        and len(raw) == proof['bytes'] == command[stream + '_bytes'] and not proof.get('errors'), 'raw test log binding differs')
                plain[stream] = raw.decode('utf-8')
            if argv[1:] == ('--list', '--format', 'terse'):
                names = [line[:-6] for line in plain['stdout'].splitlines() if line.endswith(': test')]
                require(len(names) == len(set(names)), 'duplicate test inventory')
                inventories[argv[0]] = set(names)
            elif argv[1:] == ('--list', '--format', 'terse', '--ignored'):
                ignored[argv[0]] = {line[:-6] for line in plain['stdout'].splitlines() if line.endswith(': test')}
            else:
                require(len(argv) == 4 and argv[2:] == ('--exact', '--test-threads=1'), 'unexpected test command arguments')
                verdicts = re.findall(r'^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;', plain['stdout'], re.MULTILINE)
                require(bool(verdicts) and verdicts[-1][:5] == ('ok', '1', '0', '0', '0')
                        and all(v[0] == 'ok' and v[2] == '0' for v in verdicts)
                        and ('test ' + argv[1] + ' ... ') in plain['stdout'], 'raw libtest verdict differs')
        require(set(inventories) == set(ignored) == set(binaries), 'missing independent test inventory')
        for b in summary['binaries']:
            selected = {r['name'] for r in rows if r['binary'] == b['path']}
            require(selected == inventories[b['path']] and len(selected) == b['inventory_count']
                    and ignored[b['path']] == set(b['ignored_names']), 'test selection is incomplete')
        for row in rows:
            require(row['binary'] in binaries and row['binary_sha256'] == binaries[row['binary']]['sha256'], 'test row uses a different binary')
            if row['status'] == 'ignored':
                require(row['name'] in ignored[row['binary']], 'unlisted test ignored')
            else:
                expected_argv = (row['binary'], row['name'], '--exact', '--test-threads=1')
                require(tuple(row['argv']) == expected_argv, 'test row argv differs')
                cmd = command_by_argv[expected_argv]
                require(all(row[key] == value for key, value in cmd.items()), 'test row differs from executed command')
                require(row['stdout_proof'] == audited_commands[row['stdout_gzip']]['stdout'], 'test row proof differs from audit')
        checks['all_raw_logs_inventories_and_exact_test_verdicts_match'] = True
        copied = report['binaries']
        check('complete_release_binary_set', set(copied) == {'hepta-runtime', 'hepta-runtime-jobctl', 'native_process_driver'})
        receipt['binaries'] = {}
        for name, row in sorted(copied.items()):
            original = target / 'release' / ('examples/native_process_driver' if name == 'native_process_driver' else name)
            kept = out / name
            actual_hash = digest(kept)
            require(row['path'] == str(kept) and row['sha256'] == actual_hash == digest(original)
                    and same_bytes(original, kept), 'release source/copy identity differs: ' + name)
            receipt['binaries'][name] = {'path': str(kept), 'sha256': actual_hash, 'size': evidence[str(kept)]['size']}
        reference = BASELINE.parent / 'qualification-02/hepta-runtime-jobctl'
        check('jobctl_release_identical_to_baseline', freeze['baseline_jobctl_binary'] == {'path': str(reference), 'sha256': JOBCTL_BINARY_SHA256}
              and digest(reference) == digest(out / 'hepta-runtime-jobctl') == JOBCTL_BINARY_SHA256
              and same_bytes(reference, out / 'hepta-runtime-jobctl'))
        check('all_sources_and_evidence_stable_during_verification', read_tree(source) == actual and read_tree(BASELINE) == baseline
              and {str(path): fingerprint(path) if os.path.lexists(path) else None for path in config_paths} == configurations
              and all(fingerprint(Path(path)) == row for path, row in evidence.items()))
        receipt['source_input_count'] = len(actual_inputs)
        receipt['source_full_count'] = len(actual)
        receipt['changed_paths'] = changed
        receipt['qualified_report_sha256'] = evidence[str(out / 'report.json')]['sha256']
        receipt['source_freeze_sha256'] = evidence[str(root / 'source-freeze-01.json')]['sha256']
        receipt['source_middle_sha256'] = evidence[str(root / 'source-middle-01.json')]['sha256']
        receipt['source_after_sha256'] = evidence[str(root / 'source-after-01.json')]['sha256']
        receipt['component_chain'] = launch['component_chain']
        receipt['tools_manifest'] = launch['tools_manifest']
        receipt['baseline_bindings'] = baseline_bindings
        receipt['retained_test_binaries'] = [{'path': path, 'sha256': row['sha256'], 'target': row['target']['name']} for path, row in binaries.items()]
        receipt['evidence_file_count'] = len(evidence)
        receipt['evidence_manifest_sha256'] = hashlib.sha256(json.dumps(evidence, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        receipt['accepted'] = all(checks.values())
    except Exception as error:
        checks['verification_completed'] = False
        receipt['error'] = type(error).__name__ + ': ' + str(error)
    receipt['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    return receipt


def self_test():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / 'src').mkdir()
        (root / 'src/file.rs').write_bytes(b'one')
        before = read_tree(root)
        (root / 'src/file.rs').write_bytes(b'two')
        require(read_tree(root) != before, 'mutation escaped verification')
        (root / 'link').symlink_to(root / 'src/file.rs')
        try:
            read_tree(root)
        except ValueError:
            pass
        else:
            raise AssertionError('symlink accepted')
        events = [{'reason': 'compiler-artifact', 'manifest_path': str(root / 'Cargo.toml'), 'fresh': False,
                   'profile': {'test': True}, 'executable': str(root / 'target/debug' / str(i)),
                   'target': {'src_path': str(root / 'src' / (str(i) + '.rs'))}} for i in range(5)]
        events.append({'reason': 'build-finished', 'success': True})
        validate_root_artifacts(events, root, root / 'target')
        events[2]['fresh'] = True
        try:
            validate_root_artifacts(events, root, root / 'target')
        except ValueError:
            pass
        else:
            raise AssertionError('stale artifact accepted')
        events[2]['fresh'] = False
        events[2]['executable'] = '/old-target/stale'
        try:
            validate_root_artifacts(events, root, root / 'target')
        except ValueError:
            pass
        else:
            raise AssertionError('foreign target accepted')
    print(json.dumps({'self_test': True, 'compilation_started': False}))
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=DEFAULT_ROOT)
    parser.add_argument('--expected-jobs-sha256')
    parser.add_argument('--component-chain', type=Path)
    parser.add_argument('--expected-component-chain-sha256')
    parser.add_argument('--expected-tools-manifest-sha256')
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if not re.fullmatch('[0-9a-f]{64}', args.expected_jobs_sha256 or ''):
        parser.error('--expected-jobs-sha256 must be lowercase SHA256')
    for key in ('expected_component_chain_sha256', 'expected_tools_manifest_sha256'):
        if not re.fullmatch('[0-9a-f]{64}', getattr(args, key) or ''):
            parser.error('--' + key.replace('_', '-') + ' must be lowercase SHA256')
    if args.component_chain is None:
        parser.error('--component-chain is required')
    root = args.root.absolute()
    output = root / 'independent-acceptance-01.json'
    require(not os.path.lexists(output), 'acceptance receipt already exists')
    receipt = verify(root, args.expected_jobs_sha256, args.component_chain.absolute(),
                     args.expected_component_chain_sha256, args.expected_tools_manifest_sha256)
    with output.open('x') as stream:
        stream.write(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'accepted': receipt['accepted'], 'receipt': str(output), 'receipt_sha256': fingerprint(output)['sha256'],
                      'checks_passed': sum(value is True for value in receipt['checks'].values()), 'checks_total': len(receipt['checks']),
                      'test_counts': receipt.get('test_counts'), 'binaries': receipt.get('binaries'), 'error': receipt.get('error')}, sort_keys=True))
    return 0 if receipt['accepted'] else 1


if __name__ == '__main__':
    sys.exit(main())

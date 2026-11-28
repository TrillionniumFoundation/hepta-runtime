# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Join actual aggregate processes to the frozen private storage qualifications.

The ordinary qualifier owns every process group. Its completion hook records
the real PID, wait result and complete streams in the private owner's receipt
format; these are never synthesized from a retained PASS assertion.
"""
from pathlib import Path
import json
import math
import os
import signal
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))

import hia_native_result_storage_qualification as q
import hia_native_result_storage_reference as reference
from result_storage_registry import encoded, profile, regular, require, sha

KEYS = {
    'request_storage_json': 'storage_json',
    'request_record_validation': 'record_validation',
    'request_safe_dto': 'safe_dto',
    'request_retention': 'retention',
    'request_record_io': 'record_io',
    'request_store_directory': 'directory',
    'request_archive_metadata': 'archive_metadata',
    'request_archive_publish': 'archive_publish',
    'request_archive_store': 'archive_store',
}
NATIVE = 'result-storage-native'
ORIGINAL = 'result-storage-original'
ORIGINAL_PROCESSES = 'result-storage-original-processes'
ORIGINAL_SUITE = 'result-storage-original-suite.json'
CONTROL = 'result-storage-evidence-controls'
CONTROL_INPUT = 'result-storage-controls-input.json'
NAMES = {domain: ('test_result_' + domain + '.py' if domain in q.PURE
    else 'result-storage-' + domain.replace('_', '-')) for domain in q.PURE + q.FS}
TESTS = tuple(NAMES.values())
RUST_NAMES = {domain: 'storage-' + domain.replace('_', '-') + '-rust-compare'
    for domain in reference.DOMAINS}
CONTROL_LABELS = (
    'native-source-byte', 'native-image-byte', 'static-elf-byte',
    'compiler-empty-observer', 'native-complete-output', 'native-summary-count',
    'native-completion-argv', 'native-completion-timeout', 'native-completion-stdout',
    'native-seal-byte', 'native-resealed-missing-domain', 'native-resealed-execution-count',
    'native-resealed-build-pin', 'original-comparison-status', 'original-reference-source',
    'original-locked-crate', 'original-elf-byte', 'original-compile-command',
    'original-complete-input', 'original-complete-output', 'original-replay-cwd',
    'original-replay-timeout', 'original-outer-timeout',
    'original-resealed-replay-command', 'original-filesystem-full-output',
    'native-raw-value-complete-input', 'native-raw-value-complete-output',
    'native-raw-value-completion', 'original-raw-value-complete-output',
    'original-raw-value-resealed-command',
    'native-retention-missing-worker', 'native-retention-worker-timeout',
    'native-retention-worker-command', 'native-retention-worker-process-group',
    'native-retention-worker-output', 'native-retention-worker-domain',
    'native-retention-overlong-worker', 'native-retention-collected-record',
    'native-retention-foreign-parent',
)


def sources(root):
    return (*q.source_pins(root), 'scripts/hia_native_result_storage_pipeline.py',
        'scripts/check_result_storage_evidence.py', 'native/result_storage_integration.md')


def build_storage(hepta, build, root):
    root, build = Path(root).resolve(strict=True), Path(build).resolve()
    path = build / 'result-storage-build.json'
    if path.exists():
        q.build_evidence(root, build, hepta=hepta)
    else:
        q.build_storage(hepta, build, root)
    return path


def bundle_for(root, output, report):
    root, output = Path(root).resolve(strict=True), Path(output).resolve(strict=True)
    fixed = profile(root);paths = set()
    for key, domain in KEYS.items():
        row = report['modules'][key]
        require(row['source'] == 'native/' + key + '.hepta'
            and row['builder'] == 'result_storage', 'registered storage owner differs')
        path = q.confined(output, row['manifest'])
        require(q.pin(path)['sha256'] == row['sha256'], 'storage bundle changed')
        paths.add(path)
    require(len(paths) == 1, 'storage owners lost their shared fixed build')
    path = paths.pop()
    require(path == output / 'build/result-storage-build.json'
        and len(fixed['modules']) == 30, 'storage build location or domain differs')
    return path


def test_commands(root, output, report):
    bundle = bundle_for(root, output, report)
    return {NAMES[domain]: command for domain, command in
        q.commands(root, bundle.parent, Path(output) / NATIVE).items()}


def process_folder(output, name):
    for domain, expected in NAMES.items():
        if name == expected:
            return Path(output) / NATIVE / 'processes' / domain
    for domain, expected in RUST_NAMES.items():
        if name == expected:
            return Path(output) / ORIGINAL_PROCESSES / domain
    return None


def finish_actual_process(root, output, check, process, stdout, stderr):
    """Called by record_check with its live Popen object after the real wait.

    Only this invocation's new process group is retired. The process result
    and failure streams remain evidence even when normal admission will fail.
    Outer-parent death is deliberately not claimed as a qualified boundary.
    """
    folder = process_folder(output, check['name'])
    require(folder is not None, 'unknown storage process completion')
    folder.mkdir(mode=0o700, parents=True, exist_ok=False)
    started = time.monotonic();cleanup_error = None
    if process is not None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError as error:
            cleanup_error = repr(error)
    cleanup_elapsed = time.monotonic() - started
    row = {'schema': 'hepta.result-storage.actual-aggregate-process.v1',
        'command': check['command'], 'cwd': str(root),
        'timeout_seconds': check['timeout_seconds'], 'cleanup_seconds': 3,
        'cleanup_elapsed_seconds': cleanup_elapsed, 'cleanup_error': cleanup_error,
        'timed_out': check['timed_out'], 'exit_code': check['exit_code'],
        'pid': None if process is None else process.pid,
        'process_reaped': process is not None and process.returncode is not None,
        'elapsed_seconds': check['elapsed_seconds'],
        'outer_parent_death_cleanup_qualified': False,
        'actual_aggregate_check': check,
        'stdout': {'bytes': len(stdout), 'sha256': sha(stdout)},
        'stderr': {'bytes': len(stderr), 'sha256': sha(stderr)}}
    for name, raw in (('stdout', stdout), ('stderr', stderr), ('result.json', encoded(row))):
        with (folder / name).open('xb') as stream:
            stream.write(raw)
    require(cleanup_error is None and cleanup_elapsed <= 3,
        'storage process group cleanup failed; original evidence retained')


def completed_process(root, output, report, name, command, completed):
    row, summary = completed(output, report, name)
    elapsed = row.get('elapsed_seconds')
    require(row.get('command') == command and row.get('timeout_seconds') == 180
        and row.get('exit_code') == 0 and row.get('timed_out') is False
        and not row.get('start_error') and type(elapsed) in (int, float)
        and math.isfinite(elapsed) and 0 <= elapsed <= 180,
        'actual storage aggregate process is incomplete or changed')
    folder = process_folder(output, name)
    observed, stdout, stderr = q.process_evidence(folder, command, root)
    require(observed.get('schema') == 'hepta.result-storage.actual-aggregate-process.v1'
        and observed.get('actual_aggregate_check') == row
        and type(observed.get('pid')) is int and observed['pid'] > 0
        and observed.get('cleanup_error') is None
        and 0 <= observed.get('cleanup_elapsed_seconds', -1) <= 3
        and observed.get('outer_parent_death_cleanup_qualified') is False
        and regular(Path(output) / (name + '.stdout')) == stdout
        and regular(Path(output) / (name + '.stderr')) == stderr
        and not stderr and json.loads(stdout) == summary,
        'actual aggregate and owner process receipts disagree')
    return observed, summary


def retained(output, paths):
    output = Path(output).resolve(strict=True);values = {}
    for path in paths:
        path = Path(path)
        require(path.resolve(strict=True).is_relative_to(output) and not path.is_symlink(),
            'storage evidence escapes its qualification directory')
        values[path.relative_to(output).as_posix()] = q.pin(path)['sha256']
    return values


def native_evidence(root, output, report, completed, *, create=False):
    output = Path(output).resolve(strict=True)
    bundle = bundle_for(root, output, report);build = bundle.parent
    compiled = q.build_evidence(root, build, hepta=Path(report['compiler_checkout']))
    commands = test_commands(root, output, report);processes = {};receipts = {}
    for domain, name in NAMES.items():
        receipts[name], _ = completed_process(root, output, report, name, commands[name], completed)
        processes[domain] = str(process_folder(output, name))
    observed = q.native_evidence(root, build, output / NATIVE, processes)
    path = output / NATIVE / 'native-evidence.json'
    if create:
        with path.open('xb') as stream:
            stream.write(encoded(observed))
    require(q.object_at(path) == observed, 'complete storage native evidence changed')
    corpus = [path for path in (output / NATIVE).rglob('*') if path.is_file()]
    corpus.extend(output / (name + suffix) for name in TESTS for suffix in ('.stdout', '.stderr'))
    return {'schema': 'hepta.runtime.result-storage-native.v1', 'status': 'PASS',
        'native_evidence': q.pin(path), 'completed_processes': receipts,
        'artifact_sha256': retained(output, [build / name for name in compiled['artifact_pins']]),
        'corpus_sha256': retained(output, corpus), 'complete_native_domains': 13,
        'new_native_executions_by_admission': 0, 'new_original_executions_by_admission': 0,
        'production_activated': False, 'result_storage_closed': False}


def original_command(root, output, report, rustc, cargo, domain):
    require(domain in reference.DOMAINS, 'unknown storage reference domain')
    bundle = bundle_for(root, output, report);output = Path(output)
    seal = report['result_storage_evidence']['native_evidence']
    evidence = output / NATIVE / 'native-evidence.json'
    require(q.pin(evidence) == seal, 'storage native seal changed')
    return list(map(str, [sys.executable, '-I', '-B', Path(root) / 'tests/hia_native/compare_result_storage_original.py',
        '--root', root, '--build', bundle.parent, '--native', output / NATIVE,
        '--output', output / ORIGINAL / domain, '--native-evidence', evidence,
        '--native-evidence-sha256', seal['sha256'], '--rustc', Path(rustc).absolute(),
        '--cargo', Path(cargo).absolute(), '--domain', domain]))


def original_evidence(root, output, report, completed, domain):
    output = Path(output);bundle = bundle_for(root, output, report)
    folder = output / ORIGINAL / domain
    built = q.object_at(folder / 'build/result.json')
    require(built['rustc_path'] == report['rust_compiler']['invocation_path'],
        'storage original did not use the aggregate compiler invocation')
    command = original_command(root, output, report, built['rustc_path'], built['cargo_path'], domain)
    receipt, summary = completed_process(root, output, report, RUST_NAMES[domain], command, completed)
    seal = report['result_storage_evidence']['native_evidence']
    observed = reference.original_evidence(root, bundle.parent, output / NATIVE, folder, domain,
        output / NATIVE / 'native-evidence.json', seal['sha256'])
    expected = {'status': 'PASS', 'domain': domain,
        'original_requests': observed['original_requests'],
        'original_processes': observed['original_processes'], 'new_native_executions': 0,
        'complete_original_native_bytes_equal': True}
    require(summary == expected, 'actual storage original stdout omits part of its domain')
    paths = [path for path in folder.rglob('*') if path.is_file()]
    paths.extend(process_folder(output, RUST_NAMES[domain]).iterdir())
    paths.extend(output / (RUST_NAMES[domain] + suffix) for suffix in ('.stdout', '.stderr'))
    return {'schema': 'hepta.runtime.result-storage-original.v1', 'status': 'PASS',
        'domain': domain, 'owner_evidence': observed, 'completed_process': receipt,
        'artifact_sha256': retained(output, paths),
        'new_native_executions_by_admission': 0, 'new_original_executions_by_admission': 0,
        'production_activated': False, 'result_storage_closed': False}


def original_suite(root, output, report, completed):
    output = Path(output);observations = {};checks = {}
    for key, domain in KEYS.items():
        value = original_evidence(root, output, report, completed, domain)
        require(report['original_rust_comparisons'].get(key) == value,
            'storage original recipe differs before evidence controls')
        observations[domain] = value['owner_evidence']
        checks[domain] = value['completed_process']
    require(set(observations) == set(reference.DOMAINS), 'storage original group is incomplete')
    return {'schema': 'hepta.result-storage.original-suite.v1', 'status': 'PASS',
        'sources_unchanged': True, 'sources': q.source_pins(root), 'domains': 9,
        'new_native_executions': 0, 'production_activated': False, 'result_storage_closed': False,
        'native_evidence': report['result_storage_evidence']['native_evidence'],
        'checks': checks, 'original_evidence': observations}


def control_command(root, output):
    return list(map(str, [sys.executable, '-I', '-B', Path(root) / 'scripts/hia_native_result_storage_pipeline.py',
        '--run-controls', '--root', root, '--output', output, '--report', Path(output) / CONTROL_INPUT]))


def execute_controls(root, output, report_path):
    """Run the frozen evidence mutations, then bind their complete result bytes."""
    import contextlib
    import io
    import runpy
    root, output = Path(root).resolve(strict=True), Path(output).resolve(strict=True)
    report = q.object_at(report_path);bundle = bundle_for(root, output, report)
    native = output / NATIVE / 'native-evidence.json'
    require(q.pin(native) == report['result_storage_evidence']['native_evidence'],
        'storage control input native seal differs')
    command = list(map(str, [root / 'scripts/check_result_storage_evidence.py',
        '--root', root, '--build', bundle.parent, '--native', output / NATIVE,
        '--original', output / ORIGINAL, '--original-processes', output / ORIGINAL_PROCESSES,
        '--original-suite', output / ORIGINAL_SUITE, '--native-evidence', native,
        '--native-evidence-sha256', q.pin(native)['sha256'], '--output', output / CONTROL]))
    capture = io.StringIO();previous = sys.argv
    try:
        sys.argv = command
        with contextlib.redirect_stdout(capture):
            runpy.run_path(command[0], run_name='__main__')
    finally:
        sys.argv = previous
        if (output / CONTROL).is_dir():
            with (output / CONTROL / 'mutation-summary.stdout').open('xb') as stream:
                stream.write(capture.getvalue().encode())
    result = output / CONTROL / 'result.json'
    print(json.dumps({'status': 'PASS', 'mutation_summary': json.loads(capture.getvalue()),
        'complete_result': q.pin(result)}, sort_keys=True))


def control_evidence(root, output, report, completed):
    output = Path(output);snapshot_path = output / CONTROL_INPUT
    snapshot = q.object_at(snapshot_path)
    indices = [i for i, row in enumerate(report['checks']) if row.get('name') == CONTROL]
    require(len(indices) == 1 and snapshot['checks'] == report['checks'][:indices[0]],
        'storage controls did not follow every completed original process')
    for key in ('source_sha256', 'modules', 'result_storage_evidence', 'original_rust_comparisons',
            'compiler_checkout', 'compiler_commit', 'compiler_image_sha256', 'rust_compiler'):
        require(snapshot.get(key) == report.get(key), 'storage control snapshot changed: ' + key)
    row, summary = completed(output, report, CONTROL)
    elapsed = row.get('elapsed_seconds')
    require(row['command'] == control_command(root, output) and row['timeout_seconds'] == 180
        and row['phase'] == 'original_rust_comparison' and row['exit_code'] == 0
        and row['timed_out'] is False and not row.get('start_error')
        and type(elapsed) in (int, float) and math.isfinite(elapsed) and 0 <= elapsed <= 180
        and not regular(output / (CONTROL + '.stderr')), 'actual storage evidence controls differ')
    folder = output / CONTROL;result_path = folder / 'result.json';value = q.object_at(result_path)
    require(summary == {'status': 'PASS',
        'mutation_summary': json.loads(regular(folder / 'mutation-summary.stdout')),
        'complete_result': q.pin(result_path)}, 'complete evidence-control result is unbound')
    expected_summary = {key: value[key] for key in ('status', 'rejected', 'complete_native_domains',
        'complete_original_domains', 'new_native_executions', 'new_original_executions', 'elapsed_seconds')}
    require(summary['mutation_summary'] == expected_summary
        and value['schema'] == 'hepta.result-storage.evidence-controls.v1'
        and value['status'] == 'PASS' and value['rejected'] == 39
        and value['complete_native_domains'] == 13 and value['complete_original_domains'] == 9
        and value['new_native_executions'] == value['new_original_executions'] == 0
        and value['restored_all_files'] is True and value['sources_unchanged'] is True
        and value['script'] == q.pin(Path(root) / 'scripts/check_result_storage_evidence.py')
        and value['sources'] == q.source_pins(root)
        and value['native_evidence'] == report['result_storage_evidence']['native_evidence']
        and value['original_suite'] == q.pin(output / ORIGINAL_SUITE)
        and tuple(item['name'] for item in value['controls']) == CONTROL_LABELS
        and [item['label'] for item in value['complete_admissions']] == ['before', 'after'],
        'complete storage corruption/restoration domain differs')
    for item in value['controls']:
        require(item['passed'] is True and item['restored'] is True
            and bool(item['refusal']) and bool(item['files']), 'storage control was not a real refusal')
        for changed in item['files']:
            path, backup = Path(changed['path']), Path(changed['backup'])
            require(backup.resolve(strict=True).is_relative_to((folder / 'restoration').resolve(strict=True))
                and q.pin(backup) == changed['before'] and q.pin(path) == changed['before']
                and (path.stat().st_mode & 0o7777) == changed['mode'],
                'storage evidence mutation was not completely restored')
    require(q.object_at(output / ORIGINAL_SUITE) == original_suite(root, output, report, completed),
        'complete original suite changed after evidence controls')
    require(native_evidence(root, output, report, completed) == report['result_storage_evidence'],
        'complete native evidence changed after evidence controls')
    paths = [path for path in folder.rglob('*') if path.is_file()]
    paths.extend((snapshot_path, output / ORIGINAL_SUITE,
        output / (CONTROL + '.stdout'), output / (CONTROL + '.stderr')))
    return {'schema': 'hepta.runtime.result-storage-controls.v1', 'status': 'PASS',
        'artifact_sha256': retained(output, paths), 'rejected': 39,
        'complete_native_domains': 13, 'complete_original_domains': 9,
        'new_native_executions': 0, 'new_original_executions': 0}


def run_controls(root, output, report, completed, record_check, environment):
    output = Path(output)
    for path, value in ((output / ORIGINAL_SUITE, original_suite(root, output, report, completed)),
            (output / CONTROL_INPUT, report)):
        with path.open('xb') as stream:
            stream.write(encoded(value))
    record_check(output, report, name=CONTROL, command=control_command(root, output),
        timeout=180, env=environment)
    report['result_storage_evidence_controls'] = control_evidence(root, output, report, completed)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-controls', action='store_true', required=True)
    for name in ('root', 'output', 'report'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    execute_controls(args.root, args.output, args.report)

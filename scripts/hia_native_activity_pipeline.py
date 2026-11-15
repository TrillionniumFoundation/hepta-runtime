# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Join actual aggregate processes to the frozen private audit qualifications.

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

import hia_native_activity_qualification as q
import hia_native_activity_reference as reference
from audit_activity_registry import encoded, profile, regular, require, sha

KEYS = {'request_audit_active': 'active', 'request_audit_active_publication': 'active_publication', 'request_audit_hot_cache': 'hot_cache'}
NATIVE = 'audit-activity-native'
ORIGINAL = 'audit-activity-original'
ORIGINAL_PROCESSES = 'audit-activity-original-processes'
CONTROL = 'audit-activity-evidence-controls'
CONTROL_INPUT = 'audit-activity-controls-input.json'
def owner_domains(domain):
    return (domain, domain + '_controls')


NAMES = {domain: 'audit-activity-' + domain.replace('_', '-')
    for owner in KEYS.values() for domain in owner_domains(owner)}
TESTS = tuple(NAMES.values())
require(set(NAMES) == set(q.DOMAINS) and len(TESTS) == 6,
    'every audit native domain must have one aggregate process')
RUST_NAMES = {domain: 'audit-activity-' + domain.replace('_', '-') + '-rust-compare'
    for domain in reference.DOMAINS}
CONTROL_LABELS = ('owner-source', 'borrowed-control-source', 'compiled-owner-image', 'complete-static-elf', 'packer-observer-empty', 'native-process-exit', 'native-process-timeout', 'native-summary-empty', 'native-request-frame', 'native-response-frame', 'native-commuting-domain', 'cache-scripted-input', 'cache-scripted-result', 'publication-control-domain', 'fresh-original-summary', 'fresh-original-command', 'fresh-original-binary', 'fresh-original-count')


def sources(root):
    return (*reference.original_sources(root), 'scripts/hia_native_activity_pipeline.py',
        'scripts/check_activity_evidence.py', 'native/audit_activity_integration.md')


def build_activity(hepta, build, root):
    root, build = Path(root).resolve(strict=True), Path(build).resolve()
    path = build / 'audit-activity-build.json'
    if path.exists():
        q.build_evidence(root, build, hepta=hepta)
    else:
        q.build_activity(hepta, build, root)
    return path


def bundle_for(root, output, report):
    root, output = Path(root).resolve(strict=True), Path(output).resolve(strict=True)
    fixed = profile(root);paths = set()
    for key, domain in KEYS.items():
        row = report['modules'][key]
        require(row['source'] == 'native/' + key + '.hepta'
            and row['builder'] == 'audit_activity', 'registered audit owner differs')
        path = q.confined(output, row['manifest'])
        require(q.pin(path)['sha256'] == row['sha256'], 'audit bundle changed')
        paths.add(path)
    require(len(paths) == 1, 'audit owners lost their shared fixed build')
    path = paths.pop()
    require(path == output / 'build/audit-activity-build.json'
        and len(fixed['modules']) == 4, 'audit build location or domain differs')
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
    require(folder is not None, 'unknown audit process completion')
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
    row = {'schema': 'hepta.audit-activity.actual-aggregate-process.v1',
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
        'audit process group cleanup failed; original evidence retained')


def completed_process(root, output, report, name, command, completed):
    row, summary = completed(output, report, name)
    elapsed = row.get('elapsed_seconds')
    require(row.get('command') == command and row.get('timeout_seconds') == 180
        and row.get('exit_code') == 0 and row.get('timed_out') is False
        and not row.get('start_error') and type(elapsed) in (int, float)
        and math.isfinite(elapsed) and 0 <= elapsed <= 180,
        'actual audit aggregate process is incomplete or changed')
    folder = process_folder(output, name)
    observed, stdout, stderr = q.process_evidence(folder, command, root)
    require(observed.get('schema') == 'hepta.audit-activity.actual-aggregate-process.v1'
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
            'audit evidence escapes its qualification directory')
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
    value = {'schema': 'hepta.audit-activity.native-run.v1', 'status': 'PASS',
        'sources': q.source_pins(root), 'processes': processes, 'evidence': observed,
        'actual_original_executions': 0, 'production_activated': False, 'audit_storage_closed': False}
    path = output / NATIVE / 'result.json'
    if create:
        with path.open('xb') as stream:
            stream.write(encoded(value))
    require(q.object_at(path) == value, 'complete actual activity native evidence changed')
    corpus = [path for path in (output / NATIVE).rglob('*') if path.is_file()]
    corpus.extend(output / (name + suffix) for name in TESTS for suffix in ('.stdout', '.stderr'))
    return {'schema': 'hepta.runtime.audit-activity-native.v1', 'status': 'PASS',
        'native_evidence': q.pin(path), 'completed_processes': receipts,
        'artifact_sha256': retained(output, [build / name for name in compiled['artifact_pins']]),
        'corpus_sha256': retained(output, corpus), 'complete_native_domains': 6,
        'new_native_executions_by_admission': 0, 'new_original_executions_by_admission': 0,
        'production_activated': False, 'audit_storage_closed': False}


def original_command(root, output, report, rustc, cargo, domain):
    require(domain in reference.DOMAINS, 'unknown audit reference domain')
    bundle = bundle_for(root, output, report);output = Path(output)
    seal = report['audit_activity_evidence']['native_evidence']
    evidence = output / NATIVE / 'result.json'
    require(q.pin(evidence) == seal, 'audit native seal changed')
    return list(map(str, [sys.executable, '-I', '-B', Path(root) / 'tests/hia_native/compare_activity_original.py',
        '--repo', root, '--build', bundle.parent, '--native', output / NATIVE,
        '--output', output / ORIGINAL / domain, '--domain', domain, '--native-evidence', evidence,
        '--native-evidence-sha256', seal['sha256'], '--rustc', Path(rustc).absolute(),
        '--cargo', Path(cargo).absolute()]))


def original_evidence(root, output, report, completed, domain):
    output = Path(output);bundle = bundle_for(root, output, report)
    folder = output / ORIGINAL / domain
    built = q.object_at(folder / 'reference-build/result.json')
    require(built['rustc_path'] == report['rust_compiler']['invocation_path'],
        'audit original did not use the aggregate compiler invocation')
    command = original_command(root, output, report, built['rustc_path'], built['cargo_path'], domain)
    receipt, summary = completed_process(root, output, report, RUST_NAMES[domain], command, completed)
    seal = report['audit_activity_evidence']['native_evidence']
    observed = reference.original_evidence(root, bundle.parent, output / NATIVE, folder, domain,
        output / NATIVE / 'result.json', seal['sha256'])
    expected = {'status': 'PASS', 'domain': domain, **observed['comparison'],
        'production_activated': False, 'whole_runtime_replaced': False}
    require(summary == expected, 'actual audit original stdout omits part of its domain')
    paths = [path for path in folder.rglob('*') if path.is_file()]
    paths.extend(process_folder(output, RUST_NAMES[domain]).iterdir())
    paths.extend(output / (RUST_NAMES[domain] + suffix) for suffix in ('.stdout', '.stderr'))
    return {'schema': 'hepta.runtime.audit-activity-original.v1', 'status': 'PASS',
        'domain': domain, 'owner_evidence': observed, 'completed_process': receipt,
        'artifact_sha256': retained(output, paths),
        'new_native_executions_by_admission': 0, 'new_original_executions_by_admission': 0,
        'production_activated': False, 'audit_storage_closed': False}





def control_command(root, output, report):
    bundle = bundle_for(root, output, report);output = Path(output)
    seal = report['audit_activity_evidence']['native_evidence']
    return list(map(str, [sys.executable, '-I', '-B', Path(root) / 'scripts/check_activity_evidence.py',
        '--hepta', report['compiler_checkout'], '--build', bundle.parent, '--native', output / NATIVE,
        '--original', output / ORIGINAL, '--native-evidence', output / NATIVE / 'result.json',
        '--native-evidence-sha256', seal['sha256'], '--output', output / CONTROL]))





def control_evidence(root, output, report, completed):
    output = Path(output);snapshot_path = output / CONTROL_INPUT
    snapshot = q.object_at(snapshot_path)
    indices = [i for i, row in enumerate(report['checks']) if row.get('name') == CONTROL]
    require(len(indices) == 1 and snapshot['checks'] == report['checks'][:indices[0]],
        'activity controls did not follow every completed original process')
    for key in ('source_sha256', 'modules', 'audit_activity_evidence', 'original_rust_comparisons',
            'compiler_checkout', 'compiler_commit', 'compiler_image_sha256', 'rust_compiler'):
        require(snapshot.get(key) == report.get(key), 'activity control snapshot changed: ' + key)
    row, summary = completed(output, report, CONTROL)
    elapsed = row.get('elapsed_seconds')
    require(row['command'] == control_command(root, output, report) and row['timeout_seconds'] == 180
        and row['phase'] == 'original_rust_comparison' and row['exit_code'] == 0
        and row['timed_out'] is False and not row.get('start_error')
        and type(elapsed) in (int, float) and math.isfinite(elapsed) and 0 <= elapsed <= 180
        and not regular(output / (CONTROL + '.stderr')), 'actual activity evidence controls differ')
    folder = output / CONTROL;value = q.object_at(folder / 'result.json')
    require(summary == {key: item for key, item in value.items() if key != 'controls'}
        and value['schema'] == 'hepta.audit-activity.evidence-controls.v1'
        and value['status'] == 'PASS' and value['damaged_evidence_refusals'] == 18
        and value['complete_readmissions'] == 20 and value['restored'] is True
        and value['native_domains'] == 6 and value['original_recipes'] == 3
        and value['actual_native_executions_added'] == value['actual_original_executions_added'] == 0
        and value['native_evidence_sha256'] == report['audit_activity_evidence']['native_evidence']['sha256']
        and all(value[key] is False for key in ('production_activated', 'audit_storage_closed', 'whole_runtime_replaced'))
        and tuple(item['name'] for item in value['controls']) == CONTROL_LABELS,
        'complete activity corruption and restoration domain differs')
    build = bundle_for(root, output, report).parent
    bundle = q.object_at(build / 'audit-activity-build.json')
    module = q.confined(build, bundle['modules']['request_audit_active']['path'])
    graph = q.confined(build, bundle['graphs']['active_publication']['path'])
    captured = output / NATIVE;originals = output / ORIGINAL
    first_name = q.object_at(captured / 'active/result.json')['results'][0]['name']
    first = captured / 'active' / first_name / 'native'
    hot = q.object_at(captured / 'hot_cache/result.json')
    targets = dict(zip(CONTROL_LABELS, (
        Path(root) / 'native/request_audit_active.hepta',
        Path(root) / q.HARNESS / 'test_audit_active_controls.py',
        module.parent / q.object_at(module)['image'], graph.parent / q.object_at(graph)['executable'],
        graph.parent / 'pack.stdout', captured / 'processes/active/result.json',
        captured / 'processes/hot_cache/result.json', captured / 'processes/active/stdout',
        first / 'stdin.bin', first / 'stdout.bin', captured / 'active/result.json',
        captured / 'hot_cache' / hot['inputs']['path'], captured / 'hot_cache' / hot['native_results']['path'],
        captured / 'active_publication_controls/result.json', originals / 'active/complete-comparison.stdout',
        originals / 'active/complete-comparison.process.json',
        originals / 'active/reference-build' / reference.BINS['active'], originals / 'hot_cache/result.json'), strict=True))
    for item in value['controls']:
        backup = folder / 'restoration' / (item['name'] + '.bin')
        target = targets[item['name']]
        require(item['rejected'] is True and bool(item['reason'])
            and q.pin(backup)['sha256'] == item['restored_sha256']
            and q.pin(target) == q.pin(backup)
            and type(item['restored_mode']) is int and 0 <= item['restored_mode'] <= 0o777
            and target.stat().st_mode & 0o7777 == item['restored_mode'],
            'activity control was not an actual refusal with retained restoration bytes')
    for key, domain in KEYS.items():
        require(report['original_rust_comparisons'].get(key) ==
            original_evidence(root, output, report, completed, domain),
            'complete original activity suite changed after evidence controls')
    require(native_evidence(root, output, report, completed) == report['audit_activity_evidence'],
        'complete native activity evidence changed after evidence controls')
    paths = [path for path in folder.rglob('*') if path.is_file()]
    paths.extend((snapshot_path, output / (CONTROL + '.stdout'), output / (CONTROL + '.stderr')))
    return {'schema': 'hepta.runtime.audit-activity-controls.v1', 'status': 'PASS',
        'artifact_sha256': retained(output, paths), 'rejected': 18,
        'complete_native_domains': 6, 'complete_original_domains': 3,
        'new_native_executions': 0, 'new_original_executions': 0}


def run_controls(root, output, report, completed, record_check, environment):
    output = Path(output)
    for key, domain in KEYS.items():
        require(report['original_rust_comparisons'].get(key) ==
            original_evidence(root, output, report, completed, domain),
            'activity originals are incomplete before controls')
    with (output / CONTROL_INPUT).open('xb') as stream:
        stream.write(encoded(report))
    record_check(output, report, name=CONTROL, command=control_command(root, output, report),
        timeout=180, env=environment)
    report['audit_activity_evidence_controls'] = control_evidence(root, output, report, completed)




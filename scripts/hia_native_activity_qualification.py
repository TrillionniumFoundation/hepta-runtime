# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Strict actual compilation and complete capture admission for activity owners."""
from pathlib import Path
import ast
import json
import os
import struct
import sys

from audit_activity_registry import (COMPILER, COMPILER_IMAGE, HARNESS, REFERENCES,
    build_sources, encoded, graph_order, profile, regular, require, sha)
from build_audit_activity import inspect_graph, source_composition
from hia_native_result_storage_qualification import (OBSERVER, compilation, confined,
    object_at, pin, process_evidence, run_process)
from activity_evidence import activity_capture, hot_cache_capture

SEMANTIC = ('active', 'active_publication', 'hot_cache')
CONTROLS = {'active_controls': (50, 45, 5), 'active_publication_controls': (74, 66, 8),
    'hot_cache_controls': (103, 100, 3)}
DOMAINS = SEMANTIC + tuple(CONTROLS)


def source_pins(root):
    root = Path(root);names = set(build_sources(root)) | {'Cargo.toml', 'Cargo.lock'}
    queue = ['hia_native_activity_qualification', 'activity_evidence']
    seen = set()
    while queue:
        name = queue.pop();path = root / 'scripts' / (name + '.py')
        if name in seen or not path.is_file():
            continue
        seen.add(name);names.add(str(path.relative_to(root)))
        for node in ast.walk(ast.parse(regular(path))):
            if isinstance(node, ast.Import):
                queue.extend(item.name.split('.')[0] for item in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                queue.append(node.module.split('.')[0])
    for directory in (HARNESS, REFERENCES):
        names.update(str(path.relative_to(root)) for path in (root / directory).rglob('*') if path.is_file())
    names.update(('tests/hia_native/run_activity_native.py', 'scripts/check_activity_evidence.py',
        'native/audit_activity_integration.md'))
    return {name: pin(root / name) for name in sorted(names)}


def build_evidence(root, build, *, hepta=None, require_process=True):
    root, build = Path(root).resolve(strict=True), Path(build).resolve(strict=True)
    fixed = profile(root);bundle = object_at(build / 'audit-activity-build.json');artifacts = {}
    require(bundle['sources'] == build_sources(root) and bundle['compiler_commit'] == COMPILER
        and bundle['compiler_sha256'] == COMPILER_IMAGE and set(bundle['modules']) == set(fixed['modules'])
        and set(bundle['graphs']) == set(fixed['graphs']) and bundle['actual_original_executions'] == 0,
        'audit build domain changed')
    images = {};manifests = {}
    for name, spec in fixed['modules'].items():
        manifests[name], images[name] = compilation(root, build, spec, bundle['modules'][name], artifacts)
    for name, graph in fixed['graphs'].items():
        manifest = confined(build, bundle['graphs'][name]['path'])
        require(pin(manifest)['sha256'] == bundle['graphs'][name]['sha256'], 'audit graph manifest changed')
        row = object_at(manifest);folder = manifest.parent
        layout_raw = regular(root / graph['layout']);layout = json.loads(layout_raw)
        require(sha(layout_raw) == graph['layout_sha256'], 'audit boundary layout changed')
        order = graph_order(graph, layout);elf = regular(confined(folder, row['executable']))
        require(row['members'] == inspect_graph(elf, graph, layout, images)
            and row['executable_sha256'] == sha(elf) and row['executable_bytes'] == len(elf),
            'actual audit embedded images differ')
        frame = graph['magic'].encode() + b''.join(struct.pack('<Q', len(images[key])) for key in order)
        frame += b''.join(images[key] for key in order)
        require(regular(folder / 'pack.input.bin') == frame and row['input_sha256'] == sha(frame)
            and row['input_bytes'] == len(frame), 'complete audit packer frame differs')
        packer = bundle['modules'][graph['packer']]
        command = [sys.executable, '-I', '-B', str(root / 'scripts/audit_activity_pack_child.py'),
            '--graph', name, '--manifest', str(confined(build, packer['path'])),
            '--input', str(folder / 'pack.input.bin'), '--output', str(folder / row['executable'])]
        receipt = object_at(folder / 'pack-process.json')
        stdout, stderr = regular(folder / 'pack.stdout'), regular(folder / 'pack.stderr')
        require(receipt['command'] == command and receipt['cwd'] == str(root)
            and receipt['timeout_seconds'] == 30 and receipt['exit_code'] == 0
            and receipt['timed_out'] is False and receipt['start_error'] is None and not stderr
            and (receipt['stdout_bytes'], receipt['stdout_sha256']) == (len(stdout), sha(stdout))
            and (receipt['stderr_bytes'], receipt['stderr_sha256']) == (len(stderr), sha(stderr)),
            'actual audit packer process is incomplete')
        observed = json.loads(stdout)
        require(set(observed) == OBSERVER and observed['status'] == 'returned'
            and observed['native_result_code'] == observed['output_bytes'] == observed['output_capacity'] == len(elf)
            and observed['manifest_sha256'] == packer['sha256'] and observed['input_sha256'] == sha(frame)
            and observed['input_bytes'] == len(frame) and observed['output_sha256'] == sha(elf)
            and observed['workspace_capacity'] == 4096 and observed['source_unchanged'] is True
            and observed['forbidden_compiler_modules_loaded'] == [], 'actual audit packer observer differs')
        artifacts.update({str(path.relative_to(build)): pin(path) for path in folder.iterdir() if path.is_file()})
    if hepta is not None:
        require(bundle['composition'] == source_composition(root, hepta), 'audit imported IR closure differs')
    for name in ('B1.image.bin', 'B2.image.bin', 'B3.image.bin'):
        path = build / 'bootstrap' / name
        require(sha(regular(path)) == COMPILER_IMAGE, 'native compiler fixed point changed')
        artifacts[str(path.relative_to(build))] = pin(path)
    if require_process:
        command = [sys.executable, '-I', '-B', str(root / 'scripts/build_audit_activity.py'),
            '--hepta', str(Path(hepta).resolve(strict=True)), '--build-root', str(build)]
        _, stdout, stderr = process_evidence(build / 'audit-activity-build-process', command, root)
        require(not stderr and json.loads(stdout) == {'build': str(build / 'audit-activity-build.json'),
            'modules': 4, 'static_graphs': 2, 'actual_original_executions': 0}, 'actual audit build summary differs')
        artifacts.update({str(path.relative_to(build)): pin(path)
            for path in (build / 'audit-activity-build-process').iterdir()})
    artifacts['audit-activity-build.json'] = pin(build / 'audit-activity-build.json')
    return {'schema': 'hepta.audit-activity.build-evidence.v1', 'modules': manifests,
        'bundle': bundle, 'artifact_pins': artifacts, 'new_native_executions': 0,
        'new_original_executions': 0, 'fresh_full_cold_qualified': False}


def build_activity(hepta, build, root):
    root, build = Path(root).resolve(strict=True), Path(build).resolve()
    build.mkdir(parents=True, exist_ok=True);before = source_pins(root)
    command = [sys.executable, '-I', '-B', str(root / 'scripts/build_audit_activity.py'),
        '--hepta', str(Path(hepta).resolve(strict=True)), '--build-root', str(build)]
    run_process(root, build / 'audit-activity-build-process', command,
        environment={key: value for key, value in os.environ.items() if not key.startswith('HIA_')})
    require(source_pins(root) == before, 'audit sources changed during actual build')
    return build_evidence(root, build, hepta=hepta)


def commands(root, build, output):
    root, build, output = map(Path, (root, build, output))
    bundle = object_at(build / 'audit-activity-build.json');fixed = profile(root);result = {}
    for domain in DOMAINS:
        owner = domain.removesuffix('_controls')
        command = [sys.executable, '-I', '-B', str(root / HARNESS / ('test_audit_' + domain + '.py'))]
        if domain in ('active', 'active_publication'):
            path = confined(build, bundle['graphs'][owner]['path'])
            command += ['--native', str(path.parent / object_at(path)['executable'])]
        else:
            module = confined(build, bundle['modules'][fixed['owners'][owner]]['path'])
            command += ['--manifest', str(module), '--runtime', str(root)]
        result[domain] = command + ['--output', str(output / domain)]
    require(len(result) == 6 and set(result) == set(DOMAINS), 'activity native suite domain differs')
    return result


def control_evidence(folder, domain, manifest_sha256):
    report = object_at(Path(folder) / 'result.json');checks, rejected, synthetic = CONTROLS[domain]
    require(report.get('status') == 'PASS' and report.get('manifest_sha256') == manifest_sha256
        and report.get('checks') == checks and report.get('rejection_controls') == rejected
        and all(report.get(key) is False for key in ('original_executed', 'native_language_unwind_qualified',
            'whole_runtime_replaced', 'production_activated')), 'activity control scope or count differs')
    if domain == 'active_publication_controls':
        previous = object_at(Path(folder) / 'base/result.json')
        require(report['base_controls'] == {key: value for key, value in previous.items() if key != 'cases'}
            and previous['checks'] == 50 and previous['rejection_controls'] == 45
            and previous['synthetic_growth_and_counter_controls'] == 5
            and previous['manifest_sha256'] == manifest_sha256
            and report['synthetic_controls'] == synthetic
            and report['baseline_control_delta'] == 'Only unknown op 13 becomes 15 because 13 and 14 are newly admitted.',
            'complete inherited publication controls differ')
        rows = previous['cases'] + report['extension_cases']
    else:
        rows = report['cases']
        field = 'synthetic_growth_and_counter_controls' if domain == 'active_controls' else 'synthetic_completion_controls'
        require(report[field] == synthetic, 'synthetic activity control domain differs')
    require(len(rows) == len({row['name'] for row in rows}) == checks, 'activity controls are missing or repeated')
    if domain.startswith('active'):
        require(report['real_threads_executed'] is False, 'borrowed controls claimed actual threads')
    else:
        require(report['real_archive_executed'] is False and report['real_filesystem_effects'] is False,
            'scripted controls claimed actual filesystem effects')
    return report


def domain_evidence(root, build, output, domain):
    root, build, output = map(Path, (root, build, output))
    require(domain in DOMAINS, 'unknown activity evidence domain')
    bundle = object_at(build / 'audit-activity-build.json');fixed = profile(root)
    folder = output / domain;owner = domain.removesuffix('_controls')
    manifest_sha256 = bundle['modules'][fixed['owners'][owner]]['sha256']
    if domain in ('active', 'active_publication'):
        path = confined(build, bundle['graphs'][domain]['path'])
        executable = path.parent / object_at(path)['executable']
        activity_capture(root, folder, domain, {'native': pin(executable)['sha256']})
    elif domain == 'hot_cache':
        hot_cache_capture(root, folder, manifest_sha256)
    else:
        control_evidence(folder, domain, manifest_sha256)
    return {'domain': domain, 'report': pin(folder / 'result.json'),
        'files': {str(path.relative_to(folder)): pin(path)
            for path in sorted(folder.rglob('*')) if path.is_file()},
        'new_native_executions_by_admission': 0, 'new_original_executions_by_admission': 0}


def native_evidence(root, build, output, processes):
    require(set(processes) == set(DOMAINS), 'not every mandatory activity process completed')
    result = {};expected = commands(root, build, output)
    for domain in DOMAINS:
        row, stdout, stderr = process_evidence(processes[domain], expected[domain], root)
        require(not stderr and type(json.loads(stdout)) is dict, 'activity process lacks its complete summary')
        summary = json.loads(stdout);report = object_at(Path(output) / domain / 'result.json')
        require(summary.get('status') == 'PASS' and all(report.get(key) == value for key, value in summary.items()),
            'actual activity stdout differs from its complete report')
        result[domain] = {'process': row, 'summary': summary,
            'evidence': domain_evidence(root, build, output, domain)}
    return {'schema': 'hepta.audit-activity.native-evidence.v1', 'status': 'PASS',
        'sources': source_pins(root), 'domains': result, 'mandatory_processes': 6,
        'actual_original_executions': 0, 'production_activated': False, 'audit_storage_closed': False,
        'hot_cache_real_filesystem_executed': False, 'public_request_dispatch_qualified': False}

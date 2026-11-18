# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Actual build and full-process qualification for real filesystem Stamp graphs."""
from pathlib import Path
import ast
import json
import os
import struct
import sys

from audit_stamp_registry import (COMPILER, COMPILER_IMAGE, HARNESS, REFERENCES,
    build_sources, encoded, graph_order, profile, regular, require, sha)
from build_audit_stamp_graphs import inspect_graph, source_composition
from hia_native_result_storage_qualification import (OBSERVER, compilation, confined,
    object_at, pin, process_evidence, run_process)
from stamp_evidence import COUNTS, capture, capture_files

SEMANTIC = tuple(COUNTS)
CONTROLS = {'stamp_controls': (41, 38, 3), 'cache_stamp_controls': (30, 27, 3)}
DOMAINS = SEMANTIC + tuple(CONTROLS)


def source_pins(root):
    root = Path(root);names = set(build_sources(root)) | {'Cargo.toml', 'Cargo.lock'}
    queue = ['hia_native_stamp_qualification', 'stamp_evidence', 'hia_native_stamp_reference']
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
    names.update(('tests/hia_native/run_stamp_native.py', 'tests/hia_native/run_stamp_domain.py',
        'tests/hia_native/compare_stamp_original.py', 'scripts/check_stamp_evidence.py',
        'scripts/qualify_audit_stamp.py', 'native/audit_stamp_integration.md'))
    return {name: pin(root / name) for name in sorted(names)}


def build_evidence(root, build, *, hepta=None, require_process=True):
    root, build = Path(root).resolve(strict=True), Path(build).resolve(strict=True)
    fixed = profile(root);bundle = object_at(build / 'audit-stamp-build.json');artifacts = {}
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
        command = [sys.executable, '-I', '-B', str(root / 'scripts/audit_stamp_pack_child.py'),
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
        command = [sys.executable, '-I', '-B', str(root / 'scripts/build_audit_stamp_graphs.py'),
            '--hepta', str(Path(hepta).resolve(strict=True)), '--build-root', str(build)]
        _, stdout, stderr = process_evidence(build / 'audit-stamp-build-process', command, root)
        require(not stderr and json.loads(stdout) == {'build': str(build / 'audit-stamp-build.json'),
            'modules': 5, 'static_graphs': 2, 'actual_original_executions': 0}, 'actual audit build summary differs')
        artifacts.update({str(path.relative_to(build)): pin(path)
            for path in (build / 'audit-stamp-build-process').iterdir()})
    artifacts['audit-stamp-build.json'] = pin(build / 'audit-stamp-build.json')
    return {'schema': 'hepta.audit-stamp.build-evidence.v1', 'modules': manifests,
        'bundle': bundle, 'artifact_pins': artifacts, 'new_native_executions': 0,
        'new_original_executions': 0, 'fresh_full_cold_qualified': False}


def build_stamp(hepta, build, root):
    root, build = Path(root).resolve(strict=True), Path(build).resolve()
    build.mkdir(parents=True, exist_ok=True);before = source_pins(root)
    command = [sys.executable, '-I', '-B', str(root / 'scripts/build_audit_stamp_graphs.py'),
        '--hepta', str(Path(hepta).resolve(strict=True)), '--build-root', str(build)]
    run_process(root, build / 'audit-stamp-build-process', command,
        environment={key: value for key, value in os.environ.items() if not key.startswith('HIA_')})
    require(source_pins(root) == before, 'audit sources changed during actual build')
    return build_evidence(root, build, hepta=hepta)


def commands(root, build, output):
    root, build, output = map(Path, (root, build, output))
    bundle = object_at(build / 'audit-stamp-build.json');fixed = profile(root);result = {}
    for domain in DOMAINS:
        owner = domain.removesuffix('_kernel').removesuffix('_controls')
        if domain in CONTROLS:
            name = 'test_audit_stamp_controls.py' if owner == 'stamp' else 'test_cache_stamp_controls.py'
            module = confined(build, bundle['modules'][fixed['owners'][owner]]['path'])
            command = [sys.executable, '-I', '-B', str(root / HARNESS / name),
                '--manifest', str(module), '--runtime', str(root)]
        else:
            path = confined(build, bundle['graphs'][owner]['path'])
            executable = path.parent / object_at(path)['executable']
            command = [sys.executable, '-I', '-B', str(root / 'tests/hia_native/run_stamp_domain.py'),
                '--domain', domain, '--native', str(executable)]
        result[domain] = command + ['--output', str(output / domain)]
    require(len(result) == 6 and set(result) == set(DOMAINS), 'complete Stamp suite domain differs')
    return result


def control_evidence(folder, domain, manifest_sha256):
    report = object_at(Path(folder) / 'result.json');checks, rejected, synthetic = CONTROLS[domain]
    require(report.get('status') == 'PASS' and report.get('manifest_sha256') == manifest_sha256
        and report.get('checks') == checks and report.get('rejection_controls') == rejected
        and report.get('synthetic_completion_controls') == synthetic
        and all(report.get(key) is False for key in ('original_executed', 'real_filesystem_effects',
            'whole_runtime_replaced', 'production_activated')), 'Stamp control scope or counts differ')
    rows = report['cases']
    require(len(rows) == len({row['name'] for row in rows}) == checks, 'Stamp controls missing or repeated')
    for row in rows[:rejected]:
        require(row.get('output_untouched') is True and row.get('code') in (0xffffffff, 0xfffffffe, 0xfffffff9)
            and type(row.get('state_sha256')) is str and len(row['state_sha256']) == 64,
            'actual borrowed-state refusal is incomplete')
    require(all(row['name'].startswith('synthetic-') for row in rows[rejected:]),
        'borrowed-state completion was relabeled as an actual filesystem call')
    if domain == 'cache_stamp_controls':
        require(report['cold_snapshot_admitted'] is False, 'unqualified cold snapshot admitted')
    return report


def domain_evidence(root, build, output, domain):
    root, build, output = map(Path, (root, build, output))
    require(domain in DOMAINS, 'unknown Stamp evidence domain')
    bundle = object_at(build / 'audit-stamp-build.json');fixed = profile(root)
    folder = output / domain;owner = domain.removesuffix('_kernel').removesuffix('_controls')
    if domain in CONTROLS:
        manifest_sha256 = bundle['modules'][fixed['owners'][owner]]['sha256']
        control_evidence(folder, domain, manifest_sha256)
        require({path.name for path in folder.iterdir()} == {'result.json'}, 'unexpected control artifact')
        files = {'result.json': pin(folder / 'result.json')}
    else:
        path = confined(build, bundle['graphs'][owner]['path'])
        executable = path.parent / object_at(path)['executable']
        capture(root, folder, domain, {'native': executable})
        files = capture_files(folder);files['retired-fixtures.json'] = pin(folder / 'retired-fixtures.json')
    return {'domain': domain, 'report': pin(folder / 'result.json'), 'files': files,
        'new_native_executions_by_admission': 0, 'new_original_executions_by_admission': 0}


def native_evidence(root, build, output, processes):
    require(set(processes) == set(DOMAINS), 'not every mandatory Stamp process completed')
    result = {};expected = commands(root, build, output)
    for domain in DOMAINS:
        row, stdout, stderr = process_evidence(processes[domain], expected[domain], root)
        require(not stderr and type(json.loads(stdout)) is dict, 'Stamp process lacks complete summary')
        summary = json.loads(stdout);report = object_at(Path(output) / domain / 'result.json')
        require(summary.get('status') == 'PASS'
            and summary == {key: value for key, value in report.items() if key != 'cases'},
            'actual Stamp stdout differs from its complete report')
        result[domain] = {'process': row, 'summary': summary,
            'evidence': domain_evidence(root, build, output, domain)}
    return {'schema': 'hepta.audit-stamp.native-evidence.v1', 'status': 'PASS',
        'sources': source_pins(root), 'domains': result, 'mandatory_processes': 6,
        'actual_native_processes': 126, 'actual_process_requests': 507,
        'actual_kernel_controls': 77, 'borrowed_state_controls': 71,
        'actual_original_executions': 0, 'production_activated': False, 'audit_storage_closed': False,
        'real_filesystem_children_executed': True, 'cold_snapshot_admitted': False,
        'public_request_dispatch_qualified': False, 'whole_runtime_replaced': False}



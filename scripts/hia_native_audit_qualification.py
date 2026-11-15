# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Actual compilation, native capture and complete evidence for audit owners."""
from pathlib import Path
import gzip
import importlib.util
import json
import os
import struct
import sys

from audit_readiness_registry import (COMPILER, COMPILER_IMAGE, HARNESS, REFERENCES,
    build_sources, encoded, graph_order, profile, regular, require, sha)
from build_audit_readiness import inspect_graph, source_composition
from hia_native_result_storage_qualification import (OBSERVER, compilation, confined,
    object_at, pin, process_evidence, run_process)

FS = ('prepare', 'prepare_faults', 'audit_directory', 'audit_directory_faults',
    'audit_read', 'audit_read_faults', 'audit_write', 'audit_write_faults', 'audit_write_edges',
    'audit_remove', 'audit_remove_faults', 'audit_remove_edges',
    'audit_entries', 'audit_entries_faults', 'audit_entries_edges', 'audit_lock')
PURE = ('audit_json', 'audit_retention_policy')
CONTROLS = {'audit_read_controls': (25, 24, 1), 'audit_write_controls': (25, 24, 1),
    'audit_remove_controls': (25, 24, 1), 'audit_entries_controls': (26, 25, 1),
    'audit_lock_controls': (59, 32, 27), 'audit_retention_controls': (80, 78, 2)}
DOMAINS = PURE + FS + tuple(CONTROLS)


def source_pins(root):
    root = Path(root);names = set(build_sources(root))
    names.update(('scripts/hia_native_audit_qualification.py',
        'scripts/hia_native_result_storage_qualification.py',
        'tests/hia_native/test_audit_readiness_fs.py',
        'tests/hia_native/test_audit_readiness_json.py',
        'tests/hia_native/test_result_storage_fs.py',
        'tests/hia_native/run_audit_native.py', 'Cargo.toml', 'Cargo.lock'))
    for directory in (HARNESS, REFERENCES):
        names.update(str(path.relative_to(root)) for path in (root / directory).rglob('*') if path.is_file())
    return {name: pin(root / name) for name in sorted(names)}


def build_evidence(root, build, *, hepta=None, require_process=True):
    root, build = Path(root).resolve(strict=True), Path(build).resolve(strict=True)
    fixed = profile(root);bundle = object_at(build / 'audit-readiness-build.json');artifacts = {}
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
        command = [sys.executable, '-I', '-B', str(root / 'scripts/audit_readiness_pack_child.py'),
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
        command = [sys.executable, '-I', '-B', str(root / 'scripts/build_audit_readiness.py'),
            '--hepta', str(Path(hepta).resolve(strict=True)), '--build-root', str(build)]
        _, stdout, stderr = process_evidence(build / 'audit-readiness-build-process', command, root)
        require(not stderr and json.loads(stdout) == {'build': str(build / 'audit-readiness-build.json'),
            'modules': 22, 'static_graphs': 7, 'actual_original_executions': 0}, 'actual audit build summary differs')
        artifacts.update({str(path.relative_to(build)): pin(path)
            for path in (build / 'audit-readiness-build-process').iterdir()})
    artifacts['audit-readiness-build.json'] = pin(build / 'audit-readiness-build.json')
    return {'schema': 'hepta.audit-readiness.build-evidence.v1', 'modules': manifests,
        'bundle': bundle, 'artifact_pins': artifacts, 'new_native_executions': 0,
        'new_original_executions': 0, 'fresh_full_cold_qualified': False}


def build_audit(hepta, build, root):
    root, build = Path(root).resolve(strict=True), Path(build).resolve()
    build.mkdir(parents=True, exist_ok=True);before = source_pins(root)
    command = [sys.executable, '-I', '-B', str(root / 'scripts/build_audit_readiness.py'),
        '--hepta', str(Path(hepta).resolve(strict=True)), '--build-root', str(build)]
    run_process(root, build / 'audit-readiness-build-process', command,
        environment={key: value for key, value in os.environ.items() if not key.startswith('HIA_')})
    require(source_pins(root) == before, 'audit sources changed during actual build')
    return build_evidence(root, build, hepta=hepta)


def commands(root, build, output):
    root, build, output = map(Path, (root, build, output));bundle = object_at(build / 'audit-readiness-build.json')
    module = lambda stem: confined(build, bundle['modules'][stem]['path'])
    result = {}
    for domain in PURE:
        script = (root / 'tests/hia_native/test_audit_readiness_json.py' if domain == 'audit_json'
            else root / HARNESS / 'test_audit_retention.py')
        stem = 'request_audit_json' if domain == 'audit_json' else 'request_audit_retention'
        result[domain] = list(map(str, [sys.executable, '-I', '-B', script, '--manifest', module(stem),
            '--runtime', root, '--output', output / domain]))
    for domain in FS:
        owner = domain.removesuffix('_faults').removesuffix('_edges')
        path = confined(build, bundle['graphs'][owner]['path']);executable = path.parent / object_at(path)['executable']
        result[domain] = list(map(str, [sys.executable, '-I', '-B', root / 'tests/hia_native/test_audit_readiness_fs.py',
            '--domain', domain, '--phase', 'native', '--executable', executable, '--output', output / domain]))
    for domain in CONTROLS:
        stem = 'request_' + domain.removesuffix('_controls')
        result[domain] = list(map(str, [sys.executable, '-I', '-B', root / HARNESS / ('test_' + domain + '.py'),
            '--manifest', module(stem), '--runtime', root, '--output', output / domain]))
    require(len(result) == 24 and set(result) == set(DOMAINS), 'native audit suite set differs')
    return result


def test_module(root, name):
    root = Path(root);sys.path[:0] = [str(root / HARNESS), str(root / 'tests/hia_native')]
    path = root / ('tests/hia_native' if name.startswith('test_audit_readiness') else HARNESS) / (name + '.py')
    spec = importlib.util.spec_from_file_location('_audit_' + name + '_' + sha(regular(path)), path)
    module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def uncompressed(folder, row):
    path = confined(folder, row['path']);raw = regular(path)
    require((len(raw), sha(raw)) == (row['compressed_bytes'], row['compressed_sha256']), 'compressed audit stream differs')
    value = gzip.decompress(raw)
    require((len(value), sha(value)) == (row['bytes'], row['sha256']), 'complete audit stream differs')
    return value


def domain_evidence(root, build, output, domain):
    root, build, output = map(Path, (root, build, output))
    require(domain in DOMAINS, 'unknown audit native domain')
    folder = output / domain;report = object_at(folder / 'result.json')
    bundle = object_at(build / 'audit-readiness-build.json');fixed = profile(root)
    require(report.get('status') == 'PASS' and report.get('whole_runtime_replaced') is False
        and report.get('production_activated') is False, 'audit domain is incomplete or expanded its scope')
    if domain in FS:
        harness = test_module(root, 'test_audit_readiness_fs')
        require(report == harness.admit_capture(folder, domain), 'complete audit capture differs')
        owner = harness.DOMAINS[domain][0];path = confined(build, bundle['graphs'][owner]['path'])
        executable = path.parent / object_at(path)['executable']
        require(report['executable'] == harness.pin(executable), 'audit domain executed a different static graph')
        _, count, requests, processes, killed = harness.DOMAINS[domain]
        require((report['case_count'], report['requests'], report['processes'], report['deliberately_killed_requests'])
            == (count, requests, processes, killed) and report['new_native_processes'] == processes
            and report['new_original_processes'] == 0 and report['semantic_reference_comparison_complete'] is False,
            'audit current native execution counts differ')
    elif domain in CONTROLS:
        checks, rejected, synthetic = CONTROLS[domain]
        stem = 'request_' + domain.removesuffix('_controls')
        require(report.get('checks') == checks and report.get('rejection_controls') == rejected
            and report.get('synthetic_controls', report.get('synthetic_completion_controls')) == synthetic
            and len(report['cases']) == len({r['name'] for r in report['cases']}) == checks
            and report['manifest_sha256'] == bundle['modules'][stem]['sha256']
            and report.get('original_executed') is False, 'complete borrowed-buffer control domain differs')
        if domain == 'audit_lock_controls':
            require(report.get('real_threads_executed') is False and report.get('real_clock_readings') is False,
                'synthetic lock controls claimed real thread or clock effects')
        else:
            require(report.get('real_filesystem_effects') is False, 'synthetic controls claimed real filesystem effects')
    elif domain == 'audit_json':
        cases = test_module(root, 'audit_json_cases');rows = list(cases.cases())
        incoming = b''.join(wire.hex().encode() + b'\n' for _, wire in rows)
        require(regular(folder / 'reference.stdin') == incoming and report['reference_input'] == pin(folder / 'reference.stdin'),
            'complete original-bound audit JSON input differs')
        output_rows = regular(folder / 'native.stdout').splitlines()
        require(len(rows) == len(output_rows) == len(report['cases']) == 3390
            and report.get('cases_executed') == 3390 and report.get('native_entries') == 3418
            and report.get('controls_passed') == len(report['controls']) == 28
            and all(row['passed'] is True for row in report['controls'])
            and report.get('accepted') == 2538 and report.get('actual_original_requests') == 0
            and report.get('semantic_reference_comparison_complete') is False,
            'complete native JSON cases or controls differ')
        manifest = confined(build, bundle['modules']['request_audit_json']['path']);metadata = object_at(manifest)
        require(report['module'] == metadata, 'audit JSON executed a different image')
        for index, ((label, wire), line, observed) in enumerate(zip(rows, output_rows, report['cases'], strict=True)):
            encoded_code, text = line.split(b':');code = int(encoded_code, 16);raw = bytes.fromhex(text.decode())
            require(line == f'{code:08x}:'.encode() + raw.hex().encode()
                and (code in (0xffffffff, 0xfffffffe) and not raw or code == len(raw)), 'invalid audit JSON output framing')
            require(observed == {'ordinal': index, 'label': label, 'input_bytes': len(wire), 'input_sha256': sha(wire),
                'code': code, 'output_bytes': len(raw), 'output_sha256': sha(raw)}, 'audit JSON corpus row differs')
        executable = manifest.parent / metadata['standalone']['path']
        require(len(report['processes']) == report['native_standalone_processes'] == 4, 'standalone audit JSON domain differs')
        for kind, base in enumerate(cases.BASES, 1):
            name = 'native-elf-' + str(kind);row = object_at(folder / (name + '.process.json'))
            wire = cases.frame(kind, cases.encoded(base))
            expected = next(output_rows[i] for i, (_, value) in enumerate(rows) if value == wire)
            require(row == report['processes'][kind - 1] and row['command'] == [str(executable)]
                and row['exit_code'] == 0 and row['reaped'] is True and row['timed_out'] is False
                and row['timeout_seconds'] == 180, 'actual standalone audit JSON process is incomplete')
            for stream in ('stdin', 'stdout', 'stderr'):
                raw = regular(folder / (name + '.' + stream))
                require((row[stream + '_bytes'], row[stream + '_sha256']) == (len(raw), sha(raw)),
                    'standalone audit JSON stream differs')
            require(regular(folder / (name + '.stdin')) == wire and not regular(folder / (name + '.stderr'))
                and regular(folder / (name + '.stdout')) == bytes.fromhex(expected.split(b':')[1].decode()),
                'standalone complete audit JSON bytes differ')
    else:
        cases = test_module(root, 'audit_retention_cases');rows = list(cases.cases())
        enc = lambda value: (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False) + '\n').encode()
        incoming = b''.join(enc(row) for row in rows)
        require(uncompressed(folder, report['inputs']) == incoming, 'complete scripted retention input differs')
        output_rows = [json.loads(line) for line in uncompressed(folder, report['native_results']).splitlines()]
        framed = b''.join(struct.pack('<Q', len(cases.request(row))) + cases.request(row) for row in rows)
        require(uncompressed(folder, report['native_requests']) == framed
            and len(rows) == len(output_rows) == len(report['case_results']) == report['cases'] == 974
            and report['manifest_sha256'] == bundle['modules']['request_audit_retention']['sha256']
            and report['native_machine_invocations'] == 5907
            and report['scripted_child_calls_per_implementation'] == 4933
            and report['original_process'] is None and report['actual_original_processes'] == 0
            and report['all_original_results_and_effect_transcripts_equal'] is False
            and report['child_contracts_scripted'] is True
            and all(report[key] is False for key in ('real_archive_executed', 'real_active_registry_executed',
                'real_hot_filesystem_executed', 'standalone_native_process_qualified')),
            'scripted retention scope or complete execution domain differs')
        for row, actual, observed in zip(rows, output_rows, report['case_results'], strict=True):
            raw = bytes.fromhex(actual['result_hex'])
            require(actual['name'] == row['name'] and all(effect in row['effects'] for effect in actual['trace']),
                'scripted retention effect escaped its fixed fixture')
            require(observed == {'name': row['name'], 'native_calls': actual['native_calls'],
                'child_effects': len(actual['trace']), 'result_bytes': len(raw), 'result_sha256': sha(raw)},
                'scripted retention complete case result differs')
        require(sum(row['native_calls'] for row in output_rows) == 5907
            and sum(len(row['trace']) for row in output_rows) == 4933, 'scripted retention totals differ')
    return {'report': pin(folder / 'result.json'), 'domain': domain,
        'files': {str(p.relative_to(folder)): pin(p) for p in sorted(folder.rglob('*')) if p.is_file()},
        'new_native_executions_by_admission': 0, 'new_original_executions_by_admission': 0}


def native_evidence(root, build, output, processes):
    require(set(processes) == set(DOMAINS), 'not every mandatory audit native process completed')
    result = {};expected = commands(root, build, output)
    for domain in DOMAINS:
        row, stdout, stderr = process_evidence(processes[domain], expected[domain], root)
        require(not stderr and type(json.loads(stdout)) is dict, 'audit native process lacks its complete summary')
        summary = json.loads(stdout);report = object_at(Path(output) / domain / 'result.json')
        require(summary.get('status') == 'PASS' and all(report.get(key) == value for key, value in summary.items()),
            'actual native stdout summary differs from the complete report')
        result[domain] = {'process': row, 'summary': summary,
            'evidence': domain_evidence(root, build, output, domain)}
    return {'schema': 'hepta.audit-readiness.native-evidence.v1', 'status': 'PASS',
        'sources': source_pins(root), 'domains': result, 'mandatory_processes': 24,
        'actual_original_executions': 0, 'production_activated': False, 'audit_storage_closed': False}

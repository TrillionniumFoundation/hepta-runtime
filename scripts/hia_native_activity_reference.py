# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Fresh exact Rust activity lifetimes and hot-cache policy comparisons."""
from pathlib import Path
import json
import os
import shutil
import subprocess
import sys
import time
import tomllib

from audit_activity_registry import REFERENCES as REF_ROOT, encoded, regular, require, sha
from hia_native_activity_qualification import (source_pins as native_sources, object_at, pin,
    native_evidence as admit_native, commands as native_commands, profile, confined)
from activity_evidence import activity_capture, hot_cache_capture
from result_value_registry import REMOVED_ENVIRONMENT
from hia_native_result_reference import archive_files, files

DOMAINS = ('active', 'active_publication', 'hot_cache')
PACKAGES = {'active': 1, 'active_publication': 1, 'hot_cache': 12}
BINS = {'active': 'hia-audit-active-reference',
    'active_publication': 'hia-audit-active-publication-reference',
    'hot_cache': 'hia-audit-hot-cache-reference'}
BLOCKS = {'active': 6, 'active_publication': 6, 'hot_cache': 14}
FIELDS = ('name', 'version', 'source', 'checksum')
RUST_VERSION = b'commit-hash: 59807616e1fa2540724bfbac14d7976d7e4a3860\n'


def original_sources(root):
    root = Path(root);result = dict(native_sources(root))
    for name in ('scripts/hia_native_activity_reference.py', 'scripts/result_value_registry.py',
            'scripts/hia_native_result_reference.py', 'scripts/hia_native_result_qualification.py',
            'tests/hia_native/compare_activity_original.py'):
        result[name] = pin(root / name)
    return dict(sorted(result.items()))


def tool_pin(path):
    path = Path(path).absolute();resolved = path.resolve(strict=True)
    return {'invocation': str(path), 'resolved': str(resolved), **pin(resolved)}


def reference_inputs(root, domain):
    require(domain in DOMAINS, 'unknown original storage owner')
    root = Path(root);project = root / REF_ROOT / domain
    proof = object_at(project / 'reference-inputs.json')
    actual = files(project)
    require(len(proof['original_blocks']) == BLOCKS[domain], 'complete original block count differs')
    require(set(actual) == set(proof['files']) | {'reference-inputs.json'}
        and all(actual[name] == record for name, record in proof['files'].items()),
        'complete original source projection changed')
    for row in proof['original_blocks']:
        original = regular(root / row['source']);target = regular(project / row['target'])
        start, size, destination = row['offset'], row['bytes'], row['target_offset']
        require(sha(original) == row['source_sha256'] and sha(original[start:start + size]) == row['sha256']
            and target[destination:destination + size] == original[start:start + size],
            'an unchanged original source block differs')
    original_lock = regular(root / 'Cargo.lock')
    if (project / 'original-runtime.lock').exists():
        require(regular(project / 'original-runtime.lock') == original_lock, 'original runtime lock changed')
    locked = [row for row in tomllib.loads(regular(project / 'Cargo.lock').decode())['package'] if 'checksum' in row]
    expected = [{key: row[key] for key in FIELDS} for row in proof['original_registry_packages']]
    actual_locked = [{key: row[key] for key in FIELDS} for row in locked]
    original = {(row['name'], row['version']): row for row in tomllib.loads(original_lock.decode())['package']}
    package_key = lambda row: (row['name'], row['version'], row['source'])
    require(len(locked) == PACKAGES[domain] and sorted(actual_locked, key=package_key) == sorted(expected, key=package_key)
        and all(row == {key: original[(row['name'], row['version'])][key] for key in FIELDS}
            for row in actual_locked), 'exact original dependency closure differs')
    manifest = tomllib.loads(regular(project / 'Cargo.toml').decode())
    require(len(manifest['bin']) == 1 and manifest['bin'][0]['name'] == BINS[domain]
        and manifest['bin'][0]['path'] in proof['files'], 'original executable projection differs')
    if domain == 'hot_cache':
        require(manifest['dependencies']['serde_json']['features'] == ['float_roundtrip', 'raw_value'],
            'locked original JSON feature domain differs')
    return proof


def registry(project, retained, metadata, proof, root):
    expected = {(row['name'], row['version'], row['source']): row for row in proof['original_registry_packages']}
    packages = [row for row in metadata['packages'] if row.get('source') is not None]
    require(len(packages) == len(expected)
        and {(row['name'], row['version'], row['source']) for row in packages} == set(expected),
        'actual Cargo dependency set differs')
    retained.mkdir(mode=0o700, exist_ok=True);result = {}
    for package in packages:
        name = package['name'] + '-' + package['version'];source = Path(package['manifest_path']).parent
        require(source.name == name and source.parent.parent.name == 'src', 'actual registry source is unexpected')
        locked = expected[(package['name'], package['version'], package['source'])]
        archive = source.parents[2] / 'cache' / source.parent.name / (name + '.crate')
        raw = regular(archive);members = archive_files(raw, name)
        require(sha(raw) == locked['checksum'] and files(source) == members,
            'actual complete registry source differs from locked package bytes')
        target = retained / (name + '.crate')
        if target.exists():
            require(regular(target) == raw, 'retained package archive changed')
        else:
            with target.open('xb') as stream:
                stream.write(raw)
        result[name] = {'package': {key: locked[key] for key in FIELDS}, 'archive': pin(target),
            'members': len(members), 'members_sha256': sha(encoded(members))}
    return result


def environment(rustc, target, temporary):
    env = {key: value for key, value in os.environ.items() if key not in REMOVED_ENVIRONMENT
        and not key.startswith(('HIA_', 'CARGO_PROFILE_'))
        and not (key.startswith('CARGO_TARGET_') and key.endswith('_RUSTFLAGS'))}
    temporary.mkdir(mode=0o700, parents=True, exist_ok=True)
    env.update(RUSTC=str(Path(rustc).absolute()), CARGO_TARGET_DIR=str(target), TMPDIR=str(temporary),
        PATH=str(Path(rustc).absolute().parent) + os.pathsep + env.get('PATH', os.defpath))
    return env


def run(command, name, folder, root, env, *, timeout=180, data=None, refusal=False):
    """Keep complete streams; children inherit the outer owned group and deadline."""
    folder = Path(folder);command = list(map(str, command));started = time.monotonic()
    report = {'command': command, 'cwd': str(root), 'state': 'RUNNING', 'timeout_seconds': timeout,
        'cleanup_seconds': 3, 'inherits_outer_process_group': True, 'process_group': os.getpgrp(),
        'exit_code': None, 'timed_out': False, 'reaped': False, 'startup_refusal': refusal}
    save = lambda: (folder / (name + '.process.json')).write_bytes(encoded(report))
    save()
    try:
        if data is not None:
            with (folder / (name + '.stdin')).open('xb') as stream:
                stream.write(data)
            report['stdin'] = pin(folder / (name + '.stdin'))
        with (folder / (name + '.stdout')).open('xb') as out, (folder / (name + '.stderr')).open('xb') as err:
            source = (folder / (name + '.stdin')).open('rb') if data is not None else None
            try:
                child = subprocess.Popen(command, cwd=root, env=env, stdin=source or subprocess.DEVNULL,
                    stdout=out, stderr=err)
                report['pid'] = child.pid
                require(os.getpgid(child.pid) == os.getpgrp(), 'reference child escaped its owner group')
                save()
                try:
                    child.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    report['timed_out'] = True;child.kill();child.wait(timeout=3)
                report.update(exit_code=child.returncode, reaped=True)
            finally:
                if source is not None:
                    source.close()
        stdout, stderr = regular(folder / (name + '.stdout')), regular(folder / (name + '.stderr'))
        require(not report['timed_out'] and (report['exit_code'] != 0 if refusal else report['exit_code'] == 0),
            'fresh original process failed: ' + name)
        if refusal:
            require(not stdout and b'runtime config must declare at least one host' in stderr,
                'original startup refusal differs')
        report['state'] = 'PASS'
        return stdout, stderr, report
    except BaseException as error:
        report.update(state='FAIL', error=repr(error));raise
    finally:
        report['elapsed_seconds'] = time.monotonic() - started
        for channel in ('stdout', 'stderr'):
            if (folder / (name + '.' + channel)).exists():
                report[channel] = pin(folder / (name + '.' + channel))
        save()


def build_reference(root, output, domain, rustc, cargo):
    root, output = Path(root).resolve(strict=True), Path(output).resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    proof = reference_inputs(root, domain);pins = original_sources(root)
    project = output / 'reference';shutil.copytree(root / REF_ROOT / domain, project)
    target = output / 'cargo-target';env = environment(rustc, target, output / 'temporary')
    rustc, cargo = Path(rustc).absolute(), Path(cargo).absolute()
    report = {'schema': 'hepta.audit-activity.original-build.v1', 'status': 'RUNNING', 'domain': domain,
        'source_pins': pins, 'projection': proof, 'project_files': files(project), 'checks': {},
        'rustc_path': str(rustc), 'cargo_path': str(cargo), 'tool_pins': {'rustc': tool_pin(rustc), 'cargo': tool_pin(cargo)},
        'environment_removed': list(REMOVED_ENVIRONMENT), 'clear_hia_environment': True,
        'clear_cargo_profile_environment': True, 'clear_target_rustflags': True,
        'owned_tmpdir': str(output / 'temporary'), 'outer_process_group': os.getpgrp(),
        'new_native_executions': 0, 'whole_runtime_replaced': False, 'production_activated': False}
    save = lambda: (output / 'result.json').write_bytes(encoded(report))
    save();started = time.monotonic()
    try:
        stdout, stderr, row = run([rustc, '--version', '--verbose'], 'rust-version', output, root, env, timeout=30)
        report['checks']['rust-version'] = row
        require(stdout.startswith(b'rustc 1.95.0 ') and b'release: 1.95.0\n' in stdout
            and RUST_VERSION in stdout and not stderr, 'actual fixed Rust 1.95 differs')
        stdout, _, row = run([cargo, 'metadata', '--manifest-path', project / 'Cargo.toml',
            '--format-version', '1', '--locked'], 'metadata', output, root, env, timeout=60)
        report['checks']['metadata'] = row;metadata = json.loads(stdout)
        report['registry'] = registry(project, output / 'registry-archives', metadata, proof, root)
        _, _, row = run([cargo, 'build', '--manifest-path', project / 'Cargo.toml', '--release', '--locked', '--bins'],
            'compile', output, root, env)
        report['checks']['compile'] = row
        raw = regular(target / 'release' / BINS[domain]);require(raw.startswith(b'\x7fELF'), 'Rust artifact is not ELF')
        binary = output / BINS[domain];binary.write_bytes(raw);binary.chmod(0o500)
        report['executable'] = {'name': binary.name, **pin(binary)}
        require(original_sources(root) == pins and reference_inputs(root, domain) == proof
            and files(project) == report['project_files']
            and registry(project, output / 'registry-archives', metadata, proof, root) == report['registry']
            and {'rustc': tool_pin(rustc), 'cargo': tool_pin(cargo)} == report['tool_pins'],
            'actual reference source/tool changed during compilation')
        shutil.rmtree(target)
        report.update(status='PASS', intermediate_target_retired=True, sources_unchanged=True)
    except BaseException as error:
        report.update(status='FAIL', error=repr(error));raise
    finally:
        report['elapsed_seconds'] = time.monotonic() - started;save()
    return binary, report


def verify_process(folder, name, command, root, *, timeout=180, refusal=False, data=None):
    folder = Path(folder);row = object_at(folder / (name + '.process.json'))
    require(row.get('command') == list(map(str, command)) and row.get('cwd') == str(root)
        and row.get('state') == 'PASS' and row.get('timeout_seconds') == timeout
        and row.get('cleanup_seconds') == 3 and row.get('timed_out') is False and row.get('reaped') is True
        and row.get('inherits_outer_process_group') is True and row.get('startup_refusal') is refusal
        and type(row.get('process_group')) is int and row['process_group'] > 0
        and type(row.get('pid')) is int and row['pid'] > 0
        and type(row.get('elapsed_seconds')) in (int, float) and 0 <= row['elapsed_seconds'] <= timeout + 3
        and (row.get('exit_code') != 0 if refusal else row.get('exit_code') == 0),
        'actual original process receipt is incomplete or changed')
    streams = {}
    for channel in ('stdout', 'stderr'):
        streams[channel] = regular(folder / (name + '.' + channel))
        require(row[channel] == pin(folder / (name + '.' + channel)), 'actual original stream changed')
    if data is not None:
        require(regular(folder / (name + '.stdin')) == data and row['stdin'] == pin(folder / (name + '.stdin')),
            'complete original input changed')
    else:
        require('stdin' not in row and not (folder / (name + '.stdin')).exists(), 'unexpected original input')
    if refusal:
        require(not streams['stdout'] and b'runtime config must declare at least one host' in streams['stderr'],
            'actual original startup refusal differs')
    return row, streams


def build_evidence(root, folder, domain):
    root, folder = Path(root).resolve(strict=True), Path(folder).resolve(strict=True)
    report = object_at(folder / 'result.json');proof = reference_inputs(root, domain)
    project = folder / 'reference';rustc = Path(report['rustc_path']);cargo = Path(report['cargo_path'])
    require(report.get('schema') == 'hepta.audit-activity.original-build.v1' and report.get('status') == 'PASS'
        and report.get('domain') == domain and report.get('source_pins') == original_sources(root)
        and report.get('projection') == proof and report.get('project_files') == files(project) == files(root / REF_ROOT / domain)
        and report.get('tool_pins') == {'rustc': tool_pin(rustc), 'cargo': tool_pin(cargo)}
        and report.get('environment_removed') == list(REMOVED_ENVIRONMENT)
        and all(report.get(key) is True for key in ('clear_hia_environment', 'clear_cargo_profile_environment',
            'clear_target_rustflags', 'intermediate_target_retired', 'sources_unchanged'))
        and report.get('owned_tmpdir') == str(folder / 'temporary')
        and all(report.get(key) is False for key in ('whole_runtime_replaced', 'production_activated'))
        and report.get('new_native_executions') == 0 and not (folder / 'cargo-target').exists(),
        'fresh original build or exact inputs differ')
    expected = {
        'rust-version': ([rustc, '--version', '--verbose'], 30),
        'metadata': ([cargo, 'metadata', '--manifest-path', project / 'Cargo.toml', '--format-version', '1', '--locked'], 60),
        'compile': ([cargo, 'build', '--manifest-path', project / 'Cargo.toml', '--release', '--locked', '--bins'], 180),
    }
    require(set(report['checks']) == set(expected), 'fresh original build process domain differs')
    metadata = None
    for name, (command, limit) in expected.items():
        row, streams = verify_process(folder, name, command, root, timeout=limit)
        require(row == report['checks'][name] and row['process_group'] == report['outer_process_group'],
            'fresh build process receipt differs from its actual streams')
        if name == 'rust-version':
            require(streams['stdout'].startswith(b'rustc 1.95.0 ') and b'release: 1.95.0\n' in streams['stdout']
                and RUST_VERSION in streams['stdout'] and not streams['stderr'], 'fixed Rust 1.95 bytes differ')
        if name == 'metadata':
            metadata = json.loads(streams['stdout'])
    expected_packages = {row['name'] + '-' + row['version']: row for row in proof['original_registry_packages']}
    require(set(report['registry']) == set(expected_packages)
        and {path.name for path in (folder / 'registry-archives').iterdir()}
            == {name + '.crate' for name in expected_packages}, 'locked retained package domain differs')
    for name, package in expected_packages.items():
        path = folder / 'registry-archives' / (name + '.crate');raw = regular(path)
        require(sha(raw) == package['checksum'], 'retained package checksum differs')
        members = archive_files(raw, name)
        require(report['registry'][name] == {'package': {key: package[key] for key in FIELDS},
            'archive': pin(path), 'members': len(members), 'members_sha256': sha(encoded(members))},
            'complete retained package member inventory differs')
    packages = [row for row in metadata['packages'] if row.get('source') is not None]
    require(len(packages) == len(expected_packages) and {(row['name'], row['version'], row['source']) for row in packages}
        == {(row['name'], row['version'], row['source']) for row in expected_packages.values()},
        'actual fresh Cargo metadata differs from the locked source closure')
    binary = folder / BINS[domain]
    require(binary.stat().st_mode & 0o777 == 0o500 and regular(binary).startswith(b'\x7fELF')
        and report['executable'] == {'name': binary.name, **pin(binary)}, 'fresh original executable changed')
    return report


def captured_native(root, build, native, evidence, evidence_sha256):
    path = Path(evidence).resolve(strict=True);raw = regular(path)
    require(sha(raw) == evidence_sha256, 'externally bound native activity seal differs')
    record = json.loads(raw)
    require(record.get('schema') == 'hepta.audit-activity.native-run.v1' and record.get('status') == 'PASS'
        and record.get('sources') == native_sources(root), 'actual native activity run is incomplete')
    expected = {domain: str(Path(native) / 'processes' / domain)
        for domain in native_commands(root, build, native)}
    require(record.get('processes') == expected, 'native activity process origins differ')
    current = admit_native(root, build, native, expected)
    require(current == record.get('evidence'), 'complete native activity capture changed')
    return current


def comparison_command(root, build, output, domain, binary):
    command = native_commands(root, build, Path(output) / 'paired')[domain]
    return command + ['--oracle', str(binary)]


def compare_bytes(root, build, output, domain, binary):
    folder = Path(output) / 'paired' / domain
    bundle = object_at(Path(build) / 'audit-activity-build.json')
    if domain in ('active', 'active_publication'):
        path = confined(build, bundle['graphs'][domain]['path'])
        executable = path.parent / object_at(path)['executable']
        report = activity_capture(root, folder, domain,
            {'native': pin(executable)['sha256'], 'original': pin(binary)['sha256']})
        return report, {'original_processes': report['actual_original_processes'],
            'original_requests': report['requests_per_implementation'],
            'native_processes_added_by_original_recipe': report['actual_native_processes'],
            'native_machine_invocations_added_by_original_recipe': 0,
            'complete_exact_frames_equal': True,
            'exact_tagged_frames': report['exact_tagged_frames_per_implementation'],
            'commuting_operations': report['commuting_operations_per_implementation'],
            'complete_commuting_phase_multisets_equal': True, 'ordered_scripted_child_calls': 0}
    stem = profile(root)['owners'][domain]
    report = hot_cache_capture(root, folder, bundle['modules'][stem]['sha256'], pin(binary)['sha256'])
    return report, {'original_processes': report['actual_original_processes'],
        'original_requests': report['commands_per_implementation'],
        'native_processes_added_by_original_recipe': 0,
        'native_machine_invocations_added_by_original_recipe': report['native_machine_invocations'],
        'complete_returned_bytes_equal': True, 'ordered_scripted_child_calls': 6000,
        'real_archive_executed': False, 'real_hot_filesystem_executed': False}


def replay(root, build, native, output, domain, evidence, evidence_sha256, rustc, cargo):
    root, build, native = map(lambda path: Path(path).resolve(strict=True), (root, build, native))
    output = Path(output).resolve();output.mkdir(mode=0o700, parents=True, exist_ok=False)
    require(domain in DOMAINS, 'unknown original activity domain')
    sources = original_sources(root)
    before = captured_native(root, build, native, evidence, evidence_sha256)
    report = {'schema': 'hepta.audit-activity.original-comparison.v1', 'status': 'RUNNING',
        'domain': domain, 'sources': sources, 'native_evidence_path': str(Path(evidence).resolve(strict=True)),
        'native_evidence_sha256': evidence_sha256, 'native_evidence': before,
        'production_activated': False, 'public_request_dispatch_qualified': False,
        'audit_storage_closed': False, 'whole_runtime_replaced': False,
        'native_language_unwind_qualified': False, 'hot_cache_storage_children_scripted': domain == 'hot_cache'}
    save = lambda: (output / 'result.json').write_bytes(encoded(report))
    started = time.monotonic();save()
    try:
        binary, original = build_reference(root, output / 'reference-build', domain, rustc, cargo)
        report['reference_build'] = original;save()
        command = comparison_command(root, build, output, domain, binary)
        env = environment(rustc, output / 'unused-target', output / 'temporary')
        stdout, stderr, process = run(command, 'complete-comparison', output, root, env)
        require(not stderr, 'complete actual activity comparison emitted stderr')
        paired, comparison = compare_bytes(root, build, output, domain, binary)
        summary = json.loads(stdout)
        require(type(summary) is dict and summary.get('status') == 'PASS'
            and all(paired.get(key) == value for key, value in summary.items()),
            'actual original comparison stdout differs from full streams')
        report.update(comparison_process=process, comparison=comparison,
            comparison_report=pin(output / 'paired' / domain / 'result.json'))
        require(original_sources(root) == sources
            and captured_native(root, build, native, evidence, evidence_sha256) == before,
            'activity source or native capture changed during original replay')
        require(build_evidence(root, output / 'reference-build', domain) == original,
            'reference build changed during complete activity comparison')
        report.update(status='PASS', sources_unchanged=True, full_capture_unchanged=True)
    except BaseException as error:
        report.update(status='FAIL', error=repr(error));raise
    finally:
        report['elapsed_seconds'] = time.monotonic() - started;save()
    return original_evidence(root, build, native, output, domain, evidence, evidence_sha256)


def original_evidence(root, build, native, output, domain, evidence, evidence_sha256):
    root, build, native, output = map(lambda path: Path(path).resolve(strict=True), (root, build, native, output))
    report = object_at(output / 'result.json')
    require(report.get('schema') == 'hepta.audit-activity.original-comparison.v1'
        and report.get('status') == 'PASS' and report.get('domain') == domain
        and report.get('sources') == original_sources(root)
        and report.get('native_evidence_path') == str(Path(evidence).resolve(strict=True))
        and report.get('native_evidence_sha256') == evidence_sha256
        and report.get('sources_unchanged') is True and report.get('full_capture_unchanged') is True
        and report.get('hot_cache_storage_children_scripted') is (domain == 'hot_cache')
        and all(report.get(key) is False for key in ('production_activated', 'public_request_dispatch_qualified',
            'audit_storage_closed', 'whole_runtime_replaced', 'native_language_unwind_qualified')),
        'actual original activity evidence is incomplete or expanded its scope')
    require(captured_native(root, build, native, evidence, evidence_sha256) == report['native_evidence'],
        'original activity evidence refers to changed native execution')
    original = build_evidence(root, output / 'reference-build', domain)
    require(original == report['reference_build'], 'actual original activity build differs')
    binary = output / 'reference-build' / original['executable']['name']
    process, streams = verify_process(output, 'complete-comparison',
        comparison_command(root, build, output, domain, binary), root)
    require(process == report['comparison_process'] and not streams['stderr'],
        'actual original activity comparison process differs')
    paired, comparison = compare_bytes(root, build, output, domain, binary)
    summary = json.loads(streams['stdout'])
    require(type(summary) is dict and summary.get('status') == 'PASS'
        and all(paired.get(key) == value for key, value in summary.items())
        and comparison == report['comparison']
        and pin(output / 'paired' / domain / 'result.json') == report['comparison_report'],
        'original activity complete comparison or stdout changed')
    return {'schema': 'hepta.audit-activity.original-evidence.v1', 'status': 'PASS', 'domain': domain,
        'report': pin(output / 'result.json'), 'comparison': comparison,
        'files': files(output), 'source_pins': original_sources(root),
        'new_native_executions_by_admission': 0, 'new_original_executions_by_admission': 0}

# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Fresh original audit owners, with complete current native capture binding."""
from pathlib import Path
import json
import os
import shutil
import subprocess
import time
import tomllib

from audit_readiness_registry import REFERENCES as REF_ROOT, encoded, regular, require, sha
from hia_native_audit_qualification import (FS, PURE, DOMAINS as NATIVE_DOMAINS,
    domain_evidence, object_at, pin, source_pins as native_sources, test_module, uncompressed)
from result_value_registry import REMOVED_ENVIRONMENT
from hia_native_result_reference import archive_files, files

DOMAINS = ('audit_directory', 'audit_entries', 'audit_json', 'audit_lock', 'audit_read', 'audit_remove', 'audit_retention_policy', 'audit_write', 'prepare')
PACKAGES = {'audit_directory': 2, 'audit_entries': 13, 'audit_json': 11, 'audit_lock': 0, 'audit_read': 13, 'audit_remove': 13, 'audit_retention_policy': 12, 'audit_write': 19, 'prepare': 22}
BINS = {'audit_directory': 'hia-request-audit-directory-reference', 'audit_entries': 'hia-audit-entries-reference', 'audit_json': 'hia-audit-json-reference', 'audit_lock': 'hia-audit-lock-reference', 'audit_read': 'hia-audit-read-reference', 'audit_remove': 'hia-audit-remove-reference', 'audit_retention_policy': 'hia-audit-retention-reference', 'audit_write': 'hia-audit-write-reference', 'prepare': 'hia-request-storage-prepare-reference'}
BLOCKS = {'audit_directory': 12, 'audit_entries': 19, 'audit_json': 8, 'audit_lock': 10, 'audit_read': 17, 'audit_remove': 18, 'audit_retention_policy': 10, 'audit_write': 21, 'prepare': 36}
FIELDS = ('name', 'version', 'source', 'checksum')
RUST_VERSION = b'commit-hash: 59807616e1fa2540724bfbac14d7976d7e4a3860\n'

def original_sources(root):
    root = Path(root);result = dict(native_sources(root))
    for name in ('scripts/hia_native_audit_reference.py', 'scripts/result_value_registry.py',
            'scripts/hia_native_result_reference.py', 'scripts/hia_native_result_qualification.py',
            'tests/hia_native/compare_audit_original.py'):
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
    if domain not in ('audit_directory', 'audit_lock'):
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
    report = {'schema': 'hepta.audit-readiness.original-build.v1', 'status': 'RUNNING', 'domain': domain,
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
    require(report.get('schema') == 'hepta.audit-readiness.original-build.v1' and report.get('status') == 'PASS'
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


def native_evidence(root, build, native, domain, evidence_path, evidence_sha256):
    from hia_native_audit_qualification import commands, process_evidence, build_evidence as native_build
    require(domain in DOMAINS, 'unknown audit original owner')
    root, build, native = map(Path, (root, build, native))
    raw = regular(evidence_path);require(sha(raw) == evidence_sha256, 'current native evidence seal changed')
    report = json.loads(raw)
    require(report.get('schema') == 'hepta.audit-readiness.native-evidence.v1'
        and report.get('status') == 'PASS' and report.get('sources') == native_sources(root)
        and set(report.get('domains', {})) == set(NATIVE_DOMAINS)
        and report.get('mandatory_processes') == 24 and report.get('actual_original_executions') == 0
        and report.get('production_activated') is False and report.get('audit_storage_closed') is False,
        'current native source or complete execution domain changed')
    names = [domain]
    names += [name for name in (domain + '_faults', domain + '_edges') if name in FS]
    control = domain.removesuffix('_policy') + '_controls'
    if control in NATIVE_DOMAINS:
        names.append(control)
    actual = {};expected = commands(root, build, native)
    for name in names:
        old = report['domains'][name]
        value = domain_evidence(root, build, native, name)
        row, stdout, stderr = process_evidence(native / 'processes' / name, expected[name], root)
        summary = json.loads(stdout)
        require(not stderr and old == {'process': row, 'summary': summary, 'evidence': value},
            'complete current native execution or capture changed')
        actual[name] = old
    return {'domains': actual, 'build_artifacts': native_build(root, build, require_process=False)['artifact_pins']}


def pure_input(root, native, domain):
    folder = Path(native) / domain
    if domain == 'audit_json':
        rows = list(test_module(root, 'audit_json_cases').cases())
        incoming = b''.join(wire.hex().encode() + b'\n' for _, wire in rows)
        require(incoming == regular(folder / 'reference.stdin') and len(rows) == 3390,
            'complete audit JSON input changed')
        return incoming
    require(domain == 'audit_retention_policy', 'unknown pure audit owner')
    cases = list(test_module(root, 'audit_retention_cases').cases())
    compact = lambda value: (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False) + '\n').encode()
    incoming = b''.join(compact(row) for row in cases)
    report = object_at(folder / 'result.json')
    require(len(cases) == 974 and incoming == uncompressed(folder, report['inputs']),
        'complete scripted retention input changed')
    return incoming


def compare_pure(native, domain, stdout, stderr):
    folder = Path(native) / domain
    require(not stderr, 'original audit oracle emitted stderr')
    if domain == 'audit_json':
        require(stdout == regular(folder / 'native.stdout') and len(stdout.splitlines()) == 3390,
            'complete actual original/native audit JSON bytes differ')
        return {'original_requests': 3390, 'original_processes': 1,
            'complete_original_native_bytes_equal': True, 'ordered_scripted_child_calls': 0}
    report = object_at(folder / 'result.json')
    reference = [json.loads(line) for line in stdout.splitlines()]
    actual = [json.loads(line) for line in uncompressed(folder, report['native_results']).splitlines()]
    require(len(reference) == len(actual) == 974, 'complete original retention replay truncated')
    effects = 0
    for old, new in zip(reference, actual, strict=True):
        require(set(old) == {'name', 'result_hex', 'trace', 'original_policy_executed',
                'real_archive_executed', 'real_active_registry_executed', 'real_hot_filesystem_executed'}
            and old['original_policy_executed'] is True
            and all(old[key] is False for key in ('real_archive_executed', 'real_active_registry_executed',
                'real_hot_filesystem_executed'))
            and all(old[key] == new[key] for key in ('name', 'result_hex', 'trace')),
            'complete original retention result or ordered scripted effects differ')
        effects += len(old['trace'])
    require(effects == 4933, 'complete original scripted child count differs')
    return {'original_requests': 974, 'original_processes': 1,
        'complete_original_native_bytes_equal': True, 'ordered_scripted_child_calls': effects}


def summary(report):
    return {key: report[key] for key in ('schema', 'status', 'phase', 'domain', 'case_count',
        'requests', 'processes', 'deliberately_killed_requests', 'new_original_processes',
        'new_native_processes', 'semantic_reference_comparison_complete', 'elapsed_seconds')}


def replay_domain(root, build, native, output, domain, evidence, evidence_sha256, rustc, cargo):
    root, build, native = (Path(path).resolve(strict=True) for path in (root, build, native))
    output = Path(output).resolve();output.mkdir(mode=0o700, parents=True, exist_ok=False)
    sources = original_sources(root);captured = native_evidence(root, build, native, domain, evidence, evidence_sha256)
    report = {'schema': 'hepta.audit-readiness.original-comparison.v1', 'status': 'RUNNING', 'domain': domain,
        'sources': sources, 'native_evidence_path': str(evidence), 'native_evidence_sha256': evidence_sha256,
        'native_domains': captured, 'new_native_executions': 0, 'reference_checks': {},
        'whole_runtime_replaced': False, 'production_activated': False, 'audit_storage_closed': False}
    save = lambda: (output / 'result.json').write_bytes(encoded(report))
    save();started = time.monotonic()
    try:
        binary, built = build_reference(root, output / 'build', domain, rustc, cargo)
        report['build_result_sha256'] = pin(output / 'build/result.json')['sha256']
        env = environment(rustc, output / 'unused-target', output / 'temporary')
        if domain in PURE:
            folder = output / 'replay';folder.mkdir(mode=0o700)
            stdout, stderr, row = run([binary], 'complete', folder, root, env,
                data=pure_input(root, native, domain))
            report['reference_checks']['complete'] = row
            report['replay'] = compare_pure(native, domain, stdout, stderr)
        else:
            requests = processes = 0
            for name in captured['domains']:
                if name not in FS:
                    continue
                command = [os.sys.executable, '-I', '-B', str(root / 'tests/hia_native/test_audit_readiness_fs.py'),
                    '--domain', name, '--phase', 'original', '--executable', str(binary),
                    '--output', str(output / name), '--native-capture', str(native / name)]
                stdout, stderr, row = run(command, name, output, root, env)
                observed = object_at(output / name / 'result.json')
                require(not stderr and json.loads(stdout) == summary(observed)
                    and observed['status'] == 'PASS' and observed['phase'] == 'original'
                    and observed['new_native_processes'] == 0
                    and observed['semantic_reference_comparison_complete'] is True,
                    'actual complete original filesystem process did not compare')
                report['reference_checks'][name] = row
                requests += observed['requests'];processes += observed['new_original_processes']
            report['replay'] = {'original_requests': requests, 'original_processes': processes,
                'complete_original_native_bytes_equal': True, 'ordered_scripted_child_calls': 0}
        require(native_evidence(root, build, native, domain, evidence, evidence_sha256) == captured
            and original_sources(root) == sources and build_evidence(root, output / 'build', domain) == built,
            'actual original input or binary changed during comparison')
        report.update(status='PASS', sources_unchanged=True)
    except BaseException as error:
        report.update(status='FAIL', error=repr(error));raise
    finally:
        report['elapsed_seconds'] = time.monotonic() - started;save()
    return report


def original_evidence(root, build, native, output, domain, evidence, evidence_sha256):
    """Read every current input, process stream, native result and original result."""
    root, build, native, output = (Path(path).resolve(strict=True) for path in (root, build, native, output))
    inventory = test_module(root, 'test_audit_readiness_fs').inventory
    report = object_at(output / 'result.json')
    captured = native_evidence(root, build, native, domain, evidence, evidence_sha256)
    require(report.get('schema') == 'hepta.audit-readiness.original-comparison.v1'
        and report.get('status') == 'PASS' and report.get('domain') == domain
        and report.get('sources') == original_sources(root) and report.get('sources_unchanged') is True
        and report.get('native_evidence_path') == str(evidence)
        and report.get('native_evidence_sha256') == evidence_sha256
        and report.get('native_domains') == captured and report.get('new_native_executions') == 0
        and all(report.get(key) is False for key in ('whole_runtime_replaced', 'production_activated',
            'audit_storage_closed')), 'original complete comparison is incomplete or changed')
    build_evidence(root, output / 'build', domain)
    require(report['build_result_sha256'] == pin(output / 'build/result.json')['sha256'],
        'actual original build result changed')
    binary = output / 'build' / BINS[domain]
    if domain in PURE:
        require(set(report['reference_checks']) == {'complete'}, 'original pure process domain differs')
        row, streams = verify_process(output / 'replay', 'complete', [binary], root,
            data=pure_input(root, native, domain))
        require(row == report['reference_checks']['complete']
            and report['replay'] == compare_pure(native, domain, streams['stdout'], streams['stderr']),
            'actual pure comparison differs from its complete streams')
    else:
        harness = test_module(root, 'test_audit_readiness_fs');requests = processes = 0
        names = set(captured['domains']) & set(FS)
        require(set(report['reference_checks']) == names, 'complete original filesystem domain differs')
        for name in sorted(names):
            folder = output / name;result = object_at(folder / 'result.json')
            command = [os.sys.executable, '-I', '-B', str(root / 'tests/hia_native/test_audit_readiness_fs.py'),
                '--domain', name, '--phase', 'original', '--executable', str(binary),
                '--output', str(folder), '--native-capture', str(native / name)]
            receipt, streams = verify_process(output, name, command, root)
            require(receipt == report['reference_checks'][name] and not streams['stderr']
                and json.loads(streams['stdout']) == summary(result)
                and result['status'] == 'PASS' and result['phase'] == 'original' and result['domain'] == name
                and result['source_files'] == harness.source_files() and result['source_unchanged'] is True
                and result['executable'] == harness.pin(binary) and result['new_native_processes'] == 0
                and result['semantic_reference_comparison_complete'] is True
                and all(result.get(key) is False for key in harness.SCOPE),
                'actual original filesystem process, scope or executable differs')
            rows = harness.definitions(name)
            require(regular(folder / 'definitions.json') == harness.ENCODE(rows)
                and result['definitions'] == harness.pin(folder / 'definitions.json')
                and len(rows) == len(result['cases']), 'complete original definitions changed')
            for index, (definition, record) in enumerate(zip(rows, result['cases'], strict=True)):
                case = folder / f'{index:04d}';paired = native / name / f'{index:04d}'
                require(record['index'] == index and record['name'] == definition['name']
                    and record['completed'] is True and record['artifacts'] == harness.inventory(case)
                    and record['semantic'] == harness.pin(case / 'semantic-comparison.json')
                    and record['complete_output'] == harness.pin(case / 'complete-projected-output.bin')
                    and regular(case / 'semantic-comparison.json') == regular(paired / 'semantic-comparison.json')
                    and regular(case / 'complete-projected-output.bin') == regular(paired / 'complete-projected-output.bin'),
                    'complete original/native filesystem responses or observations differ')
            _, count, request_count, process_count, killed = harness.DOMAINS[name]
            require((result['case_count'], result['requests'], result['processes'],
                    result['deliberately_killed_requests'], result['new_original_processes'])
                == (count, request_count, process_count, killed, process_count),
                'complete original request, process or deliberate-death count differs')
            requests += request_count;processes += process_count
        require(report['replay'] == {'original_requests': requests, 'original_processes': processes,
            'complete_original_native_bytes_equal': True, 'ordered_scripted_child_calls': 0},
            'complete original process count differs')
    return {'schema': 'hepta.audit-readiness.original-evidence.v1', 'domain': domain,
        **report['replay'], 'sources': original_sources(root), 'artifacts': inventory(output),
        'new_native_executions_by_admission': 0, 'new_original_executions_by_admission': 0,
        'native_evidence_sha256': evidence_sha256}

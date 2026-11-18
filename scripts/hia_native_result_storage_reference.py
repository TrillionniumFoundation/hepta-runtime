# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Fresh exact original storage builds and full retained-native comparisons."""
from pathlib import Path
import json
import os
import shutil
import subprocess
import time
import tomllib

from result_storage_registry import REF_ROOT, encoded, regular, require, sha
from result_value_registry import REMOVED_ENVIRONMENT, sdk_sources
from hia_native_result_reference import archive_files, files
from hia_native_result_storage_qualification import (FS, PURE, domain_evidence, object_at,
    pin, source_pins)

DOMAINS = ('safe_dto', 'retention', 'storage_json', 'record_validation', 'record_io',
    'directory', 'archive_metadata', 'archive_publish', 'archive_store')
PACKAGES = {'safe_dto': 100, 'retention': 100, 'storage_json': 11, 'record_validation': 22,
    'record_io': 22, 'directory': 2, 'archive_metadata': 22, 'archive_publish': 22, 'archive_store': 22}
BINS = {'safe_dto': 'hia-safe-dto-reference', 'retention': 'hia-request-retention-reference',
    'storage_json': 'hia-storage-json-reference', 'record_validation': 'hia-request-record-validation-reference',
    'record_io': 'hia-request-record-io-reference', 'directory': 'hia-request-store-directory-reference',
    'archive_metadata': 'hia-request-archive-metadata-reference',
    'archive_publish': 'hia-request-archive-publish-reference', 'archive_store': 'hia-request-archive-store-reference'}
FIELDS = ('name', 'version', 'source', 'checksum')
RUST_VERSION = b'commit-hash: 59807616e1fa2540724bfbac14d7976d7e4a3860\n'


def tool_pin(path):
    path = Path(path).absolute();resolved = path.resolve(strict=True)
    return {'invocation': str(path), 'resolved': str(resolved), **pin(resolved)}


def reference_inputs(root, domain):
    require(domain in DOMAINS, 'unknown original storage owner')
    root = Path(root);project = root / REF_ROOT / domain
    proof = object_at(project / 'reference-inputs.json')
    actual = files(project)
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
    if domain != 'directory':
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
        if name == 'rmcp-3.4.1':
            require(members == sdk_sources(root), 'complete original SDK source differs')
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
    proof = reference_inputs(root, domain);pins = source_pins(root)
    project = output / 'reference';shutil.copytree(root / REF_ROOT / domain, project)
    target = output / 'cargo-target';env = environment(rustc, target, output / 'temporary')
    rustc, cargo = Path(rustc).absolute(), Path(cargo).absolute()
    report = {'schema': 'hepta.result-storage.original-build.v1', 'status': 'RUNNING', 'domain': domain,
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
        require(source_pins(root) == pins and reference_inputs(root, domain) == proof
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
    require(report.get('schema') == 'hepta.result-storage.original-build.v1' and report.get('status') == 'PASS'
        and report.get('domain') == domain and report.get('source_pins') == source_pins(root)
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
        if name == 'rmcp-3.4.1':
            require(members == sdk_sources(root), 'complete retained SDK differs')
    packages = [row for row in metadata['packages'] if row.get('source') is not None]
    require(len(packages) == len(expected_packages) and {(row['name'], row['version'], row['source']) for row in packages}
        == {(row['name'], row['version'], row['source']) for row in expected_packages.values()},
        'actual fresh Cargo metadata differs from the locked source closure')
    binary = folder / BINS[domain]
    require(binary.stat().st_mode & 0o777 == 0o500 and regular(binary).startswith(b'\x7fELF')
        and report['executable'] == {'name': binary.name, **pin(binary)}, 'fresh original executable changed')
    return report


def native_evidence(root, build, native, domain, evidence_path, evidence_sha256):
    from hia_native_result_storage_qualification import (commands, process_evidence, summary_from_report,
        build_evidence as native_build_evidence)
    raw = regular(evidence_path);require(sha(raw) == evidence_sha256, 'current native admission seal differs')
    report = json.loads(raw)
    require(report['schema'] == 'hepta.result-storage.native-evidence.v1'
        and report['sources'] == source_pins(root) and set(report['domains']) == set(PURE + FS)
        and report['actual_original_executions'] == report['new_native_executions_by_admission']
            == report['new_original_executions_by_admission'] == 0,
        'current complete native qualification identity differs')
    require(report['build_artifacts'] == native_build_evidence(root, build, require_process=False)['artifact_pins'],
        'current complete compiled native artifacts changed')
    names = (domain, domain + '_faults') if domain + '_faults' in FS else (domain,)
    selected = {}
    for name in names:
        value = domain_evidence(root, build, native, name);old = report['domains'][name]
        require(value['corpus'] == old['corpus'] and value['artifacts'] == old['artifacts']
            and pin(Path(native) / name / 'result.json')['sha256'] == old['result_sha256'],
            'current native complete corpus changed before original replay')
        row, stdout, stderr = process_evidence(old['process_directory'], commands(root, build, native)[name], root)
        require(row == old['process'] and not stderr and json.loads(stdout) == summary_from_report(name, value['result']),
            'current native externally completed process differs')
        selected[name] = old
    return selected


def replay_pure(root, binary, folder, native, domain, environment):
    from result_storage_native_evidence import fixture, test_module
    folder.mkdir(mode=0o700);checks = {};requests = processes = 0
    if domain in ('storage_json', 'record_validation'):
        streams, _ = fixture(root, domain, '', 'original', Path(native) / domain, suffix='')
        out, err, receipt = run([binary], 'complete', folder, root, environment, data=streams['input'])
        require(out == streams['stdout'] == regular(Path(native) / domain / 'native.stdout') and not err,
            'fresh complete original/native projection differs')
        checks['complete'] = receipt;requests = len(streams['input'].splitlines());processes = 1
    else:
        configurations = test_module(root, 'result_storage_fixture').configurations(domain)
        for label, hosts in configurations.items():
            directory = folder / label;directory.mkdir(mode=0o700)
            config = None
            if hosts is not None:
                config = directory / 'config.json'
                config.write_bytes(encoded({'state_dir': str(directory / 'state'), 'hosts': hosts}));config.chmod(0o600)
            command = [binary] + (['--runtime-config', config] if config else [])
            names = ('original-startup',) if hosts == {} else ('original-summaries',
                *(() if domain == 'safe_dto' else ('original-size-probes',)), 'original-cases')
            for name in names:
                streams, _ = fixture(root, domain, label, name, Path(native) / domain / label, refusal=hosts == {})
                out, err, receipt = run(command, name, directory, root, environment,
                    data=streams['input'], refusal=hosts == {})
                require(out == streams['stdout'] and err == streams['stderr'],
                    'fresh original complete profile response differs: ' + label + '/' + name)
                checks[label + '/' + name] = receipt;requests += len(streams['input'].splitlines());processes += 1
            if hosts != {}:
                test_module(root, 'test_result_safe_dto').locks_released(directory / 'state' if config else None)
            if hosts == {}:
                require(not (directory / 'state').exists(), 'invalid original configuration installed state')
    return {'checks': checks, 'original_requests': requests, 'original_processes': processes,
        'complete_original_native_bytes_equal': True}


def replay_domain(root, build, native, output, domain, evidence, evidence_sha256, rustc, cargo):
    root, build, native = (Path(path).resolve(strict=True) for path in (root, build, native))
    output = Path(output).resolve();output.mkdir(mode=0o700, parents=True, exist_ok=False)
    sources = source_pins(root);captured = native_evidence(root, build, native, domain, evidence, evidence_sha256)
    report = {'schema': 'hepta.result-storage.original-comparison.v1', 'status': 'RUNNING', 'domain': domain,
        'sources': sources, 'native_evidence_path': str(evidence), 'native_evidence_sha256': evidence_sha256,
        'native_domains': captured, 'new_native_executions': 0, 'reference_checks': {},
        'whole_runtime_replaced': False, 'production_activated': False, 'result_storage_closed': False}
    save = lambda: (output / 'result.json').write_bytes(encoded(report))
    save();started = time.monotonic()
    try:
        binary, built = build_reference(root, output / 'build', domain, rustc, cargo)
        report['build_result_sha256'] = pin(output / 'build/result.json')['sha256']
        env = environment(rustc, output / 'unused-target', output / 'temporary')
        if domain in PURE:
            report['replay'] = replay_pure(root, binary, output / 'replay', native, domain, env)
        else:
            from hia_native_result_storage_qualification import summary_from_report
            test = root / 'tests/hia_native/test_result_storage_fs.py';processes = requests = 0
            for name in captured:
                command = [os.sys.executable, '-I', '-B', str(test), '--domain', name, '--phase', 'original',
                    '--executable', str(binary), '--output', str(output / name), '--native-capture', str(native / name)]
                stdout, stderr, row = run(command, name, output, root, env)
                completed = object_at(output / name / 'result.json')
                require(not stderr and completed['status'] == 'PASS' and completed['phase'] == 'original'
                    and json.loads(stdout) == summary_from_report(name, completed)
                    and completed['semantic_reference_comparison_complete'] is True
                    and completed['new_native_processes'] == 0, 'actual original filesystem comparison incomplete')
                report['reference_checks'][name] = row
                requests += completed['requests'];processes += completed['new_original_processes']
            report['replay'] = {'original_requests': requests, 'original_processes': processes,
                'complete_original_native_bytes_equal': True}
        require(native_evidence(root, build, native, domain, evidence, evidence_sha256) == captured
            and source_pins(root) == sources and build_evidence(root, output / 'build', domain) == built,
            'actual complete original comparison inputs changed')
        report.update(status='PASS', sources_unchanged=True)
    except BaseException as error:
        report.update(status='FAIL', error=repr(error));raise
    finally:
        report['elapsed_seconds'] = time.monotonic() - started;save()
    return report


def verify_pure_replay(root, binary, folder, native, domain, report):
    from result_storage_native_evidence import fixture, test_module
    checks = {};requests = processes = 0
    if domain in ('storage_json', 'record_validation'):
        streams, _ = fixture(root, domain, '', 'original', Path(native) / domain, suffix='')
        row, actual = verify_process(folder, 'complete', [binary], root, data=streams['input'])
        require(actual['stdout'] == streams['stdout'] == regular(Path(native) / domain / 'native.stdout')
            and not actual['stderr'], 'fresh complete original/native stream changed')
        checks['complete'] = row;requests = len(streams['input'].splitlines());processes = 1
    else:
        for label, hosts in test_module(root, 'result_storage_fixture').configurations(domain).items():
            directory = folder / label;config = directory / 'config.json' if hosts is not None else None
            if config:
                require(json.loads(regular(config)) == {'state_dir': str(directory / 'state'), 'hosts': hosts},
                    'original administrator fixture changed')
            command = [binary] + (['--runtime-config', config] if config else [])
            names = ('original-startup',) if hosts == {} else ('original-summaries',
                *(() if domain == 'safe_dto' else ('original-size-probes',)), 'original-cases')
            for name in names:
                streams, _ = fixture(root, domain, label, name, Path(native) / domain / label, refusal=hosts == {})
                row, actual = verify_process(directory, name, command, root, data=streams['input'], refusal=hosts == {})
                require(actual['stdout'] == streams['stdout'] and actual['stderr'] == streams['stderr'],
                    'fresh original complete profile stream changed')
                checks[label + '/' + name] = row;requests += len(streams['input'].splitlines());processes += 1
            if hosts == {}:
                require(not (directory / 'state').exists(), 'invalid original configuration left installed state')
    require(report == {'checks': checks, 'original_requests': requests, 'original_processes': processes,
        'complete_original_native_bytes_equal': True}, 'complete original replay domain differs')


def original_evidence(root, build, native, output, domain, evidence, evidence_sha256):
    """Recheck build, every original response and every current native counterpart."""
    from hia_native_result_storage_qualification import summary_from_report
    from result_storage_native_evidence import inventory, test_module
    root, build, native, output = (Path(path).resolve(strict=True) for path in (root, build, native, output))
    report = object_at(output / 'result.json')
    captured = native_evidence(root, build, native, domain, evidence, evidence_sha256)
    require(report.get('schema') == 'hepta.result-storage.original-comparison.v1'
        and report.get('status') == 'PASS' and report.get('domain') == domain
        and report.get('sources') == source_pins(root) and report.get('sources_unchanged') is True
        and report.get('native_evidence_path') == str(evidence) and report.get('native_evidence_sha256') == evidence_sha256
        and report.get('native_domains') == captured and report.get('new_native_executions') == 0
        and all(report.get(key) is False for key in ('whole_runtime_replaced', 'production_activated', 'result_storage_closed')),
        'fresh original complete comparison is incomplete or has different inputs')
    built = build_evidence(root, output / 'build', domain)
    require(report['build_result_sha256'] == pin(output / 'build/result.json')['sha256'], 'original build receipt changed')
    binary = output / 'build' / BINS[domain]
    if domain in PURE:
        require(not report['reference_checks'], 'unexpected filesystem reference process')
        verify_pure_replay(root, binary, output / 'replay', native, domain, report['replay'])
    else:
        test = test_module(root, 'test_result_storage_fs');requests = processes = 0
        require(set(report['reference_checks']) == set(captured), 'complete original filesystem domain differs')
        for name in captured:
            directory = output / name;result = object_at(directory / 'result.json')
            command = [os.sys.executable, '-I', '-B', str(root / 'tests/hia_native/test_result_storage_fs.py'),
                '--domain', name, '--phase', 'original', '--executable', str(binary), '--output', str(directory),
                '--native-capture', str(native / name)]
            receipt, streams = verify_process(output, name, command, root)
            require(receipt == report['reference_checks'][name] and not streams['stderr']
                and json.loads(streams['stdout']) == summary_from_report(name, result)
                and result['status'] == 'PASS' and result['phase'] == 'original' and result['domain'] == name
                and result['source_files'] == test.source_files() and result['source_unchanged'] is True
                and result['executable'] == test.pin(binary) and result['new_native_processes'] == 0
                and result['semantic_reference_comparison_complete'] is True,
                'actual original filesystem process or image differs')
            rows = test.definitions(name)
            require(regular(directory / 'definitions.json') == test.ENCODE(rows)
                and result['definitions'] == test.pin(directory / 'definitions.json'), 'original case domain changed')
            native_report = object_at(native / name / 'result.json')
            for index, (definition, record, observed) in enumerate(zip(rows, result['cases'], native_report['cases'], strict=True)):
                case = directory / f'{index:04d}';paired = native / name / f'{index:04d}'
                require(record['index'] == index and record['name'] == definition['name'] and record['completed'] is True
                    and record['artifacts'] == test.inventory(case) and record['semantic'] == test.pin(case / 'semantic-comparison.json')
                    and record['complete_output'] == test.pin(case / 'complete-projected-output.bin')
                    and regular(case / 'semantic-comparison.json') == regular(paired / 'semantic-comparison.json')
                    and regular(case / 'complete-projected-output.bin') == regular(paired / 'complete-projected-output.bin'),
                    'complete original/native filesystem bytes or observations changed')
            count, request_count, process_count, killed = test.DOMAINS[name][2:]
            require((result['case_count'], result['requests'], result['processes'], result['deliberately_killed_requests'],
                result['new_original_processes']) == (count, request_count, process_count, killed, process_count),
                'complete original filesystem count differs')
            requests += request_count;processes += process_count
        require(report['replay'] == {'original_requests': requests, 'original_processes': processes,
            'complete_original_native_bytes_equal': True}, 'complete original process totals differ')
    return {'schema': 'hepta.result-storage.original-evidence.v1', 'domain': domain,
        'original_requests': report['replay']['original_requests'], 'original_processes': report['replay']['original_processes'],
        'artifact_pins': inventory(output), 'sources': source_pins(root), 'new_native_executions_by_admission': 0,
        'new_original_executions_by_admission': 0, 'native_evidence_sha256': evidence_sha256}

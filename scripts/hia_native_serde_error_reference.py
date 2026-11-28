# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Fresh explicit Rust 1.95 build and complete from_slice::<Value> replay."""
from __future__ import annotations
import argparse
import gzip
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import sys
import tarfile
import tomllib

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hia_native_serde_error_qualification as evidence

RUST_COMMIT = '59807616e1fa2540724bfbac14d7976d7e4a3860'
REMOVED_ENV = {'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_BUILD_TARGET', 'CARGO_BUILD_RUSTFLAGS',
    'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'RUSTC_BOOTSTRAP', 'RUSTUP_TOOLCHAIN'}


def environment(tool, output):
    removed = sorted(key for key in os.environ if key in REMOVED_ENV or key.startswith('HIA_')
        or key.startswith('CARGO_TARGET_') or key.startswith('CARGO_PROFILE_'))
    env = {key: value for key, value in os.environ.items() if key not in removed}
    env.update(RUSTC=str(tool/'rustc'), RUSTFMT=str(tool/'rustfmt'),
        CARGO_TARGET_DIR=str(output/'target'), TMPDIR=str(output/'temporary'),
        PATH=str(tool)+os.pathsep+env.get('PATH',''))
    return env, {'policy':'explicit-rust-1.95-no-flags-wrappers-or-profile-overrides.v1',
        'removed_names':removed, 'rustc':str(tool/'rustc'), 'rustfmt':str(tool/'rustfmt'),
        'cargo_target_dir':str(output/'target'), 'temporary':str(output/'temporary')}


def archive_members(raw, prefix):
    result = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
        for item in archive:
            path = PurePosixPath(item.name)
            evidence.require(not path.is_absolute() and '..' not in path.parts and path.parts
                             and path.parts[0] == prefix, 'registry archive path escaped')
            if item.isdir():
                continue
            evidence.require(item.isfile() and len(path.parts) >= 2, 'registry member is not a regular file')
            name = PurePosixPath(*path.parts[1:]).as_posix()
            evidence.require(item.name == prefix + '/' + name and name not in result,
                             'registry duplicate/noncanonical member')
            value = archive.extractfile(item).read()
            evidence.require(len(value) == item.size, 'registry source truncated')
            result[name] = {'bytes':len(value), 'sha256':evidence.digest(value)}
    evidence.require(bool(result), 'registry archive empty')
    return result


def registry(metadata, expected, retained):
    packages = [row for row in metadata['packages'] if row.get('source')]
    wanted = {(row['name'],row['version'],row['source']):row for row in expected}
    evidence.require(len(packages) == 11 and {(row['name'],row['version'],row['source'])
                     for row in packages} == set(wanted), 'registry package graph changed')
    retained.mkdir(exist_ok=True)
    result = {}
    for package in packages:
        name = package['name'] + '-' + package['version']
        source = Path(package['manifest_path']).parent
        evidence.require(source.name == name and source.parent.parent.name == 'src', 'registry source layout changed')
        path = source.parents[2]/'cache'/source.parent.name/(name+'.crate')
        raw = evidence.read(path)
        evidence.require(evidence.digest(raw) == wanted[package['name'],package['version'],package['source']]['checksum'],
                         'registry archive checksum differs from original lock')
        members = archive_members(raw,name)
        files = {}
        for item in sorted(source.rglob('*')):
            evidence.require(not item.is_symlink(), 'actual registry source symlink')
            if item.is_dir():
                continue
            relative = item.relative_to(source).as_posix()
            if relative not in ('.cargo-ok','.cargo-checksum.json'):
                files[relative] = evidence.pin(item)
        evidence.same(files,members,'actual full registry source differs from locked archive')
        target = retained/path.name
        if target.exists():
            evidence.require(evidence.read(target) == raw,'retained registry archive changed')
        else:
            target.write_bytes(raw)
        result[name] = {'source':str(source), 'archive':path.name, 'archive_pin':evidence.pin(target), 'members':members}
    return result


def reference_contract(root):
    contract = evidence.object_at(root / 'native/serde_error_reference.json')
    for name, expected in contract['runtime_sources'].items():
        evidence.same(evidence.pin(root / name), expected, 'original runtime Cargo source changed')
    lock = tomllib.loads(evidence.read(root / (evidence.TEST_DIR + '/oracle/Cargo.lock')).decode())
    packages = [row for row in lock['package'] if 'source' in row]
    evidence.same(packages, contract['locked_packages'], 'locked registry graph changed')
    original = {(row['name'], row['version']): row for row in tomllib.loads(evidence.read(root / 'Cargo.lock').decode())['package']}
    evidence.require(len(packages) == 11 and len(contract['serde_json_sources']) == 40,
                     'locked reference inventory changed')
    for row in packages:
        old = original[(row['name'], row['version'])]
        evidence.same({key: row[key] for key in ('source', 'checksum')},
                      {key: old[key] for key in ('source', 'checksum')}, 'original locked crate differs')
    return contract


def actual_process(output, name, argv, env, incoming=None):
    evidence.run_in_owned_group(output / name, argv, env=env, incoming=incoming, cwd=output/'project')
    return output / name / 'stdout'


def build(options, native):
    root, output, tool = options.root, options.output, options.rust_bin
    evidence.require(not output.exists(), 'fresh reference output already exists')
    output.mkdir(parents=True)
    contract = reference_contract(root)
    project = output / 'project'
    project.mkdir()
    for name in ('Cargo.toml', 'Cargo.lock', 'main.rs'):
        shutil.copyfile(root / evidence.TEST_DIR / 'oracle' / name, project / name)
    temporary = output / 'temporary'; temporary.mkdir()
    env, environment_record = environment(tool, output)
    tools_before = {name: {'path':str(tool/name), **evidence.pin(tool/name)}
                    for name in ('cargo','rustc','rustfmt')}
    source_before = evidence.source_bindings(root)
    version = actual_process(output, 'compiler-version', [tool / 'rustc', '-Vv'], env).read_text()
    evidence.require('\nrelease: 1.95.0\n' in version and '\ncommit-hash: '+RUST_COMMIT+'\n' in version,
                     'actual Rust release differs')
    actual_process(output, 'format', [tool / 'rustfmt', '--check', '--edition', '2021',
                   '--config', 'hard_tabs=true,skip_children=true', project / 'main.rs'], env)
    offline = ['--offline'] if options.offline else []
    metadata = json.loads(evidence.read(actual_process(output, 'metadata', [tool / 'cargo', 'metadata',
        '--locked', *offline, '--format-version=1', '--manifest-path', project / 'Cargo.toml'], env)))
    crate = next(row for row in metadata['packages'] if row['name'] == 'serde_json' and row['version'] == '1.0.151')
    directory = Path(crate['manifest_path']).parent
    actual_files = {name: evidence.pin(evidence.child(directory, name)) for name in contract['serde_json_sources']}
    evidence.same(actual_files, contract['serde_json_sources'], 'actual serde_json source changed')
    features = next(row['features'] for row in metadata['resolve']['nodes'] if row['id'] == crate['id'])
    evidence.same(sorted(features), contract['serde_json_features'], 'actual serde_json feature graph changed')
    packages = [{key: row[key] for key in ('name', 'version', 'source')} for row in metadata['packages'] if row['source']]
    expected = [{key: row[key] for key in ('name', 'version', 'source')} for row in contract['locked_packages']]
    evidence.same(sorted(packages, key=lambda x: x['name']), sorted(expected, key=lambda x: x['name']),
                  'actual Cargo dependency selection changed')
    registry_before = registry(metadata, contract['locked_packages'], output/'registry-archives')
    (output/'registry.json').write_text(json.dumps(registry_before,sort_keys=True,indent=2)+'\n')
    actual_process(output, 'build', [tool / 'cargo', 'build', '--release', '--locked', *offline,
                   '--manifest-path', project / 'Cargo.toml'], env)
    binary = output / 'original.elf'
    shutil.copyfile(output / 'target/release/hia-serde-error-reference', binary)
    binary.chmod(0o700)
    evidence.require(b'Compiling hia-serde-error-reference' in evidence.read(output / 'build/stderr'),
                     'actual observer was not freshly compiled')
    for name in ('Cargo.toml', 'Cargo.lock', 'main.rs'):
        evidence.require(evidence.read(project / name) == evidence.read(root / evidence.TEST_DIR / 'oracle' / name),
                         'generated original observer source changed')
    evidence.same(source_before, evidence.source_bindings(root), 'sources changed during original build')
    evidence.same(registry(metadata,contract['locked_packages'],output/'registry-archives'), registry_before,
                  'actual locked crate source changed during compilation')
    evidence.same(tools_before, {name:{'path':str(tool/name), **evidence.pin(tool/name)}
                  for name in tools_before}, 'selected compiler/formatter changed')
    processes = {name: evidence.object_at(output / name / 'result.json')
                 for name in ('compiler-version', 'format', 'metadata', 'build')}
    result = {'schema': 'hepta.runtime.serde-error-original-build.v1', 'status': 'PASS',
        'original_rust_recompiled': True, 'compiler_version': version,
        'toolchain': tools_before, 'environment': environment_record, 'registry':evidence.pin(output/'registry.json'),
        'sources': source_before, 'reference': contract, 'actual_crate_source_files': actual_files,
        'actual_features': features, 'original_binary': evidence.pin(binary), 'processes': processes,
        'native_evidence': native, 'source_unchanged': True, 'new_native_executions': 0,
        'new_original_semantic_calls': 0, 'whole_runtime_closed': False}
    (output / 'build-report.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    return result


def verified_build(root, output, native, *, live_tools=True):
    result = evidence.object_at(output / 'build-report.json')
    evidence.require(result['status'] == 'PASS' and result['original_rust_recompiled'] is True
                     and result['source_unchanged'] is True and result['new_original_semantic_calls'] == 0,
                     'actual fresh original build incomplete')
    evidence.require(result['whole_runtime_closed'] is False and result['new_native_executions'] == 0,
                     'original build scope changed')
    evidence.same(result['sources'], evidence.source_bindings(root), 'original build sources changed')
    evidence.same(result['reference'], reference_contract(root), 'original reference contract changed')
    evidence.same(result['actual_crate_source_files'], result['reference']['serde_json_sources'],
                  'actual compiled crate source inventory changed')
    evidence.same(sorted(result['actual_features']), result['reference']['serde_json_features'],
                  'actual compiled features changed')
    evidence.same(result['native_evidence'], native, 'original build used different native observations')
    evidence.same(result['original_binary'], evidence.pin(output / 'original.elf'), 'original executable changed')
    evidence.require(set(result['processes']) == {'compiler-version', 'format', 'metadata', 'build'},
                     'original build process inventory incomplete')
    for name, row in result['processes'].items():
        evidence.same(row, evidence.object_at(output / name / 'result.json'), 'actual original process changed')
        evidence.require(row['exit_code'] == 0 and row['process_reaped'] is True and row['timed_out'] is False
                         and row['timeout_seconds'] == 180, 'actual original process incomplete')
        for stream in ('stdout', 'stderr'):
            evidence.same(row[stream], evidence.pin(output / name / stream), 'original process bytes changed')
    version = evidence.read(output / 'compiler-version/stdout').decode()
    evidence.require(version == result['compiler_version'] and '\nrelease: 1.95.0\n' in version
                     and '\ncommit-hash: '+RUST_COMMIT+'\n' in version,
                     'actual compiler-version output changed')
    evidence.require(b'Compiling hia-serde-error-reference' in evidence.read(output / 'build/stderr')
                     and evidence.read(output / 'format/stdout') == b''
                     and evidence.read(output / 'format/stderr') == b'', 'fresh compile/format evidence changed')
    metadata = evidence.object_at(output / 'metadata/stdout')
    packages = [{key: row[key] for key in ('name', 'version', 'source')}
                for row in metadata['packages'] if row['source']]
    expected = [{key: row[key] for key in ('name', 'version', 'source')}
                for row in result['reference']['locked_packages']]
    evidence.same(sorted(packages, key=lambda x: x['name']), sorted(expected, key=lambda x: x['name']),
                  'actual compiled Cargo packages changed')
    crate = next(row for row in metadata['packages'] if row['name'] == 'serde_json' and row['version'] == '1.0.151')
    features = next(row['features'] for row in metadata['resolve']['nodes'] if row['id'] == crate['id'])
    evidence.same(sorted(features), result['reference']['serde_json_features'], 'actual metadata features changed')
    evidence.same(result['registry'],evidence.pin(output/'registry.json'),'retained registry receipt changed')
    records = evidence.object_at(output/'registry.json')
    wanted = {(row['name'],row['version'],row['source']):row for row in result['reference']['locked_packages']}
    evidence.require(set(records) == {row['name']+'-'+row['version'] for row in metadata['packages'] if row['source']},
                     'registry receipt omitted compiled package')
    for package in metadata['packages']:
        if not package['source']:
            continue
        name = package['name']+'-'+package['version']; record=records[name]
        evidence.require(record['source'] == str(Path(package['manifest_path']).parent)
                         and record['archive'] == name+'.crate', 'actual registry origin changed')
        path=output/'registry-archives'/record['archive'];raw=evidence.read(path)
        evidence.same(evidence.pin(path),record['archive_pin'],'retained registry archive changed')
        evidence.require(evidence.digest(raw) == wanted[package['name'],package['version'],package['source']]['checksum'],
                         'retained registry checksum differs from original lock')
        evidence.same(archive_members(raw,name),record['members'],'retained complete source bytes changed')
    tools = {name:Path(row['path']) for name,row in result['toolchain'].items()}
    evidence.require(set(tools) == {'cargo','rustc','rustfmt'} and all(path.is_absolute() for path in tools.values()),
                     'original tool identities malformed')
    if live_tools:
        evidence.same({name:{'path':str(path), **evidence.pin(path)} for name,path in tools.items()},
                      result['toolchain'],'actual selected compiler/formatter changed')
    origin = Path(result['processes']['metadata']['command'][-1]).parent
    evidence.require(origin.is_absolute() and origin.name == 'project','actual original project origin malformed')
    env = result['environment']
    environment_expected = {'policy':'explicit-rust-1.95-no-flags-wrappers-or-profile-overrides.v1',
        'rustc':str(tools['rustc']), 'rustfmt':str(tools['rustfmt']),
        'cargo_target_dir':str(origin.parent/'target'), 'temporary':str(origin.parent/'temporary')}
    evidence.same({key:env[key] for key in environment_expected}, environment_expected,'original environment changed')
    evidence.require(env['removed_names'] == sorted(set(env['removed_names'])) and all(
        key in REMOVED_ENV or key.startswith('HIA_') or key.startswith('CARGO_TARGET_')
        or key.startswith('CARGO_PROFILE_') for key in env['removed_names']), 'environment sanitizer record changed')
    expected_commands = {
        'compiler-version':[str(tools['rustc']),'-Vv'],
        'format':[str(tools['rustfmt']),'--check','--edition','2021','--config',
                  'hard_tabs=true,skip_children=true',str(origin/'main.rs')],
        'metadata':[str(tools['cargo']),'metadata','--locked'],
        'build':[str(tools['cargo']),'build','--release','--locked'],
    }
    for name in ('metadata','build'):
        command=result['processes'][name]['command']; prefix=expected_commands[name]
        offline=['--offline'] if len(command)>len(prefix) and command[len(prefix)]=='--offline' else []
        expected_commands[name]=prefix+offline+(['--format-version=1'] if name=='metadata' else [])+[
            '--manifest-path',str(origin/'Cargo.toml')]
    for name,expected in expected_commands.items():
        row=result['processes'][name]
        evidence.same(row['command'],expected,'actual original invocation changed')
        evidence.require(row['cwd'] == str(origin) and row['input'] is None,
                         'original build cwd/stdin changed')
    for name in ('Cargo.toml', 'Cargo.lock', 'main.rs'):
        evidence.require(evidence.read(output / 'project' / name) == evidence.read(root / evidence.TEST_DIR / 'oracle' / name),
                         'compiled observer source changed')
    return result


def original_evidence(root, hepta, manifest, native_output, output):
    """Inspect complete retained bytes, without adding an original execution."""
    native = evidence.qualification_evidence(root,hepta,manifest,native_output)
    built = verified_build(root,output,native,live_tools=False)
    result = evidence.object_at(output/'result.json')
    evidence.require(result['status'] == 'PASS' and result['source_unchanged'] is True
                     and result['original_owner_calls'] == 98701 and result['native_cases_added_by_replay'] == 0,
                     'original complete replay status changed')
    evidence.require(all(result[key] is False for key in ('whole_runtime_closed',
        'typed_derive_diagnostics_closed','generic_value_serialization_closed')), 'original replay scope changed')
    evidence.same(result['sources'],evidence.source_bindings(root),'replayed source bindings changed')
    evidence.same(result['native_evidence'],native,'replayed native observations changed')
    evidence.same(result['original_binary'],evidence.pin(output/'original.elf'),'replayed original executable changed')
    evidence.same(result['build_report'],evidence.pin(output/'build-report.json'),'replayed fresh build report changed')
    contract=evidence.object_at(root/'native/serde_error_corpus_contract.json')
    evidence.require(set(result['domains']) == {'base','resources'},'original replay omitted a domain')
    origin=Path(built['processes']['metadata']['command'][-1]).parent.parent
    for name,row in result['domains'].items():
        folder=output/('replay-'+name);process=evidence.object_at(folder/'result.json')
        evidence.same(process,row['process'],'actual replay process record changed')
        evidence.require(process['command'] == [str(origin/'original.elf')]
                         and process['cwd'] == str(origin/'project') and process['exit_code'] == 0
                         and process['timed_out'] is False and process['process_reaped'] is True
                         and process['timeout_seconds'] == 180, 'actual original replay incomplete')
        expected=contract[name]['corpus']
        evidence.same(process['input'],{'path':str(origin/'temporary'/(name+'.input.bin')),
            'bytes':expected['input_bytes'],'sha256':expected['input_sha256']},'actual replay input not bound')
        for stream in ('stdout','stderr'):
            evidence.same(process[stream],evidence.pin(folder/stream),'actual replay stream changed')
        evidence.same(row['complete_output'],{'bytes':expected['output_bytes'],'sha256':expected['output_sha256']},
                      'original complete output domain changed')
        evidence.same(process['stdout'],row['complete_output'],'actual original output differs')
        evidence.require(row['complete_output_equal'] is True and row['original_owner_calls'] == contract[name]['semantic_cases'],
                         'original call count changed')
        evidence.same(evidence.object_at(folder/'stderr'),{'status':'PASS',
            'original_owner_calls':contract[name]['semantic_cases'],'adapter_only_rows':0},'actual original summary changed')
        with (folder/'stdout').open('rb') as left,gzip.open(native_output/name/'corpus/native-output.bin.gz','rb') as right:
            while True:
                a,b=left.read(1048576),right.read(1048576)
                evidence.require(a==b,'full original/native output differs')
                if not a:break
    return {'status':'PASS','result':evidence.pin(output/'result.json'),'build':evidence.pin(output/'build-report.json'),
        'original_owner_calls':98701,'complete_compared_output_bytes':8597971,
        'retained_locked_crates':11,'capture_only':True,'new_original_executions':0,'new_native_executions':0}


def replay(options, native):
    root, output = options.root, options.output
    built = verified_build(root, output, native)
    evidence.require(not (output / 'result.json').exists(), 'original replay already completed')
    contract = evidence.object_at(root / 'native/serde_error_corpus_contract.json')
    observations = {}
    for name in ('base', 'resources'):
        destination = output / ('replay-' + name)
        incoming = output / 'temporary' / (name + '.input.bin')
        with gzip.open(options.native_output / name / 'corpus/cases.bin.gz', 'rb') as source, incoming.open('xb') as target:
            shutil.copyfileobj(source, target, 1048576)
        expected = contract[name]['corpus']
        evidence.same(evidence.pin(incoming), {'bytes': expected['input_bytes'], 'sha256': expected['input_sha256']},
                      'complete original input changed')
        actual_process(output, 'replay-' + name, [output / 'original.elf'], os.environ.copy(), incoming)
        original = destination / 'stdout'
        evidence.same(evidence.pin(original), {'bytes': expected['output_bytes'], 'sha256': expected['output_sha256']},
                      'complete original diagnostic bytes differ')
        with original.open('rb') as left, gzip.open(options.native_output / name / 'corpus/native-output.bin.gz', 'rb') as right:
            while True:
                a, b = left.read(1048576), right.read(1048576)
                evidence.require(a == b, 'original/native output bytes differ')
                if not a:
                    break
        evidence.same(evidence.object_at(destination / 'stderr'), {'status': 'PASS',
            'original_owner_calls': contract[name]['semantic_cases'], 'adapter_only_rows': 0},
            'actual original call domain changed')
        incoming.unlink()
        observations[name] = {'original_owner_calls': contract[name]['semantic_cases'],
            'complete_output': evidence.pin(original), 'complete_output_equal': True,
            'process': evidence.object_at(destination / 'result.json')}
    evidence.same(built, verified_build(root, output, native), 'original build evidence changed during replay')
    result = {'schema': 'hepta.runtime.serde-error-original-comparison.v1', 'status': 'PASS',
        'source_unchanged': True, 'sources': evidence.source_bindings(root), 'original_owner_calls': 98701,
        'native_cases_added_by_replay': 0, 'original_binary': evidence.pin(output / 'original.elf'),
        'build_report': evidence.pin(output / 'build-report.json'), 'domains': observations,
        'native_evidence': native, 'typed_derive_diagnostics_closed': False,
        'generic_value_serialization_closed': False, 'whole_runtime_closed': False}
    (output / 'result.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--hepta', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--native-output', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--rust-bin', type=Path)
    parser.add_argument('--offline', action='store_true')
    parser.add_argument('--phase', choices=('build', 'replay'), required=True)
    options = parser.parse_args()
    for name in ('root', 'hepta', 'manifest', 'native_output', 'output'):
        setattr(options, name, getattr(options, name).resolve())
    native = evidence.qualification_evidence(options.root, options.hepta, options.manifest, options.native_output)
    if options.phase == 'build':
        evidence.require(options.rust_bin is not None, 'explicit Rust 1.95 tools required')
        options.rust_bin = options.rust_bin.resolve()
        result = build(options, native)
        summary = {'status': result['status'], 'actual_build_processes': 4,
                   'original_owner_calls': 0, 'fresh_rust_build': True}
    else:
        result = replay(options, native)
        original_evidence(options.root,options.hepta,options.manifest,options.native_output,options.output)
        summary = {'status': result['status'], 'actual_replay_processes': 2,
                   'original_owner_calls': 98701, 'native_cases_added_by_replay': 0}
    evidence.same(native, evidence.qualification_evidence(options.root, options.hepta, options.manifest, options.native_output),
                  'native evidence changed during original phase')
    print(json.dumps(summary, sort_keys=True))


if __name__ == '__main__':
    main()

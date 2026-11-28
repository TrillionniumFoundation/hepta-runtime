#!/usr/bin/env python3
"""Read retained build/stdio/state/filesystem evidence without running any owner."""
from pathlib import Path
from types import SimpleNamespace
import argparse
import gzip
import hashlib
import io
import json
import struct
import sys
import tarfile
import tomllib

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from contracts import Q, U, compare_saved, configuration_bytes, encode, load, namespace, ordinary_cases, sha
from source_check import file_pins, verify as verify_source


def document(path):
    return json.loads(path.read_bytes())


def file_identity(path):
    assert path.is_file() and not path.is_symlink(), str(path)
    digest = hashlib.sha256()
    size = 0
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            size += len(block)
            digest.update(block)
    return {'bytes': size, 'sha256': digest.hexdigest()}


def expect_file(path, pin):
    identity = file_identity(path)
    assert identity == {key: pin[key] for key in ('bytes', 'sha256')}, str(path)
    return identity


def relative_file(root, name):
    relative = Path(name)
    assert not relative.is_absolute() and '..' not in relative.parts and str(relative) == name, name
    candidate = root / relative
    resolved = candidate.resolve(strict=True)
    assert resolved.is_relative_to(root.resolve(strict=True)) and candidate.is_file() and not candidate.is_symlink(), name
    return candidate


def relocate(recorded, execution_root, evidence):
    path = Path(recorded)
    assert path.is_absolute() and '..' not in path.parts and path.is_relative_to(execution_root), recorded
    return relative_file(evidence, str(path.relative_to(execution_root)))


def process_streams(directory, row, *, names, timeout):
    assert row['exit_code'] == 0 and row['timed_out'] is False, row.get('name')
    assert row['timeout_seconds'] == timeout
    for stream in names:
        pin = row[stream]
        name = pin.get('path', row['name'] + '.' + stream)
        assert name == row['name'] + '.' + stream
        expect_file(relative_file(directory, name), pin)


def check_builds(source, evidence, execution_root):
    deps = document(source / 'ci/dependencies.json')
    native_pins = document(source / 'source-pins/native-target.json')
    input_root = evidence / 'input'
    assert verify_source(input_root) == verify_source(source)
    native_root = evidence / 'native-build'
    build = document(native_root / 'BUILD.json')
    assert build['status'] == 'FRESH_COMPLETE_PRIVATE_GRAPH_BUILD_PASS'
    assert build['fresh_native_members'] == build['source_members'] == 75
    assert build['fresh_hia_link_pack'] is True and build['bootstrap_reused'] is False
    assert build['ordinary_parity_qualified'] is False
    assert build['public_text_editor_route'] is build['whole_runtime_replaced'] is False
    manifest_path = relocate(build['manifest'], execution_root, evidence)
    assert sha(manifest_path.read_bytes()) == build['manifest_sha256']
    native = document(manifest_path)
    assert native['status'] == 'PASS' and native['physical_images'] == len(native['members']) == 75
    assert native['private_instance_fixture'] is True and native['fixture_sessions'] == 2
    assert native['public_text_editor_route'] is False
    assert native['source_root'] == str(execution_root / 'input/source')
    assert native['compiler_commit'] == deps['compiler']['commit']
    assert native['compiler_image_sha256'] == deps['compiler']['generation_sha256']
    binding_raw = (input_root / 'source/native/runtime_mcp_sources.json').read_bytes()
    assert sha(binding_raw) == native_pins['source_binding_sha256'] == native['source_binding']['manifest_sha256']
    assert native['source_binding']['files'] == json.loads(binding_raw)['sources']
    compiler_root = native_root / 'build/bootstrap'
    bootstrap = document(compiler_root / 'bootstrap.json')
    assert bootstrap['qualification'] == 'development_fixed_point'
    assert bootstrap['dependency']['commit'] == deps['compiler']['commit']
    assert bootstrap['dependency']['tree'] == deps['compiler']['tree']
    assert bootstrap['generation_sha256'] == deps['compiler']['generation_sha256']
    for name in ('B1', 'B2', 'B3'):
        assert file_identity(compiler_root / (name + '.image.bin'))['sha256'] == bootstrap['generation_sha256']
    binary = relative_file(manifest_path.parent, native['elf'])
    assert relocate(build['elf'], execution_root, evidence) == binary
    native_identity = expect_file(binary, {'bytes': native_pins['expected_elf_bytes'], 'sha256': native_pins['expected_elf_sha256']})
    assert native_identity == {'bytes': native['elf_bytes'], 'sha256': native['elf_sha256']}
    assert native_identity == {'bytes': build['elf_bytes'], 'sha256': build['elf_sha256']}
    assert binary.read_bytes()[:4] == b'\x7fELF'
    members = {}
    for row, expected in zip(native['members'], native_pins['members'], strict=True):
        assert all(row[key] == expected[key] for key in expected), row['name']
        assert row['fresh_compile'] is True
        member_path = relocate(row['manifest'], execution_root, evidence)
        assert sha(member_path.read_bytes()) == row['manifest_sha256']
        member = document(member_path)
        assert member['schema'] == 'hepta.runtime.native-module.v1'
        assert member['compiler_commit'] == native['compiler_commit']
        assert member['compiler_sha256'] == native['compiler_image_sha256']
        assert member.get('standalone') is None
        assert member.get('buffer_profile', 'standard') == row['buffer_profile']
        declared = relative_file(member_path.parent, member['source']).read_bytes()
        assert declared == (input_root / 'source' / row['source']).read_bytes()
        assert sha(declared) == member['source_sha256'] == row['source_sha256']
        image = relative_file(member_path.parent, member['image'])
        expect_file(image, {'bytes': row['image_bytes'], 'sha256': row['image_sha256']})
        assert member['image_sha256'] == row['image_sha256']
        members[row['name']] = {'row': row, 'path': member_path, 'module': member, 'image': image}
    assert set(native['physical_image_members']) == set(members)
    for label, incoming, outgoing in (('link', 'link.input.bin', 'linked-prefix.elf'),
                                     ('pack', 'pack.input.bin', 'pack.output.bin')):
        record = native[label]
        assert record == document(manifest_path.parent / (label + '.receipt.json'))
        assert record['fresh_compile'] is True
        expect_file(manifest_path.parent / incoming, {'bytes': record['input_bytes'], 'sha256': record['input_sha256']})
        expect_file(manifest_path.parent / outgoing, {'bytes': record['output_bytes'], 'sha256': record['output_sha256']})
        path = relocate(record['manifest'], execution_root, evidence)
        assert sha(path.read_bytes()) == record['manifest_sha256']
        module = document(path)
        assert module['compiler_commit'] == native['compiler_commit'] and module['compiler_sha256'] == native['compiler_image_sha256']
        declared = relative_file(path.parent, module['source']).read_bytes()
        assert sha(declared) == module['source_sha256']
        assert file_identity(relative_file(path.parent, module['image']))['sha256'] == module['image_sha256']
        wanted = (bootstrap['dependency']['files']['examples/hia_bootstrap/elf_static_linker.hepta']
                  if label == 'link' else sha((input_root / 'source/native/runtime_mcp_image_packer.hepta').read_bytes()))
        assert sha(declared) == wanted
    packed = (manifest_path.parent / 'pack.output.bin').read_bytes()
    assert native['pack']['actual_return'] == 32
    assert packed[:32] == b'HIAIMR02' + Q(0, native_identity['bytes'], 0)
    assert packed[32:] == binary.read_bytes()
    image_sources = native['pack']['image_sources']
    assert len(image_sources) == len(native['pack']['image_offsets']) == 75
    for name, recorded, offset in zip(native['physical_image_members'], image_sources, native['pack']['image_offsets'], strict=True):
        image = relocate(recorded, execution_root, evidence)
        assert image == members[name]['image'] and offset % 16 == 0
        raw = image.read_bytes()
        assert packed[32 + offset:32 + offset + len(raw)] == raw
    for row in native['boundary_processes']:
        process_streams(manifest_path.parent, row, names=('stdout', 'stderr'), timeout=60 if row['name'] == 'assemble' else 30)
        assert row == document(manifest_path.parent / (row['name'] + '.process.json'))
    assert sha((manifest_path.parent / 'combined.S').read_bytes()) == native['assembled_source_sha256']
    assert sha((manifest_path.parent / 'bridge.o').read_bytes()) == native['object_sha256']
    typed = document(native_root / 'typed-members.json')
    assert typed == {'serde_json_span': {'manifest': members['wide_value']['row']['manifest'],
                                       'manifest_sha256': members['wide_value']['row']['manifest_sha256']}}
    original_root = evidence / 'reference-build'
    original_build = document(original_root / 'BUILD.json')
    assert original_build['status'] == 'FRESH_CURRENT_GATEWAY_REFERENCE_BUILD_PASS'
    assert original_build['source_files'] == 35 and original_build['qualification'] == 'NOT_RUN'
    original_binary = relocate(original_build['binary'], execution_root, evidence)
    assert original_binary == original_root / 'target/release/hepta-text-editor-gateway-local-original-oracle'
    original_identity = expect_file(original_binary, original_build)
    assert original_binary.read_bytes()[:4] == b'\x7fELF'
    source_closure = file_pins(input_root / 'reference-v1')
    assert source_closure == document(original_root / 'source-closure.json')
    processes = document(original_root / 'processes.json')
    assert [r['name'] for r in processes] == ['rustc-version', 'cargo-version', 'cargo-fetch', 'cargo-metadata', 'cargo-build']
    for row in processes:
        process_streams(original_root, row, names=('stdout', 'stderr'), timeout=180)
        assert row['cwd'] == str(execution_root / 'input/reference-v1')
    assert (original_root / 'rustc-version.stdout').read_bytes() == b'rustc 1.95.0 (59807616e 2026-04-14)\n'
    for row in processes[2:]:
        assert '--locked' in row['command']
    assert '--offline' in processes[3]['command'] and '--offline' in processes[4]['command']
    registry = document(original_root / 'registry-sources.json')
    retained = document(original_root / 'registry-archives.json')
    assert len(registry) == len(retained['archives']) == original_build['registry_crates']
    full_lock = tomllib.loads((input_root / 'reference-v1/target/Cargo.lock').read_text())
    target_packages = {(p['name'], p['version']): p for p in full_lock['package'] if p.get('source')}
    observed_files = 0
    for row in registry:
        key = row['name'], row['version']
        target = target_packages[key]
        archive_record = retained['archives'][row['name'] + '-' + row['version']]
        archive = relative_file(original_root, archive_record['path'])
        assert expect_file(archive, archive_record)['sha256'] == row['checksum'] == target['checksum']
        files = {}
        with tarfile.open(archive, 'r:gz') as package:
            for member in package.getmembers():
                pieces = Path(member.name).parts
                assert pieces and pieces[0] == row['name'] + '-' + row['version'] and '..' not in pieces
                if member.isdir():
                    continue
                assert member.isfile()
                raw = package.extractfile(member).read()
                files[str(Path(*pieces[1:]))] = {'bytes': len(raw), 'sha256': sha(raw)}
        assert files == row['files'], key
        observed_files += len(files)
    assert observed_files == original_build['registry_files']
    return {'native': native, 'native_build': build, 'native_binary': binary,
            'native_identity': native_identity, 'typed_members': typed,
            'original_build': original_build, 'original_binary': original_binary,
            'original_identity': original_identity, 'registry_crates': len(registry),
            'registry_source_files': observed_files,
            'native_manifest_relative': str(manifest_path.relative_to(evidence))}


def typed_capture(directory, rows, typed_members):
    index = document(directory / 'typed-calls-index.json')
    assert document(directory / 'typed-members.json') == typed_members
    cursor = 0
    offset = 0
    outputs = {}
    with gzip.open(directory / 'typed-calls.bin.gz', 'rb') as capture:
        for case in rows:
            if case['kind'] != 'call':
                continue
            raw = encode(case['parameters']).rstrip(b'\n')
            wanted_wire = b'HJSMS002' + Q(1, len(raw)) + raw
            before = bytes(16512)
            capacity = 32
            completed = False
            for _ in range(24):
                assert cursor < len(index), case['id']
                item = index[cursor]
                assert item['case'] == case['id'] and item['owner'] == 'serde_json_span'
                assert item['offset'] == offset
                record = capture.read(item['bytes'])
                assert len(record) == item['bytes'] and sha(record) == item['sha256']
                code, wire_length, workspace_length, output_capacity = struct.unpack_from('<4Q', record)
                assert code == item['return_code'] == 32
                assert wire_length == len(wanted_wire) and workspace_length == len(before) and output_capacity == capacity
                assert len(record) == 32 + wire_length + 2 * workspace_length + 2 * capacity
                at = 32
                wire = record[at:at + wire_length]; at += wire_length
                workspace_before = record[at:at + workspace_length]; at += workspace_length
                output_before = record[at:at + capacity]; at += capacity
                output = record[at:at + capacity]; at += capacity
                after = record[at:at + workspace_length]
                assert wire == wanted_wire and workspace_before == before and output_before == b'\xa5' * capacity
                status = U(output, 8)
                assert output[:8] == b'HJSVR002'
                cursor += 1
                offset += len(record)
                if status == 2:
                    needed = U(output, 24)
                    assert needed > len(before)
                    before = after + bytes(needed - len(after))
                elif status == 3:
                    needed = U(output, 24)
                    assert needed > capacity
                    capacity, before = needed, after
                else:
                    assert status == 0, (case['id'], status)
                    length = 32 + U(output, 16)
                    assert length <= capacity and output[length:] == b'\xa5' * (capacity - length)
                    assert case['id'] not in outputs
                    outputs[case['id']] = output[:length]
                    completed = True
                    break
            assert completed, case['id']
        assert cursor == len(index) and capture.read(1) == b''
    return SimpleNamespace(index=index, offset=offset), outputs


def check_native_input(directory, rows, outputs):
    with (directory / 'native.stdin').open('rb') as incoming:
        def frame(session, slot, payload=b''):
            assert incoming.read(32) == b'HFSFXQ02' + Q(session, slot, len(payload))
            assert incoming.read(len(payload)) == payload
        for row in rows:
            if row['kind'] == 'call':
                value = outputs[row['id']][32:]
                metadata = row.get('metadata')
                meta = b'' if metadata is None else encode(metadata).rstrip(b'\n')
                payload = b'HTEWGQ03' + Q(1, len(value), int(metadata is not None), len(meta), 0) + value + meta
                frame(row['session'], 37, payload)
            else:
                assert row['kind'] == 'cache'
                frame(row['session'], 32, bytes.fromhex(row['wire_hex']))
            frame(0, 33)
            frame(1, 33)
            frame(0, 41)
        assert incoming.read(1) == b''


def saved_filesystem(directory, label):
    rows = document(directory / (label + '-filesystem.json'))
    assert [row['path'] for row in rows] == sorted({row['path'] for row in rows})
    files = set()
    for row in rows:
        path = Path(row['path'])
        assert not path.is_absolute() and '..' not in path.parts and str(path) == row['path']
        assert type(row['mode']) is int and 0 <= row['mode'] <= 0o7777
        if row['kind'] == 'file':
            files.add(row['path'])
            expect_file(relative_file(directory / (label + '-filesystem'), row['path']), row)
            assert row['links'] >= 1
            assert row['hardlink_peers'] == sorted(set(row['hardlink_peers']))
            assert row['path'] in row['hardlink_peers']
        elif row['kind'] == 'symlink':
            assert isinstance(row['target'], str)
        else:
            assert row['kind'] == 'directory'
    snapshot = directory / (label + '-filesystem')
    assert {str(p.relative_to(snapshot)) for p in snapshot.rglob('*') if p.is_file()} == files
    assert not any(p.is_symlink() for p in snapshot.rglob('*'))
    by_path = {row['path']: row for row in rows if row['kind'] == 'file'}
    for row in by_path.values():
        for peer in row['hardlink_peers']:
            other = by_path[peer]
            for key in ('bytes', 'sha256', 'links', 'hardlink_peers', 'mode'):
                assert row[key] == other[key], (row['path'], peer, key)
    return rows


def check_profile(source, evidence, execution_root, builds, profile, expected_cases, contract):
    directory = evidence / 'profiles' / profile
    recorded_directory = execution_root / 'profiles' / profile
    cases_raw = (directory / 'cases.jsonl').read_bytes()
    rows = [json.loads(line) for line in cases_raw.splitlines()]
    reconstructed = ordinary_cases(contract, profile, recorded_directory / 'effects')
    assert cases_raw == b''.join(encode(row) for row in reconstructed)
    assert len(rows) == expected_cases and len({row['id'] for row in rows}) == expected_cases
    assert all(row['session'] in (0, 1) for row in rows)
    assert (directory / 'original.stdin').read_bytes() == cases_raw
    configured = profile in ('configured', 'denied')
    if configured:
        assert (directory / 'runtime-config.json').read_bytes() == configuration_bytes(contract, profile, recorded_directory)
    else:
        assert not (directory / 'runtime-config.json').exists()
    native_process = document(directory / 'native-process.json')
    original_process = document(directory / 'original-process.json')
    for row in (native_process, original_process):
        process_streams(directory, row, names=('stdin', 'stdout', 'stderr'), timeout=60)
        assert row['cwd'] == str(recorded_directory / 'effects')
        expected_fence = {'HEPTA_EFFECT_OWNER_FENCE_REQUIRED': '1'} if profile == 'fence_required' else {}
        assert row['controlled_effect_fence'] == expected_fence
    wanted_native = [builds['native_build']['elf']]
    wanted_original = [builds['original_build']['binary']]
    if configured:
        wanted_native += ['--runtime-config', str(recorded_directory / 'runtime-config.json')]
        wanted_original += [str(recorded_directory / 'runtime-config.json')]
    assert native_process['command'] == wanted_native
    assert original_process['command'] == wanted_original
    typed, typed_outputs = typed_capture(directory, rows, builds['typed_members'])
    check_native_input(directory, rows, typed_outputs)
    native_files = saved_filesystem(directory, 'native')
    original_files = saved_filesystem(directory, 'original')
    input_root = evidence / 'input'
    source_before = document(directory / 'source-closure.json')
    reference_before = document(directory / 'reference-closure.json')
    assert source_before == file_pins(input_root / 'source')
    assert reference_before == file_pins(input_root / 'reference-v1')
    values = namespace(contract, profile, recorded_directory / 'effects')
    values.update(OUT=directory, SOURCE=input_root / 'source', REFERENCE=input_root / 'reference-v1',
        ORIGINAL=execution_root / 'reference-build', binary=builds['native_binary'],
        original_binary=builds['original_binary'], rows=rows, typed=typed,
        native_files=native_files, original_files=original_files,
        source_before=source_before, reference_before=reference_before,
        native_output=(directory / 'native.stdout').read_bytes(),
        original_output=(directory / 'original.stdout').read_bytes())
    summary, observations = compare_saved(contract, values)
    assert encode(observations) == (directory / 'observations.json').read_bytes()
    assert encode(summary) == (directory / 'SUMMARY.json').read_bytes()
    assert summary['status'] == 'SERIAL_LOCAL_FOUR_COMMAND_GATEWAY_COMPARISON_PASS'
    assert summary['profile'] == profile and summary['cases'] == expected_cases
    assert summary['actual_native_records'] == 4 * expected_cases
    for key in ('actual_session_state_compared', 'actual_file_effects', 'complete_files_compared',
                'complete_shared_history_compared', 'complete_shared_lock_state_compared'):
        assert summary[key] is True, key
    for key in ('public_text_editor_route', 'production_handler_qualified', 'production_activated',
                'whole_runtime_replaced', 'cancellation_fence_publication_timing_qualified',
                'cancellation_worker_drain_qualified', 'full_sdk_router_qualified'):
        assert summary[key] is False, key
    return {'profile': profile, 'status': 'RETAINED_EVIDENCE_COMPARISON_PASS',
            'cases': len(rows), 'native_records': summary['actual_native_records'],
            'typed_native_calls': len(typed.index), 'typed_full_record_bytes': typed.offset,
            'compared_response_state_bytes': summary['complete_compared_response_and_cache_bytes'],
            'compared_file_bytes': summary['complete_compared_file_bytes'],
            'summary_sha256': sha((directory / 'SUMMARY.json').read_bytes()),
            'cases_sha256': sha(cases_raw), 'native_stdout': file_identity(directory / 'native.stdout'),
            'original_stdout': file_identity(directory / 'original.stdout'),
            'native_process_sha256': sha((directory / 'native-process.json').read_bytes()),
            'original_process_sha256': sha((directory / 'original-process.json').read_bytes())}


def verify(source, evidence):
    source = Path(source).resolve(strict=True)
    evidence = Path(evidence).resolve(strict=True)
    source_result = verify_source(source)
    paths = document(evidence / 'paths.json')
    assert paths['schema'] == 'hepta.text-local.ci-paths.v1'
    assert paths['source_manifest_sha256'] == sha((source / 'source-manifest.json').read_bytes())
    execution_root = Path(paths['execution_root'])
    assert execution_root.is_absolute() and '..' not in execution_root.parts
    builds = check_builds(source, evidence, execution_root)
    deps = document(source / 'ci/dependencies.json')
    contract = load(source)
    # These two frozen modules are pure byte readers; no loader or runtime owner
    # is imported by this program or by the selected comparison AST.
    sys.path.insert(0, str(evidence / 'input'))
    profiles = [check_profile(source, evidence, execution_root, builds, profile,
                              deps['profiles'][profile], contract)
                for profile in deps['profile_order']]
    assert len(profiles) == 7 and sum(row['cases'] for row in profiles) == 357
    assert sum(row['native_records'] for row in profiles) == 1428
    assert verify_source(source) == source_result
    assert verify_source(evidence / 'input') == source_result
    return {'schema': 'hepta.text-local.retained-evidence-verification.v1',
            'status': 'RETAINED_COMPLETE_LOCAL_EVIDENCE_PASS', 'profiles': profiles,
            'ordinary_cases': sum(row['cases'] for row in profiles),
            'actual_native_records': sum(row['native_records'] for row in profiles),
            'typed_native_calls': sum(row['typed_native_calls'] for row in profiles),
            'complete_compared_response_state_bytes': sum(row['compared_response_state_bytes'] for row in profiles),
            'complete_compared_file_bytes': sum(row['compared_file_bytes'] for row in profiles),
            'source_manifest_sha256': paths['source_manifest_sha256'],
            'native_elf': builds['native_identity'], 'original_elf': builds['original_identity'],
            'fresh_native_owner_images': 75, 'registry_crate_archives_verified': builds['registry_crates'],
            'registry_source_files_verified': builds['registry_source_files'],
            'exact_original_target_commit': deps['original_target']['commit'],
            'exact_original_fragments': 106, 'read_only_comparison_ast': contract['fingerprints'],
            'verification_invoked_graph_or_original': False, 'verification_wrote_files': False,
            'private_serial_local_four_command_domain': True,
            'full_sdk_qualified': False, 'full_136_route_qualified': False,
            'full_async_runtime_qualified': False, 'native_task_registry_qualified': False,
            'native_future_cancellation_qualified': False, 'fresh_cold_qualified': False,
            'public_text_editor_route': False, 'production_activated': False,
            'old_path_removed': False, 'whole_runtime_replaced': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--evidence', required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.source, args.evidence), sort_keys=True))


if __name__ == '__main__':
    main()

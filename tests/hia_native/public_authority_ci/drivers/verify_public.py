"""Read retained source, native build bytes, and full ordinary public streams.

No process, native image, original program, or fixture effect is executed.
This program writes nothing and prints only its independently derived result.
"""
from __future__ import annotations
import argparse
import base64
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path
import struct
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
B3 = 'bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'
HEPTA = 'd3e2c90173cf733e42b299d0c4274df4b593a12f'
BASE = '0bbb39cbfd04cdb16539c64c7305c4e5d10e6e1594cfcf66acc7bad9f28668cc'
EIGHT = ['host_list', 'effective_config', 'execution_shadow_admit', 'view', 'workdir', 'directory_create', 'file_move', 'directory_move']

def hashed(path, sha, size=None):
    raw = path.read_bytes()
    assert SHA(raw) == sha, path
    if size is not None:
        assert len(raw) == size, path
    return raw

def read_json(path):
    return json.loads(path.read_bytes())

def comparable(rows):
    return {name: {k: v for k, v in row.items() if k not in ('device', 'inode', 'uid', 'gid')} for name, row in rows.items()}

def verify(source, build, loop, module_map=None):
    binding = read_json(source / 'native/runtime_mcp_sources.json')
    assert binding['schema'] == 'hepta.runtime.public-source-closure.v2'
    for rel, pin in binding['sources'].items():
        path = Path(rel)
        assert not path.is_absolute() and '..' not in path.parts
        hashed(source / path, pin['sha256'], pin['bytes'])
    built = read_json(build / 'BUILD.json')
    assert built['status'] == 'NATIVE_BUILD_PASS' and built['physical_images'] == 91
    folder = build / 'build/public-authority'
    manifest_raw = hashed(folder / 'manifest.json', built['manifest_sha256'])
    md = json.loads(manifest_raw)
    assert md['status'] == 'PASS' and md['schema'] == 'hepta.runtime.public-nine-build.v1'
    assert md['source_binding']['files'] == binding['sources']
    assert md['source_binding']['manifest_sha256'] == SHA((source / 'native/runtime_mcp_sources.json').read_bytes())
    assert md['physical_images'] == len(md['members']) == 91
    assert md['private_instance_fixture'] is False
    assert md['compiler_commit'] == HEPTA and md['compiler_image_sha256'] == B3
    assert len(md['extra_table']) == 57 and md['extra_table'][41] is None
    assert md['extra_table'][35:41] == ['text_call', None, 'text_gateway', 'text_params', 'tb_adapter', None]
    assert md['extra_table'][42:47] == ['target_message', 'target_request', 'target_bridge', 'historical_protocol', 'text_constructor']
    assert md['extra_table'][47:53] == [None] * 6 and md['extra_table'][53:] == ['target_shutdown', 'current_get_info', 'target_connection', None]
    assert md['target_connection_identity_integrated'] is True and md['target_connection_lifecycle_integrated'] is True
    assert md['target_connection_slot'] == 55
    assert md['target_get_info_integrated'] is True and md['target_get_info_slot'] == 54
    assert md['target_get_info_source_sha256'] == 'e2c4829a305593938202a5bf00e6411c5f4ba095167ff6a0603882e32fc5c89c'
    assert md['implemented_tools'] == EIGHT + ['text_editor']
    assert md['target_text_constructor_integrated'] is True and md['target_text_constructor_slot'] == 46
    assert md['target_text_constructor_source_sha256'] == '3a4c9b40136e0c3dbf3b580e475447e94fb79913f93416a0ec906da6d294996d'
    assert md['typed_result_publication_uses_raw_owned_mode'] is True
    for name in ('target_response_owner_integrated', 'target_async_transport_integrated', 'full_sdk_qualified', 'full_136_route_qualified', 'production_activated', 'old_path_removed'):
        assert md[name] is False, name
    elf = hashed(folder / md['elf'], built['elf_sha256'], built['elf_bytes'])
    assert md['elf_sha256'] == built['elf_sha256'] and md['elf_bytes'] == len(elf)
    maps = read_json(module_map) if module_map else None

    def module_path(original):
        if maps is None:
            return Path(original)
        relative = Path(maps['modules'][original])
        assert not relative.is_absolute() and '..' not in relative.parts
        return module_map.parent / relative

    def module(row, expected_source=None):
        path = module_path(row['manifest'])
        data = json.loads(hashed(path, row['manifest_sha256']))
        assert data['schema'] == 'hepta.runtime.native-module.v1'
        assert data['compiler_commit'] == HEPTA and data['compiler_sha256'] == B3
        assert data['standalone'] is None
        text = hashed(path.parent / data['source'], data['source_sha256'])
        image = hashed(path.parent / data['image'], data['image_sha256'])
        if expected_source is not None:
            assert text == expected_source
        if 'source_sha256' in row:
            assert data['source_sha256'] == row['source_sha256']
            assert data['image_sha256'] == row['image_sha256'] and len(image) == row['image_bytes']
            assert data.get('buffer_profile', 'standard') == row['buffer_profile']
        receipt = read_json(path.parent / 'module.receipt.json')
        assert receipt['status'] == 'returned' and receipt['abi_status'] == 0
        assert receipt['artifact_sha256'] == B3 and receipt['source_unchanged'] is True
        assert receipt['source_sha256'] == receipt['input_sha256'] == data['source_sha256']
        assert receipt['produced_sha256'] == data['image_sha256']
        assert receipt['core_u32'] == receipt['result_u64'] == receipt['produced_bytes'] == len(image)
        assert (path.parent / 'module.input.bin').read_bytes() == text
        output = hashed(path.parent / 'module.output.bin', receipt['output_sha256'])
        assert output[:len(image)] == image
        assert not (path.parent / 'module.stderr.log').read_bytes()
        return image
    by_name = {row['name']: row for row in md['members']}
    positions = md['pack']['image_offsets']
    order = md['physical_image_members']
    assert len(positions) == len(order) == 91 and len(set(order)) == 91
    for row in md['members']:
        image = module(row, (source / row['source']).read_bytes())
        at = positions[order.index(row['name'])]
        assert at % 16 == 0 and elf[at:at + len(image)] == image
    fresh = sum((row['fresh_compile'] is True for row in md['members']))
    assert built['fresh_member_compiles'] == fresh and built['checked_reused_members'] == 91 - fresh
    for name in ('B1', 'B2', 'B3'):
        hashed(build / 'build/bootstrap' / (name + '.image.bin'), B3)
    linked = hashed(folder / 'linked-prefix.elf', md['link']['output_sha256'], md['link']['output_bytes'])
    linkin = hashed(folder / 'link.input.bin', md['link']['input_sha256'], md['link']['input_bytes'])
    assert linkin[:8] == b'HIALNK01' and linked[:4] == b'\x7fELF'
    module(md['link'])
    module(md['pack'], (source / 'native/runtime_mcp_image_packer.hepta').read_bytes())
    packin = hashed(folder / 'pack.input.bin', md['pack']['input_sha256'], md['pack']['input_bytes'])
    packout = hashed(folder / 'pack.output.bin', md['pack']['output_sha256'], md['pack']['output_bytes'])
    assert packin[:8] == b'HIAIMG02' and packout[:8] == b'HIAIMR02'
    assert struct.unpack_from('<3Q', packout, 8) == (0, len(elf), 0) and packout[32:] == elf
    assert struct.unpack_from('<4Q', packin, 8) == (len(linked), 91, len(md['pack']['fixed_patches']), 0)
    assert packin[40:40 + len(linked)] == linked
    sizes = struct.unpack_from('<91Q', packin, 40 + len(linked))
    assert list(sizes) == [by_name[name]['image_bytes'] for name in order]
    patches_at = 40 + len(linked) + 91 * 8
    for index, row in enumerate(md['pack']['fixed_patches']):
        assert struct.unpack_from('<3Q', packin, patches_at + index * 24) == tuple(row)
        kind, at, image_index = row
        if kind == 1:
            assert struct.unpack_from('<Q', elf, at)[0] == 4194304 + positions[image_index]
        else:
            assert kind == 2 and struct.unpack_from('<I', elf, at)[0] == positions[image_index] - at - 4
    image_at = patches_at + len(md['pack']['fixed_patches']) * 24
    for name, size in zip(order, sizes, strict=True):
        image = packin[image_at:image_at + size]
        assert SHA(image) == by_name[name]['image_sha256']
        image_at += size
    assert image_at == len(packin)
    hashed(folder / 'combined.S', md['assembled_source_sha256'])
    hashed(folder / 'bridge.o', md['object_sha256'])
    for process in md['boundary_processes']:
        assert process['exit_code'] == 0 and process['timed_out'] is False
        for stream in ('stdout', 'stderr'):
            hashed(folder / (process['name'] + '.' + stream), process[stream]['sha256'], process[stream]['bytes'])
    summary = read_json(loop / 'summary.json')
    assert summary['status'] == 'NATIVE_PUBLIC_NINE_ORDINARY_PASS'
    assert summary['manifest_sha256'] == built['manifest_sha256']
    assert summary['candidate_elf_sha256'] == SHA(elf) and summary['baseline_elf_sha256'] == BASE
    assert summary['rust_executed'] is False and summary['private_fixture_selectors_used'] is False
    hashed(loop / 'executables/eight.elf', BASE)
    assert (loop / 'executables/nine.elf').read_bytes() == elf
    rows = [json.loads(line) for line in (loop / 'responses.jsonl').read_bytes().splitlines()]
    counts = Counter()
    reference = hashed(loop / 'current-get-info-original.stdout', 'c9ff4c9282e406de911119c2287093165d3829c333be43da06ac14f75edf295d', 1236951)
    original = json.loads(reference)
    assert original['target_commit'] == 'd3d75c30719db966b004756f610007a7c723729e'
    info = original['get_info_wire'].encode()
    assert SHA(info) == '6d005e04c53f0a4ef515d4f61ea95e564cbe841a51b7752fe312fc4af86cbf41'
    expected_initialize = b'{"jsonrpc":"2.0","id":1,"result":' + info.replace(
        b'"protocolVersion":"2026-07-28"', b'"protocolVersion":"2025-11-25"', 1) + b'}'
    assert summary['current_get_info_reference_sha256'] == SHA(reference)
    assert summary['current_get_info_wire_sha256'] == SHA(info)
    assert summary['actual_current_sdk_handshake_compared'] is False
    captured = {}
    states = {}
    for era in ('legacy', 'modern'):
        for variant in ('eight', 'nine'):
            key = era + '-' + variant
            folder = loop / key
            process = read_json(folder / 'capture-process.json')
            assert process['exit_code'] == 0 and (not process['timed_out'])
            assert process['timeout_seconds'] == 60 and process['failure_cleanup_requested'] is False
            assert process['unconsumed_stdout_bytes'] == 0 and process['environment'] == {'PATH': '', 'LC_ALL': 'C'}
            streams = {}
            for stream in ('stdin', 'stdout', 'stderr'):
                raw = gzip.decompress((folder / (stream + '.bin.gz')).read_bytes())
                assert SHA(raw) == process[stream]['sha256'] and len(raw) == process[stream]['bytes']
                streams[stream] = raw
            assert streams['stderr'] == b''
            exchanges = read_json(folder / 'exchanges.json')
            assert len(exchanges) == process['exchanges']
            input_at = 0
            output_lines = streams['stdout'].splitlines()
            output_at = 0
            response_rows = [row for row in rows if row['era'] == era and row['variant'] == variant]
            assert len(output_lines) == len(response_rows)
            requests = []
            for event in exchanges:
                assert event['error'] is None and event['timeout_seconds'] == 60
                size = event['requested_bytes']
                assert event['written_bytes'] == size
                raw = streams['stdin'][input_at:input_at + size]
                input_at += size
                assert raw.endswith(b'\n') and SHA(raw) == event['request_sha256']
                request = json.loads(raw)
                requests.append(request)
                for response in event['responses']:
                    line = output_lines[output_at]
                    stored = response_rows[output_at]
                    output_at += 1
                    assert len(line) == response['bytes'] and SHA(line) == response['sha256']
                    assert line == stored['response'].encode() and raw[:-1] == stored['request'].encode()
                    assert SHA(line) == stored['response_sha256'] and SHA(raw[:-1]) == stored['request_sha256']
                    parsed = json.loads(line)
                    assert parsed['jsonrpc'] == '2.0' and 'result' in parsed
                    assert parsed['id'] == request['id']
                    counts['response_lines'] += 1
                    if stored['tool']:
                        assert parsed['result']['isError'] is (stored['label'] == 'text-undo-no-more')
                        counts[variant + '_tool_responses'] += 1
            assert input_at == len(streams['stdin']) and output_at == len(output_lines)
            assert {r['tool'] for r in response_rows if r['tool']} == set(EIGHT + ([] if variant == 'eight' else ['text_editor']))
            captured[key] = {row['label']: row for row in response_rows}
            state = read_json(folder / 'filesystem-snapshots.json')
            states[key] = state
            for entry in state:
                for path, record in entry['files'].items():
                    relative = Path(path)
                    assert not relative.is_absolute() and '..' not in relative.parts
                    if record['kind'] == 'file':
                        raw = base64.b64decode(record['data_base64'], validate=True)
                        assert len(raw) == record['bytes'] and SHA(raw) == record['sha256']
                    else:
                        assert record['kind'] == 'directory'
            counts['actual_public_processes'] += 1
    for era in ('legacy', 'modern'):
        before = captured[era + '-eight']
        after = captured[era + '-nine']
        for label, row in before.items():
            if label == 'tools-list':
                continue
            assert row['request'] == after[label]['request']
            if label == 'initialize':
                assert after[label]['response'].encode() == expected_initialize
                assert json.loads(row['response'])['result']['serverInfo']['version'] == '3.4.1'
                counts['current_get_info_initialize_checks'] += 1
            else:
                assert row['response'] == after[label]['response']
                counts['retained_complete_response_matches'] += 1
        old = json.loads(before['tools-list']['response'])['result']
        new = json.loads(after['tools-list']['response'])['result']
        assert [t['name'] for t in new['tools']] == EIGHT + ['text_editor']
        retained = dict(new)
        retained['tools'] = retained['tools'][:-1]
        assert retained == old
        counts['retained_catalog_objects_matched'] += 8
        counts['ninth_catalog_responses'] += 1
        old = states[era + '-eight']
        new = states[era + '-nine']
        assert len(old) == 15 and len(new) == 21
        for a, b in zip(old, new[:15], strict=True):
            assert a['step'] == b['step'] and comparable(a['files']) == comparable(b['files'])
            counts['retained_complete_filesystem_snapshots_matched'] += 1
        expected = [('create', b'alpha\nline\n'), ('replace', b'beta\nline\n'), ('delete', None), ('undo-delete', b'beta\nline\n'), ('undo-replace', b'alpha\nline\n'), ('undo-no-more', b'alpha\nline\n')]
        for (label, data), record in zip(expected, new[15:], strict=True):
            assert record['step'] == 'text-' + label
            files = comparable(record['files'])
            sequence = files.pop('workspace/sequence.txt', None)
            assert files == comparable(old[-1]['files'])
            if data is None:
                assert sequence is None
            else:
                assert sequence['kind'] == 'file' and base64.b64decode(sequence['data_base64']) == data
            counts['public_text_editor_effects_matched'] += 1
            if data is not None and label != 'undo-no-more':
                view = json.loads(after['view-after-' + label]['response'])['result']
                text = '\n'.join((x.get('text', '') for x in view['content']))
                assert data.decode().splitlines()[0] in text
                counts['same_public_session_view_cache_checks'] += 1
    assert dict(counts) == summary['counts']
    assert counts['actual_public_processes'] == 4 and counts['response_lines'] == 90
    return {'schema': 'hepta.runtime.public-get-info-readonly-verification.v1', 'status': 'READONLY_NATIVE_PUBLIC_NINE_PASS', 'physical_images': 91, 'fresh_member_compiles': fresh, 'checked_reused_members': 91 - fresh, 'elf_sha256': SHA(elf), 'source_binding_sha256': SHA((source / 'native/runtime_mcp_sources.json').read_bytes()), 'counts': dict(counts), 'processes_or_native_or_rust_executed': False, 'verification_wrote_files': False, 'target_original_public_handler_comparison': False, 'full_sdk_qualified': False, 'full_136_route_qualified': False, 'production_activated': False, 'old_path_removed': False}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'build', 'loop'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--module-map', type=Path)
    args = parser.parse_args()
    result = verify(args.source.resolve(strict=True), args.build.resolve(strict=True), args.loop.resolve(strict=True), args.module_map.resolve(strict=True) if args.module_map else None)
    print(json.dumps(result, sort_keys=True))
if __name__ == '__main__':
    main()

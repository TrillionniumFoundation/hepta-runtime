"""Run ordinary public9 calls and compare the retained eight-route prefix.

Every effect is beneath an owned fixture. No Rust executable is invoked.
"""
from pathlib import Path
from collections import Counter
import argparse, hashlib, importlib.util, json, shutil, sys, time, traceback
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from ordinary_public_helpers import snapshot, comparable, setup, retire, sha, wire
from ordinary_execution_input import fixture as execution_input
EIGHT = ['host_list', 'effective_config', 'execution_shadow_admit', 'view', 'workdir', 'directory_create', 'file_move', 'directory_move']
CAPS = 'io.modelcontextprotocol/clientCapabilities'
VERSION = 'io.modelcontextprotocol/protocolVersion'

def put(path, value):
    path.write_text(json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + '\n')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'manifest', 'baseline-elf', 'get-info-reference', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    manifest = args.manifest.resolve(strict=True)
    md = json.loads(manifest.read_bytes())
    assert md['schema'] == 'hepta.runtime.public-nine-build.v1'
    assert md['status'] == 'PASS' and md['physical_images'] == 83
    assert md['target_text_constructor_integrated'] is True and md['target_text_constructor_slot'] == 46
    assert md['private_instance_fixture'] is False and md['implemented_tools'] == EIGHT + ['text_editor']
    assert md['target_get_info_integrated'] is True and md['target_get_info_slot'] == 54
    candidate = manifest.parent / md['elf']
    assert sha(candidate.read_bytes()) == md['elf_sha256']
    baseline = args.baseline_elf.resolve(strict=True)
    assert sha(baseline.read_bytes()) == '0bbb39cbfd04cdb16539c64c7305c4e5d10e6e1594cfcf66acc7bad9f28668cc'
    spec = importlib.util.spec_from_file_location('_nine_capture', source / 'tests/hia_native/runtime_mcp_public_capture.py')
    capture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(capture)
    out = args.output.resolve()
    assert not out.exists() and (not out.is_relative_to(source))
    out.mkdir(parents=True)
    reference = args.get_info_reference.resolve(strict=True).read_bytes()
    assert len(reference) == 1236951 and sha(reference) == 'c9ff4c9282e406de911119c2287093165d3829c333be43da06ac14f75edf295d'
    original = json.loads(reference)
    assert original['target_commit'] == 'd3d75c30719db966b004756f610007a7c723729e'
    info = original['get_info_wire'].encode()
    assert sha(info) == '6d005e04c53f0a4ef515d4f61ea95e564cbe841a51b7752fe312fc4af86cbf41'
    expected_initialize = b'{"jsonrpc":"2.0","id":1,"result":' + info.replace(
        b'"protocolVersion":"2026-07-28"', b'"protocolVersion":"2025-11-25"', 1) + b'}'
    (out / 'current-get-info-original.stdout').write_bytes(reference)
    executable_dir = out / 'executables'
    executable_dir.mkdir()
    executable_custody = {}
    for label, original in [('eight', baseline), ('nine', candidate)]:
        copied = executable_dir / (label + '.elf')
        shutil.copyfile(original, copied)
        copied.chmod(320)
        assert sha(copied.read_bytes()) == sha(original.read_bytes())
        executable_custody[label] = {'source': str(original), 'bytes': original.stat().st_size, 'sha256': sha(original.read_bytes()), 'executed_copy': str(copied)}
    put(out / 'executable-custody.json', executable_custody)
    baseline = executable_dir / 'eight.elf'
    candidate = executable_dir / 'nine.elf'
    counts = Counter()
    responses = []
    processes = []
    current = None
    started = time.monotonic()
    report = {'schema': 'hepta.runtime.public-nine-native-ordinary.v1', 'status': 'RUNNING', 'manifest_sha256': sha(manifest.read_bytes()), 'candidate_elf_sha256': md['elf_sha256'], 'baseline_elf_sha256': sha(baseline.read_bytes()), 'public_stdio_only': True, 'private_fixture_selectors_used': False, 'rust_executed': False, 'target_original_public_handler_comparison': False, 'target_connection_identity_integrated': True, 'target_response_owner_integrated': False, 'target_async_transport_integrated': False, 'full_sdk_qualified': False, 'full_136_route_qualified': False, 'full_async_text_editor_qualified': False, 'scope_wide_qualified': False, 'cancellation_fence_timing_qualified': False, 'production_activated': False, 'old_path_removed': False}

    def save():
        report.update(counts=dict(counts), processes=processes, elapsed_seconds=time.monotonic() - started)
        put(out / 'summary.json', report)
        (out / 'responses.jsonl').write_bytes(b''.join((wire(row) + b'\n' for row in responses)))
    report.update(current_get_info_reference_sha256=sha(reference), current_get_info_wire_sha256=sha(info),
        initialize_behavior_change='current SDK identity3.9.0 and field order; negotiated protocol retained',
        actual_current_sdk_handshake_compared=False, ordinary_cases_retained=90)
    save()
    workflow = [('host-list', 'host_list', {}), ('effective-config', 'effective_config', {}), ('shadow-admit', 'execution_shadow_admit', execution_input('owned')), ('view-root', 'view', {'path': 'seed.txt', 'full': True}), ('view-cache', 'view', {'path': 'seed.txt'}), ('workdir-sub', 'workdir', {'path': 'sub'}), ('view-nested', 'view', {'path': 'nested.txt'}), ('directory-create', 'directory_create', {'path': 'created/a'}), ('file-move', 'file_move', {'source': 'moveme.txt', 'destination': 'moved.txt'}), ('directory-move', 'directory_move', {'source': 'tree', 'destination': 'tree-moved'}), ('view-moved-file', 'view', {'path': 'moved.txt', 'full': True}), ('view-moved-tree', 'view', {'path': 'tree-moved/leaf.txt', 'full': True}), ('workdir-reset', 'workdir', {'reset': True}), ('view-root-after-reset', 'view', {'path': 'seed.txt', 'full': True})]
    try:
        for modern in (False, True):
            era = 'modern' if modern else 'legacy'
            expected = {}
            previous = None
            old_catalog = None
            for variant, binary in [('eight', baseline), ('nine', candidate)]:
                report['current'] = era + '-' + variant
                save()
                root = out / 'fixture'
                work, config = setup(root)
                run = out / (era + '-' + variant)
                state = [{'step': 'before', 'files': snapshot(root)}]
                before_file = (work / 'sub/moveme.txt').stat()
                before_dir = (work / 'sub/tree').stat()
                before_leaf = (work / 'sub/tree/leaf.txt').stat()
                current = capture.Public(run, binary, work, config)
                metadata = {VERSION: '2026-07-28', CAPS: {}}

                def exchange(label, value, tool=None, error=False, compare=True):
                    raw_input = wire(value)
                    raw = current.exchange(raw_input + b'\n')[0]
                    parsed = json.loads(raw)
                    assert parsed.get('jsonrpc') == '2.0' and 'result' in parsed, (label, parsed)
                    assert parsed['id'] == value['id']
                    responses.append({'era': era, 'variant': variant, 'label': label, 'tool': tool, 'request': raw_input.decode(), 'response': raw.decode(), 'request_sha256': sha(raw_input), 'response_sha256': sha(raw)})
                    counts['response_lines'] += 1
                    if tool:
                        assert parsed['result'].get('isError') is error, (label, parsed)
                        counts[variant + '_tool_responses'] += 1
                    if label == 'initialize' and variant == 'nine':
                        assert raw == expected_initialize, ('current get_info plus retained default SDK negotiation', parsed)
                        counts['current_get_info_initialize_checks'] += 1
                    elif compare:
                        if variant == 'eight':
                            expected[label] = raw
                        else:
                            assert raw == expected[label], (era, label, 'retained wire differs')
                            counts['retained_complete_response_matches'] += 1
                    save()
                    return parsed

                def call(label, identifier, tool, parameters, error=False, compare=True):
                    params = {'name': tool, 'arguments': parameters}
                    if modern:
                        params['_meta'] = metadata
                    if label == 'host-list':
                        params.update(inputResponses={}, requestState='')
                    return exchange(label, {'jsonrpc': '2.0', 'id': identifier, 'method': 'tools/call', 'params': params}, tool, error, compare)
                if not modern:
                    exchange('initialize', {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {'protocolVersion': '2025-11-25', 'capabilities': {}, 'clientInfo': {'name': 'owned-nine-loop', 'version': '1'}}})
                    current.exchange(wire({'jsonrpc': '2.0', 'method': 'notifications/initialized'}) + b'\n', 0)
                listed = exchange('tools-list', {'jsonrpc': '2.0', 'id': 10, 'method': 'tools/list', 'params': {'_meta': metadata} if modern else {}}, compare=False)['result']
                assert [t['name'] for t in listed['tools']] == EIGHT + ([] if variant == 'eight' else ['text_editor'])
                if variant == 'eight':
                    old_catalog = listed
                else:
                    retained = dict(listed)
                    retained['tools'] = retained['tools'][:-1]
                    assert retained == old_catalog
                    counts['retained_catalog_objects_matched'] += 8
                    counts['ninth_catalog_responses'] += 1
                for index, (label, tool, parameters) in enumerate(workflow):
                    call(label, 100 + index, tool, parameters)
                    if label == 'directory-create':
                        assert (work / 'sub/created/a').is_dir()
                    if label == 'file-move':
                        after = (work / 'sub/moved.txt').stat()
                        assert not (work / 'sub/moveme.txt').exists()
                        assert (after.st_dev, after.st_ino) == (before_file.st_dev, before_file.st_ino)
                        assert (work / 'sub/moved.txt').read_bytes() == b'ordinary file move\n'
                    if label == 'directory-move':
                        after = (work / 'sub/tree-moved').stat()
                        leaf = (work / 'sub/tree-moved/leaf.txt').stat()
                        assert not (work / 'sub/tree').exists()
                        assert (after.st_dev, after.st_ino) == (before_dir.st_dev, before_dir.st_ino)
                        assert (leaf.st_dev, leaf.st_ino) == (before_leaf.st_dev, before_leaf.st_ino)
                    state.append({'step': label, 'files': snapshot(root)})
                for label, identifier in [('float-id', 1200.0), ('unicode-id', 'ordinary-中')]:
                    call(label, identifier, 'host_list', {})
                if variant == 'eight':
                    previous = state
                else:
                    for old, new in zip(previous, state, strict=True):
                        assert old['step'] == new['step'] and comparable(old['files']) == comparable(new['files'])
                        counts['retained_complete_filesystem_snapshots_matched'] += 1
                    text_steps = [('create', {'command': 'create', 'path': 'sequence.txt', 'content': 'alpha\nline\n'}, b'alpha\nline\n', False), ('replace', {'command': 'str_replace', 'path': 'sequence.txt', 'old_text': 'alpha', 'new_text': 'beta'}, b'beta\nline\n', False), ('delete', {'command': 'delete', 'path': 'sequence.txt'}, None, False), ('undo-delete', {'command': 'undo_edit', 'path': 'sequence.txt'}, b'beta\nline\n', False), ('undo-replace', {'command': 'undo_edit', 'path': 'sequence.txt'}, b'alpha\nline\n', False), ('undo-no-more', {'command': 'undo_edit', 'path': 'sequence.txt'}, b'alpha\nline\n', True)]
                    for index, (label, parameters, content, error) in enumerate(text_steps):
                        result = call('text-' + label, 'text-' + label, 'text_editor', parameters, error, False)
                        assert len(result['result']['content']) == 1 and result['result']['content'][0]['type'] == 'text'
                        path = work / 'sequence.txt'
                        if content is None:
                            assert not path.exists()
                        else:
                            assert path.read_bytes() == content
                        counts['public_text_editor_effects_matched'] += 1
                        if content is not None and (not error):
                            viewed = call('view-after-' + label, 200 + index, 'view', {'path': 'sequence.txt', 'full': True}, compare=False)
                            text = '\n'.join((part.get('text', '') for part in viewed['result']['content']))
                            assert content.decode().splitlines()[0] in text
                            counts['same_public_session_view_cache_checks'] += 1
                        state.append({'step': 'text-' + label, 'files': snapshot(root)})
                put(run / 'filesystem-snapshots.json', state)
                receipt = current.close()
                current = None
                processes.append({'era': era, 'variant': variant, 'elf_sha256': sha(binary.read_bytes()), **receipt})
                counts['actual_public_processes'] += 1
                retire(root, out)
                save()
        assert counts['actual_public_processes'] == 4 and counts['public_text_editor_effects_matched'] == 12
        assert counts['same_public_session_view_cache_checks'] == 8
        assert counts['retained_complete_filesystem_snapshots_matched'] == 30
        report.update(status='NATIVE_PUBLIC_NINE_ORDINARY_PASS', ordinary_public_entry_executed=True, retained_eight_routes_matched=True, complete_original_nine_handlers_qualified=False)
    except BaseException:
        report.update(status='FAIL', failure=traceback.format_exc())
        if current is not None:
            try:
                processes.append(current.close(failed=True))
            except BaseException:
                report['cleanup_failure'] = traceback.format_exc()
        raise
    finally:
        save()
    print(json.dumps(report, sort_keys=True), flush=True)
if __name__ == '__main__':
    main()

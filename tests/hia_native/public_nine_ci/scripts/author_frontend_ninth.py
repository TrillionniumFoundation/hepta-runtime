#!/usr/bin/env python3
"""Add one ordinary public route while retaining every old function body.

This is source generation only. It does not invoke a native image or Rust.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
SHA = lambda data: hashlib.sha256(data).hexdigest()
BASE_SHA = 'c2d5ac1e06305bc3b516ce878594aee9b338fb21a399b071ec1ee6ea01fbb768'
HEPTA_COMMIT = 'd3e2c90173cf733e42b299d0c4274df4b593a12f'
HEPTA_TREE = '8d8b0fb8d015fb7edab302498bb9ed4c74ab6f49'


def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def author(source: Path, output: Path, hepta: Path, helper: Path) -> dict:
    sys.path.insert(0, str(hepta))
    sys.path.insert(0, str(helper))
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    from compile_overlay import compile_source

    raw = (source / 'native/runtime_mcp.hepta').read_bytes()
    assert SHA(raw) == BASE_SHA
    old = assemble_program(raw).as_dict()
    assert len(old['functions']) == 43
    composition = json.loads((source / 'native/runtime_mcp_composition.json').read_bytes())
    assert composition['source_sha256'] == BASE_SHA
    names = dict(composition['functions'])
    assert names['prepare'] == 'f8' and names['tool_kind'] == 'f29'
    work = copy.deepcopy(old)
    original = {f['name']: f for f in old['functions']}
    moved = {'tool_kind': 'f43', 'prepare': 'f44'}
    for alias, relocated in moved.items():
        item = copy.deepcopy(original[names[alias]])
        item['name'] = relocated
        work['functions'].append(item)
        names['retained_' + alias] = relocated

    pseudo_path = Path(__file__).with_name('frontend_ninth.pseudo')
    pseudo = pseudo_path.read_text()
    assert int.from_bytes(b'text_edi', 'little') == 7594306332303844724
    assert int.from_bytes(b'HTEWGQ02', 'little') == 3616479867627197512
    generated, result, names = compile_source(pseudo, work, names, {})
    actual = assemble_program(generated).as_dict()
    assert actual == result
    after = {f['name']: f for f in actual['functions']}
    unchanged = {}
    for name, item in original.items():
        if name in ('f8', 'f29'):
            relocated = moved['prepare' if name == 'f8' else 'tool_kind']
            expected = copy.deepcopy(item)
            expected['name'] = relocated
            assert after[relocated] == expected
        else:
            assert after[name] == item
            unchanged[name] = SHA(json.dumps(item, sort_keys=True, separators=(',', ':')).encode())
    assert len(unchanged) == 41 and len(actual['functions']) == 46
    assert names['prepare_text_editor'] == 'f45'
    (output / 'native').mkdir(parents=True, exist_ok=True)
    (output / 'native/runtime_mcp.hepta').write_bytes(generated)
    proof = {
        'schema': 'hepta.runtime.public-text-editor-route-source.v1',
        'baseline_sha256': BASE_SHA,
        'source_sha256': SHA(generated), 'source_bytes': len(generated),
        'authoring_sha256': SHA(pseudo.encode()),
        'compiler_source_commit': HEPTA_COMMIT, 'compiler_source_tree': HEPTA_TREE,
        'functions': names, 'retained_exact_functions': unchanged,
        'relocated_exact_function_bodies': {'f29': 'f43', 'f8': 'f44'},
        'replaced_function_bodies': ['f8', 'f29'], 'new_function': 'f45',
        'frontend_tool_kind': 9, 'frontend_local_child': 9,
        'gateway_engine_slot': 37, 'gateway_frame': 'HTEWGQ02',
        'argument_value_owner': 'native/serde_json_span.hepta',
        'metadata_owner': 'native/runtime_mcp_admission.hepta',
        'resolved_experimental_full_span': True,
        'metadata_reparsed_in_gateway': False,
        'phase': 6, 'existing_result_path_retained_exactly': True,
        'public_name_registered_in_candidate_source': 'text_editor',
        'native_execution_qualified': False, 'public_route_qualified': False,
        'target_response_owner_integrated': False, 'full_sdk_qualified': False,
        'production_activated': False, 'old_path_removed': False,
    }
    composition['source_sha256'] = SHA(generated)
    composition['source_bytes'] = len(generated)
    composition['functions'] = names
    composition['function_sha256'] = {
        f['name']: SHA(json.dumps(f, sort_keys=True, separators=(',', ':')).encode())
        for f in actual['functions']
    }
    assert composition['supported_tool_names'] == [
        'host_list', 'effective_config', 'execution_shadow_admit', 'view',
        'workdir', 'directory_create', 'file_move', 'directory_move']
    composition['supported_tool_names'].append('text_editor')
    composition['public_text_editor_extension'] = proof
    write_json(output / 'native/runtime_mcp_composition.json', composition)
    return proof


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--hepta', type=Path, required=True)
    parser.add_argument('--helper', type=Path, required=True)
    args = parser.parse_args()
    result = author(args.source.resolve(strict=True), args.output.resolve(),
                    args.hepta.resolve(strict=True), args.helper.resolve(strict=True))
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()

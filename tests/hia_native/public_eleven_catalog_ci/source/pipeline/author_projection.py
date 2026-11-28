"""Specialize the qualified HIA policy to an installed-name intersection.

Only declarations, the fixed 11-name surface, and the original HIA graph are
inputs. No observed original result or expected wire is read by this author.
The original visibility function is preserved verbatim behind one new mask;
the schema traversal, validation, and serialization functions remain exact.
"""
from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from domain import SELECTED_TOOLS, TARGET

BASE_SOURCE = '7a95a957874c1ee21b6bc6be6b4b75c4f09a20e421c0ec67b1d13690fb4a5e2d'
DECLARATIONS = '1b2d78f06d17f87bca4a0b1a21e02d0bc74f40567f75b1d3bf31cb6d4648532e'


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def graph_pin(value):
    return sha(json.dumps(value, sort_keys=True, separators=(',', ':')).encode())


def generate(hepta, source, output):
    sys.path.insert(0, str(hepta))
    from tools.generate_hia_selfhost import Builder, total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    baseline_raw = (source / 'policy_base/native/catalog_policy.hepta').read_bytes()
    declarations_raw = (source / 'policy_base/declarations.json').read_bytes()
    assert sha(baseline_raw) == BASE_SOURCE and sha(declarations_raw) == DECLARATIONS
    asset = json.loads(declarations_raw)
    assert set(asset) == {'schema', 'target_commit', 'raw_tool_wires',
                          'runtime_tool_names', 'weight_tool_names', 'hia_tool_names'}
    assert asset['target_commit'] == TARGET
    tools = [json.loads(raw) for raw in asset['raw_tool_wires']]
    names = [tool['name'] for tool in tools]
    assert len(names) == 136 and names == sorted(set(names))
    assert len(SELECTED_TOOLS) == len(set(SELECTED_TOOLS)) == 11
    assert set(SELECTED_TOOLS) <= set(names)
    baseline = assemble_program(baseline_raw).as_dict()
    old_proof = json.loads((source / 'policy_base/native/author-proof.json').read_bytes())
    assert old_proof['source_sha256'] == BASE_SOURCE
    aliases = old_proof['function_map']
    funcs = {function['name']: function for function in baseline['functions']}
    original_visible = funcs[aliases['visible']]
    assert not any(op['op'] == 'call' for block in original_visible['blocks'] for op in block['ops'])
    classifications = old_proof['classifications']
    assert [row['name'] for row in classifications] == names
    table = bytearray()
    selected = bytearray()
    classified = []
    for row in classifications:
        name, old = row['name'], row['classification']
        assert type(old) is int and 0 <= old < 64
        word = name.encode('ascii')
        expected = (int(name in asset['runtime_tool_names']) |
            int(name in asset['hia_tool_names']) << 1 |
            int(name in asset['weight_tool_names']) << 2 |
            int(name in {'rea_inspect_elf_notes', 'rea_get_evidence_bundle',
                'rea_inspect_apk_signature_evidence', 'rea_inspect_analysis_view',
                'rea_export_evidence_bundle', 'rea_import_evidence_bundle'}) << 3 |
            int(name.startswith('rea_static_')) << 4 | int(name == 'shell') << 5)
        assert old == expected
        installed = name in SELECTED_TOOLS
        table.extend(bytes((len(word), old)) + word)
        selected.extend(bytes((len(word), old | (64 if installed else 0))) + word)
        classified.append({'name': name, 'original_classification': old,
                           'installed': installed, 'classification': old | (64 if installed else 0)})
    assert len(table) == len(selected) and 8192 + len(table) < 16384

    def compile_one(text, mapping, external_signatures):
        nodes = ast.parse(text).body
        assert len(nodes) == 1 and isinstance(nodes[0], ast.FunctionDef)
        node = nodes[0]
        signatures = dict(external_signatures)
        signatures[node.name] = ([arg.annotation.id for arg in node.args.args], node.returns.id)
        builder = Builder(node, mapping, signatures, total_scalar_functions(nodes))
        builder.statements(node.body)
        function = {'name': mapping[node.name], 'params': [builder.param(value) for value in builder.params],
            'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
            'entry': 'b0', 'blocks': builder.blocks}
        # Verify only after restoring the entire fixed call graph below.
        # A single function cannot admit its external put/visibility callee.
        return function

    def packed(data):
        lines = ['def init_names(w: mutbuf) -> u64:']
        for offset in range(0, len(data), 8):
            word = int.from_bytes(data[offset:offset + 8].ljust(8, b'\0'), 'little')
            lines.append(f'    put(w, {8192 + offset}, {word})')
        lines.append('    return 0')
        return compile_one('\n'.join(lines) + '\n',
            {'init_names': aliases['init_names'], 'put': aliases['put']},
            {'put': (['mutbuf', 'u64', 'u64'], 'u64')})

    # Before adding the mask, independently reproduce the entire old table
    # writer AST with the exact original compiler authoring lowering.
    assert packed(table) == funcs[aliases['init_names']]
    old_name = 'f' + str(len(baseline['functions']))
    wrapper = compile_one(
        'def visible(classification: u64, flags: u64) -> u64:\n'
        '    if (classification & 64) == 0:\n'
        '        return 0\n'
        '    return original_visible(classification, flags)\n',
        {'visible': aliases['visible'], 'original_visible': old_name},
        {'original_visible': (['u64', 'u64'], 'u64')})
    document = copy.deepcopy(baseline)
    document['module'] = 'runtime_catalog_eleven_policy'
    for index, function in enumerate(document['functions']):
        if function['name'] == aliases['visible']:
            document['functions'][index] = wrapper
        elif function['name'] == aliases['init_names']:
            document['functions'][index] = packed(selected)
    preserved = copy.deepcopy(original_visible)
    preserved['name'] = old_name
    document['functions'].append(preserved)
    result = render_assembly(document).encode()
    assert assemble_program(result).as_dict() == document
    changed = {aliases['visible'], aliases['init_names']}
    retained = {function['name']: graph_pin(function) for function in baseline['functions']
                if function['name'] not in changed}
    assert all(function == funcs[function['name']] for function in document['functions'][:-1]
               if function['name'] not in changed)
    restored_visible = copy.deepcopy(preserved)
    restored_visible['name'] = aliases['visible']
    assert restored_visible == original_visible
    stats = {'functions': len(document['functions']),
             'blocks': sum(len(f['blocks']) for f in document['functions']),
             'instructions': sum(len(b['ops']) for f in document['functions'] for b in f['blocks'])}
    assert stats['functions'] <= 128 and stats['blocks'] <= 1536 and stats['instructions'] <= 8192
    output.mkdir(parents=True, exist_ok=False)
    (output / 'catalog_eleven_policy.hepta').write_bytes(result)
    proof = {'schema': 'hepta.runtime.catalog-eleven-policy-author.v1',
        'target_commit': TARGET, 'author_sha256': sha(Path(__file__).read_bytes()),
        'domain_sha256': sha((source / 'domain.py').read_bytes()),
        'baseline_source_sha256': BASE_SOURCE, 'declarations_sha256': DECLARATIONS,
        'baseline_table_reproduced_exactly': True, 'selected_tools': list(SELECTED_TOOLS),
        'changed_functions': sorted(changed), 'retained_function_graphs': retained,
        'original_visibility_preserved_as': old_name,
        'original_visibility_graph_sha256': graph_pin(original_visible),
        'classification_table_bytes': len(table), 'classifications': classified,
        'source_sha256': sha(result), 'source_bytes': len(result), **stats,
        'expected_wire_used_as_implementation': False,
        'public_all_configuration_qualified': False, 'whole_runtime_replaced': False}
    (output / 'projection-proof.json').write_bytes(encoded(proof))
    return proof


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hepta', type=Path, required=True)
    parser.add_argument('--source', type=Path, default=ROOT)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    proof = generate(args.hepta.resolve(strict=True), args.source.resolve(strict=True), args.output)
    print(json.dumps({key: proof[key] for key in ('source_sha256', 'source_bytes',
        'functions', 'blocks', 'instructions', 'changed_functions')}, sort_keys=True))

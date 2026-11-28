"""Replace only tools/list literals; retain the exact entry and non-list ASTs."""
from pathlib import Path
import copy
import hashlib
import json
import sys


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def author(root, hepta):
    root = Path(root).resolve(strict=True)
    sys.path.insert(0, str(Path(hepta).resolve(strict=True)))
    from compile_overlay import compile_source
    from hepta.hia_agent_assembly import assemble_program
    base = (root / 'baseline/runtime_mcp_catalog_target.hepta').read_bytes()
    assert sha(base) == '130afb86a6e085647c1fecd829230fb7637ec3808a0511680432293fa03edc5d'
    doc = assemble_program(base).as_dict()
    before = copy.deepcopy(doc)
    names = dict(json.loads((root / 'baseline/runtime_mcp_catalog_target_composition.json').read_bytes())['aliases'])
    assert names['entry'] == 'f0'
    qualification = json.loads((root / 'evidence/catalog-comparison.json').read_bytes())
    assert qualification['status'] == 'PASS'
    assert qualification['ordinary_policy_cases'] == 6
    assert qualification['typed_deserialization_policy_cases'] == 3
    assert qualification['actual_constructor_policy_cases'] == 3
    assert qualification['actual_list_constructor_executed'] is True
    assert qualification['actual_macro_metadata'] is True
    assets = [(root / ('evidence/public-nine-tools-policy' + str(policy) + '.suffix.bin')).read_bytes()
              for policy in (1, 2)]
    for raw in assets:
        assert raw.startswith(b',"result":') and raw.endswith(b'}')
        tools = json.loads(b'{"id":0' + raw)['result']['tools']
        assert len(tools) == 9 and tools[-1]['name'] == 'text_editor'
    # The baseline already contains the complete eight-tool list emitter.
    # Replace that private literal region instead of linking a second copy.
    # Its exact f0 remains the owner of admission, growth and non-list routing.
    source = '''def target_size(mode:u64) -> u64:
    if mode == 0:
        return LEGACY_SIZE
    return MODERN_SIZE

def target_literal(o:mutbuf, at:u64, mode:u64) -> u64:
'''.replace('LEGACY_SIZE', str(len(assets[0]))).replace('MODERN_SIZE', str(len(assets[1])))
    common = assets[0][len(b',"result":{'):]
    assert common and assets[1].endswith(common)
    prefixes = [raw[:-len(common)] for raw in assets]
    for mode, prefix in enumerate(prefixes):
        source += f'    if mode == {mode}:\n        prefix_{mode}(o, at)\n        common_literal(o, at + {len(prefix)})\n        return 0\n'
    source += '    return 0\n\ndef common_literal(o:mutbuf, at:u64) -> u64:\n'
    for start in range(0, len(common), 512):
        source += f'    common_{start}(o, at + {start})\n'
    source += '    return 0\n'
    pieces = [('prefix_' + str(i), raw) for i, raw in enumerate(prefixes)]
    pieces += [('common_' + str(start), common[start:start + 512]) for start in range(0, len(common), 512)]
    for name, body in pieces:
        source += f'\ndef {name}(o:mutbuf, at:u64) -> u64:\n'
        full = len(body) // 8 * 8
        # Advancing one cursor reuses the constant eight in each straight-line
        # block. Every native-produced literal byte remains present, while the
        # module stays inside the pinned compiler's 8192-instruction ceiling.
        for offset in range(0, full, 8):
            source += f'    put(o, at, {int.from_bytes(body[offset:offset + 8], "little")})\n'
            if offset + 8 < len(body):
                source += '    at = at + 8\n'
        for offset in range(full, len(body)):
            source += f'    store(o, at + {offset - full}, {body[offset]})\n'
        source += '    return 0\n'
    raw, after, names = compile_source(source, doc, names, {})
    old_by = {f['name']: f for f in before['functions']}
    new_by = {f['name']: f for f in after['functions']}
    changed = [name for name, value in old_by.items() if value != new_by[name]]
    literal_aliases = {'target_size', 'target_literal', 'common_literal'} | {name for name, _ in pieces}
    literal_functions = {names[name] for name in literal_aliases}
    assert set(changed) <= literal_functions, changed
    assert old_by['f0'] == new_by['f0']
    instructions = sum(len(block['ops']) for function in after['functions'] for block in function['blocks'])
    assert instructions <= 8192, instructions
    retained = {name: sha(json.dumps(value, sort_keys=True, separators=(',', ':')).encode())
                for name, value in old_by.items() if value == new_by[name]}
    destination = root / 'generated/native/runtime_mcp_catalog_ninth.hepta'
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(raw)
    (root / 'generated/ninth-catalog-authoring.txt').write_text(source)
    record = {'schema': 'hepta.g5.ninth-public-catalog-overlay.v3',
              'source_sha256': sha(raw), 'source_bytes': len(raw), 'baseline_sha256': sha(base),
              'changed_original_functions': changed, 'retained_exact_functions': retained,
              'baseline_entry_retained_exactly': True,
              'replaced_list_literal_functions': sorted(literal_functions, key=lambda name: int(name[1:])),
              'instructions': instructions, 'compiler_instruction_limit': 8192,
              'functions': len(after['functions']),
              'blocks': sum(len(f['blocks']) for f in after['functions']), 'aliases': names,
              'request_magic': 'HRMCD002', 'response_magic': 'HRCATR02', 'entry_return_bytes': 32,
              'compatible_catalog_slot': 0, 'declared_tool_count': 9,
              'literal_producer': 'fresh native sdk_catalog from exact macro metadata and retained eight declarations',
              'literal_result_construction': 'ListToolsResult::with_all_items',
              'original_sdk_expected_wire_used_as_implementation': False,
              'ordinary_catalog_comparison_sha256': sha((root / 'evidence/catalog-comparison.json').read_bytes()),
              'assets': [{'policy': policy, 'bytes': len(assets[i]), 'sha256': sha(assets[i])}
                         for i, policy in enumerate((1, 2))],
              'native_execution_qualified': False, 'public_route_registered': False,
              'tool_handler_executed': False, 'full_sdk_qualified': False,
              'full_136_route_qualified': False, 'production_activated': False, 'old_path_removed': False}
    (root / 'generated/native/runtime_mcp_catalog_ninth_composition.json').write_text(json.dumps(record, sort_keys=True, indent=2) + '\n')
    return destination, record

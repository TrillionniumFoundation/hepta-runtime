"""Install native-produced tools/list literals while preserving baseline function ASTs."""
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
    names['previous_entry'] = 'f' + str(len(doc['functions']))
    copied = copy.deepcopy(doc['functions'][0])
    copied['name'] = names['previous_entry']
    doc['functions'].append(copied)
    qualification = json.loads((root / 'evidence/catalog-comparison.json').read_bytes())
    assert qualification['status'] == 'PASS'
    assert qualification['ordinary_policy_cases'] == 3
    assert qualification['actual_macro_metadata'] is True
    assets = [(root / ('evidence/public-nine-tools-policy' + str(policy) + '.suffix.bin')).read_bytes()
              for policy in (1, 2)]
    for raw in assets:
        assert raw.startswith(b',"result":') and raw.endswith(b'}')
        tools = json.loads(b'{"id":0' + raw)['result']['tools']
        assert len(tools) == 9 and tools[-1]['name'] == 'text_editor'
    source = '''def entry(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 24:
        return previous_entry(s, o, w)
    if load(s, 0) != REQUEST:
        return previous_entry(s, o, w)
    if load(s, 8) != 1:
        return previous_entry(s, o, w)
    if length(o) < 32:
        return 4294967294
    if length(w) < 4096:
        return grow(o, 1, 4096)
    mode = load(s, 16)
    if length(s) != 24:
        return 4294967295
    if mode > 1:
        return 4294967295
    size = ninth_size(mode)
    if size > length(o) - 32:
        return grow(o, 2, 32 + size)
    ninth_literal(o, 32, mode)
    return finish(o, size)

def ninth_size(mode:u64) -> u64:
    if mode == 0:
        return LEGACY_SIZE
    return MODERN_SIZE

def ninth_literal(o:mutbuf, at:u64, mode:u64) -> u64:
'''.replace('REQUEST', str(int.from_bytes(b'HRMCD002', 'little'))).replace(
        'LEGACY_SIZE', str(len(assets[0]))).replace('MODERN_SIZE', str(len(assets[1])))
    common = assets[0][len(b',"result":{'):]
    assert common and assets[1].endswith(common)
    prefixes = [raw[:-len(common)] for raw in assets]
    for mode, prefix in enumerate(prefixes):
        source += f'    if mode == {mode}:\n        ninth_prefix_{mode}(o, at)\n        ninth_common(o, at + {len(prefix)})\n        return 0\n'
    source += '    return 0\n\ndef ninth_common(o:mutbuf, at:u64) -> u64:\n'
    for start in range(0, len(common), 512):
        source += f'    ninth_common_{start}(o, at + {start})\n'
    source += '    return 0\n'
    pieces = [('ninth_prefix_' + str(i), raw) for i, raw in enumerate(prefixes)]
    pieces += [('ninth_common_' + str(start), common[start:start + 512]) for start in range(0, len(common), 512)]
    for name, body in pieces:
        source += f'\ndef {name}(o:mutbuf, at:u64) -> u64:\n'
        full = len(body) // 8 * 8
        for at in range(0, full, 8):
            source += f'    put(o, at + {at}, {int.from_bytes(body[at:at + 8], "little")})\n'
        for at in range(full, len(body)):
            source += f'    store(o, at + {at}, {body[at]})\n'
        source += '    return 0\n'
    raw, after, names = compile_source(source, doc, names, {})
    old_by = {f['name']: f for f in before['functions']}
    new_by = {f['name']: f for f in after['functions']}
    changed = [name for name, value in old_by.items() if value != new_by[name]]
    assert changed == ['f0'], changed
    retained = {name: sha(json.dumps(value, sort_keys=True, separators=(',', ':')).encode())
                for name, value in old_by.items() if name != 'f0'}
    copied_entry = copy.deepcopy(new_by[names['previous_entry']])
    copied_entry['name'] = 'f0'
    assert copied_entry == old_by['f0']
    destination = root / 'generated/native/runtime_mcp_catalog_ninth.hepta'
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(raw)
    (root / 'generated/ninth-catalog-authoring.txt').write_text(source)
    record = {'schema': 'hepta.g5.ninth-public-catalog-overlay.v2',
              'source_sha256': sha(raw), 'source_bytes': len(raw), 'baseline_sha256': sha(base),
              'changed_original_functions': changed, 'retained_exact_functions': retained,
              'previous_entry': names['previous_entry'], 'previous_entry_cloned_exactly': True,
              'functions': len(after['functions']),
              'blocks': sum(len(f['blocks']) for f in after['functions']), 'aliases': names,
              'request_magic': 'HRMCD002', 'response_magic': 'HRCATR02', 'entry_return_bytes': 32,
              'compatible_catalog_slot': 0, 'declared_tool_count': 9,
              'literal_producer': 'fresh native sdk_catalog from exact macro metadata and retained eight declarations',
              'original_sdk_expected_wire_used_as_implementation': False,
              'ordinary_catalog_comparison_sha256': sha((root / 'evidence/catalog-comparison.json').read_bytes()),
              'assets': [{'policy': policy, 'bytes': len(assets[i]), 'sha256': sha(assets[i])}
                         for i, policy in enumerate((1, 2))],
              'native_execution_qualified': False, 'public_route_registered': False,
              'tool_handler_executed': False, 'full_sdk_qualified': False,
              'full_136_route_qualified': False, 'production_activated': False, 'old_path_removed': False}
    (root / 'generated/native/runtime_mcp_catalog_ninth_composition.json').write_text(json.dumps(record, sort_keys=True, indent=2) + '\n')
    return destination, record

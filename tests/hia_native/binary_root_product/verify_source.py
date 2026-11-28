"""Verify the narrow qualified-owner import and exact bridge inverse."""
from pathlib import Path
import argparse, copy, hashlib, json, sys

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
def check(base, source, hepta):
    sys.path.insert(0, str(hepta))
    from hepta.hia_agent_assembly import assemble_program
    sys.path.insert(0, str(source / 'scripts'))
    from public_nine_build import source_check, MEMBERS, EXTRA
    composition = json.loads((source / 'native/runtime_mcp_binary_root_integration.json').read_bytes())
    owner = composition['owner']['path']
    before, after = (base / owner).read_bytes(), (source / owner).read_bytes()
    for raw, expected in ((before, composition['owner']['before']), (after, composition['owner']['after'])):
        assert {'bytes': len(raw), 'sha256': SHA(raw)} == expected
    assert SHA(after) == 'cb22aa72a33b4a429356fdb7d70dd33828492676de1a89c11837d9d8f68a55b5'
    old, new = assemble_program(before).as_dict(), assemble_program(after).as_dict()
    assert len(old['functions']) == 52 and len(new['functions']) == 60
    unchanged = [i for i in range(52) if old['functions'][i] == new['functions'][i]]
    assert unchanged == [i for i in range(52) if i not in (0, 8)]
    relocated = copy.deepcopy(new['functions'][52]); relocated['name'] = 'f8'
    assert relocated == old['functions'][8]
    entry = copy.deepcopy(new['functions'][0])
    differences = [i for i, (a, b) in enumerate(zip(old['functions'][0]['blocks'], entry['blocks'], strict=True)) if a != b]
    assert len(differences) == 1
    block = entry['blocks'][differences[0]]
    original = old['functions'][0]['blocks'][differences[0]]
    assert block['id'] == original['id'] == 'b39'
    assert block['ops'][:2] == original['ops'][:2]
    assert block['ops'][2:] == [
        {'args': [], 'attrs': {'value': 9}, 'op': 'const', 'out': [{'name': 'v641', 'type': 'u64'}]},
        {'args': ['v369', 'v368'], 'attrs': {}, 'op': 'compare.eq', 'out': [{'name': 'v642', 'type': 'bool'}]},
        {'args': ['v369', 'v641'], 'attrs': {}, 'op': 'compare.eq', 'out': [{'name': 'v643', 'type': 'bool'}]},
        {'args': ['v642', 'v643'], 'attrs': {}, 'op': 'bool.or', 'out': [{'name': 'v370', 'type': 'bool'}]}]
    block['ops'] = original['ops']
    assert entry == old['functions'][0]
    bridge = composition['bridge']['path']
    restored = (source / bridge).read_text()
    for previous, current in reversed(composition['bridge']['exact_replacements']):
        assert restored.count(current) == 1
        restored = restored.replace(current, previous, 1)
    assert restored.encode() == (base / bridge).read_bytes()
    a = json.loads((base / 'native/runtime_mcp_sources.json').read_bytes())
    b = json.loads((source / 'native/runtime_mcp_sources.json').read_bytes())
    assert a['qualification'] == b['qualification']
    new_composition = 'native/runtime_mcp_binary_root_integration.json'
    assert set(b['sources']) - set(a['sources']) == {new_composition}
    assert not set(a['sources']) - set(b['sources'])
    changed = [p for p in a['sources'] if a['sources'][p] != b['sources'][p]]
    assert set(changed) == {owner, bridge}
    for path in a['sources']:
        if path not in changed:
            assert (base / path).read_bytes() == (source / path).read_bytes(), path
    restored_binding = copy.deepcopy(b)
    del restored_binding['binary_root_extension']
    del restored_binding['sources'][new_composition]
    for path in changed: restored_binding['sources'][path] = a['sources'][path]
    assert restored_binding == a
    assert len(MEMBERS) == 116 and len(EXTRA) == 69
    binding = source_check(source)
    return {'status': 'PASS', 'source_binding_sha256': binding['manifest_sha256'],
            'qualified_owner_bytes_exact': True, 'retained_functions': len(unchanged),
            'old_query_body_relocated_exactly': True, 'entry_operation9_extension_exact': True,
            'bridge_inverse_exact': True, 'unchanged_bound_files': len(a['sources']) - 2,
            'public_frontend_unchanged': True, 'qualification_flags_unchanged': True,
            'direct_hia_members': 116, 'engine_slots': 69}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('base', 'source', 'hepta', 'output'): p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    result = check(a.base.resolve(), a.source.resolve(), a.hepta.resolve())
    a.output.write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    print(json.dumps(result, sort_keys=True))
if __name__ == '__main__': main()

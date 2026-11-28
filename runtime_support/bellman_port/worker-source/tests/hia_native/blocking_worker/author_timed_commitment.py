"""Generate the resumable writer while preserving all 48 old helper graphs."""
from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import json
from pathlib import Path
import sys

from timed_commitment_source import SOURCE

OLD_SHA = "18a810c251fa1c73764bb0968d8db969ac5fc6a922e4a692cd5ce5e3f960ae36"
LITERALS = [b'{', b'"', b'states', b':', b'[', b']', b'}', b'actions', b'null', b',',
            b'kind', b'terminal', b'value', b'continue', b'branches', b'probability',
            b'successor', b'reward', b'fee']
# Negative values name a typed scalar, never an externally supplied raw JSON span.
# The caller supplies a branch base without its fixed 24-byte action header.
GROUPS = {
    1: [0, 1, 2, 1, 3, 4],
    3: [0, 1, 7, 1, 3, 4],
    6: [0, 1, 10, 1, 3, 1, 11, 1, 9, 1, 12, 1, 3, -1, 6],
    7: [0, 1, 10, 1, 3, 1, 13, 1, 9, 1, 14, 1, 3, 4],
    9: [0, 1, 15, 1, 3, -2, 9, 1, 16, 1, 3, -3,
        9, 1, 17, 1, 3, -4, 9, 1, 18, 1, 3, -5, 6],
    10: [5, 6], 12: [5, 6], 14: [5, 6],
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def author(root, hepta):
    sys.path.insert(0, str(hepta))
    from hepta.hia_agent_assembly import _parse_assembly_document, render_assembly
    from hepta.hia_program import verify_program
    from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
    original_raw = (root / "native/bellman_commitment.hepta").read_bytes()
    assert sha(original_raw) == OLD_SHA
    original = _parse_assembly_document(original_raw)
    assert len(original["functions"]) == 49
    old = {fn["name"]: fn for fn in original["functions"]}
    assert all(op.get("attrs", {}).get("function") != "f0"
               for fn in original["functions"][1:] for b in fn["blocks"] for op in b["ops"])
    source = SOURCE
    magics = {"INIT_MAGIC": b"HBTCIN01", "STATE_MAGIC": b"HBTCST01", "INIT_RESULT_MAGIC": b"HBTCIR01",
              "INPUT_MAGIC": b"HBCMT001", "CORE_MAGIC": b"HIABELL1", "OUTPUT_MAGIC": b"HBCMTRES",
              "EFFECT_MAGIC": b"HBTCEF01", "ACK_MAGIC": b"HBTCAK01"}
    for name, magic in magics.items():
        source = source.replace(name, str(int.from_bytes(magic, "little")))
    source += '\ndef group_size(pc:u64) -> u64:\n'
    for group, seq in GROUPS.items():
        source += f'    if pc == {group}:\n        return {len(seq)}\n'
    source += '    return 0\n'
    source += '\ndef group_fragment(s:readbuf, w:mutbuf, pc:u64, token:u64, at:u64) -> u64:\n'
    scalars = {-1: 'stage_float(w, old_10(s, at + 8))',
               -2: 'stage_float(w, old_10(s, at + 24))',
               -3: 'stage_integer(w, old_10(s, at + 32))',
               -4: 'stage_float(w, old_10(s, at + 40))',
               -5: 'stage_float(w, old_10(s, at + 48))'}
    for group, seq in GROUPS.items():
        source += f'    if pc == {group}:\n'
        for index, value in enumerate(seq):
            expression = scalars[value] if value < 0 else f'literal(w, {value})'
            source += f'        if token == {index}:\n            return {expression}\n'
    source += '    return 4294967295\n'
    source += '\ndef literal(w:mutbuf, code:u64) -> u64:\n    clear_fragment(w)\n    at = length(w) - 288\n'
    for code, raw in enumerate(LITERALS):
        source += f'    if code == {code}:\n'
        cursor = 0
        while cursor + 8 <= len(raw):
            value = int.from_bytes(raw[cursor:cursor + 8], "little")
            source += f'        old_12(w, at + {cursor}, {value})\n'
            cursor += 8
        for index in range(cursor, len(raw)):
            source += f'        store(w, at + {index}, {raw[index]})\n'
        source += f'        return {len(raw)}\n'
    source += '    return 4294967295\n'
    for index in range(1, 49):
        fn = old['f' + str(index)]
        args = ', '.join(f'a{i}:{p["type"]}' for i, p in enumerate(fn['params']))
        returned = 'False' if fn['returns'][0] == 'bool' else '0'
        source += f'\ndef old_{index}({args}) -> {fn["returns"][0]}:\n    return {returned}\n'
    nodes = ast.parse(source).body
    new_nodes = [n for n in nodes if not n.name.startswith('old_')]
    names = {new_nodes[0].name: 'f0'}
    names.update({n.name: 'f' + str(48 + i) for i, n in enumerate(new_nodes[1:], 1)})
    names.update({'old_' + str(i): 'f' + str(i) for i in range(1, 49)})
    signatures = {node.name: ([p.annotation.id for p in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(v) for v in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    result = compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'bellman_timed_commitment', 'functions': functions})
    for index, fn in enumerate(result['functions']):
        if fn['name'] in old and fn['name'] != 'f0':
            result['functions'][index] = copy.deepcopy(old[fn['name']])
    result['functions'].sort(key=lambda f: int(f['name'][1:]))
    verify_program(result)
    raw = render_assembly(result).encode()
    reread = _parse_assembly_document(raw)
    assert reread == result
    imported = {}
    for fn in reread['functions']:
        if fn['name'] in old and fn['name'] != 'f0':
            assert fn == old[fn['name']]
            imported[fn['name']] = sha(json.dumps(fn,sort_keys=True,separators=(',', ':')).encode())
    assert len(imported) == 48
    target = root / 'native/bellman_timed_commitment.hepta'
    target.write_bytes(raw)
    proof = {'schema': 'hepta.runtime.bellman-timed-commitment.source-proof.v1', 'status': 'SOURCE_ONLY_PASS',
             'source_bytes': len(raw), 'source_sha256': sha(raw), 'original_commitment_sha256': sha(original_raw),
             'author_sha256': sha(Path(__file__).read_bytes()),
             'pseudo_source_sha256': sha((Path(__file__).parent / 'timed_commitment_source.py').read_bytes()),
             'functions': len(result['functions']), 'blocks': sum(len(fn['blocks']) for fn in result['functions']),
             'unchanged_imported_function_graphs': imported, 'literal_write_fragments_hex': [x.hex() for x in LITERALS],
             'write_grammar': GROUPS, 'original_write_trace_commit': '0d5130aae148d88303e337cbd87f012d5d35d0ef',
             'original_write_trace_run': 43820406101, 'original_write_trace_artifact': 14204845314,
             'native_executed': False, 'original_executed_in_author': False,
             'actual_deadline_qualified': False, 'public_handler_qualified': False}
    (root / 'native/bellman_timed_commitment_source_proof.json').write_text(json.dumps(proof,indent=2,sort_keys=True)+'\n')
    return proof


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-root',type=Path,required=True)
    p.add_argument('--hepta',type=Path,required=True)
    a=p.parse_args()
    print(json.dumps(author(a.source_root.resolve(),a.hepta.resolve()),sort_keys=True))

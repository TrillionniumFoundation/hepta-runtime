"""Emit HIA, proving the imported formatter and SHA function graphs unchanged."""
import argparse
import ast
import copy
import hashlib
import json
from pathlib import Path
import sys

from commitment_source import SOURCE

PINS = {
    'native/serde_json.hepta': 'ef9dd3a567acf523257c4245c022b8cefa9b3ddb83075e826f129b1a1f341d18',
    'native/binary_codec.hepta': 'f58ab824ecb47545f19cd1d0daded9e41fca5457110693677d84e393e3098f23',
}
PREFIX = b'hepta.weight.bellman-plan.v1\0finite_dag_ordered_f64_v1\0'
TEXT = {
    'request_open': b'{"states":[', 'state_open': b'{"actions":[',
    'comma': b',', 'null': b'null', 'object_close': b'}',
    'array_object_close': b']}',
    'terminal_open': b'{"kind":"terminal","value":',
    'continue_open': b'{"kind":"continue","branches":[',
    'probability': b'{"probability":', 'successor': b',"successor":',
    'reward': b',"reward":', 'fee': b',"fee":',
}

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def graph_digest(value):
    return digest(json.dumps(value, sort_keys=True, separators=(',', ':')).encode())

def contract_source_borrow(fn):
    """Merge SHA update's read source into its one exclusive workspace loan.

    No operations are added or removed. Caller-owned spans at or above 8192
    are disjoint from every SHA state/schedule byte below 8192.
    """
    removed = {block['id']: [i for i, p in enumerate(block['params']) if p['type'] == 'readbuf']
               for block in fn['blocks']}
    fn['params'] = [p for p in fn['params'] if p['type'] != 'readbuf']
    for block in fn['blocks']:
        mutable = [p['name'] for p in block['params'] if p['type'] == 'mutbuf']
        assert len(mutable) == 1
        aliases = {p['name']: mutable[0] for p in block['params'] if p['type'] == 'readbuf'}
        block['params'] = [p for p in block['params'] if p['type'] != 'readbuf']
        for op in block['ops']:
            if op['op'] == 'buffer.store':
                assert op['args'][0] not in aliases, 'source write in imported SHA update'
            op['args'] = [aliases.get(v, v) for v in op['args']]
        term = block['term']
        if term['op'] == 'jump':
            edges = [term]
        elif term['op'] == 'branch':
            edges = [term['then'], term['else']]
            term['cond'] = aliases.get(term['cond'], term['cond'])
        else:
            edges = []
            term['values'] = [aliases.get(v, v) for v in term['values']]
        for edge in edges:
            edge['args'] = [aliases.get(v, v) for i, v in enumerate(edge['args'])
                            if i not in removed[edge['target']]]
    return fn

def generate(hepta, runtime, output):
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(hepta))
    from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    documents = {}
    for path, expected in PINS.items():
        raw = (runtime / path).read_bytes()
        assert digest(raw) == expected, ('source pin differs', path, digest(raw))
        documents[path] = {fn['name']: fn for fn in assemble_program(raw).as_dict()['functions']}
    fmt = documents['native/serde_json.hepta']
    closure = set()
    def visit(name):
        if name in closure:
            return
        closure.add(name)
        for block in fmt[name]['blocks']:
            for op in block['ops']:
                if op['op'] == 'call':
                    visit(op['attrs']['function'])
    visit('f16')
    assert closure == {'f' + str(i) for i in range(7, 21)}
    relocations = {
        'native/serde_json.hepta': {name: ('format_bits' if name == 'f16' else 'format_' + name)
                                  for name in sorted(closure, key=lambda v: int(v[1:]))},
        'native/binary_codec.hepta': {
            'f17': 'sha_init', 'f9': 'sha_update', 'f10': 'sha_finish',
            'f21': 'sha_word', 'f19': 'sha_compress', 'f20': 'sha_rotate', 'f22': 'sha_store'},
    }
    source = SOURCE
    for name, value in {
        'INPUT_MAGIC': int.from_bytes(b'HBCMT001', 'little'),
        'OUTPUT_MAGIC': int.from_bytes(b'HBCMTRES', 'little'),
        'IDENTITY_LENGTH': len(PREFIX) + 129,
        'PREFIX_LENGTH': len(PREFIX),
    }.items():
        source = source.replace(name, str(value))
    for name, raw in TEXT.items():
        source += f'\ndef text_{name}(w:mutbuf) -> u64:\n    at = reserve(w, {len(raw)})\n    if at == 0:\n        return 0\n'
        source += ''.join(f'    store(w, at + {i}, {byte})\n' for i, byte in enumerate(raw))
        source += '    return 0\n'
    source += '\ndef identity_prefix(w:mutbuf) -> u64:\n'
    source += ''.join(f'    store(w, {8192 + i}, {byte})\n' for i, byte in enumerate(PREFIX))
    source += '    return 0\n'
    for path, names in relocations.items():
        for old, new in names.items():
            function = documents[path][old]
            args = ', '.join(f'p{i}:{p["type"]}' for i, p in enumerate(function['params'])
                             if not (new == 'sha_update' and p['type'] == 'readbuf'))
            source += f'\ndef {new}({args}) -> {function["returns"][0]}:\n    return 0\n'
    nodes = ast.parse(source).body
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([p.annotation.id for p in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(p) for p in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    doc = compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'bellman_commitment', 'functions': functions})
    records, inserted = {}, {}
    for path, mapping in relocations.items():
        relocated = {old: names[new] for old, new in mapping.items()}
        records[path] = {'source_sha256': PINS[path], 'functions': {}, 'relocation': relocated}
        for old, target in relocated.items():
            fn = copy.deepcopy(documents[path][old])
            records[path]['functions'][old] = graph_digest(fn)
            fn['name'] = target
            if path.endswith('binary_codec.hepta') and old == 'f9':
                fn = contract_source_borrow(fn)
            for block in fn['blocks']:
                for op in block['ops']:
                    if op['op'] == 'call':
                        op['attrs']['function'] = relocated[op['attrs']['function']]
            i = next(i for i, item in enumerate(doc['functions']) if item['name'] == target)
            doc['functions'][i] = fn
            inserted[target] = fn
    assembly = render_assembly(doc).encode()
    result = assemble_program(assembly).as_dict()
    for fn in result['functions']:
        if fn['name'] in inserted:
            assert fn == inserted[fn['name']], 'imported graph differs after assembly'
        assert len(fn['blocks']) <= 256
        assert max(len(b['params']) for b in fn['blocks']) <= 16, fn['name']
        for block in fn['blocks']:
            for op in block['ops']:
                assert not op['op'].startswith(('float.', 'foreign.', 'ffi.'))
    output.write_bytes(assembly)
    output.with_suffix('.names.json').write_text(json.dumps(names, indent=2) + '\n')
    output.with_suffix('.composition.json').write_text(json.dumps({
        'schema': 'hia.bellman-commitment.composition.v1', 'source_sha256': digest(assembly),
        'imports': records, 'allowed_changes': [
            'function names and direct-call targets',
            'SHA update source readbuf loan contracted into the existing mutbuf loan; source references alias workspace and corresponding edge arguments are removed; no operation added or removed'],
        'implementation_source_digest': 'private trusted-installation input; no public request field',
        'public_handler_qualified': False,
    }, indent=2) + '\n')
    return {'path': str(output), 'bytes': len(assembly), 'sha256': digest(assembly), 'functions': len(functions)}

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hepta', type=Path, required=True)
    parser.add_argument('--runtime', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    a = parser.parse_args()
    print(json.dumps(generate(a.hepta.resolve(), a.runtime.resolve(), a.output.resolve())))

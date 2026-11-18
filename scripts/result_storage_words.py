# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Derive and verify six ordered eight-byte helpers in private storage images."""
from pathlib import Path
import argparse
import ast
import copy
import hashlib
import json
import sys

BASE_SHA = '6c3afb7d322b3c42d89727651aaae7cc1907a7766773e0bff4fdac9b11567a96'
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
CANON = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def ordered_word_source():
    text = ''
    for name, kind, buffer in (('get', 'mutbuf', 'w'), ('read64', 'readbuf', 's')):
        text += f'def {name}({buffer}:{kind}, at:u64) -> u64:\n    value = byte({buffer}, at)\n'
        for index in range(1, 8):
            text += f'    value = value | (byte({buffer}, at + {index}) << {8 * index})\n'
        text += '    return value\n\n'
    text += 'def put(w:mutbuf, at:u64, value:u64) -> u64:\n'
    for index in range(8):
        text += f'    store(w, at + {index}, value >> {8 * index})\n'
    return text + '    return 0\n'


def derive(source, hepta):
    raw = Path(source).read_bytes()
    assert SHA(raw) == BASE_SHA
    sys.path.insert(0, str(Path(hepta).resolve(strict=True)))
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
    before = assemble_program(raw).as_dict()
    assert len(before['functions']) == 47
    result = copy.deepcopy(before)
    text = ordered_word_source()
    nodes = ast.parse(text).body
    names = {'get': 'f14', 'put': 'f15', 'read64': 'f21'}
    signatures = {node.name: ([p.annotation.id for p in node.args.args], node.returns.id) for node in nodes}
    changes = []
    for node in nodes:
        builder = Builder(node, names, signatures, total_scalar_functions(nodes))
        builder.statements(node.body)
        function = dict(name=names[node.name], params=[builder.param(p) for p in builder.params],
            returns=[builder.returns], effects=['read', 'write', 'trap'], entry='b0', blocks=builder.blocks)
        function = compact_authoring_cfg(dict(schema='hepta.hia.program.v8', module='ordered_words',
            functions=[function]))['functions'][0]
        index = int(function['name'][1:])
        assert function['params'] == before['functions'][index]['params']
        assert function['returns'] == before['functions'][index]['returns']
        result['functions'][index] = function
        changes.append(dict(function=function['name'], alias=node.name,
            before_sha256=SHA(CANON(before['functions'][index])), after_sha256=SHA(CANON(function))))
    preserved = {function['name']: SHA(CANON(function)) for function in before['functions']
        if function['name'] not in names.values()}
    assert len(preserved) == 44
    for index, function in enumerate(result['functions']):
        if function['name'] in preserved:
            assert function == before['functions'][index]
    result['module'] = 'runtime_result_storage_value'
    rendered = render_assembly(result).encode()
    assert assemble_program(rendered).as_dict()['functions'] == result['functions']
    proof = dict(schema='hepta.result-storage.value-ordered-words.v1',
        original_source='native/serde_json.hepta', original_source_sha256=BASE_SHA,
        source='native/result_storage_value.hepta', source_sha256=SHA(rendered),
        functions=changes, unchanged_functions=preserved,
        authoring_source=text, authoring_source_sha256=SHA(text.encode()),
        input_output_workspace_limits_unchanged=True, original_allocation_and_error_order_unchanged=True,
        raw_value_special_key_semantics_added=False, whole_runtime_replaced=False,
        production_activated=False)
    return rendered, proof


def derive_retention(root, hepta, value_sha):
    root = Path(root)
    path = root / 'native/request_retention.hepta'
    raw = path.read_bytes()
    assert SHA(raw) == 'f6b7a81ea874cabf142332907fb9c3e9c1fb92a6494772a4611fec252e312bf6'
    sys.path.insert(0, str(Path(hepta).resolve(strict=True)))
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
    before = assemble_program(raw).as_dict()
    assert render_assembly(before).encode() == raw
    assert len(before['functions']) == 27
    result = copy.deepcopy(before)
    text = ordered_word_source()
    nodes = ast.parse(text).body
    names = {'get': 'f23', 'put': 'f24', 'read64': 'f22'}
    signatures = {node.name: ([p.annotation.id for p in node.args.args], node.returns.id) for node in nodes}
    changes = {}
    for node in nodes:
        builder = Builder(node, names, signatures, total_scalar_functions(nodes))
        builder.statements(node.body)
        function = dict(name=names[node.name], params=[builder.param(p) for p in builder.params],
            returns=[builder.returns], effects=['read', 'write', 'trap'], entry='b0', blocks=builder.blocks)
        function = compact_authoring_cfg(dict(schema='hepta.hia.program.v8', module='ordered_words',
            functions=[function]))['functions'][0]
        index = int(function['name'][1:])
        assert function['params'] == before['functions'][index]['params']
        assert function['returns'] == before['functions'][index]['returns']
        result['functions'][index] = function
        changes[function['name']] = dict(before_sha256=SHA(CANON(before['functions'][index])),
            after_sha256=SHA(CANON(function)))
    preserved = {f['name']: SHA(CANON(f)) for f in before['functions'] if f['name'] not in names.values()}
    assert len(preserved) == 24
    for index, function in enumerate(result['functions']):
        if function['name'] in preserved:
            assert function == before['functions'][index]
    rendered = render_assembly(result).encode()
    assert assemble_program(rendered).as_dict()['functions'] == result['functions']
    proof = json.loads((root / 'native/request_retention_composition.json').read_bytes())
    imported = [r for r in proof['imports'] if r['source'] == 'native/text_budget.hepta']
    assert len(imported) == 1 and imported[0]['relocation'] == {'f14':'f22','f15':'f23','f16':'f24'}
    proof['imports'] = [r for r in proof['imports'] if r not in imported]
    proof['local_word_helpers'] = dict(schema='hepta.result-storage.retention-ordered-words.v1',
        baseline_source_sha256=SHA(raw), original_import=imported[0], names=names,
        functions=changes, unchanged_functions=preserved,
        authoring_source=text, authoring_source_sha256=SHA(text.encode()))
    proof['source_sha256'] = SHA(rendered)
    proof['children']['value'] = dict(source='result_storage_value.hepta', sha256=value_sha)
    return rendered, proof


def verify_storage_words(root, hepta, *, with_retention_baseline=False):
    """Rebuild every changed IR function and restore the exact retained baseline."""
    from result_storage_registry import regular, require
    root, hepta = Path(root), Path(hepta)
    expected_value, expected_proof = derive(root / 'native/serde_json.hepta', hepta)
    require(regular(root / 'native/result_storage_value.hepta') == expected_value,
        'private storage Value is not the exact three-function derivation')
    require(json.loads(regular(root / 'native/result_storage_value_composition.json')) == expected_proof,
        'private storage Value derivation proof differs')
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    value = assemble_program(expected_value).as_dict()
    source = regular(root / 'native/request_retention.hepta')
    current = assemble_program(source).as_dict()
    proof = json.loads(regular(root / 'native/request_retention_composition.json'))
    local = proof['local_word_helpers']
    require(local['schema'] == 'hepta.result-storage.retention-ordered-words.v1'
        and local['baseline_source_sha256'] == 'f6b7a81ea874cabf142332907fb9c3e9c1fb92a6494772a4611fec252e312bf6'
        and len(current['functions']) == 27,
        'retention baseline or complete function domain differs')
    names = {'get':'f23', 'put':'f24', 'read64':'f22'}
    require(local['names'] == names, 'retention helper function mapping differs')
    text = ordered_word_source()
    require(local['authoring_source'] == text and local['authoring_source_sha256'] == SHA(text.encode()),
        'retention fixed ordered-byte authoring differs')
    replacements = {'f21':'f22', 'f14':'f23', 'f15':'f24'}
    current_functions = {f['name']:f for f in current['functions']}
    value_functions = {f['name']:f for f in value['functions']}
    require(len(current_functions) == 27, 'retention function identifiers repeat')
    for old, new in replacements.items():
        expected = copy.deepcopy(value_functions[old])
        expected['name'] = new
        require(current_functions[new] == expected, 'retention ordered-byte helper IR differs')
    imported = local['original_import']
    mapping = {'f14':'f22', 'f15':'f23', 'f16':'f24'}
    require(imported['source'] == 'native/text_budget.hepta' and imported['relocation'] == mapping
        and set(imported['functions']) == set(mapping), 'retention original import domain differs')
    original = regular(root / imported['source'])
    require(SHA(original) == imported['sha256'], 'retention original helper source differs')
    original_functions = {f['name']:f for f in assemble_program(original).as_dict()['functions']}
    restored = copy.deepcopy(current)
    changed = {}
    for old, new in mapping.items():
        function = copy.deepcopy(original_functions[old])
        require(SHA(CANON(function)) == imported['functions'][old], 'retention original helper IR differs')
        function['name'] = new
        for block in function['blocks']:
            for op in block['ops']:
                if op['op'] == 'call':
                    require(op['attrs']['function'] in mapping, 'retention helper has an undeclared dependency')
                    op['attrs']['function'] = mapping[op['attrs']['function']]
        restored['functions'][int(new[1:])] = function
        changed[new] = dict(before_sha256=SHA(CANON(function)),
            after_sha256=SHA(CANON(current_functions[new])))
    require(SHA(render_assembly(restored).encode()) == local['baseline_source_sha256'],
        'retention non-helper behavior differs from the complete frozen baseline')
    preserved = {f['name']:SHA(CANON(f)) for f in restored['functions'] if f['name'] not in names.values()}
    require(len(preserved) == 24 and preserved == local['unchanged_functions']
        and changed == local['functions'], 'retention derivation receipts differ')
    require(SHA(source) == proof['source_sha256'] and proof['children']['value'] ==
        dict(source='result_storage_value.hepta', sha256=SHA(expected_value)),
        'retention private Value child binding differs')
    counts = dict(value_preserved_functions=44, retention_preserved_functions=24, ordered_word_helpers=6)
    return (counts, restored) if with_retention_baseline else counts


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--hepta', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    value, value_proof = derive(args.root / 'native/serde_json.hepta', args.hepta)
    retention, retention_proof = derive_retention(args.root, args.hepta, SHA(value))
    dto_proof = json.loads((args.root / 'native/request_safe_dto_composition.json').read_bytes())
    dto_proof['value_child_source'] = 'result_storage_value.hepta'
    dto_proof['value_child_sha256'] = SHA(value)
    args.output.mkdir(parents=True, mode=0o700, exist_ok=True)
    files = {'result_storage_value.hepta':value,
        'result_storage_value_composition.json':CANON(value_proof)+b'\n',
        'request_retention.hepta':retention,
        'request_retention_composition.json':CANON(retention_proof)+b'\n',
        'request_safe_dto_composition.json':CANON(dto_proof)+b'\n'}
    for name, raw in files.items():
        (args.output/name).write_bytes(raw)
    print(json.dumps({name:{'sha256':SHA(raw),'bytes':len(raw)} for name,raw in files.items()},sort_keys=True))


if __name__ == '__main__':
    main()

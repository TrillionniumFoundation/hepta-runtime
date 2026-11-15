# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Author the source-owned serde_json 1.0.151 Value diagnostic state machine."""
from pathlib import Path
import argparse
import ast
import copy
import hashlib
import json
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
CANONICAL = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
VALUE_SHA = '6c3afb7d322b3c42d89727651aaae7cc1907a7766773e0bff4fdac9b11567a96'
UTF8_SHA = '89df7b4320fdbd3525450e9446267ae3d54a5b62660d8904fe8f09be36a7fbf9'
LITERALS = {
    1: b'EOF while parsing a list', 2: b'EOF while parsing an object',
    3: b'EOF while parsing a string', 4: b'EOF while parsing a value',
    5: b'expected `:`', 6: b'expected `,` or `]`', 7: b'expected `,` or `}`',
    8: b'expected ident', 9: b'expected value', 10: b'expected `"`',
    11: b'invalid escape', 12: b'invalid number', 13: b'number out of range',
    14: b'invalid unicode code point',
    15: b'control character (\\u0000-\\u001F) found while parsing a string',
    16: b'key must be a string',
    17: b'invalid value: expected key to be a number in quotes',
    18: b'float key must be finite (got NaN or +/-inf)',
    19: b'lone leading surrogate in hex escape', 20: b'trailing comma',
    21: b'trailing characters', 22: b'unexpected end of hex escape',
    23: b'recursion limit exceeded',
    100: b'invalid type: null, expected raw value',
    101: b'invalid type: boolean `true`, expected raw value',
    102: b'invalid type: boolean `false`, expected raw value',
    103: b'invalid type: sequence, expected raw value',
    104: b'invalid type: map, expected raw value',
    105: b'invalid type: integer `', 106: b'invalid type: floating point `',
    107: b'`, expected raw value', 200: b' at line ', 201: b' column ',
}


def private_number_source(function, name):
    """Coalesce read-only token and numeric scratch into a disjoint private arena.

    The caller copies the immutable token above DATA=1MiB. Existing numeric
    writes remain below 8192. This only removes one resource parameter and
    redirects its reads; arithmetic operations and every branch are preserved.
    """
    result = copy.deepcopy(function)
    assert name in {'f3', 'f4'}
    assert [p['type'] for p in result['params']] == ['readbuf', 'mutbuf', 'u64', 'u64']
    removed, renamed = {}, {}
    for block in result['blocks']:
        reads = [i for i, p in enumerate(block['params']) if p['type'] == 'readbuf']
        writes = [p['name'] for p in block['params'] if p['type'] == 'mutbuf']
        assert len(reads) <= 1
        if reads:
            assert len(writes) == 1
            removed[block['id']] = reads[0]
            renamed[block['params'][reads[0]]['name']] = writes[0]
    for block in result['blocks']:
        for operation in block['ops']:
            assert not any(p['type'] == 'readbuf' for p in operation['out'])
            operation['args'] = [renamed.get(a, a) for a in operation['args']]
            if operation['op'] == 'call' and operation['attrs']['function'] in {'f3', 'f4'}:
                assert operation['args'][0] == operation['args'][1]
                operation['args'].pop(0)
        term = block['term']
        if 'cond' in term:
            term['cond'] = renamed.get(term['cond'], term['cond'])
        if term['op'] == 'jump':
            edges = [term]
        elif term['op'] == 'branch':
            edges = [term['then'], term['else']]
        else:
            assert term['op'] == 'ret'
            term['values'] = [renamed.get(a, a) for a in term['values']]
            edges = []
        for edge in edges:
            edge['args'] = [renamed.get(a, a) for a in edge['args']]
            if edge['target'] in removed:
                edge['args'].pop(removed[edge['target']])
        if block['id'] in removed:
            block['params'].pop(removed[block['id']])
    result['params'].pop(0)
    return result


def generated_source():
    source = '\n'.join((ROOT / 'scripts' / path).read_text()
        for path in ('serde_error_parser_source.py.txt', 'serde_error_string_source.py.txt', 'serde_error_display_source.py.txt'))
    constants = dict(INVALID=0xffffffff, CAPACITY=0xfffffffe, P=16384, NUMBER_TEXT=24576,
        STACK=32768, DATA=1048576, REQUEST=int.from_bytes(b'HSJERQ01', 'little'),
        RESPONSE=int.from_bytes(b'HSJERR01', 'little'))
    source = re.sub(r'\b(' + '|'.join(constants) + r')\b', lambda match: str(constants[match[0]]), source)
    source += '\ndef literal_size(code:u64) -> u64:\n'
    for code, raw in LITERALS.items():
        source += f'    if code == {code}:\n        return {len(raw)}\n'
    source += '    return 0\n\ndef literal(o:mutbuf, at:u64, code:u64) -> u64:\n'
    for code, raw in LITERALS.items():
        source += f'    if code == {code}:\n'
        full = len(raw) // 8 * 8
        for offset in range(0, full, 8):
            source += f'        put(o, at + {offset}, {int.from_bytes(raw[offset:offset+8], "little")})\n'
        for offset in range(full, len(raw)):
            source += f'        store(o, at + {offset}, {raw[offset]})\n'
        source += f'        return at + {len(raw)}\n'
    source += '    return at\n\ndef token_byte(index:u64) -> u64:\n'
    token = b'$serde_json::private::RawValue'
    assert len(token) == 30
    for index, value in enumerate(token):
        source += f'    if index == {index}:\n        return {value}\n'
    source += '    return 256\n\ndef ident_byte(first:u64, index:u64) -> u64:\n'
    for token in (b'null', b'true', b'false'):
        source += f'    if first == {token[0]}:\n'
        for index, value in enumerate(token[1:]):
            source += f'        if index == {index}:\n            return {value}\n'
    return source + '    return 256\n'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--hepta', type=Path, required=True)
    parser.add_argument('--runtime', type=Path, required=True)
    options = parser.parse_args()
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(options.hepta.resolve(strict=True)))
    from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program, render_assembly

    class Bulk(Builder):
        def expr(self, node):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'copy_range':
                args = [self.expr(item) for item in node.args]
                if args[0] == args[1]:
                    return self.op('buffer.move_within', [args[0], *(self.cast(x, 'usize') for x in args[2:])])
                source = args[1]
                if source[1] == 'mutbuf':
                    source = self.op('borrow.read', [source], 'readbuf')
                result = self.op('buffer.copy_range', [args[0], source, *(self.cast(x, 'usize') for x in args[2:])])
                if args[1][1] == 'mutbuf':
                    self.op('loan.end', [source])
                return result
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in self.signatures:
                values = [self.expr(item) for item in node.args]
                signature = self.signatures[node.func.id]
                assert len(values) == len(signature[0])
                args, loans = [], []
                for value, kind in zip(values, signature[0]):
                    if value[1] == 'mutbuf' and kind == 'readbuf':
                        value = self.op('borrow.read', [value], 'readbuf')
                        loans.append(value)
                    args.append(self.cast(value, kind) if value[1] != kind else value)
                result = self.op('call', args, signature[1], function=self.names[node.func.id])
                for value in loans:
                    self.op('loan.end', [value])
                return result
            return super().expr(node)

    nodes = ast.parse(generated_source()).body
    names = {node.name: 'f' + str(index) for index, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id) for node in nodes}
    specs = [
        ('native/serde_json.hepta', {'classify_private': 'f3', 'format_bits': 'f16',
            'get': 'f14', 'put': 'f15', 'read64': 'f21'}, VALUE_SHA, {'f3', 'f4'}),
        ('native/text_budget.hepta', {'utf8': 'f2'}, UTF8_SHA, set()),
    ]
    imports, proof = [], []
    for relative, aliases, expected, private in specs:
        raw = (options.runtime / relative).read_bytes()
        assert SHA(raw) == expected, (relative, SHA(raw), expected)
        original = {f['name']: f for f in assemble_program(raw).as_dict()['functions']}
        selected = set(aliases.values())
        pending = list(selected)
        while pending:
            for block in original[pending.pop()]['blocks']:
                for op in block['ops']:
                    if op['op'] == 'call' and op['attrs']['function'] not in selected:
                        selected.add(op['attrs']['function'])
                        pending.append(op['attrs']['function'])
        relocation = {old: 'f' + str(len(nodes) + len(imports) + index)
            for index, old in enumerate(sorted(selected, key=lambda name: int(name[1:])))}
        derived = {old: private_number_source(original[old], old) if old in private else copy.deepcopy(original[old])
            for old in selected}
        for alias, old in aliases.items():
            names[alias] = relocation[old]
            signatures[alias] = ([arg['type'] for arg in derived[old]['params']], derived[old]['returns'][0])
        for old, new in relocation.items():
            item = copy.deepcopy(derived[old])
            item['name'] = new
            for block in item['blocks']:
                for op in block['ops']:
                    if op['op'] == 'call':
                        op['attrs']['function'] = relocation[op['attrs']['function']]
            imports.append(item)
        proof.append(dict(source=relative, sha256=expected, relocation=relocation,
            functions={name: SHA(CANONICAL(original[name])) for name in relocation},
            derived_functions={name: SHA(CANONICAL(derived[name])) for name in relocation},
            coalesced_private_arena_functions=sorted(private), numeric_scratch=[0, 8192], input_base=1048576))
    functions = []
    total = total_scalar_functions(nodes)
    for node in nodes:
        builder = Bulk(node, names, signatures, total)
        builder.statements(node.body)
        functions.append(dict(name=names[node.name], params=[builder.param(p) for p in builder.params],
            returns=[builder.returns], effects=['read', 'write', 'trap'], entry='b0', blocks=builder.blocks))
    document = compact_authoring_cfg(dict(schema='hepta.hia.program.v8',
        module='serde_json_value_diagnostics', functions=functions + imports))
    document['functions'] = document['functions'][:len(functions)] + imports
    raw = render_assembly(document).encode()
    actual = {f['name']: f for f in assemble_program(raw).as_dict()['functions']}
    assert all(actual[item['name']] == item for item in imports)
    (ROOT / 'native').mkdir(exist_ok=True)
    (ROOT / 'native/serde_error.hepta').write_bytes(raw)
    (ROOT / 'names.json').write_text(json.dumps(names, sort_keys=True, indent=2) + '\n')
    metadata = dict(schema='hepta.runtime.serde-value-error-composition.v1',
        source_sha256=SHA(raw), imports=proof,
        original='serde_json 1.0.151 from_slice::<Value>, float_roundtrip/raw_value',
        qualified=False, typed_derive_diagnostics_closed=False, complete_runtime=False)
    (ROOT / 'native/serde_error_composition.json').write_text(json.dumps(metadata, sort_keys=True, indent=2) + '\n')
    print(json.dumps(dict(source_sha256=SHA(raw), bytes=len(raw), functions=len(actual),
        instructions=sum(len(b['ops']) for f in actual.values() for b in f['blocks'])), sort_keys=True))


if __name__ == '__main__':
    main()

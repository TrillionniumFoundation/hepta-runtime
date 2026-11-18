# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Author the closed HIA open_legacy_archive_at state owner."""
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
CANON = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
CONSTANTS = dict(INVALID=0xffffffff, CAPACITY=0xfffffffe, EFFECT=0xfffffff0,
    WORK=1048576, PHASE=8, SEQUENCE=16, OUTPUT_LENGTH=24, WORK_LENGTH=32,
    OPERATION=40, LIVE=48, LEASE=56, GENERATION=64, DIAGNOSTIC=72, ERRNO=80,
    WRITE_POSITION=88, WRITE_LENGTH=96, METADATA_RETURN=104, METADATA_ERROR=112,
    METADATA_CACHE=120, METADATA_SLOT=128, ANCHOR_LEASE=136, TEMP_LIVE=144,
    CREATING=152, SAVED_ACTION=160, PINNED_LENGTH=216, ACTION=256, SNAPSHOT=512,
    STAT=1024, ROOT_STAMP=2048, LEGACY_STAMP=2304, STATX=3072,
    TEMP_NAME=4096, LEGACY_NAME=4352, ANCHOR_NAME=4608, JSON_BYTES=6144,
    CHILD_REQUEST=8192, CHILD_REPLY=12288, REQUEST_COPY=16384,
    PROJECTION=20480, PINNED_BYTES=24576)
CONSTANTS.update({key: int.from_bytes(value, 'little') for key, value in dict(
    REQUEST_MAGIC=b'HRALQ001', RESPONSE_MAGIC=b'HRALR001', STATE_MAGIC=b'HRALW001',
    ACTION_MAGIC=b'HRALA001', ANCHOR_REQUEST=b'HRAAQ001', ANCHOR_RESPONSE=b'HRAAR001',
    NAMESPACE_REQUEST=b'HNSVQ001', NAMESPACE_RESPONSE=b'HNSVR001',
    ENTROPY_REQUEST=b'HRENT001', PROJECTION_MAGIC=b'HRAJJ001').items()})


class ExplicitBoolean(ast.NodeTransformer):
    def visit_UnaryOp(self, node):
        node = self.generic_visit(node)
        if isinstance(node.op, ast.Not):
            return ast.copy_location(ast.Compare(left=node.operand, ops=[ast.Eq()], comparators=[ast.Constant(False)]), node)
        return node


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hepta', type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.hepta.resolve(strict=True)))
    from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program, render_assembly

    class BorrowBuilder(Builder):
        def expr(self, node):
            if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.FloorDiv, ast.Mod)):
                arguments = [self.cast(self.expr(value), 'u64') for value in (node.left, node.right)]
                return self.op('int.div.checked' if isinstance(node.op, ast.FloorDiv) else 'int.rem.checked', arguments, 'u64')
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'copy_range':
                values = [self.expr(value) for value in node.args]
                if values[0] == values[1]:
                    return self.op('buffer.move_within', [values[0], *(self.cast(v, 'usize') for v in values[2:])])
                source = values[1]
                if source[1] == 'mutbuf':
                    source = self.op('borrow.read', [source], 'readbuf')
                result = self.op('buffer.copy_range', [values[0], source, *(self.cast(v, 'usize') for v in values[2:])])
                if values[1][1] == 'mutbuf':
                    self.op('loan.end', [source])
                return result
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in self.signatures:
                arguments = [self.expr(value) for value in node.args]
                signature = self.signatures[node.func.id]
                loans, converted = [], []
                for value, kind in zip(arguments, signature[0], strict=True):
                    if value[1] == 'mutbuf' and kind == 'readbuf':
                        value = self.op('borrow.read', [value], 'readbuf')
                        loans.append(value)
                    converted.append(self.cast(value, kind) if value[1] != kind else value)
                result = self.op('call', converted, signature[1], function=self.names[node.func.id])
                for loan in loans:
                    self.op('loan.end', [loan])
                return result
            return super().expr(node)

    pins = json.loads((ROOT / 'dependency-inputs.json').read_bytes())
    for name, expected in pins.items():
        raw = (ROOT / name).read_bytes()
        assert dict(bytes=len(raw), sha256=SHA(raw)) == expected
    authored = (ROOT / 'scripts/legacy_source.py.txt').read_text()
    literals = {1: b'{"root_device":', 2: b',"root_inode":',
        3: b',"archive_device":', 4: b',"archive_inode":',
        5: b'.archive-anchor-', 6: b'.tmp'}
    authored += '\ndef literal(w:mutbuf, target:u64, which:u64) -> u64:\n'
    for number, literal in literals.items():
        authored += f'    if which == {number}:\n'
        for i, value in enumerate(literal):
            authored += f'        store(w, target + {i}, {value})\n'
        authored += f'        return target + {len(literal)}\n'
    authored += '    return target\n\ndef names(w:mutbuf) -> u64:\n'
    for name, literal in (('LEGACY_NAME', b'request-archive-v11'),
                          ('ANCHOR_NAME', b'.request-archive-v11-anchor.json')):
        for i, value in enumerate(literal + b'\0'):
            authored += f'    store(w, {name} + {i}, {value})\n'
    authored += '    return 0\n'
    authored = re.sub(r'\b(' + '|'.join(CONSTANTS) + r')\b', lambda m: str(CONSTANTS[m[0]]), authored)
    nodes = ExplicitBoolean().visit(ast.parse(authored)).body
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([p.annotation.id for p in node.args.args], node.returns.id) for node in nodes}
    anchor = json.loads((ROOT / 'dependencies/anchor_composition_frozen.json').read_bytes())
    groups = [('dependencies/text_budget.hepta', dict(load='f14', get='f15', put='f16')),
        ('dependencies/anchor_frozen.hepta', dict(normalize_statx=anchor['functions']['normalize_statx']))]
    imported, imports = [], []
    for filename, aliases in groups:
        raw = (ROOT / filename).read_bytes()
        original = {f['name']: f for f in assemble_program(raw).as_dict()['functions']}
        selected, pending = set(aliases.values()), list(aliases.values())
        while pending:
            for block in original[pending.pop()]['blocks']:
                for op in block['ops']:
                    if op['op'] == 'call' and op['attrs']['function'] not in selected:
                        selected.add(op['attrs']['function']);pending.append(op['attrs']['function'])
        relocation = {old: 'f' + str(len(nodes) + len(imported) + i) for i, old in enumerate(sorted(selected, key=lambda n: int(n[1:])))}
        for alias, old in aliases.items():
            names[alias] = relocation[old]
            signatures[alias] = ([p['type'] for p in original[old]['params']], original[old]['returns'][0])
        for old, new in relocation.items():
            value = copy.deepcopy(original[old]);value['name'] = new
            for block in value['blocks']:
                for op in block['ops']:
                    if op['op'] == 'call':
                        op['attrs']['function'] = relocation[op['attrs']['function']]
            imported.append(value)
        imports.append(dict(source=filename, sha256=SHA(raw), relocation=relocation,
            functions={old: SHA(CANON(original[old])) for old in relocation}))
    functions = []
    total = total_scalar_functions(nodes)
    for node in nodes:
        builder = BorrowBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append(dict(name=names[node.name], params=[builder.param(p) for p in builder.params],
            returns=[builder.returns], effects=['read', 'write', 'trap'], entry='b0', blocks=builder.blocks))
    document = compact_authoring_cfg(dict(schema='hepta.hia.program.v8', module='runtime_audit_legacy', functions=functions + imported))
    document['functions'] = document['functions'][:len(functions)] + imported
    raw = render_assembly(document).encode()
    actual = {f['name']: f for f in assemble_program(raw).as_dict()['functions']}
    assert all(actual[value['name']] == value for value in imported)
    (ROOT / 'native/audit_legacy.hepta').write_bytes(raw)
    proof = dict(schema='hepta.runtime.audit-legacy-composition.v1', source_sha256=SHA(raw),
        functions=names, constants=CONSTANTS, imports=imports,
        children={key: dict(source=value, sha256=SHA((ROOT / value).read_bytes())) for key, value in dict(
            anchor='native/audit_legacy_anchor.hepta', namespace='native/audit_legacy_namespace.hepta',
            typed_json='dependencies/request_audit_json.hepta', entropy='dependencies/entropy_policy.hepta').items()},
        original_sources={str(p.relative_to(ROOT / 'original')): SHA(p.read_bytes()) for p in (ROOT / 'original').glob('*.rs')},
        trusted_parent_owns_root_descriptor=True, no_caller_selected_root=True,
        actual_qualification_executed=False, complete_archive_acquisition=False,
        production_activated=False, whole_runtime_replaced=False)
    (ROOT / 'native/audit_legacy_composition.json').write_text(json.dumps(proof, sort_keys=True, indent=2) + '\n')
    print(json.dumps(dict(bytes=len(raw), sha256=SHA(raw), functions=len(actual), imports=len(imported))))


if __name__ == '__main__':
    main()

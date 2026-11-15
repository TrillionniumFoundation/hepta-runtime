# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Compose actual-file hot-cache methods with a frozen cache owner and private inspection."""
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
CONSTANTS = json.loads((ROOT / 'dependencies/hot_cache_composition.json').read_bytes())['constants']


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
    sys.path[:0] = [str(ROOT / 'scripts'), str(args.hepta.resolve(strict=True))]
    from borrow_builder import BorrowBuilder
    from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    for name, pin in json.loads((ROOT / 'dependency-inputs.json').read_bytes()).items():
        raw = (ROOT / name).read_bytes()
        assert (len(raw), SHA(raw)) == (pin['bytes'], pin['sha256'])
    source = (ROOT / 'scripts/cache_stamp_source.py.txt').read_text()
    source = re.sub(r'\b(' + '|'.join(CONSTANTS) + r')\b', lambda m: str(CONSTANTS[m[0]]), source)
    nodes = ExplicitBoolean().visit(ast.parse(source)).body
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([p.annotation.id for p in node.args.args], node.returns.id) for node in nodes}
    composed = json.loads((ROOT / 'dependencies/hot_cache_composition.json').read_bytes())
    dependency = 'dependencies/request_audit_hot_cache.hepta'
    raw = (ROOT / dependency).read_bytes()
    originals = {f['name']: f for f in assemble_program(raw).as_dict()['functions']}
    aliases = dict(composed['functions']);aliases['cache'] = aliases.pop('entry')
    selected = set(originals)
    relocation = {old: 'f' + str(len(nodes) + i) for i, old in enumerate(sorted(selected, key=lambda n: int(n[1:])))}
    imported = []
    for alias, old in aliases.items():
        names[alias] = relocation[old]
        signatures[alias] = ([p['type'] for p in originals[old]['params']], originals[old]['returns'][0])
    for old, new in relocation.items():
        value = copy.deepcopy(originals[old]);value['name'] = new
        for block in value['blocks']:
            for op in block['ops']:
                if op['op'] == 'call':op['attrs']['function'] = relocation[op['attrs']['function']]
        imported.append(value)
    functions = []
    total = total_scalar_functions(nodes)
    for node in nodes:
        builder = BorrowBuilder(node, names, signatures, total);builder.statements(node.body)
        functions.append(dict(name=names[node.name], params=[builder.param(p) for p in builder.params],
            returns=[builder.returns], effects=['read', 'write', 'trap'], entry='b0', blocks=builder.blocks))
    document = compact_authoring_cfg(dict(schema='hepta.hia.program.v8', module='runtime_request_audit_cache_stamp', functions=functions + imported))
    document['functions'] = document['functions'][:len(functions)] + imported
    native = render_assembly(document).encode()
    actual = {f['name']: f for f in assemble_program(native).as_dict()['functions']}
    assert all(actual[value['name']] == value for value in imported)
    (ROOT / 'native/request_audit_cache_stamp.hepta').write_bytes(native)
    proof = dict(schema='hepta.request-audit.cache-stamp-composition.v1', source_sha256=SHA(native),
        functions=names, constants=CONSTANTS,
        imports=[dict(source=dependency, sha256=SHA(raw), relocation=relocation,
            functions={old: SHA(CANON(originals[old])) for old in relocation})],
        children={key: dict(source=name, sha256=SHA((ROOT / name).read_bytes())) for key,name in dict(
            stamp='dependencies/request_audit_stamp.hepta',namespace='dependencies/audit_legacy_namespace.hepta').items()},
        original_source_sha256=SHA((ROOT / 'original/request_audit.rs').read_bytes()),
        original_cache_functions_unchanged=True, cold_snapshot_admitted=False, private_inspection_only=True,
        owned_metadata_cache_shared_with_namespace=True, actual_qualification_executed=False,
        standalone_native_process_qualified=False, public_dispatch_qualified=False,
        production_activated=False, whole_runtime_replaced=False, audit_storage_closed=False)
    (ROOT / 'native/request_audit_cache_stamp_composition.json').write_text(json.dumps(proof, sort_keys=True, indent=2) + '\n')
    print(json.dumps(dict(bytes=len(native), sha256=SHA(native), functions=len(actual), imported_functions=len(imported))))


if __name__ == '__main__':main()

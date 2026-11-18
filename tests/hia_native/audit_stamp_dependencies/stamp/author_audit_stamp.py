# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Author archive_stamp; import the frozen statx normalization closure exactly."""
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
    METADATA_RETURN=104, METADATA_ERROR=112, METADATA_CACHE=120, METADATA_SLOT=128,
    SAVED_ACTION=160, ACTION=256, SNAPSHOT=512, STAT=1024, STATX=3072,
    CHILD_REQUEST=8192, CHILD_REPLY=12288, REQUEST_COPY=16384)
CONSTANTS.update({key: int.from_bytes(value, 'little') for key, value in dict(
    REQUEST_MAGIC=b'HRASQ001', RESPONSE_MAGIC=b'HRACC001', STATE_MAGIC=b'HRASW001',
    ACTION_MAGIC=b'HRASA001', NAMESPACE_REQUEST=b'HNSVQ001',
    NAMESPACE_RESPONSE=b'HNSVR001', STAMP_MAGIC=b'HRAST001').items()})


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
    source = (ROOT / 'scripts/audit_stamp_source.py.txt').read_text()
    legacy = (ROOT / 'dependencies/legacy_source.py.txt').read_text()
    selected = ('acknowledged', 'metadata', 'metadata_done', 'metadata_failed',
        'metadata_probe', 'metadata_resume', 'effect', 'pending', 'copy_range', 'fill_range')
    author_imports = []
    for node in ast.parse(legacy).body:
        if node.name not in selected:
            continue
        raw = ast.get_source_segment(legacy, node)
        original = raw
        if node.name == 'metadata_done':
            assert raw.count('acquire_resume') == 1
            raw = raw.replace('acquire_resume', 'stamp_resume')
        source += '\n' + raw + '\n'
        author_imports.append(dict(function=node.name, source_sha256=SHA(original.encode()),
            composed_sha256=SHA(raw.encode()), change='callback rename only' if node.name == 'metadata_done' else 'unchanged'))
    source = re.sub(r'\b(' + '|'.join(CONSTANTS) + r')\b', lambda m: str(CONSTANTS[m[0]]), source)
    nodes = ExplicitBoolean().visit(ast.parse(source)).body
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([p.annotation.id for p in node.args.args], node.returns.id) for node in nodes}
    composed = json.loads((ROOT / 'dependencies/audit_legacy_composition.json').read_bytes())
    dependency = 'dependencies/audit_legacy_frozen.hepta'
    raw = (ROOT / dependency).read_bytes()
    originals = {f['name']: f for f in assemble_program(raw).as_dict()['functions']}
    aliases = {name: composed['functions'][name] for name in ('load', 'get', 'put', 'normalize_statx')}
    selected, pending = set(aliases.values()), list(aliases.values())
    while pending:
        for block in originals[pending.pop()]['blocks']:
            for op in block['ops']:
                if op['op'] == 'call' and op['attrs']['function'] not in selected:
                    selected.add(op['attrs']['function']);pending.append(op['attrs']['function'])
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
    document = compact_authoring_cfg(dict(schema='hepta.hia.program.v8', module='runtime_request_audit_stamp', functions=functions + imported))
    document['functions'] = document['functions'][:len(functions)] + imported
    native = render_assembly(document).encode()
    actual = {f['name']: f for f in assemble_program(native).as_dict()['functions']}
    assert all(actual[value['name']] == value for value in imported)
    (ROOT / 'native/request_audit_stamp.hepta').write_bytes(native)
    proof = dict(schema='hepta.request-audit.stamp-composition.v1', source_sha256=SHA(native),
        functions=names, constants=CONSTANTS, author_imports=author_imports,
        imports=[dict(source=dependency, sha256=SHA(raw), relocation=relocation,
            functions={old: SHA(CANON(originals[old])) for old in relocation})],
        children=dict(namespace=dict(source='dependencies/audit_legacy_namespace.hepta',
            sha256=SHA((ROOT / 'dependencies/audit_legacy_namespace.hepta').read_bytes()))),
        original_source_sha256=SHA((ROOT / 'original/request_audit.rs').read_bytes()),
        owned_metadata_cache_shared_with_namespace=True, actual_qualification_executed=False,
        standalone_native_process_qualified=False, public_dispatch_qualified=False,
        production_activated=False, whole_runtime_replaced=False, audit_storage_closed=False)
    (ROOT / 'native/request_audit_stamp_composition.json').write_text(json.dumps(proof, sort_keys=True, indent=2) + '\n')
    print(json.dumps(dict(bytes=len(native), sha256=SHA(native), functions=len(actual), imported_functions=len(imported))))


if __name__ == '__main__':main()

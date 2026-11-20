#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Author the pure fixed-planner continuation and parent request conversion."""
import argparse
import ast
import hashlib
import json
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'hepta', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    output = args.output.absolute()
    if output.exists():
        raise ValueError('fresh author output required')
    sys.path.insert(0, str(args.hepta.resolve(strict=True)))
    from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program, render_assembly

    class NativeBuilder(Builder):
        def expr(self, node):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'copy_span':
                values = [self.expr(arg) for arg in node.args]
                assert len(values) == 5 and values[0][1] == 'mutbuf' and values[1][1] in ('readbuf', 'mutbuf')
                borrowed = self.op('borrow.read', [values[1]], 'readbuf') if values[1][1] == 'mutbuf' else None
                self.op('buffer.copy_range', [values[0], borrowed or values[1], *(self.cast(v, 'usize') for v in values[2:])])
                if borrowed is not None:
                    self.op('loan.end', [borrowed])
                return None
            return super().expr(node)

    constants = dict(LIMIT=0xffff0000, INVALID=0xffffffff, SHORT=0xfffffffe, NEED=0xffffffd0,
                     MAXIMUM=(1 << 64) - 1)
    for name, tag in [('REQUEST', b'HBWAQ001'), ('RESPONSE', b'HBWAR001'), ('WORK', b'HBWAS001'),
                      ('PLAN_REQUEST', b'HBPLQ001'), ('PLAN_RESPONSE', b'HBPLR001'),
                      ('TYPED', b'HBPRR001'), ('CONFIG_RESULT', b'HRCFGM01'),
                      ('PARENT_REQUEST', b'HBPWQ001'), ('GROW', b'HGRWS002')]:
        constants[name] = int.from_bytes(tag, 'little')
    pseudo = (source / 'authoring/binary_write_adapter.pseudo').read_text()
    expanded = re.sub(r'\b(' + '|'.join(constants) + r')\b', lambda m: str(constants[m[0]]), pseudo)
    nodes = ast.parse(expanded).body
    assert all(isinstance(node, ast.FunctionDef) for node in nodes) and nodes[0].name == 'entry'
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([p.annotation.id for p in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = NativeBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append(dict(name=names[node.name], params=[builder.param(p) for p in builder.params],
                              returns=[builder.returns], effects=['read', 'write', 'trap'], entry='b0', blocks=builder.blocks))
    document = compact_authoring_cfg(dict(schema='hepta.hia.program.v8', module='binary_write_adapter', functions=functions))
    raw = render_assembly(document).encode()
    actual = assemble_program(raw).as_dict()
    assert render_assembly(actual).encode() == raw
    limits = json.loads((args.hepta / 'docs/HIA_SELFHOST_CORE_SUPPORT.json').read_bytes())['limits']
    ops = sum(len(block['ops']) for fn in actual['functions'] for block in fn['blocks'])
    blocks = sum(len(fn['blocks']) for fn in actual['functions'])
    assert len(actual['functions']) <= limits['functions'] == 128
    assert ops <= 8192 and blocks <= limits['blocks_total'] == 1536
    for fn in actual['functions']:
        assert len(fn['blocks']) <= 256
        assert max(len(block['params']) for block in fn['blocks']) <= 16
        assert len(set(re.findall(r'"(v[0-9]+)"', json.dumps(fn)))) <= limits['ssa_names_per_function'] == 2048
    sha = lambda value: hashlib.sha256(value).hexdigest()
    planner = (source / 'dependency/native/binary_call_plan.hepta').read_bytes()
    assert sha(planner) == 'fc8624cc760735a0fdaea46fb5c7434c09cc1fe96d8b218d510a3858fe3305bc'
    receipt = dict(schema='hepta.runtime.binary-write-adapter.author.v1', source_sha256=sha(raw),
                   source_bytes=len(raw), aliases=names, constants=constants, functions=len(actual['functions']),
                   instructions=ops, blocks=blocks, exact_planner_sha256=sha(planner),
                   parent_protocol='HBPWQ001', planner_source_changed=False, parent_fd_in_request=False,
                   native_compiled=False, native_executed=False, public_binary_write_registered=False,
                   host_audit_ssh_lifecycle_qualified=False, whole_runtime_replaced=False)
    output.mkdir(parents=True)
    (output / 'binary_write_adapter.hepta').write_bytes(raw)
    (output / 'binary_write_adapter_composition.json').write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
    (output / 'binary_write_adapter.pseudo').write_text(expanded)
    print(json.dumps(receipt, sort_keys=True))


if __name__ == '__main__':
    main()

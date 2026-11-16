"""Author a HIA packer for a mechanical native audit callable composition.

Binutils are used only to author the fixed effect adapter. Runtime policy is the
unchanged HIA controller, embedded together with its HIA-emitted sync boundary.
"""
from pathlib import Path
import argparse
import ast
import hashlib
import json
import re
import subprocess
import sys


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hepta', type=Path, required=True)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root, output = args.root.resolve(), args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    source = root / 'authoring/audit_controller_callable.S'
    commands = [
        ['/usr/bin/as', '--64', '-o', str(output / 'callable.o'), str(source)],
        ['/usr/bin/objcopy', '-O', 'binary', '--only-section=.text',
         str(output / 'callable.o'), str(output / 'template.bin')],
        ['/usr/bin/readelf', '--wide', '--relocs', '--symbols', str(output / 'callable.o')],
    ]
    records = []
    for index, command in enumerate(commands):
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=60, check=False,
                                env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC'})
        (output / (str(index) + '.stdout')).write_bytes(result.stdout)
        (output / (str(index) + '.stderr')).write_bytes(result.stderr)
        records.append(dict(command=command, exit_code=result.returncode,
                            stdout=pin(result.stdout), stderr=pin(result.stderr)))
        assert result.returncode == 0 and not result.stderr
    symbols = (output / '2.stdout').read_text()
    assert 'There are no relocations in this file.' in symbols
    assert len([line for line in symbols.splitlines() if ' UND ' in line]) == 1
    offsets = {}
    for name in ('entry', 'controller', 'sync', 'end'):
        match = re.findall(r'\d+:\s+([0-9a-f]+)\s+\d+\s+\S+\s+GLOBAL\s+DEFAULT\s+1\s+audit_callable_' + name + r'\s*$', symbols, re.M)
        assert len(match) == 1, (name, symbols)
        offsets[name] = int(match[0], 16)
    raw = (output / 'template.bin').read_bytes()
    assert offsets['entry'] == 0 and offsets['sync'] - offsets['controller'] == 160544
    assert len(raw) == offsets['end'] == offsets['sync'] + 1635
    stub = raw[:offsets['controller']]
    assert raw[len(stub):] == b'\0' * (160544 + 1635)
    (output / 'adapter.bin').write_bytes(stub)
    magic = int.from_bytes(b'HAPMPK01', 'little')
    start = f'''def audit_controller_callable(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=162211 or read64(s,0)!={magic} or read64(s,8)!=1 or read64(s,16)!=160544 or read64(s,24)!=1635:
        return 4294967295
    if length(o)<{len(raw)}:
        return 4294967294
'''
    chunks = []
    for at in range(0, len(stub), 96):
        name = 'emit_' + str(at)
        start += f'    {name}(o)\n'
        body = f'def {name}(o:mutbuf) -> u64:\n'
        body += ''.join(f'    store(o,{position},{byte})\n'
                        for position, byte in enumerate(stub[at:at + 96], at))
        chunks.append(body + '    return 0\n')
    start += f'''    at=0
    while at<160544:
        store(o,{offsets['controller']}+at,byte(s,32+at))
        at=at+1
    at=0
    while at<1635:
        store(o,{offsets['sync']}+at,byte(s,160576+at))
        at=at+1
    return {len(raw)}
'''
    functions = [start, *chunks, '''def read64(s:readbuf,at:u64) -> u64:
    return byte(s,at)|(byte(s,at+1)<<8)|(byte(s,at+2)<<16)|(byte(s,at+3)<<24)|(byte(s,at+4)<<32)|(byte(s,at+5)<<40)|(byte(s,at+6)<<48)|(byte(s,at+7)<<56)
''']
    pseudo = '\n'.join(functions)
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(args.hepta.resolve()))
    from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    nodes = ast.parse(pseudo).body
    names = {node.name: 'f' + str(index) for index, node in enumerate(nodes)}
    signatures = {node.name: ([p.annotation.id for p in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    rendered = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        rendered.append(dict(name=names[node.name], params=[builder.param(p) for p in builder.params],
                             returns=[builder.returns], effects=['read', 'write', 'trap'],
                             entry='b0', blocks=builder.blocks))
    program = compact_authoring_cfg(dict(schema='hepta.hia.program.v8',
                                         module='audit_controller_callable', functions=rendered))
    hia = render_assembly(program).encode()
    checked = assemble_program(hia).as_dict()
    assert all(len(f['blocks']) <= 256 for f in checked['functions'])
    (root / 'native/audit_controller_callable.hepta').write_bytes(hia)
    proof = dict(schema='hepta.audit-controller-callable.source.v1',
                 source=pin(source.read_bytes()), author=pin(Path(__file__).read_bytes()),
                 hia=pin(hia), adapter=pin(stub), adapter_hex=stub.hex(), offsets=offsets, complete_image_bytes=len(raw),
                 controller=dict(bytes=160544, sha256='1c2d4e44f4d2185ef06dc1de0566f21a33f92bee61b05fa7ebed6ee9841de90a'),
                 synchronization=dict(bytes=1635, sha256='b2a5f181d26382ab4c7d0759097b922eb4df1864636e0209b66db2e80f3c0ca9'),
                 functions=len(checked['functions']), relocations=0, unresolved_symbols=0,
                 abi='sysv-amd64 request256/actor512/context128; context owns mapped queue and borrows kernel64',
                 runtime_python_required=False, runtime_rust_required=False, queue_policy_in_adapter=False,
                 observer_optional=True, source_only=True, semantic_execution=False,
                 resource_exhaustion_qualified=False, public_handler_qualified=False, whole_runtime_replaced=False)
    (root / 'native/audit_controller_callable.composition.json').write_text(json.dumps(proof, indent=2, sort_keys=True) + '\n')
    (output / 'AUTHORING.json').write_text(json.dumps(dict(commands=records, source=proof), indent=2, sort_keys=True) + '\n')
    print(json.dumps(proof, sort_keys=True))


if __name__ == '__main__':
    main()

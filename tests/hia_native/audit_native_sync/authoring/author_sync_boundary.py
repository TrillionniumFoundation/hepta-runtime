"""Author a HIA emitter for the closed Linux synchronization instruction boundary.

GNU binutils are source authoring tools only. The emitted runtime boundary has no
undefined symbols, loader, libc dependency, queue policy, or embedded Rust owner.
"""
from pathlib import Path
import argparse
import ast
import hashlib
import json
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
    source = root / 'authoring/audit_sync_adapter.S'
    commands = ([ '/usr/bin/as', '--64', '-o', str(output / 'boundary.o'), str(source)],
                [ '/usr/bin/objcopy', '-O', 'binary', '--only-section=.text',
                  str(output / 'boundary.o'), str(output / 'boundary.bin')],
                [ '/usr/bin/readelf', '--relocs', '--symbols', str(output / 'boundary.o')])
    rows = []
    for index, command in enumerate(commands):
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=60, check=False,
            env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC'})
        (output / (str(index) + '.stdout')).write_bytes(result.stdout)
        (output / (str(index) + '.stderr')).write_bytes(result.stderr)
        rows.append(dict(command=command, exit_code=result.returncode,
                         stdout=pin(result.stdout), stderr=pin(result.stderr)))
        assert result.returncode == 0 and not result.stderr
    symbols = (output / '2.stdout').read_text()
    assert 'There are no relocations in this file.' in symbols
    assert symbols.count('audit_sync_entry') == 1
    assert len([line for line in symbols.splitlines() if ' UND ' in line]) == 1
    raw = (output / 'boundary.bin').read_bytes()
    assert 0 < len(raw) < 65536
    magic = int.from_bytes(b'HASYPK01', 'little')
    functions = [f'''def audit_sync_boundary(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=16 or read64(s,0)!={magic} or read64(s,8)!=1:
        return 4294967295
    if length(o)<{len(raw)}:
        return 4294967294
''']
    chunks = []
    for start in range(0, len(raw), 96):
        name = 'emit_' + str(start)
        functions[0] += f'    {name}(o)\n'
        body = f'def {name}(o:mutbuf) -> u64:\n'
        body += ''.join(f'    store(o,{offset},{byte})\n'
                        for offset, byte in enumerate(raw[start:start + 96], start))
        chunks.append(body + '    return 0\n')
    functions[0] += f'    return {len(raw)}\n'
    functions.extend(chunks)
    functions.append('''def read64(s:readbuf,at:u64) -> u64:
    return byte(s,at)|(byte(s,at+1)<<8)|(byte(s,at+2)<<16)|(byte(s,at+3)<<24)|(byte(s,at+4)<<32)|(byte(s,at+5)<<40)|(byte(s,at+6)<<48)|(byte(s,at+7)<<56)
''')
    pseudo = '\n'.join(functions)
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(args.hepta.resolve()))
    from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    nodes = ast.parse(pseudo).body
    names = {node.name: 'f' + str(index) for index, node in enumerate(nodes)}
    signatures = {node.name: ([p.annotation.id for p in node.args.args], node.returns.id)
                  for node in nodes}
    total = total_scalar_functions(nodes)
    rendered = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        rendered.append(dict(name=names[node.name], params=[builder.param(p) for p in builder.params],
            returns=[builder.returns], effects=['read', 'write', 'trap'], entry='b0', blocks=builder.blocks))
    program = compact_authoring_cfg(dict(schema='hepta.hia.program.v8',
                                         module='audit_sync_boundary', functions=rendered))
    hia = render_assembly(program).encode()
    checked = assemble_program(hia).as_dict()
    assert all(len(f['blocks']) <= 256 for f in checked['functions'])
    native = root / 'native'
    native.mkdir(exist_ok=True)
    (native / 'audit_sync_boundary.hepta').write_bytes(hia)
    proof = dict(schema='hepta.audit-sync-boundary.source.v1',
        compiler_commit='d3e2c90173cf733e42b299d0c4274df4b593a12f',
        source=pin(source.read_bytes()), author=pin(Path(__file__).read_bytes()),
        hia=pin(hia), emitted_instructions=pin(raw), entry_offset=0,
        functions=len(checked['functions']), unresolved_symbols=0, relocations=0,
        abi='sysv-amd64 three borrowed buffers; request128/output128/state64',
        effects=['gettid', 'clock_gettime(CLOCK_MONOTONIC)', 'futex wait/wake',
                 'atomic compare-exchange', 'atomic exchange', 'atomic sequence increment'],
        queue_policy_in_boundary=False, runtime_rust_required=False, runtime_python_required=False,
        source_only=True, semantic_execution=False, concurrent_native_lock_qualified=False,
        public_handler_qualified=False, whole_runtime_replaced=False)
    (native / 'audit_sync_boundary.composition.json').write_text(json.dumps(proof, sort_keys=True, indent=2) + '\n')
    (output / 'AUTHORING.json').write_text(json.dumps(dict(commands=rows, source=proof), sort_keys=True, indent=2) + '\n')
    print(json.dumps(proof, sort_keys=True))


if __name__ == '__main__':
    main()

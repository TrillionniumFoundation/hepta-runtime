#!/usr/bin/env python3
"""Assemble and HIA-pack the actual 14-owner extract development fixture."""
from pathlib import Path
import argparse
import ast
import copy
import hashlib
import json
import struct
import subprocess
import sys


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def author_packer(hepta, runtime, prefix, table):
    sys.path.insert(0, str(hepta))
    from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    text = (runtime / 'native/text_budget.hepta').read_bytes()
    assert sha(text) == '89df7b4320fdbd3525450e9446267ae3d54a5b62660d8904fe8f09be36a7fbf9'
    original = assemble_program(text).as_dict()
    assert len(prefix) % 8 == 0
    chunks = []
    for off in range(0, len(prefix), 2048):
        rows = [f'def literal_{len(chunks)}(o: mutbuf) -> u64:']
        for at in range(off, min(len(prefix), off + 2048), 8):
            rows.append(f'    put(o, {at}, {int.from_bytes(prefix[at:at + 8], "little")})')
        rows.append('    return 1')
        chunks.append('\n'.join(rows))
    entry = [
        'def entry(s: readbuf, o: mutbuf, w: mutbuf) -> u32:',
        '    if length(s) < 134:', '        return 4294967295',
        f'    if load(s, 0) != {int.from_bytes(b"HEXTPX01", "little")}:', '        return 4294967295',
        '    index = 0', '    total = 0', '    while index < 14:',
        '        size = load(s, 8 + index * 8)', '        if size == 0 or size > 1048576:',
        '            return 4294967295', '        total = total + size', '        index = index + 1',
        '    if total != length(s) - 120:', '        return 4294967295',
        f'    needed = {len(prefix)} + total', '    if length(o) < needed:', '        return 4294967294',
        *[f'    literal_{n}(o)' for n in range(len(chunks))],
        '    put(o, 96, needed)', '    put(o, 104, needed)',
        f'    copy_range(o, s, {table}, 8, 112)',
        f'    copy_range(o, s, {len(prefix)}, 120, total)', '    return needed',
    ]
    pseudo = '\n'.join(entry) + '\n\n' + '\n\n'.join(chunks) + '\n'
    nodes = ast.parse(pseudo).body
    names = {n.name: 'f' + str(i) for i, n in enumerate(nodes)}
    names.update(load='f' + str(len(nodes)), put='f' + str(len(nodes) + 1))
    signatures = {n.name: ([a.annotation.id for a in n.args.args], n.returns.id) for n in nodes}
    signatures.update(load=(['readbuf', 'u64'], 'u64'), put=(['mutbuf', 'u64', 'u64'], 'u64'))

    class PackerBuilder(Builder):
        def expr(self, node):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'copy_range':
                destination, source, at, start, size = [self.expr(a) for a in node.args]
                positions = [self.cast(v, 'usize') for v in (at, start, size)]
                self.op('buffer.copy_range', [destination, source, *positions])
                return None
            return super().expr(node)

    new = []
    for node in nodes:
        b = PackerBuilder(node, names, signatures, total_scalar_functions(nodes))
        b.statements(node.body)
        new.append(dict(name=names[node.name], params=[b.param(v) for v in b.params],
            returns=[b.returns], effects=['read', 'write', 'trap'], entry='b0', blocks=b.blocks))
    retained = []
    for alias, ident in [('load', 'f14'), ('put', 'f16')]:
        f = copy.deepcopy(next(f for f in original['functions'] if f['name'] == ident))
        assert not any(op['op'] == 'call' for block in f['blocks'] for op in block['ops'])
        f['name'] = names[alias]; retained.append(f)
    temp = dict(schema=original['schema'], module='extract_fixture_packer', functions=new + retained)
    new_names = {f['name'] for f in new}
    functions = [f for f in compact_authoring_cfg(temp)['functions'] if f['name'] in new_names] + retained
    doc = dict(schema=original['schema'], module='runtime_local_extract_fixture_packer', functions=functions)
    raw = render_assembly(doc).encode()
    assert assemble_program(raw).as_dict() == doc
    stats = dict(functions=len(functions), blocks=sum(len(f['blocks']) for f in functions),
        operations=sum(len(b['ops']) for f in functions for b in f['blocks']))
    assert stats['functions'] <= 128 and stats['blocks'] <= 1536 and stats['operations'] <= 8192, stats
    return raw, pseudo.encode(), stats


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--runtime', type=Path, required=True)
    p.add_argument('--hepta', type=Path, required=True)
    p.add_argument('--callable-source', type=Path, required=True)
    p.add_argument('--members-build', type=Path, required=True)
    p.add_argument('--native-build-root', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--prepare-only', action='store_true')
    a = p.parse_args()
    sys.dont_write_bytecode = True
    a.output.mkdir(parents=True, exist_ok=False)
    record = dict(schema='hepta.runtime.extract-fixture-development-build.v1', status='BUILDING',
        processes=[], runtime_python_required=False, runtime_libc_required=False,
        original_rust_executed=False, semantic_body_qualified=False, public_handler_qualified=False)
    def save(): (a.output / 'build.json').write_bytes(canonical(record))
    save()
    try:
        commands = [
            ['as', '--64', '-o', str(a.output/'fixture.o'), str(a.callable_source/'local_extract_lines_fixture.S')],
            ['ld', '-nostdlib', '-Ttext=0', '-e', '_start', '-o', str(a.output/'fixture-code.elf'), str(a.output/'fixture.o')],
            ['objcopy', '-O', 'binary', '--only-section=.text', str(a.output/'fixture-code.elf'), str(a.output/'fixture.bin')],
            ['readelf', '-r', str(a.output/'fixture-code.elf')], ['nm', '-n', str(a.output/'fixture-code.elf')],
        ]
        for i, command in enumerate(commands):
            child = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            row = dict(command=command, exit_code=child.returncode, deadline_seconds=30)
            for kind, data in [('stdout', child.stdout), ('stderr', child.stderr)]:
                name = f'assembly-{i}.{kind}'; (a.output/name).write_bytes(data)
                row[kind] = dict(path=name, bytes=len(data), sha256=sha(data))
            record['processes'].append(row); save()
            assert child.returncode == 0, (command, child.stderr)
        assert b'There are no relocations' in (a.output/'assembly-3.stdout').read_bytes()
        symbols = {line.split()[-1]: int(line.split()[0], 16) for line in (a.output/'assembly-4.stdout').read_text().splitlines() if len(line.split()) == 3}
        code = (a.output/'fixture.bin').read_bytes()
        assert symbols['_start'] == 0 and symbols['images'] == len(code)
        table = 176 + symbols['image_table']
        assert code[symbols['image_table']:] == bytes(112)
        old_prefix = (a.runtime/'tests/hia_native/local_text_body/prefix.bin').read_bytes()
        prefix = old_prefix[:176] + code
        assert prefix[96:112] == bytes(16)
        (a.output/'prefix.bin').write_bytes(prefix)
        packer, pseudo, stats = author_packer(a.hepta, a.runtime, prefix, table)
        (a.output/'extract_fixture_packer.hepta').write_bytes(packer)
        (a.output/'extract_fixture_packer.pseudo').write_bytes(pseudo)
        record.update(prefix_bytes=len(prefix), prefix_sha256=sha(prefix), table_offset=table,
            packer_sha256=sha(packer), packer_stats=stats, callable_proof=json.loads((a.callable_source/'callable.proof.json').read_bytes()))
        if a.prepare_only:
            record['status']='PREPARED'; save(); print(json.dumps(record)); return
        sys.path.insert(0, str(a.runtime/'scripts'))
        from hia_native_build import NativeBuild
        from hia_native_loader import NativeModule
        member_build = json.loads(a.members_build.read_bytes())
        assert member_build['status'] == 'PASS' and member_build['actual_compiles'] == 14
        images = []
        for row in member_build['members']:
            m = Path(row['manifest']); raw = m.read_bytes(); assert sha(raw) == row['manifest_sha256']
            info = json.loads(raw); image = (m.parent/info['image']).read_bytes()
            assert len(image) == row['image_bytes'] and sha(image) == row['image_sha256']
            assert sha(Path(row['source']).read_bytes()) == row['source_sha256']
            images.append(image)
        assert len(images) == 14
        builder = NativeBuild(a.hepta, a.native_build_root)
        manifest = builder.compile('extract-fixture-packer', a.output/'extract_fixture_packer.hepta', standalone=None, buffer_profile='history.v1')
        executable = bytearray(prefix); total = len(prefix) + sum(map(len, images))
        struct.pack_into('<2Q', executable, 96, total, total)
        struct.pack_into('<14Q', executable, table, *(len(x) for x in images))
        executable = bytes(executable) + b''.join(images)
        frame = b'HEXTPX01' + struct.pack('<14Q', *(len(x) for x in images)) + b''.join(images)
        with NativeModule(manifest, manifest_sha256=sha(manifest.read_bytes())) as owner:
            code, output, workspace = owner.invoke_raw(frame, output_capacity=total+4096,
                workspace_capacity=4096, output_fill=0xB3, workspace_fill=0xC7)
        for name, raw in [('pack.input.bin',frame),('pack.output.bin',output),('pack.workspace.bin',workspace)]:
            (a.output/name).write_bytes(raw)
        assert code == total and output == executable + b'\xB3'*4096 and workspace == b'\xC7'*4096
        elf=a.output/'local-extract-lines.elf';elf.write_bytes(executable);elf.chmod(0o500)
        record.update(status='PASS', executable=dict(path=elf.name,bytes=len(executable),sha256=sha(executable)),
            members=member_build['members'], actual_member_compiles=14, actual_packer_compiles=1,
            packer_manifest=str(manifest), packer_manifest_sha256=sha(manifest.read_bytes()), packer_return=code)
        save();print(json.dumps(record))
    except BaseException as error:
        record.update(status='FAIL',error=repr(error));save();raise


if __name__ == '__main__':
    main()

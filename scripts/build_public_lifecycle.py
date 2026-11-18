#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Build the selected graph and verify all four bounded HIA pack outputs."""
from pathlib import Path
import argparse
import json
import os
import shutil
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from hia_native_build import NativeBuild
from hia_native_loader import NativeModule
from public_lifecycle_registry import COMPILER, COMPILER_IMAGE, encoded, graph, regular, require, sha, source_pins


def assemble(root, folder, profile):
    folder.mkdir(mode=0o700)
    source = regular(root / profile['adapter_source'])
    marker = b'.include "public_lifecycle_metadata.S"\n'
    require(source.count(marker) == 1 and source.count(b'.include') == 1 and b'.incbin' not in source,
            'fixed adapter include graph changed')
    expanded = source.replace(marker, regular(root / profile['metadata_source']))
    require(sha(expanded) == profile['expanded_adapter_sha256'], 'expanded fixed adapter changed')
    target = folder / 'adapter.S'
    target.write_bytes(expanded)
    commands = (
        ('assembler', ['as', '--64', str(target), '-o', str(folder / 'adapter.o')]),
        ('relocations', ['readelf', '-r', str(folder / 'adapter.o')]),
        ('symbols', ['nm', '-n', str(folder / 'adapter.o')]),
        ('flat', ['objcopy', '-O', 'binary', '--only-section=.text', str(folder / 'adapter.o'), str(folder / 'adapter.bin')]),
    )
    records = []
    for name, command in commands:
        command[0] = shutil.which(command[0])
        require(command[0] is not None, 'required assembler tool unavailable')
        begin = time.monotonic()
        done = subprocess.run(command, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        (folder / (name + '.stdout')).write_bytes(done.stdout)
        (folder / (name + '.stderr')).write_bytes(done.stderr)
        row = dict(name=name, command=command, cwd=str(root), exit_code=done.returncode,
                   timeout_seconds=30, elapsed_seconds=time.monotonic() - begin,
                   tool_sha256=sha(Path(command[0]).resolve().read_bytes()),
                   stdout_bytes=len(done.stdout), stdout_sha256=sha(done.stdout),
                   stderr_bytes=len(done.stderr), stderr_sha256=sha(done.stderr))
        records.append(row)
        (folder / 'processes.json').write_bytes(encoded(records))
        require(done.returncode == 0 and not done.stderr, 'fixed assembly failed: ' + name)
    require(b'There are no relocations' in regular(folder / 'relocations.stdout'), 'unresolved fixed relocation')
    symbols = {}
    for line in regular(folder / 'symbols.stdout').decode().splitlines():
        words = line.split()
        if len(words) == 3 and words[1].lower() == 't':
            require(words[2] not in symbols, 'duplicate text symbol')
            symbols[words[2]] = int(words[0], 16)
    code = regular(folder / 'adapter.bin')
    require(symbols.get('_start') == 0 and symbols.get('images') == len(code), 'fixed entry or end changed')
    header = (b'\x7fELF\x02\x01\x01' + bytes(9)
              + struct.pack('<HHIQQQIHHHHHH',2,62,1,0x4000b0,64,0,0,64,56,2,0,0,0)
              + struct.pack('<IIQQQQQQ',1,5,0,0x400000,0x400000,0,0,4096)
              + struct.pack('<IIQQQQQQ',0x6474e551,6,0,0,0,0,0,16))
    prefix = header + code
    require(len(header) == 176 and len(prefix) == profile['prefix_bytes']
            and sha(prefix) == profile['prefix_sha256'], 'complete assembled prefix differs')
    seen = set()
    for row in profile['patches']:
        at = row['offset']
        require(type(at) is int and 176 <= at and at + 8 <= len(prefix)
                and prefix[at:at+8] == bytes(8) and row['kind'] in ('address','bytes')
                and not seen.intersection(range(at,at+8)), 'invalid fixed image slot')
        require(row['module'] == profile['roles'][row['role']], 'fixed slot alias changed')
        seen.update(range(at,at+8))
    require({r['module'] for r in profile['patches']} == set(profile['image_order']), 'unbound selected image')
    (folder / 'prefix.bin').write_bytes(prefix)
    return prefix


def build(root, hepta, destination):
    root, hepta = Path(root).resolve(strict=True), Path(hepta).resolve(strict=True)
    destination = Path(destination).resolve()
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    profile, pins = graph(root), source_pins(root)
    report = dict(schema='hepta.public-lifecycle.build.v1', status='RUNNING', sources=pins,
                  modules={}, semantic_compiles=0, packer_compiles=0, pack_invocations=0,
                  actual_service_processes=0, production_activated=False, whole_runtime_replaced=False)
    begin = time.monotonic()
    def save():
        report['elapsed_seconds'] = time.monotonic() - begin
        (destination / 'build.json').write_bytes(encoded(report))
    save()
    try:
        prefix = assemble(root, destination / 'adapter', profile)
        builder = NativeBuild(hepta, destination)
        builder.bootstrap()
        require(builder.identity['commit'] == COMPILER and builder.compiler_sha256 == COMPILER_IMAGE,
                'actual compiler identity changed')
        images = {}
        selected = [(role, profile['modules'][role], False) for role in profile['image_order']]
        selected += [('packer_' + str(row['part']), row, True) for row in profile['packers']]
        for role, row, is_packer in selected:
            path = builder.compile('public-lifecycle-' + role, root / row['source'],
                                   standalone=None, buffer_profile=row['buffer_profile'])
            raw = regular(path)
            meta = json.loads(raw)
            image = regular(path.parent / meta['image'])
            require(sha(image) == row['image_sha256'], 'fresh image differs: ' + role)
            if not is_packer:
                require(len(image) == row['image_bytes'], 'fresh image size differs')
                images[role] = image
                report['semantic_compiles'] += 1
            else:
                report['packer_compiles'] += 1
            report['modules'][role] = dict(path=str(path.relative_to(destination)), sha256=sha(raw))
        order = profile['image_order']
        sizes = [len(images[n]) for n in order]
        outputs, records = [], []
        for packer in profile['packers']:
            part, contract = packer['part'], packer['contract']
            require(sizes == contract['complete_image_sizes'], 'fixed size table changed')
            require(contract['input_magic'] == 'HRISEG03' and contract['input_header_bytes'] == 24 + 8*len(order),
                    'fixed pack input contract changed')
            pm = report['modules']['packer_' + str(part)]
            with NativeModule(destination / pm['path'], manifest_sha256=pm['sha256']) as module:
                for stage, (first, last) in enumerate(contract['ranges']):
                    frame = b'HRISEG03' + struct.pack('<QQ', part, stage)
                    frame += struct.pack('<'+'Q'*len(order), *sizes)
                    frame += b''.join(images[n] for n in order[first:last])
                    capacity = contract['output_bytes'][stage]
                    require(len(frame) == contract['input_bytes'][stage] and len(frame) <= 8388608
                            and capacity <= 8388608, 'original pack limit exceeded')
                    name = f'pack-p{part}-s{stage}'
                    (destination / (name + '.input')).write_bytes(frame)
                    code, output, workspace = module.invoke_raw(frame, output_capacity=capacity,
                        workspace_capacity=packer['workspace_bytes'], output_fill=0xa5, workspace_fill=0x5a)
                    row = dict(part=part, stage=stage, artifact_prefix=name, image_range=[first, last],
                        result_u64=code, input_bytes=len(frame), input_sha256=sha(frame),
                        output_bytes=len(output), output_sha256=sha(output), workspace_bytes=len(workspace),
                        workspace_sha256=sha(workspace))
                    require(row == profile['pack_stages'][len(records)], 'complete pack output/workspace differs')
                    for suffix, raw in (('output', output), ('workspace', workspace)):
                        (destination / (name + '.' + suffix)).write_bytes(raw)
                    (destination / (name + '.json')).write_bytes(encoded(row))
                    report['pack_invocations'] += 1
                    outputs.append(output)
                    records.append(row)
        size = len(prefix) + sum(sizes)
        expected = bytearray(prefix)
        struct.pack_into('<QQ', expected,96,size,size)
        positions, at = {}, len(prefix)
        for role in order:
            positions[role] = at
            at += len(images[role])
        for row in profile['patches']:
            value = 0x400000 + positions[row['module']] if row['kind'] == 'address' else len(images[row['module']])
            struct.pack_into('<Q',expected,row['offset'],value)
        result = b''.join(outputs)
        require(result == bytes(expected) + b''.join(images[n] for n in order), 'whole packed ELF differs')
        require((len(result),sha(result)) == (profile['executable_bytes'],profile['executable_sha256']),
                'selected executable identity changed')
        path = destination / 'public-lifecycle.elf'
        path.write_bytes(result)
        path.chmod(0o500)
        builder._recheck()
        require(source_pins(root) == pins, 'source changed during actual build')
        report.update(status='BUILT_NOT_RUNTIME_QUALIFIED', compiler_commit=COMPILER,
                      compiler_sha256=builder.compiler_sha256, executable=path.name,
                      executable_bytes=len(result), executable_sha256=sha(result),
                      pack_stages=records, full_cold_executed=False)
    except BaseException as error:
        report.update(status='FAIL', error=repr(error))
        raise
    finally:
        save()
    return destination / 'build.json'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hepta', required=True, type=Path)
    parser.add_argument('--build-root', required=True, type=Path)
    args = parser.parse_args()
    result = build(ROOT, args.hepta, args.build_root)
    print(json.dumps({'build':str(result),'images':114,'packer_compiles':2,'pack_invocations':4},sort_keys=True))

# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Compile five fixed HIA images and inspect both real filesystem Stamp graphs."""
from pathlib import Path
import argparse
import copy
import json
import os
import struct
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from audit_stamp_registry import (COMPILER, COMPILER_IMAGE, build_sources, encoded,
    graph_order, manifest_image, profile, regular, require, sha)
from build_result_storage import inspect_elf


def source_composition(root, hepta):
    root, hepta = Path(root), Path(hepta)
    sys.path.insert(0, str(hepta))
    from hepta.hia_agent_assembly import assemble_program
    fixed = profile(root);parsed = {};counts = {}
    canonical = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
    def functions(name):
        if name not in parsed:
            parsed[name] = {f['name']: f for f in assemble_program(regular(root / name)).as_dict()['functions']}
        return parsed[name]
    for stem in sorted(fixed['owners'].values()):
        source = 'native/' + stem + '.hepta'
        proof = json.loads(regular(root / ('native/' + stem + '_composition.json')))
        require(sha(regular(root / source)) == proof['source_sha256']
            and proof['original_source_sha256'] in {r['sha256'] for r in fixed['original_sources'].values()},
            'fixed Stamp owner or original source differs')
        actual = functions(source);count = 0
        for row in proof['imports']:
            require(sha(regular(root / row['source'])) == row['sha256'], 'Stamp import source differs')
            old = functions(row['source']);reverse = {new: before for before, new in row['relocation'].items()}
            require(len(reverse) == len(row['relocation']), 'duplicate Stamp imported target')
            for before, after in row['relocation'].items():
                require(sha(canonical(old[before])) == row['functions'][before], 'original imported Stamp IR differs')
                value = copy.deepcopy(actual[after]);value['name'] = before
                for block in value['blocks']:
                    for op in block['ops']:
                        if op['op'] == 'call':
                            require(op['attrs']['function'] in reverse, 'undeclared Stamp import dependency')
                            op['attrs']['function'] = reverse[op['attrs']['function']]
                require(value == old[before], 'complete Stamp imported relocation differs');count += 1
        counts[stem] = count
    return counts


def inspect_graph(raw, graph, layout, images):
    prefix = bytes.fromhex(layout['prefix_hex']);order = graph_order(graph, layout)
    require(len(prefix) == layout['prefix_bytes'] and sha(prefix) == layout['prefix_sha256'],
        'fixed boundary prefix differs')
    holes = {graph['members'][name]: hole for name, hole in layout['call_holes'].items()}
    members = inspect_elf(raw, prefix, images, order, holes)
    require((len(raw), sha(raw)) == (graph['executable_bytes'], graph['executable_sha256']),
        'complete final ELF differs from the frozen graph')
    return members


def pack_graph(root, build, name, graph, paths):
    layout_raw = regular(root / graph['layout']);layout = json.loads(layout_raw)
    require(sha(layout_raw) == graph['layout_sha256'], 'fixed layout changed')
    order = graph_order(graph, layout);images = {key: manifest_image(paths[key])[1] for key in order}
    frame = graph['magic'].encode() + b''.join(struct.pack('<Q', len(images[key])) for key in order)
    frame += b''.join(images[key] for key in order)
    directory = build / 'audit-stamp-graphs' / name;directory.mkdir(mode=0o700, parents=True)
    (directory / 'pack.input.bin').write_bytes(frame)
    executable = directory / ('audit-stamp-' + name + '.elf');packer = paths[graph['packer']]
    command = [sys.executable, '-I', '-B', str(root / 'scripts/audit_stamp_pack_child.py'),
        '--graph', name, '--manifest', str(packer), '--input', str(directory / 'pack.input.bin'),
        '--output', str(executable)]
    env = {key: value for key, value in os.environ.items() if not key.startswith('HIA_')}
    start = time.monotonic();timed = False;error = None;code = None
    try:
        done = subprocess.run(command, cwd=root, env=env, capture_output=True, timeout=30)
        stdout, stderr, code = done.stdout, done.stderr, done.returncode
    except subprocess.TimeoutExpired as caught:
        timed = True;stdout, stderr = caught.stdout or b'', caught.stderr or b''
    except OSError as caught:
        error = repr(caught);stdout, stderr = b'', b''
    receipt = {'command': command, 'cwd': str(root), 'exit_code': code, 'timed_out': timed,
        'start_error': error, 'timeout_seconds': 30, 'elapsed_seconds': time.monotonic() - start,
        'stdout_bytes': len(stdout), 'stdout_sha256': sha(stdout),
        'stderr_bytes': len(stderr), 'stderr_sha256': sha(stderr)}
    (directory / 'pack.stdout').write_bytes(stdout);(directory / 'pack.stderr').write_bytes(stderr)
    (directory / 'pack-process.json').write_bytes(encoded(receipt))
    require(code == 0 and not timed and error is None and not stderr, 'actual HIA packer process failed')
    observed = json.loads(stdout);raw = regular(executable)
    require(observed['input_sha256'] == sha(frame) and observed['output_sha256'] == sha(raw)
        and observed['source_unchanged'] is True and observed['forbidden_compiler_modules_loaded'] == [],
        'actual HIA packer input/output custody differs')
    members = inspect_graph(raw, graph, layout, images);executable.chmod(0o700)
    result = {'schema': 'hepta.audit-stamp.static-graph.v1', 'name': name,
        'executable': executable.name, 'executable_bytes': len(raw), 'executable_sha256': sha(raw),
        'members': members, 'layout_sha256': sha(layout_raw),
        'packer_manifest': str(packer.relative_to(build)), 'packer_manifest_sha256': sha(regular(packer)),
        'input_bytes': len(frame), 'input_sha256': sha(frame), 'actual_hia_packer_calls': 1,
        'runtime_rust_required': False, 'runtime_python_required': False, 'runtime_libc_required': False,
        'production_activated': False, 'public_request_dispatch_qualified': False}
    target = directory / 'manifest.json';target.write_bytes(encoded(result))
    return {'path': str(target.relative_to(build)), 'sha256': sha(regular(target))}


def build_audit(root, hepta, output):
    from hia_native_build import NativeBuild
    root = Path(root).resolve(strict=True);build = Path(output).resolve()
    target = build / 'audit-stamp-build.json';require(not target.exists(), 'audit build already exists')
    before = build_sources(root);fixed = profile(root)
    compiler = NativeBuild(Path(hepta).resolve(strict=True), build);compiler.bootstrap()
    composition = source_composition(root, compiler.hepta);paths = {};modules = {}
    for name, spec in fixed['modules'].items():
        source = regular(root / spec['source'])
        require((len(source), sha(source)) == (spec['source_bytes'], spec['source_sha256']), 'fixed HIA source changed')
        path = compiler.compile('audit-' + name.replace('_', '-'), root / spec['source'],
            standalone=spec['standalone'], buffer_profile=spec['buffer_profile'])
        metadata, image, digest = manifest_image(path)
        require(metadata['source_sha256'] == spec['source_sha256'] and sha(image) == spec['image_sha256'],
            'fresh HIA image differs from the frozen owner')
        paths[name] = path;modules[name] = {'path': str(path.relative_to(build)), 'sha256': digest,
            'source_sha256': spec['source_sha256'], 'image_sha256': sha(image), 'image_bytes': len(image)}
    graphs = {name: pack_graph(root, build, name, graph, paths) for name, graph in fixed['graphs'].items()}
    compiler._recheck();require(build_sources(root) == before, 'fixed audit inputs changed during build')
    result = {'schema': 'hepta.audit-stamp.native-build.v1', 'sources': before,
        'modules': modules, 'graphs': graphs, 'composition': composition,
        'compiler_commit': COMPILER, 'compiler_sha256': COMPILER_IMAGE,
        'actual_native_images': len(modules), 'actual_static_graphs': len(graphs),
        'actual_native_packer_calls': len(graphs), 'actual_original_executions': 0,
        'fresh_cold_qualified': False, 'whole_runtime_replaced': False, 'audit_storage_closed': False,
        'production_activated': False, 'public_request_dispatch_qualified': False}
    target.write_bytes(encoded(result));return target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('hepta', 'build-root'):
        parser.add_argument('--' + key, required=True, type=Path)
    args = parser.parse_args()
    target = build_audit(Path(__file__).resolve().parents[1], args.hepta, args.build_root)
    print(json.dumps({'build': str(target), 'modules': 5, 'static_graphs': 2, 'actual_original_executions': 0}))


if __name__ == '__main__':
    main()

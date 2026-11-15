# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Run one fixed, compiled storage packer with complete input/output custody."""
from pathlib import Path
import argparse
import json
import struct
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from hia_native_loader import NativeModule
from result_storage_registry import profile, regular, require, sha


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--graph', required=True)
    for name in ('manifest', 'input', 'output'):
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    fixed = profile(ROOT);graph = fixed['graphs'][args.graph]
    layout = json.loads(regular(ROOT / graph['layout']))
    order = (graph['members'] if args.graph == 'configuration' else
        [graph['members'][name] for name in layout['image_order']])
    manifest = regular(args.manifest);metadata = json.loads(manifest)
    packer = fixed['modules'][graph['packer']]
    require(metadata['source_sha256'] == packer['source_sha256']
        and metadata['image_sha256'] == packer['image_sha256'], 'fixed native packer differs')
    incoming = regular(args.input)
    require(incoming[:8] == graph['magic'].encode(), 'fixed packer frame magic differs')
    count = len(order);at = 8 + count * 8
    sizes = struct.unpack_from('<' + 'Q' * count, incoming, 8)
    reserved = graph.get('reserved_words', 0) * 8
    require(incoming[at:at + reserved] == bytes(reserved), 'fixed frame reserved words differ')
    at += reserved
    for name, size in zip(order, sizes, strict=True):
        require(size > 0 and sha(incoming[at:at + size]) == fixed['modules'][name]['image_sha256'],
            'embedded native image differs')
        at += size
    require(at == len(incoming), 'packer frame has trailing bytes')
    capacity = layout['prefix_bytes'] + sum(sizes)
    begin = time.monotonic_ns()
    with NativeModule(args.manifest, manifest_sha256=sha(manifest)) as module:
        result = module.invoke(incoming, output_capacity=capacity, workspace_capacity=4096)
    elapsed = time.monotonic_ns() - begin
    forbidden = sorted(name for name in sys.modules if name.startswith('hepta.') or name.startswith('generate_hia_'))
    require(not forbidden and regular(args.manifest) == manifest and regular(args.input) == incoming,
        'native packer source custody changed')
    require(len(result) == capacity, 'fixed native ELF length differs')
    with args.output.open('xb') as stream:
        stream.write(result)
    print(json.dumps({'status': 'returned', 'native_result_code': len(result), 'source_unchanged': True,
        'manifest_sha256': sha(manifest), 'input_sha256': sha(incoming), 'input_bytes': len(incoming),
        'output_sha256': sha(result), 'output_bytes': len(result), 'output_capacity': capacity,
        'workspace_capacity': 4096, 'elapsed_nanoseconds': elapsed,
        'forbidden_compiler_modules_loaded': forbidden}, sort_keys=True))


if __name__ == '__main__':
    main()

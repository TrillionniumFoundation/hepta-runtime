"""Build the internal record owner with fixed HIA crypto leaves and a test root.

This is a source-custody build driver. The resulting ELF contains no Python.
The hexadecimal root is a test fixture, not an exposed runtime tool/profile.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from hia_native_composition_build import ModuleSpec, build_composition


def build_record(hepta: Path, build_root: Path, *, source_root: Path = ROOT,
                 reference_root: Path | None = None) -> Path:
    reference_root = source_root if reference_root is None else reference_root
    proof = json.loads((source_root / 'native/operation_record_composition.json').read_bytes())
    paths = [source_root / 'tests/hia_native/record_hex_transport.hepta',
             source_root / 'native/operation_record.hepta', reference_root / 'native/operation_kdf.hepta',
             reference_root / 'native/binary_codec.hepta', reference_root / 'native/operation_aead.hepta']
    for path, row in zip(paths, proof['members'], strict=True):
        if hashlib.sha256(path.read_bytes()).hexdigest() != row['source_sha256']:
            raise ValueError('operation record composition source differs: ' + str(path))
    packer = reference_root / 'native/composition_packer.hepta'
    if hashlib.sha256(packer.read_bytes()).hexdigest() != proof['packer_source_sha256']:
        raise ValueError('operation record bridge source differs')
    members = [ModuleSpec('record-hex-fixture', paths[0], flags=1, call_mask=2, workspace_capacity=16 << 20),
               ModuleSpec('operation-record', paths[1], flags=1, call_mask=28,
                          output_capacity=2 << 20, workspace_capacity=3 << 20),
               ModuleSpec('operation-kdf', paths[2], output_capacity=32, workspace_capacity=2048),
               ModuleSpec('binary-codec', paths[3], output_capacity=32, workspace_capacity=1184),
               ModuleSpec('operation-aead', paths[4], output_capacity=1048640, workspace_capacity=512)]
    return build_composition(hepta, build_root, members, source_root=reference_root)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hepta', type=Path, default=os.environ.get('HIA_HEPTA_DIR'))
    parser.add_argument('--build-root', type=Path, default=os.environ.get('HIA_BUILD_ROOT'))
    parser.add_argument('--source-root', type=Path, default=ROOT)
    parser.add_argument('--reference-root', type=Path, default=os.environ.get('HIA_REFERENCE_RUNTIME'))
    args = parser.parse_args()
    if not args.hepta or not args.build_root:
        parser.error('explicit pinned Hepta and build root required')
    print(json.dumps({'manifest': str(build_record(args.hepta, args.build_root,
          source_root=args.source_root, reference_root=args.reference_root))}))

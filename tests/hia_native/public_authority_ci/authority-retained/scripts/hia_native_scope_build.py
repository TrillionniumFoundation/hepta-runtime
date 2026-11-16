"""Build the internal private scope with pinned HIA owners and trusted fixtures.

The test entropy child supplies deterministic synthetic bytes. It is not an
operating-system entropy provider or an installed MCP runtime profile.
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


def build_scope(hepta: Path, build_root: Path, *, source_root: Path = ROOT,
                reference_root: Path | None = None) -> Path:
    reference_root = source_root if reference_root is None else reference_root
    proof = json.loads((source_root / 'native/operation_scope_composition.json').read_bytes())
    paths = [source_root / 'tests/hia_native/scope_hex_transport.hepta',
             reference_root / 'native/operation_record.hepta', reference_root / 'native/operation_kdf.hepta',
             reference_root / 'native/binary_codec.hepta', reference_root / 'native/operation_aead.hepta',
             reference_root / 'native/operation_nonce.hepta', source_root / 'native/operation_scope.hepta',
             source_root / 'tests/hia_native/scope_entropy_fixture.hepta']
    for path, row in zip(paths, proof['members'], strict=True):
        if hashlib.sha256(path.read_bytes()).hexdigest() != row['source_sha256']:
            raise ValueError('scope composition source differs: ' + str(path))
    if hashlib.sha256((reference_root / 'native/composition_packer.hepta').read_bytes()).hexdigest() != proof['packer_source_sha256']:
        raise ValueError('scope composition bridge source differs')
    members = [ModuleSpec('scope-hex-fixture', paths[0], flags=1, call_mask=192, workspace_capacity=16 << 20),
               ModuleSpec('operation-record', paths[1], flags=1, call_mask=28,
                          output_capacity=2 << 20, workspace_capacity=3 << 20),
               ModuleSpec('operation-kdf', paths[2], output_capacity=128, workspace_capacity=2048),
               ModuleSpec('binary-codec', paths[3], output_capacity=32, workspace_capacity=1184),
               ModuleSpec('operation-aead', paths[4], output_capacity=1048640, workspace_capacity=512),
               ModuleSpec('operation-nonce', paths[5], input_capacity=164, output_capacity=64, workspace_capacity=1576960),
               ModuleSpec('operation-scope', paths[6], flags=1, call_mask=166,
                          output_capacity=2 << 20, workspace_capacity=3 << 20),
               ModuleSpec('scope-entropy-fixture', paths[7], input_capacity=48, output_capacity=128, workspace_capacity=128)]
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
    print(json.dumps({'manifest': str(build_scope(args.hepta, args.build_root,
          source_root=args.source_root, reference_root=args.reference_root))}))

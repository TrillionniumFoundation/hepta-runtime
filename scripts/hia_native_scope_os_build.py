"""Build the fixed internal scope composition with real Linux entropy effects."""
from pathlib import Path
import argparse
import json
import os
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from hia_native_composition_build import ModuleSpec, build_composition


def build_scope_os(hepta: Path, build_root: Path, *, source_root: Path = ROOT) -> Path:
    specs = [
        ModuleSpec('scope-os-hex-fixture', source_root / 'tests/hia_native/scope_os_hex_transport.hepta',
                   flags=1, call_mask=64, workspace_capacity=16 << 20),
        ModuleSpec('operation-record', source_root / 'native/operation_record.hepta', flags=1, call_mask=28,
                   output_capacity=2 << 20, workspace_capacity=3 << 20),
        ModuleSpec('operation-kdf', source_root / 'native/operation_kdf.hepta', output_capacity=128,
                   workspace_capacity=2048),
        ModuleSpec('binary-codec', source_root / 'native/binary_codec.hepta', output_capacity=32,
                   workspace_capacity=1184),
        ModuleSpec('operation-aead', source_root / 'native/operation_aead.hepta', output_capacity=1048640,
                   workspace_capacity=512),
        ModuleSpec('operation-nonce', source_root / 'native/operation_nonce.hepta', input_capacity=164,
                   output_capacity=64, workspace_capacity=1576960),
        ModuleSpec('operation-scope', source_root / 'native/operation_scope.hepta', flags=1, call_mask=166,
                   output_capacity=2 << 20, workspace_capacity=3 << 20),
        ModuleSpec('system-entropy', source_root / 'native/entropy_policy.hepta', flags=4,
                   input_capacity=24, output_capacity=128, workspace_capacity=1024),
    ]
    return build_composition(hepta, build_root, specs, source_root=source_root)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hepta', type=Path, default=os.environ.get('HIA_HEPTA_DIR'))
    parser.add_argument('--build-root', type=Path, default=os.environ.get('HIA_BUILD_ROOT'))
    parser.add_argument('--source-root', type=Path, default=ROOT)
    args = parser.parse_args()
    if not args.hepta or not args.build_root:
        parser.error('explicit pinned Hepta and build root required')
    print(json.dumps({'manifest': str(build_scope_os(args.hepta, args.build_root, source_root=args.source_root))}))

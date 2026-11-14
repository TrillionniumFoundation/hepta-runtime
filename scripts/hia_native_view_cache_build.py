"""Build a test-only persistent native cache composition with no OS effects."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import sys

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = Path(os.environ.get('HIA_REFERENCE_RUNTIME', ROOT))
sys.path.insert(0, str(REFERENCE / 'scripts'))
from hia_native_composition_build import ModuleSpec, build_composition


def build_cache(hepta: Path, build_root: Path, *, source_root: Path = ROOT,
                reference_root: Path = REFERENCE) -> Path:
    proof = json.loads((source_root / 'native/view_cache_composition.json').read_bytes())
    cache = source_root / 'native/view_cache.hepta'
    transport = source_root / 'tests/hia_native/view_cache_hex_transport.hepta'
    for path, expected in [(cache, proof['source_sha256']),
                           (transport, proof['transport_source_sha256']),
                           (reference_root / 'native/composition_packer.hepta', proof['packer_source_sha256'])]:
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError('view cache composition source differs: ' + str(path))
    members = [ModuleSpec('view-cache-hex-fixture', transport, flags=1, call_mask=2,
                          workspace_capacity=16 << 20),
               ModuleSpec('view-cache', cache, output_capacity=(1 << 20) + 32,
                          workspace_capacity=8 << 20)]
    return build_composition(hepta, build_root, members, source_root=reference_root)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hepta', type=Path, default=os.environ.get('HIA_HEPTA_DIR'))
    parser.add_argument('--build-root', type=Path, default=os.environ.get('HIA_BUILD_ROOT'))
    parser.add_argument('--source-root', type=Path, default=ROOT)
    parser.add_argument('--reference-root', type=Path, default=REFERENCE)
    args = parser.parse_args()
    if not args.hepta or not args.build_root:
        parser.error('explicit pinned Hepta and build root required')
    print(json.dumps({'manifest': str(build_cache(args.hepta, args.build_root,
          source_root=args.source_root, reference_root=args.reference_root))}))

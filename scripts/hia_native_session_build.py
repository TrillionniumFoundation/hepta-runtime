"""Build the native session state and its separate persistent transport fixture."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = Path(os.environ.get('HIA_REFERENCE_RUNTIME', ROOT))
sys.path[:0] = [str(ROOT / 'scripts'), str(REFERENCE / 'scripts')]
from hia_native_build import NativeBuild, json_bytes, write_new
from hia_native_composition_build import ModuleSpec, build_composition
from hia_native_loader import NativeModule

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def build_session(hepta: Path, build_root: Path, *, source_root: Path = ROOT,
                  reference_root: Path = REFERENCE) -> Path:
    build_root = build_root.resolve()
    source_root = source_root.resolve(strict=True)
    reference_root = reference_root.resolve(strict=True)
    source = source_root / 'native/session_workdir.hepta'
    proof_path = source_root / 'native/session_workdir_composition.json'
    source_hash, proof_hash = sha(source), sha(proof_path)
    proof = json.loads(proof_path.read_bytes())
    if proof['source_sha256'] != source_hash:
        raise ValueError('session HIA source differs from its source proof')
    builder = NativeBuild(hepta, build_root)
    module = builder.compile('session-workdir-' + source_hash[:24], source,
                             standalone=None, buffer_profile='history.v1')
    fixture = build_composition(hepta, build_root, [
        ModuleSpec('session-hex-fixture', reference_root / 'tests/hia_native/view_cache_hex_transport.hepta',
                   flags=1, call_mask=2, workspace_capacity=16 << 20),
        ModuleSpec('session-workdir', source, workspace_capacity=(16 << 20) + 64),
    ], source_root=reference_root)
    metadata = json.loads(module.read_bytes())
    packed = json.loads(fixture.read_bytes())
    if packed['members'][1]['image_sha256'] != metadata['image_sha256']:
        raise ValueError('session fixture and wide native image differ')
    with NativeModule(module, manifest_sha256=sha(module)):
        pass
    data = {'schema': 'hepta.runtime.session-workdir-bundle.v1',
        'source_sha256': source_hash, 'proof_sha256': proof_hash,
        'module': str(module.relative_to(build_root)), 'module_sha256': sha(module),
        'fixture': str(fixture.relative_to(build_root)), 'fixture_sha256': sha(fixture),
        'image_sha256': metadata['image_sha256'], 'compiler_commit': metadata['compiler_commit'],
        'compiler_sha256': metadata['compiler_sha256'],
        'full_raw_path_bytes': 8 << 20, 'workspace_bytes': (16 << 20) + 64,
        'fixture_is_complete_wide_domain': False,
        'whole_runtime_replaced': False, 'production_activated': False}
    raw = json_bytes(data)
    folder = build_root / 'session-workdir' / hashlib.sha256(raw).hexdigest()
    path = folder / 'bundle.json'
    if path.exists():
        if path.read_bytes() != raw:
            raise ValueError('cached session bundle changed')
    else:
        folder.mkdir(parents=True, mode=0o700)
        write_new(path, raw)
    if sha(source) != source_hash or sha(proof_path) != proof_hash:
        raise ValueError('session source changed during compilation')
    return path

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hepta', type=Path, required=True)
    parser.add_argument('--build-root', type=Path, required=True)
    parser.add_argument('--source-root', type=Path, default=ROOT)
    parser.add_argument('--reference-root', type=Path, default=REFERENCE)
    args = parser.parse_args()
    print(json.dumps({'bundle': str(build_session(args.hepta, args.build_root,
        source_root=args.source_root, reference_root=args.reference_root))}, sort_keys=True))

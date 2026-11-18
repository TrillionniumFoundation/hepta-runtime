"""Build native history state and its separate bounded static transport fixture."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = Path(os.environ.get("HIA_REFERENCE_RUNTIME", ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
from hia_native_build import NativeBuild, json_bytes, write_new
from hia_native_loader import NativeModule
sys.path.append(str(REFERENCE / "scripts"))
from hia_native_composition_build import ModuleSpec, build_composition


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_history(hepta: Path, build_root: Path, *, source_root: Path = ROOT,
                  reference_root: Path = REFERENCE) -> Path:
    build_root = build_root.resolve()
    source_root = source_root.resolve(strict=True)
    reference_root = reference_root.resolve(strict=True)
    source = source_root / "native/history.hepta"
    proof = source_root / "native/history_composition.json"
    identity = sha(source)
    if json.loads(proof.read_bytes())["source_sha256"] != identity:
        raise ValueError("history HIA source differs from its composition proof")
    builder = NativeBuild(hepta, build_root)
    manifest = builder.compile("history-" + identity[:24], source,
                               standalone=None, buffer_profile="history.v1")
    transport = reference_root / "tests/hia_native/view_cache_hex_transport.hepta"
    fixture = build_composition(hepta, build_root, [
        ModuleSpec("history-hex-fixture", transport, flags=1, call_mask=2,
                   workspace_capacity=16 << 20),
        ModuleSpec("history", source, output_capacity=(1 << 20) + 32,
                   workspace_capacity=8 << 20),
    ], source_root=reference_root)
    module = json.loads(manifest.read_bytes())
    packed = json.loads(fixture.read_bytes())
    if packed["members"][1]["image_sha256"] != module["image_sha256"]:
        raise ValueError("history wide image differs from its static fixture image")
    with NativeModule(manifest, manifest_sha256=sha(manifest)):
        pass
    bundle = {"schema": "hepta.runtime.history-bundle.v1",
              "source_sha256": identity, "proof_sha256": sha(proof),
              "module": str(manifest.relative_to(build_root)), "module_sha256": sha(manifest),
              "fixture": str(fixture.relative_to(build_root)), "fixture_sha256": sha(fixture),
              "compiler_commit": module["compiler_commit"],
              "compiler_sha256": module["compiler_sha256"], "image_sha256": module["image_sha256"],
              "wide_profile": "history.v1", "wide_capacities": [128 << 20, 128 << 20, 256 << 20],
              "fixture_is_complete_wide_domain": False,
              "production_activated": False, "whole_runtime_replaced": False}
    key = hashlib.sha256(json_bytes(bundle)).hexdigest()
    destination = build_root / "history" / key
    path = destination / "bundle.json"
    if path.exists():
        if path.read_bytes() != json_bytes(bundle):
            raise ValueError("cached history bundle changed")
    else:
        destination.mkdir(parents=True, mode=0o700)
        write_new(path, json_bytes(bundle))
    if sha(source) != identity or sha(proof) != bundle["proof_sha256"]:
        raise ValueError("history source/proof changed during build")
    return path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta", type=Path, required=True)
    parser.add_argument("--build-root", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, default=ROOT)
    parser.add_argument("--reference-root", type=Path, default=REFERENCE)
    args = parser.parse_args()
    print(json.dumps({"bundle": str(build_history(args.hepta, args.build_root,
          source_root=args.source_root, reference_root=args.reference_root))}, sort_keys=True))

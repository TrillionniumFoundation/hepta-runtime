"""Build the private HIA scope/lease integration with unchanged context/cache owners.

The root is a qualification-only hexadecimal transport. Lifecycle decisions,
clone lifetime, context calls and cache calls execute inside the emitted ELF.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from hia_native_composition_build import ModuleSpec, build_composition
from hia_native_build import HEPTA_COMMIT


def members(root: Path) -> list[ModuleSpec]:
    return [
        ModuleSpec("request-scope-fixture", root / "tests/hia_native/request_scope_fixture.hepta",
                   flags=1, call_mask=62),
        ModuleSpec("request-scope-a", root / "native/request_scope_lifecycle.hepta",
                   flags=1, call_mask=40),
        ModuleSpec("request-scope-b", root / "native/request_scope_lifecycle.hepta",
                   flags=1, call_mask=48),
        ModuleSpec("request-context-a", root / "native/request_context.hepta"),
        ModuleSpec("request-context-b", root / "native/request_context.hepta"),
        ModuleSpec("shared-cache-lease", root / "native/request_cache_lease.hepta",
                   flags=1, call_mask=64),
        ModuleSpec("shared-view-cache", root / "native/view_cache.hepta"),
    ]


def source_check(root: Path) -> dict:
    proof = json.loads((root / "native/request_scope_lifecycle_composition.json").read_bytes())
    if (proof.get("schema") != "hepta.runtime.request-scope-lifecycle-composition.v1"
            or proof.get("compiler_commit") != HEPTA_COMMIT):
        raise ValueError("request lifetime composition identity differs")
    expected = {
        "native/request_scope_lifecycle.hepta", "native/request_cache_lease.hepta",
        "tests/hia_native/request_scope_fixture.hepta",
    }
    if {row.get("path") for row in proof.get("sources", [])} != expected:
        raise ValueError("request lifetime owner source inventory differs")
    for row in proof["sources"]:
        raw = (root / row["path"]).read_bytes()
        if hashlib.sha256(raw).hexdigest() != row["sha256"] or len(raw) != row["bytes"]:
            raise ValueError("request lifetime source changed: " + row["path"])
        for imported in row["imports"]:
            if hashlib.sha256((root / imported["path"]).read_bytes()).hexdigest() != imported["sha256"]:
                raise ValueError("request lifetime imported helper changed")
    required = {"native/request_context.hepta", "native/view_cache.hepta", "native/composition_packer.hepta"}
    if set(proof.get("dependencies", {})) != required:
        raise ValueError("request lifetime child source inventory differs")
    for relative, expected_hash in {**proof["dependencies"], **proof["original_sources"]}.items():
        if hashlib.sha256((root / relative).read_bytes()).hexdigest() != expected_hash:
            raise ValueError("request lifetime dependency changed: " + relative)
    return proof


def build_request_scope(hepta: Path, build_root: Path, *, source_root: Path = ROOT) -> Path:
    before = source_check(source_root)
    manifest = build_composition(hepta, build_root, members(source_root), source_root=source_root)
    if source_check(source_root) != before:
        raise ValueError("request lifetime sources changed during compilation")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta", type=Path, default=os.environ.get("HIA_HEPTA_DIR"))
    parser.add_argument("--build-root", type=Path, default=os.environ.get("HIA_BUILD_ROOT"))
    parser.add_argument("--source-root", type=Path, default=ROOT)
    args = parser.parse_args()
    if not args.hepta or not args.build_root:
        parser.error("explicit pinned Hepta and build root required")
    manifest = build_request_scope(args.hepta, args.build_root, source_root=args.source_root)
    print(json.dumps({"manifest": str(manifest)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

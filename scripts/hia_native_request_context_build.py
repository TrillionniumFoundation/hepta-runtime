"""Build the request-context qualification ELF from fixed HIA images.

The existing generic hexadecimal fixture drives one private context image.
It is a test transport, not a public scheduler or an MCP context-selection API.
The emitted process has no Python, Rust or dynamic-loader dependency.
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


def members(source_root: Path) -> list[ModuleSpec]:
    return [
        ModuleSpec("request-context-hex-fixture",
                   source_root / "tests/hia_native/view_cache_hex_transport.hepta",
                   flags=1, call_mask=2, workspace_capacity=16 << 20),
        ModuleSpec("request-context", source_root / "native/request_context.hepta",
                   workspace_capacity=32 << 20),
    ]


def build_request_context(hepta: Path, build_root: Path, *,
                          source_root: Path = ROOT) -> Path:
    proof = json.loads((source_root / "native/request_context_transport.json").read_bytes())
    if proof.get("schema") != "hepta.runtime.request-context-transport-profile.v1":
        raise ValueError("unknown request context composition")
    expected_paths = {
        "native/request_context.hepta",
        "native/composition_packer.hepta",
        "tests/hia_native/view_cache_hex_transport.hepta",
    }
    pins = proof.get("sources", {})
    if set(pins) != expected_paths:
        raise ValueError("request context composition source inventory differs")
    for name, expected in pins.items():
        raw = (source_root / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError("request context composition source differs: " + name)
    return build_composition(hepta, build_root, members(source_root), source_root=source_root)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta", type=Path, default=os.environ.get("HIA_HEPTA_DIR"))
    parser.add_argument("--build-root", type=Path, default=os.environ.get("HIA_BUILD_ROOT"))
    parser.add_argument("--source-root", type=Path, default=ROOT)
    args = parser.parse_args()
    if not args.hepta or not args.build_root:
        parser.error("explicit pinned Hepta and build root required")
    path = build_request_context(args.hepta, args.build_root, source_root=args.source_root)
    print(json.dumps({"manifest": str(path)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

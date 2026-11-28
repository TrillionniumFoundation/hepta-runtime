#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Invoke only the compiled fixed HIA packer; no compiler or semantic fallback."""
from pathlib import Path
import argparse
import hashlib
import json
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from hia_native_loader import NativeModule
from public_registry_registry import profile

sha = lambda raw: hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    graph = profile(ROOT)
    manifest = args.manifest.resolve(strict=True)
    before = manifest.read_bytes()
    raw = args.input.read_bytes()
    assert len(raw) == graph["frame_bytes"] and sha(raw) == graph["frame_sha256"]
    meta = json.loads(before)
    assert meta["source_sha256"] == graph["packer"]["source_sha256"]
    assert meta["image_sha256"] == graph["packer"]["image_sha256"]
    begin = time.monotonic_ns()
    with NativeModule(manifest, manifest_sha256=sha(before)) as module:
        result = module.invoke(raw, output_capacity=graph["elf_bytes"], workspace_capacity=4096)
    elapsed = time.monotonic_ns() - begin
    forbidden = sorted(name for name in sys.modules if name.startswith("hepta.") or name.startswith("generate_hia_"))
    unchanged = args.input.read_bytes() == raw and manifest.read_bytes() == before
    assert unchanged and not forbidden and len(result) == graph["elf_bytes"] and sha(result) == graph["elf_sha256"]
    with args.output.open("xb") as stream:
        stream.write(result)
    print(json.dumps({"status": "returned", "native_result_code": len(result), "source_unchanged": unchanged,
        "manifest_sha256": sha(before), "input_sha256": sha(raw), "input_bytes": len(raw),
        "output_sha256": sha(result), "output_bytes": len(result), "output_capacity": graph["elf_bytes"],
        "workspace_capacity": 4096, "elapsed_nanoseconds": elapsed,
        "forbidden_compiler_modules_loaded": forbidden}, sort_keys=True))


if __name__ == "__main__":
    main()

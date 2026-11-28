#!/usr/bin/env python3
"""Compile the rebuilt Batch adapters and their unchanged typed baseline."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import sys
import time

GENERATION = "bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0"


def pin(path):
    raw = path.read_bytes()
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta", type=Path, required=True)
    parser.add_argument("--bootstrap", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    output = args.output.absolute()
    assert not output.exists()
    assert os.environ.get("GITHUB_ACTIONS") == "true" or args.bootstrap is not None
    output.mkdir(parents=True)
    if args.bootstrap is not None:
        bootstrap = args.bootstrap.resolve(strict=True)
        target = output / "bootstrap"
        target.mkdir()
        metadata = json.loads((bootstrap / "bootstrap.json").read_bytes())
        assert metadata["generation_sha256"] == GENERATION
        for name in ("bootstrap.json", "B1.image.bin", "B2.image.bin", "B3.image.bin"):
            path = bootstrap / name
            assert path.is_file() and not path.is_symlink()
            if name.endswith("image.bin"):
                assert pin(path)["sha256"] == GENERATION
            shutil.copyfile(path, target / name)
            assert pin(path) == pin(target / name)
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(root / "runtime_support/scripts"))
    from hia_native_build import NativeBuild
    builder = NativeBuild(args.hepta, output)
    before = {}
    modules = {}
    started = time.monotonic()
    for name, source in (
        ("value", "retained/serde_json_span.hepta"),
        ("batch_params_original", "retained/batch_edit_params.hepta"),
        ("batch_params", "native/batch_params.hepta"),
        ("batch_gateway", "native/batch_gateway.hepta"),
        ("batch_call", "native/batch_call.hepta"),
    ):
        before[source] = pin(root / source)
        manifest = builder.compile(name, root / source, standalone=None,
                                   buffer_profile="history.v1")
        metadata = json.loads(manifest.read_bytes())
        assert metadata["source_sha256"] == before[source]["sha256"]
        image = manifest.parent / metadata["image"]
        assert pin(image)["sha256"] == metadata["image_sha256"]
        modules[name] = {"manifest": str(manifest.relative_to(output)),
            "manifest_pin": pin(manifest), "source": source, "source_pin": before[source],
            "image_pin": pin(image)}
    assert all(pin(root / name) == value for name, value in before.items())
    result = {"schema": "hepta.runtime.rebuilt-batch-adapter-build.v1", "status": "PASS",
        "modules": modules, "elapsed_seconds": time.monotonic() - started,
        "source_root": str(root), "output_root": str(output),
        "copied_qualified_bootstrap": args.bootstrap is not None,
        "fresh_native_compilations": len(modules), "semantic_qualification": False,
        "fresh_current_original_compared": False, "public_batch_qualified": False,
        "whole_runtime_replaced": False}
    (output / "BUILD.json").write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()

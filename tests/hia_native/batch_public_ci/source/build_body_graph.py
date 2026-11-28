#!/usr/bin/env python3
"""Compile exact HIA body members and assemble the new callable boundary."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent
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
    out = args.output.absolute()
    out.mkdir(parents=True, exist_ok=False)
    if args.bootstrap is None:
        assert os.environ.get("GITHUB_ACTIONS") == "true"
    else:
        original = args.bootstrap.resolve(strict=True)
        (out / "bootstrap").mkdir()
        doc = json.loads((original / "bootstrap.json").read_bytes())
        assert doc["generation_sha256"] == GENERATION
        for name in ("bootstrap.json", "B1.image.bin", "B2.image.bin", "B3.image.bin"):
            path = original / name
            assert path.is_file() and not path.is_symlink()
            if name.endswith(".image.bin"):
                assert pin(path)["sha256"] == GENERATION
            shutil.copyfile(path, out / "bootstrap" / name)
            assert pin(path) == pin(out / "bootstrap" / name)
    started = time.monotonic()
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(ROOT / "runtime_support/scripts"))
    from hia_native_build import NativeBuild
    builder = NativeBuild(args.hepta, out)
    inputs = json.loads((ROOT / "body-inputs.json").read_bytes())
    sources = {"body-inputs.json": pin(ROOT / "body-inputs.json"), "build_body_graph.py": pin(Path(__file__)),
        "native_boundary/local_batch_body_callable.S": pin(ROOT / "native_boundary/local_batch_body_callable.S"),
        "native_boundary/callable-author-proof.json": pin(ROOT / "native_boundary/callable-author-proof.json")}
    modules = {}
    specs = [(name, f"body_native/{name}.hepta", "batch-write.v1" if index in (0, 13) else "batch-plan.v1")
             for index, name in enumerate(inputs["order"])]
    specs.extend([("batch_plan_input", "retained/batch_plan_input.hepta", "history.v1"),
                  ("batch_body_adapter", "native/batch_body_adapter.hepta", "history.v1")])
    for name, relative, profile in specs:
        path = ROOT / relative
        sources[relative] = pin(path)
        if relative in inputs["files"]:
            assert all(sources[relative][key] == inputs["files"][relative][key] for key in ("bytes", "sha256"))
        manifest = builder.compile(name, path, standalone=None, buffer_profile=profile)
        metadata = json.loads(manifest.read_bytes())
        assert metadata["source_sha256"] == sources[relative]["sha256"]
        modules[name] = {"source": relative, "source_pin": sources[relative],
            "manifest": str(manifest.relative_to(out)), "manifest_pin": pin(manifest),
            "image_pin": pin(manifest.parent / metadata["image"]), "profile": profile}
    boundary = out / "boundary"
    boundary.mkdir()
    processes = []

    def run(name, argv):
        before = time.monotonic()
        result = subprocess.run(argv, cwd=boundary, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        (boundary / (name + ".stdout")).write_bytes(result.stdout)
        (boundary / (name + ".stderr")).write_bytes(result.stderr)
        row = {"name": name, "argv": argv, "cwd": str(boundary), "returncode": result.returncode,
            "timeout_seconds": 60, "elapsed_seconds": time.monotonic() - before,
            "stdout": pin(boundary / (name + ".stdout")), "stderr": pin(boundary / (name + ".stderr"))}
        processes.append(row)
        (boundary / "processes.json").write_text(json.dumps(processes, sort_keys=True, indent=2) + "\n")
        assert result.returncode == 0, (name, result.stderr.decode(errors="replace"))
        return result.stdout

    source = str(ROOT / "native_boundary/local_batch_body_callable.S")
    run("assemble", ["as", "--64", "-o", "callable.o", source])
    run("link", ["ld", "-shared", "-Bsymbolic", "-nostdlib", "-z", "noexecstack", "-o", "callable.so", "callable.o"])
    relocations = run("relocations", ["readelf", "-rW", "callable.so"])
    assert b"There are no relocations in this file." in relocations
    symbols = run("symbols", ["nm", "-D", "--defined-only", "callable.so"])
    names = {}
    for line in symbols.decode().splitlines():
        address, kind, name = line.split()
        assert kind == "T"
        names[name] = int(address, 16)
    assert set(names) == {"local_batch_body_run", "local_batch_body_resume", "local_batch_body_cancel_wait", "local_batch_body_release"}
    run("image", ["objcopy", "-O", "binary", "-j", ".text", "callable.so", "callable.image.bin"])
    assert sources == {name: pin(ROOT / name) for name in sources}
    result = {"schema": "hepta.runtime.rebuilt-batch-body-build.v1", "status": "PASS",
        "source_root": str(ROOT), "build_root": str(out), "source_inputs": {"files": sources},
        "order": inputs["order"], "modules": modules, "fresh_native_compilations": len(modules),
        "boundary": {"shared_object": "boundary/callable.so", "shared_object_pin": pin(boundary / "callable.so"),
            "image": "boundary/callable.image.bin", "image_pin": pin(boundary / "callable.image.bin"),
            "symbols": names, "processes": processes, "external_relocations": 0},
        "elapsed_seconds": time.monotonic() - started, "semantic_qualification": False,
        "fresh_current_original_compared": False, "public_batch_qualified": False,
        "full_async_cancellation_qualified": False, "whole_runtime_replaced": False}
    (out / "BUILD.json").write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print(json.dumps({key: result[key] for key in ("status", "fresh_native_compilations", "elapsed_seconds", "boundary")}, sort_keys=True))


if __name__ == "__main__":
    main()

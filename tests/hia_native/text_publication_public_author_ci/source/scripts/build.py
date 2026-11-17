#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Fresh controller authoring and HIA compilation; no handler qualification claim."""
from pathlib import Path
import argparse
import json
import os
import shutil
import subprocess
import sys
import time
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from callable_common import encoded, decode, pin, require, sources, syntax

def process(output, name, argv):
    start = time.monotonic_ns()
    row = dict(argv=[str(x) for x in argv], limit_seconds=60, timed_out=False)
    with (output / (name + ".stdout")).open("xb") as out, (output / (name + ".stderr")).open("xb") as err:
        try:
            child = subprocess.run(row["argv"], stdout=out, stderr=err, timeout=60, check=False)
            row["returncode"] = child.returncode
        except subprocess.TimeoutExpired:
            row["returncode"] = None
            row["timed_out"] = True
    row["elapsed_ns"] = time.monotonic_ns() - start
    row["streams"] = {key: pin(output / (name + "." + key)) for key in ("stdout", "stderr")}
    (output / (name + ".json")).write_bytes(encoded(row))
    require(row["returncode"] == 0 and not row["timed_out"], "source author failed")
    require((output / (name + ".stderr")).read_bytes() == b"", "source author stderr")
    return row

def run(source, hepta, output):
    require(os.environ.get("GITHUB_ACTIONS") == "true", "native build restricted to CI")
    identity = syntax(source)
    require(not output.exists(), "fresh output required")
    output.mkdir(parents=True)
    generated = output / "generated"
    row = process(output, "author", [sys.executable, "-I", "-S", "-B", source / "scripts/author.py",
        "--source", source, "--hepta", hepta, "--output", generated])
    for path in sorted((generated / "native").iterdir()):
        raw = path.read_bytes()
        print("GENERATED_SOURCE_JSON:" + json.dumps({"path": path.relative_to(generated).as_posix(),
            "bytes": len(raw), "sha256": __import__("hashlib").sha256(raw).hexdigest(),
            "text": raw.decode("utf-8")}, sort_keys=True), flush=True)
    from hia_native_build import NativeBuild
    native = NativeBuild(hepta, output / "build")
    members = {}
    for name in ("runtime_mcp", "runtime_mcp_catalog_ninth"):
        path = generated / "native" / (name + ".hepta")
        manifest = native.compile(name, path, standalone=None, buffer_profile="history.v1")
        meta = decode(manifest.read_bytes())
        members[name] = dict(source=pin(path), source_path=path.relative_to(output).as_posix(),
            manifest=manifest.relative_to(output).as_posix(), manifest_identity=pin(manifest),
            image=pin(manifest.parent / meta["image"]))
    compiler = output / "compiler-source"
    compiler.mkdir()
    for name in native.identity["files"]:
        path = compiler / name
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(hepta / name, path)
    result = dict(status="ACTUAL_PUBLICATION_ROUTE_CATALOG_BUILD_PASS", source=identity,
        author=row, compiler=native.identity, members=members, actual_hia_compiles=2,
        public_route=False, actual_scope_caller_comparison=False, configured_path_comparison=False,
        actual_cache_forget_comparison=False, full_async=False, full_sdk=False, production_installed=False)
    (output / "BUILD.json").write_bytes(encoded(result))
    print(json.dumps(result, sort_keys=True))

def main():
    p = argparse.ArgumentParser()
    p.add_argument("mode", choices=("check", "build"))
    p.add_argument("--source", required=True, type=Path)
    p.add_argument("--hepta", type=Path)
    p.add_argument("--output", type=Path)
    a = p.parse_args()
    source = a.source.resolve(strict=True)
    if a.mode == "check":
        print(json.dumps(syntax(source), sort_keys=True))
    else:
        run(source, a.hepta.resolve(strict=True), a.output.absolute())

if __name__ == "__main__":
    main()

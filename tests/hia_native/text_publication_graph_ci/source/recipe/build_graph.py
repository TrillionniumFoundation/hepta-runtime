#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Fresh fixed private graph from the source-only composition; no handler claims."""
from pathlib import Path
import argparse
import json
import hashlib
import os
import shutil
import sys
sys.dont_write_bytecode = True
SHA = lambda b: hashlib.sha256(b).hexdigest()
def require(x, message):
    if not x: raise ValueError(message)
def put(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")

def main():
    p = argparse.ArgumentParser()
    for name in ("source", "hepta", "output"):
        p.add_argument("--" + name, type=Path, required=True)
    a = p.parse_args()
    require(os.environ.get("GITHUB_ACTIONS") == "true", "native build is restricted to CI")
    source, hepta, output = a.source.resolve(strict=True), a.hepta.resolve(strict=True), a.output.absolute()
    require(not output.exists(), "fresh build output required")
    output.mkdir(parents=True)
    sys.path.insert(0, str(source / "scripts"))
    from hia_native_runtime_mcp_build import run_build_step, WORKER_SOURCE_SHA256
    from public_nine_build import source_check, build_runtime_mcp, MEMBERS, EXTRA, PORT_PACKAGE_SHA256
    identity = source_check(source)
    from hia_native_build import check_dependency
    compiler_identity = check_dependency(hepta)
    compiler_copy = output / "compiler-source"
    for name, digest in compiler_identity["files"].items():
        path = compiler_copy / name
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(hepta / name, path)
        require(SHA(path.read_bytes()) == digest, "retained compiler source differs")
    put(output / "compiler-identity.json", compiler_identity)
    require(len(MEMBERS) == 108 and len(EXTRA) == 68, "fixed publisher graph inventory differs")
    require(EXTRA[59:] == [None]*5 + ["publisher_gateway", "publisher_params", "publisher_call", None],
        "publisher or reserved extract descriptors differ")
    package = source / "runtime_support/bellman_port"
    require(SHA((package / "PACKAGE.json").read_bytes()) == PORT_PACKAGE_SHA256, "retained port package differs")
    python = [sys.executable, "-I", "-S", "-B"]
    commands = [
        ("worker", python + [str(package / "worker-source/tests/hia_native/blocking_worker/worker_build.py"),
            "--source-root", str(package / "worker-source"), "--hepta", str(hepta),
            "--capture", str(output / "worker"), "--source-pins-sha256", WORKER_SOURCE_SHA256]),
        ("port", python + [str(package / "recipe/build_capability.py"), "--package", str(package),
            "--hepta", str(hepta), "--worker-build", str(output / "worker"),
            "--output", str(output / "port"), "--package-sha256", PORT_PACKAGE_SHA256])]
    processes = []
    report = dict(status="RUNNING", source=identity, processes=processes, public_route=False,
        actual_gateway_comparison=False, full_async=False, full_sdk=False, production_installed=False)
    put(output / "BUILD.json", report)
    try:
        for label, command in commands:
            processes.append(run_build_step(output, label, command))
            put(output / "BUILD.json", report)
        shutil.copytree(output / "worker/build/bootstrap", output / "build/bootstrap")
        manifest = build_runtime_mcp(hepta, output / "build", name="publisher-private",
            source_root=source, private_fixture=True, bellman_port_build=output / "port/build-v3",
            bellman_port_package=package, bellman_worker_build=output / "worker")
        raw = manifest.read_bytes()
        md = json.loads(raw)
        require(md["physical_images"] == 109 and len(md["members"]) == 108 and md["runtime_hia_images"] == 116,
            "actual graph inventory differs")
        require(all(row["fresh_compile"] is True for row in md["members"]), "unexpected leaf reuse")
        require(source_check(source) == identity, "source changed during fresh build")
        report.update(status="FRESH_PRIVATE_PUBLISHER116_BUILD_PASS", manifest=str(manifest),
            manifest_sha256=SHA(raw), physical_images=109, runtime_hia_images=116,
            direct_fresh_hia_images=108, packed_fresh_hia_images=8,
            binary=str(manifest.parent / md["elf"]), binary_bytes=md["elf_bytes"],
            binary_sha256=md["elf_sha256"], source_files=len(identity["files"])+1)
    except BaseException as exc:
        report.update(status="FAIL", error=repr(exc))
        raise
    finally:
        put(output / "BUILD.json", report)
    print(json.dumps(report, sort_keys=True))
if __name__ == "__main__": main()

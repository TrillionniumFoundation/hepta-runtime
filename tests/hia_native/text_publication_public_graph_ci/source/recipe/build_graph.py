#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Build the combined public graph and two fixed observation entries in CI."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import sys
sys.dont_write_bytecode = True
SHA = lambda b: hashlib.sha256(b).hexdigest()
def require(ok, message):
    if not ok: raise ValueError(message)
def put(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")

def main():
    parser = argparse.ArgumentParser()
    for name in ("source", "hepta", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    require(os.environ.get("GITHUB_ACTIONS") == "true", "actual builds restricted to CI")
    source, hepta, output = args.source.resolve(strict=True), args.hepta.resolve(strict=True), args.output.absolute()
    require(not output.exists(), "fresh complete build output required")
    output.mkdir(parents=True)
    sys.path.insert(0, str(source / "scripts"))
    from hia_native_runtime_mcp_build import run_build_step, WORKER_SOURCE_SHA256
    from hia_native_build import check_dependency
    from public_nine_build import source_check, build_runtime_mcp, MEMBERS, EXTRA, PORT_PACKAGE_SHA256
    identity = source_check(source)
    compiler = check_dependency(hepta)
    for name, digest in compiler["files"].items():
        target = output / "compiler-source" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(hepta / name, target)
        require(SHA(target.read_bytes()) == digest, "complete compiler source differs")
    put(output / "compiler-identity.json", compiler)
    require(len(MEMBERS) == 115 and len(EXTRA) == 69, "combined fixed graph count differs")
    require(EXTRA[59:] == ["extract_gateway", "extract_params", "extract_call", "extract_adapter", None,
        "publisher_gateway", "publisher_params", "publisher_call", None, None], "actual fixed descriptors differ")
    package = source / "runtime_support/bellman_port"
    require(SHA((package / "PACKAGE.json").read_bytes()) == PORT_PACKAGE_SHA256, "packed port source differs")
    python = [sys.executable, "-I", "-S", "-B"]
    commands = [
        ("worker", python + [str(package / "worker-source/tests/hia_native/blocking_worker/worker_build.py"),
            "--source-root", str(package / "worker-source"), "--hepta", str(hepta),
            "--capture", str(output / "worker"), "--source-pins-sha256", WORKER_SOURCE_SHA256]),
        ("port", python + [str(package / "recipe/build_capability.py"), "--package", str(package),
            "--hepta", str(hepta), "--worker-build", str(output / "worker"),
            "--output", str(output / "port"), "--package-sha256", PORT_PACKAGE_SHA256])]
    report = dict(status="RUNNING", source=identity, compiler_commit=compiler["commit"],
        processes=[], roles={}, public_route_registered=True, public_qualified=False,
        actual_public_comparison=False, shared_extract_wait_qualified=False,
        publication_async_qualified=False, full_sdk=False, installed=False)
    put(output / "BUILD.json", report)
    try:
        for label, command in commands:
            report["processes"].append(run_build_step(output, label, command))
            put(output / "BUILD.json", report)
        shutil.copytree(output / "worker/build/bootstrap", output / "build/bootstrap")
        reuse = None
        for role, flags in (("public", {}), ("filesystem", {"private_fixture": True}),
                            ("trace", {"private_pump_fixture": True, "private_pump_trace": True})):
            manifest = build_runtime_mcp(hepta, output / "build", name="publication-" + role,
                source_root=source, manifests=reuse, bellman_port_build=output / "port/build-v3",
                bellman_port_package=package, bellman_worker_build=output / "worker", **flags)
            raw = manifest.read_bytes()
            row = json.loads(raw)
            require(row["physical_images"] == 116 and len(row["members"]) == 115
                    and row["runtime_hia_images"] == 123, "actual image inventory differs")
            require(all(m["fresh_compile"] is (reuse is None) for m in row["members"]),
                    "same-CI fresh/reuse provenance differs")
            current = {m["name"]: (m["source_sha256"], m["image_sha256"], m["image_bytes"], m["buffer_profile"])
                       for m in row["members"]}
            if reuse is None:
                images = current
                reuse = {m["name"]: m["manifest"] for m in row["members"]}
            else:
                require(current == images, "observation entry changed a HIA image or source")
            report["roles"][role] = dict(manifest=str(manifest), manifest_sha256=SHA(raw),
                binary=str(manifest.parent / row["elf"]), binary_bytes=row["elf_bytes"],
                binary_sha256=row["elf_sha256"], physical_images=116, runtime_hia_images=123,
                direct_fresh=115 if role == "public" else 0, direct_same_ci_reuse=0 if role == "public" else 115)
            put(output / "BUILD.json", report)
        require(source_check(source) == identity, "whole graph source changed during actual build")
        report.update(status="FRESH_COMBINED_PUBLICATION123_BUILD_PASS", direct_fresh_hia_images=115,
            packed_fresh_hia_images=8, source_files=len(identity["files"])+1)
    except BaseException as error:
        report.update(status="FAIL", error=repr(error))
        raise
    finally:
        put(output / "BUILD.json", report)
    print(json.dumps(report, sort_keys=True))
if __name__ == "__main__":
    main()

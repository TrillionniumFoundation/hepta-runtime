#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Build fixed HIA owners and the actual three-image SDK transport fixture."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from hia_native_build import NativeBuild
from connection_registry import COMPILER, COMPILER_IMAGE, MODULES, source_pins
from hia_native_connection_reference import prepare_cases

sha = lambda raw: hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta", type=Path, required=True)
    parser.add_argument("--build-root", type=Path, required=True)
    args = parser.parse_args()
    build_root = args.build_root.resolve()
    build = NativeBuild(args.hepta, build_root)
    build.bootstrap()
    assert build.identity["commit"] == COMPILER and build.compiler_sha256 == COMPILER_IMAGE
    pins = source_pins(ROOT)
    modules = {}
    for key, (name, profile, source_hash, image_hash) in MODULES.items():
        if key == "packer":
            continue
        source = ROOT / "native" / (name + ".hepta")
        assert sha(source.read_bytes()) == source_hash
        manifest = build.compile("sdk-" + key, source, standalone=None, buffer_profile=profile)
        meta = json.loads(manifest.read_bytes())
        assert meta["image_sha256"] == image_hash
        modules[key] = {"path": str(manifest), "sha256": sha(manifest.read_bytes())}
    command = [sys.executable, "-I", "-B", str(ROOT / "scripts/build_connection_fixture.py"),
               "--hepta", str(args.hepta.resolve(strict=True)), "--runtime", str(ROOT),
               "--build-root", str(build_root), "--name", "sdk-connection"]
    for key in ("message", "connection", "fixture"):
        command += ["--" + key + "-manifest", modules[key]["path"]]
    begin = time.monotonic()
    try:
        process = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
        out, err, code, timed = process.stdout, process.stderr, process.returncode, False
    except subprocess.TimeoutExpired as error:
        out, err, code, timed = error.stdout or b"", error.stderr or b"", None, True
    (build_root / "connection-fixture.stdout").write_bytes(out)
    (build_root / "connection-fixture.stderr").write_bytes(err)
    record = {"command": command, "cwd": str(ROOT), "stdout_sha256": sha(out), "stderr_sha256": sha(err),
              "exit_code": code, "timed_out": timed, "timeout_seconds": 120, "elapsed_seconds": time.monotonic() - begin}
    (build_root / "connection-fixture-process.json").write_text(json.dumps(record, sort_keys=True, indent=2) + "\n")
    assert not timed and code == 0 and not err
    observed = json.loads(out)
    manifest = Path(observed["manifest"])
    executable = json.loads(manifest.read_bytes())
    assert manifest == build_root / "sdk-connection-elf/manifest.json"
    packer = Path(executable["packer_manifest"])
    packer_meta = json.loads(packer.read_bytes())
    assert packer_meta["source_sha256"] == MODULES["packer"][2] and packer_meta["image_sha256"] == MODULES["packer"][3]
    modules["packer"] = {"path": str(packer), "sha256": sha(packer.read_bytes())}
    data = build_root / "connection-reference-data"
    index = prepare_cases(ROOT, data)
    assert source_pins(ROOT) == pins
    build._recheck()
    result = {"schema": "hepta.sdk-connection.build.v1", "compiler_commit": COMPILER, "compiler_sha256": COMPILER_IMAGE,
              "modules": modules, "fixture": {"path": str(manifest), "sha256": sha(manifest.read_bytes())},
              "sources": pins, "reference_data": str(data), "reference_files": index["files"],
              "reference_index_sha256": sha((ROOT / "tests/hia_native/connection_reference_cases.json").read_bytes()),
              "production_tool_dispatch_closed": False, "fixture_handler_is_test_only": True,
              "client_result_typed_normalization_closed": False, "fresh_cold_qualified": False}
    path = build_root / "connection-build.json"
    path.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"manifest": str(path), "modules": 4, "actual_static_elfs": 1}, sort_keys=True))


if __name__ == "__main__":
    main()

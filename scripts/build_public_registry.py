#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Compile the fixed seventeen images and HIA packer without an assembler."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from hia_native_build import NativeBuild
from public_registry_registry import COMPILER, COMPILER_IMAGE, profile, source_pins

sha = lambda raw: hashlib.sha256(raw).hexdigest()
encoded = lambda value: (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta", required=True, type=Path)
    parser.add_argument("--build-root", required=True, type=Path)
    args = parser.parse_args()
    destination = args.build_root.resolve()
    builder = NativeBuild(args.hepta, destination)
    builder.bootstrap()
    assert builder.identity["commit"] == COMPILER and builder.compiler_sha256 == COMPILER_IMAGE
    pins, graph = source_pins(ROOT), profile(ROOT)
    members, images, modules = [], [], {}
    for row in [*graph["members"], {"name": "packer", **graph["packer"]}]:
        source = ROOT / row["source"]
        assert sha(source.read_bytes()) == row["source_sha256"]
        path = builder.compile("public-registry-" + row["name"], source,
            standalone=None, buffer_profile=row["buffer_profile"])
        metadata = json.loads(path.read_bytes())
        image = (path.parent / metadata["image"]).read_bytes()
        assert sha(image) == row["image_sha256"]
        modules[row["name"]] = {"path": str(path), "sha256": sha(path.read_bytes())}
        if row["name"] != "packer":
            member = {**row, "manifest": str(path), "manifest_sha256": sha(path.read_bytes())}
            members.append(member)
            images.append(image)
    folder = destination / "public-registry-elf"
    folder.mkdir(mode=0o700)
    frame = b"HPRTMCP1" + b"".join(struct.pack("<Q", len(image)) for image in images) + bytes(8) + b"".join(images)
    assert (len(frame), sha(frame)) == (graph["frame_bytes"], graph["frame_sha256"])
    (folder / "pack.input.bin").write_bytes(frame)
    command = [sys.executable, "-I", "-B", str(ROOT / "scripts/public_registry_pack_child.py"),
        "--manifest", modules["packer"]["path"], "--input", str(folder / "pack.input.bin"),
        "--output", str(folder / "public-runtime.elf")]
    env = {key: value for key, value in os.environ.items() if not key.startswith("HIA_")}
    begin = time.monotonic()
    code, timed, error = None, False, None
    try:
        done = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, timeout=30)
        out, err, code = done.stdout, done.stderr, done.returncode
    except subprocess.TimeoutExpired as exc:
        out, err, timed = exc.stdout or b"", exc.stderr or b"", True
    except OSError as exc:
        out, err, error = b"", b"", repr(exc)
    record = dict(command=command, cwd=str(ROOT), exit_code=code, timed_out=timed, start_error=error,
        timeout_seconds=30, elapsed_seconds=time.monotonic() - begin,
        stdout_sha256=sha(out), stdout_bytes=len(out), stderr_sha256=sha(err), stderr_bytes=len(err))
    (folder / "pack.stdout").write_bytes(out)
    (folder / "pack.stderr").write_bytes(err)
    (folder / "pack-process.json").write_bytes(encoded(record))
    assert code == 0 and not timed and error is None and not err
    observed = json.loads(out)
    binary = folder / "public-runtime.elf"
    elf = binary.read_bytes()
    assert (len(elf), sha(elf)) == (graph["elf_bytes"], graph["elf_sha256"])
    assert observed["output_sha256"] == sha(elf) and observed["input_sha256"] == sha(frame)
    prefix = bytearray(elf[:graph["prefix_bytes"]])
    struct.pack_into("<QQ", prefix, 96, 0, 0)
    at = len(prefix)
    for member, image in zip(members, images, strict=True):
        hole = member["call_displacement_offset"]
        assert member["offset"] == at and elf[at:at + len(image)] == image
        assert elf[hole - 1] == 0xe8 and hole + 4 + struct.unpack_from("<i", elf, hole)[0] == at
        struct.pack_into("<I", prefix, hole, 0)
        at += len(image)
    assert at == len(elf) and sha(prefix) == graph["prefix_sha256"]
    binary.chmod(0o500)
    metadata = {"schema": "hepta.runtime.public-registry-native.v1", "members": members,
        "compiler_commit": COMPILER, "compiler_sha256": COMPILER_IMAGE,
        "executable": binary.name, "elf_bytes": len(elf), "elf_sha256": sha(elf),
        "adapter_source_sha256": graph["adapter_source_sha256"], "prefix_bytes": graph["prefix_bytes"],
        "prefix_sha256": graph["prefix_sha256"], "pack_input_sha256": sha(frame),
        "packer_manifest": modules["packer"]["path"], "packer_manifest_sha256": modules["packer"]["sha256"],
        "source_map": pins, "call_edges": graph["call_edges"], "only_effect_owner": 1,
        "caller_configuration_installation": False, "public_request_audit_closed": False,
        "public_request_result_lifecycle_closed": False, "production_activated": False,
        "fresh_cold_qualified": False}
    manifest = folder / "manifest.json"
    manifest.write_bytes(encoded(metadata))
    builder._recheck()
    assert source_pins(ROOT) == pins
    for row in modules.values():
        assert sha(Path(row["path"]).read_bytes()) == row["sha256"]
    bundle = {"schema": "hepta.public-registry.build.v1", "compiler_commit": COMPILER,
        "compiler_sha256": COMPILER_IMAGE, "sources": pins, "modules": modules,
        "executable": {"path": str(manifest), "sha256": sha(manifest.read_bytes())},
        "production_activated": False, "public_request_audit_closed": False,
        "public_request_result_lifecycle_closed": False, "fresh_cold_qualified": False}
    output = destination / "public-registry-build.json"
    output.write_bytes(encoded(bundle))
    print(json.dumps({"manifest": str(output), "modules": 18, "actual_static_elfs": 1}, sort_keys=True))


if __name__ == "__main__":
    main()

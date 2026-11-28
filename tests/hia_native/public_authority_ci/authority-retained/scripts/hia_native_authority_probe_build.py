"""Build the real startup-only private-loader qualification executable.

The probe returns owned test-fixture bytes. Production keeps the same HIA
loader result inside private native buffers and never exposes that operation.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from hia_native_build import HEPTA_COMMIT, NativeBuild, json_bytes, write_new
from hia_native_authority_build import checked_flat, read, require, same, sha
from hia_native_entropy_qualification import inspect_elf, native_receipt

POLICY_SHA = "fabb5314b1570d762de12b99968dd1109e9a5f5eb1ea06a6a5afdff6e0d4999a"
POLICY_IMAGE_SHA = "5845f4e188db29d26a2c1348583398f63f30e883b2bedabb1af6e259b0997d48"
PACKER_SHA = "feb13a0ecefdf07abbcff1016270bdbaaf7b4d9e0bde9440a8129c56f3659fda"
PACKER_IMAGE_SHA = "a49cd0dc921eaaca373103b68714bae89fc2fb5798776b07d3063c22b045daa6"


def build_loader_probe(hepta: Path, build_root: Path, *, source_root: Path = ROOT) -> Path:
    source_root = Path(source_root).resolve(strict=True)
    paths = {"policy": source_root / "native/authority_loader.hepta",
             "packer": source_root / "tests/hia_native/authority_loader_probe_packer.hepta"}
    sources = {kind: read(path) for kind, path in paths.items()}
    require(sha(sources["policy"]) == POLICY_SHA and sha(sources["packer"]) == PACKER_SHA,
            "loader probe fixed native sources differ")
    build = NativeBuild(hepta, build_root)
    compiler_sha = sha(read(build.bootstrap()))
    expected_images = {"policy": POLICY_IMAGE_SHA, "packer": PACKER_IMAGE_SHA}
    modules = {kind: checked_flat(build, "authority-loader-" + kind + "-" + sha(sources[kind])[:16],
                                  path, expected_images[kind])
               for kind, path in paths.items()}
    destination = build.root / "authority-loader-probe" / sha(sources["policy"] + sources["packer"])
    manifest_path = destination / "manifest.json"
    frame = b"HIALODP1" + struct.pack("<Q", len(modules["policy"][2])) + modules["policy"][2]
    expected = {"schema": "hepta.runtime.authority-loader-probe.v1", "target": "linux-x86_64",
                "transport": "trusted-startup-argv-u32-fixture-result", "compiler_sha256": compiler_sha,
                "compiler_commit": HEPTA_COMMIT, "executable": "authority-loader-probe.elf",
                "policy_manifest": "policy.json", "packer_manifest": "packer.json",
                "maximum_startup_bytes": 131095, "maximum_result_bytes": 4096,
                "workspace_bytes": 262144, "runtime_python_required": False,
                "runtime_libc_required": False, "qualification_fixture": True,
                "publishes_owned_fixture_bytes": True, "registered_mcp_tool": False,
                "production_activated": False, "whole_runtime_replaced": False}

    def verify():
        metadata = json.loads(read(manifest_path))
        same({key: metadata.get(key) for key in expected}, expected,
             "cached loader probe compiler/contract differs")
        for kind, (_, original, image) in modules.items():
            copied = {**original, "source": kind + ".hepta", "image": kind + ".image.bin"}
            copied_path = destination / (kind + ".json")
            same(json.loads(read(copied_path)), copied, "loader probe copied native manifest differs")
            require(read(destination / (kind + ".hepta")) == sources[kind]
                    and read(destination / (kind + ".image.bin")) == image
                    and metadata.get(kind + "_manifest_sha256") == sha(read(copied_path))
                    and metadata.get(kind + "_source_sha256") == sha(sources[kind])
                    and metadata.get(kind + "_image_sha256") == sha(image),
                    "loader probe native source/image custody differs")
        executable = read(destination / expected["executable"])
        require(metadata.get("executable_sha256") == sha(executable), "loader probe executable differs")
        same(metadata.get("inspection"), inspect_elf(executable), "loader probe ELF inspection differs")
        require(read(destination / "pack.input.bin") == frame, "loader probe native packing input differs")
        receipt = json.loads(read(destination / "pack.receipt.json"))
        same(metadata.get("pack_receipt"), receipt, "loader probe native packing receipts disagree")
        native_receipt(receipt, image=modules["packer"][2], source=frame,
                       output=read(destination / "pack.output.bin"), produced=executable)
        for kind, path in paths.items():
            require(read(path) == sources[kind], "loader probe source changed during build")
        build._recheck()

    if manifest_path.exists():
        verify()
        return manifest_path
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination.mkdir(mode=0o700)
    from tools.qualify_hia_selfhost import invoke
    receipt, raw = invoke(destination, "pack", modules["packer"][0].parent / "module.image.bin", frame)
    count = receipt.get("core_u32")
    require(type(count) is int and 0 < count <= min(1 << 20, len(raw)),
            "loader probe native packer did not return a bounded executable")
    executable = raw[:count]
    native_receipt(receipt, image=modules["packer"][2], source=frame, output=raw, produced=executable)
    inspection = inspect_elf(executable)
    metadata = {**expected, "pack_receipt": receipt, "inspection": inspection,
                "executable_sha256": sha(executable)}
    for kind, (_, original, image) in modules.items():
        copied_path = destination / (kind + ".json")
        write_new(destination / (kind + ".hepta"), sources[kind])
        write_new(destination / (kind + ".image.bin"), image)
        write_new(copied_path, json_bytes({**original, "source": kind + ".hepta",
                                         "image": kind + ".image.bin"}))
        metadata.update({kind + "_source_sha256": sha(sources[kind]),
                         kind + "_image_sha256": sha(image),
                         kind + "_manifest_sha256": sha(read(copied_path))})
    write_new(destination / expected["executable"], executable, 0o500)
    write_new(manifest_path, json_bytes(metadata))
    verify()
    return manifest_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta", type=Path, default=os.environ.get("HIA_HEPTA_DIR"))
    parser.add_argument("--build-root", type=Path, default=os.environ.get("HIA_BUILD_ROOT"))
    args = parser.parse_args()
    if args.hepta is None or args.build_root is None:
        parser.error("--hepta and --build-root are required")
    print(build_loader_probe(args.hepta, args.build_root))

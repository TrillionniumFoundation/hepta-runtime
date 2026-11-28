#!/usr/bin/env python3
"""Build the independent serial Batch fixture with its actual HIA packer."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
PIN = lambda raw: {"bytes": len(raw), "sha256": SHA(raw)}
GENERATION = "bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0"


def checked_compile(folder, source, image):
    report = json.loads((folder / "build.json").read_bytes())
    receipt = json.loads((folder / "module.receipt.json").read_bytes())
    stdout = json.loads((folder / "module.stdout.log").read_bytes())
    assert report["compile_receipt"] == receipt
    assert all(receipt[k] == v for k, v in stdout.items())
    assert len(stdout) == 15 and (folder / "module.stderr.log").read_bytes() == b""
    assert receipt["status"] == "returned" and receipt["abi_status"] == 0
    assert receipt["source_unchanged"] is True and receipt["forbidden_compiler_modules_loaded"] == []
    assert receipt["artifact_sha256"] == GENERATION and receipt["format"] == "flat-x86-64"
    assert receipt["input_sha256"] == SHA(source) and receipt["input_bytes"] == len(source)
    assert receipt["produced_sha256"] == SHA(image) and receipt["produced_bytes"] == len(image)
    assert receipt["core_u32"] == len(image) and (folder / "module.input.bin").read_bytes() == source


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta", type=Path, required=True)
    parser.add_argument("--bootstrap", type=Path)
    parser.add_argument("--body-build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    out = args.output.absolute()
    out.mkdir(parents=True, exist_ok=False)
    begin = time.monotonic()
    component_raw = (ROOT / "fixture-component.json").read_bytes()
    component = json.loads(component_raw)
    before = {name: PIN((ROOT / name).read_bytes()) for name in component["files"]}
    assert before == component["files"]
    before.update({name: PIN((ROOT / name).read_bytes()) for name in (
        "fixture-component.json", "build_fixture.py", "authoring/author_fixture_pack.py",
        "retained/elf-header.bin", "runtime_support/scripts/hia_native_build.py",
        "runtime_support/scripts/hia_native_loader.py")})
    author_command = [sys.executable, str(ROOT / "authoring/author_fixture_pack.py"),
        "--hepta", str(args.hepta), "--output", str(out / "reproduced")]
    started = time.monotonic()
    authored = subprocess.run(author_command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=60)
    (out / "author.stdout").write_bytes(authored.stdout)
    (out / "author.stderr").write_bytes(authored.stderr)
    author_process = {"argv": author_command, "returncode": authored.returncode, "timeout_seconds": 60,
        "elapsed_seconds": time.monotonic() - started, "stdout": PIN(authored.stdout), "stderr": PIN(authored.stderr)}
    (out / "author-process.json").write_text(json.dumps(author_process, sort_keys=True, indent=2) + "\n")
    assert authored.returncode == 0 and authored.stderr == b"", authored.stderr
    assert (out / "reproduced/batch_fixture_prefix.bin").read_bytes() == (ROOT / "native_boundary/batch_fixture_prefix.bin").read_bytes()
    assert (out / "reproduced/batch_fixture_packer.hepta").read_bytes() == (ROOT / "native/batch_fixture_packer.hepta").read_bytes()
    body_root = args.body_build.resolve(strict=True)
    body = json.loads((body_root / "BUILD.json").read_bytes())
    assert body["status"] == "PASS" and body["fresh_native_compilations"] == 16
    assert body["order"] == [member["name"] for member in component["members"]]
    images = []
    members = []
    for member in component["members"]:
        row = body["modules"][member["name"]]
        manifest_path = body_root / row["manifest"]
        manifest_raw = manifest_path.read_bytes()
        manifest = json.loads(manifest_raw)
        source = (ROOT / member["source"]).read_bytes()
        image = (manifest_path.parent / manifest["image"]).read_bytes()
        assert PIN(source) == member["source_pin"] and PIN(image) == member["image_pin"]
        assert manifest["source_sha256"] == SHA(source) and manifest["image_sha256"] == SHA(image)
        assert manifest["buffer_profile"] == member["profile"] and manifest["compiler_sha256"] == GENERATION
        checked_compile(manifest_path.parent, source, image)
        before[member["source"]] = PIN(source)
        images.append(image)
        members.append({"name": member["name"], "manifest": str(manifest_path), "manifest_pin": PIN(manifest_raw),
            "source_pin": PIN(source), "image_pin": PIN(image)})
    if args.bootstrap is not None:
        original = args.bootstrap.resolve(strict=True)
        (out / "bootstrap").mkdir()
        assert json.loads((original / "bootstrap.json").read_bytes())["generation_sha256"] == GENERATION
        for name in ("bootstrap.json", "B1.image.bin", "B2.image.bin", "B3.image.bin"):
            path = original / name
            assert path.is_file() and not path.is_symlink()
            if name.endswith(".image.bin"):
                assert SHA(path.read_bytes()) == GENERATION
            shutil.copyfile(path, out / "bootstrap" / name)
    else:
        assert os.environ.get("GITHUB_ACTIONS") == "true"
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(ROOT / "runtime_support/scripts"))
    from hia_native_build import NativeBuild
    from hia_native_loader import NativeModule
    builder = NativeBuild(args.hepta, out)
    manifest_path = builder.compile("batch-fixture-packer", ROOT / "native/batch_fixture_packer.hepta",
                                    standalone=None, buffer_profile="history.v1")
    metadata = json.loads(manifest_path.read_bytes())
    checked_compile(manifest_path.parent, (ROOT / "native/batch_fixture_packer.hepta").read_bytes(),
                    (manifest_path.parent / metadata["image"]).read_bytes())
    prefix = (ROOT / "native_boundary/batch_fixture_prefix.bin").read_bytes()
    total = len(prefix) + sum(map(len, images))
    expected = bytearray(prefix)
    struct.pack_into("<QQ", expected, 96, total, total)
    struct.pack_into("<14Q", expected, component["table_offset"], *map(len, images))
    expected = bytes(expected) + b"".join(images)
    assert PIN(expected) == component["expected_elf"]
    wire = b"HLBBPX01" + struct.pack("<14Q", *map(len, images)) + b"".join(images)
    with NativeModule(manifest_path, manifest_sha256=SHA(manifest_path.read_bytes())) as packer:
        code, output, work = packer.invoke_raw(wire, output_capacity=total + 4096,
            workspace_capacity=4096, output_fill=0xb3, workspace_fill=0xc7)
    assert code == total and output == expected + b"\xb3" * 4096 and work == b"\xc7" * 4096
    artifacts = {}
    for name, raw in (("pack.input.bin", wire), ("pack.output.bin", output), ("pack.workspace.bin", work),
                      ("local-batch-body.elf", expected)):
        (out / name).write_bytes(raw)
        artifacts[name] = PIN(raw)
    (out / "local-batch-body.elf").chmod(0o500)
    assert before == {name: PIN((ROOT / name).read_bytes()) for name in before}
    builder._recheck()
    report = {"schema": "hepta.runtime.rebuilt-batch-callable-fixture-build.v1", "status": "PASS",
        "source_root": str(ROOT), "source_inputs": {"files": before}, "body_build": str(body_root / "BUILD.json"),
        "body_build_pin": PIN((body_root / "BUILD.json").read_bytes()), "members": members,
        "packer_manifest": str(manifest_path.relative_to(out)), "packer_manifest_pin": PIN(manifest_path.read_bytes()),
        "artifacts": artifacts, "actual_packer_return": code, "fresh_packer_compilations": 1,
        "reused_reverified_member_compilations": 14, "author_process": author_process,
        "scope": component["scope"], "semantic_qualification": False,
        "elapsed_seconds": time.monotonic() - begin}
    (out / "BUILD.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps({key: report[key] for key in ("status", "artifacts", "elapsed_seconds")}, sort_keys=True))


if __name__ == "__main__":
    main()

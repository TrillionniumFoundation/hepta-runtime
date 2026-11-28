#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Build a one-shot native writer from the exact qualified HIA parent graph."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import shutil
import stat
import struct
import subprocess
import sys
import time

sys.dont_write_bytecode = True


def require(value, message):
    if not value:
        raise ValueError(message)


def pin(path):
    raw = Path(path).read_bytes()
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def inventory(root):
    result = {}
    for path in sorted(root.rglob("*")):
        mode = path.lstat().st_mode
        require(not path.is_symlink(), "bootstrap symlink")
        if stat.S_ISREG(mode):
            result[path.relative_to(root).as_posix()] = {**pin(path), "mode": stat.S_IMODE(mode)}
        else:
            require(stat.S_ISDIR(mode), "bootstrap special file")
    return result


def imported(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def process(output, label, command, timeout):
    start = time.monotonic()
    command = [str(value) for value in command]
    with (output / (label + ".stdout")).open("xb") as stdout, (output / (label + ".stderr")).open("xb") as stderr:
        completed = subprocess.run(command, stdout=stdout, stderr=stderr,
                                   stdin=subprocess.DEVNULL, timeout=timeout)
    record = {"argv": command, "returncode": completed.returncode,
              "seconds": time.monotonic() - start, "timeout_seconds": timeout,
              "stdout": pin(output / (label + ".stdout")),
              "stderr": pin(output / (label + ".stderr"))}
    (output / (label + ".json")).write_bytes(encoded(record))
    require(completed.returncode == 0 and record["stderr"]["bytes"] == 0,
            "native binary-write build process failed: " + label)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "hepta", "bootstrap", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--images", type=Path, help="Reuse only an exact source-bound original twelve-image build")
    args = parser.parse_args()
    root = args.source.resolve(strict=True)
    source = root / "runtime_support/binary_write/source/parent"
    output = args.output.absolute()
    require(not output.exists(), "fresh binary-write build output required")
    output.mkdir(parents=True)
    sys.path.insert(0, str(root / "scripts"))
    from hia_native_build import NativeBuild, check_dependency
    from hia_native_loader import NativeModule
    from hia_native_public_file_info_walk import flatten
    original = imported("public_binary_write_original_link", source / "scripts/link_callable.py")
    custody = imported("public_binary_write_original_custody", source / "scripts/evidence_common.py")
    qualified = custody.source_evidence(source)
    compiler = check_dependency(args.hepta.resolve(strict=True))
    require(compiler == json.loads((source / "COMPILER_INPUT.json").read_bytes()),
            "complete original compiler identity differs")
    paths = ["scripts/hia_native_public_binary_write.py", "scripts/hia_native_public_file_info_walk.py",
             "scripts/hia_native_build.py", "scripts/hia_native_loader.py",
             "authoring/public_binary_write/author_stdio.py", "authoring/public_binary_write/STDIO_AUTHOR.json",
             "authoring/public_binary_write/author_current.py", "authoring/public_publication_v1/source_support.py",
             "authoring/public_binary_write/author_base64.py", "authoring/public_binary_write/base64_current.pseudo",
             "native/public_binary_parent_owner.hepta", "native/public_binary_parent_owner_composition.json",
             "native/public_binary_write_body.hepta", "native/public_binary_write_body_composition.json",
             "native/public_binary_base64_decode.hepta", "native/public_binary_base64_decode_composition.json",
             "asm/public_binary_write_stdio.S", "runtime_support/binary_write/ORIGIN.json"]
    bindings = {name: pin(root / name) for name in paths}
    records = [process(output, "author", [sys.executable, "-I", "-B",
        root / "authoring/public_binary_write/author_stdio.py", "--source", root,
        "--output", output / "authored"], 30)]
    require((output / "authored/public_binary_write_stdio.S").read_bytes()
            == (root / "asm/public_binary_write_stdio.S").read_bytes(), "complete stdio author reproduction differs")
    require((output / "authored/STDIO_AUTHOR.json").read_bytes()
            == (root / "authoring/public_binary_write/STDIO_AUTHOR.json").read_bytes(), "stdio author proof differs")
    records.append(process(output, "current-author", [sys.executable, "-I", "-B",
        root / "authoring/public_binary_write/author_current.py", "--source", root,
        "--hepta", args.hepta.resolve(strict=True), "--output", output / "current-authored"], 30))
    for name in ("public_binary_parent_owner", "public_binary_write_body"):
        for suffix in (".hepta", "_composition.json"):
            require((output / "current-authored" / (name + suffix)).read_bytes()
                    == (root / "native" / (name + suffix)).read_bytes(), "whole current owner author differs: " + name)
    records.append(process(output, "base64-author", [sys.executable, "-I", "-B",
        root / "authoring/public_binary_write/author_base64.py", "--source", root,
        "--hepta", args.hepta.resolve(strict=True), "--output", output / "base64-authored"], 30))
    for suffix in (".hepta", "_composition.json"):
        name = "public_binary_base64_decode" + suffix
        require((output / "base64-authored" / name).read_bytes()
                == (root / "native" / name).read_bytes(), "whole current base64 author differs")
    images_root = args.images.resolve(strict=True) if args.images else output / "images"
    if args.images is None:
        records.append(process(output, "original-images", [sys.executable, "-I", "-S", "-B",
            source / "scripts/build_images.py", "--hepta", args.hepta.resolve(strict=True),
            "--retained-bootstrap", args.bootstrap.resolve(strict=True), "--output", images_root], 180))
    images_receipt = json.loads((images_root / "IMAGES.json").read_bytes())
    require(images_receipt["status"] == "FRESH_ACTUAL_B3_COMPILE_PASS"
            and images_receipt["source"] == qualified and images_receipt["compiler"] == compiler,
            "complete original image build source differs")
    members = images_receipt["members"]
    require(set(members) == set(original.IMAGES) | {"linker", "packer"}, "complete twelve-image build required")
    images = []
    for name in original.IMAGES:
        row = members[name]
        manifest = images_root / row["manifest"]
        metadata = json.loads(manifest.read_bytes())
        require(pin(manifest) == row["identity"] and pin(source / row["source_path"]) == row["source"],
                "compiled image source changed: " + name)
        image = manifest.parent / metadata["image"]
        require(pin(image) == row["image"], "compiled original image changed: " + name)
        images.append(image.read_bytes())
    # The old source and complete original twelve-image receipt remain intact.
    # Two demonstrated os.open literals and the current strict-base64 parser
    # differ. Their authors preserve all unchanged functions and a full inverse.
    native = NativeBuild(args.hepta.resolve(strict=True), output / "derived-build")
    retained = args.bootstrap.resolve(strict=True)
    bootstrap_before = inventory(retained)
    copied = output / "derived-build/bootstrap"
    shutil.copytree(retained, copied, copy_function=shutil.copy2)
    require(inventory(copied) == bootstrap_before, "complete copied bootstrap differs")
    compiler_image = native.bootstrap()
    require(pin(compiler_image)["sha256"] == "bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0",
            "actual current owner B3 differs")
    derived = {}
    for name, owner in (("parent", "public_binary_parent_owner"), ("body", "public_binary_write_body"),
                        ("base64", "public_binary_base64_decode")):
        manifest = native.compile(owner, root / "native" / (owner + ".hepta"),
                                  standalone=None, buffer_profile="history.v1")
        metadata = json.loads(manifest.read_bytes())
        image = manifest.parent / metadata["image"]
        images[original.IMAGES.index(name)] = image.read_bytes()
        derived[name] = {"manifest": manifest.relative_to(output).as_posix(),
                         "identity": pin(manifest), "image": pin(image),
                         "source": pin(root / "native" / (owner + ".hepta")),
                         "proof": pin(root / "native" / (owner + "_composition.json"))}
    native._recheck()
    require(inventory(retained) == bootstrap_before == inventory(copied), "bootstrap changed during owner compile")
    assembly = "\n".join((source / name).read_text() for name in original.ASM[:-1])
    assembly += "\n" + (root / "asm/public_binary_write_stdio.S").read_text()
    (output / "combined.S").write_text(flatten(assembly))
    records.extend([
        process(output, "assemble", ["as", "--64", "-o", output / "bridge.o", output / "combined.S"], 30),
        process(output, "relocations", ["readelf", "-r", output / "bridge.o"], 30),
    ])
    require(b"There are no relocations" in (output / "relocations.stdout").read_bytes(), "unresolved native relocations")
    obj = (output / "bridge.o").read_bytes()
    text, symbols = original.object_layout(obj)
    frame = b"HIALNK01" + struct.pack("<3Q", 1, 6, 0) + b"_start" + struct.pack("<Q", len(obj)) + obj
    (output / "link.input.bin").write_bytes(frame)
    row = members["linker"]
    with NativeModule(images_root / row["manifest"], manifest_sha256=row["identity"]["sha256"]) as module:
        code, raw, arena = module.invoke_raw(frame, output_capacity=8 << 20, workspace_capacity=32 << 20)
    (output / "link.output.bin").write_bytes(raw)
    (output / "link.workspace.bin").write_bytes(arena)
    end = 256 + len(text)
    require(code == (end + 4095) & ~4095 and 256 < end <= code <= len(raw), "actual HIA linker extent differs")
    prefix = raw[:code]
    require(prefix[256:end] == text and prefix[end:] == bytes(code - end)
            and raw[code:] == bytes(len(raw) - code), "complete linked text or padding differs")
    require(prefix[:4] == b"\x7fELF" and struct.unpack_from("<Q", prefix, 24)[0] == 4194304 + 232
            and prefix[238] == 0xe8 and 243 + struct.unpack_from("<i", prefix, 239)[0]
            == 256 + symbols["_start"], "actual native entry differs")
    (output / "prefix.elf").write_bytes(prefix)
    # The old fixture's formatter call is replaced by the production helper's
    # identical image call. Every actual parent/body call site remains present.
    missing = {name for name, _ in original.PATCHES if name not in symbols}
    require(missing == {"binary_write_body_error_call_displacement"},
            "unexpected missing original parent/body call site")
    patch_names = tuple(row for row in original.PATCHES if row[0] not in missing)
    patch_names += (("public_binary_write_error_call_displacement", "error"),)
    patches = [(2, 256 + symbols[name], original.IMAGES.index(image)) for name, image in patch_names]
    for _, at, _ in patches:
        require(prefix[at - 1:at + 4] == b"\xe9\0\0\0\0", "fixed HIA call displacement differs")
    frame = b"HIAIMG02" + struct.pack("<4Q", len(prefix), len(images), len(patches), 0) + prefix
    frame += b"".join(struct.pack("<Q", len(image)) for image in images)
    frame += b"".join(struct.pack("<3Q", *patch) for patch in patches) + b"".join(images)
    (output / "pack.input.bin").write_bytes(frame)
    expected, positions = bytearray(prefix), []
    for image in images:
        expected += bytes(-len(expected) % 16)
        positions.append(len(expected))
        expected += image
    text_end = len(expected)
    expected += bytes(-len(expected) % 4096)
    for _, at, index in patches:
        struct.pack_into("<i", expected, at, positions[index] - at - 4)
    struct.pack_into("<QQ", expected, 96, text_end, text_end)
    struct.pack_into("<QQQ", expected, 128, len(expected), 4194304 + len(expected), 4194304 + len(expected))
    row = members["packer"]
    with NativeModule(images_root / row["manifest"], manifest_sha256=row["identity"]["sha256"]) as module:
        packed, raw, arena = module.invoke_raw(frame, output_capacity=32 + len(expected), workspace_capacity=4096,
                                               output_fill=0xb3, workspace_fill=0xc7)
    (output / "pack.output.bin").write_bytes(raw)
    (output / "pack.workspace.bin").write_bytes(arena)
    require(packed == 32 and raw == b"HIAIMR02" + struct.pack("<3Q", 0, len(expected), 0) + expected,
            "actual HIA-packed executable differs")
    executable = output / "public-binary-write.elf"
    executable.write_bytes(raw[32:])
    executable.chmod(0o500)
    require(bindings == {name: pin(root / name) for name in paths}, "public writer source changed during build")
    require(custody.source_evidence(source) == qualified and check_dependency(args.hepta.resolve(strict=True)) == compiler,
            "original parent or compiler source changed during build")
    report = {"schema": "hepta.runtime.public-binary-write.stdio-build.v1", "status": "PASS",
              "source_files": bindings, "original_parent_source": qualified, "compiler": compiler,
              "images_directory": str(images_root), "images_manifest": pin(images_root / "IMAGES.json"),
              "fresh_hia_compilations": 3 if args.images else 15, "runtime_images": list(original.IMAGES),
              "current_derived_owners": derived, "retained_bootstrap": bootstrap_before,
              "processes": records, "patches": patches, "image_offsets": positions,
              "link_return": code, "pack_return": packed, "executable": pin(executable),
              "artifacts": {name: pin(output / name) for name in (
                  "combined.S", "bridge.o", "link.input.bin", "link.output.bin", "link.workspace.bin",
                  "prefix.elf", "pack.input.bin", "pack.output.bin", "pack.workspace.bin")},
              "runtime_python_required": False, "runtime_libc_required": False,
              "original_filesystem_compared": False, "public_binary_write_registered": False,
              "whole_runtime_replaced": False}
    (output / "BUILD.json").write_bytes(encoded(report))
    print(json.dumps({"status": "PASS", "images": len(images), "executable": report["executable"]}, sort_keys=True))


if __name__ == "__main__":
    main()

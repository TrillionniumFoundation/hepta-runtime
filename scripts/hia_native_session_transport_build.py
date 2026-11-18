# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Rebuild four finite session graphs from exact HIA and fixed ABI source.

This is a build driver. Semantic decisions stay in the HIA images. The graph
manifest records historical origins separately from newly executed compilation,
assembly and packing. No public server graph or completion flag is changed.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from hia_native_build import NativeBuild, check_dependency, json_bytes, write_new
from hia_native_loader import NativeModule

GRAPH = "tests/hia_native/session_transport/graph.json"
FOLDER = "session-transport"
COMPILER = "bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0"
COMMIT = "d3e2c90173cf733e42b299d0c4274df4b593a12f"
SCHEMA = "hepta.runtime.session-transport-build.v1"


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path):
    path = Path(path)
    require(path.resolve(strict=True) == path.absolute(), "source or artifact crosses a symlink")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as handle:
        before = os.fstat(handle.fileno())
        require(stat.S_ISREG(before.st_mode), "source or artifact is not a regular file")
        raw = handle.read()
        after = os.fstat(handle.fileno())
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    require(identity(before) == identity(after), "source or artifact changed while reading")
    return raw


def object_at(path):
    def unique(pairs):
        out = {}
        for key, value in pairs:
            require(key not in out, "duplicate JSON member")
            out[key] = value
        return out
    return json.loads(read(path), object_pairs_hook=unique)


def relative(root, name):
    require(type(name) is str and name and not Path(name).is_absolute()
            and all(part not in {"", ".", ".."} for part in name.split("/"))
            and "\\" not in name, "invalid relative artifact path")
    return Path(root) / name


def source_pins(root):
    root = Path(root).absolute()
    graph = object_at(root / GRAPH)
    paths = {GRAPH, "scripts/hia_native_session_transport_build.py"}
    paths.update(graph["sources"])
    for item in graph["graphs"].values():
        paths.add(item["adapter"]["source"])
        paths.update(row["source"] for row in item["packers"])
    return {name: sha(read(relative(root, name))) for name in sorted(paths)}


def elf_prefix(code):
    header = (b"\x7fELF\x02\x01\x01" + bytes(9)
        + struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0x4000b0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
        + struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, 0, 0, 4096)
        + struct.pack("<IIQQQQQQ", 0x6474e551, 6, 0, 0, 0, 0, 0, 16))
    require(len(header) == 176, "ELF prefix header size differs")
    result = header + code
    return result + bytes((-len(result)) % 8)


def compile_evidence(folder, metadata, expected, dependency, build_origin, compiler_path):
    """Read the complete actual compiler input/output and all stdout fields."""
    folder = Path(folder)
    source = read(folder / metadata["source"])
    image = read(folder / metadata["image"])
    require(sha(source) == metadata["source_sha256"] and sha(image) == metadata["image_sha256"],
            "compiled source or flat image changed")
    require(0 < len(source) <= 1 << 20 and 0 < len(image) <= 1 << 20, "module limits changed")
    require(metadata["compiler_commit"] == COMMIT and metadata["compiler_sha256"] == COMPILER
            and metadata["standalone"] is None, "module compiler or transport differs")
    if expected is not None:
        for name in ("source_sha256", "image_sha256", "input_capacity", "output_capacity", "workspace_capacity"):
            require(metadata[name] == expected[name], "module " + name + " differs from the admitted graph")
        require(metadata.get("buffer_profile", "standard") == expected["buffer_profile"]
                and len(source) == expected["source_bytes"]
                and ("image_bytes" not in expected or len(image) == expected["image_bytes"]),
                "module source/image size or buffer profile differs")
    report = object_at(folder / "build.json")
    record = object_at(folder / "module.receipt.json")
    stdout = object_at(folder / "module.stdout.log")
    request = object_at(folder / "module.request.json")
    raw_output = read(folder / "module.output.bin")
    require(report["compile_receipt"] == record and report["compiler_dependency"] == dependency
            and report["whole_runtime_replaced"] is False, "compiler build receipt differs")
    added = {"case", "input_sha256", "input_bytes", "artifact_sha256", "format",
             "runner_sha256", "wall_elapsed_ns", "produced_image", "produced_bytes", "produced_sha256"}
    stdout_fields = {"abi_status", "core_u32", "forbidden_compiler_modules_loaded",
        "image_sha256", "limits", "loader_operations", "native_elapsed_ns",
        "output_sha256", "output_unchanged", "result_u64", "return_encoding",
        "source_sha256", "source_unchanged", "status", "workspace_header"}
    require(set(stdout) == stdout_fields and set(record) == stdout_fields | added
            and all(record[name] == value for name, value in stdout.items()),
            "complete compiler stdout differs from its receipt or exact field set")
    require(record["source_sha256"] == sha(source)
            and record["output_unchanged"] is False
            and record["loader_operations"] ==
                "copy; sealed shared loader or RW-to-RX mmap; fixed ABI call"
            and type(record["native_elapsed_ns"]) is int
            and record["native_elapsed_ns"] >= 0
            and type(record["wall_elapsed_ns"]) is int
            and record["wall_elapsed_ns"] >= record["native_elapsed_ns"],
            "compiler source identity or actual loader observations differ")
    header = record["workspace_header"]
    require(type(header) is dict and set(header) ==
            {"0", "8", "16", "24", "40", "48", "56", "64", "72", "80", "88",
             "96", "104", "112", "224", "248", "1024"}
            and all(type(value) is int and 0 <= value < (1 << 64)
                    for value in header.values())
            and header["0"] == header["24"] == len(source)
            and header["56"] == len(image),
            "complete observed compiler workspace header differs")
    require(read(folder / "module.stderr.log") == b"" and read(folder / "module.input.bin") == source,
            "compiler stderr or complete input differs")
    require(set(request) == {"format", "image", "image_sha256", "source", "source_sha256",
                             "capacity", "workspace_size", "workspace_fill", "output"},
            "compiler request fields differ")
    require(request == {"format": "flat-x86-64", "image": compiler_path,
            "image_sha256": COMPILER, "source": str(Path(build_origin) / "module.input.bin"),
            "source_sha256": sha(source), "capacity": 1 << 20,
            "workspace_size": 1 << 20, "workspace_fill": 0,
            "output": str(Path(build_origin) / "module.output.bin")},
            "actual compiler input or original invocation paths differ")
    require(type(record["abi_status"]) is int and record["abi_status"] == 0
            and type(record["core_u32"]) is int and record["core_u32"] == len(image)
            and type(record["result_u64"]) is int and record["result_u64"] == len(image)
            and record["status"] == "returned" and record["source_unchanged"] is True
            and record["forbidden_compiler_modules_loaded"] == []
            and record["input_bytes"] == len(source) and record["input_sha256"] == sha(source)
            and record["artifact_sha256"] == record["image_sha256"] == COMPILER
            and record["output_sha256"] == sha(raw_output) and len(raw_output) == 1 << 20
            and record["produced_bytes"] == len(image) and record["produced_sha256"] == sha(image)
            and record["produced_image"] == str(Path(build_origin) / "module.image.bin")
            and raw_output[:len(image)] == image and record["format"] == "flat-x86-64"
            and record["return_encoding"] == "zero-extended-u32"
            and record["case"] == "module"
            and record["runner_sha256"] == dependency["files"]["tools/hia_selfhost_child.py"],
            "actual complete compilation result differs")
    require(record["limits"] == {"address_bytes": 268435456, "core_dumpable": False,
            "cpu_seconds": 10, "output_capacity": 1 << 20, "stack_bytes": 8388608,
            "workspace_bytes": 1 << 20}, "compiler resource limits changed")
    return {"source_sha256": sha(source), "image_sha256": sha(image), "image_bytes": len(image),
            "stdout_sha256": sha(read(folder / "module.stdout.log")),
            "receipt_sha256": sha(read(folder / "module.receipt.json"))}


def _inventory(root):
    return {p.relative_to(root).as_posix(): {"sha256": sha(read(p)), "bytes": p.stat().st_size,
            "mode": stat.S_IMODE(p.stat().st_mode)}
            for p in sorted(root.rglob("*")) if p.is_file()}


def build_session_transport(hepta, build_root, source_root):
    root, build_root = Path(source_root).absolute(), Path(build_root).absolute()
    folder = build_root / FOLDER
    require(not folder.exists(), "session graph build is create-only")
    folder.mkdir(parents=True, mode=0o700)
    started = time.monotonic()
    pins = source_pins(root)
    graph = object_at(root / GRAPH)
    require(graph["compiler_commit"] == COMMIT and graph["compiler_sha256"] == COMPILER
            and graph["production_activated"] is graph["whole_runtime_replaced"] is False
            and set(graph["graphs"]) == {"server_message", "worker_owners", "handle_initialize", "local_worker_error"},
            "source graph identity or scope differs")
    builder = NativeBuild(hepta, build_root)
    require(sha(read(builder.bootstrap())) == COMPILER, "compiler generation differs")
    report = {"schema": SCHEMA, "status": "RUNNING", "source_sha256": pins,
        "compiler_dependency": builder.identity, "compiler_path_at_execution": str(builder.compiler),
        "build_origin": str(build_root), "semantic_modules": {}, "packers": {}, "graphs": {},
        "actual_semantic_compile_attempts": 0, "actual_packer_compile_attempts": 0,
        "actual_semantic_compiles": 0, "actual_packer_compiles": 0, "actual_hia_pack_calls": 0,
        "actual_native_semantic_executions": 0, "actual_original_executions": 0,
        "production_activated": False, "whole_runtime_replaced": False}
    try:
        semantic_sources = {name for item in graph["graphs"].values() for name in item["roles"].values()}
        packer_sources = {row["source"] for item in graph["graphs"].values() for row in item["packers"]}
        require(len(semantic_sources) == 38 and len(packer_sources) == 18
                and not semantic_sources & packer_sources
                and set(graph["sources"]) == semantic_sources | packer_sources,
                "complete semantic and packer source domains differ")
        for i, name in enumerate(sorted(semantic_sources)):
            expected = graph["sources"][name]
            source = read(root / name)
            require(sha(source) == expected["source_sha256"] and len(source) == expected["source_bytes"],
                    "canonical semantic source differs")
            report["actual_semantic_compile_attempts"] += 1
            compiled = builder.compile("session-transport-" + str(i), root / name, standalone=None,
                                       buffer_profile=expected["buffer_profile"])
            report["actual_semantic_compiles"] += 1
            metadata = object_at(compiled)
            proof = compile_evidence(compiled.parent, metadata, expected, builder.identity,
                                     str(compiled.parent), str(builder.compiler))
            report["semantic_modules"][name] = {"manifest": compiled.relative_to(build_root).as_posix(),
                "manifest_sha256": sha(read(compiled)), "compile": proof}
        tool_paths = {name: str(Path(shutil.which(name)).resolve(strict=True))
                      for name in ("as", "objcopy", "readelf", "nm")}
        tool_pins = {name: sha(read(path)) for name, path in tool_paths.items()}
        report["assembly_tools"] = {name: {"path": path, "sha256": tool_pins[name]}
                                    for name, path in tool_paths.items()}
        for key, expected in sorted(graph["graphs"].items()):
            out = folder / key
            out.mkdir(mode=0o700)
            source = read(root / expected["adapter"]["source"])
            require(sha(source) == expected["adapter"]["sha256"], "fixed ABI source changed")
            write_new(out / "adapter.S", source)
            commands = []
            def command(tool, arguments, label):
                argv = [tool_paths[tool], *map(str, arguments)]
                begin = time.monotonic()
                with (out / (label + ".stdout")).open("xb") as stdout, (out / (label + ".stderr")).open("xb") as stderr:
                    done = subprocess.run(argv, stdout=stdout, stderr=stderr, timeout=30)
                row = {"tool": tool, "argv": argv, "returncode": done.returncode, "timeout_seconds": 30,
                       "elapsed_seconds": time.monotonic() - begin}
                commands.append(row)
                require(done.returncode == 0 and read(out / (label + ".stderr")) == b"", "fixed ABI assembly failed")
                return read(out / (label + ".stdout"))
            command("as", ["--64", out / "adapter.S", "-o", out / "adapter.o"], "assemble")
            require(b"There are no relocations" in command("readelf", ["-r", out / "adapter.o"], "relocations"),
                    "fixed ABI has a relocation")
            require(command("nm", ["-u", out / "adapter.o"], "undefined") == b"", "fixed ABI has undefined symbols")
            command("objcopy", ["-O", "binary", "--only-section=.text", out / "adapter.o", out / "adapter.bin"], "objcopy")
            symbols = command("nm", ["-n", out / "adapter.o"], "symbols").decode()
            for name, offset in expected["exports"].items():
                matches = re.findall(r"^([0-9a-f]+) [tT] " + re.escape(name) + r"$", symbols, re.M)
                require(len(matches) == 1 and int(matches[0], 16) + 176 == offset, "fixed export offset differs: " + name)
            binary = read(out / "adapter.bin")
            require(len(binary) == expected["adapter"]["assembled_bytes"]
                    and sha(binary) == expected["adapter"]["assembled_sha256"], "fixed ABI code differs")
            prefix = elf_prefix(binary)
            require(len(prefix) == expected["prefix_bytes"] and sha(prefix) == expected["prefix_sha256"],
                    "complete prefix differs")
            images = []
            for role in expected["role_order"]:
                name = expected["roles"][role]
                row = report["semantic_modules"][name]
                manifest = relative(build_root, row["manifest"])
                metadata = object_at(manifest)
                require(expected["call_targets"][role] == len(prefix) + sum(map(len, images)),
                        "full image address differs")
                images.append(read(manifest.parent / metadata["image"]))
            chunks = []
            pack_records = []
            for index, pack in enumerate(expected["packers"]):
                path = root / pack["source"]
                report["actual_packer_compile_attempts"] += 1
                manifest = builder.compile("session-pack-" + key.replace("_", "-") + "-" + str(index),
                                           path, standalone=None)
                report["actual_packer_compiles"] += 1
                metadata = object_at(manifest)
                proof = compile_evidence(manifest.parent, metadata, graph["sources"][pack["source"]], builder.identity,
                                         str(manifest.parent), str(builder.compiler))
                report["packers"][pack["source"]] = {"manifest": manifest.relative_to(build_root).as_posix(),
                    "manifest_sha256": sha(read(manifest)), "compile": proof}
                last = index == len(expected["packers"]) - 1
                if last:
                    pieces = chunks + images
                    wire = struct.pack("<" + str(len(pieces) + 1) + "Q", int.from_bytes(b"HRCMELF1", "little"),
                                       *map(len, pieces)) + b"".join(pieces)
                else:
                    wire = struct.pack("<QQ", int.from_bytes(b"HRCMPFX1", "little"), index)
                require(len(wire) == pack["input_bytes"] and sha(wire) == pack["input_sha256"], "packer input differs")
                write_new(out / ("pack-" + str(index) + ".input"), wire)
                with NativeModule(manifest, manifest_sha256=sha(read(manifest))) as module:
                    code, output, workspace = module.invoke_raw(wire, output_capacity=pack["output_bytes"], workspace_capacity=64)
                report["actual_hia_pack_calls"] += 1
                require(code == pack["return_code"] == len(output) == pack["output_bytes"]
                        and sha(output) == pack["output_sha256"] and workspace == bytes(64), "actual HIA pack result differs")
                write_new(out / ("pack-" + str(index) + ".output"), output)
                write_new(out / ("pack-" + str(index) + ".workspace"), workspace)
                pack_records.append({"source": pack["source"], "return_code": code,
                    "input_sha256": sha(wire), "output_sha256": sha(output), "workspace_sha256": sha(workspace),
                    "input_bytes": len(wire), "output_bytes": len(output)})
                if not last:
                    require(output == prefix[index * 12288:(index + 1) * 12288], "actual prefix chunk differs")
                    chunks.append(output)
            reconstructed = bytearray(prefix)
            size = len(prefix) + sum(map(len, images))
            struct.pack_into("<QQ", reconstructed, 96, size, size)
            for role, hole in expected["call_holes"].items():
                require(prefix[hole - 1:hole + 4] == b"\xe8\0\0\0\0", "call patch is not a declared empty call")
                displacement = expected["call_targets"][role] - hole - 4
                require(displacement == expected["call_displacements"][role], "call displacement differs")
                struct.pack_into("<i", reconstructed, hole, displacement)
            reconstructed += b"".join(images)
            require(output == bytes(reconstructed) and size == expected["artifact"]["bytes"]
                    and sha(output) == expected["artifact"]["sha256"], "complete independently reconstructed ELF differs")
            write_new(out / (key + ".elf"), output, 0o500)
            report["graphs"][key] = {"artifact": (out / (key + ".elf")).relative_to(build_root).as_posix(),
                "artifact_sha256": sha(output), "artifact_bytes": len(output), "exports": expected["exports"],
                "commands": commands, "pack_calls": pack_records, "semantic_images": len(images)}
        builder._recheck()
        require(source_pins(root) == pins and all(sha(read(tool_paths[n])) == v for n, v in tool_pins.items()),
                "build source or assembly tool changed")
        require(report["actual_semantic_compiles"] == 38 and report["actual_packer_compiles"] == 18
                and report["actual_hia_pack_calls"] == 18, "complete four-graph build did not finish")
        report["status"] = "BUILT_NOT_SEMANTICALLY_QUALIFIED"
    except BaseException as error:
        report.update(status="FAIL", error=repr(error))
        raise
    finally:
        report["elapsed_seconds"] = time.monotonic() - started
        write_new(folder / "manifest.json", json_bytes(report))
    return folder / "manifest.json"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--hepta", required=True, type=Path)
    parser.add_argument("--build-root", required=True, type=Path)
    args = parser.parse_args()
    path = build_session_transport(args.hepta, args.build_root, args.root)
    report = object_at(path)
    print(json.dumps({"status": report["status"], "manifest": str(path), "sha256": sha(read(path)),
        "semantic_compiles": report["actual_semantic_compiles"], "packer_compiles": report["actual_packer_compiles"],
        "hia_pack_calls": report["actual_hia_pack_calls"], "actual_semantic_executions": 0,
        "whole_runtime_replaced": False}, sort_keys=True))


if __name__ == "__main__":
    main()

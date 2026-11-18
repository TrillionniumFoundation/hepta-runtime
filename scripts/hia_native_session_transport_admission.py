# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Portable, data-only admission of the four session transport build graphs."""
from __future__ import annotations
from pathlib import Path
import re
import stat
import struct
from hia_native_session_transport_build import (
    GRAPH, SCHEMA, COMMIT, COMPILER, read, sha, object_at, relative, require,
    source_pins, elf_prefix, compile_evidence,
)


def inventory(folder):
    folder = Path(folder)
    result = {}
    for path in sorted(folder.rglob("*")):
        info = path.lstat()
        require(not path.is_symlink(), "build contains a symlink")
        if stat.S_ISDIR(info.st_mode):
            continue
        require(stat.S_ISREG(info.st_mode), "build contains a special file")
        result[path.relative_to(folder).as_posix()] = {
            "bytes": info.st_size, "sha256": sha(read(path)),
            "mode": stat.S_IMODE(info.st_mode),
        }
    return result


def verify_build(manifest, source_root, *, dependency=None):
    """No compilation, assembly, packing or semantic process is started here."""
    manifest = Path(manifest).absolute()
    root = Path(source_root).absolute()
    folder = manifest.parent
    build_root = folder.parent
    require(folder.name == "session-transport" and manifest.name == "manifest.json",
            "unexpected four-graph manifest location")
    report = object_at(manifest)
    graph = object_at(root / GRAPH)
    require(report["schema"] == SCHEMA
            and report["status"] == "BUILT_NOT_SEMANTICALLY_QUALIFIED",
            "session transport build did not complete")
    require(report["production_activated"] is False
            and report["whole_runtime_replaced"] is False
            and report["actual_native_semantic_executions"] == report["actual_original_executions"] == 0,
            "build scope or execution accounting changed")
    require(report["source_sha256"] == source_pins(root), "build source closure changed")
    dep = report["compiler_dependency"]
    require(dep["commit"] == COMMIT
            and dep["tree"] == "8d8b0fb8d015fb7edab302498bb9ed4c74ab6f49",
            "compiler Git identity differs")
    if dependency is not None:
        require(dep == dependency, "current complete compiler source identity differs")
    bootstrap = object_at(build_root / "bootstrap" / "bootstrap.json")
    require(bootstrap["schema"] == "hepta.runtime.native-bootstrap.v1"
            and bootstrap["dependency"] == dep
            and bootstrap["generation_sha256"] == COMPILER
            and bootstrap["qualification"] == "development_fixed_point",
            "retained fixed-point compiler identity differs")
    for generation in ("B1", "B2", "B3"):
        require(sha(read(build_root / "bootstrap" / (generation + ".image.bin"))) == COMPILER,
                "retained compiler generation differs")
    require(report["compiler_path_at_execution"] ==
            str(Path(report["build_origin"]) / "bootstrap/B3.image.bin"),
            "actual compilation used another bootstrap path")
    semantic = {name for item in graph["graphs"].values() for name in item["roles"].values()}
    packers = {row["source"] for item in graph["graphs"].values() for row in item["packers"]}
    require(len(semantic) == 38 and len(packers) == 18 and not semantic & packers
            and set(graph["sources"]) == semantic | packers,
            "source domains are incomplete or overlap")
    require(set(report["semantic_modules"]) == semantic and set(report["packers"]) == packers,
            "compiled module inventory differs")
    require((report["actual_semantic_compile_attempts"], report["actual_semantic_compiles"],
             report["actual_packer_compile_attempts"], report["actual_packer_compiles"],
             report["actual_hia_pack_calls"]) == (38, 38, 18, 18, 18),
            "complete compiler/packer invocation counts differ")
    origin = Path(report["build_origin"])
    require(origin.is_absolute(), "original build origin is not absolute")
    modules = {}
    for role_set, rows in (("semantic", report["semantic_modules"]), ("packer", report["packers"])):
        for name, row in sorted(rows.items()):
            module_manifest = relative(build_root, row["manifest"])
            require(sha(read(module_manifest)) == row["manifest_sha256"],
                    "compiled manifest changed")
            metadata = object_at(module_manifest)
            proof = compile_evidence(
                module_manifest.parent, metadata, graph["sources"][name], dep,
                str(origin / Path(row["manifest"]).parent),
                report["compiler_path_at_execution"],
            )
            require(proof == row["compile"], "complete compiler proof differs")
            modules[name] = read(module_manifest.parent / metadata["image"])
    require(set(report["graphs"]) == set(graph["graphs"]), "four-graph inventory differs")
    packed = 0
    graph_evidence = {}
    for key, expected in sorted(graph["graphs"].items()):
        observed = report["graphs"][key]
        out = folder / key
        original_out = origin / "session-transport" / key
        require(read(out / "adapter.S") == read(root / expected["adapter"]["source"])
                and sha(read(out / "adapter.S")) == expected["adapter"]["sha256"],
                "fixed adapter source changed")
        commands = observed["commands"]
        labels = ("assemble", "relocations", "undefined", "objcopy", "symbols")
        tools = ("as", "readelf", "nm", "objcopy", "nm")
        suffixes = (
            ["--64", str(original_out / "adapter.S"), "-o", str(original_out / "adapter.o")],
            ["-r", str(original_out / "adapter.o")],
            ["-u", str(original_out / "adapter.o")],
            ["-O", "binary", "--only-section=.text",
             str(original_out / "adapter.o"), str(original_out / "adapter.bin")],
            ["-n", str(original_out / "adapter.o")],
        )
        require(len(commands) == 5, "complete assembly command list differs")
        for command, label, tool, suffix in zip(commands, labels, tools, suffixes, strict=True):
            require(command["argv"] == [report["assembly_tools"][tool]["path"], *suffix]
                    and command["tool"] == tool and command["returncode"] == 0
                    and command["timeout_seconds"] == 30
                    and type(command["elapsed_seconds"]) in (int, float)
                    and command["elapsed_seconds"] >= 0
                    and read(out / (label + ".stderr")) == b"",
                    "actual fixed-ABI command or completion differs")
        require(read(out / "assemble.stdout") == read(out / "objcopy.stdout") == b"",
                "assembly emitted unexpected stdout")
        require(b"There are no relocations" in read(out / "relocations.stdout")
                and read(out / "undefined.stdout") == b"",
                "fixed-ABI relocation/undefined admission differs")
        symbols = read(out / "symbols.stdout").decode()
        require(observed["exports"] == expected["exports"], "callable exports differ")
        for name, offset in expected["exports"].items():
            matches = re.findall(r"^([0-9a-f]+) [tT] " + re.escape(name) + r"$", symbols, re.M)
            require(len(matches) == 1 and int(matches[0], 16) + 176 == offset,
                    "complete symbol table differs")
        binary = read(out / "adapter.bin")
        require(len(binary) == expected["adapter"]["assembled_bytes"]
                and sha(binary) == expected["adapter"]["assembled_sha256"],
                "fixed ABI machine bytes changed")
        prefix = elf_prefix(binary)
        require(len(prefix) == expected["prefix_bytes"]
                and sha(prefix) == expected["prefix_sha256"], "complete prefix changed")
        images = []
        for role in expected["role_order"]:
            require(expected["call_targets"][role] == len(prefix) + sum(map(len, images)),
                    "module address is not based on the complete prefix")
            images.append(modules[expected["roles"][role]])
        require(observed["semantic_images"] == len(images), "semantic image count differs")
        require(len(observed["pack_calls"]) == len(expected["packers"]), "pack invocation count differs")
        chunks = []
        for index, (pack, captured) in enumerate(zip(expected["packers"], observed["pack_calls"], strict=True)):
            last = index == len(expected["packers"]) - 1
            pieces = chunks + images
            wire = (struct.pack("<" + str(len(pieces) + 1) + "Q",
                                int.from_bytes(b"HRCMELF1", "little"), *map(len, pieces))
                    + b"".join(pieces)) if last else struct.pack(
                        "<QQ", int.from_bytes(b"HRCMPFX1", "little"), index)
            require(read(out / ("pack-" + str(index) + ".input")) == wire
                    and len(wire) == pack["input_bytes"] and sha(wire) == pack["input_sha256"],
                    "complete pack input differs")
            result = read(out / ("pack-" + str(index) + ".output"))
            workspace = read(out / ("pack-" + str(index) + ".workspace"))
            require(len(result) == pack["return_code"] == pack["output_bytes"]
                    and sha(result) == pack["output_sha256"] and workspace == bytes(64),
                    "complete pack output/workspace differs")
            require(captured == {"source": pack["source"], "return_code": len(result),
                    "input_sha256": sha(wire), "output_sha256": sha(result),
                    "workspace_sha256": sha(workspace), "input_bytes": len(wire),
                    "output_bytes": len(result)}, "captured pack invocation differs")
            if not last:
                require(result == prefix[index * 12288:(index + 1) * 12288],
                        "prefix fragment differs")
                chunks.append(result)
            packed += 1
        reconstructed = bytearray(prefix)
        size = len(prefix) + sum(map(len, images))
        struct.pack_into("<QQ", reconstructed, 96, size, size)
        require(set(expected["call_holes"]) == set(expected["call_displacements"]),
                "declared call patch domain differs")
        for role, hole in expected["call_holes"].items():
            require(prefix[hole - 1:hole + 4] == b"\xe8\0\0\0\0",
                    "call patch is not a declared empty call")
            displacement = expected["call_targets"][role] - hole - 4
            require(displacement == expected["call_displacements"][role],
                    "call displacement differs")
            struct.pack_into("<i", reconstructed, hole, displacement)
        reconstructed += b"".join(images)
        artifact = relative(build_root, observed["artifact"])
        require(artifact == out / (key + ".elf")
                and read(artifact) == result == bytes(reconstructed)
                and len(result) == size == observed["artifact_bytes"] == expected["artifact"]["bytes"]
                and sha(result) == observed["artifact_sha256"] == expected["artifact"]["sha256"],
                "independently reconstructed complete ELF differs")
        graph_evidence[key] = {"bytes": len(result), "sha256": sha(result),
                               "semantic_images": len(images), "exports": expected["exports"],
                               "artifact": artifact}
    require(packed == 18, "not all pack invocations were reconstructed")
    return {"schema": "hepta.runtime.session-transport-build-admission.v1",
            "manifest_sha256": sha(read(manifest)), "source_sha256": source_pins(root),
            "semantic_compiles": 38, "packer_compiles": 18, "hia_pack_calls": 18,
            "graphs": graph_evidence, "new_semantic_executions": 0,
            "production_activated": False, "whole_runtime_replaced": False}

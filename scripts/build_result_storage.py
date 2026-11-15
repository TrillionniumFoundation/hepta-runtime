# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Compile fixed HIA storage owners and inspect every embedded byte in six ELFs."""
from pathlib import Path
import argparse
import copy
import json
import os
import struct
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from result_storage_registry import (
    COMPILER, COMPILER_IMAGE, ORIGINAL, ORIGINAL_SHA, build_sources, encoded,
    manifest_image, profile, regular, require, sha,
)


def source_composition(root, hepta):
    """Check imported IR and its complete call relocation before compilation."""
    root, hepta = Path(root), Path(hepta)
    sys.path.insert(0, str(hepta))
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    fixed = profile(root)
    canonical = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    parsed = {}

    def functions(name):
        if name not in parsed:
            parsed[name] = {f["name"]: f for f in assemble_program(regular(root / name)).as_dict()["functions"]}
        return parsed[name]

    def restored(function, old, reverse):
        value = copy.deepcopy(function)
        value["name"] = old
        for block in value["blocks"]:
            for op in block["ops"]:
                if op["op"] == "call":
                    require(op["attrs"]["function"] in reverse, "import has an undeclared dependency")
                    op["attrs"]["function"] = reverse[op["attrs"]["function"]]
        return value

    from result_storage_words import verify_storage_words
    counts, retention_baseline = verify_storage_words(root, hepta, with_retention_baseline=True)
    for name, stem in fixed["owners"].items():
        path = "native/" + stem + ".hepta"
        proof = json.loads(regular(root / ("native/" + stem + "_composition.json")))
        require(sha(regular(root / path)) == proof["source_sha256"]
            and proof["original_source_sha256"] == ORIGINAL_SHA,
            "frozen owner or original source identity differs")
        actual = functions(path)
        count = 0
        for row in proof["imports"]:
            if "source_derivation" in row:
                # Record IO retains its old imported word helper. Reconstruct its
                # complete source baseline instead of changing that owner or
                # shipping a second obsolete retention implementation.
                require(name == "record_io" and row["source"] == "native/request_retention.hepta"
                    and row["source_derivation"] == "retention-before-ordered-word-helpers"
                    and row["sha256"] == sha(render_assembly(retention_baseline).encode()),
                    "historical import derivation differs")
                old = {f["name"]: f for f in retention_baseline["functions"]}
            else:
                require(sha(regular(root / row["source"])) == row["sha256"], "import source differs")
                old = functions(row["source"])
            reverse = {new: before for before, new in row["relocation"].items()}
            require(len(reverse) == len(row["relocation"]), "duplicate import target")
            for before, after in row["relocation"].items():
                require(sha(canonical(old[before])) == row["functions"][before], "original imported IR differs")
                require(restored(actual[after], before, reverse) == old[before], "import relocation differs")
                count += 1
        children = list(proof.get("children", {}).values())
        if name == "safe_dto":
            require(proof["value_child_source"] == "result_storage_value.hepta",
                "safe DTO private Value child differs")
            children.extend((dict(source="config_result_owner.hepta", sha256=proof["config_child_sha256"]),
                dict(source=proof["value_child_source"], sha256=proof["value_child_sha256"])))
        for row in children:
            require(sha(regular(root / "native" / row["source"])) == row["sha256"], "fixed child source differs")
        counts[name] = count

    # The historical config baseline is bound by its complete source digest and
    # all 48 canonical IR digests. A second obsolete owner need not be shipped.
    proof = json.loads(regular(root / "native/config_result_composition.json"))
    actual = functions("native/config_result_owner.hepta")
    require(sha(regular(root / "native/config_result_owner.hepta")) == proof["source_sha256"]
        and proof["baseline_source_sha256"] == "367ab9bd8dfe6f092653c96d87e3b95211e48babf0977627f01c449bc9a60ce3",
        "configuration projection source differs")
    reverse = {new: before for before, new in proof["relocation"].items()}
    require(len(reverse) == 48 and set(proof["unchanged_functions"]) == set(proof["relocation"]),
        "configuration prior-operation domain differs")
    for before, after in proof["relocation"].items():
        require(sha(canonical(restored(actual[after], before, reverse))) == proof["unchanged_functions"][before],
            "prior configuration operation changed")
    counts["configuration_preserved_functions"] = 48
    require(sha(regular(root / ORIGINAL)) == ORIGINAL_SHA, "original owner changed during composition")
    return counts


def inspect_elf(elf, prefix, images, order, holes):
    expected = bytearray(prefix)
    struct.pack_into("<2Q", expected, 96, len(elf), len(elf))
    offset = len(prefix)
    members = []
    for name in order:
        image = images[name]
        hole = holes[name]
        require(prefix[hole - 1:hole + 4] == b"\xe8\0\0\0\0", "fixed call site is not empty")
        struct.pack_into("<i", expected, hole, offset - hole - 4)
        require(elf[offset:offset + len(image)] == image, "embedded image bytes differ")
        members.append(dict(name=name, offset=offset, bytes=len(image), sha256=sha(image), call_offset=hole))
        offset += len(image)
    require(offset == len(elf) and elf[:len(prefix)] == expected, "fixed ELF prefix or length differs")
    require(struct.unpack_from("<HHIQQQIHHHHHH", elf, 16)
        == (2, 62, 1, 0x4000b0, 64, 0, 0, 64, 56, 2, 0, 0, 0), "ELF header differs")
    require(struct.unpack_from("<IIQQQQQQ", elf, 64)
        == (1, 5, 0, 0x400000, 0x400000, len(elf), len(elf), 4096), "ELF RX segment differs")
    require(struct.unpack_from("<IIQQQQQQ", elf, 120)
        == (0x6474e551, 6, 0, 0, 0, 0, 0, 16), "ELF stack segment differs")
    return members


def pack_graph(root, build, name, graph, paths):
    layout_raw = regular(root / graph["layout"])
    require(sha(layout_raw) == graph["layout_sha256"], "graph layout changed")
    layout = json.loads(layout_raw)
    prefix = bytes.fromhex(layout["prefix_hex"])
    require(sha(prefix) == layout["prefix_sha256"] and len(prefix) == layout["prefix_bytes"],
        "fixed native boundary bytes changed")
    if name == "configuration":
        baseline = layout["original_bundle"]
        order = list(graph["members"])
        holes = {key: row["call_displacement_offset"] for key, row in zip(order, baseline["members"], strict=True)}
        require(len(order) == 11 and len(set(holes.values())) == 11, "configuration image table differs")
    else:
        order = [graph["members"][member] for member in layout["image_order"]]
        holes = {graph["members"][key]: value for key, value in layout["call_holes"].items()}
    images = {key: manifest_image(paths[key])[1] for key in order}
    frame = graph["magic"].encode("ascii") + b"".join(struct.pack("<Q", len(images[key])) for key in order)
    frame += bytes(8 * graph.get("reserved_words", 0))
    frame += b"".join(images[key] for key in order)
    require(len(graph["magic"]) == 8, "invalid fixed packer signature")
    directory = build / "result-storage-graphs" / name
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    (directory / "pack.input.bin").write_bytes(frame)
    packer = paths[graph["packer"]]
    executable = directory / ("result-storage-" + name + ".elf")
    command = [sys.executable, "-I", "-B", str(root / "scripts/result_storage_pack_child.py"),
        "--graph", name, "--manifest", str(packer), "--input", str(directory / "pack.input.bin"),
        "--output", str(executable)]
    start = time.monotonic();timed = False;error = None;code = None
    environment = {key: value for key, value in os.environ.items() if not key.startswith("HIA_")}
    try:
        done = subprocess.run(command, cwd=root, env=environment, capture_output=True, timeout=30)
        stdout, stderr, code = done.stdout, done.stderr, done.returncode
    except subprocess.TimeoutExpired as caught:
        timed = True;stdout, stderr = caught.stdout or b"", caught.stderr or b""
    except OSError as caught:
        stdout, stderr, error = b"", b"", repr(caught)
    receipt = dict(command=command, cwd=str(root), exit_code=code, timed_out=timed,
        start_error=error, timeout_seconds=30, elapsed_seconds=time.monotonic() - start,
        stdout_bytes=len(stdout), stdout_sha256=sha(stdout), stderr_bytes=len(stderr), stderr_sha256=sha(stderr))
    (directory / "pack.stdout").write_bytes(stdout);(directory / "pack.stderr").write_bytes(stderr)
    (directory / "pack-process.json").write_bytes(encoded(receipt))
    require(code == 0 and not timed and error is None and not stderr, "actual native packer process failed")
    observed = json.loads(stdout)
    elf = regular(executable)
    require(observed["input_sha256"] == sha(frame) and observed["output_sha256"] == sha(elf)
        and observed["source_unchanged"] is True and observed["forbidden_compiler_modules_loaded"] == [],
        "actual native packer custody failed")
    members = inspect_elf(elf, prefix, images, order, holes)
    executable.chmod(0o700)
    manifest = dict(schema="hepta.result-storage.static-graph.v1", name=name,
        executable=executable.name, executable_sha256=sha(elf), executable_bytes=len(elf),
        prefix_sha256=sha(prefix), prefix_bytes=len(prefix), members=members,
        layout_sha256=sha(layout_raw), packer_manifest=str(packer.relative_to(build)),
        packer_manifest_sha256=sha(regular(packer)), input_bytes=len(frame), input_sha256=sha(frame),
        runtime_rust_required=False, runtime_python_required=False, runtime_libc_required=False,
        actual_hia_packer_calls=1, production_activated=False, public_request_dispatch_qualified=False)
    target = directory / "manifest.json"
    target.write_bytes(encoded(manifest))
    return dict(path=str(target.relative_to(build)), sha256=sha(regular(target)))


def build_storage(root, hepta, build_root):
    from hia_native_build import NativeBuild
    root = Path(root).resolve(strict=True)
    build = Path(build_root).resolve()
    target = build / "result-storage-build.json"
    require(not target.exists(), "result storage build already exists")
    before = build_sources(root)
    fixed = profile(root)
    compiler = NativeBuild(Path(hepta).resolve(strict=True), build)
    compiler.bootstrap()
    composition = source_composition(root, compiler.hepta)
    paths, modules = {}, {}
    for name, row in fixed["modules"].items():
        source = regular(root / row["source"])
        require((len(source), sha(source)) == (row["source_bytes"], row["source_sha256"]), "native source differs")
        path = compiler.compile("storage-" + name.replace("_", "-"), root / row["source"],
            standalone=row["standalone"], buffer_profile=row["buffer_profile"])
        metadata, image, digest = manifest_image(path)
        require(metadata["source_sha256"] == row["source_sha256"] and sha(image) == row["image_sha256"],
            "compiled image differs from the exact observed owner")
        require(metadata.get("buffer_profile", "standard") == row["buffer_profile"], "module capacity profile differs")
        paths[name] = path
        modules[name] = dict(path=str(path.relative_to(build)), sha256=digest,
            source_sha256=row["source_sha256"], image_sha256=sha(image), image_bytes=len(image))
    graphs = {name: pack_graph(root, build, name, row, paths) for name, row in fixed["graphs"].items()}
    compiler._recheck()
    require(build_sources(root) == before, "source changed during storage build")
    result = dict(schema="hepta.result-storage.native-build.v1", sources=before, modules=modules,
        graphs=graphs, composition=composition, compiler_commit=COMPILER, compiler_sha256=COMPILER_IMAGE,
        actual_native_images=len(modules), actual_static_graphs=len(graphs),
        actual_native_packer_calls=len(graphs), actual_original_executions=0,
        fresh_cold_qualified=False, whole_runtime_replaced=False, result_storage_closed=False,
        production_activated=False, public_request_dispatch_qualified=False)
    target.write_bytes(encoded(result))
    return target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta", type=Path, required=True)
    parser.add_argument("--build-root", type=Path, required=True)
    args = parser.parse_args()
    target = build_storage(Path(__file__).resolve().parents[1], args.hepta, args.build_root)
    print(json.dumps(dict(build=str(target), modules=30, static_graphs=6, actual_original_executions=0)))


if __name__ == "__main__":
    main()

"""Build the fixed five-image HIA/Linux asynchronous effect-fence owner.

This is a build and evidence driver. The executable contains only native HIA
images and the frozen syscall/lifecycle adapter emitted by the HIA packer.
No assembler, host semantic dispatcher, Rust or Python runtime is used by it.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from hia_native_build import ABI, NativeBuild, json_bytes, write_new

PROFILE = "native/effect_fence_profile.json"
MEMBER_SOURCES = ("native/effect_owner_fence.hepta", "native/effect_fence_fs.hepta",
                  "native/fence_json.hepta", "native/binary_codec.hepta",
                  "native/effect_fence_manager.hepta")
COMPILE_FILES = ("build.json", "module.input.bin", "module.output.bin", "module.request.json",
                 "module.receipt.json", "module.stdout.log", "module.stderr.log")
OBSERVER_FIELDS = frozenset(("status", "result_u64", "abi_status", "return_encoding", "core_u32",
    "source_sha256", "image_sha256", "output_sha256", "source_unchanged", "output_unchanged",
    "workspace_header", "native_elapsed_ns", "forbidden_compiler_modules_loaded", "loader_operations", "limits"))


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def require(condition, message: str) -> None:
    if not condition:
        raise ValueError(message)


def relative(root: Path, name: str) -> Path:
    require(type(name) is str and name and not Path(name).is_absolute()
            and ".." not in Path(name).parts, "effect fence artifact path differs")
    path = root / name
    require(path.resolve(strict=True).is_relative_to(root.resolve(strict=True))
            and not path.is_symlink(), "effect fence artifact escapes its directory")
    return path


def receipt(receipt_data: dict, input_raw: bytes, output_raw: bytes, image: bytes, compiler: str) -> None:
    count = receipt_data.get("core_u32")
    require(receipt_data.get("status") == "returned" and type(receipt_data.get("abi_status")) is int
            and receipt_data["abi_status"] == 0 and type(count) is int and count == len(image)
            and type(receipt_data.get("result_u64")) is int and receipt_data["result_u64"] == count
            and receipt_data.get("source_unchanged") is True
            and type(receipt_data.get("input_bytes")) is int and receipt_data["input_bytes"] == len(input_raw)
            and receipt_data.get("input_sha256") == sha(input_raw)
            and receipt_data.get("artifact_sha256") == compiler
            and receipt_data.get("output_sha256") == sha(output_raw)
            and receipt_data.get("forbidden_compiler_modules_loaded") == []
            and output_raw[:count] == image, "effect fence native receipt differs")


def process_stdout(report: dict, raw: bytes, *, capacity: int, workspace: int) -> None:
    """Bind every field printed by the pinned native child, not a subset."""
    value = json.loads(raw)
    require(type(value) is dict and set(value) == OBSERVER_FIELDS,
            "effect fence native process stdout fields differ")
    require(json_bytes(value) == json_bytes({key: report.get(key) for key in OBSERVER_FIELDS})
            and value["source_sha256"] == report.get("input_sha256")
            and value["image_sha256"] == report.get("artifact_sha256")
            and value["return_encoding"] == "zero-extended-u32"
            and value["output_unchanged"] is False
            and type(value["native_elapsed_ns"]) is int and value["native_elapsed_ns"] >= 0
            and value["loader_operations"] == "copy; sealed shared loader or RW-to-RX mmap; fixed ABI call",
            "effect fence native process stdout differs")
    require(json_bytes(value["limits"]) == json_bytes({"cpu_seconds": 10, "address_bytes": 256 << 20,
            "core_dumpable": False, "stack_bytes": 8 << 20, "output_capacity": capacity,
            "workspace_bytes": workspace}), "effect fence native process limits differ")
    header = value["workspace_header"]
    require(type(header) is dict and set(header) == {str(i) for i in
            (0, 8, 16, 24, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 224, 248, 1024)}
            and all(type(word) is int and 0 <= word < 1 << 64 for word in header.values()),
            "effect fence native process workspace observation differs")


def module_evidence(path: Path, expected_source: bytes, build: NativeBuild) -> tuple[dict, bytes, dict]:
    data = json.loads(path.read_bytes())
    source = relative(path.parent, data.get("source")).read_bytes()
    image = relative(path.parent, data.get("image")).read_bytes()
    required = {"schema": "hepta.runtime.native-module.v1", "abi": ABI, "target": "linux-x86_64",
                "compiler_commit": build.identity["commit"], "compiler_sha256": build.compiler_sha256,
                "source_sha256": sha(expected_source), "image_sha256": sha(image),
                "input_capacity": 8 << 20, "output_capacity": 8 << 20,
                "workspace_capacity": 32 << 20, "qualification": "development_fixed_point", "standalone": None}
    require(source == expected_source and all(data.get(k) == v for k, v in required.items())
            and "buffer_profile" not in data and 0 < len(image) <= 1 << 20,
            "effect fence compiled module differs")
    records = {name: relative(path.parent, name).read_bytes() for name in COMPILE_FILES}
    build_data = json.loads(records["build.json"])
    report = json.loads(records["module.receipt.json"])
    require(build_data.get("compiler_dependency") == build.identity
            and build_data.get("compile_receipt") == report
            and build_data.get("whole_runtime_replaced") is False,
            "effect fence compiler source custody differs")
    require(report.get("runner_sha256") == build.identity["files"].get("tools/hia_selfhost_child.py"),
            "effect fence native compiler observer differs")
    require(records["module.input.bin"] == source and records["module.stderr.log"] == b"",
            "effect fence compile input or process stderr differs")
    receipt(report, source, records["module.output.bin"], image, build.compiler_sha256)
    require(report.get("produced_bytes") == len(image) and report.get("produced_sha256") == sha(image)
            and report.get("source_sha256") == sha(source), "effect fence compiler output differs")
    process_stdout(report, records["module.stdout.log"], capacity=1 << 20, workspace=1 << 20)
    request = json.loads(records["module.request.json"])
    require(request.get("format") == "flat-x86-64"
            and request.get("image_sha256") == build.compiler_sha256
            and request.get("source_sha256") == sha(source)
            and request.get("capacity") == 1 << 20 and request.get("workspace_size") == 1 << 20,
            "effect fence compiler invocation contract differs")
    inventory = {name: {"bytes": len(raw), "sha256": sha(raw)} for name, raw in records.items()}
    return data, image, inventory


def inspect_embedded(elf: bytes, images: list[bytes], profile: dict, selected: dict) -> None:
    require(len(elf) == selected["elf_bytes"] and sha(elf) == selected["elf_sha256"],
            "effect fence executable identity differs")
    prefix_size = profile["prefix_bytes"]
    normalized = bytearray(elf[:prefix_size])
    require(elf[:7] == b"\x7fELF\x02\x01\x01" and struct.unpack_from("<HH", elf, 16) == (2, 62)
            and struct.unpack_from("<Q", elf, 24)[0] == 0x4000b0
            and struct.unpack_from("<QQ", elf, 96) == (len(elf), len(elf)),
            "effect fence ELF entry or segment size differs")
    struct.pack_into("<QQ", normalized, 96, 0, 0)
    cursor = prefix_size
    for member, image in zip(profile["members"], images):
        hole = member["call_displacement_offset"]
        require(member["offset"] == cursor and len(image) == member["image_bytes"]
                and sha(image) == member["image_sha256"]
                and elf[cursor:cursor + len(image)] == image
                and 1 <= hole and hole + 4 <= prefix_size and elf[hole - 1] == 0xe8
                and struct.unpack_from("<i", elf, hole)[0] == cursor - hole - 4,
                "effect fence embedded native image or call target differs")
        normalized[hole:hole + 4] = bytes(4)
        cursor += len(image)
    require(cursor == len(elf) and sha(bytes(normalized)) == selected["prefix_sha256"],
            "effect fence fixed adapter prefix differs")


def verify_sha_import(packer: bytes, codec: bytes, selected: dict) -> None:
    from hepta.hia_agent_assembly import assemble_program
    proof = selected["sha_import"]
    require(proof.get("source") == "native/binary_codec.hepta" and proof.get("source_sha256") == sha(codec)
            and proof.get("allowed_changes") == "function names and direct-call targets only",
            "effect fence SHA import owner differs")
    old = {fn["name"]: fn for fn in assemble_program(codec).as_dict()["functions"]}
    new = {fn["name"]: fn for fn in assemble_program(packer).as_dict()["functions"]}
    relocation = proof["relocation"]
    require(set(relocation) == {"f17", "f9", "f10", "f21", "f19", "f20", "f22"},
            "effect fence SHA imported closure differs")
    for source, target in relocation.items():
        function = copy.deepcopy(old[source])
        require(sha(json.dumps(function, sort_keys=True, separators=(",", ":")).encode())
                == proof["original_functions_sha256"].get(source), "effect fence SHA original function differs")
        function["name"] = target
        for block in function["blocks"]:
            for op in block["ops"]:
                if op["op"] == "call":
                    op["attrs"]["function"] = relocation[op["attrs"]["function"]]
        require(new.get(target) == function, "effect fence SHA closure changed beyond direct relocation")


def build_effect_fence(hepta: Path, build_root: Path, *, source_root: Path = ROOT,
                       queue_fixture: bool = False) -> Path:
    source_root = Path(source_root).resolve(strict=True)
    build = NativeBuild(hepta, build_root)
    build.bootstrap()
    profile_raw = (source_root / PROFILE).read_bytes()
    profile = json.loads(profile_raw)
    selection = "queue_fixture" if queue_fixture else "production"
    selected = profile["profiles"][selection]
    require(profile.get("schema") == "hepta.runtime.effect-fence-profile.v1"
            and profile.get("compiler_commit") == build.identity["commit"]
            and profile.get("compiler_sha256") == build.compiler_sha256
            and selected.get("worker_limit") == (1 if queue_fixture else 512)
            and len(profile.get("members", [])) == 5
            and [m.get("id") for m in profile["members"]] == list(range(5))
            and tuple(m.get("source") for m in profile["members"]) == MEMBER_SOURCES,
            "effect fence frozen native profile differs")
    paths = [*MEMBER_SOURCES, selected["packer_source"]]
    sources = {name: relative(source_root, name).read_bytes() for name in paths}
    for member in profile["members"]:
        require(sha(sources[member["source"]]) == member["source_sha256"], "effect fence owner source differs")
    require(sha(sources[paths[-1]]) == selected["packer_source_sha256"], "effect fence packer source differs")
    verify_sha_import(sources[paths[-1]], sources[MEMBER_SOURCES[3]], selected)
    key = sha(profile_raw + selection.encode() + b"".join(sources[name] for name in paths))
    destination = Path(build_root).resolve() / "effect-fence" / key
    manifest_path = destination / "manifest.json"
    from tools.qualify_hia_selfhost_cli import inspect_executable

    def verify_completed() -> None:
        data = json.loads(manifest_path.read_bytes())
        expected = {"schema": "hepta.runtime.native-effect-fence.v1", "target": "linux-x86_64",
            "compiler_commit": build.identity["commit"], "compiler_sha256": build.compiler_sha256,
            "profile": selection, "profile_sha256": sha(profile_raw), "worker_limit": selected["worker_limit"],
            "fixture_pool_profile": queue_fixture, "executable": "effect-fence-async.elf",
            "elf_sha256": selected["elf_sha256"], "elf_bytes": selected["elf_bytes"],
            "prefix_bytes": profile["prefix_bytes"], "packer_manifest": "packer/manifest.json",
            "runtime_python_required": False, "runtime_libc_required": False,
            "fresh_cold_qualified": False, "registered_mcp_tool": False, "production_activated": False,
            "whole_runtime_replaced": False, "complete_effect_fence_owner": False}
        require(all(data.get(k) == v for k, v in expected.items()), "effect fence completed manifest contract differs")
        require(relative(destination, "profile.json").read_bytes() == profile_raw
                and len(data.get("members", [])) == 5, "effect fence retained profile differs")
        images = []
        for index, frozen in enumerate(profile["members"]):
            member = data["members"][index]
            require(all(member.get(k) == v for k, v in frozen.items())
                    and member.get("manifest") == f"member{index}/manifest.json",
                    "effect fence completed member contract differs")
            path = relative(destination, member["manifest"])
            require(sha(path.read_bytes()) == member.get("manifest_sha256"), "effect fence member manifest differs")
            module, image, inventory = module_evidence(path, sources[paths[index]], build)
            require(member.get("compile_files") == inventory
                    and module["image_sha256"] == frozen["image_sha256"], "effect fence member evidence differs")
            images.append(image)
        packer_path = relative(destination, data["packer_manifest"])
        packer, packer_image, inventory = module_evidence(packer_path, sources[paths[-1]], build)
        require(data.get("packer_manifest_sha256") == sha(packer_path.read_bytes())
                and data.get("packer_image_sha256") == sha(packer_image)
                and data.get("packer_source_sha256") == sha(sources[paths[-1]])
                and data.get("packer_compile_files") == inventory, "effect fence packer evidence differs")
        frame = b"HFFPACK2" + b"".join(struct.pack("<Q", len(image)) for image in images) + bytes(16) + b"".join(images)
        require(relative(destination, "pack.input.bin").read_bytes() == frame, "effect fence actual pack input differs")
        elf = relative(destination, data["executable"]).read_bytes()
        output = relative(destination, "pack.output.bin").read_bytes()
        report = json.loads(relative(destination, "pack.receipt.json").read_bytes())
        require(data.get("pack_receipt") == report and data.get("pack_input_sha256") == sha(frame),
                "effect fence retained packer receipt differs")
        require(report.get("runner_sha256") == build.identity["files"].get("tools/hia_selfhost_child.py"),
                "effect fence native packing observer differs")
        receipt(report, frame, output, elf, sha(packer_image))
        request = json.loads(relative(destination, "pack.request.json").read_bytes())
        require(request.get("capacity") == len(elf) and request.get("workspace_size") == 4096
                and request.get("source_sha256") == sha(frame)
                and request.get("image_sha256") == sha(packer_image)
                and relative(destination, "pack.stderr.log").read_bytes() == b"",
                "effect fence actual packer process differs")
        process_stdout(report, relative(destination, "pack.stdout.log").read_bytes(),
                       capacity=len(elf), workspace=4096)
        inspect_embedded(elf, images, profile, selected)
        require(inspect_executable(elf) == data.get("inspection"), "effect fence ELF inspection differs")
        require((source_root / PROFILE).read_bytes() == profile_raw
                and all((source_root / name).read_bytes() == raw for name, raw in sources.items()),
                "effect fence source changed during build")
        build._recheck()

    if manifest_path.exists():
        verify_completed()
        return manifest_path

    compiled = []
    for index, name in enumerate(paths):
        label = "fence-owner-" + str(index) + "-" + sha(sources[name])[:16]
        path = build.root / "modules" / label / "manifest.json"
        if not path.exists():
            path = build.compile(label, source_root / name, standalone=None)
        module, image, inventory = module_evidence(path, sources[name], build)
        if index < 5:
            require(module["image_sha256"] == profile["members"][index]["image_sha256"],
                    "effect fence fresh native compiler image differs from the exact profile")
        compiled.append((path, module, image, inventory))
    destination.mkdir(parents=True, mode=0o700)
    write_new(destination / "profile.json", profile_raw)
    members = []
    for index, (path, module, image, inventory) in enumerate(compiled):
        folder = destination / (f"member{index}" if index < 5 else "packer")
        folder.mkdir(mode=0o700)
        for filename in ("manifest.json", module["source"], module["image"], *COMPILE_FILES):
            write_new(folder / filename, relative(path.parent, filename).read_bytes())
        if index < 5:
            members.append(dict(profile["members"][index], manifest=f"member{index}/manifest.json",
                manifest_sha256=sha(path.read_bytes()), compile_files=inventory))
    images = [item[2] for item in compiled[:5]]
    frame = b"HFFPACK2" + b"".join(struct.pack("<Q", len(image)) for image in images) + bytes(16) + b"".join(images)
    from tools.qualify_hia_selfhost import invoke
    packer_path = destination / "packer" / compiled[5][1]["image"]
    report, output = invoke(destination, "pack", packer_path, frame,
                            capacity=selected["elf_bytes"], workspace_size=4096)
    count = report.get("core_u32")
    require(type(count) is int and count == selected["elf_bytes"], "effect fence HIA packer refused")
    elf = output[:count]
    receipt(report, frame, output, elf, sha(compiled[5][2]))
    inspect_embedded(elf, images, profile, selected)
    inspection = inspect_executable(elf)
    write_new(destination / "effect-fence-async.elf", elf, 0o500)
    data = {"schema": "hepta.runtime.native-effect-fence.v1", "target": "linux-x86_64",
        "compiler_commit": build.identity["commit"], "compiler_sha256": build.compiler_sha256,
        "profile": selection, "profile_sha256": sha(profile_raw), "worker_limit": selected["worker_limit"],
        "fixture_pool_profile": queue_fixture, "executable": "effect-fence-async.elf",
        "elf_sha256": sha(elf), "elf_bytes": len(elf), "prefix_bytes": profile["prefix_bytes"],
        "members": members, "packer_manifest": "packer/manifest.json",
        "packer_manifest_sha256": sha((destination / "packer/manifest.json").read_bytes()),
        "packer_source_sha256": sha(sources[paths[-1]]), "packer_image_sha256": sha(compiled[5][2]),
        "packer_compile_files": compiled[5][3], "inspection": inspection,
        "pack_receipt": report, "pack_input_sha256": sha(frame),
        "runtime_python_required": False, "runtime_libc_required": False,
        "fresh_cold_qualified": False, "registered_mcp_tool": False, "production_activated": False,
        "whole_runtime_replaced": False, "complete_effect_fence_owner": False}
    write_new(manifest_path, json_bytes(data))
    verify_completed()
    return manifest_path


def build_effect_fence_bundle(hepta: Path, build_root: Path, *, source_root: Path = ROOT) -> Path:
    """Retain the production owner and the immutable one-worker test profile."""
    build_root = Path(build_root).resolve()
    paths = {"production": build_effect_fence(hepta, build_root, source_root=source_root),
             "queue_fixture": build_effect_fence(hepta, build_root, source_root=source_root, queue_fixture=True)}
    rows = {name: {"manifest": str(path.relative_to(build_root)), "manifest_sha256": sha(path.read_bytes()),
                  "executable_sha256": json.loads(path.read_bytes())["elf_sha256"]}
            for name, path in paths.items()}
    selected = json.loads(paths["production"].read_bytes())
    data = {"schema": "hepta.runtime.effect-fence-bundle.v1", "compiler_commit": selected["compiler_commit"],
            "compiler_sha256": selected["compiler_sha256"], "profile_sha256": selected["profile_sha256"],
            "members": rows, "production_activated": False, "whole_runtime_replaced": False}
    raw = json_bytes(data)
    folder = build_root / "effect-fence-bundles" / sha(raw)
    path = folder / "manifest.json"
    if path.exists():
        require(path.read_bytes() == raw, "effect fence retained bundle differs")
    else:
        folder.mkdir(parents=True, mode=0o700)
        write_new(path, raw)
    return path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta", type=Path, default=os.environ.get("HIA_HEPTA_DIR"))
    parser.add_argument("--build-root", type=Path, default=os.environ.get("HIA_BUILD_ROOT"))
    parser.add_argument("--queue-fixture", action="store_true")
    parser.add_argument("--bundle", action="store_true")
    args = parser.parse_args()
    if not args.hepta or not args.build_root:
        parser.error("--hepta and --build-root or their HIA environment variables are required")
    if args.bundle and args.queue_fixture:
        parser.error("--bundle and --queue-fixture are mutually exclusive")
    path = (build_effect_fence_bundle(args.hepta, args.build_root) if args.bundle else
            build_effect_fence(args.hepta, args.build_root, queue_fixture=args.queue_fixture))
    print(json.dumps({"manifest": str(path)}))

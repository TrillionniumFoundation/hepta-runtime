"""Build the HIA foreground file-IO owner and its fixed Linux capability fixture.

The shared process build utilities provide byte hashing, immutable buffer capture,
ELF inspection and recorded assembler invocation only; they choose no IO outcome.
All source paths are explicit and sealed. Readers never execute native code.
"""
from __future__ import annotations
import argparse
import json
import os
import re
import struct
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from hia_native_build import NativeBuild, json_bytes, write_new
from hia_native_loader import NativeModule
from hia_native_shell_process_build import (
    sha, inspect_fixed_executable, strict_json, ordinary, pin, member,
    tool_process, invocation_cases, invoke_recorded, CONTROL_NAMES, GUARDS,
)
INPUTS = (
    "native/shell_output_io.hepta", "native/shell_output_packer.hepta",
    "native/shell_output_layout.json", "scripts/shell_output_adapter.S",
)
PRODUCERS = (
    "native/shell_output_io_abi.md", "native/shell_output_fixture.md",
    "scripts/hia_native_shell_output_build.py", "scripts/hia_native_shell_process_build.py",
    "scripts/hia_native_loader.py", "scripts/hia_native_build.py",
)
SCOPE = {
    "production_activated": False, "production_shell_execution_qualified": False,
    "whole_runtime_replaced": False, "old_stack_removal_qualified": False,
}

def build_shell_output(
    hepta: Path, build_root: Path, *, source_root: Path = ROOT
) -> Path:
    hepta = hepta.resolve(strict=True)
    source_root = source_root.resolve(strict=True)
    build_root = build_root.resolve()
    source_bytes = {name: ordinary(source_root / name) for name in INPUTS + PRODUCERS}
    layout = strict_json(source_bytes["native/shell_output_layout.json"])
    if layout.get("schema") != "hepta.runtime.shell-output-layout.v1":
        raise ValueError("shell process adapter layout schema differs")
    image_offset = layout.get("image_offset")
    if type(image_offset) is not int or image_offset < 176 or image_offset % 16:
        raise ValueError("shell process image offset is invalid")
    adapter_source = source_bytes["scripts/shell_output_adapter.S"]
    if layout.get("adapter_source_sha256") != sha(adapter_source):
        raise ValueError("shell process adapter source differs from layout")
    folder = build_root / "shell-output"
    folder.mkdir(parents=True, exist_ok=False, mode=0o700)
    for relative, raw in source_bytes.items():
        destination = member(folder / "source-snapshots", relative)
        destination.parent.mkdir(parents=True, exist_ok=True)
        write_new(destination, raw)
    (folder / "tools").mkdir()

    build = NativeBuild(hepta, build_root)
    compiler_sha = sha(build.bootstrap().read_bytes())

    def component(name: str, relative_source: str) -> Path:
        path = build.compile(
            name, folder / "source-snapshots" / relative_source, standalone=None
        )
        metadata = strict_json(ordinary(path))
        if (metadata.get("source_sha256") != sha(source_bytes[relative_source])
                or metadata.get("compiler_sha256") != compiler_sha):
            raise ValueError("actual native component differs from sealed input")
        return path

    owner = component("shell-output", "native/shell_output_io.hepta")
    packer = component("shell-output-packer", "native/shell_output_packer.hepta")
    owner_metadata = strict_json(ordinary(owner))
    image = ordinary(owner.parent / owner_metadata["image"])
    if sha(image) != owner_metadata["image_sha256"]:
        raise ValueError("shell process owner image differs")
    total = image_offset + len(image)
    with NativeModule(packer, manifest_sha256=sha(ordinary(packer))) as module:
        executable = b""
        for name, wire, capacity, expected in invocation_cases(image, total):
            actual = invoke_recorded(module, folder, name, wire, capacity, expected)
            if name == "success":
                executable = actual
    if (len(executable) != total or executable[image_offset:] != image
            or struct.unpack_from("<Q", executable, 96)[0] != total
            or struct.unpack_from("<Q", executable, 104)[0] != total):
        raise ValueError("shell process embedded owner or ELF extent differs")

    source = folder / "source-snapshots/scripts/shell_output_adapter.S"
    obj = folder / "adapter.o"
    binary = folder / "adapter.bin"
    tool_process(folder, "as", ["--64", "-o", str(obj), str(source)], [source], [obj])
    tool_process(folder, "objcopy", ["-O", "binary", "-j", ".text", str(obj), str(binary)],
                 [obj], [binary])
    adapter_image = ordinary(binary)
    if (adapter_image[-1:] != b"\0" or len(adapter_image) != image_offset - 176 + 1
            or sha(adapter_image[:-1]) != layout.get("adapter_image_sha256")
            or executable[176:image_offset] != adapter_image[:-1]):
        raise ValueError("source-owned syscall adapter differs from HIA-packed bytes")

    from tools.qualify_hia_selfhost_cli import inspect_executable
    inspection = inspect_executable(executable)
    if inspection != inspect_fixed_executable(executable):
        raise ValueError("independent fixed ELF inspection differs")
    write_new(folder / "shell-output.elf", executable, 0o500)
    evidence_files = {}
    for path in sorted(folder.rglob("*")):
        if path.is_file() and path.name != "shell-output.elf":
            evidence_files[str(path.relative_to(folder))] = pin(path)
    evidence = {
        "schema": "hepta.runtime.shell-output-build-evidence.v1", "status": "PASS",
        "producer_folder": str(folder), "source_files": {
            name: {"size": len(raw), "sha256": sha(raw)} for name, raw in source_bytes.items()},
        "tool_receipts": ["tools/as.json", "tools/objcopy.json"],
        "packer_cases": list(CONTROL_NAMES), "files": evidence_files, **SCOPE,
    }
    write_new(folder / "build-evidence.json", json_bytes(evidence))
    metadata = {
        "schema": "hepta.runtime.shell-output.v1", "target": "linux-x86_64",
        "elf": "shell-output.elf", "elf_sha256": sha(executable), "image_offset": image_offset,
        "owner_manifest": str(owner.relative_to(build_root)),
        "owner_manifest_sha256": sha(ordinary(owner)),
        "owner_source_sha256": owner_metadata["source_sha256"], "owner_image_sha256": sha(image),
        "packer_manifest": str(packer.relative_to(build_root)),
        "packer_manifest_sha256": sha(ordinary(packer)),
        "adapter_source_sha256": sha(adapter_source),
        "adapter_image_sha256": sha(adapter_image[:-1]),
        "layout_sha256": sha(source_bytes["native/shell_output_layout.json"]),
        "source_sha256": {name: sha(source_bytes[name]) for name in INPUTS},
        "compiler_commit": owner_metadata["compiler_commit"],
        "compiler_sha256": owner_metadata["compiler_sha256"],
        "effect_abi": "HSHOIFX1", "prepared_capture_required": True,
        "raw_fd_or_pid_input_allowed": False, "runtime_python_required": False,
        "runtime_libc_required": False,
        "fixture_argv": ["--output-fixture", "CAPTURE_DIRECTORY"], "inspection": inspection,
        "build_evidence": "build-evidence.json",
        "build_evidence_sha256": sha(ordinary(folder / "build-evidence.json")), **SCOPE,
    }
    if any(ordinary(source_root / name) != raw for name, raw in source_bytes.items()):
        raise ValueError("shell process build input changed")
    build._recheck()
    path = folder / "manifest.json"
    write_new(path, json_bytes(metadata))
    read_evidence(path, source_root=source_root)
    return path


def read_evidence(manifest: Path, *, source_root: Path | None = ROOT) -> dict:
    """Purely read sealed bytes; explicit None selects portable byte verification."""
    manifest = manifest.absolute()
    ordinary(manifest)
    folder = manifest.parent
    metadata = strict_json(ordinary(manifest))
    if (type(metadata) is not dict or metadata.get("schema") != "hepta.runtime.shell-output.v1"
            or metadata.get("target") != "linux-x86_64" or metadata.get("elf") != "shell-output.elf"
            or metadata.get("compiler_commit") != "d3e2c90173cf733e42b299d0c4274df4b593a12f"
            or metadata.get("effect_abi") != "HSHOIFX1"
            or metadata.get("prepared_capture_required") is not True
            or metadata.get("raw_fd_or_pid_input_allowed") is not False
            or metadata.get("runtime_python_required") is not False
            or metadata.get("runtime_libc_required") is not False
            or any(metadata.get(key) is not value for key, value in SCOPE.items())):
        raise ValueError("native build manifest identity or scope differs")
    evidence_raw = ordinary(member(folder, metadata["build_evidence"]))
    if sha(evidence_raw) != metadata["build_evidence_sha256"]:
        raise ValueError("build evidence changed")
    evidence = strict_json(evidence_raw)
    if (type(evidence) is not dict
            or evidence.get("schema") != "hepta.runtime.shell-output-build-evidence.v1"
            or evidence.get("status") != "PASS"
            or evidence.get("packer_cases") != list(CONTROL_NAMES)
            or evidence.get("tool_receipts") != ["tools/as.json", "tools/objcopy.json"]
            or set(evidence.get("source_files", {})) != set(INPUTS + PRODUCERS)
            or any(evidence.get(key) is not value for key, value in SCOPE.items())):
        raise ValueError("build evidence identity or scope differs")
    expected_files = {"adapter.o", "adapter.bin", *["source-snapshots/" + x for x in INPUTS + PRODUCERS]}
    for name in ("as", "objcopy"):
        expected_files |= {"tools/" + name + suffix for suffix in (".json", ".stdout.bin", ".stderr.bin")}
    for name in CONTROL_NAMES:
        expected_files.add("packer/" + name + "/invocation.json")
        expected_files |= {"packer/" + name + "/" + label + "." + when + ".bin"
                          for label in ("input", "output", "workspace", "guards")
                          for when in ("before", "after")}
    if set(evidence.get("files", {})) != expected_files:
        raise ValueError("build evidence file inventory differs")
    for relative, expected_pin in evidence["files"].items():
        if pin(member(folder, relative)) != expected_pin:
            raise ValueError("build evidence member changed: " + relative)
    for relative, expected_pin in evidence["source_files"].items():
        if pin(member(folder / "source-snapshots", relative)) != expected_pin:
            raise ValueError("sealed source changed")
    if metadata["source_sha256"] != {
        name: evidence["source_files"][name]["sha256"] for name in INPUTS
    }:
        raise ValueError("manifest inputs differ from sealed bytes")
    if source_root is not None:
        source_root = source_root.resolve(strict=True)
        for relative in INPUTS + PRODUCERS:
            if ordinary(source_root / relative) != ordinary(folder / "source-snapshots" / relative):
                raise ValueError("current output input or producer differs: " + relative)
        if evidence["producer_folder"] != str(folder):
            raise ValueError("strong build path differs from recorded producer")
    if (type(metadata.get("compiler_sha256")) is not str
            or not re.fullmatch("[0-9a-f]{64}", metadata["compiler_sha256"])):
        raise ValueError("compiler identity is not a complete SHA256")
    components = {}
    for name in ("owner", "packer"):
        source = member(folder.parent, metadata[name + "_manifest"])
        raw = ordinary(source)
        if sha(raw) != metadata[name + "_manifest_sha256"]:
            raise ValueError("native component manifest changed")
        component = strict_json(raw)
        if (type(component) is not dict
                or component.get("schema") != "hepta.runtime.native-module.v1"
                or component.get("abi") != "hepta.runtime.borrowed-bytes.linux-x86_64.v1"
                or component.get("target") != metadata["target"]
                or component.get("compiler_commit") != metadata["compiler_commit"]
                or component.get("compiler_sha256") != metadata["compiler_sha256"]):
            raise ValueError("native component compiler differs")
        source_name = "native/shell_output_io.hepta" if name == "owner" else "native/shell_output_packer.hepta"
        if (component["source_sha256"] != metadata["source_sha256"][source_name]
                or sha(ordinary(member(source.parent, component["source"]))) != component["source_sha256"]):
            raise ValueError("native component source changed")
        image = ordinary(member(source.parent, component["image"]))
        if sha(image) != component["image_sha256"]:
            raise ValueError("native component image changed")
        components[name] = (component, image)
    image = components["owner"][1]
    executable = ordinary(folder / "shell-output.elf")
    offset = metadata["image_offset"]
    layout_raw = ordinary(folder / "source-snapshots/native/shell_output_layout.json")
    layout = strict_json(layout_raw)
    adapter = ordinary(folder / "adapter.bin")
    if (sha(executable) != metadata["elf_sha256"]
            or metadata["owner_source_sha256"] != components["owner"][0]["source_sha256"]
            or metadata["owner_image_sha256"] != sha(image)
            or sha(layout_raw) != metadata["layout_sha256"]
            or layout.get("adapter_source_sha256") != metadata["adapter_source_sha256"]
            or metadata["adapter_source_sha256"] != metadata["source_sha256"]["scripts/shell_output_adapter.S"]
            or layout.get("image_offset") != offset or adapter[-1:] != b"\0"
            or len(adapter) != offset - 176 + 1
            or sha(adapter[:-1]) != metadata["adapter_image_sha256"]
            or layout.get("adapter_image_sha256") != metadata["adapter_image_sha256"]
            or executable[176:offset] != adapter[:-1] or executable[offset:] != image
            or struct.unpack_from("<Q", executable, 96)[0] != len(executable)
            or struct.unpack_from("<Q", executable, 104)[0] != len(executable)):
        raise ValueError("HIA-packed ELF source/image binding differs")
    if inspect_fixed_executable(executable) != metadata["inspection"]:
        raise ValueError("ELF static inspection differs")
    producer = Path(evidence["producer_folder"])
    tool_specs = (
        ("as", ["--64", "-o", str(producer/"adapter.o"),
                str(producer/"source-snapshots/scripts/shell_output_adapter.S")],
         ["source-snapshots/scripts/shell_output_adapter.S"], ["adapter.o"]),
        ("objcopy", ["-O", "binary", "-j", ".text",
                     str(producer/"adapter.o"), str(producer/"adapter.bin")],
         ["adapter.o"], ["adapter.bin"]),
    )
    for name, args, inputs, outputs in tool_specs:
        receipt = strict_json(ordinary(folder / ("tools/" + name + ".json")))
        tool_pin = receipt.get("tool_before")
        if (type(tool_pin) is not dict or set(tool_pin) != {"size", "sha256"}
                or type(tool_pin["size"]) is not int or tool_pin["size"] <= 0
                or type(tool_pin["sha256"]) is not str
                or not re.fullmatch("[0-9a-f]{64}", tool_pin["sha256"])):
            raise ValueError("actual assembler tool identity is malformed")
        if source_root is not None:
            if pin(Path(receipt["resolved_tool"])) != tool_pin:
                raise ValueError("actual assembler tool changed after retained process")
        if (receipt.get("schema") != "hepta.runtime.shell-process-build-tool.v1"
                or receipt.get("name") != name
                or receipt.get("argv") != [receipt.get("resolved_tool"), *args]
                or receipt.get("cwd") != str(producer)
                or not Path(receipt["resolved_tool"]).is_absolute()
                or receipt.get("tool_before") != receipt.get("tool_after")
                or type(receipt.get("pid")) is not int or receipt["pid"] <= 0
                or receipt.get("exit_code") != 0 or receipt.get("timed_out") is not False
                or receipt.get("exception") is not None or receipt.get("deadline_ms") != 30000
                or receipt.get("env") != {"PATH": os.defpath, "LC_ALL": "C"}
                or receipt["finished_ns"] < receipt["started_ns"]
                or receipt["duration_ns"] != receipt["finished_ns"] - receipt["started_ns"]
                or receipt.get("input_files_before") != {x: pin(folder/x) for x in inputs}
                or receipt.get("input_files_after") != receipt.get("input_files_before")
                or receipt.get("output_files") != {x: pin(folder/x) for x in outputs}
                or receipt.get("stdout") != pin(folder / ("tools/" + name + ".stdout.bin"))
                or receipt.get("stderr") != pin(folder / ("tools/" + name + ".stderr.bin"))):
            raise ValueError("actual assembler tool receipt differs: " + name)
    for name, wire, capacity, expected in invocation_cases(image, len(executable)):
        case = folder / "packer" / name
        receipt = strict_json(ordinary(case / "invocation.json"))
        expected_buffers = {label + "." + when + ".bin"
                            for label in ("input", "output", "workspace", "guards")
                            for when in ("before", "after")}
        if (receipt.get("schema") != "hepta.runtime.shell-process-packer-invocation.v1"
                or receipt.get("status") != "PASS" or receipt.get("name") != name
                or receipt.get("manifest_sha256") != metadata["packer_manifest_sha256"]
                or receipt.get("image_sha256") != components["packer"][0]["image_sha256"]
                or receipt.get("source_sha256") != components["packer"][0]["source_sha256"]
                or receipt.get("returned") != expected or receipt.get("expected_return") != expected
                or receipt.get("input_capacity") != len(wire)
                or receipt.get("output_capacity") != capacity
                or receipt.get("workspace_capacity") != 4096
                or receipt.get("exception") is not None
                or receipt["finished_ns"] < receipt["started_ns"]
                or receipt["duration_ns"] != receipt["finished_ns"] - receipt["started_ns"]
                or set(receipt.get("files", {})) != expected_buffers
                or any(receipt.get(key) is not True for key in (
                    "input_and_workspace_unchanged", "guards_unchanged",
                    "output_tail_or_refusal_unchanged"))):
            raise ValueError("actual HIA packer invocation receipt differs: " + name)
        for filename, expected_pin in receipt["files"].items():
            if pin(case / filename) != expected_pin:
                raise ValueError("actual packer array changed")
        after_output = ordinary(case / "output.after.bin")
        if (ordinary(case/"input.before.bin") != wire or ordinary(case/"input.after.bin") != wire
                or ordinary(case/"output.before.bin") != b"\xa7"*capacity
                or ordinary(case/"workspace.before.bin") != b"\x5c"*4096
                or ordinary(case/"workspace.after.bin") != b"\x5c"*4096
                or ordinary(case/"guards.before.bin") != GUARDS
                or ordinary(case/"guards.after.bin") != GUARDS
                or len(after_output) != capacity):
            raise ValueError("borrowed packer buffers or guards differ: " + name)
        desired = executable + b"\xa7"*37 if name == "success" else b"\xa7"*capacity
        if after_output != desired:
            raise ValueError("packer output/refusal/tail differs: " + name)
    return {"status": "PASS", "schema": "hepta.runtime.shell-output-build-read.v1",
            "verification": ("strong-current-source-and-tool-bindings" if source_root is not None
                             else "portable-byte-evidence"),
            "manifest_sha256": sha(ordinary(manifest)),
            "elf_sha256": sha(executable), "compiler_sha256": metadata["compiler_sha256"],
            "tool_processes": 2, "packer_invocations": len(CONTROL_NAMES),
            "sealed_sources": len(INPUTS + PRODUCERS), **SCOPE}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta", type=Path)
    parser.add_argument("--build", type=Path)
    parser.add_argument("--source-root", type=Path, default=ROOT)
    parser.add_argument("--verify", type=Path)
    args = parser.parse_args()
    if args.verify is not None:
        print(json.dumps(read_evidence(args.verify, source_root=args.source_root), sort_keys=True))
    else:
        if args.hepta is None or args.build is None:
            parser.error("--hepta and --build are required for an actual build")
        print(build_shell_output(args.hepta, args.build, source_root=args.source_root))


if __name__ == "__main__":
    main()
"""Build and verify the HIA process owner with its fixed Linux syscall boundary.

The executable is a prepared-capture fixture. Production MCP dispatch, durable
background jobs, and whole-runtime replacement require separate qualification.
Every successful build retains the actual tool processes and borrowed arrays;
the reader reconstructs those checks without executing code or rewriting proof.
"""
from __future__ import annotations

import argparse
import ctypes
import datetime
import hashlib
import json
import os
import shutil
import stat
import struct
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from hia_native_build import NativeBuild, json_bytes, write_new
from hia_native_loader import NativeModule

INPUTS = (
    "native/shell_process.hepta", "native/shell_process_packer.hepta",
    "native/shell_process_layout.json", "scripts/shell_process_adapter.S",
)
PRODUCERS = (
    "native/shell_process_abi.md", "native/shell_process_fixture.md",
    "scripts/hia_native_shell_process_build.py", "scripts/hia_native_loader.py",
    "scripts/hia_native_build.py",
)
SCOPE = {
    "production_activated": False, "production_shell_execution_qualified": False,
    "whole_runtime_replaced": False, "old_stack_removal_qualified": False,
}
CONTROL_NAMES = ("success", "short-header", "bad-magic", "length-mismatch",
                 "trailing-byte", "zero-image", "short-output")
GUARDS = b"\xc1"*16 + b"\xc2"*16 + b"\xa5"*16 + b"\xa6"*16 + b"\x5a"*16 + b"\x5b"*16


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def inspect_fixed_executable(raw: bytes) -> dict:
    """Validate the complete two-program-header ELF shape without imports."""
    if len(raw) <= 176 or raw[:16] != b"\x7fELF\x02\x01\x01" + bytes(9):
        raise ValueError("not the canonical ELF64 executable")
    header = struct.unpack_from("<HHIQQQIHHHHHH", raw, 16)
    if header != (2, 62, 1, 0x4000b0, 64, 0, 0, 64, 56, 2, 0, 0, 0):
        raise ValueError("unexpected fixed executable header")
    if struct.unpack_from("<IIQQQQQQ", raw, 64) != (
        1, 5, 0, 0x400000, 0x400000, len(raw), len(raw), 4096
    ):
        raise ValueError("fixed PT_LOAD differs from actual bytes")
    if struct.unpack_from("<IIQQQQQQ", raw, 120) != (
        0x6474e551, 6, 0, 0, 0, 0, 0, 16
    ):
        raise ValueError("fixed GNU_STACK differs")
    return {
        "elf_type": "ET_EXEC", "machine": "EM_X86_64", "entry": header[3],
        "program_headers": ["PT_LOAD_RX", "PT_GNU_STACK_RW"],
        "interpreter": None, "dynamic_loader": False, "libc": False,
        "bytes": len(raw), "sha256": sha(raw),
    }


def strict_json(raw: bytes):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    def bad_number(value):
        raise ValueError("non-integer JSON number: " + value)
    return json.loads(raw, object_pairs_hook=pairs, parse_float=bad_number,
                      parse_constant=bad_number)


def ordinary(path: Path) -> bytes:
    if (not stat.S_ISREG(path.lstat().st_mode) or path.is_symlink()
            or path.resolve(strict=True) != path.absolute()):
        raise ValueError("build evidence member is not an ordinary file")
    return path.read_bytes()


def pin(path: Path) -> dict:
    data = ordinary(path)
    return {"size": len(data), "sha256": sha(data)}


def member(root: Path, relative: str) -> Path:
    if (type(relative) is not str or not relative or relative.startswith("/")
            or any(part in ("", ".", "..") for part in relative.split("/"))):
        raise ValueError("unsafe evidence member")
    return root / relative


def tool_process(folder: Path, name: str, args: list[str],
                 inputs: list[Path], outputs: list[Path]) -> None:
    tool_name = shutil.which(name)
    if tool_name is None:
        raise ValueError("required assembler tool is absent: " + name)
    tool = Path(tool_name).resolve(strict=True)
    before_tool = pin(tool)
    argv = [str(tool), *args]
    environment = {"PATH": os.defpath, "LC_ALL": "C"}
    input_pins = {str(path.relative_to(folder)): pin(path) for path in inputs}
    process = None
    stdout = stderr = b""
    timed_out = False
    exception = None
    started_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    started_ns = time.monotonic_ns()
    try:
        process = subprocess.Popen(
            argv, cwd=folder, env=environment, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
        )
        try:
            stdout, stderr = process.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            stdout, stderr = process.communicate(timeout=5)
    except Exception as error:
        exception = {"type": type(error).__name__, "message": str(error)}
        if process is not None and process.poll() is None:
            process.kill()
            stdout, stderr = process.communicate(timeout=5)
    finished_ns = time.monotonic_ns()
    write_new(folder / ("tools/" + name + ".stdout.bin"), stdout)
    write_new(folder / ("tools/" + name + ".stderr.bin"), stderr)
    after_tool = pin(tool)
    after_inputs = {str(path.relative_to(folder)): pin(path) for path in inputs}
    output_pins = {str(path.relative_to(folder)): pin(path)
                   for path in outputs if path.exists()}
    receipt = {
        "schema": "hepta.runtime.shell-process-build-tool.v1",
        "name": name, "argv": argv, "cwd": str(folder), "env": environment,
        "resolved_tool": str(tool), "tool_before": before_tool, "tool_after": after_tool,
        "pid": process.pid if process is not None else None,
        "started_at": started_at, "started_ns": started_ns, "finished_ns": finished_ns,
        "duration_ns": finished_ns - started_ns, "deadline_ms": 30000,
        "exit_code": process.returncode if process is not None else None,
        "timed_out": timed_out, "exception": exception,
        "input_files_before": input_pins, "input_files_after": after_inputs,
        "output_files": output_pins,
        "stdout": pin(folder / ("tools/" + name + ".stdout.bin")),
        "stderr": pin(folder / ("tools/" + name + ".stderr.bin")),
    }
    write_new(folder / ("tools/" + name + ".json"), json_bytes(receipt))
    if (receipt["exit_code"] != 0 or timed_out or exception is not None
            or before_tool != after_tool or input_pins != after_inputs
            or len(output_pins) != len(outputs)):
        raise ValueError("actual " + name + " process failed; retained its complete receipt")


def invocation_cases(image: bytes, total: int):
    wire = b"HSHPPK01" + struct.pack("<Q", len(image)) + image
    return (
        ("success", wire, total + 37, total),
        ("short-header", wire[:15], total + 37, 0xffffffff),
        ("bad-magic", b"X" + wire[1:], total + 37, 0xffffffff),
        ("length-mismatch", wire[:8] + struct.pack("<Q", len(image) + 1) + image,
         total + 37, 0xffffffff),
        ("trailing-byte", wire + b"x", total + 37, 0xffffffff),
        ("zero-image", b"HSHPPK01" + struct.pack("<Q", 0), total + 37, 0xffffffff),
        ("short-output", wire, total - 1, 0xfffffffe),
    )


def invoke_recorded(module: NativeModule, folder: Path, name: str, wire: bytes,
                    capacity: int, expected: int) -> bytes:
    """Use admitted sealed code and preserve every actual borrowed span.

    This qualification-only FFI captures both guards around all three buffers.
    NativeModule supplies the pinned immutable image; no host packer is called.
    """
    case = folder / "packer" / name
    case.mkdir(parents=True, exist_ok=False)
    workspace_capacity = 4096
    if (len(wire) > module.metadata["input_capacity"]
            or capacity > module.metadata["output_capacity"]
            or workspace_capacity > module.metadata["workspace_capacity"]):
        raise ValueError("packer qualification exceeds admitted borrowed profile")
    arrays = [ctypes.create_string_buffer(len(wire) + 32),
              ctypes.create_string_buffer(capacity + 32),
              ctypes.create_string_buffer(workspace_capacity + 32)]
    lengths = (len(wire), capacity, workspace_capacity)
    for i, (array, size) in enumerate(zip(arrays, lengths)):
        ctypes.memmove(ctypes.addressof(array), GUARDS[32*i:32*i+16], 16)
        ctypes.memmove(ctypes.addressof(array)+16+size, GUARDS[32*i+16:32*i+32], 16)
    ctypes.memmove(ctypes.addressof(arrays[0])+16, wire, len(wire))
    ctypes.memset(ctypes.addressof(arrays[1])+16, 0xa7, capacity)
    ctypes.memset(ctypes.addressof(arrays[2])+16, 0x5c, workspace_capacity)

    def spans():
        bodies = [ctypes.string_at(ctypes.addressof(a)+16, size)
                  for a, size in zip(arrays, lengths)]
        guards = b"".join(ctypes.string_at(ctypes.addressof(a), 16)
                          + ctypes.string_at(ctypes.addressof(a)+16+size, 16)
                          for a, size in zip(arrays, lengths))
        return bodies + [guards]

    before = spans()
    for label, data in zip(("input", "output", "workspace", "guards"), before):
        write_new(case / (label + ".before.bin"), data)
    started_ns = time.monotonic_ns()
    returned = None
    exception = None
    try:
        with module._lock:
            if (module._entry is None
                    or sha(ordinary(module.source_path)) != module.metadata["source_sha256"]):
                raise ValueError("admitted packer source changed before native entry")
            returned = int(module._entry(
                ctypes.addressof(arrays[0])+16, lengths[0],
                ctypes.addressof(arrays[1])+16, lengths[1],
                ctypes.addressof(arrays[2])+16, lengths[2],
            ))
    except Exception as error:
        exception = {"type": type(error).__name__, "message": str(error)}
    finished_ns = time.monotonic_ns()
    after = spans()
    for label, data in zip(("input", "output", "workspace", "guards"), after):
        write_new(case / (label + ".after.bin"), data)
    unchanged = before[0] == after[0] and before[2] == after[2]
    guarded = before[3] == after[3] == GUARDS
    output_valid = (after[1][expected:] == before[1][expected:]
                    if name == "success" else after[1] == before[1])
    passed = (exception is None and returned == expected
              and unchanged and guarded and output_valid)
    files = {p.name: pin(p) for p in sorted(case.iterdir()) if p.is_file()}
    receipt = {
        "schema": "hepta.runtime.shell-process-packer-invocation.v1",
        "name": name, "status": "PASS" if passed else "FAIL",
        "manifest_sha256": module.manifest_sha256,
        "source_sha256": module.metadata["source_sha256"],
        "image_sha256": module.metadata["image_sha256"],
        "returned": returned, "expected_return": expected,
        "input_capacity": lengths[0], "output_capacity": lengths[1],
        "workspace_capacity": lengths[2],
        "output_fill": 0xa7, "workspace_fill": 0x5c,
        "started_ns": started_ns, "finished_ns": finished_ns,
        "duration_ns": finished_ns - started_ns, "exception": exception,
        "input_and_workspace_unchanged": unchanged, "guards_unchanged": guarded,
        "output_tail_or_refusal_unchanged": output_valid, "files": files,
    }
    write_new(case / "invocation.json", json_bytes(receipt))
    if not passed:
        raise ValueError("actual native packer invocation failed: " + name)
    return after[1][:returned] if name == "success" else b""


def build_shell_process(
    hepta: Path, build_root: Path, *, source_root: Path = ROOT
) -> Path:
    hepta = hepta.resolve(strict=True)
    source_root = source_root.resolve(strict=True)
    build_root = build_root.resolve()
    source_bytes = {name: ordinary(source_root / name) for name in INPUTS + PRODUCERS}
    layout = strict_json(source_bytes["native/shell_process_layout.json"])
    if layout.get("schema") != "hepta.runtime.shell-process-layout.v1":
        raise ValueError("shell process adapter layout schema differs")
    image_offset = layout.get("image_offset")
    if type(image_offset) is not int or image_offset < 176 or image_offset % 16:
        raise ValueError("shell process image offset is invalid")
    adapter_source = source_bytes["scripts/shell_process_adapter.S"]
    if layout.get("adapter_source_sha256") != sha(adapter_source):
        raise ValueError("shell process adapter source differs from layout")
    folder = build_root / "shell-process"
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

    owner = component("shell-process", "native/shell_process.hepta")
    packer = component("shell-process-packer", "native/shell_process_packer.hepta")
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

    source = folder / "source-snapshots/scripts/shell_process_adapter.S"
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
    write_new(folder / "shell-process.elf", executable, 0o500)
    evidence_files = {}
    for path in sorted(folder.rglob("*")):
        if path.is_file() and path.name != "shell-process.elf":
            evidence_files[str(path.relative_to(folder))] = pin(path)
    evidence = {
        "schema": "hepta.runtime.shell-process-build-evidence.v1", "status": "PASS",
        "producer_folder": str(folder), "source_files": {
            name: {"size": len(raw), "sha256": sha(raw)} for name, raw in source_bytes.items()},
        "tool_receipts": ["tools/as.json", "tools/objcopy.json"],
        "packer_cases": list(CONTROL_NAMES), "files": evidence_files, **SCOPE,
    }
    write_new(folder / "build-evidence.json", json_bytes(evidence))
    metadata = {
        "schema": "hepta.runtime.shell-process.v1", "target": "linux-x86_64",
        "elf": "shell-process.elf", "elf_sha256": sha(executable), "image_offset": image_offset,
        "owner_manifest": str(owner.relative_to(build_root)),
        "owner_manifest_sha256": sha(ordinary(owner)),
        "owner_source_sha256": owner_metadata["source_sha256"], "owner_image_sha256": sha(image),
        "packer_manifest": str(packer.relative_to(build_root)),
        "packer_manifest_sha256": sha(ordinary(packer)),
        "adapter_source_sha256": sha(adapter_source),
        "adapter_image_sha256": sha(adapter_image[:-1]),
        "layout_sha256": sha(source_bytes["native/shell_process_layout.json"]),
        "source_sha256": {name: sha(source_bytes[name]) for name in INPUTS},
        "compiler_commit": owner_metadata["compiler_commit"],
        "compiler_sha256": owner_metadata["compiler_sha256"],
        "effect_abi": "HSHPRFX1", "prepared_capture_required": True,
        "raw_fd_or_pid_input_allowed": False, "runtime_python_required": False,
        "runtime_libc_required": False,
        "fixture_argv": ["--process-fixture", "CAPTURE_DIRECTORY"], "inspection": inspection,
        "build_evidence": "build-evidence.json",
        "build_evidence_sha256": sha(ordinary(folder / "build-evidence.json")), **SCOPE,
    }
    if any(ordinary(source_root / name) != raw for name, raw in source_bytes.items()):
        raise ValueError("shell process build input changed")
    build._recheck()
    path = folder / "manifest.json"
    write_new(path, json_bytes(metadata))
    read_evidence(path)
    return path


def read_evidence(manifest: Path) -> dict:
    """Read portable bytes, receipts and actual borrowed spans; never execute."""
    manifest = manifest.resolve(strict=True)
    folder = manifest.parent
    metadata = strict_json(ordinary(manifest))
    if (type(metadata) is not dict or metadata.get("schema") != "hepta.runtime.shell-process.v1"
            or metadata.get("target") != "linux-x86_64" or metadata.get("elf") != "shell-process.elf"
            or metadata.get("compiler_commit") != "d3e2c90173cf733e42b299d0c4274df4b593a12f"
            or metadata.get("effect_abi") != "HSHPRFX1"
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
            or evidence.get("schema") != "hepta.runtime.shell-process-build-evidence.v1"
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
    components = {}
    for name in ("owner", "packer"):
        source = member(folder.parent, metadata[name + "_manifest"])
        raw = ordinary(source)
        if sha(raw) != metadata[name + "_manifest_sha256"]:
            raise ValueError("native component manifest changed")
        component = strict_json(raw)
        if (type(component) is not dict
                or component.get("schema") != "hepta.runtime.native-module.v1"
                or component.get("compiler_commit") != metadata["compiler_commit"]
                or component.get("compiler_sha256") != metadata["compiler_sha256"]):
            raise ValueError("native component compiler differs")
        source_name = "native/shell_process.hepta" if name == "owner" else "native/shell_process_packer.hepta"
        if (component["source_sha256"] != metadata["source_sha256"][source_name]
                or sha(ordinary(member(source.parent, component["source"]))) != component["source_sha256"]):
            raise ValueError("native component source changed")
        image = ordinary(member(source.parent, component["image"]))
        if sha(image) != component["image_sha256"]:
            raise ValueError("native component image changed")
        components[name] = (component, image)
    image = components["owner"][1]
    executable = ordinary(folder / "shell-process.elf")
    offset = metadata["image_offset"]
    layout_raw = ordinary(folder / "source-snapshots/native/shell_process_layout.json")
    layout = strict_json(layout_raw)
    adapter = ordinary(folder / "adapter.bin")
    if (sha(executable) != metadata["elf_sha256"]
            or metadata["owner_source_sha256"] != components["owner"][0]["source_sha256"]
            or metadata["owner_image_sha256"] != sha(image)
            or sha(layout_raw) != metadata["layout_sha256"]
            or layout.get("adapter_source_sha256") != metadata["adapter_source_sha256"]
            or metadata["adapter_source_sha256"] != metadata["source_sha256"]["scripts/shell_process_adapter.S"]
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
                str(producer/"source-snapshots/scripts/shell_process_adapter.S")],
         ["source-snapshots/scripts/shell_process_adapter.S"], ["adapter.o"]),
        ("objcopy", ["-O", "binary", "-j", ".text",
                     str(producer/"adapter.o"), str(producer/"adapter.bin")],
         ["adapter.o"], ["adapter.bin"]),
    )
    for name, args, inputs, outputs in tool_specs:
        receipt = strict_json(ordinary(folder / ("tools/" + name + ".json")))
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
    return {"status": "PASS", "verification": "portable-byte-evidence",
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
        print(json.dumps(read_evidence(args.verify), sort_keys=True))
    else:
        if args.hepta is None or args.build is None:
            parser.error("--hepta and --build are required for an actual build")
        print(build_shell_process(args.hepta, args.build, source_root=args.source_root))


if __name__ == "__main__":
    main()

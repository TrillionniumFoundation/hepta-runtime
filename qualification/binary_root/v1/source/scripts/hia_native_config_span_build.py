"""Build the native configuration span owners and their real Linux fixture.

All runtime decisions execute in the nineteen HIA images. The boundary joins
their borrowed buffers to Linux syscalls and emits private qualification traces.
The HIA compiler and static linker execute their actual native images.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import stat
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = "tests/hia_native/config_span/"
PROFILE = "native/config_span_sources.json"
sys.path.insert(0, str(ROOT / "scripts"))
from hia_native_build import NativeBuild, json_bytes, write_new
from hia_native_loader import NativeModule


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def source_check(root):
    binding = json.loads((root / PROFILE).read_bytes())
    if binding.get("schema") != "hepta.runtime.config-span-source-closure.v1":
        raise ValueError("configuration span source schema differs")
    for name, expected in binding["sources"].items():
        relative = Path(name)
        path = root / relative
        if relative.is_absolute() or ".." in relative.parts or path.resolve() != path.absolute():
            raise ValueError("configuration span source escaped checkout")
        if not stat.S_ISREG(path.stat().st_mode):
            raise ValueError("configuration span source is not regular")
        raw = path.read_bytes()
        if expected != dict(bytes=len(raw), sha256=sha(raw)):
            raise ValueError("configuration span source differs: " + name)
    return binding


def execute(root, output, name, command, timeout):
    started = time.monotonic()
    timed_out = False
    failure = None
    code = None
    with (output / (name + ".stdout")).open("xb") as stdout, \
            (output / (name + ".stderr")).open("xb") as stderr:
        try:
            child = subprocess.Popen(command, cwd=root, stdin=subprocess.DEVNULL,
                                     stdout=stdout, stderr=stderr, start_new_session=True)
            try:
                code = child.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(child.pid, signal.SIGKILL)
                code = child.wait(timeout=3)
        except (OSError, subprocess.TimeoutExpired) as error:
            failure = dict(type=type(error).__name__, message=str(error))
    row = dict(command=command, cwd=str(root), timeout_seconds=timeout,
               elapsed_seconds=time.monotonic() - started, exit_code=code,
               timed_out=timed_out)
    if failure is not None:
        row["start_error"] = failure
    for stream in ("stdout", "stderr"):
        raw = (output / (name + "." + stream)).read_bytes()
        row[stream] = dict(bytes=len(raw), sha256=sha(raw))
    write_new(output / (name + ".process.json"), json_bytes(row))
    if code != 0 or timed_out or failure:
        raise RuntimeError(name + " failed; complete streams and receipt retained")
    return row


def load_fixture(root):
    spec = importlib.util.spec_from_file_location(
        "_native_config_span_fixture", root / FIXTURE / "config_fixture.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def boundary_source(root, declarations, images, configuration):
    helper = load_fixture(root)
    engine = (root / "scripts/view_call_engine.S").read_text()
    allocator = engine[engine.index("view_allocate:\n"):
                       engine.index("/* Actual partial writes.")]
    fixture = helper.combine((root / "scripts/config_mcp_grow_adapter.S").read_text(),
                             (root / FIXTURE / "grow_fixture.S").read_text())
    for row in declarations:
        name = row["name"]
        fixture = helper.replace(fixture, "\n" + name + "_call_displacement:\n    .long 0",
                                 "\n" + name + "_call_displacement:\n    .long grow_config_" + name + " - (. + 4)")
    source = ((root / FIXTURE / "grow_bridge.S").read_text() + "\n"
              + (root / "scripts/runtime_mcp_workdir_io_bridge.S").read_text() + "\n"
              + (root / FIXTURE / "canonical_bridge.S").read_text() + "\n"
              + fixture + "\n" + allocator)
    marker = "grow_fixture_images:\n    .zero 144"
    if source.count(marker) != 1:
        raise ValueError("configuration span fixture table anchor differs")
    source = source.replace(marker, "grow_fixture_images:\n" + "".join(
        "    .quad " + ("grow_image_" + str(i) if i in images else "0") + "\n"
        for i in range(18)))
    for name in re.findall(r"^\.global ([A-Za-z_][A-Za-z_0-9]*)$", source, re.M):
        if name == "_start":
            continue
        alias = name + "_flat"
        source = source.replace("\n" + name + ":", "\n" + name + ":\n" + alias + ":")
        source = re.sub(r"\b(call|jmp) " + re.escape(name) + r"\b",
                        lambda match: match[1] + " " + alias, source)
    for slot, path in images.items():
        if slot != 11:
            source += "\n.balign 16\ngrow_image_" + str(slot) + ":\n    .incbin " + json.dumps(str(path)) + "\n"
    for name, path in configuration.items():
        source += ("\n.balign 16\n" + ("grow_image_11:\n" if name == "owner" else "")
                   + "grow_config_" + name + ":\n    .incbin " + json.dumps(str(path)) + "\n")
    return source, sha(allocator.encode())


def build_config_span(hepta, output, *, source_root=ROOT):
    root = Path(source_root).resolve(strict=True)
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    if (output / "result.json").exists() or (output / "combined.S").exists():
        raise ValueError("configuration span build output was already used")
    started = time.monotonic()
    binding = source_check(root)
    declarations = json.loads((root / FIXTURE / "graph_sources.json").read_bytes())
    if len(declarations) != 17:
        raise ValueError("configuration span startup image count differs")
    native = NativeBuild(hepta, output / "build")
    native.bootstrap()
    members, configuration, images = [], {}, {}

    def compile_member(name, source, extra):
        path = root / source
        before = time.monotonic()
        manifest = native.compile("config-span-" + name.replace("_", "-"), path,
                                  standalone=None, buffer_profile="history.v1")
        metadata = json.loads(manifest.read_bytes())
        image = manifest.parent / metadata["image"]
        members.append(dict(name=name, source=str(path), source_sha256=sha(path.read_bytes()),
                            manifest=str(manifest), manifest_sha256=sha(manifest.read_bytes()),
                            image_sha256=sha(image.read_bytes()), fresh_compile=True,
                            elapsed_seconds=time.monotonic() - before, **extra))
        return image

    for index, row in enumerate(declarations):
        path = root / row["source"]
        if sha(path.read_bytes()) != row["sha256"]:
            raise ValueError("configuration span HIA member differs: " + row["name"])
        configuration[row["name"]] = compile_member("config-" + row["name"], row["source"],
                                                    dict(config_slot=index))
    images[11] = configuration["owner"]
    for slot, name, source in ((7, "directory-move-guard", "native/directory_move_guard.hepta"),
                               (8, "canonical", "native/canonical_path.hepta")):
        images[slot] = compile_member(name, source, dict(slot=slot))
    source, allocator_sha = boundary_source(root, declarations, images, configuration)
    write_new(output / "combined.S", source.encode())
    steps = [execute(root, output, "assemble", ["as", "--64", "-o", str(output / "bridge.o"),
                                               str(output / "combined.S")], 60)]
    obj = (output / "bridge.o").read_bytes()
    entry = b"_start"
    frame = (b"HIALNK01" + struct.pack("<3Q", 1, len(entry), 0) + entry
             + struct.pack("<Q", len(obj)) + obj)
    write_new(output / "link.input.bin", frame)
    linker = native.compile("config-span-elf-linker", Path(hepta) / "examples/hia_bootstrap/elf_static_linker.hepta",
                            standalone=None)
    before = time.monotonic()
    with NativeModule(linker, manifest_sha256=sha(linker.read_bytes())) as module:
        elf = module.invoke(frame, output_capacity=8 << 20, workspace_capacity=32 << 20)
    binary = output / "bridge.elf"
    write_new(binary, elf, 0o500)
    link = dict(elapsed_seconds=time.monotonic() - before, manifest=str(linker),
                manifest_sha256=sha(linker.read_bytes()), input_bytes=len(frame), input_sha256=sha(frame),
                output_bytes=len(elf), output_sha256=sha(elf))
    write_new(output / "link.receipt.json", json_bytes(link))
    steps.append(execute(root, output, "readelf", ["readelf", "-lW", str(binary)], 30))
    headers = (output / "readelf.stdout").read_bytes()
    if b"INTERP" in headers or b"RWE" in headers or b"GNU_STACK" not in headers:
        raise ValueError("configuration span executable permissions differ")
    native._recheck()
    if source_check(root) != binding:
        raise ValueError("configuration span source changed during the actual build")
    result = dict(schema="hepta.runtime.config-span-build.v1", status="PASS",
                  elapsed_seconds=time.monotonic() - started, binary=str(binary), binary_sha256=sha(elf),
                  source_root=str(root), build_root=str(output), source_binding=binding,
                  sources={str(root / name): value for name, value in binding["sources"].items()
                           if not name.startswith("native/")},
                  allocator_closure_sha256=allocator_sha, members=members, link=link, processes=steps,
                  compiler_commit=native.identity["commit"], compiler_sha256=native.compiler_sha256,
                  cold_qualification=False, semantic_qualification="NOT_RUN", selected_private_slots=[7, 8, 11],
                  guard_action_magic="HFDMGA02", public_handler_complete=False, public_mcp_complete=False,
                  installed_config_startup=True, shared_installed_config_owner_slot=11)
    path = output / "result.json"
    write_new(path, json_bytes(result))
    return path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, default=ROOT)
    args = parser.parse_args()
    print(build_config_span(args.hepta.resolve(), args.output.resolve(), source_root=args.source_root))

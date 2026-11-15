"""Compile and HIA-link the fixed MCP/view composition.

The assembler supplies only the reviewed syscall/borrow boundary. The pinned
upstream HIA ELF linker resolves every actual address and emits the executable.
There is no Python, Rust, libc, external linker or configurable image table in
the resulting service. This builder does not claim the unfinished tool routes.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from hia_native_build import NativeBuild, json_bytes, write_new
from hia_native_loader import NativeModule

sha = lambda raw: hashlib.sha256(raw).hexdigest()
MEMBERS = [
    ("owner", "config_directory_owner", "history.v1"),
    ("fs", "config_fs", "standard"),
    ("json", "config_json", "serde-json.v1"),
    ("validation", "config_validation", "history.v1"),
    ("identity", "config_identity", "history.v1"),
    ("mcp", "runtime_mcp", "history.v1"),
    ("execution", "execution_controller", "history.v1"),
    ("execution_json", "execution_json", "history.v1"),
    ("execution_core", "execution_shadow", "history.v1"),
    ("value", "serde_json", "serde-json.v1"),
    ("publication", "result_publication", "standard"),
    ("catalog", "runtime_mcp_catalog", "history.v1"),
    ("admission", "runtime_mcp_admission", "history.v1"),
    ("gateway", "view_gateway", "history.v1"),
    ("client", "client_context", "history.v1"),
    ("params", "view_params", "history.v1"),
    ("session_context", "session_context", "history.v1"),
    ("session_state", "session_workdir", "history.v1"),
    ("policy", "local_path_policy", "history.v1"),
    ("canonical", "canonical_path", "history.v1"),
    ("path_source", "path_source", "history.v1"),
    ("view", "view_call", "history.v1"),
    ("read", "view_read", "history.v1"),
    ("endpoint", "line_endpoint", "history.v1"),
    ("key", "file_lock_key", "history.v1"),
    ("scope", "request_scope_lifecycle", "standard"),
    ("lease", "request_cache_lease", "standard"),
    ("cache", "view_cache", "history.v1"),
    ("render", "view_render", "history.v1"),
    ("request_context", "request_context", "standard"),
    ("view_error", "view_error", "standard"),
]
BASE = "scripts/config_mcp_adapter.S"
BOUNDARIES = [
    "scripts/runtime_mcp_extra_engine.S",
    "scripts/runtime_mcp_canonical_bridge.S",
    "scripts/view_call_engine.S",
    "scripts/view_call_read_bridge.S",
    "scripts/view_call_key_bridge.S",
    "scripts/view_call_scope_bridge.S",
]
EXTRA = ["catalog", "admission", "gateway", "client", "params",
         "session_context", "session_state", "policy", "canonical",
         "path_source", "value", "owner"]
VIEW = ["view", "read", "read", "read", "endpoint", "key", "scope",
        "lease", "cache", "render", "request_context", "view_error"]


def replace_once(source: str, old: str, new: str) -> str:
    if source.count(old) != 1:
        raise ValueError("reviewed native boundary anchor differs: " + old[:80])
    return source.replace(old, new, 1)


def source_check(root: Path) -> dict:
    raw = (root / 'native/runtime_mcp_sources.json').read_bytes()
    proof = json.loads(raw)
    for name, expected in proof['sources'].items():
        path = Path(name)
        if path.is_absolute() or '..' in path.parts:
            raise ValueError('runtime source pin escaped checkout')
        data = (root / path).read_bytes()
        if expected != {'bytes': len(data), 'sha256': sha(data)}:
            raise ValueError('runtime frozen source changed: ' + name)
    return {'manifest_sha256': sha(raw), 'files': proof['sources']}


def adapter_source(root: Path, images: dict[str, Path]) -> str:
    source = (root / BASE).read_text()
    source = replace_once(source, "_start:\n    cld\n", ".type _start, @function\n_start:\n    add rsp, 8 /* Restore Linux stack after the HIA linker's entry call. */\n    cld\n")
    source = replace_once(source, "    cmp qword ptr [rbx], 3\n    jne argv_fatal\n", "    jmp runtime_arguments_start\nruntime_arguments_done:\n")
    source = replace_once(source, "    lea rax, [rbx + 40]\n    mov [r15 + 648], rax\n", "    mov rax, [rbx]\n    lea rax, [rbx + rax * 8 + 16]\n    mov [r15 + 648], rax\n    call runtime_admit_auxv\n")
    source = replace_once(source, "frame_next:\n", "frame_next:\n    cmp qword ptr [r15 + MCP_WORK + FOOTER + 208], 0\n    jne frame_eof\n")
    source = replace_once(source, "frame_eof:\n", "frame_eof:\n    call runtime_finish_private\n    cmp qword ptr [r15 + 928], 0\n    je finish_ok\n")
    source = replace_once(source, "    cmp qword ptr [r14 + FOOTER + 120], 0\n    je startup_completed\n", "    cmp qword ptr [r14 + FOOTER + 120], 0\n    je startup_completed\n    cmp qword ptr [r14 + FOOTER + 120], 4\n    je startup_completed\n")
    source = replace_once(source, "startup_completed:\n    test eax, eax\n    jz frame_next\n", "startup_completed:\n    test eax, eax\n    jz runtime_install_private\n")
    source = replace_once(source, "    mov rax, [rdx + 16]\n    cmp rax, 9\n    je mcp_value_call\n", "    mov rax, [rdx + 16]\n    cmp rax, 11\n    jae runtime_mcp_extra_call\n    cmp rax, 9\n    je mcp_value_call\n")
    for name, _, _ in MEMBERS[:11]:
        source = replace_once(source, "\n" + name + "_call_displacement:\n    .long 0", "\n" + name + "_call_displacement:\n    .long runtime_image_" + name + " - (. + 4)")
    source += "\n" + "\n".join((root / p).read_text() for p in BOUNDARIES)
    for table, slots in [("runtime_extra_image_table", EXTRA), ("runtime_view_image_table", VIEW)]:
        source = replace_once(source, table + ":\n    .zero 96", table + ":\n" + "".join("    .quad runtime_image_" + n + "\n" for n in slots))
    # Resolve callable helpers locally in the one object; only fixed image
    # addresses in the two installed tables require actual HIA relocations.
    for name in re.findall(r"^\.global ([A-Za-z_][A-Za-z_0-9]*)$", source, re.M):
        if name == "_start" or name.endswith("_displacement"):
            continue
        alias = name + "_flat"
        if "\n" + alias + ":" not in source:
            source = source.replace("\n" + name + ":", "\n" + name + ":\n" + alias + ":")
        source = re.sub(r"\b(call|jmp) " + re.escape(name) + r"\b", lambda m: m[1] + " " + alias, source)
        source = source.replace("[rip + " + name + "]", "[rip + " + alias + "]")
    source += "\n.section .text\n"
    for name, _, _ in MEMBERS:
        source += "\n.balign 16\nruntime_image_" + name + ":\n    .incbin " + json.dumps(str(images[name])) + "\n"
    return source


def checked_member(build: NativeBuild, root: Path, name: str, source: str,
                   profile: str, manifest: Path) -> tuple[dict, Path]:
    raw = manifest.read_bytes()
    info = json.loads(raw)
    source_raw = (manifest.parent / info["source"]).read_bytes()
    image = manifest.parent / info["image"]
    if (source_raw != (root / "native" / (source + ".hepta")).read_bytes()
        or sha(source_raw) != info["source_sha256"]
        or sha(image.read_bytes()) != info["image_sha256"]
        or info["compiler_commit"] != build.identity["commit"]
        or info["compiler_sha256"] != build.compiler_sha256
        or info.get("buffer_profile", "standard") != profile):
        raise ValueError("runtime member source/image/profile changed: " + name)
    return {"name": name, "source": "native/" + source + ".hepta",
            "manifest": str(manifest), "manifest_sha256": sha(raw),
            "source_sha256": info["source_sha256"], "image_sha256": info["image_sha256"],
            "image_bytes": image.stat().st_size, "buffer_profile": profile}, image


def build_runtime_mcp(hepta: Path, output: Path, *, name: str = "runtime-mcp",
                      source_root: Path = ROOT, manifests: dict | None = None) -> Path:
    source_binding = source_check(source_root)
    build = NativeBuild(hepta, output)
    build.bootstrap()
    folder = output / name
    folder.mkdir(parents=True, exist_ok=False)
    closure = {p: sha((source_root / p).read_bytes()) for p in [BASE, *BOUNDARIES]}
    members = []
    images = {}
    for member, source, profile in MEMBERS:
        path = Path(manifests[member]).resolve(strict=True) if manifests and member in manifests else build.compile(name + "-" + member.replace("_", "-"), source_root / "native" / (source + ".hepta"), standalone=None, buffer_profile=profile)
        receipt, images[member] = checked_member(build, source_root, member, source, profile, path)
        receipt["fresh_compile"] = not (manifests and member in manifests)
        members.append(receipt)
    assembly = adapter_source(source_root, images)
    write_new(folder / "combined.S", assembly.encode())
    processes = []
    def execute(label, command, timeout):
        started = time.monotonic()
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        write_new(folder / (label + '.stdout'), result.stdout)
        write_new(folder / (label + '.stderr'), result.stderr)
        processes.append({'name': label, 'command': command, 'timeout_seconds': timeout,
                          'elapsed_seconds': time.monotonic() - started, 'exit_code': result.returncode,
                          'stdout': {'bytes': len(result.stdout), 'sha256': sha(result.stdout)},
                          'stderr': {'bytes': len(result.stderr), 'sha256': sha(result.stderr)}})
        write_new(folder / (label + '.process.json'), json_bytes(processes[-1]))
        result.check_returncode()
        return result
    execute('assemble', ["as", "--64", "-o", str(folder / "runtime.o"), str(folder / "combined.S")], 60)
    object_bytes = (folder / "runtime.o").read_bytes()
    entry = b"_start"
    frame = b"HIALNK01" + struct.pack("<3Q", 1, len(entry), 0) + entry + struct.pack("<Q", len(object_bytes)) + object_bytes
    write_new(folder / "link.input.bin", frame)
    linker_source = hepta / "examples/hia_bootstrap/elf_static_linker.hepta"
    linker = build.compile(name + "-elf-linker", linker_source, standalone=None)
    started = time.monotonic()
    with NativeModule(linker, manifest_sha256=sha(linker.read_bytes())) as module:
        elf = module.invoke(frame, output_capacity=8 << 20, workspace_capacity=32 << 20)
    link_receipt = {'schema': 'hepta.runtime.mcp-view-hia-link.v1', 'returned_u32': len(elf),
                    'elapsed_seconds': time.monotonic() - started,
                    'input': {'bytes': len(frame), 'sha256': sha(frame)},
                    'output': {'bytes': len(elf), 'sha256': sha(elf)},
                    'input_capacity': len(frame), 'output_capacity': 8 << 20,
                    'workspace_capacity': 32 << 20, 'borrow_guards_unchanged': True,
                    'linker_manifest_sha256': sha(linker.read_bytes())}
    write_new(folder / 'link.receipt.json', json_bytes(link_receipt))
    write_new(folder / "runtime-mcp.elf", elf, 0o500)
    inspect = execute('readelf', ["readelf", "-lW", str(folder / "runtime-mcp.elf")], 30)
    if b"INTERP" in inspect.stdout or b"RWE" in inspect.stdout or b"GNU_STACK" not in inspect.stdout:
        raise ValueError("runtime executable boundary differs")
    build._recheck()
    if source_check(source_root) != source_binding:
        raise ValueError('runtime source closure changed during build')
    if closure != {p: sha((source_root / p).read_bytes()) for p in closure}:
        raise ValueError("runtime boundary changed during build")
    for member, source, profile in MEMBERS:
        row = next(row for row in members if row["name"] == member)
        again, _ = checked_member(build, source_root, member, source, profile, Path(row["manifest"]))
        if any(row[k] != v for k, v in again.items()):
            raise ValueError("runtime member changed during link")
    report = {
        "schema": "hepta.runtime.mcp-view-build.v1", "members": members,
        "compiler_commit": build.identity["commit"], "compiler_image_sha256": build.compiler_sha256,
        "elf": "runtime-mcp.elf", "elf_sha256": sha(elf), "elf_bytes": len(elf),
        "boundary_sources": closure, "assembled_source_sha256": sha(assembly.encode()),
        "object_sha256": sha(object_bytes), "link_input_sha256": sha(frame),
        "linker_source": "examples/hia_bootstrap/elf_static_linker.hepta",
        "linker_source_sha256": sha(linker_source.read_bytes()),
        "linker_manifest": str(linker), "linker_manifest_sha256": sha(linker.read_bytes()),
        "extra_table": EXTRA, "view_table": VIEW, "runtime_host_semantics": False,
        "public_configuration_from_stdin": False, "public_private_instance_selectors": False,
        "complete_sdk_frontend": False, "whole_view_replaced": False, "whole_runtime_replaced": False,
        "directory_content_remote_routes_replaced": False,
        "response_storage_globally_unbounded": False,
        "public_line_profile_bytes": 8 << 20, "gateway_reply_profile_bytes": 64 << 20,
        "result_publication_grows": True, "fresh_cold_qualified": False,
        "builder_source_sha256": sha(Path(__file__).read_bytes()),
        "source_binding": source_binding, "boundary_processes": processes,
        "link_receipt_sha256": sha((folder / 'link.receipt.json').read_bytes()),
    }
    manifest = folder / "manifest.json"
    write_new(manifest, json_bytes(report))
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--name", default="runtime-mcp")
    parser.add_argument("--member-manifests-json", type=Path,
                        help="explicit development-only reused member manifests; never claims a fresh compile")
    args = parser.parse_args()
    manifests = json.loads(args.member_manifests_json.read_bytes()) if args.member_manifests_json else None
    print(build_runtime_mcp(args.hepta.resolve(), args.build.resolve(), name=args.name, manifests=manifests))

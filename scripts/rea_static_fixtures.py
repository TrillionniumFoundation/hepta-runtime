#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Qualify selected static facts on newly constructed owned artifacts only.

No inspected artifact is executed. The optional REA oracle requires a complete
byte match with the frozen published 6.8.0 archive; nothing is installed here.
This complements, and does not replace, the real MCP/SSH lifecycle test.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tarfile

REA_COMMIT = "93b8b82db70279e40f484114cff9dc1958dc14ee"
REA_ARCHIVE_SHA256 = "8d542ec76a9cb350584b60a6c9c088706ff812d5bb5b094c20c95b6dc25698bb"
BUILD_ID = "00112233445566778899aabbccddeeff10213243"
LIMIT = 512 * 1024


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def run(argv, timeout=45):
    # Every command is an argv list; no shell, arbitrary target, or artifact exec.
    completed = subprocess.run(
        [str(arg) for arg in argv], capture_output=True, timeout=timeout,
        env={**os.environ, "LC_ALL": "C"}, check=False,
    )
    if len(completed.stdout) > LIMIT or len(completed.stderr) > LIMIT:
        raise RuntimeError("owned fixture diagnostic exceeded its report bound")
    return completed


def success(argv):
    result = run(argv)
    if result.returncode:
        raise RuntimeError(f"owned fixture step failed: {argv[0]}: {result.stderr.decode(errors='replace')}")
    return result.stdout.decode("utf-8")


def synthetic_gpu(path):
    """ELF64 AMDGPU identifier + sections, deliberately no GPU instructions."""
    names = b"\0.text\0.note.hepta\0.shstrtab\0"
    note = struct.pack("<III", 6, 9, 1) + b"HEPTA\0\0\0" + b"SYNTHETIC\0\0\0"
    text_offset, note_offset = 64, 68
    names_offset = note_offset + len(note)
    section_offset = (names_offset + len(names) + 7) & ~7
    header = struct.pack(
        "<16sHHIQQQIHHHHHH", b"\x7fELF\x02\x01\x01" + bytes(9),
        1, 224, 1, 0, 0, section_offset, 0, 64, 0, 0, 64, 4, 3,
    )
    sections = bytes(64)
    sections += struct.pack("<IIQQQQIIQQ", 1, 1, 6, 0, text_offset, 4, 0, 0, 4, 0)
    sections += struct.pack("<IIQQQQIIQQ", 7, 7, 0, 0, note_offset, len(note), 0, 0, 4, 0)
    sections += struct.pack("<IIQQQQIIQQ", 19, 3, 0, 0, names_offset, len(names), 0, 0, 1, 0)
    body = header + bytes(4) + note + names
    path.write_bytes(body + bytes(section_offset - len(body)) + sections)


def pinned_rea(package, archive, artifact):
    """Only execute the already-installed exact reference after checking bytes."""
    if digest(archive) != REA_ARCHIVE_SHA256:
        raise RuntimeError("reference archive does not match frozen REA 6.8.0")
    package = package.resolve(strict=True)
    compared = 0
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar:
            if member.isdir():
                continue
            if not member.isfile() or member.size > 16 * 1024 * 1024:
                raise RuntimeError("unexpected reference archive member")
            parts = Path(member.name).parts
            if not parts or parts[0] != "package" or ".." in parts:
                raise RuntimeError("unexpected reference archive path")
            local = package.joinpath(*parts[1:]).resolve(strict=True)
            if not local.is_relative_to(package) or local.is_symlink():
                raise RuntimeError("reference package path escaped")
            archived = tar.extractfile(member).read()
            if local.read_bytes() != archived:
                raise RuntimeError(f"reference package differs from frozen archive: {member.name}")
            compared += 1
    metadata = json.loads((package / "package.json").read_text())
    if metadata.get("version") != "6.8.0":
        raise RuntimeError("unexpected reference version")
    node = shutil.which("node")
    if not node:
        raise RuntimeError("existing node executable is required for reference comparison")
    # REA 6.8's published CLI supports the explicit read-only ELF note command.
    output = success([node, package / "scripts/rea.mjs", "inspect-elf-notes", artifact, "--json"])
    result = json.loads(output)
    values = []

    def visit(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key == "build_id_hex":
                    values.append(item)
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(result)
    if BUILD_ID not in values:
        raise RuntimeError("frozen REA did not return the fixture GNU build-id")
    return {"executed": True, "archive_sha256": REA_ARCHIVE_SHA256,
            "matched_package_files": compared, "build_id_hex": BUILD_ID,
            "selected_field_match": True, "complete_evidence_equivalence": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True, help="new isolated output directory")
    parser.add_argument("--rea-package", type=Path)
    parser.add_argument("--rea-archive", type=Path)
    args = parser.parse_args()
    if bool(args.rea_package) != bool(args.rea_archive):
        parser.error("both frozen REA archive and installed package are required")
    root = args.output_dir.resolve()
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    rustc = shutil.which("rustc")
    if not rustc:
        raise RuntimeError("existing rustc required; this script installs nothing")
    source = root / "owned.rs"
    source.write_text('''#[no_mangle]
pub static HEPTA_STATIC_MARKER: i32 = 17;
extern "C" { fn puts(p: *const i8) -> i32; }
#[no_mangle]
pub unsafe extern "C" fn hepta_static_fixture(p: *const i8) -> i32 {
    puts(p) + HEPTA_STATIC_MARKER
}
''')
    object_path, library_path, gpu_path = root / "owned.o", root / "owned.so", root / "synthetic-amdgpu.o"
    success([rustc, "--edition=2021", "-Cdebuginfo=0", "-Cpanic=abort", "--crate-type=lib", "--emit=obj", source, "-o", object_path])
    success([rustc, "--edition=2021", "-Cdebuginfo=0", "-Cpanic=abort", "--crate-type=cdylib", f"-Clink-arg=-Wl,--build-id=0x{BUILD_ID}", source, "-o", library_path])
    synthetic_gpu(gpu_path)
    operations = {
        "readelf": {"headers": ["--file-header", "--wide"], "sections": ["--section-headers", "--wide"], "symbols": ["--symbols", "--wide"], "notes": ["--notes", "--wide"], "relocations": ["--relocs", "--wide"]},
        "objdump": {"headers": ["--file-headers"], "sections": ["--section-headers"], "symbols": ["--syms"], "relocations": ["--reloc"]},
    }
    semantic = {"headers": "elf", "sections": ".text", "symbols": "hepta_static_fixture", "relocations": "puts", "notes": BUILD_ID}
    providers, checks = {}, []
    for name, commands in operations.items():
        executable = Path("/usr/bin") / name
        version = success([executable, "--version"]).splitlines()[0]
        if not version.startswith(f"GNU {name} "):
            raise RuntimeError("expected existing GNU backend")
        providers[name] = {"path": str(executable), "sha256": digest(executable), "version": version}
        for operation, flags in commands.items():
            artifact = library_path if operation == "notes" else object_path
            output = success([executable, *flags, "--", artifact])
            expected = semantic[operation]
            if expected.lower() not in output.lower():
                raise RuntimeError(f"missing owned Rust fact: {name}/{operation}/{expected}")
            destination = root / f"{name}-{operation}.txt"
            destination.write_text(output)
            checks.append({"provider": name, "operation": operation, "artifact": artifact.name,
                           "artifact_sha256": digest(artifact), "expected_fact": expected,
                           "observed": True, "output_sha256": digest(destination)})
    gpu_checks = []
    for operation, expected in [("headers", "AMD GPU"), ("sections", ".note.hepta"), ("notes", "HEPTA")]:
        output = success(["/usr/bin/readelf", *operations["readelf"][operation], "--", gpu_path])
        if expected not in output:
            raise RuntimeError(f"missing synthetic structural fact: {operation}/{expected}")
        destination = root / f"synthetic-amdgpu-{operation}.txt"
        destination.write_text(output)
        gpu_checks.append({"operation": operation, "expected_fact": expected, "observed": True,
                           "output_sha256": digest(destination)})
    reference = {"executed": False, "reason": "frozen package/archive were not supplied",
                 "source_commit": REA_COMMIT, "version": "6.8.0"}
    if args.rea_package:
        reference.update(pinned_rea(args.rea_package, args.rea_archive, library_path))
    report = {"schema": "hepta.rea.static-fixture-qualification.v1", "providers": providers,
              "compiler": success([rustc, "--version"]).strip(), "artifact_execution_count": 0,
              "rust_checks": checks, "synthetic_gpu": {"artifact_sha256": digest(gpu_path), "checks": gpu_checks,
              "synthetic": True, "gpu_isa_validated": False, "cuda_or_rocm_build_qualified": False},
              "rea_reference": reference, "rea_full_parity": False,
              "limitations": ["direct backend fixture checks do not replace MCP/SSH lifecycle tests",
                              "notes compares only GNU build-id, not REA ranges, descriptor hashes or PT_NOTE/SHT_NOTE table coverage",
                              "GPU fixture carries only a machine identifier and structural sections; it has no valid GPU ISA"]}
    report_path = root / "qualification.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"report": str(report_path), "sha256": digest(report_path), "rust_checks": len(checks), "synthetic_gpu_checks": len(gpu_checks), "rea_reference_executed": reference["executed"]}))


if __name__ == "__main__":
    main()

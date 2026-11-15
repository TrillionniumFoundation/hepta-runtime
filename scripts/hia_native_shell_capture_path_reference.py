#!/usr/bin/env python3
"""Build a source-bound, std-only original capture-path typed projection."""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import time
import tomllib

ROOT = Path(__file__).resolve().parents[1]
DRIVER = "scripts/hia_native_shell_capture_path_reference.py"
HELPERS = "scripts/hia_native_shell_process_reference.py"
ORACLE = "tests/hia_native/shell_capture_path_oracle"
TRANSPORT = ("README.md", "source_manifest.json", "src/main.rs", "src/projection.rs.in", "src/std_temp_dir.rs.in")
SCHEMA = "hepta.runtime.shell-capture-path-original-build.v1"
TARGET = "x86_64-unknown-linux-gnu"
DRIVER_BYTES = Path(__file__).read_bytes()

def load_ref(runtime):
    path = runtime / HELPERS
    spec = importlib.util.spec_from_file_location("hia_capture_reference_helpers", path)
    if spec is None or spec.loader is None:
        raise ValueError("reference helpers unavailable")
    ref = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = ref
    spec.loader.exec_module(ref)
    ref.require(ref.read(runtime, DRIVER) == DRIVER_BYTES, "executing capture reference differs")
    ref.require(ref.read(runtime, HELPERS) == ref.DRIVER_BYTES, "executing reference helpers differ")
    return ref

def scope():
    return {"original_path_equality_executable_projection": True,
            "original_path_parent_executable_projection": True,
            "original_capture_format_statement_projection": True,
            "atomic_fetch_add_statement_preserved": True,
            "tmpdir_and_pid_are_typed_observations": True,
            "real_environment_or_pid_acquisition_executed": False,
            "original_prepare_or_registry_executed": False,
            "original_filesystem_creation_executed": False,
            "concurrent_counter_or_registry_qualified": False,
            "original_tests": 0,
            "production_activated": False, "whole_runtime_replaced": False,
            "old_stack_removal_qualified": False}

def source_provenance(runtime, ref):
    oracle = runtime / ORACLE
    ref.ordinary_source_inventory(oracle, TRANSPORT)
    transport = {name: ref.read(oracle, name) for name in TRANSPORT}
    manifest = ref.decode(transport["source_manifest.json"])
    ref.require(manifest.get("schema") == "hepta.runtime.shell-capture-path-original-source.v1",
                "capture projection source schema differs")
    ref.exact(manifest.get("required_target"), TARGET, "capture projection target differs")
    ref.exact(manifest.get("required_rust_version"), "1.95.0", "capture Rust version differs")
    ref.exact(sorted(manifest["files"]), ["Cargo.toml", "src/mcp/fs/background.rs"],
              "capture original source member set differs")
    originals = {}
    for name, expected in manifest["files"].items():
        raw = ref.read(runtime, name)
        blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        ref.exact({**ref.pin(raw), "git_blob_sha1": blob}, expected, "capture original source changed: " + name)
        originals[name] = raw
    package = tomllib.loads(originals["Cargo.toml"].decode())
    ref.exact(package["package"]["edition"], "2021", "production Rust edition differs")
    ref.exact(package["profile"]["release"], {"lto": True, "codegen-units": 1, "panic": "abort",
              "strip": True, "opt-level": 3, "overflow-checks": False}, "production release profile differs")
    spans = {}
    ref.exact(sorted(manifest["original_spans"]), ["jobs_dir", "next_id", "stderr_join", "stdout_join"],
              "capture original statement span set differs")
    for name, span in manifest["original_spans"].items():
        start, end = span["start"], span["end"]
        raw = originals[span["source"]]
        ref.require(type(start) is int and type(end) is int and 0 <= start < end <= len(raw),
                    "capture original span bounds differ")
        part = raw[start:end]
        ref.exact(ref.pin(part), {"bytes": span["bytes"], "sha256": span["sha256"]},
                  "capture original statement bytes differ: " + name)
        spans[name] = part
    std = manifest["reviewed_standard_library_sources"]["temp_dir"]["retained_span"]
    ref.exact(ref.pin(transport[std["source"]]), {"bytes": std["bytes"], "sha256": std["sha256"]},
              "retained original std temp_dir span differs")
    generated = transport[manifest["projection_template"]]
    ref.exact(sorted(manifest["projections"]), ["ORIGINAL_JOBS_DIR", "ORIGINAL_LINUX_TEMP_DIR",
              "ORIGINAL_NEXT_ID", "ORIGINAL_STDERR_JOIN", "ORIGINAL_STDOUT_JOIN"], "projection member set differs")
    projection_receipts = {}
    for name, projection in manifest["projections"].items():
        raw = spans[projection["span"]] if "span" in projection else transport[projection["source"]]
        before = raw
        for edit in projection["edits"]:
            old, new = edit["from"].encode(), edit["to"].encode()
            ref.require(type(edit["count"]) is int and edit["count"] > 0 and raw.count(old) == edit["count"],
                        "projection primitive substitution occurrence differs: " + name)
            raw = raw.replace(old, new)
        marker = ("/* " + name + " */").encode()
        ref.require(generated.count(marker) == 1, "projection marker occurrence differs")
        generated = generated.replace(marker, raw)
        projection_receipts[name] = {"original": ref.pin(before), "projected": ref.pin(raw), "edits": projection["edits"]}
    ref.require(b"/* ORIGINAL_" not in generated, "unresolved capture original source marker")
    compiled = {"src/main.rs": transport["src/main.rs"], manifest["compiled_projection"]: generated}
    provenance = {"manifest": manifest, "transport": {k: ref.pin(v) for k, v in transport.items()},
                  "drivers": {name: ref.pin(ref.read(runtime, name)) for name in (DRIVER, HELPERS)},
                  "compiled": {k: ref.pin(v) for k, v in compiled.items()}, "projections": projection_receipts,
                  "production_edition": package["package"]["edition"], "production_profile": package["profile"]["release"]}
    return provenance, originals, transport, compiled

def target_libraries(directory, ref):
    directory = Path(directory)
    ref.require(directory.is_absolute() and directory.resolve(strict=True) == directory
                and directory.is_dir(), "target library directory is not canonical")
    files = {}
    def visit(parent):
        with os.scandir(parent) as iterator:
            entries = sorted(iterator, key=lambda entry: entry.name)
        for entry in entries:
            path = parent / entry.name
            ref.require(not entry.is_symlink(), "target library contains a symlink")
            if entry.is_dir(follow_symlinks=False):
                visit(path)
            else:
                ref.require(entry.is_file(follow_symlinks=False), "target library contains a special file")
                files[path.relative_to(directory).as_posix()] = ref.pin(path.read_bytes())
    visit(directory)
    ref.require(files and any(name.startswith("libstd-") and name.endswith(".rlib") for name in files),
                "target standard library archive missing")
    return {"path": str(directory), "files": files, "file_count": len(files)}

def environment(output):
    return {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "TZ": "UTC",
            "TMPDIR": str(output / "temporary")}

def command_plan(output, rustc, linker, sysroot):
    crate = output / "crate"
    executable = output / "capture-path-original"
    common = [str(rustc), "--target", TARGET, "--sysroot", str(sysroot)]
    compile_command = common + ["--crate-name", "hepta_shell_capture_path_original", "--crate-type=bin",
        "--edition=2021", "-C", "opt-level=3", "-C", "lto=fat", "-C", "codegen-units=1",
        "-C", "panic=abort", "-C", "strip=symbols", "-C", "overflow-checks=off",
        "-C", "linker=" + str(linker), "--emit=link,dep-info=" + str(output / "capture-path.d"),
        str(crate / "src/main.rs"), "-o", str(executable)]
    return [("rustc-version", [str(rustc), "--version", "--verbose"], 30),
            ("rustc-sysroot", [str(rustc), "--print", "sysroot"], 30),
            ("rustc-target-libdir", common + ["--print", "target-libdir"], 30),
            ("rustc-compile", compile_command, 180)]

def retained_sources(output, originals, transport, compiled, ref):
    for folder, items in (("original-source", originals), ("transport", transport), ("crate", compiled)):
        for name, raw in items.items():
            ref.require(ref.read(output / folder, name) == raw,
                        "retained capture build source differs: " + folder + "/" + name)
        ref.ordinary_source_inventory(output / folder, items)

def read_evidence(runtime, output, rustc=None, linker=None):
    """Validate complete retained evidence without any compiler or executable entry."""
    runtime, output = Path(runtime).absolute(), Path(output).absolute()
    ref = load_ref(runtime)
    report = ref.decode(ref.read(output, "result.json"))
    ref.require(report.get("schema") == SCHEMA and report.get("status") == "PASS"
                and report.get("error") is None, "capture original build incomplete")
    ref.exact(report.get("scope"), scope(), "capture original build scope differs")
    provenance, originals, transport, compiled = source_provenance(runtime, ref)
    ref.exact(report.get("source_provenance"), provenance, "capture original source closure changed")
    retained_sources(output, originals, transport, compiled, ref)
    rustc = Path(rustc or report["tools"]["rustc"]["launch_path"])
    linker = Path(linker or report["tools"]["linker"]["launch_path"])
    ld = Path(report["tools"]["ld"]["launch_path"])
    ref.exact(str(ld), "/usr/bin/ld", "capture system linker path differs")
    ref.exact(report.get("tools"), {"rustc": ref.tool_identity(rustc), "linker": ref.tool_identity(linker),
              "ld": ref.tool_identity(ld)}, "capture compiler or linker changed")
    sysroot = rustc.resolve(strict=True).parent.parent
    ref.exact(report.get("sysroot"), str(sysroot), "capture toolchain sysroot differs")
    ref.exact(report.get("environment"), environment(output), "capture build environment differs")
    plan = command_plan(output, rustc, linker, sysroot)
    rows = report.get("processes")
    ref.require(type(rows) is list and len(rows) == len(plan), "capture actual build process set incomplete")
    last = 0
    for row, (label, command, timeout) in zip(rows, plan):
        ref.completed_process(output, label, row, command, output / "crate", timeout)
        ref.require(row["started_unix_ns"] >= last, "capture build process order differs")
        last = row["finished_unix_ns"]
        ref.require(ref.read(output, label + ".stderr") == b"", "capture compiler emitted diagnostics")
    version = ref.read(output, "rustc-version.stdout").decode()
    ref.require(version.startswith("rustc 1.95.0 ") and "host: " + TARGET + "\n" in version,
                "capture original compiler is not fixed Rust 1.95.0 GNU Linux")
    ref.exact(report.get("rustc_version"), version, "capture compiler version receipt differs")
    ref.require(ref.read(output, "rustc-sysroot.stdout") == (str(sysroot) + "\n").encode(), "actual sysroot differs")
    libdir = sysroot / "lib/rustlib" / TARGET / "lib"
    ref.require(ref.read(output, "rustc-target-libdir.stdout") == (str(libdir) + "\n").encode(), "actual target library directory differs")
    ref.exact(report.get("target_libraries"), target_libraries(libdir, ref), "target standard library bytes changed")
    ref.require(ref.read(output, "rustc-compile.stdout") == b"", "unexpected compiler output")
    ref.exact(report.get("dependency_file"), ref.pin(ref.read(output, "capture-path.d")), "capture dependency receipt changed")
    executable = ref.tool_identity(output / "capture-path-original")
    ref.exact(report.get("executable"), executable, "capture original executable bytes changed")
    return {"schema": "hepta.runtime.shell-capture-path-original-build-read.v1", "status": "PASS",
            "report_sha256": ref.sha(ref.read(output, "result.json")), "executable": executable,
            "actual_build_processes": len(rows), "target_library_files": report["target_libraries"]["file_count"],
            "fresh_original_projection_build_qualified": True, **scope()}

def run(runtime, output, rustc, linker):
    runtime, output = Path(runtime).absolute(), Path(output).absolute()
    if output.exists():
        raise ValueError("capture reference output must be fresh")
    output.mkdir(parents=True)
    result = output / "result.json"
    report = {"schema": SCHEMA, "status": "RUNNING", "error": None,
              "scope": scope(), "processes": []}
    def save():
        result.write_text(json.dumps(report, sort_keys=True, indent=2, allow_nan=False) + "\n")
    save()
    started = time.monotonic()
    try:
        ref = load_ref(runtime)
        provenance, originals, transport, compiled = source_provenance(runtime, ref)
        report["source_provenance"] = provenance
        for folder, items in (("original-source", originals), ("transport", transport), ("crate", compiled)):
            for name, raw in items.items():
                path = output / folder / name
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open("xb") as stream:
                    stream.write(raw)
        (output / "temporary").mkdir()
        report["tools"] = {"rustc": ref.tool_identity(rustc), "linker": ref.tool_identity(linker),
                           "ld": ref.tool_identity(Path("/usr/bin/ld"))}
        sysroot = Path(rustc).resolve(strict=True).parent.parent
        report["sysroot"] = str(sysroot)
        env = environment(output)
        report["environment"] = env
        plan = command_plan(output, rustc, linker, sysroot)
        for label, command, timeout in plan:
            if label == "rustc-compile":
                report["target_libraries"] = target_libraries(sysroot / "lib/rustlib" / TARGET / "lib", ref)
            save()
            row = ref.process(output, label, command, output / "crate", env, timeout)
            report["processes"].append(row)
            save()
            ref.require(row["passed"], "capture original build process failed: " + label)
            ref.require(ref.read(output, label + ".stderr") == b"", "capture original compiler diagnostics: " + label)
            if label == "rustc-version":
                version = ref.read(output, label + ".stdout").decode()
                ref.require(version.startswith("rustc 1.95.0 ") and "host: " + TARGET + "\n" in version,
                            "capture original compiler is not Rust 1.95.0 GNU Linux")
                report["rustc_version"] = version
            elif label == "rustc-sysroot":
                ref.require(ref.read(output, label + ".stdout") == (str(sysroot) + "\n").encode(), "actual sysroot differs")
            elif label == "rustc-target-libdir":
                ref.require(ref.read(output, label + ".stdout") ==
                            (str(sysroot / "lib/rustlib" / TARGET / "lib") + "\n").encode(), "actual target libraries differ")
        report["dependency_file"] = ref.pin(ref.read(output, "capture-path.d"))
        report["executable"] = ref.tool_identity(output / "capture-path-original")
        ref.exact(source_provenance(runtime, ref)[0], provenance, "capture source changed during build")
        report["status"] = "PASS"
    except Exception as exc:
        report["status"] = "FAIL"
        report["error"] = type(exc).__name__ + ": " + str(exc)
    report["duration_seconds"] = time.monotonic() - started
    save()
    if report["status"] == "PASS":
        try:
            evidence = read_evidence(runtime, output, rustc, linker)
            (output / "evidence.json").write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n")
        except Exception as exc:
            report["status"] = "FAIL"
            report["error"] = "read-back " + type(exc).__name__ + ": " + str(exc)
            save()
    return report, result

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rustc", type=Path, required=True)
    parser.add_argument("--linker", type=Path, default=Path("/usr/bin/cc"))
    parser.add_argument("--read-only", action="store_true")
    args = parser.parse_args()
    if args.read_only:
        print(json.dumps(read_evidence(args.runtime, args.output, args.rustc, args.linker), sort_keys=True))
        return 0
    report, result = run(args.runtime, args.output, args.rustc, args.linker)
    print(json.dumps({"status": report["status"], "result": str(result), "error": report["error"],
                      "actual_processes": len(report["processes"]), **scope()}, sort_keys=True))
    return 0 if report["status"] == "PASS" else 1

if __name__ == "__main__":
    raise SystemExit(main())

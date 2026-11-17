#!/usr/bin/env python3
"""CI-only fresh build from exact current target registry archive bytes."""
from pathlib import Path
import argparse
import hashlib
import io
import json
import os
import shutil
import stat
import sys
import tarfile
import tomllib

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from receipt_support import ROOT, SHA, PIN, require, regular, read_json, put, process

PACKAGE = "hepta-batch-sdk-current-original-oracle"
BINARIES = (PACKAGE,)


def build(rust_bin, output, target_checkout, core_source):
    require(os.environ.get("GITHUB_ACTIONS") == "true", "fresh Rust is restricted to the authorized CI host")
    rust_bin = Path(rust_bin).resolve(strict=True)
    output = Path(output).absolute()
    output.mkdir(parents=True, exist_ok=False)
    from verify_source import check
    proof = check(target_checkout, core_source)
    generated = {name: regular(ROOT / "project" / name) for name in proof["files"]}
    generated["SOURCE.json"] = regular(ROOT / "project/SOURCE.json")
    project = output / "project"
    project.mkdir()
    for name, raw in generated.items():
        require(regular(ROOT / "project" / name) == raw, "reference extraction drift: " + name)
        destination = project / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
    lock_seed = regular(Path(target_checkout) / "Cargo.lock")
    (project / "Cargo.lock").write_bytes(lock_seed)
    (output / "lock-before-metadata.toml").write_bytes(lock_seed)
    targets = {(p["name"], p["version"], p.get("source")): p.get("checksum")
        for p in tomllib.loads(lock_seed.decode())["package"] if p.get("source")}
    target = output / "target"
    environment = {"PATH": str(rust_bin) + ":/usr/bin:/bin", "RUSTC": str(rust_bin / "rustc"),
        "CARGO_TARGET_DIR": str(target), "CARGO_BUILD_JOBS": "2", "CARGO_INCREMENTAL": "0",
        "RUSTFLAGS": "", "CARGO_ENCODED_RUSTFLAGS": "", "RUSTC_WRAPPER": "", "RUSTC_WORKSPACE_WRAPPER": ""}
    report = {"schema": "hepta.runtime.extract-sdk-current-original-build.v1", "status": "RUNNING",
        "target_commit": proof["target_commit"], "target_lock": PIN(lock_seed), "project": "project",
        "fresh_original_build": False, "fresh_target_directory": True, "process_names": [],
        "source_inputs": {"files": {"project/" + name: PIN(raw) for name, raw in generated.items()}},
        "controlled_env": environment, "public_batch_qualified": False, "public_extract_qualified": False, "whole_runtime_replaced": False}
    report["source_inputs"]["files"].update({name: PIN(regular(ROOT / name)) for name in
        ("build_reference.py", "receipt_support.py", "verify_source.py",
         "authoring/author_public_reference.py", "authoring/public_reference_main.rs")})
    report["source_inputs"]["files"].update({name: PIN(regular(ROOT / name)) for name in
        ("authoring/resolved-lock.toml", "authoring/lock-origin.json")})
    report["independent_target_checkout"] = str(Path(target_checkout).resolve(strict=True))
    report["target_files"] = proof["target_files"]
    put(output / "BUILD.json", report)
    processes = output / "processes"
    def run(name, argv):
        row, stdout, stderr = process(processes, name, argv, cwd=project, env=environment)
        report["process_names"].append(name)
        put(output / "BUILD.json", report)
        return row, stdout, stderr
    registry = []
    packages = []
    try:
        _, version, _ = run("rustc-version", [rust_bin / "rustc", "--version", "--verbose"])
        require(version.decode().splitlines()[0] == "rustc 1.95.0 (59807616e 2026-04-14)", "actual Rust compiler version")
        run("cargo-version", [rust_bin / "cargo", "--version", "--verbose"])
        _, metadata_raw, _ = run("metadata-offline", [rust_bin / "cargo", "metadata", "--offline", "--format-version", "1"])
        metadata = json.loads(metadata_raw)
        lock = regular(project / "Cargo.lock")
        require(lock == regular(ROOT / "project/Cargo.lock"), "fresh target subset changed the independently retained fixture lock")
        for package in tomllib.loads(lock.decode())["package"]:
            if not package.get("source"):
                require(package["name"] == PACKAGE and package["version"] == "0.1.0", "fixture package identity")
            else:
                key = package["name"], package["version"], package["source"]
                require(targets.get(key) == package["checksum"], "fixture lock escaped exact target: " + repr(key))
                packages.append({k: package[k] for k in ("name", "version", "source", "checksum")})
        archive_dir = output / "registry-archives"
        archive_dir.mkdir()
        for package in metadata["packages"]:
            if not package.get("source"):
                require(package["name"] == PACKAGE, "unexpected local dependency")
                continue
            key = package["name"], package["version"], package["source"]
            require(key in targets, "registry source absent from target lock")
            crate = Path(package["manifest_path"]).parent
            source_archive = crate.parent.parent.parent / "cache" / crate.parent.name / (crate.name + ".crate")
            archived = regular(source_archive)
            require(SHA(archived) == targets[key], "registry archive checksum differs")
            source_files = {}
            with tarfile.open(fileobj=io.BytesIO(archived), mode="r:gz") as archive:
                for member in archive.getmembers():
                    parts = Path(member.name).parts
                    require(parts and parts[0] == crate.name and ".." not in parts, "registry archive member path")
                    if member.isdir():
                        continue
                    require(member.isfile() and len(parts) > 1, "registry archive non-file")
                    relative = str(Path(*parts[1:]))
                    raw = archive.extractfile(member).read()
                    require(regular(crate / relative) == raw, "actual registry compiler input differs: " + relative)
                    source_files[relative] = PIN(raw)
            name = crate.name + ".crate"
            (archive_dir / name).write_bytes(archived)
            registry.append({"name": package["name"], "version": package["version"], "source": package["source"],
                "source_directory": str(crate), "checksum": targets[key], "archive": "registry-archives/" + name,
                "archive_pin": PIN(archived), "files": source_files})
        require(not target.exists(), "metadata unexpectedly created the fresh build target")
        run("cargo-build-locked-offline", [rust_bin / "cargo", "build", "--locked", "--offline", "--release", "--bins"])
        require(regular(project / "Cargo.lock") == lock, "locked build modified dependency resolution")
        for item in registry:
            for name, expected in item["files"].items():
                require(PIN(regular(Path(item["source_directory"]) / name)) == expected,
                        "registry compiler input changed during build")
        binaries = {}
        compiler_binary_copies = {}
        (output / "bin").mkdir()
        for name in BINARIES:
            compiled = target / "release" / name
            info = compiled.lstat()
            require(stat.S_ISREG(info.st_mode) and compiled.resolve(strict=True) == compiled,
                    "fresh compiler result is not a regular executable")
            # Cargo may link its public executable name to its own deps alias.
            # Retain an independent full-byte copy, then detach only this owned
            # alias so every admitted evidence file has a single owner.
            raw = compiled.read_bytes()
            after = compiled.lstat()
            require((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
                    == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
                    "fresh compiler executable changed while copied")
            require(raw.startswith(b"\x7fELF"), "fresh reference is not an ELF")
            destination = output / "bin" / name
            destination.write_bytes(raw)
            destination.chmod(0o500)
            detached = compiled.with_name(name + ".evidence-copy")
            with detached.open("xb") as stream:
                stream.write(raw)
            detached.chmod(0o500)
            os.replace(detached, compiled)
            require(regular(compiled) == regular(destination) == raw,
                    "independent fresh executable copy changed bytes")
            compiler_binary_copies[name] = {"compiler_path": str(compiled), "compiler_links": info.st_nlink,
                "compiler_bytes": PIN(raw), "independent_evidence_copy": True}
            binaries[name] = dict(path="bin/" + name, **PIN(raw))
        require(report["source_inputs"]["files"] == {name: PIN(regular(ROOT / name))
                for name in report["source_inputs"]["files"]}, "reference source changed during build")
        require(check(target_checkout, core_source) == proof, "original target or source changed during build")
        report.update(status="PASS", fresh_original_build=True, rustc_version=version.decode(),
            fixture_lock=PIN(lock), retained_packages=packages, registry_sources=registry, binaries=binaries,
            compiler_binary_copies=compiler_binary_copies,
            original_body_fragments=15, original_parameter_fragments=2, extract_original_spans=13, actual_target_sdk="3.9.0",
            actual_target_tokio="1.53.3", all_retained_exactly_match_target=True,
            actual_reference_executions=0, fresh_rust_targets=[str(target)])
        put(output / "BUILD.json", report)
        return report
    except BaseException as error:
        report.update(status="FAIL", failure=repr(error), fresh_original_build=False,
                      retained_packages=packages, registry_sources=registry)
        put(output / "BUILD.json", report)
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rust-bin", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--core", type=Path, required=True)
    args = parser.parse_args()
    result = build(args.rust_bin, args.output, args.target, args.core)
    print(json.dumps({key: result[key] for key in ("status", "fresh_original_build", "binaries",
        "actual_target_sdk", "actual_target_tokio", "actual_reference_executions")}, sort_keys=True))

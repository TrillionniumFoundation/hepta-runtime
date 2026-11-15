# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Fresh locked Rust reference build and complete private-result replays."""
from pathlib import Path, PurePosixPath
from functools import lru_cache
import gzip
import io
import json
import os
import shutil
import signal
import subprocess
import tarfile
import time
import tomllib

from result_value_registry import (BINS, COUNTS, DOMAINS, REFERENCE, FIXTURES, REMOVED_ENVIRONMENT,
    encoded, regular, require, sha, source_pins, sdk_sources)


def identity(path):
    raw = regular(path)
    return dict(bytes=len(raw), sha256=sha(raw))


def reference_inputs(root):
    root = Path(root)
    project = root / REFERENCE
    proof = json.loads(regular(project / "source-projection.json"))
    require(proof.get("schema") == "hepta.result-values.original-source-projection.v1"
        and proof.get("original_function_blocks") == len(proof.get("blocks", [])) == 11
        and proof.get("one_shared_cargo_build") is True, "original reference projection changed")
    actual = {p.name: identity(p) for p in project.iterdir() if p.is_file() and p.name != "source-projection.json"}
    require(actual == proof["files"], "original reference project changed")
    for item in proof["blocks"]:
        source = regular(root / item["source"])
        target = regular(project / item["target"])
        block = source[item["offset"]:item["offset"] + item["bytes"]]
        require(sha(source) == item["source_sha256"] and len(block) == item["bytes"] and sha(block) == item["sha256"]
            and target[item["target_offset"]:item["target_offset"] + item["bytes"]] == block,
            "original function bytes changed: " + item["source"])
    row = proof["json_size"]
    source = regular(root / row["source"])
    target = regular(project / row["target"])
    require(len(source) == row["bytes"] and sha(source) == row["sha256"]
        and target[row["target_offset"]:] == source, "complete original JSON byte counter changed")
    lock_raw = regular(project / "original-runtime.lock")
    require(sha(lock_raw) == proof["original_runtime_lock_sha256"] and lock_raw == regular(root / "Cargo.lock"),
        "original runtime dependency lock changed")
    locked = [p for p in tomllib.loads(regular(project / "Cargo.lock").decode())["package"] if "checksum" in p]
    original = {(p["name"], p["version"]): p for p in tomllib.loads(lock_raw.decode())["package"] if "checksum" in p}
    require(len(locked) == 100 and locked == proof["registry_packages"], "reference dependency set changed")
    for package in locked:
        other = original[(package["name"], package["version"])]
        require(all(package[k] == other[k] for k in ("name", "version", "source", "checksum")),
            "reference dependency differs from original runtime")
    manifest = tomllib.loads(regular(project / "Cargo.toml").decode())
    require({p["name"]: p["path"] for p in manifest["bin"]} == {
        BINS["binary32"]: "binary32.rs", BINS["typed"]: "typed_result.rs", BINS["request"]: "request_result.rs"}
        and manifest["dependencies"]["serde_json"]["features"] == ["float_roundtrip", "raw_value"],
        "original typed serialization features or binaries changed")
    return proof


def run(name, command, folder, cwd, env, timeout=180, stdin=None):
    """Retain successful and failed process streams under the original limit."""
    folder = Path(folder)
    begin = time.monotonic()
    timed = False
    # The outer qualifier owns this isolated group and its unchanged deadline.
    with (folder / (name + ".stdout")).open("xb") as stdout, (folder / (name + ".stderr")).open("xb") as stderr:
        child = subprocess.Popen(list(map(str, command)), cwd=cwd, env=env, stdin=stdin,
            stdout=stdout, stderr=stderr)
        group = os.getpgid(child.pid)
        require(group == os.getpgrp(), "original child escaped the outer process group")
        pending = dict(command=list(map(str, command)), cwd=str(cwd), pid=child.pid,
            state="RUNNING", process_group=group, inherits_outer_process_group=True, timeout_seconds=timeout)
        (folder / (name + ".receipt.json")).write_bytes(encoded(pending))
        try:
            child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed = True
            child.kill()
            child.wait(timeout=3)
    out, err = regular(folder / (name + ".stdout")), regular(folder / (name + ".stderr"))
    row = dict(command=list(map(str, command)), cwd=str(cwd), pid=child.pid, reaped=True,
        exit_code=child.returncode, timed_out=timed, timeout_seconds=timeout, cleanup_seconds=3,
        elapsed_seconds=time.monotonic() - begin, stdout_bytes=len(out), stdout_sha256=sha(out),
        stderr_bytes=len(err), stderr_sha256=sha(err), outer_parent_death_cleanup_qualified=False,
        process_group=group, inherits_outer_process_group=True)
    for suffix, value in (("stdout", out), ("stderr", err), ("receipt.json", encoded(row))):
        (folder / (name + "." + suffix)).write_bytes(value)
    require(child.returncode == 0 and not timed, "original process failed: " + name)
    return out, row


def files(root):
    root = Path(root)
    result = {}
    for path in sorted(root.rglob("*")):
        require(not path.is_symlink(), "registry or reference source contains a symlink")
        if path.is_dir():
            continue
        require(path.is_file(), "registry or reference source is not regular")
        relative = path.relative_to(root).as_posix()
        if relative not in (".cargo-ok", ".cargo-checksum.json"):
            result[relative] = identity(path)
    return result


@lru_cache(maxsize=128)
def archive_inventory(raw, prefix):
    """Hash every locked crate member; cache only immutable complete bytes."""
    result = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            require(not path.is_absolute() and ".." not in path.parts and path.parts
                and path.parts[0] == prefix, "registry archive member escapes its package")
            if member.isdir():
                continue
            require(member.isfile() and len(path.parts) > 1, "registry archive member is not regular")
            name = PurePosixPath(*path.parts[1:]).as_posix()
            require(member.name == prefix + "/" + name and name not in result,
                "registry archive member is noncanonical or duplicated")
            value = archive.extractfile(member).read()
            require(len(value) == member.size, "registry archive member is truncated")
            result[name] = (len(value), sha(value))
    require(result, "registry archive contains no source files")
    return tuple((name, *value) for name, value in sorted(result.items()))


def archive_files(raw, prefix):
    return {name: {"bytes": size, "sha256": digest} for name, size, digest in archive_inventory(raw, prefix)}


def registry_sources(root, project, metadata):
    proof = reference_inputs(root)
    expected = {(p["name"], p["version"], p["source"]): p for p in proof["registry_packages"]}
    packages = [p for p in metadata["packages"] if p.get("source") is not None]
    require(len(packages) == 100 and {(p["name"], p["version"], p["source"]) for p in packages} == set(expected),
        "actual Cargo package domain differs")
    roots, checked, archives = {}, [], {}
    retained = project.parent / "registry-archives"
    retained.mkdir(mode=0o700, exist_ok=True)
    for package in packages:
        source = Path(package["manifest_path"]).parent
        name = package["name"] + "-" + package["version"]
        require(source.name == name and source.parent.parent.name == "src",
            "actual Cargo package source location differs")
        roots[name] = source
        expected_package = expected[(package["name"], package["version"], package["source"])]
        archive = source.parents[2] / "cache" / source.parent.name / (name + ".crate")
        raw = regular(archive)
        require(sha(raw) == expected_package["checksum"], "actual registry package checksum differs")
        members = archive_files(raw, name)
        require(files(source) == members, "actual locked registry source differs from complete package archive")
        target = retained / (name + ".crate")
        if target.exists():
            require(regular(target) == raw, "retained registry archive changed")
        else:
            with target.open("xb") as stream:
                stream.write(raw)
        archives[name] = {"path": "registry-archives/" + target.name, "bytes": len(raw), "sha256": sha(raw),
            "files": len(members), "files_sha256": sha(encoded(members))}
        checked.append({k: expected_package[k] for k in ("name", "version", "source", "checksum")})
    require(files(roots["rmcp-3.4.1"]) == sdk_sources(root), "complete actual SDK source bytes differ")
    crates = json.loads(regular(project / "crate-sources.json"))
    require(set(crates) == {"serde_json-1.0.151", "zmij-1.0.23"}
        and {name: files(roots[name]) for name in crates} == crates, "actual number serialization source bytes differ")
    return dict(packages=sorted(checked, key=lambda row: (row["name"], row["version"])),
        actual_sdk_sources=sdk_sources(root), actual_number_sources=crates,
        archives=archives, registry_source_files_verified=sum(row["files"] for row in archives.values()))


def environment(rustc, target):
    env = {k: v for k, v in os.environ.items() if not k.startswith("HIA_") and k not in REMOVED_ENVIRONMENT
           and not (k.startswith("CARGO_TARGET_") and k.endswith("_RUSTFLAGS"))}
    # A rustup shim must keep its selected invocation path and argv[0].
    env.update(RUSTC=str(Path(rustc).absolute()), CARGO_TARGET_DIR=str(target),
        PATH=str(Path(rustc).absolute().parent) + os.pathsep + env.get("PATH", os.defpath))
    return env


def build_reference(root, original, rustc, cargo):
    root, original = Path(root).resolve(strict=True), Path(original).resolve()
    folder = original / "build"
    if (folder / "result.json").exists():
        from hia_native_result_qualification import reference_build_evidence
        return reference_build_evidence(root, original, rustc=rustc, cargo=cargo)["result"]
    folder.mkdir(mode=0o700, parents=True, exist_ok=False)
    project = folder / "reference"
    shutil.copytree(root / REFERENCE, project)
    target = folder / "cargo-target"
    env = environment(rustc, target)
    pins, proof = source_pins(root), reference_inputs(root)
    report = dict(schema="hepta.result-values.original-build.v1", status="RUNNING", sources=pins,
        project_files=files(project), source_projection=proof, checks={}, one_shared_cargo_build=True,
        environment_removed=list(REMOVED_ENVIRONMENT), inherited_hia_environment=False,
        clear_target_rustflags=True, outer_process_group=os.getpgrp(),
        rustc_path=str(Path(rustc).absolute()), cargo_path=str(Path(cargo).absolute()),
        native_execution_or_fallback=False, whole_runtime_replaced=False, production_activated=False)
    save = lambda: (folder / "result.json").write_bytes(encoded(report))
    save()
    started = time.monotonic()
    try:
        command = [Path(rustc).absolute(), "--version", "--verbose"]
        out, report["checks"]["rust-version"] = run("rust-version", command, folder, root, env, 30)
        require(out.startswith(b"rustc 1.95.0 ") and b"release: 1.95.0\n" in out
            and b"commit-hash: 59807616e1fa2540724bfbac14d7976d7e4a3860\n" in out,
            "original comparison requires the fixed Rust 1.95 toolchain")
        command = [Path(cargo).absolute(), "metadata", "--manifest-path", project / "Cargo.toml", "--format-version", "1", "--locked"]
        out, report["checks"]["metadata"] = run("metadata", command, folder, root, env, 60)
        metadata = json.loads(out)
        report["registry"] = registry_sources(root, project, metadata)
        rustfmt = Path(rustc).absolute().with_name("rustfmt")
        command = [rustfmt, "--check", "--edition", "2021", "--config", "hard_tabs=true,skip_children=true",
            *[project / name for name in ("binary32.rs", "typed_result.rs", "request_result.rs", "json_size.rs")]]
        _, report["checks"]["format"] = run("format", command, folder, root, env, 30)
        command = [Path(cargo).absolute(), "build", "--manifest-path", project / "Cargo.toml", "--release", "--locked", "--bins"]
        _, report["checks"]["compile"] = run("compile", command, folder, root, env, 180)
        binary_folder = folder / "bin"
        binary_folder.mkdir()
        report["executables"] = {}
        for domain, name in BINS.items():
            source, destination = target / "release" / name, binary_folder / name
            raw = regular(source)
            require(raw.startswith(b"\x7fELF"), "actual Rust executable is not ELF")
            destination.write_bytes(raw)
            destination.chmod(0o500)
            report["executables"][domain] = {"path": str(destination), **identity(destination)}
        require(source_pins(root) == pins and reference_inputs(root) == proof
            and files(project) == report["project_files"] and registry_sources(root, project, metadata) == report["registry"],
            "original source changed during compilation")
        # Keep the three compiled executables, full metadata and process logs.
        # The owned intermediate Cargo target is not part of the replay input.
        shutil.rmtree(target)
        report.update(status="PASS", intermediate_target_retired=True, original_sources_unchanged=True,
            elapsed_seconds=time.monotonic() - started)
    except BaseException as error:
        report.update(status="FAIL", error=repr(error), elapsed_seconds=time.monotonic() - started)
        raise
    finally:
        save()
    return report


def replay_domain(root, original, native, domain, rustc, cargo):
    root, original, native = Path(root).resolve(strict=True), Path(original).resolve(), Path(native).resolve(strict=True)
    require(domain in DOMAINS, "unknown original result domain")
    build = build_reference(root, original, rustc, cargo)
    folder = original / domain
    folder.mkdir(mode=0o700, parents=True, exist_ok=False)
    pins = source_pins(root)
    report = dict(schema="hepta.result-values.original-replay.v1", status="RUNNING", domain=domain, sources=pins,
        build_sha256=sha(regular(original / "build/result.json")), executable=build["executables"][domain],
        native_result_sha256=sha(regular(native / domain / "result.json")), cases=sum(COUNTS[domain].values()),
        actual_original_processes=0, actual_native_entries_added=0, inputs={}, checks={},
        outer_process_group=os.getpgrp(),
        whole_runtime_replaced=False, production_activated=False)
    save = lambda: (folder / "result.json").write_bytes(encoded(report))
    save()
    started = time.monotonic()
    names = {"binary32": {"main": "original"}, "typed": {"probes": "probes", "cases": "original"},
        "request": {"probes": "original-budget-probes", "cases": "original-cases"}}[domain]
    fixtures = json.loads(regular(root / FIXTURES / "manifest.json"))["domains"][domain]
    env = environment(rustc, original / "build/cargo-target")
    try:
        for name, source in names.items():
            request_gz = regular(native / domain / source / "requests.bin.gz")
            wire = gzip.decompress(request_gz)
            expected = fixtures[name]
            require((len(wire), sha(wire)) == (expected["request_bytes"], expected["request_sha256"]),
                "original replay input differs from the complete native corpus")
            request = folder / (name + ".stdin.bin")
            request.write_bytes(wire)
            (folder / (name + ".stdin.bin.gz")).write_bytes(request_gz)
            with request.open("rb") as stream:
                stdout, receipt = run(name, [build["executables"][domain]["path"]], folder, root, env, 180, stream)
            receipt.update(stdin_bytes=len(wire), stdin_sha256=sha(wire), cases=COUNTS[domain][name],
                executable_sha256=build["executables"][domain]["sha256"])
            (folder / (name + ".receipt.json")).write_bytes(encoded(receipt))
            report["checks"][name] = receipt
            report["actual_original_processes"] += 1
            require(not regular(folder / (name + ".stderr")), "actual original reference wrote an error")
            require((len(stdout), sha(stdout)) == (expected["raw_bytes"], expected["raw_sha256"])
                and stdout.count(b"\n") == COUNTS[domain][name], "fresh original complete output differs")
            retained = gzip.decompress(regular(native / domain / source / "retained.stdout.gz"))
            require(stdout == retained, "fresh original bytes differ from the native reference join")
            packed = gzip.compress(stdout, compresslevel=6, mtime=0)
            (folder / (name + ".stdout.gz")).write_bytes(packed)
            require(gzip.decompress(regular(folder / (name + ".stdout.gz"))) == stdout, "original output retention changed")
            report["inputs"][name] = dict(request_bytes=len(wire), request_sha256=sha(wire),
                request_gzip_sha256=sha(request_gz), output_bytes=len(stdout), output_sha256=sha(stdout),
                output_gzip_sha256=sha(packed), native_fixture_receipt_sha256=sha(regular(native / domain / source / "receipt.json")),
                complete_bytes_equal=True)
            request.unlink()
            (folder / (name + ".stdout")).unlink()
            save()
        require(source_pins(root) == pins and sha(regular(native / domain / "result.json")) == report["native_result_sha256"]
            and sha(regular(build["executables"][domain]["path"])) == build["executables"][domain]["sha256"],
            "original or native source changed during replay")
        report.update(status="PASS", complete_bytes_equal=True, original_sources_unchanged=True,
            elapsed_seconds=time.monotonic() - started)
    except BaseException as error:
        report.update(status="FAIL", error=repr(error), elapsed_seconds=time.monotonic() - started)
        raise
    finally:
        save()
    return report

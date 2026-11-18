# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""One fresh Cargo build, four actual references, complete portable admission."""
from __future__ import annotations
import argparse
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import time
import tomllib
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parent))
from hia_native_session_transport_build import read, sha, object_at, require, relative
from hia_native_session_transport_admission import inventory
import hia_native_session_transport_capture as capture
import hia_native_session_transport_server as server

INPUT = "tests/hia_native/session_transport"
REFERENCE_SHA = "efb5c0f7f34d43b7068d6d06bafe0b3f4d22a45477d4263985c54482beeb87fd"
SELF = "scripts/hia_native_session_transport_reference.py"
DOMAIN_KEY = {"worker_owners": "worker", "handle_initialize": "initialize", "local_worker_error": "local_error"}
SELECTED = {"server": "hia-server-message-original", "worker": "hia-worker-owners-original",
            "initialize": "hia-handle-initialize-original", "local_error": "hia-local-worker-error-original"}
J = lambda value: (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode()


def pin(path):
    value = read(path)
    return {"bytes": len(value), "sha256": sha(value)}


def save(path, value):
    capture.save(Path(path), J(value))


def rewrite(path, value):
    path = Path(path)
    require(not path.is_symlink(), "report cannot be a symlink")
    path.write_bytes(J(value))


def inputs(root):
    root = Path(root)
    manifest = root / INPUT / "reference.json"
    require(sha(read(manifest)) == REFERENCE_SHA, "reference source manifest changed")
    reference = object_at(manifest)
    require(reference["schema"] == "hepta.runtime.session-reference-input.v1"
            and reference["selected_bins"] == SELECTED and reference["registry_dependencies"] == 139
            and reference["local_dependencies"] == 1 and reference["original_runtime_blocks"] == 312,
            "reference source profile differs")
    archive = root / INPUT / "reference-source.tar.gz"
    require(pin(archive) == reference["archive"], "reference source archive changed")
    snapshot = server.sources(root)
    for name in (SELF, INPUT + "/reference.json", INPUT + "/reference-source.tar.gz"):
        snapshot[name] = pin(root / name)
    return reference, snapshot


def unpack(root, destination, reference):
    destination.mkdir(mode=0o700)
    seen = set()
    with tarfile.open(Path(root) / INPUT / "reference-source.tar.gz", "r:gz") as archive:
        for member in archive:
            name = member.name
            path = PurePosixPath(name)
            require(member.isfile() and not path.is_absolute() and ".." not in path.parts
                    and path.as_posix() == name and name not in seen
                    and name in reference["members"], "unsafe or unexpected source member")
            seen.add(name)
            data = archive.extractfile(member).read()
            require({"bytes": len(data), "sha256": sha(data), "mode": member.mode} ==
                    reference["members"][name], "complete source member differs")
            target = relative(destination, name)
            target.parent.mkdir(parents=True, exist_ok=True)
            capture.save(target, data, member.mode)
            target.chmod(member.mode)
    require(seen == set(reference["members"]) and inventory(destination) == reference["members"],
            "complete source inventory differs")


def helper(source, reference):
    path = Path(source) / "public_lifecycle_crates.py"
    require(sha(read(path)) == reference["helper_sha256"], "crate admission helper changed")
    spec = importlib.util.spec_from_file_location("session_reference_crates", path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def tool_pin(path):
    path = Path(path).absolute()
    resolved = path.resolve(strict=True)
    return {"invocation_path": str(path), "resolved_path": str(resolved), **pin(resolved)}


def toolchain_paths(sysroot):
    sysroot = Path(sysroot)
    require(sysroot.is_absolute(), "actual compiler sysroot must be absolute")
    libraries = sorted((sysroot / "lib/rustlib/x86_64-unknown-linux-gnu/lib").glob("*.rlib"))
    drivers = sorted((sysroot / "lib").glob("librustc_driver-*.so"))
    require(libraries and drivers, "complete Rust standard library/toolchain unavailable")
    paths = [sysroot / "bin" / name for name in ("cargo", "rustc", "rustfmt")]
    paths.extend(libraries)
    paths.extend(drivers)
    require(len(set(paths)) == len(paths), "complete toolchain paths must be unique")
    return paths


def run(output, report, name, command, cwd, env, timeout, stdin_path=None):
    output, cwd = Path(output), Path(cwd)
    command = [str(value) for value in command]
    started = time.monotonic()
    row = {"name": name, "command": command, "cwd": str(cwd), "timeout_seconds": timeout,
           "pid": None, "pgid": os.getpgrp(), "exit_code": None, "timed_out": False,
           "stdin_bytes_consumed": None, "start_error": None}
    child = None
    stream = None
    try:
        if stdin_path is not None:
            stream = Path(stdin_path).open("rb", buffering=0)
        with (output / (name + ".stdout")).open("xb", buffering=0) as out, \
                (output / (name + ".stderr")).open("xb", buffering=0) as err:
            child = subprocess.Popen(command, cwd=cwd, env=env,
                                     stdin=stream if stream else subprocess.DEVNULL,
                                     stdout=out, stderr=err)
            row["pid"] = child.pid
            try:
                row["exit_code"] = child.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                row["timed_out"] = True
                child.kill()
                row["exit_code"] = child.wait()
    except OSError as error:
        row["start_error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        if stream is not None:
            row["stdin_bytes_consumed"] = stream.tell()
            stream.close()
        row["elapsed_seconds"] = time.monotonic() - started
        for label in ("stdout", "stderr"):
            path = output / (name + "." + label)
            if not path.exists():
                capture.save(path, b"")
            row[label] = pin(path)
        report["processes"].append(row)
        rewrite(output / "result.json", report)
    if row["timed_out"]:
        report.update(status="FAIL", error="owned process timeout: " + name)
        rewrite(output / "result.json", report)
        # This script is the explicitly owned process-group leader. Cargo's
        # descendants inherit this group; no detached compilation is created.
        require(os.getpid() == os.getpgrp(), "timeout group ownership differs")
        os.killpg(os.getpgrp(), signal.SIGKILL)
    require(row["exit_code"] == 0 and row["start_error"] is None,
            "actual reference process failed: " + name)
    return read(output / (name + ".stdout")), read(output / (name + ".stderr"))


def native_binding(root, manifest, native_output, server_output):
    owned = capture.verify(native_output, manifest, root)
    factory = server.verify(server_output, manifest, root)
    return {"manifest_sha256": sha(read(manifest)), "owned": owned, "server": factory,
            "native_capture_result": pin(Path(native_output) / "result.json"),
            "server_capture_result": pin(Path(server_output) / "result.json")}


def build(root, manifest, native_output, server_output, output, rust_bin):
    root, output = Path(root).absolute(), Path(output).absolute()
    require(os.getpid() == os.getpgrp(), "reference builder needs its owned process group")
    reference, sources = inputs(root)
    before = native_binding(root, manifest, native_output, server_output)
    output.mkdir(mode=0o700)
    report = {"schema": "hepta.runtime.session-reference-build.v1", "status": "RUNNING",
              "source_sha256": sources, "native_before": before, "processes": [],
              "fresh_cargo_builds": 0, "actual_original_processes": 0,
              "actual_native_processes": 0, "production_activated": False,
              "whole_runtime_replaced": False, "owner_pid": os.getpid(), "owner_pgid": os.getpgrp(),
              "build_origin": str(output)}
    rewrite(output / "result.json", report)
    try:
        source = output / "source"
        unpack(root, source, reference)
        crates = helper(source, reference)
        project = output / "project"
        shutil.copytree(source / "project", project)
        require(inventory(project) == reference["project_inventory"], "working project differs")
        env = {key: value for key, value in os.environ.items()
               if key not in crates.REMOVED and not key.startswith("HIA_")}
        invocation = Path(rust_bin).absolute() / "rustc"
        report["compiler_invocation"] = tool_pin(invocation)
        version, errors = run(output, report, "rustc-version", [invocation, "--version", "--verbose"], project, env, 10)
        require(b"release: 1.95.0\n" in version and not errors, "Rust 1.95.0 is required")
        sysroot_raw, errors = run(output, report, "rustc-sysroot", [invocation, "--print", "sysroot"], project, env, 10)
        require(not errors, "Rust sysroot query emitted stderr")
        sysroot = Path(sysroot_raw.decode().strip()).absolute()
        tc = sysroot / "bin"
        tools = toolchain_paths(sysroot)
        report["tools_before"] = {str(path): tool_pin(path) for path in tools}
        temporary, target = output / "temporary", output / "target"
        temporary.mkdir()
        require(not target.exists(), "fresh Cargo target already exists")
        env.update(PATH=str(tc) + os.pathsep + env.get("PATH", ""), RUSTC=str(tc / "rustc"),
                   RUSTFMT=str(tc / "rustfmt"), CARGO_BUILD_JOBS="2", CARGO_TARGET_DIR=str(target),
                   TMPDIR=str(temporary))
        # Metadata may fetch the exact locked registry packages in a fresh CI
        # runner. The following compile is offline and uses this checked set.
        metadata_raw, _ = run(output, report, "cargo-metadata", [tc / "cargo", "metadata", "--locked", "--format-version", "1"], project, env, 30)
        metadata = json.loads(metadata_raw)
        lock = tomllib.loads(read(project / "Cargo.lock").decode())
        original_lock = tomllib.loads(read(project / "original-runtime.lock").decode())
        report["registry_before"] = crates.registry(metadata, lock, original_lock, output / "registry")
        require(len(report["registry_before"]) == 139, "locked registry set differs")
        local = [row for row in metadata["packages"] if row.get("source") is None]
        require({row["name"] for row in local} == {"hia-public-read-original", "rmcp"}, "local package set differs")
        rmcp = next(row for row in local if row["name"] == "rmcp")
        require(rmcp["version"] == "3.4.1" and Path(rmcp["manifest_path"]) == project / "vendor/rmcp/Cargo.toml", "rmcp source differs")
        report["local_dependency"] = {"package": rmcp, "members": crates.files(project / "vendor/rmcp")}
        command = [tc / "cargo", "build", "--release", "--locked", "--offline"]
        for key in SELECTED:
            command.extend(["--bin", SELECTED[key]])
        rewrite(output / "result.json", report)
        run(output, report, "cargo-build", command, project, env, 120)
        report["fresh_cargo_builds"] = 1
        binaries = output / "binaries"
        binaries.mkdir()
        report["binaries"] = {}
        for key, name in SELECTED.items():
            origin = target / "release" / name
            retained = binaries / (name + ".elf")
            capture.save(retained, read(origin), 0o500)
            require(read(origin) == read(retained), "actual Cargo output copy differs")
            report["binaries"][key] = {"path": retained.relative_to(output).as_posix(),
                                      "origin": origin.relative_to(output).as_posix(), **pin(retained)}
        report["registry_after"] = crates.registry(metadata, lock, original_lock, output / "registry")
        require(report["registry_before"] == report["registry_after"], "registry sources changed during compilation")
        require(inventory(project) == reference["project_inventory"] and inventory(source) == reference["members"],
                "complete reference inputs changed during compilation")
        require(toolchain_paths(sysroot) == tools, "Rust toolchain member set changed")
        report["tools_after"] = {str(path): tool_pin(path) for path in tools}
        require(report["tools_after"] == report["tools_before"]
                and tool_pin(invocation) == report["compiler_invocation"], "Rust toolchain changed")
        require(inputs(root)[1] == sources, "repository source closure changed during compilation")
        report.update(status="BUILT_NOT_SEMANTICALLY_QUALIFIED", registry_packages=139, selected_binaries=4,
                      source_manifest_sha256=REFERENCE_SHA)
        rewrite(output / "result.json", report)
        verify_build(root, output)
        summary = {"status": "BUILT_NOT_SEMANTICALLY_QUALIFIED", "fresh_cargo_builds": 1,
                   "registry_packages": 139, "local_dependencies": 1, "selected_binaries": 4,
                   "actual_original_processes": 0, "actual_native_processes": 0}
        save(output / "build-summary.json", summary)
        return summary
    except BaseException as error:
        report.update(status="FAIL", error=repr(error), traceback=traceback.format_exc())
        rewrite(output / "result.json", report)
        raise


def derivation(source, reference):
    """Recover the complete parent and all four previously compiled projects."""
    source = Path(source)
    require(inventory(source) == reference["members"], "complete extracted source differs")
    proof = object_at(source / "derivation.json")
    require(sha(read(source / "derivation.json")) == reference["source_derivation_sha256"]
            and proof["project_inventory"] == reference["project_inventory"]
            and proof["selected_bins"] == SELECTED and proof["production_bytes_changed"] == 0,
            "source composition proof differs")
    parent = object_at(source / "origin/parent-derivation.json")
    recovered = {name: read(source / "project" / name) for name in reference["project_inventory"]}
    for name, row in proof["append_edits"].items():
        prefix = recovered[name][:row["original"]["bytes"]]
        require({"bytes": len(prefix), "sha256": sha(prefix)} == row["original"], "original dependency prefix differs")
        tails = [b"\n" + read(source / item["author"]) for item in row["appends"]]
        require(recovered[name] == prefix + b"".join(tails), "dependency append composition differs")
        for tail, item in zip(tails, row["appends"]):
            require(len(tail) == item["bytes"] and sha(tail) == item["sha256"], "complete dependency append differs")
        recovered[name] = prefix
    cargo = recovered["Cargo.toml"]
    require(sha(cargo[:proof["cargo_prefix_bytes"]]) == proof["cargo_prefix_sha256"]
            and cargo[proof["cargo_prefix_bytes"]:].hex() == proof["cargo_append_hex"], "Cargo composition does not invert")
    recovered["Cargo.toml"] = cargo[:parent["project_files"]["Cargo.toml"]["bytes"]]
    for key, row in proof["source_origins"].items():
        require(recovered.pop(row["main"]) == read(source / "authors" / (key + "-main.rs")), "original main changed")
    pins = lambda values: {name: {"bytes": len(raw), "sha256": sha(raw)} for name, raw in values.items()}
    require(pins(recovered) == parent["project_files"], "complete original parent does not recover")
    for key, row in proof["source_origins"].items():
        original = object_at(source / "origin" / (key + "-derivation.json"))
        require(sha(read(source / "origin" / (key + "-derivation.json"))) == row["derivation_sha256"], "original derivation differs")
        project = dict(recovered)
        project[row["main"]] = read(source / "authors" / (key + "-main.rs"))
        project["Cargo.toml"] += ('\n[[bin]]\nname="' + row["binary"] + '"\npath="' + row["main"] + '"\n').encode()
        if row["append_target"]:
            project[row["append_target"]] += b"\n" + read(source / "authors" / (key + "-append.rs"))
        require(pins(project) == original["project_files"], "complete compiled origin does not recover: " + key)
    return proof


def process_evidence(output, row, command, cwd, timeout, *, stdin=None, empty_stderr=False):
    require(row["command"] == list(map(str, command)) and row["cwd"] == str(cwd)
            and row["timeout_seconds"] == timeout and row["exit_code"] == 0
            and row["timed_out"] is False and row["start_error"] is None
            and type(row["pid"]) is int and row["pid"] > 0
            and type(row["pgid"]) is int and row["pgid"] > 0
            and type(row["elapsed_seconds"]) in (float, int)
            and 0 <= row["elapsed_seconds"] <= timeout, "actual completed reference process differs")
    for label in ("stdout", "stderr"):
        require(pin(Path(output) / (row["name"] + "." + label)) == row[label], "complete reference process stream differs")
    require(row["stdin_bytes_consumed"] == (None if stdin is None else len(stdin)), "actual process input consumption differs")
    if empty_stderr:
        require(read(Path(output) / (row["name"] + ".stderr")) == b"", "reference process emitted stderr")


def registry_evidence(source, output, report, metadata, reference):
    crates = helper(source, reference)
    project = Path(output) / "project"
    lock = tomllib.loads(read(project / "Cargo.lock").decode())
    original = tomllib.loads(read(project / "original-runtime.lock").decode())
    expected = {(row["name"], row["version"], row["source"]): row
                for row in lock["package"] if "checksum" in row}
    old = {(row["name"], row["version"], row["source"]): row
           for row in original["package"] if "checksum" in row}
    packages = [row for row in metadata["packages"] if row.get("source") is not None]
    require(len(expected) == len(packages) == 139
            and {(p["name"], p["version"], p["source"]) for p in packages} == set(expected), "actual locked package closure differs")
    require(report["registry_before"] == report["registry_after"], "complete before/after registry differs")
    records = report["registry_before"]
    require(set(records) == {p["name"] + "-" + p["version"] for p in packages}, "retained registry package set differs")
    def edges(package, universe):
        result = set()
        for edge in package.get("dependencies", []):
            words = edge.split()
            found = [(q["name"], q["version"]) for q in universe["package"]
                     if q["name"] == words[0] and (len(words) == 1 or q["version"] == words[1])]
            require(len(found) == 1, "ambiguous original locked edge")
            result.add(found[0])
        return result
    for package in packages:
        key = (package["name"], package["version"], package["source"])
        want = expected[key]
        require(all(want[x] == old[key][x] for x in ("name", "version", "source", "checksum"))
                and edges(want, lock) <= edges(old[key], original), "dependency identity/edge differs from original")
        prefix = package["name"] + "-" + package["version"]
        row = records[prefix]
        archive = Path(output) / "registry" / (prefix + ".crate")
        require(row["package"] == want and pin(archive) == row["archive"]
                and sha(read(archive)) == want["checksum"]
                and crates.package_files(read(archive), prefix) == row["members"]
                and Path(package["manifest_path"]).parent == Path(row["actual_source"]), "complete registry source/archive binding differs")
    require({p.name for p in (Path(output) / "registry").iterdir()} == {name + ".crate" for name in records}, "extra or missing retained crate")
    local = [p for p in metadata["packages"] if p.get("source") is None]
    require({p["name"] for p in local} == {"hia-public-read-original", "rmcp"}, "local package set differs")
    rmcp = next(p for p in local if p["name"] == "rmcp")
    require(rmcp == report["local_dependency"]["package"] and rmcp["version"] == "3.4.1"
            and Path(rmcp["manifest_path"]) == Path(report["build_origin"]) / "project/vendor/rmcp/Cargo.toml"
            and crates.files(project / "vendor/rmcp") == report["local_dependency"]["members"], "complete actual local dependency differs")


def verify_build(root, output):
    root, output = Path(root), Path(output)
    reference, sources = inputs(root)
    report = object_at(output / "result.json")
    require(report["schema"] == "hepta.runtime.session-reference-build.v1"
            and report["status"] == "BUILT_NOT_SEMANTICALLY_QUALIFIED"
            and report["source_sha256"] == sources and report["source_manifest_sha256"] == REFERENCE_SHA
            and report["fresh_cargo_builds"] == 1 and report["selected_binaries"] == 4
            and report["registry_packages"] == 139 and report["actual_original_processes"] == 0
            and report["actual_native_processes"] == 0
            and report["whole_runtime_replaced"] is report["production_activated"] is False,
            "actual reference build state or source binding differs")
    derivation(output / "source", reference)
    require(inventory(output / "project") == reference["project_inventory"], "actual compiled project changed")
    rows = report["processes"]
    require([row["name"] for row in rows] == ["rustc-version", "rustc-sysroot", "cargo-metadata", "cargo-build"], "actual build command sequence differs")
    origin = Path(report["build_origin"])
    invocation = report["compiler_invocation"]["invocation_path"]
    process_evidence(output, rows[0], [invocation, "--version", "--verbose"], origin / "project", 10, empty_stderr=True)
    require(b"release: 1.95.0\n" in read(output / "rustc-version.stdout"), "completed compiler version differs")
    process_evidence(output, rows[1], [invocation, "--print", "sysroot"], origin / "project", 10, empty_stderr=True)
    sysroot = Path(read(output / "rustc-sysroot.stdout").decode().strip())
    tc = sysroot / "bin"
    process_evidence(output, rows[2], [tc / "cargo", "metadata", "--locked", "--format-version", "1"], origin / "project", 30)
    command = [tc / "cargo", "build", "--release", "--locked", "--offline"]
    for key in SELECTED:
        command.extend(["--bin", SELECTED[key]])
    process_evidence(output, rows[3], command, origin / "project", 120)
    require(b"Finished `release` profile" in read(output / "cargo-build.stderr"), "actual Cargo completion missing")
    require(report["owner_pid"] == report["owner_pgid"]
            and len({row["pid"] for row in rows}) == 4
            and all(row["pgid"] == report["owner_pgid"] for row in rows), "owned compiler process identity differs")
    require(set(report["tools_before"]) == set(report["tools_after"]) ==
            {str(path) for path in toolchain_paths(sysroot)}
            and report["tools_before"] == report["tools_after"],
            "complete toolchain before/after member set or bytes differ")
    for path, wanted in report["tools_before"].items():
        require(tool_pin(path) == wanted, "actual pinned compiler/std source differs")
    require(tool_pin(invocation) == report["compiler_invocation"], "invocation executable differs")
    metadata = object_at(output / "cargo-metadata.stdout")
    registry_evidence(output / "source", output, report, metadata, reference)
    require(set(report["binaries"]) == set(SELECTED), "actual binary set differs")
    for key, binary in report["binaries"].items():
        name = SELECTED[key]
        require(binary["path"] == "binaries/" + name + ".elf"
                and binary["origin"] == "target/release/" + name, "Cargo binary origin path differs")
        expected = {"bytes": binary["bytes"], "sha256": binary["sha256"]}
        require(pin(relative(output, binary["path"])) == expected
                and pin(relative(output, binary["origin"])) == expected
                and stat.S_IMODE(relative(output, binary["path"]).stat().st_mode) == 0o500,
                "actual Cargo and retained executable differ")
    return {"result_sha256": sha(read(output / "result.json")), "binaries": report["binaries"],
            "source_sha256": sources, "registry_packages": 139, "fresh_cargo_builds": 1}


def case_input(root, key):
    root = Path(root)
    if key == "server":
        return read(root / server.ORIGIN / "reference-factory.stdin"), 90
    domain = next(k for k, v in DOMAIN_KEY.items() if v == key)
    cases = object_at(root / capture.ORIGIN / capture.DOMAIN[domain]["cases"])
    return b"".join((json.dumps(case, separators=(",", ":"), ensure_ascii=False) + "\n").encode() for case in cases), len(cases)


def pair(root, native_output, server_output, replay_output, key):
    root, replay_output = Path(root), Path(replay_output)
    raw = read(replay_output / (key + ".stdout"))
    if key == "server":
        expected = read(root / server.ORIGIN / "reference-factory.stdout")
        require(raw == expected, "complete actual Original Server JSONL differs from paired wire answers")
        answers = [json.loads(line) for line in raw.splitlines()]
        require(len(answers) == 90, "Server Original program count differs")
        fixture = object_at(root / server.ORIGIN / "factory-fixture.json")
        require(answers == fixture["answers"], "Server complete typed answers differ")
        return {"programs": 90, "paired_native_modes": 2, "stdout_sha256": sha(raw),
                "wire_answers_sha256": sha(J(answers)), "original_owned_factory_qualified": False}
    domain = next(k for k, v in DOMAIN_KEY.items() if v == key)
    cases = object_at(root / capture.ORIGIN / capture.DOMAIN[domain]["cases"])
    decoder, proof = capture.frames(root, domain)
    canonical, metrics = decoder.original_capture(raw, cases)
    for mode in (1, 2):
        native = object_at(Path(native_output) / domain / ("mode-" + str(mode)) / "canonical.json")
        require(canonical == native, "actual Original complete ownership/Waker flow differs: " + domain)
    return {"programs": len(cases), "paired_native_modes": 2, "canonical_sha256": sha(capture.J(canonical)),
            "metrics": metrics, "verifier_derivation": proof}


def replay(root, manifest, native_output, server_output, output):
    root, output = Path(root).absolute(), Path(output).absolute()
    require(os.getpid() == os.getpgrp(), "reference replay needs its owned process group")
    built = verify_build(root, output)
    before = native_binding(root, manifest, native_output, server_output)
    build_report = object_at(output / "result.json")
    require(before == build_report["native_before"], "retained native captures changed since compilation")
    folder = output / "replay"
    folder.mkdir(mode=0o700)
    report = {"schema": "hepta.runtime.session-reference-replay.v1", "status": "RUNNING",
              "build": built, "native_before": before, "processes": [], "domains": {},
              "actual_original_processes": 0, "actual_native_processes": 0,
              "whole_runtime_replaced": False, "production_activated": False,
              "origin": str(output), "owner_pid": os.getpid(), "owner_pgid": os.getpgrp()}
    rewrite(folder / "result.json", report)
    try:
        for key in SELECTED:
            wire, count = case_input(root, key)
            stdin_path = folder / (key + ".stdin")
            capture.save(stdin_path, wire)
            binary = relative(output, built["binaries"][key]["path"])
            _, stderr = run(folder, report, key, [binary], folder, os.environ.copy(), 30, stdin_path)
            report["actual_original_processes"] += 1
            require(not stderr, "actual Original emitted stderr")
            report["domains"][key] = pair(root, native_output, server_output, folder, key)
            require(report["domains"][key]["programs"] == count, "actual Original count differs")
            rewrite(folder / "result.json", report)
        report["native_after"] = native_binding(root, manifest, native_output, server_output)
        require(report["native_after"] == before and verify_build(root, output) == built,
                "source/compiled output/retained native evidence changed during Original execution")
        report.update(status="CAPTURED_NOT_QUALIFIED", actual_programs=342, paired_rows=684)
        rewrite(folder / "result.json", report)
        verify_replay(root, manifest, native_output, server_output, output, captured=True)
        report["status"] = "PASS"
        rewrite(folder / "result.json", report)
        summary = {"status": "PASS", "actual_original_processes": 4, "actual_native_processes": 0,
                   "actual_programs": 342, "paired_rows": 684, "owned_original_programs": 252,
                   "server_wire_programs": 90, "domains": report["domains"],
                   "whole_runtime_replaced": False, "production_activated": False}
        save(output / "replay-summary.json", summary)
        return summary
    except BaseException as error:
        report.update(status="FAIL", error=repr(error), traceback=traceback.format_exc())
        rewrite(folder / "result.json", report)
        raise


def verify_replay(root, manifest, native_output, server_output, output, *, captured=False):
    root, output = Path(root), Path(output)
    built = verify_build(root, output)
    current = native_binding(root, manifest, native_output, server_output)
    folder = output / "replay"
    report = object_at(folder / "result.json")
    require(report["schema"] == "hepta.runtime.session-reference-replay.v1"
            and report["status"] == ("CAPTURED_NOT_QUALIFIED" if captured else "PASS")
            and report["build"] == built and report["native_before"] == report["native_after"] == current
            and report["actual_original_processes"] == 4 and report["actual_native_processes"] == 0
            and report["actual_programs"] == 342 and report["paired_rows"] == 684
            and report["whole_runtime_replaced"] is report["production_activated"] is False,
            "complete reference replay state differs")
    rows = report["processes"]
    require([row["name"] for row in rows] == list(SELECTED) and len({row["pid"] for row in rows}) == 4
            and report["owner_pid"] == report["owner_pgid"]
            and all(row["pgid"] == report["owner_pgid"] for row in rows), "actual semantic process identity differs")
    expected_files = {"result.json"}
    domains = {}
    for key, row in zip(SELECTED, rows):
        wire, count = case_input(root, key)
        require(read(folder / (key + ".stdin")) == wire, "actual Original stdin differs from exact corpus")
        origin = Path(report["origin"])
        process_evidence(folder, row, [origin / built["binaries"][key]["path"]], origin / "replay", 30,
                         stdin=wire, empty_stderr=True)
        domains[key] = pair(root, native_output, server_output, folder, key)
        require(domains[key]["programs"] == count, "independent program count differs")
        expected_files.update(key + suffix for suffix in (".stdin", ".stdout", ".stderr"))
    require({p.name for p in folder.iterdir()} == expected_files and domains == report["domains"],
            "complete semantic capture inventory/projection differs")
    return domains


def verify(root, manifest, native_output, server_output, output):
    output = Path(output)
    domains = verify_replay(root, manifest, native_output, server_output, output)
    build_summary = {"status": "BUILT_NOT_SEMANTICALLY_QUALIFIED", "fresh_cargo_builds": 1,
                     "registry_packages": 139, "local_dependencies": 1, "selected_binaries": 4,
                     "actual_original_processes": 0, "actual_native_processes": 0}
    require(object_at(output / "build-summary.json") == build_summary, "build completion summary differs")
    replay_summary = {"status": "PASS", "actual_original_processes": 4, "actual_native_processes": 0,
                      "actual_programs": 342, "paired_rows": 684, "owned_original_programs": 252,
                      "server_wire_programs": 90, "domains": domains,
                      "whole_runtime_replaced": False, "production_activated": False}
    require(object_at(output / "replay-summary.json") == replay_summary, "replay completion summary differs")
    files = {p for name in ("source", "project", "registry", "binaries", "replay")
             for p in (output / name).rglob("*") if p.is_file()}
    files.update(p for p in output.iterdir() if p.is_file())
    files.update(output / "target/release" / name for name in SELECTED.values())
    return {"schema": "hepta.runtime.session-original-evidence.v1", "status": "PASS",
            "fresh_cargo_builds": 1, "registry_packages": 139, "local_dependencies": 1,
            "actual_original_processes": 4, "actual_native_processes": 0,
            "actual_programs": 342, "paired_rows": 684, "domains": domains,
            "artifact_sha256": {p.relative_to(output).as_posix(): sha(read(p)) for p in sorted(files)},
            "whole_runtime_replaced": False, "production_activated": False}


def main():
    parser = argparse.ArgumentParser()
    for name in ("root", "manifest", "native-output", "server-output", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    sub = parser.add_subparsers(dest="operation", required=True)
    sub.add_parser("build").add_argument("--rust-bin", type=Path, required=True)
    sub.add_parser("replay")
    sub.add_parser("verify")
    args = parser.parse_args()
    common = (args.root, args.manifest, args.native_output, args.server_output, args.output)
    result = build(*common, args.rust_bin) if args.operation == "build" else \
             replay(*common) if args.operation == "replay" else verify(*common)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()

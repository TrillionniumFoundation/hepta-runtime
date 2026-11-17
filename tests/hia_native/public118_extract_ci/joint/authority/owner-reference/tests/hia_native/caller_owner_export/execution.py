"""Execution-only support, never imported by the read-only evidence reader."""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import tarfile
import time
import tomllib

from common import BASE, SDK_MODEL_SHA, document, encoded, put, read, require, sha, tree_files

LIMITS = {"native-build": 300, "native-replay": 60, "legacy-replay": 60, "kernel-replay": 60, "rustc-version": 30,
          "cargo-version": 30, "cargo-build": 300, "cargo-metadata": 120, "original-replay": 60, "original-legacy": 60, "original-kernel": 60,
          "reader-controls": 180, "readonly-one": 60, "readonly-two": 60}


def execute(capture, label, command, *, cwd, env, stdin=None):
    limit = LIMITS[label]
    folder = capture / "processes"
    folder.mkdir(exist_ok=True)
    stdout, stderr = folder / (label + ".stdout"), folder / (label + ".stderr")
    receipt = {"schema": "hepta.runtime.owner-export-process.v1", "label": label,
        "command": [str(x) for x in command], "cwd": str(cwd), "timeout_seconds": limit,
        "parent_pid": os.getpid(), "start_new_session": True, "pid": None, "pgid": None,
        "returncode": None, "timed_out": False, "started": False,
        "stdin": None if stdin is None else str(stdin.relative_to(capture)),
        "stdin_sha256": None if stdin is None else sha(read(stdin)),
        "environment": {key: env.get(key) for key in ("RUSTUP_TOOLCHAIN", "CARGO_HOME", "CARGO_TARGET_DIR",
            "CARGO_ENCODED_RUSTFLAGS", "PYTHONDONTWRITEBYTECODE", "PYTHONHASHSEED", "HIA_REFERENCE_RUNTIME")}}
    process = None
    error = None
    begin = time.monotonic_ns()
    try:
        with stdout.open("xb") as out, stderr.open("xb") as err, \
             (open(os.devnull, "rb") if stdin is None else stdin.open("rb")) as inp:
            process = subprocess.Popen([str(x) for x in command], cwd=cwd, env=env, stdin=inp,
                                       stdout=out, stderr=err, start_new_session=True)
            receipt.update(started=True, pid=process.pid, pgid=process.pid)
            try:
                receipt["returncode"] = process.wait(timeout=limit)
            except subprocess.TimeoutExpired:
                receipt["timed_out"] = True
                raise
    except BaseException as exc:
        error = exc
    finally:
        # No receipt write may prevent child/group cleanup, including ENOSPC.
        if process is not None:
            try:
                if process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            finally:
                receipt["returncode"] = process.wait()
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        receipt["elapsed_ns"] = time.monotonic_ns() - begin
        if error is not None:
            receipt["failure"] = {"type": type(error).__name__, "message": str(error)}
        for key, path in (("stdout", stdout), ("stderr", stderr)):
            raw = read(path) if path.exists() else b""
            receipt[key] = {"path": path.relative_to(capture).as_posix(), "bytes": len(raw), "sha256": sha(raw)}
        put(folder / (label + ".json"), receipt)
    if error is not None:
        raise error
    require(receipt["returncode"] == 0 and not receipt["timed_out"], "actual process failed: " + label)
    return receipt


def reference_environment(work):
    env = dict(os.environ)
    blocked = {"RUSTFLAGS", "RUSTDOCFLAGS", "RUSTC", "RUSTDOC", "RUSTC_WRAPPER",
               "RUSTC_WORKSPACE_WRAPPER", "CARGO_ENCODED_RUSTFLAGS", "CARGO_ENCODED_RUSTDOCFLAGS",
               "CARGO_BUILD_RUSTC", "CARGO_BUILD_RUSTC_WRAPPER", "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
               "CARGO_BUILD_TARGET", "CARGO_BUILD_TARGET_DIR", "CARGO_BUILD_RUSTDOC"}
    for key in list(env):
        if key in blocked or (key.startswith("CARGO_") and
                              (key.endswith("RUSTFLAGS") or key.endswith("RUSTDOCFLAGS") or
                               key.endswith("_LINKER") or key.endswith("_RUNNER"))):
            del env[key]
    env.update(RUSTUP_TOOLCHAIN="1.95.0", CARGO_HOME=str(work / "cargo-home"),
               CARGO_TARGET_DIR=str(work / "cargo-target"), CARGO_ENCODED_RUSTFLAGS="",
               CARGO_ENCODED_RUSTDOCFLAGS="", PYTHONDONTWRITEBYTECODE="1", PYTHONHASHSEED="0")
    return env


def registry_snapshot(capture, metadata, lock_raw, cargo_home):
    locked = {(p["name"], p["version"]): p for p in tomllib.loads(lock_raw.decode())["package"]
              if "source" in p}
    rows = {}
    for package in metadata["packages"]:
        if package["source"] is None:
            require(package["name"] == "hia-caller-owner-export-reference" and package["version"] == "0.0.0", "unexpected local original dependency")
            continue
        key = package["name"], package["version"]
        require(key in locked and package["source"] == locked[key]["source"], "unlocked original registry package")
        name = package["name"] + "-" + package["version"]
        crate_candidates = list((cargo_home / "registry/cache").glob("*/" + name + ".crate"))
        require(len(crate_candidates) == 1, "registry archive custody: " + name)
        archive = read(crate_candidates[0])
        require(sha(archive) == locked[key]["checksum"], "registry archive checksum: " + name)
        source = Path(package["manifest_path"]).parent
        originals = {}
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
            for member in tar:
                if member.isdir():
                    continue
                require(member.isfile() and member.name.startswith(name + "/"), "registry archive member kind")
                relative = member.name[len(name) + 1:]
                require(relative not in originals and ".." not in Path(relative).parts, "registry archive member path")
                raw = tar.extractfile(member).read()
                originals[relative] = sha(raw)
                require(read(source / relative) == raw, "actual registry source differs from its locked crate: " + name + "/" + relative)
                if name == "rmcp-3.9.0" and relative == "src/model.rs":
                    require(sha(raw) == SDK_MODEL_SHA, "current ProtocolVersion owner source differs")
        observed = tree_files(source)
        metadata_names = set(observed) - set(originals)
        require(set(originals) <= set(observed) and metadata_names <= {".cargo-ok", ".cargo-checksum.json"},
                "unexpected actual registry source files: " + name)
        metadata_hex = {relative: read(source / relative).hex() for relative in sorted(metadata_names)}
        # Cargo 1.95's fetched registry cache need not have a checksum sidecar.
        # The locked archive and every actual source file above are authoritative;
        # keep cache bookkeeping exactly as observed, without fabricating it.
        if ".cargo-checksum.json" in metadata_hex:
            checksums = json.loads(bytes.fromhex(metadata_hex[".cargo-checksum.json"]))
            require(checksums["package"] == locked[key]["checksum"] and
                    checksums["files"] in ({}, originals), "Cargo checksum sidecar differs")
        source_proof = {"schema": "hepta.runtime.owner-export-registry-source.v1",
            "package_sha256": locked[key]["checksum"], "actual_source_files": originals,
            "actual_file_set": sorted(observed), "cache_metadata_hex": metadata_hex,
            "actual_manifest_sha256": sha(read(source / "Cargo.toml"))}
        put(capture / "registry" / (name + ".crate"), archive)
        put(capture / "registry" / (name + ".source-proof.json"), source_proof)
        rows[name] = {"name": key[0], "version": key[1], "source": package["source"],
            "checksum": locked[key]["checksum"], "archive_bytes": len(archive),
            "actual_source_files": originals, "source_proof_sha256": sha(encoded(source_proof)),
            "metadata_id": package["id"]}
    require("rmcp-3.9.0" in rows and "tokio-1.53.3" in rows, "missing actual current SDK registry")
    put(capture / "registry.json", {"schema": "hepta.runtime.owner-export-registry.v1", "packages": rows})


def seal(capture, pins_sha):
    from common import tree_files
    put(capture / "CAPTURE.json", {"schema": "hepta.runtime.owner-export-capture.v1",
        "source_pins_sha256": pins_sha, "files": tree_files(capture)})

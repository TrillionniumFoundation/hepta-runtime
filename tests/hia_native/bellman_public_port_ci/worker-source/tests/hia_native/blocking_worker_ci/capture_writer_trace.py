"""Fresh locked original writer tracing; development evidence, no full gate claim."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tarfile
import time
import tomllib

BASE = "tests/hia_native/blocking_worker_ci"
ORIGINAL = "tests/hia_native/blocking_worker/reference/weight_bellman.rs"
ORIGINAL_SHA = "254de61b7a169ab0a01583feb9562051fa9d477d89d98683263c52ea5545a4a7"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def put(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value if isinstance(value, bytes) else (json.dumps(value, indent=2, sort_keys=True) + "\n").encode())


def run(output, label, command, env, *, limit, stdin=None):
    directory = output / "processes"
    directory.mkdir(exist_ok=True)
    stdout, stderr = directory / (label + ".stdout"), directory / (label + ".stderr")
    row = {"label": label, "command": [str(x) for x in command], "cwd": str(output), "parent_pid": os.getpid(),
           "pid": None, "pgid": None, "timeout_seconds": limit, "started": False, "timed_out": False,
           "stdin_sha256": None if stdin is None else sha(stdin),
           "environment": {k: env.get(k) for k in ["RUSTUP_TOOLCHAIN", "CARGO_HOME", "CARGO_TARGET_DIR", "CARGO_ENCODED_RUSTFLAGS"]}}
    process = None
    failure = None
    start = time.monotonic_ns()
    try:
        with stdout.open("xb") as out, stderr.open("xb") as err:
            process = subprocess.Popen(command, cwd=output, env=env, stdout=out, stderr=err,
                                       stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                                       start_new_session=True)
            row.update(started=True, pid=process.pid, pgid=process.pid)
            try:
                process.communicate(input=stdin, timeout=limit)
            except subprocess.TimeoutExpired:
                row["timed_out"] = True
                raise
    except BaseException as exc:
        failure = exc
    finally:
        if process is not None:
            try:
                if process.poll() is None:
                    try: os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
            finally:
                row["returncode"] = process.wait()
                try: os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError: pass
        row["elapsed_ns"] = time.monotonic_ns() - start
        if failure is not None:
            row["failure"] = {"type": type(failure).__name__, "message": str(failure)}
        for key, path in [("stdout", stdout), ("stderr", stderr)]:
            raw = path.read_bytes() if path.exists() else b""
            row[key] = {"path": str(path.relative_to(output)), "bytes": len(raw), "sha256": sha(raw)}
        put(directory / (label + ".json"), row)
    if failure is not None:
        raise failure
    assert row["returncode"] == 0 and not row["timed_out"], row
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    source = args.source_root.resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(mode=0o700)
    pins_raw = (source / BASE / "writer-trace-pins.json").read_bytes()
    pins = json.loads(pins_raw)
    for name, identity in pins["files"].items():
        raw = (source / name).read_bytes()
        assert len(raw) == identity["bytes"] and sha(raw) == identity["sha256"], name
        put(output / "source" / name, raw)
    put(output / "source" / BASE / "writer-trace-pins.json", pins_raw)
    assert sha((output / "source" / ORIGINAL).read_bytes()) == ORIGINAL_SHA
    env = dict(os.environ)
    for key in list(env):
        if key in {"RUSTFLAGS", "RUSTDOCFLAGS", "RUSTC", "RUSTDOC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
                   "CARGO_BUILD_TARGET", "CARGO_BUILD_RUSTC", "CARGO_BUILD_RUSTDOC", "CARGO_BUILD_RUSTC_WRAPPER",
                   "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_TARGET_DIR"} or (
                key.startswith("CARGO_") and (key.endswith("RUSTFLAGS") or key.endswith("RUSTDOCFLAGS") or
                                             key.endswith("_LINKER") or key.endswith("_RUNNER"))):
            del env[key]
    work = output.parent / (output.name + "-build-work")
    work.mkdir(mode=0o700)
    env.update(RUSTUP_TOOLCHAIN="1.95.0", CARGO_HOME=str(work / "cargo-home"), CARGO_TARGET_DIR=str(work / "target"),
               CARGO_ENCODED_RUSTFLAGS="", CARGO_ENCODED_RUSTDOCFLAGS="", PYTHONDONTWRITEBYTECODE="1", PYTHONHASHSEED="0")
    run(output, "rustc-version", ["rustc", "--version", "--verbose"], env, limit=30)
    assert (output / "processes/rustc-version.stdout").read_bytes().startswith(b"rustc 1.95.0 ")
    run(output, "cargo-version", ["cargo", "--version"], env, limit=30)
    manifest = output / "source" / BASE / "tracer/Cargo.toml"
    lock = manifest.with_name("Cargo.lock")
    lock_raw = lock.read_bytes()
    run(output, "cargo-build", ["cargo", "build", "--locked", "--manifest-path", str(manifest)], env, limit=300)
    assert lock.read_bytes() == lock_raw
    run(output, "cargo-metadata", ["cargo", "metadata", "--locked", "--format-version", "1", "--manifest-path", str(manifest)], env, limit=120)
    metadata = json.loads((output / "processes/cargo-metadata.stdout").read_bytes())
    locked = {(p["name"], p["version"]): p for p in tomllib.loads(lock_raw.decode())["package"] if "source" in p}
    registry = {}
    for package in metadata["packages"]:
        if package["source"] is None:
            assert package["name"] == "hia-bellman-worker-reference"
            continue
        name = package["name"] + "-" + package["version"]
        pin = locked[(package["name"], package["version"])]
        candidates = list((work / "cargo-home/registry/cache").glob("*/" + name + ".crate"))
        assert len(candidates) == 1
        raw = candidates[0].read_bytes()
        assert sha(raw) == pin["checksum"] and package["source"] == pin["source"]
        actual = Path(package["manifest_path"]).parent
        rows = {}
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
            for member in tar:
                if member.isdir(): continue
                assert member.isfile() and member.name.startswith(name + "/")
                relative = member.name[len(name) + 1:]
                assert ".." not in Path(relative).parts and relative not in rows
                data = tar.extractfile(member).read()
                assert (actual / relative).read_bytes() == data
                rows[relative] = {"bytes": len(data), "sha256": sha(data)}
        put(output / "registry" / (name + ".crate"), raw)
        put(output / "registry" / (name + ".source.json"), rows)
        registry[name] = {"archive_bytes": len(raw), "sha256": sha(raw), "actual_source_files": len(rows)}
    put(output / "registry.json", registry)
    generated = list((work / "target/debug/build").glob("hia-bellman-worker-reference-*/out/original_bellman_with_observer.rs"))
    assert len(generated) == 1
    original = (output / "source" / ORIGINAL).read_bytes()
    observer = (manifest.parent / "trace_access.rs").read_bytes()
    assert generated[0].read_bytes() == original + b"\n" + observer
    assert generated[0].with_name("weight_bellman.rs").read_bytes() == original
    for name in ["original_bellman_with_observer.rs", "weight_bellman.rs", "module.rs"]:
        put(output / "generated" / name, generated[0].with_name(name).read_bytes())
    binary = work / "target/debug/hia-bellman-worker-reference"
    put(output / "original-worker-tracer", binary.read_bytes())
    (output / "original-worker-tracer").chmod(0o500)
    inputs = (output / "source" / BASE / "writer-cases.jsonl").read_bytes()
    put(output / "writer.inputs.jsonl", inputs)
    actual = run(output, "writer-trace", [str(output / "original-worker-tracer")], env, limit=60, stdin=inputs)
    observer_ids = json.loads((output / "processes/writer-trace.stderr").read_bytes())
    assert observer_ids == {"pid": actual["pid"], "parent_pid": actual["parent_pid"], "pgid": actual["pgid"]}
    lines = (output / "processes/writer-trace.stdout").read_bytes().splitlines()
    assert len(lines) == len(inputs.splitlines())
    rows = []
    for index, line in enumerate(lines):
        value = json.loads(line)
        assert value["index"] == index
        trace = value["trace"]
        fragments = [bytes.fromhex(x) for x in trace["write_calls"]]
        canonical = bytes.fromhex(trace["canonical_hex"])
        assert b"".join(fragments) == canonical and len(canonical) == trace["canonical_bytes"]
        assert sha(canonical) == trace["request_sha256"] and trace["original_source_sha256"] == ORIGINAL_SHA
        assert trace["observer_changes_original_write_body"] is False and trace["public_handler_qualified"] is False
        rows.append({"index": index, "actual_writer_calls": len(fragments), "bytes": len(canonical), "sha256": sha(canonical)})
    report = {"schema": "hepta.runtime.bellman-worker.writer-trace-development.v1", "status": "ACTUAL_TRACE_CAPTURED",
              "source_pins_sha256": sha(pins_raw), "source_commit": os.environ.get("GITHUB_SHA"),
              "binary_sha256": sha(binary.read_bytes()), "cases": rows, "registry_packages": len(registry),
              "native_executed": False, "full_solver_qualified": False, "public_handler_qualified": False}
    put(output / "RESULT.json", report)
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__": main()

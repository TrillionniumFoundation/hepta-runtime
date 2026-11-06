#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Qualify one explicit source snapshot; retain every original stage and test result."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def source_map(source):
    files = [source / name for name in ("Cargo.toml", "Cargo.lock", "rustfmt.toml")]
    for directory in ("src", "examples"):
        files.extend(path for path in (source / directory).rglob("*") if path.is_file())
    return {str(path.relative_to(source)): sha(path) for path in sorted(files) if path.is_file()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--cargo-home", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=1, choices=(1, 2))
    parser.add_argument("--stage-timeout", type=int, default=3600)
    args = parser.parse_args()
    source, out = args.source.resolve(), args.output.resolve()
    harness = source / "tools/x230/20261028"
    out.mkdir(mode=0o700, parents=False, exist_ok=False)
    os.umask(0o022)
    env = dict(os.environ)
    for key in list(env):
        if key.startswith(("HEPTA_", "SSH_", "RUST_TEST_")) or key in {
            "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTDOCFLAGS", "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER", "PYTHONPATH", "PYTHONHOME", "RUST_LOG",
        }:
            env.pop(key)
    env.update({"PATH": "/home/qian/.cargo/bin:/usr/local/bin:/usr/bin:/bin",
                "CARGO_HOME": str(args.cargo_home.resolve()),
                "CARGO_TARGET_DIR": str(args.target.resolve()),
                "CARGO_BUILD_JOBS": str(args.jobs), "CARGO_INCREMENTAL": "0",
                "RUST_TEST_THREADS": "1", "TOKIO_WORKER_THREADS": "2",
                "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1"})
    cargo = ["/home/qian/.cargo/bin/cargo", "+1.95.0"]
    report = {"schema": "hepta-x230-composed-qualification/v1", "qualified": False,
              "source": str(source), "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "source_input": source_map(source), "jobs": args.jobs, "stages": [],
              "harness_before": {p.name: sha(p) for p in sorted(harness.glob("*.py"))},
              "service_changes": False, "automatic_test_retries": 0}

    def save():
        temporary = out / "report.next"
        temporary.write_text(json.dumps(report, indent=2) + "\n")
        os.replace(temporary, out / "report.json")

    def stage(name, argv, stdout_name=None):
        row = {"name": name, "command": argv, "returncode": None}
        report["stages"].append(row)
        report["current_stage"] = name
        save()
        print(json.dumps({"stage": name, "state": "started"}), flush=True)
        started = time.monotonic()
        stdout_path, stderr_path = out / (stdout_name or name + ".stdout"), out / (name + ".stderr")
        try:
            with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
                process = subprocess.run(argv, cwd=source, env=env, stdout=stdout, stderr=stderr,
                                         timeout=args.stage_timeout)
            row["returncode"] = process.returncode
        finally:
            row["seconds"] = time.monotonic() - started
            row["stdout_sha256"] = sha(stdout_path)
            row["stderr_sha256"] = sha(stderr_path)
            save()
        print(json.dumps({"stage": name, "exit": row["returncode"], "seconds": row["seconds"]}), flush=True)
        if row["returncode"]:
            raise RuntimeError(f"{name} failed; original logs retained")

    try:
        stage("format", cargo + ["fmt", "--all"])
        stage("fmt-check", cargo + ["fmt", "--all", "--", "--check"])
        stage("harness-tests", ["/usr/bin/python3", "-B", "-m", "unittest", "discover",
                                "-s", str(harness), "-p", "*_tests.py", "-v"])
        report["source_tested"] = source_map(source)
        (out / "source-map.json").write_text(json.dumps(report["source_tested"], indent=2) + "\n")
        stage("clippy", cargo + ["clippy", "--offline", "--locked", "--all-targets", "--all-features", "--", "-D", "warnings"])
        stage("test-build", cargo + ["test", "--offline", "--locked", "--all-targets", "--all-features",
                                     "--no-run", "--message-format=json"], "cargo-no-run.jsonl")
        binary_dir = out / "test-binaries"
        binary_dir.mkdir(mode=0o700)
        artifacts = []
        for line in (out / "cargo-no-run.jsonl").read_text().splitlines():
            event = json.loads(line)
            if event.get("reason") == "compiler-artifact" and event.get("profile", {}).get("test") and event.get("executable"):
                old = Path(event["executable"])
                copied = binary_dir / old.name
                shutil.copy2(old, copied)
                if sha(old) != sha(copied):
                    raise RuntimeError("test executable changed during preservation")
                event["executable"] = str(copied)
            artifacts.append(event)
        retained = out / "retained-artifacts.jsonl"
        retained.write_text("".join(json.dumps(event) + "\n" for event in artifacts))
        stage("isolated-tests", ["/usr/bin/python3", str(source / "tools/x230/20261028/run_isolated_tests.py"),
                                 "--artifacts", str(retained), "--source-manifest", str(out / "source-map.json"),
                                 "--output", str(out / "isolated-tests"), "--timeout", "180"])
        stage("audit-isolated-tests", ["/usr/bin/python3", str(harness / "audit_isolated_tests.py"),
                                       "--evidence", str(out / "isolated-tests"),
                                       "--output", str(out / "isolated-tests.audit.json")])
        stage("release", cargo + ["build", "--offline", "--locked", "--all-features", "--release", "--bins", "--examples"])
        binaries = {}
        for relative in ("hepta-runtime", "hepta-runtime-jobctl", "examples/native_process_driver"):
            old = args.target.resolve() / "release" / relative
            copied = out / old.name
            shutil.copy2(old, copied)
            binaries[old.name] = {"path": str(copied), "sha256": sha(copied)}
        report["binaries"] = binaries
        report["source_after"] = source_map(source)
        if report["source_after"] != report["source_tested"]:
            raise RuntimeError("source changed during qualification")
        report["harness_after"] = {p.name: sha(p) for p in sorted(harness.glob("*.py"))}
        if report["harness_after"] != report["harness_before"]:
            raise RuntimeError("qualification tools changed during qualification")
        report["qualified"] = True
    except Exception as error:
        report["error"] = f"{type(error).__name__}: {error}"
    finally:
        report["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        save()
        print(json.dumps({"qualified": report["qualified"], "report": str(out / "report.json"),
                          "error": report.get("error")}), flush=True)
    return 0 if report["qualified"] else 1


if __name__ == "__main__":
    sys.exit(main())

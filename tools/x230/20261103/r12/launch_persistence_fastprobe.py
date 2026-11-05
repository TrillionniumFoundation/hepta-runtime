#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Compile receipt code and its real JobRecord tests against cached rlibs."""

import argparse
import hashlib
import json
import os
import re
import subprocess
import time
from pathlib import Path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def section(text, begin, end):
    assert text.count(begin) == 1, begin
    start = text.index(begin)
    finish = text.index(end, start)
    return text[start:finish]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--deps", required=True, type=Path)
    parser.add_argument("--rustc", type=Path, default=Path("/home/qian/.cargo/bin/rustc"))
    parser.add_argument("--opt-level", choices=["1", "2", "3"], default="3")
    args = parser.parse_args()
    args.work.mkdir(mode=0o700, parents=True, exist_ok=False)
    runtime = args.source / "src/mcp/runtime"
    paths = {name: runtime / name for name in [
        "jobs.rs", "config.rs", "jobs_persistence.rs", "jobs_persistence_tests.rs",
    ]}
    paths["Cargo.lock"] = args.source / "Cargo.lock"
    inputs = {name: digest(path) for name, path in paths.items()}
    jobs = paths["jobs.rs"].read_text()
    config = paths["config.rs"].read_text()
    schema = section(jobs, "macro_rules! job_record_schema", "job_record_schema!(JobRecord, String);")
    default = section(jobs, "fn default_launch_state()", "fn start_lane(")
    save = section(jobs, "fn save_record_at(", "fn read_record_at(")
    reader = section(jobs, "fn read_record_at(", "job_record_reader!(read_record_at_into, JobRecord);")
    mode = section(config, "/// Administrator-selected trust boundary", "#[derive(Debug, Clone, Deserialize, Serialize)]")
    limit = re.search(r"^const MAX_JOB_RECORD_BYTES:.*;$", jobs, re.M).group()
    probe = """// Generated isolated probe from exact source sections; not a production runtime.
mod mcp { pub mod runtime { pub mod jobs {
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
"""
    probe += mode + "\n" + limit + "\n" + schema
    probe += "job_record_schema!(JobRecord, String);\n" + default
    probe += f"#[path = {json.dumps(str(paths['jobs_persistence.rs']))}]\nmod persistence;\n"
    probe += save + reader + "job_record_reader!(read_record_at_into, JobRecord);\n"
    probe += "} } }\n"
    generated = args.work / "probe.rs"
    generated.write_text(probe)
    metadata = {
        "schema": "hepta-persistence-extracted-fastprobe-v1",
        "source_inputs": inputs,
        "generated_source_sha256": digest(generated),
        "started_unix": time.time(),
        "scope": (
            "Exact JobRecord schema, ExecutionMode, original descriptor-validated reader, "
            "production save_record_at and candidate encoder; unchanged sibling tests. "
            "Direct rustc test binary with cached dependency rlibs, not full release MCP qualification."
        ),
    }
    test_filter = "mcp::runtime::jobs::persistence::tests"
    benchmark_names = re.findall(
        r"fn ((?:bounded|reserved)_receipt_encoding_and_durable_save_benchmark)\(",
        paths["jobs_persistence_tests.rs"].read_text(),
    )
    assert len(benchmark_names) == 1, "one known receipt benchmark required"
    metadata["benchmark_name"] = benchmark_names[0]
    target = args.work / "probe"
    stage = "compile"
    try:
        command = [str(args.rustc), "--edition=2021", "--test", "-C", "opt-level=" + args.opt_level,
                   "-C", "debuginfo=0", "-C", "codegen-units=1", "-L", "dependency=" + str(args.deps)]
        rlibs = {}
        for name in ["serde", "serde_json", "anyhow", "tempfile", "libc", "sha2"]:
            candidates = list(args.deps.glob(f"lib{name}-*.rlib"))
            assert candidates, name
            rlib = max(candidates, key=lambda path: path.stat().st_mtime_ns)
            command += ["--extern", name + "=" + str(rlib)]
            rlibs[name] = {"path": str(rlib), "sha256": digest(rlib)}
        command += [str(generated), "-o", str(target)]
        metadata["compile_command"] = command
        metadata["rlibs"] = rlibs
        metadata["rustc_version"] = subprocess.run(
            [str(args.rustc), "--version"], check=True, capture_output=True, text=True, timeout=10
        ).stdout.strip()
        for stage, command, timeout in [
            ("compile", command, 120),
            ("tests", [str(target), test_filter, "--test-threads=1", "--nocapture"], 90),
            ("benchmark", [str(target), test_filter + "::" + benchmark_names[0],
                           "--exact", "--ignored", "--test-threads=1", "--nocapture"], 180),
        ]:
            before = time.monotonic()
            env = os.environ.copy()
            env["HEPTA_PERSISTENCE_BENCH_OUTPUT"] = str(args.work / "results.json")
            scratch = args.work / "tmp"
            scratch.mkdir(mode=0o700, exist_ok=True)
            env["TMPDIR"] = str(scratch)
            completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout, env=env)
            (args.work / f"{stage}.stdout").write_text(completed.stdout)
            (args.work / f"{stage}.stderr").write_text(completed.stderr)
            metadata[stage] = {
                "command": command, "returncode": completed.returncode,
                "wall_seconds": time.monotonic() - before,
            }
            print(stage.upper(), json.dumps(metadata[stage]), flush=True)
            if completed.returncode:
                print(completed.stderr, completed.stdout[-5000:], flush=True)
                raise RuntimeError(stage + " failed")
        metadata["binary_sha256"] = digest(target)
        metadata["results_sha256"] = digest(args.work / "results.json")
        metadata["source_after"] = {name: digest(path) for name, path in paths.items()}
        assert metadata["source_after"] == inputs, "source changed during probe"
        metadata["completed"] = True
    except Exception as error:
        metadata["error"] = repr(error)
        raise
    finally:
        metadata["stage"] = stage
        metadata["finished_unix"] = time.time()
        (args.work / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")


if __name__ == "__main__":
    main()

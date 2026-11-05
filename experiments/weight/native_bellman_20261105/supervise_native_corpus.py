#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Measure the complete driver and descendants from process spawn through exit."""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import time


def sha(data):
    return hashlib.sha256(data).hexdigest()


def save(path, value):
    data = (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()
    with path.open("xb") as stream:
        stream.write(data)
    return sha(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["binary", "inputs", "attempt", "protocol", "qualified-source-manifest", "local-qualification"]:
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    protocol_bytes = args.protocol.read_bytes()
    protocol = json.loads(protocol_bytes)
    assert sha(Path(__file__).read_bytes()) == protocol["script_sha256"]["supervisor"]
    driver = Path(__file__).with_name("run_native_corpus.py")
    assert sha(driver.read_bytes()) == protocol["script_sha256"]["driver"]
    args.attempt.mkdir(mode=0o700, parents=True, exist_ok=False)
    output = args.attempt / "corpus"
    command = [sys.executable, str(driver), "--binary", str(args.binary), "--inputs", str(args.inputs),
        "--output", str(output), "--protocol", str(args.protocol),
        "--qualified-source-manifest", str(args.qualified_source_manifest),
        "--local-qualification", str(args.local_qualification)]
    launch = {"schema": "hepta.native-bellman-supervisor-launch.v1", "command": command,
        "protocol_sha256": sha(protocol_bytes), "driver_sha256": sha(driver.read_bytes()),
        "supervisor_sha256": sha(Path(__file__).read_bytes())}
    save(args.attempt / "PRIVATE_LAUNCH.json", launch)
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    started_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
    started = time.perf_counter()
    timed_out = False
    with (args.attempt / "stdout.log").open("xb") as out, (args.attempt / "stderr.log").open("xb") as err:
        child = subprocess.Popen(command, stdout=out, stderr=err, start_new_session=True)
        try:
            code = child.wait(timeout=protocol["resource_caps"]["outer_wall_seconds"])
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(child.pid, signal.SIGTERM)
            try:
                code = child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                code = child.wait(timeout=10)
    wall_seconds = time.perf_counter() - started
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    output.mkdir(mode=0o700, exist_ok=True)
    logs = {}
    for name in ["stdout.log", "stderr.log"]:
        data = (args.attempt / name).read_bytes()
        logs[name] = {"bytes": len(data), "sha256": sha(data)}
    sources_unchanged = (sha(driver.read_bytes()) == protocol["script_sha256"]["driver"]
        and sha(Path(__file__).read_bytes()) == protocol["script_sha256"]["supervisor"])
    receipt = {"schema": "hepta.native-bellman-whole-process.v1", "started_utc": started_utc,
        "completed_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "exit_code": code, "timed_out": timed_out, "wall_seconds": wall_seconds,
        "driver_and_descendants_user_cpu_seconds": after.ru_utime - before.ru_utime,
        "driver_and_descendants_system_cpu_seconds": after.ru_stime - before.ru_stime,
        "maximum_descendant_peak_rss_kib": after.ru_maxrss,
        "measurement": "Process spawn through driver termination, using monotonic wall time and the supervisor's RUSAGE_CHILDREN delta. The driver waits for the MCP child, so descendant CPU is included. Includes Python imports, argument parsing, runtime startup, all internal execution and the driver's final receipt/manifest writes. Internal timing overlaps and must not be added.",
        "excluded_supervisor_overhead": "Supervisor argument parsing, launch-record creation, and publication of this outer receipt/final manifest occur outside the spawn-to-exit interval.",
        "scope_limit": "No original training, graph export, independent comparison/J replay, Rust compilation, LLM, transfer or energy accounting is included in this process interval.",
        "protocol_sha256": sha(protocol_bytes), "driver_sha256": sha(driver.read_bytes()),
        "supervisor_sha256": sha(Path(__file__).read_bytes()), "sources_unchanged": sources_unchanged, "logs": logs}
    receipt_sha = save(output / "WHOLE_PROCESS_RECEIPT.json", receipt)
    internal_path = output / "NATIVE_CORPUS_INTERNAL_MANIFEST.json"
    if internal_path.exists():
        internal_bytes = internal_path.read_bytes()
        manifest = json.loads(internal_bytes)
        manifest["internal_manifest_file"] = internal_path.name
        manifest["internal_manifest_sha256"] = sha(internal_bytes)
    else:
        manifest = {"schema": "hepta.native-bellman-corpus.v1", "files": {}, "planned_worlds": 320,
            "attempted_worlds": None, "failed_worlds": None, "unattempted_worlds": None,
            "fatal": {"type": "IncompleteDriver", "message": "No complete internal manifest was published."},
            "all_requests_completed_without_rpc_error": False,
            "native_execution_protocol_sha256": sha(protocol_bytes),
            "new_scientific_efficacy_evidence": False, "production_eligible": False}
    manifest["whole_process_receipt_file"] = "WHOLE_PROCESS_RECEIPT.json"
    manifest["whole_process_receipt_sha256"] = receipt_sha
    manifest["outer_process_succeeded"] = (code == 0 and not timed_out and sources_unchanged
        and manifest["native_execution_protocol_sha256"] == sha(protocol_bytes))
    manifest["execution_succeeded"] = manifest["outer_process_succeeded"] and manifest["all_requests_completed_without_rpc_error"]
    manifest_sha = save(output / "NATIVE_CORPUS_MANIFEST.json", manifest)
    print(json.dumps({"exit_code": code, "timed_out": timed_out, "execution_succeeded": manifest["execution_succeeded"],
        "wall_seconds": wall_seconds, "manifest_sha256": manifest_sha}), flush=True)
    raise SystemExit(0 if manifest["execution_succeeded"] else 1)


if __name__ == "__main__":
    main()

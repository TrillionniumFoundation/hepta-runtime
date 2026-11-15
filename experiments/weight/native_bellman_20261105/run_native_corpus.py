#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Run every frozen graph through the actual native MCP; never load reference Q."""

import argparse
import datetime
import gzip
import json
from pathlib import Path
import platform
import queue
import resource
import signal
import time
import traceback

import bridge_io
from bridge_io import canonical, sha, write, write_bytes, write_lines
import mcp_fixture_client
from mcp_fixture_client import Mcp, pin_binary, verify_binary


class RecordingMcp(Mcp):
    def __init__(self, *args):
        self.last_tool = None
        super().__init__(*args)

    def send(self, value):
        encoded = (json.dumps(value, separators=(",", ":"), allow_nan=False) + "\n").encode()
        if value.get("method") == "tools/call":
            arguments = json.dumps(value["params"]["arguments"], separators=(",", ":"), allow_nan=False).encode()
            self.last_tool = {"jsonrpc_request_id": value["id"],
                "jsonrpc_request_bytes": len(encoded), "jsonrpc_request_sha256": sha(encoded),
                "transport_arguments_bytes": len(arguments), "transport_arguments_sha256": sha(arguments),
                "transport_serialization": "Python json.dumps separators=(',',':'), ensure_ascii=True, allow_nan=False; full request includes trailing newline"}
        self.p.stdin.write(encoded.decode())
        self.p.stdin.flush()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["binary", "inputs", "output", "protocol", "qualified-source-manifest", "local-qualification"]:
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    started = time.perf_counter()
    started_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
    cpu_before = time.process_time()
    child_before = resource.getrusage(resource.RUSAGE_CHILDREN)
    protocol_bytes = args.protocol.read_bytes()
    protocol = json.loads(protocol_bytes)
    assert protocol["schema"] == "hepta.native-bellman-execution-protocol.v1"
    assert protocol["planned_worlds"] == 320
    scripts = {"driver": Path(__file__), "bridge_io": Path(bridge_io.__file__), "mcp_fixture_client": Path(mcp_fixture_client.__file__)}
    for name, path in scripts.items():
        assert sha(path.read_bytes()) == protocol["script_sha256"][name]
    handoff_bytes = (args.inputs / "REQUEST_HANDOFF.json").read_bytes()
    assert sha(handoff_bytes) == protocol["request_handoff_sha256"]
    handoff = json.loads(handoff_bytes)
    assert handoff["planned_worlds"] == 320 and handoff["native_inputs_exclude_references"]
    source_bytes = args.qualified_source_manifest.read_bytes()
    qualification_bytes = args.local_qualification.read_bytes()
    assert sha(source_bytes) == protocol["qualified_source_manifest_sha256"]
    assert sha(qualification_bytes) == protocol["local_qualification_sha256"]
    sources, qualification = json.loads(source_bytes), json.loads(qualification_bytes)
    assert qualification["passed"] and qualification["completed"]
    assert qualification["binary"]["sha256"] == protocol["binary_sha256"]
    assert qualification["source_after_last_command"] == sources
    assert {row["path"]: row["sha256"] for row in sources}["src/mcp/weight_bellman.rs"] == protocol["bellman_module_sha256"]
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    work = args.output / "private-work"
    work.mkdir(mode=0o700)
    (args.output / "EXECUTION_PROTOCOL.json").write_bytes(protocol_bytes)
    (args.output / "QUALIFIED_SOURCE_MANIFEST.json").write_bytes(source_bytes)
    (args.output / "LOCAL_QUALIFICATION.json").write_bytes(qualification_bytes)
    groups = {}
    seen = set()
    for relative, identity in sorted(handoff["group_files"].items()):
        name = Path(relative).name
        data = (args.inputs / name).read_bytes()
        assert len(data) == identity["bytes"] and sha(data) == identity["sha256"]
        requests = [json.loads(line) for line in gzip.decompress(data).splitlines()]
        assert len(requests) == 32
        for request in requests:
            assert set(request) == {"request_id", "method", "params"}
            assert request["method"] == "weight_bellman_plan" and set(request["params"]) == {"states"}
            assert request["request_id"] not in seen
            seen.add(request["request_id"])
        groups[name] = requests
    assert len(groups) == 10 and len(seen) == 320
    results = {name: [] for name in groups}
    completed_groups = []
    attempted = failed = 0
    fatal = None
    mcp = pinned = binary_stat = None
    binary_sha = None
    execution_binary_verified = False
    caps = protocol["resource_caps"]
    assert caps == {"driver_cpu_seconds": 90, "child_cpu_seconds": 210,
                    "execution_wall_seconds": 600, "outer_wall_seconds": 660,
                    "address_space_bytes_per_process": 8589934592, "nofile_per_process": 1024}

    def interrupted(*unused):
        raise TimeoutError("frozen native execution resource deadline")

    def clean(error):
        return str(error).replace(str(args.output), "<OUTPUT>").replace(str(args.inputs), "<INPUTS>")[:4096]

    signal.signal(signal.SIGALRM, interrupted)
    signal.signal(signal.SIGXCPU, interrupted)
    signal.alarm(caps["execution_wall_seconds"])
    try:
        resource.setrlimit(resource.RLIMIT_AS, (caps["address_space_bytes_per_process"], caps["address_space_bytes_per_process"]))
        resource.setrlimit(resource.RLIMIT_NOFILE, (caps["nofile_per_process"], caps["nofile_per_process"]))
        # The child initially inherits the total CPU bound. Immediately after startup
        # each process receives its own non-overlapping share of that total bound.
        resource.setrlimit(resource.RLIMIT_CPU, (300, 300))
        pinned, binary_sha, binary_stat = pin_binary(args.binary.resolve(), work)
        assert binary_sha == protocol["binary_sha256"]
        config = work / "runtime.json"
        config.write_text(json.dumps({"state_dir": str(work / "state"),
            "controller_workspace_roots": [str(work)], "weight_workers": {},
            "hosts": {"unused": {"ssh_target": "unused.invalid", "remote_state_dir": str(work / "unused"), "allow_execute": False}}}))
        mcp = RecordingMcp(pinned, config, work / "mcp.stderr.log")
        resource.prlimit(mcp.p.pid, resource.RLIMIT_CPU, (caps["child_cpu_seconds"], caps["child_cpu_seconds"]))
        resource.setrlimit(resource.RLIMIT_CPU, (caps["driver_cpu_seconds"], caps["driver_cpu_seconds"]))
        for name, requests in groups.items():
            partial = work / (name + ".partial.jsonl")
            with partial.open("x") as stream:
                for request in requests:
                    record = {"request_id": request["request_id"],
                        "graph_params_sha256": sha(canonical(request["params"]).encode()),
                        "response": None, "rpc_error": None}
                    then = time.perf_counter()
                    mcp.last_tool = None
                    attempted += 1
                    try:
                        record["response"] = mcp.call("weight_bellman_plan", request["params"])
                        response = record["response"]
                        assert response["implementation_source_sha256"] == protocol["bellman_module_sha256"]
                        assert response["state_count"] == len(request["params"]["states"])
                        assert len(response["states"]) == response["state_count"]
                        assert response["gradient_steps"] == 0 and not response["production_eligible"]
                    except BaseException as error:
                        failed += 1
                        record["rpc_error"] = {"type": type(error).__name__, "message": clean(error)}
                        if isinstance(error, (TimeoutError, queue.Empty, BrokenPipeError, KeyboardInterrupt, SystemExit)) or mcp.p.poll() is not None:
                            fatal = dict(record["rpc_error"])
                    record["rpc_wall_seconds"] = time.perf_counter() - then
                    record["transport"] = mcp.last_tool
                    results[name].append(record)
                    stream.write(canonical(record) + "\n")
                    stream.flush()
                    if fatal is not None:
                        break
            if fatal is not None:
                break
            completed_groups.append(name)
            print(canonical({"stage": "native_group_complete", "group": name,
                "attempted_worlds": attempted, "failed_worlds": failed,
                "wall_seconds": time.perf_counter() - started}), flush=True)
    except BaseException as error:
        fatal = {"type": type(error).__name__, "message": clean(error)}
        (work / "failure-trace.txt").write_text(traceback.format_exc())
    finally:
        signal.alarm(0)
        if mcp is not None:
            try:
                mcp.close()
            except BaseException as error:
                fatal = {"type": type(error).__name__, "message": "closing MCP: " + clean(error)}
        if pinned is not None and binary_stat is not None:
            try:
                verify_binary(pinned, binary_sha, binary_stat)
                execution_binary_verified = True
            except BaseException as error:
                fatal = {"type": type(error).__name__, "message": "binary verification: " + clean(error)}

    files = {}
    for name, rows in results.items():
        if rows:
            files[name] = write_lines(args.output / name, rows)
        else:
            files[name] = write_bytes(args.output / name, gzip.compress(b"", compresslevel=9, mtime=0))
    for name, path in scripts.items():
        if sha(path.read_bytes()) != protocol["script_sha256"][name]:
            fatal = {"type": "SourceChanged", "message": name + " changed during execution"}
    child_after = resource.getrusage(resource.RUSAGE_CHILDREN)
    receipt = {"schema": "hepta.native-bellman-internal-execution.v1", "started_utc": started_utc,
        "completed_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "python": platform.python_version(), "platform": platform.platform(),
        "wall_seconds": time.perf_counter() - started, "driver_cpu_seconds": time.process_time() - cpu_before,
        "child_user_cpu_seconds": child_after.ru_utime - child_before.ru_utime,
        "child_system_cpu_seconds": child_after.ru_stime - child_before.ru_stime,
        "driver_peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        "child_peak_rss_kib": child_after.ru_maxrss, "binary_sha256": binary_sha,
        "executed_binary_unchanged": execution_binary_verified,
        "planned_worlds": 320, "attempted_worlds": attempted, "failed_worlds": failed,
        "unattempted_worlds": 320 - attempted, "fatal": fatal,
        "timing_scope": "Internal timer begins after Python imports and argument parsing and ends before writing this receipt and its internal manifest. The outer supervisor separately measures the whole driver and its waited descendants; these intervals overlap and must not be added.",
        "cost_includes": ["request loading and identity checks", "binary pinning", "MCP initialization and calls", "full response capture", "deterministic gzip publication", "final source and binary checks"],
        "cost_excludes": ["original training", "scientific experiment", "graph export", "independent verification and J replay", "Rust compilation", "LLM", "transfer", "energy"]}
    receipt_identity = write(args.output / "INTERNAL_EXECUTION_RECEIPT.json", receipt)
    manifest = {"schema": "hepta.native-bellman-corpus.v1", "files": files,
        "native_execution_protocol_sha256": sha(protocol_bytes),
        "internal_execution_receipt_file": "INTERNAL_EXECUTION_RECEIPT.json",
        "internal_execution_receipt_sha256": receipt_identity["sha256"],
        "planned_worlds": 320, "attempted_worlds": attempted, "failed_worlds": failed,
        "unattempted_worlds": 320 - attempted, "completed_groups": completed_groups,
        "binary_sha256": binary_sha, "bellman_module_sha256": protocol["bellman_module_sha256"],
        "qualified_source_manifest_file": "QUALIFIED_SOURCE_MANIFEST.json",
        "qualified_source_manifest_sha256": protocol["qualified_source_manifest_sha256"],
        "local_qualification_file": "LOCAL_QUALIFICATION.json",
        "local_qualification_sha256": protocol["local_qualification_sha256"],
        "request_handoff_sha256": sha(handoff_bytes), "fatal": fatal,
        "all_requests_completed_without_rpc_error": attempted == 320 and failed == 0 and fatal is None and execution_binary_verified,
        "references_loaded_by_native_driver": False, "new_scientific_efficacy_evidence": False,
        "production_eligible": False,
        "scope": "Actual MCP replay of previously exported finite graphs. Independent Q/action and existing-world J checks run separately; no new scientific holdout."}
    write(args.output / "NATIVE_CORPUS_INTERNAL_MANIFEST.json", manifest)
    print(canonical({"stage": "native_corpus_complete", "attempted_worlds": attempted,
        "failed_worlds": failed, "unattempted_worlds": 320 - attempted, "fatal": fatal,
        "wall_seconds": receipt["wall_seconds"]}), flush=True)
    raise SystemExit(0 if manifest["all_requests_completed_without_rpc_error"] else 1)


if __name__ == "__main__":
    main()

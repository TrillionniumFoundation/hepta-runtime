#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Independently verify embedded six-host cancellation/restart evidence."""
import argparse
import base64
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path

import allocator_environment_audit as allocator_audit
import audit_native_evidence as evidence

HOSTS = {"ai395", "mac", "main", "pocket4", "rog", "x230"}
INPUT = ("0123456789abcdef" * 256).encode()


def need(value, reason):
    if not value:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def decode(files, name, optional=False):
    value = files.get(name)
    if value is None:
        need(optional, "missing independent artifact: " + name)
        return None
    raw = base64.b64decode(value["base64"], validate=True)
    need(len(raw) == value["bytes"] and sha(raw) == value["sha256"], "artifact transfer changed: " + name)
    return raw


def verify_raw_native(report, directory):
    """Bind canonical recovery results to exact controller stdout and clocks."""
    captures, statuses = {}, {}
    counts = Counter()
    resource_traces = []
    phases = (("first-controller", "first_startup", "intentional_crash"),
              ("after-crash-controller", "after_crash_startup", "after_cancel_shutdown"),
              ("after-cancel-controller", "after_cancel_startup", "shutdown"))
    for name, startup_key, shutdown_key in phases:
        startup, shutdown = report[startup_key], report[shutdown_key]
        capture = evidence.Transport(directory / name, shutdown["transport_capture"])
        capture.initialize(startup)
        captures[name] = capture
        resource_traces.append({"controller_directory": name,
            **evidence.resources(directory / name, shutdown["resources"], startup)})
    for row in report["native_calls"]:
        host, tool = row["host"], row["tool"]
        need(host in HOSTS and row["controller_directory"] in captures, "native capture controller/host differs")
        arguments = {"host": host, "job_id": report["hosts"][host]["job_id"]}
        if tool == "process_start":
            arguments = json.loads((directory / (host + "-request.json")).read_bytes())
        elif tool == "process_read":
            arguments.update(stdout_offset=0, stderr_offset=0, limit=16384)
        elif tool == "process_cancel":
            need(row["phase"] in {"concurrent_cancel", "cancel_after_terminal"}, "unexpected cancellation phase")
            arguments["grace_seconds"] = 3 if row["phase"] == "concurrent_cancel" else 0
        else:
            need(tool == "process_status", "unexpected native effect")
        need(sha(evidence.canonical(arguments)) == row["arguments_sha256"], "native request arguments differ")
        reply = captures[row["controller_directory"]].rpc(row["rpc"], "tools/call", {"name": tool, "arguments": arguments})
        expected_name = f"native-{row['sequence']:04d}-{host}-{tool}.json"
        need(Path(row["reply_path"]).name == expected_name, "canonical native reply filename differs")
        canonical_raw = evidence.bound_file(directory, {"file": expected_name, "bytes": row["reply_bytes"],
                                                       "sha256": row["response_sha256"]})
        need(canonical_raw == evidence.canonical(reply), "exact transport and canonical native result differ")
        need(row["start_monotonic_ns"] <= row["rpc"]["rpc_start_monotonic_ns"]
             <= row["rpc"]["rpc_end_monotonic_ns"] <= row["end_monotonic_ns"], "recovery RPC endpoints differ")
        evidence.near((row["end_monotonic_ns"] - row["start_monotonic_ns"]) / 1e6,
                      row["elapsed_ms"], "recovery latency differs from raw endpoints")
        need("error" not in reply and not reply["result"].get("isError", False), "raw native recovery call refused")
        texts = [part["text"] for part in reply["result"]["content"] if part.get("type") == "text"]
        need(texts, "raw recovery response has no JSON text")
        dto = json.loads(texts[0])
        need(dto.get("audit_recorded") is True and "audit_warning" not in dto, "raw recovery result lacks audit")
        if tool == "process_start":
            need(dto["job"]["host"] == host and dto["job"]["id"] == report["hosts"][host]["job_id"], "raw launch identity differs")
        else:
            need(dto["job_id"] == report["hosts"][host]["job_id"], "raw recovery job identity differs")
        if row["phase"] in {"launch", "same_key_after_crash", "same_key_after_cancel", "concurrent_cancel", "cancel_after_terminal"}:
            need(dto == report["hosts"][host][row["phase"]], "embedded effect result differs from raw transport")
        if tool == "process_status":
            statuses.setdefault((host, row["phase"]), set()).add(sha(evidence.canonical(dto)))
    for host, values in report["hosts"].items():
        for phase in ("before_crash_running", "after_transport_running", "after_crash_running", "terminal", "terminal_after_restart"):
            if phase in values:
                need(sha(evidence.canonical(values[phase]["status"])) in statuses.get((host, phase), set()),
                     "embedded terminal/running status lacks raw transport witness")
    for capture in captures.values():
        counts.update(capture.finish())
    for row in report["ssh_calls"]:
        for stream in ("stdout", "stderr"):
            item = row[stream]
            name = f"ssh-{row['sequence']:04d}-{row['host']}-{row['mode']}.{stream}"
            need(Path(item["path"]).name == name, "raw SSH filename differs")
            raw = evidence.bound_file(directory, {"file": name, "bytes": item["bytes"], "sha256": item["sha256"]})
            if stream == "stdout":
                result = json.loads(raw)
                need(result["host"] == row["host"] and result["mode"] == row["mode"]
                     and result["nonce"] == report["nonce"], "raw SSH response identity differs")
                if row["mode"] == "prepare":
                    need(result == report["hosts"][row["host"]]["prepare"], "raw topology/fixture prepare differs")
    return {"transport": dict(counts), "resource_traces": resource_traces,
            "canonical_native_replies_rehashed": len(report["native_calls"]),
            "ssh_streams_rehashed": 2 * len(report["ssh_calls"])}


def verify(raw, report_directory):
    report = json.loads(raw)
    need(report["schema"] == "hepta-six-host-cancel-recovery/v2" and report["passed"] is True,
         "not a completed cancellation/recovery report")
    need(set(report["hosts"]) == HOSTS and all(report[key] is True for key in
         ("source_originals_unchanged", "binary_unchanged", "current_agent_unchanged")), "input identity changed")
    need(report["production_service_mutations"] == report["remote_cleanup_operations"]
         == report["automatic_rpc_retries"] == 0, "unexpected effects/retries")
    topology_proof = evidence.topology(report_directory, report)
    topology = report["topology"]["hosts"]
    for host, item in report["hosts"].items():
        need(item["prepare"]["platform"] == ("darwin" if topology[host]["platform"] == "macos" else "linux"),
             "prepared platform differs from pinned preflight")
        for other, peer in report["hosts"].items():
            need((item["prepare"]["hostname"] == peer["prepare"]["hostname"])
                 == (topology[host]["machine_group"] == topology[other]["machine_group"]),
                 "prepared hostname equivalence differs from pinned preflight")
    need(report["observed_topology"]["verified"] is True, "topology was not independently observed")
    need(report["controller_records"]["exact_original_set"] is True
         and report["controller_records"]["errors"] == [], "retained controller set differs")
    need(len(report["controller_records"]["records"]) == 6 and all(
         r["original_bytes_unchanged"] is True for r in report["controller_records"]["records"]),
         "retained controller receipt changed")
    need(report["intentional_crash"]["exit_code"] == -9
         and report["intentional_crash"]["observed_descendant_survivors"] == [], "controller crash evidence differs")
    for phase in ("after_cancel_shutdown", "shutdown"):
        item = report[phase]
        need(item["exit_code"] == 0 and item["shutdown_method"] == "stdin_eof"
             and not item["observed_descendant_survivors"] and item["reader_error"] is None
             and item["unmatched_responses"] == 0, "controller normal shutdown differs")
    calls = report["native_calls"]
    need(all(r["okay"] is True and r["automatic_retry"] is False for r in calls), "native call failed/retried")
    need(all(r["okay"] is True and r["automatic_retry"] is False for r in report["ssh_calls"]), "SSH call failed/retried")
    allocator_proof = allocator_audit.validate_recovery(report)
    counts = Counter((r["host"], r["tool"]) for r in calls)
    need(all(counts[(host, "process_start")] == 3 and counts[(host, "process_cancel")] == 2
             for host in HOSTS), "expected starts/replays/cancellations differ")
    need(report["new_start_call_count"] == 6 and report["same_key_lookup_call_count"] == 12
         and report["cancel_call_count"] == 12, "effect counts differ")
    results = {}
    for host, value in report["hosts"].items():
        job_id = value["job_id"]
        need(value["launch"]["job"]["id"] == job_id and value["launch"]["reused"] is False
             and value["launch"]["launch"]["ok"] is True, "original launch binding differs")
        before = value["before_crash_running"]["proof"]["files"]
        request_raw = decode(before, "request.json")
        request = json.loads(request_raw)
        nonce = request["launch_nonce"]
        need(request["job_id"] == job_id and request["terminal_publication_protocol"] == 1,
             "original remote request differs")
        for phase in ("before_crash_running", "after_crash_running"):
            item = value[phase]
            files = item["proof"]["files"]
            need(item["status"]["job_id"] == job_id and item["status"]["state"] == "running"
                 and item["launch_nonce"] == nonce and decode(files, "request.json") == request_raw
                 and decode(files, "execution-marker") == b"EXECUTED\n"
                 and decode(files, "stdin.bin") == INPUT
                 and decode(files, "release-marker", True) is None
                 and decode(files, "cancel-request.json", True) is None
                 and decode(files, "exit.json", True) is None
                 and decode(files, "exit.witness.json", True) is None, "running/recovery proof differs")
        for phase, state in (("same_key_after_crash", "running"), ("same_key_after_cancel", "cancelled")):
            item = value[phase]
            need(item["reused"] is True and item["retried_launch"] is False and item["launch"] is None
                 and item["job"]["id"] == item["status"]["job_id"] == job_id
                 and item["status"]["state"] == state, "same-key request did not preserve original job")
        acknowledgement = value["concurrent_cancel"]
        need(acknowledgement["job_id"] == job_id and acknowledgement["result"] in {"stop_requested", "term_sent"}
             and acknowledgement["termination_confirmed"] is False
             and acknowledgement["automatic_retry"] is False
             and acknowledgement["atomic_identity"] is (topology[host]["platform"] == "linux"), "cancel signal acknowledgement differs")
        recancel = value["cancel_after_terminal"]
        need(recancel["job_id"] == job_id and recancel["result"] == "already_exited"
             and recancel["termination_confirmed"] is False, "terminal cancellation acknowledgement differs")
        end = {}
        for phase in ("terminal", "terminal_after_restart"):
            item = value[phase]
            status, files = item["status"], item["proof"]["files"]
            need(status["job_id"] == job_id and status["state"] == "cancelled"
                 and status["cancelled"] is True and not status["timed_out"]
                 and status["output_complete"] is True and status["output_durable"] is True
                 and status["terminal_publication_confirmed"] is True and item["execution_count"] == 1,
                 "durable cancellation is not established")
            need(decode(files, "request.json") == request_raw and decode(files, "stdin.bin") == INPUT
                 and decode(files, "execution-marker") == b"EXECUTED\n"
                 and decode(files, "release-marker", True) is None, "terminal input/one-execution witness differs")
            expected = {"stdout": ("BEGIN " + host + "\n").encode(),
                        "stderr": ("HEPTA-CANARY-STDERR " + host + "\n").encode()}
            for stream, output in expected.items():
                need(decode(files, stream + ".log") == output
                     and item["outputs"][stream] == {"bytes": len(output), "sha256": sha(output)},
                     "terminal output differs")
            need(status["log_synced"] == {"stdout": True, "stderr": True}
                 and status["log_truncated"] == {"stdout": False, "stderr": False}
                 and status["log_errors"] == {"stdout": None, "stderr": None}
                 and status["log_bytes"] == {s: {"seen": len(b), "stored": len(b)} for s, b in expected.items()},
                 "terminal output capture contract differs")
            artifacts = {name: decode(files, name) for name in ("cancel-request.json", "exit.json", "exit.witness.json")}
            records = {name: json.loads(data) for name, data in artifacts.items()}
            need(all(r["job_id"] == job_id and r["launch_nonce"] == nonce for r in records.values()),
                 "terminal artifact identity differs")
            need(records["exit.witness.json"]["exit_sha256"] == sha(artifacts["exit.json"])
                 and all(status.get(k) == v for k, v in records["exit.json"].items()), "terminal exact-byte witness differs")
            if end:
                need(end == artifacts, "terminal receipt changed across restart")
            end = artifacts
        results[host] = {"job_id": job_id, "launch_nonce": nonce, "execution_count": 1,
                         "request_sha256": sha(request_raw), "exit_sha256": sha(end["exit.json"]),
                         "host_reported_name": value["prepare"]["hostname"],
                         "restart_terminal_bytes_unchanged": True}
    transport = report["transport_interruption"]
    if transport["requested_host"] is not None:
        need(transport["attempted"] is True and transport["passed"] is True
             and transport["signal_receipt"]["pidfd_terminal_observed"] is True,
             "requested private transport interruption incomplete")
    raw_evidence = verify_raw_native(report, Path(report_directory))
    return {"schema": "hepta-six-host-cancel-recovery-independent-verification/v2", "verified": True,
            "source_sha256": sha(raw), "source_bytes": len(raw), "candidate_sha256": report["candidate_sha256"],
            "allocator_environment_verification": allocator_proof,
            "topology_verification": topology_proof, "raw_evidence": raw_evidence,
            "hosts": results, "native_calls": len(calls), "independent_ssh_calls": len(report["ssh_calls"]),
            "new_starts": 6, "same_key_lookups": 12, "cancellations": 12, "automatic_rpc_retries": 0,
            "elapsed_seconds": report["finished_unix"] - report["started_unix"],
            "private_transport_interruption": transport,
            "resource_errors_by_phase": {p: report[p]["resources"]["errors"] for p in
                                         ("intentional_crash", "after_cancel_shutdown", "shutdown")},
            "not_covered": report["not_covered"], "macos_signal_identity": report["macos_signal_identity"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    raw = args.report.read_bytes()
    if args.report.suffix == ".gz":
        raw = gzip.decompress(raw)
    summary = verify(raw, args.report.parent)
    with args.output.open("x") as stream:
        json.dump(summary, stream, indent=2)
        stream.write("\n")
    print(json.dumps({k: summary[k] for k in ("verified", "native_calls", "independent_ssh_calls", "elapsed_seconds")}))


if __name__ == "__main__":
    main()


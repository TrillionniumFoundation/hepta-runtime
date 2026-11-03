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


def verify(raw):
    report = json.loads(raw)
    need(report["schema"] == "hepta-six-host-cancel-recovery/v1" and report["passed"] is True,
         "not a completed cancellation/recovery report")
    need(set(report["hosts"]) == HOSTS and all(report[key] is True for key in
         ("source_originals_unchanged", "binary_unchanged", "current_agent_unchanged")), "input identity changed")
    need(report["production_service_mutations"] == report["remote_cleanup_operations"]
         == report["automatic_rpc_retries"] == 0, "unexpected effects/retries")
    need(len({r["prepare"]["hostname"] for r in report["hosts"].values()}) == 6, "hostnames are not distinct")
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
             and acknowledgement["atomic_identity"] is (host != "mac"), "cancel signal acknowledgement differs")
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
    return {"schema": "hepta-six-host-cancel-recovery-independent-verification/v1", "verified": True,
            "source_sha256": sha(raw), "source_bytes": len(raw), "candidate_sha256": report["candidate_sha256"],
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
    summary = verify(raw)
    with args.output.open("x") as stream:
        json.dump(summary, stream, indent=2)
        stream.write("\n")
    print(json.dumps({k: summary[k] for k in ("verified", "native_calls", "independent_ssh_calls", "elapsed_seconds")}))


if __name__ == "__main__":
    main()

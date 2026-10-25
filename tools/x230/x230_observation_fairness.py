#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Read-only A/B fairness probes on the six original completed jobs.

Every wave uses the same eight-head/admission-snapshot/two-tail shape. Native
request_history proves dispatch admission, not pool permit acquisition. Failed
gates and every refusal/timeout remain evidence; no call or wave is retried.
"""
import argparse
from collections import Counter
import concurrent.futures
import json
import math
import os
from pathlib import Path
import sys
import threading
import time

import x230_observation_benchmark as bench

DEV_ROOT = Path.home() / "hepta-runtime-optimization-20261023"
CELL_NAMES = ("balanced", "hot_only", "skew")


class Controller(bench.Controller):
    """Retain bounded response-size/error receipts without changing base calls."""
    def __init__(self, *args, **kwargs):
        self.rpc_receipt = threading.local()
        super().__init__(*args, **kwargs)

    def rpc(self, method, params, timeout=50):
        if method == "tools/call":
            bench.need(params.get("name") in {"process_status", "process_read", "request_history"},
                       "only original-job observations and private dispatch metadata are allowed")
        self.rpc_receipt.last = {}
        response = super().rpc(method, params, timeout)
        encoded = bench.canonical(response)
        self.rpc_receipt.last = {"canonical_response_json_bytes": len(encoded),
                                 "canonical_response_sha256": bench.digest(encoded)}
        if "error" in response or response.get("result", {}).get("isError") is True:
            self.rpc_receipt.last["full_refusal_response"] = response
        return response

    def call(self, tool, job, purpose):
        self.rpc_receipt.last = {}
        row = super().call(tool, job, purpose)
        row.update(getattr(self.rpc_receipt, "last", {}))
        return row


def history(controller, after_id, purpose, collection):
    """One fresh metadata observation, never a retry of a failed query."""
    row = {"purpose": purpose, "after_id": after_id, "okay": False,
           "automatic_retry": False, "start_monotonic": time.monotonic()}
    collection.append(row)
    params = {"limit": 32}
    if after_id is not None:
        params["after_id"] = after_id
    try:
        response = controller.rpc("tools/call", {"name": "request_history", "arguments": params}, timeout=5)
        row.update(controller.rpc_receipt.last)
        bench.need("error" not in response and response.get("result", {}).get("isError") is not True,
                   "request_history observation refused")
        content = [item["text"] for item in response["result"].get("content", []) if item.get("type") == "text"]
        bench.need(len(content) == 1, "request_history did not return exactly one JSON metadata page")
        value = json.loads(content[0])
        bench.need(value.get("history_is_live") is True and value.get("automatic_operation_retry") is False
                   and value.get("session_scope") == "native_mcp_session_only", "history scope or retry semantics differ")
        requests = value.get("requests")
        bench.need(isinstance(requests, list) and len(requests) <= 32 and value.get("next_after_id") is None,
                   "unexpected history page overflow; no hidden pagination/filtering")
        bench.need(all(isinstance(item, dict) and isinstance(item.get("request_id"), str)
                       and item.get("tool_name") in {"process_read", "process_status"}
                       and item.get("state") in {"accepted", "completed", "failed", "unknown"}
                       for item in requests), "unexpected dispatch metadata contents")
        bench.need(len({item["request_id"] for item in requests}) == len(requests), "duplicate metadata request IDs")
        row.update(okay=True, requests=requests, status_semantics=value.get("status_semantics"),
                   next_after_id=None, snapshot_return_monotonic=time.monotonic())
        return row
    except Exception as error:
        row["error"] = {"type": type(error).__name__, "reason": str(error)[:1000]}
        row.update(getattr(controller.rpc_receipt, "last", {}))
        return row
    finally:
        row["elapsed_ms"] = (time.monotonic() - row["start_monotonic"]) * 1000


def metrics(rows, seconds):
    latency = sorted(row["elapsed_ms"] for row in rows)
    count = len(rows)
    successful = sum(row.get("okay") is True for row in rows)
    result = {"calls": count, "successes": successful, "failures": count - successful,
              "seconds": seconds, "completion_rps": count / seconds if seconds > 0 else None,
              "successful_rps": successful / seconds if seconds > 0 else None,
              "no_success_filtering": True, "latency_includes_failed_calls": True,
              "max_ms": max(latency) if latency else None,
              "native_is_error_count": sum(row.get("isError") is True for row in rows),
              "rpc_error_count": sum("rpc_error" in row for row in rows),
              "client_timeout_count": sum(row.get("error_type") in {"Empty", "TimeoutError"} for row in rows),
              "max_canonical_response_json_bytes": max((row.get("canonical_response_json_bytes", 0) for row in rows), default=None)}
    for percentile in (50, 95, 99):
        result[f"p{percentile}_ms"] = latency[math.ceil(len(latency) * percentile / 100) - 1] if latency else None
    return result


def wave_plan(name, index, jobs, hot, cold):
    if name == "balanced":
        return [("process_status" if (serial // 6) % 2 == 0 else "process_read", jobs[serial % 6])
                for serial in range(index * 10, index * 10 + 10)]
    return [("process_status", hot)] * 8 + ([("process_status", hot)] * 2 if name == "hot_only"
                                           else [("process_read", cold)] * 2)


def wave(controller, pool, name, index, plan, cursor, gate_budget_ms, retained_waves):
    result = {"index": index, "name": name, "rows": [], "metadata_observations": [],
              "gate_passed": False, "tail_attempted": False, "tail_calls_submitted": 0,
              "automatic_retry": False}
    retained_waves.append(result)
    row_lock = threading.Lock()
    released = threading.Event()
    started = time.monotonic()
    def observe(ordinal):
        released.wait()
        tool, job = plan[ordinal]
        row = controller.call(tool, job, f"{name}:wave-{index}:call-{ordinal}")
        row.update(wave=index, ordinal=ordinal, role="head" if ordinal < 8 else "tail")
        with row_lock:
            result["rows"].append(row)
        return row
    head = [pool.submit(observe, ordinal) for ordinal in range(8)]
    released.set()
    gate_started = time.monotonic()
    gate_deadline = gate_started + gate_budget_ms / 1000
    snapshot = None
    # Polling observes different live metadata snapshots; a refused query ends
    # the gate immediately and is never repeated automatically.
    while True:
        snapshot = history(controller, cursor, f"{name}:wave-{index}:admission_snapshot", result["metadata_observations"])
        requests = snapshot.get("requests", [])
        unfinished = sum(not future.done() for future in head)
        accepted = [item for item in requests if item.get("state") == "accepted"]
        tools_match = Counter(item["tool_name"] for item in requests) == Counter(tool for tool, job in plan[:8])
        result["gate_snapshot"] = {"native_admitted_count": len(requests), "native_accepted_count": len(accepted),
                                   "head_futures_unfinished": unfinished,
                                   "request_ids": [item["request_id"] for item in requests],
                                   "head_tool_counts_match": tools_match,
                                   "snapshot_return_monotonic": snapshot.get("snapshot_return_monotonic"),
                                   "metadata_query_okay": snapshot["okay"]}
        if snapshot["okay"] and tools_match and len(requests) == len(accepted) == unfinished == 8:
            result["gate_passed"] = True
            break
        if not snapshot["okay"] or unfinished != 8 or time.monotonic() >= gate_deadline:
            break
        # Same small polling interval for all three cells, never a target delay.
        time.sleep(.005)
    tail_submitted = time.monotonic()
    result["gate_elapsed_ms"] = (tail_submitted - gate_started) * 1000
    result["head_unfinished_at_tail_submission"] = sum(not future.done() for future in head)
    result["tail_submission_monotonic"] = tail_submitted
    result["gate_passed"] = result["gate_passed"] and result["head_unfinished_at_tail_submission"] == 8
    tail = []
    for ordinal in range(8, 10):
        tail.append(pool.submit(observe, ordinal))
        result["tail_calls_submitted"] += 1
    result["tail_attempted"] = True
    result["rows"] = [future.result() for future in head + tail]
    result["completion_seconds_before_final_metadata"] = time.monotonic() - started
    tail_start = min(row["start_monotonic"] for row in result["rows"] if row["role"] == "tail")
    snapshot_time = result["gate_snapshot"]["snapshot_return_monotonic"]
    result["accepted_snapshot_to_first_tail_start_ms"] = ((tail_start - snapshot_time) * 1000 if snapshot_time is not None else None)
    result["head_calls_completed_before_first_tail_start"] = sum(
        row["start_monotonic"] + row["elapsed_ms"] / 1000 <= tail_start for row in result["rows"] if row["role"] == "head")
    result["gate_passed"] = result["gate_passed"] and result["head_calls_completed_before_first_tail_start"] == 0
    final_history = history(controller, cursor, f"{name}:wave-{index}:completed_metadata", result["metadata_observations"])
    result["final_metadata_consistent"] = (final_history["okay"] and len(final_history["requests"]) == 10
                                          and Counter(item["tool_name"] for item in final_history["requests"]) == Counter(tool for tool, job in plan)
                                          and all(item["state"] != "accepted" for item in final_history["requests"]))
    result["all_final_metadata_completed"] = (final_history["okay"] and len(final_history["requests"]) == 10
                                             and all(item["state"] == "completed" for item in final_history["requests"]))
    result["metrics"] = metrics(result["rows"], result["completion_seconds_before_final_metadata"])
    result["head_metrics"] = metrics(result["rows"][:8], result["completion_seconds_before_final_metadata"])
    result["tail_metrics"] = metrics(result["rows"][8:], result["completion_seconds_before_final_metadata"])
    result["passed"] = (result["gate_passed"] and result["final_metadata_consistent"] and result["all_final_metadata_completed"]
                        and all(row.get("okay") is True for row in result["rows"]))
    # A history failure is retained, then the caller ends this controller instead
    # of guessing a cursor and contaminating another wave's admission proof.
    next_cursor = final_history["requests"][-1]["request_id"] if result["final_metadata_consistent"] else None
    return result, next_cursor


def cell(controller, name, repeats, jobs, hot, cold, cursor, gate_budget_ms, retained_cells):
    before_sample = controller.resources.snapshot()["sampled_tree_cpu_seconds"]
    birth, cpu_before = bench.process_stat(controller.child.pid)
    bench.need(birth == controller.birth, "controller identity changed before fairness cell")
    result = {"name": name, "waves": [], "requested_waves": repeats, "maximum_submitted_calls_per_wave": 10,
              "native_gate_required_count": 8, "gate_budget_ms": gate_budget_ms, "passed": False}
    retained_cells.append(result)
    started = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        for index in range(repeats):
            item, cursor = wave(controller, pool, name, index, wave_plan(name, index, jobs, hot, cold), cursor, gate_budget_ms, result["waves"])
            if cursor is None:
                result["stopped_reason"] = "completed metadata could not bind exactly this wave; no guessed cursor or retry"
                break
    seconds = time.monotonic() - started
    after_birth, cpu_after = bench.process_stat(controller.child.pid)
    bench.need(after_birth == controller.birth and cpu_after >= cpu_before, "controller CPU identity/counter changed")
    rows = [row for item in result["waves"] for row in item["rows"]]
    result.update(metrics(rows, seconds))
    result.update(controller_cpu_seconds=cpu_after - cpu_before,
                  controller_cpu_ms_per_call=(cpu_after - cpu_before) * 1000 / len(rows) if rows else None,
                  sampled_tree_cpu_seconds_delta=controller.resources.snapshot()["sampled_tree_cpu_seconds"] - before_sample,
                  sampled_tree_cpu_seconds_delta_is_lower_bound=True,
                  gate_failures=sum(not item["gate_passed"] for item in result["waves"]),
                  metadata_failures=sum(not item["okay"] for wave_ in result["waves"] for item in wave_["metadata_observations"]),
                  head_metrics=metrics([row for row in rows if row["role"] == "head"], seconds),
                  tail_metrics=metrics([row for row in rows if row["role"] == "tail"], seconds))
    result["passed"] = len(result["waves"]) == repeats and all(item["passed"] for item in result["waves"])
    return result, cursor


def clean_shutdown(value):
    return (value.get("exit_code") == 0 and value.get("shutdown_method") == "stdin_eof"
            and value.get("reader_error") is None and value.get("unmatched_responses") == 0
            and value.get("observed_descendant_survivors") == [])


def originals_unchanged(directory, jobs):
    registry = directory / "state/jobs"
    return (sorted(path.name for path in registry.iterdir()) == sorted(job["id"] + ".json" for job in jobs)
            and all(bench.read_file(registry / (job["id"] + ".json"), 65536) == job["record_bytes"] for job in jobs))


def save_final(path, report):
    try:
        bench.save_report(path, report)
        return path
    except BaseException as error:
        report["passed"] = False
        report["report_save_error"] = {"type": type(error).__name__, "reason": str(error)[:1000]}
        fallback = path.parent / f"report-final-{os.getpid()}-{time.time_ns()}.json"
        try:
            bench.create_file(fallback, bench.canonical(report))
            fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
            return fallback
        except BaseException as fallback_error:
            report["fallback_save_error"] = {"type": type(fallback_error).__name__, "reason": str(fallback_error)[:1000]}
            try:
                print(json.dumps({"unsaved_fairness_report": report}), file=sys.stderr, flush=True)
            except BaseException:
                pass
            return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("baseline", "candidate", "profile-template", "frozen-jobs", "out", "socket-parent"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--waves", type=int, default=8)
    parser.add_argument("--gate-budget-ms", type=int, default=120)
    parser.add_argument("--order", choices=("ABBA", "AB"), default="ABBA")
    args = parser.parse_args()
    out = args.out.absolute()
    bench.need(sys.platform == "linux" and out.parent == DEV_ROOT and out.resolve() == out and not out.exists(),
               "run on x230 with a fresh direct child of the current private dev directory")
    bench.need(1 <= args.waves <= 8 and 1 <= args.workers <= 8 and 20 <= args.gate_budget_ms <= 250,
               "fairness dimensions exceed this bounded read-only experiment")
    out.mkdir(mode=0o700)
    path = out / "report.json"
    report = {"schema": "hepta-x230-readonly-observation-fairness/v1", "started_unix": time.time(), "passed": False,
              "order": args.order, "waves_per_cell": args.waves, "calls_per_wave": 10, "head_calls": 8, "tail_calls": 2,
              "hot_host_alias": "mac", "cold_host_alias": "ai395", "tokio_workers": args.workers,
              "effect_starts": 0, "remote_mutation_tool_calls": 0, "automatic_rpc_retries": 0,
              "wave_retry_count": 0, "inter_wave_pause_seconds": 0, "rounds": [],
              "transport": "native stdio MCP, one concurrent session per controller",
              "driver_sha256": bench.digest(Path(bench.__file__).read_bytes()),
              "fairness_harness_sha256": bench.digest(Path(__file__).read_bytes()),
              "method": {"admission_gate": "Eight distinct new request_history records must be accepted and eight head futures unfinished before tail submission; no head may finish before first tail call starts.",
                         "admission_boundary": "Native dispatch admission is observed; pool eligibility, global permit ownership and remote execution admission are not directly observed.",
                         "shape": "All cells use eight head calls, the same live metadata gate, then two tail calls; tail is still attempted if the gate fails.",
                         "balanced": "Deterministic cyclic distribution over six hosts; status/read alternate in blocks of six. Exact per-host/tool counts are recoverable from all rows.",
                         "hot_only": "All ten calls are mac process_status; detects hot-host acceptance and throughput regressions.",
                         "skew": "Eight mac process_status calls followed by two ai395 process_read calls.",
                         "timing": "Cell wall time and CPU include metadata gates and final metadata observations; row latency is the individual original-job RPC including validation.",
                         "counterbalance": "ABBA; cell order balanced/hot_only/skew then reverse alternates so both versions see both orders.",
                         "retention": "Process status/read have metadata-only native result retention; record complete response hashes and canonical serialized response sizes, not an unobserved retained-buffer peak.",
                         "resource_scope": "Existing 100ms local controller/tree sampler; sampled lower bounds, descendant executables unclassified."},
              "not_covered": ["new launches", "HTTP", "remote workload mutation", "exact pool-permit occupancy", "large output throughput", "long-term fairness", "target reboot"]}
    active = None
    jobs, binaries, hashes, directories = [], {}, {}, []
    agent = None
    agent_before = None
    try:
        jobs = bench.load_jobs(args.frozen_jobs)
        by_host = {job["host"]: job for job in jobs}
        agent = os.environ.get("SSH_AUTH_SOCK", "")
        bench.need(agent.startswith("/"), "fresh held SSH_AUTH_SOCK required")
        agent_before = bench.agent_identity(agent)
        binaries = {"A": args.baseline.absolute(), "B": args.candidate.absolute()}
        hashes = {key: bench.digest(bench.read_file(value, 128 * 1024 * 1024)) for key, value in binaries.items()}
        profile, profile_receipt = bench.fresh_profile(args.profile_template, out / "profile", args.socket_parent, agent)
        report.update(binary_sha256=hashes, profile=profile_receipt,
                      six_originals=[{"host": job["host"], "job_id": job["id"], "record_sha256": job["record_sha256"],
                                      "stdout_sha256": bench.digest(job["expected"]), "stdout_bytes": len(job["expected"])} for job in jobs])
        for number, version in enumerate(args.order):
            bench.need(bench.agent_identity(agent) == agent_before, "current agent changed before fairness round")
            bench.need(bench.digest(bench.read_file(binaries[version], 128 * 1024 * 1024)) == hashes[version], "binary changed")
            directory = out / f"round-{number}-{version}"
            config = bench.fixture(directory, jobs)
            directories.append(directory)
            process_directory = directory / "controller"
            process_directory.mkdir(mode=0o700)
            round_ = {"index": number, "version": version, "passed": False, "cells": [], "metadata_observations": []}
            report["rounds"].append(round_)
            active = Controller(binaries[version], config, profile, process_directory, args.workers)
            round_["startup"] = active.startup
            round_["initial_complete_outputs"] = [active.call("process_read", job, "prewarm_complete_output") for job in jobs]
            bench.need(all(row["okay"] for row in round_["initial_complete_outputs"]), "six-host warmup/output verification failed")
            initial_history = history(active, None, "initial_cursor_after_warmup", round_["metadata_observations"])
            bench.need(initial_history["okay"] and len(initial_history["requests"]) == 6
                       and all(item["state"] == "completed" for item in initial_history["requests"]),
                       "initial private session history differs from exactly six completed warmups")
            cursor = initial_history["requests"][-1]["request_id"]
            names = CELL_NAMES if number % 2 == 0 else tuple(reversed(CELL_NAMES))
            round_["cell_order"] = list(names)
            for name in names:
                result, cursor = cell(active, name, args.waves, jobs, by_host["mac"], by_host["ai395"], cursor, args.gate_budget_ms, round_["cells"])
                bench.save_report(path, report)
                print(json.dumps({"round": number, "version": version, "cell": name,
                                  **{key: result[key] for key in ("calls", "successes", "failures", "seconds", "p50_ms", "p95_ms", "gate_failures", "passed")}}), flush=True)
                bench.need(cursor is not None, "wave metadata incomplete; stop without another admission/retry")
            round_["final_complete_outputs"] = [active.call("process_read", job, "postflight_complete_output") for job in jobs]
            round_["shutdown"] = active.close()
            active = None
            round_["private_originals_unchanged"] = originals_unchanged(directory, jobs)
            round_["passed"] = (all(item["passed"] for item in round_["cells"])
                                and all(item["okay"] for item in round_["final_complete_outputs"])
                                and clean_shutdown(round_["shutdown"]) and round_["private_originals_unchanged"])
            bench.save_report(path, report)
        report["passed"] = all(item["passed"] for item in report["rounds"]) and len(report["rounds"]) == len(args.order)
    except BaseException as error:
        report["error"] = {"type": type(error).__name__, "reason": str(error)[:1500]}
        report["passed"] = False
    finally:
        if active is not None:
            try:
                report["interrupted_shutdown"] = active.close()
            except BaseException as error:
                report["cleanup_error"] = {"type": type(error).__name__, "reason": str(error)[:1000]}
            report["passed"] = False
        try:
            report["source_originals_unchanged"] = bool(jobs) and all(bench.read_file(job["path"], 65536) == job["record_bytes"] for job in jobs)
            report["private_originals_unchanged"] = bool(directories) and all(originals_unchanged(directory, jobs) for directory in directories)
            report["binary_hashes_unchanged"] = bool(hashes) and all(bench.digest(bench.read_file(value, 128 * 1024 * 1024)) == hashes[key] for key, value in binaries.items())
            report["current_agent_unchanged"] = agent_before is not None and bench.agent_identity(agent) == agent_before
        except BaseException as error:
            report["final_check_error"] = {"type": type(error).__name__, "reason": str(error)[:1000]}
            report["passed"] = False
        report["passed"] = report["passed"] and all(report.get(key) is True for key in (
            "source_originals_unchanged", "private_originals_unchanged", "binary_hashes_unchanged", "current_agent_unchanged"))
        report["finished_unix"] = time.time()
        path = save_final(path, report)
    print(json.dumps({"report": str(path), "passed": report["passed"], "error": report.get("error")}), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Bounded C32 observation bursts with explicit refusal and recovery accounting.

Reuses the frozen R16 Controller, transport capture, cell clocks/resources,
profile preparation and original-job fixtures. This is an overload diagnostic,
not an all-success throughput comparison or a new-job execution benchmark.
"""
import argparse
from collections import Counter
import hashlib
import importlib
import json
import math
from pathlib import Path
import sys
import threading
import time

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SOURCE_NAMES = ("run_native_boundary.py", "audit_native_boundary.py", "test_native_boundary.py",
                "harness-freeze.json", "capacity-policy.json")
CLASSES = ("success", "capacity_rejection", "other_error")
CAPACITY_TEXT = "observation pool capacity unavailable; no fallback or automatic retry"


def need(value, reason):
    if not value:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def source_hashes():
    return {name: sha((HERE / name).read_bytes()) for name in SOURCE_NAMES}


def freeze(root):
    pins = json.loads((HERE / "harness-freeze.json").read_bytes())
    need(pins["schema"] == "hepta-r16-boundary-harness-freeze/v1" and len(pins["files"]) == 12,
         "frozen harness manifest differs")
    current = {name: sha((root / name).read_bytes()) for name in pins["files"]}
    need(current == pins["files"], "frozen measurement source changed")
    return current


def load_frozen(root):
    freeze(root)
    sys.path.insert(0, str(root))
    bench = importlib.import_module("x230_observation_benchmark")
    need(Path(bench.__file__).resolve().parent == root, "loaded another observation helper")
    return bench


def load_policy(raw):
    value = json.loads(raw)
    need(value["schema"] == "hepta-native-capacity-error-policy/v1", "error policy schema differs")
    need(type(value["rendering_verified"]) is bool and isinstance(value["accepted_error_envelopes"], list),
         "error policy verification state differs")
    need(value["rendering_verified"] or not value["accepted_error_envelopes"], "unverified capacity whitelist is forbidden")
    for rule in value["accepted_error_envelopes"]:
        need(rule == {"kind": "native_single_text", "text": CAPACITY_TEXT}, "unrecognized exact error rule")
    if value["rendering_verified"]:
        need(value.get("rendering_source_proof"), "verified rendering lacks its pinned source proof")
    return value


def envelope_kind(reply, policy):
    if "error" in reply:
        return "other_error"
    result = reply.get("result")
    if not isinstance(result, dict):
        return "other_error"
    if result.get("isError") is True:
        content = result.get("content")
        for rule in policy["accepted_error_envelopes"] if policy["rendering_verified"] else ():
            if (rule["kind"] == "native_single_text" and isinstance(content, list) and len(content) == 1
                    and isinstance(content[0], dict) and content[0].get("type") == "text"
                    and content[0].get("text") == rule["text"]):
                return "capacity_rejection"
        return "other_error"
    return "candidate_success"


def make_controller(bench, policy):
    original = bench.Controller

    class BoundaryController(original):
        def __init__(self, binary, config, profile, directory, workers, **kwargs):
            need(workers == 2 and kwargs.get("allocator_values") == {"MALLOC_ARENA_MAX": "1"},
                 "boundary worker/allocator configuration differs")
            self.burst_context = None
            self.boundary_phase = "initialize"
            super().__init__(binary, config, profile, directory, workers, **kwargs)
            try:
                before = bench.counters(self.child.pid)
                start = time.monotonic_ns()
                with Path(f"/proc/{self.child.pid}/environ").open("rb") as stream:
                    raw = stream.read(1024 * 1024 + 1)
                end = time.monotonic_ns()
                after = bench.counters(self.child.pid)
                need(len(raw) <= 1024 * 1024 and raw.endswith(b"\0"), "worker environment exceeds bound/framing")
                entries = [entry + b"\0" for entry in raw.split(b"\0") if entry.startswith(b"TOKIO_WORKER_THREADS=")]
                need(entries == [b"TOKIO_WORKER_THREADS=2\0"]
                     and before["birth_ticks"] == after["birth_ticks"] == self.birth, "actual worker environment/generation differs")
                selected = b"".join(entries)
                self.startup["boundary_worker_environment"] = {
                    "source": "same-PID/start-ticks /proc/PID/environ", "observed_workers": 2,
                    "full_environment_retained": False, "selected_raw_hex": selected.hex(), "sha256": sha(selected),
                    "read_start_monotonic_ns": start, "read_end_monotonic_ns": end,
                    "controller_before": before, "controller_after": after}
            except BaseException:
                self.close()
                raise

        def rpc(self, method, params, timeout=50, evidence=None):
            reply = super().rpc(method, params, timeout, evidence)
            if method == "tools/call" and evidence is not None:
                evidence["boundary_envelope_classification"] = envelope_kind(reply, policy)
            return reply

        def call(self, tool, job, purpose):
            context = self.burst_context
            gate = None
            if context is not None:
                ready = time.monotonic_ns()
                with context["lock"]:
                    arrival = len(context["arrivals"])
                    context["arrivals"].append(ready)
                context["barrier"].wait(timeout=10)
                gate = {"burst": context["index"], "arrival_index": arrival, "ready_monotonic_ns": ready,
                        "gate_open_monotonic_ns": context["opened_monotonic_ns"],
                        "released_monotonic_ns": time.monotonic_ns()}
            row = super().call(tool, job, purpose)
            kind = row["rpc"].get("boundary_envelope_classification", "other_error")
            row["classification"] = "success" if row["okay"] else "capacity_rejection" if kind == "capacity_rejection" else "other_error"
            row["boundary_phase"] = self.boundary_phase
            if gate is not None:
                row["burst_gate"] = gate
            return row

    return BoundaryController


def classified_summary(rows, seconds):
    result = {}
    for kind in CLASSES:
        values = sorted(row["elapsed_ms"] for row in rows if row["classification"] == kind)
        result[kind] = {"count": len(values), "rate_per_second": len(values) / seconds,
                        "latency_ms": None if not values else {
                            "p50": values[math.ceil(len(values) * .50) - 1],
                            "p95": values[math.ceil(len(values) * .95) - 1],
                            "p99": values[math.ceil(len(values) * .99) - 1], "max": values[-1]}}
    return result


def run_burst(bench, controller, jobs, number):
    context = {"index": number, "lock": threading.Lock(), "arrivals": []}
    context["barrier"] = threading.Barrier(32, action=lambda: context.update(opened_monotonic_ns=time.monotonic_ns()))
    controller.boundary_phase = f"burst-{number}"
    controller.burst_context = context
    try:
        result = bench.cell(controller, jobs, 32, 32)
    finally:
        controller.burst_context = None
    need(len(context["arrivals"]) == 32, "client burst did not align 32 attempts")
    for slot, row in enumerate(result["rows"]):
        row["burst_slot"] = slot
    result["burst_index"] = number
    result["classified"] = classified_summary(result["rows"], result["seconds"])
    result["controller_cpu_ms_per_attempt"] = result["controller_cpu_ms_per_call"]
    result["client_gate"] = {"parties": 32, "arrivals": 32, "opened_monotonic_ns": context["opened_monotonic_ns"],
                             "timeout_seconds": 10, "atomic_network_dispatch_claimed": False}
    result["pool_admitted_identities_observed"] = None
    return result


def drain(controller, rows):
    start = time.monotonic_ns()
    with controller.lock:
        pending = sorted(controller.pending)
        unmatched = controller.unmatched
    result = {"start_monotonic_ns": start, "end_monotonic_ns": time.monotonic_ns(),
              "pending_rpc_ids": pending, "unmatched_responses": unmatched,
              "reader_error": controller.reader_error, "controller_running": controller.child.poll() is None,
              "complete_responses": sum(row["rpc"].get("transport_response") is not None for row in rows),
              "completed_attempts": len(rows)}
    result["complete"] = (not pending and unmatched == 0 and controller.reader_error is None
                          and result["controller_running"] and result["complete_responses"] == len(rows)
                          and all(row["end_monotonic_ns"] <= start for row in rows))
    return result


def clean_shutdown(value):
    return (value["exit_code"] == 0 and value["shutdown_method"] == "stdin_eof"
            and not value["observed_descendant_survivors"] and value["reader_error"] is None
            and value["resources"]["sampler_error"] is None and value["transport_capture"]["reader_eof"] is True
            and value["unmatched_responses"] == 0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("binary", "profile-template", "topology", "frozen-jobs", "socket-parent", "out"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--bursts", type=int, choices=(2, 3, 4), default=2)
    parser.add_argument("--harness-root", type=Path, default=HERE.parent / "measurement-tools")
    args = parser.parse_args()
    root = args.harness_root.resolve()
    bench = load_frozen(root)
    out = args.out.absolute()
    need(out.resolve() == out and out.is_relative_to(HERE.parent) and not out.exists(), "output must be a fresh direct path within R16")
    out.mkdir(mode=0o700)
    sources, frozen = source_hashes(), freeze(root)
    policy_raw = (HERE / "capacity-policy.json").read_bytes()
    policy = load_policy(policy_raw)
    bench.create_file(out / "capacity-policy.json", policy_raw)
    jobs = bench.load_jobs(args.frozen_jobs)
    topology_raw, topology = bench.load_topology(args.topology, args.profile_template)
    bench.create_file(out / "topology.json", topology_raw)
    binary = args.binary.absolute()
    binary_hash = sha(bench.read_file(binary, 128 * 1024 * 1024))
    agent = bench.os.environ.get("SSH_AUTH_SOCK", "")
    need(agent.startswith("/"), "held authenticated SSH agent required")
    agent_before = bench.agent_identity(agent)
    profile, profile_receipt = bench.fresh_profile(args.profile_template, out / "profile", args.socket_parent, agent)
    fixture = out / "controller"
    config = bench.fixture(fixture, jobs, topology)
    first = fixture / "first"
    first.mkdir(mode=0o700)
    report = {"schema": "hepta-x230-native-boundary-diagnostic/v1", "started_unix": time.time(),
        "candidate_sha256": binary_hash, "tokio_workers": 2, "arena_max": 1,
        "bursts_planned": args.bursts, "attempts_per_burst": 32, "warmup_calls": 24,
        "post_drain_concurrency": [1, 8], "post_drain_calls_per_cell": 24,
        "automatic_rpc_retries": 0, "effect_starts": 0, "remote_mutation_tool_calls": 0,
        "profile": profile_receipt, "topology": topology,
        "classification_policy": {"file": "capacity-policy.json", "bytes": len(policy_raw), "sha256": sha(policy_raw),
                                  "rendering_verified": policy["rendering_verified"]},
        "source_sha256": sources, "frozen_harness_sha256": frozen,
        "six_originals": [{"host": job["host"], "job_id": job["id"], "record_sha256": job["record_sha256"],
                           "stdout_bytes": len(job["expected"]), "stdout_sha256": sha(job["expected"])} for job in jobs],
        "allocator_configuration": bench.allocator.run_metadata({"candidate": {"MALLOC_ARENA_MAX": "1"}}, {"candidate": binary_hash}),
        "bursts": [], "passed": False,
        "scope": "bounded warm completed-job observations; client C32 gate; drain; planned C1/C8 probes; normal restart",
        "limitations": ["32 client attempts do not imply 32 native pool identities; validation may queue requests.",
                        "No refusal count is required; all 32 may succeed. This cannot establish the exact admission peak.",
                        "Only success contributes to successful_rps. Rejection and other-error rates/latencies are separate.",
                        "Post-drain probes are new planned read requests, not automatic retries.",
                        "CPU is synchronous controller CPU per attempt; no per-class or whole-cluster CPU attribution.",
                        "100 ms descendant samples remain incomplete and can double-count shared memory."]}
    controller_type = make_controller(bench, policy)
    active = None

    def save():
        try:
            report["sources_unchanged"] = source_hashes() == sources and freeze(root) == frozen
        except (OSError, ValueError):
            report["sources_unchanged"] = False
        report["passed"] = report["passed"] and report["sources_unchanged"]
        bench.save_report(out / "report.json", report)

    try:
        active = controller_type(binary, config, profile, first, 2, allocator_values={"MALLOC_ARENA_MAX": "1"})
        report["startup"] = active.startup
        active.boundary_phase = "preflight"
        report["initial_complete_outputs"] = [active.call("process_read", job, "preflight_complete_output") for job in jobs]
        need(all(row["okay"] for row in report["initial_complete_outputs"]), "six-host complete-output preflight failed")
        active.boundary_phase = "initial-warmup"
        report["initial_warmup"] = bench.cell(active, jobs, 8, 24)
        need(report["initial_warmup"]["successes"] == 24, "balanced initial warmup failed")
        for number in range(args.bursts):
            entry = {"index": number, "burst": run_burst(bench, active, jobs, number), "post_drain_cells": []}
            report["bursts"].append(entry)
            entry["drain"] = drain(active, entry["burst"]["rows"])
            save()
            need(entry["drain"]["complete"], "burst did not drain complete replies; no subsequent probes are sent")
            for concurrency in (1, 8):
                active.boundary_phase = f"post-drain-{number}-C{concurrency}"
                result = bench.cell(active, jobs, concurrency, 24)
                entry["post_drain_cells"].append(result)
                save()
                need(result["successes"] == 24, "planned balanced post-drain observation failed")
        report["shutdown"] = active.close()
        active = None
        need(clean_shutdown(report["shutdown"]), "first controller failed normal resource reclamation")
        need(sha(bench.read_file(binary, 128 * 1024 * 1024)) == binary_hash
             and bench.agent_identity(agent) == agent_before, "binary/agent changed before normal restart")
        restart = fixture / "restart"
        restart.mkdir(mode=0o700)
        active = controller_type(binary, config, profile, restart, 2, allocator_values={"MALLOC_ARENA_MAX": "1"})
        report["restart_startup"] = active.startup
        active.boundary_phase = "normal-restart"
        report["restart_checks"] = [active.call(tool, job, "restart_same_original") for job in jobs for tool in ("process_status", "process_read")]
        report["restart_shutdown"] = active.close()
        active = None
        need(all(row["okay"] for row in report["restart_checks"]) and clean_shutdown(report["restart_shutdown"]),
             "normal-restart readback or cleanup failed")
        report["drain_and_recovery_passed"] = True
        report["classified_burst_counts"] = dict(Counter(row["classification"] for entry in report["bursts"] for row in entry["burst"]["rows"]))
        report["capacity_rejection_observed"] = report["classified_burst_counts"].get("capacity_rejection", 0) > 0
        report["exact_pool_identity_peak_observed"] = False
        report["passed"] = report["classified_burst_counts"].get("other_error", 0) == 0
    except BaseException as error:
        report["error"] = {"type": type(error).__name__, "reason": str(error)[:1000]}
    finally:
        if active is not None:
            report["interrupted_shutdown"] = active.close()
        checks = {
            "source_originals_unchanged": lambda: all(bench.read_file(job["path"], 65536) == job["record_bytes"] for job in jobs),
            "copied_originals_unchanged": lambda: all(bench.read_file(fixture / "state/jobs" / (job["id"] + ".json"), 65536) == job["record_bytes"] for job in jobs),
            "binary_hashes_unchanged": lambda: sha(bench.read_file(binary, 128 * 1024 * 1024)) == binary_hash,
            "topology_manifest_unchanged": lambda: bench.read_file(args.topology, 65536) == topology_raw,
            "profile_template_unchanged": lambda: sha(bench.read_file(args.profile_template, 262144)) == profile_receipt["template_sha256"],
            "agent_identity_unchanged": lambda: bench.agent_identity(agent) == agent_before,
            "classification_policy_unchanged": lambda: (HERE / "capacity-policy.json").read_bytes() == policy_raw}
        for name, check in checks.items():
            try:
                report[name] = check()
            except Exception as error:
                report[name] = False
                report.setdefault("final_check_errors", {})[name] = type(error).__name__ + ": " + str(error)[:200]
        report["passed"] = report["passed"] and all(report[name] for name in checks)
        report["finished_unix"] = time.time()
        save()
    print(json.dumps({"report": str(out / "report.json"), "passed": report["passed"],
                      "classified_burst_counts": report.get("classified_burst_counts"), "error": report.get("error")}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())

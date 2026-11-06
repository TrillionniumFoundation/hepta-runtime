#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Descriptive R36 real async read admission/settlement ABBA; no adoption gate."""
import argparse
import base64
import concurrent.futures
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import signal
import sys
import threading
import time
import traceback
import types

sys.dont_write_bytecode = True
ROOT = Path("/home/qian/hepta-runtime-optimization-20261106-r36")
HELPER = ROOT / "tools-01/r36_campaign.py"
HELPER_SHA = "7cb886eccbefb6f52464e2c0bbab995d185349864afd9f53eaf1a36334d0ae95"
PROTOCOL = ROOT / "async-read-protocol-01.json"
OUT = ROOT / "async-read-abba-01"
SOCKETS = Path("/home/qian/h36ar01")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
RESULT_FORMAT = "serialized_original_native_sdk_payload_before_operation_metadata_and_transport_normalization"
ACTIVE_STATES = {"queued", "running", "settling"}


def need(value, reason):
    if not value:
        raise RuntimeError(reason)


def json_text(result):
    need(isinstance(result, dict) and not result.get("isError", False), "native tool refused")
    text = [item["text"] for item in result.get("content", []) if item.get("type") == "text"]
    need(len(text) == 1, "one original JSON text block required")
    value = json.loads(text[0])
    need(isinstance(value, dict), "native JSON object required")
    return value


def scope(value):
    need(value.get("ownership_scope") == value.get("session_scope") == "native_mcp_session_only"
         and value.get("cross_session_resume") is False
         and value.get("credential_metadata_resume") is False,
         "native stdio ownership scope differs")


def validate_original(raw, job, tool):
    dto = json_text(json.loads(raw))
    need(dto.get("job_id") == job["id"] and dto.get("audit_recorded") is True
         and "audit_warning" not in dto, "frozen job identity or durable read audit differs")
    if tool == "process_status":
        need(dto.get("state") == "succeeded" and dto.get("exit_code") == 0
             and dto.get("output_complete") is True and not dto.get("cancelled")
             and not dto.get("timed_out"), "original remote job terminal differs")
        need(dto.get("log_bytes") == {"stdout": {"seen": len(job["expected"]), "stored": len(job["expected"])},
              "stderr": {"seen": 0, "stored": 0}}
             and dto.get("log_truncated") == {"stdout": False, "stderr": False}
             and dto.get("log_errors") == {"stdout": None, "stderr": None}, "original job capture incomplete")
    else:
        need(tool == "process_read", "unreviewed inner operation")
        for stream, expected in (("stdout", job["expected"]), ("stderr", b"")):
            part = dto[stream]
            need(bytes.fromhex(part["bytes_hex"]) == expected and part["offset"] == 0
                 and part["next_offset"] == part["size"] == len(expected) and part["eof"] is True,
                 "full original job output differs")
    return dto


def completed(value, operation_id, tool):
    scope(value)
    need(value["operation_id"] == operation_id and value["tool_name"] == tool
         and value["automatic_retry"] is False, "operation status binding differs")
    if value["async_state"] in ACTIVE_STATES:
        return False
    need(value["async_state"] == "completed" and value["owned_future_active"] is False
         and value["payload_available"] is True and value["result_state"] == "stored_observed",
         "background read did not complete with a retained original result")
    return True


def result_page(value, operation_id, offset, previous, maximum):
    scope(value)
    need(value["operation_id"] == operation_id and value["offset"] == offset
         and type(value["offset"]) is int and type(value["next_offset"]) is int
         and value["payload_kind"] == "native_result" and value["format"] == RESULT_FORMAT
         and value["immutable_snapshot"] is True and value["automatic_retry"] is False
         and type(value["total_bytes"]) is int and 0 < value["total_bytes"] <= maximum
         and HEX64.fullmatch(value["result_sha256"]), "original result page binding differs")
    identity = {name: value[name] for name in ("total_bytes", "result_sha256", "payload_kind", "format")}
    need(previous is None or identity == previous, "original result identity changed across pages")
    raw = base64.b64decode(value["data_base64"], validate=True)
    need(len(raw) <= 16384 and value["next_offset"] == offset + len(raw) <= value["total_bytes"]
         and value["eof"] is (value["next_offset"] == value["total_bytes"])
         and (value["eof"] or len(raw) > 0), "invalid original result cursor")
    return raw, identity


def percentiles(values):
    values = sorted(values)
    need(values, "empty latency sample")
    return {"n": len(values), **{"p" + str(q) + "_ms": values[math.ceil(len(values) * q / 100) - 1]
                                for q in (50, 95, 99)}, "max_ms": values[-1]}


def memory_windows(directory, round_row):
    """Use only samples fully inside the measured cell, plus its raw endpoints."""
    cells = {cell["concurrency"]: cell for cell in round_row["cells"]}
    for cell in cells.values():
        samples = []
        timing = cell["measured"]["raw_timing"]
        for key in ("controller_before", "controller_after"):
            lines = dict(line.split(":", 1) for line in timing[key]["raw_memory_status"].splitlines())
            if "VmRSS" in lines:
                samples.append({"origin": key, "rss_kib": int(lines["VmRSS"].split()[0])})
        cell["memory_window"] = {"controller_rss_observations": samples,
            "sampler_period_seconds": 0.1, "sampled_peak_is_not_a_complete_high_water_mark": True}
    with (directory / "resource-samples.jsonl").open("rb") as stream:
        for line in stream:
            sample = json.loads(line)
            for cell in cells.values():
                timing = cell["measured"]["raw_timing"]
                if (timing["start_monotonic_ns"] <= sample["start_monotonic_ns"]
                        and sample["end_monotonic_ns"] <= timing["end_monotonic_ns"]):
                    for process in sample["processes"]:
                        if (process["scope"] == "controller" and type(process["rss_kib"]) is int
                                and process["before"]["pid"] == round_row["startup"]["pid"]
                                and process["before"]["birth_ticks"] == round_row["startup"]["birth_ticks"]):
                            cell["memory_window"]["controller_rss_observations"].append({"origin": "sampler",
                                "sample": sample["sample"], "rss_kib": process["rss_kib"]})
    for cell in cells.values():
        observations = cell["memory_window"]["controller_rss_observations"]
        need(observations, "no controller memory observations")
        cell["memory_window"]["peak_observed_controller_rss_kib"] = max(item["rss_kib"] for item in observations)


def summarize(rounds):
    summary = {"descriptive_only": True, "new_adoption_thresholds": None,
               "not_remote_compute_throughput_or_maximum_capacity": True, "cells": {}}
    for concurrency in (1, 8):
        values = {}
        for arm in "AB":
            selected = [next(cell for cell in row["cells"] if cell["concurrency"] == concurrency)
                        for row in rounds if row["arm"] == arm]
            need(len(selected) == 2, "complete fixed ABBA required for an aggregate")
            measured = [cell["measured"] for cell in selected]
            raw = [item for cell in measured for item in cell["raw_rows"]]
            count = sum(cell["count"] for cell in measured)
            need(count == len(raw) == 48, "measured admission inventory differs")
            values[arm] = {"reads": count,
                "admission_receipts_per_admission_window_second": count / sum(cell["admission_window_seconds"] for cell in measured),
                "verified_async_reads_per_cell_second": count / sum(cell["full_cell_seconds"] for cell in measured),
                "admission_latency": percentiles([item["admission_ms"] for item in raw]),
                "settlement_latency": percentiles([item["settlement_ms"] for item in raw]),
                "controller_cpu_ms_per_read": 1000 * sum(cell["controller_cpu_seconds"] for cell in measured) / count,
                "peak_observed_controller_rss_kib": max(cell["memory_window"]["peak_observed_controller_rss_kib"] for cell in selected)}
        metrics = ("admission_receipts_per_admission_window_second", "verified_async_reads_per_cell_second",
                   "controller_cpu_ms_per_read", "peak_observed_controller_rss_kib")
        ratios = {name: values["B"][name] / values["A"][name] if values["A"][name] else None for name in metrics}
        for name in ("admission_latency", "settlement_latency"):
            ratios[name + "_p95_ms"] = values["B"][name]["p95_ms"] / values["A"][name]["p95_ms"]
        summary["cells"][str(concurrency)] = {"arms": values, "b_over_a": ratios}
    return summary


def endpoint(bench, controller):
    value = bench.counters(controller.child.pid)
    need(value["birth_ticks"] == controller.birth, "controller identity changed")
    status = Path(f"/proc/{controller.child.pid}/status").read_text()
    value["raw_memory_status"] = "\n".join(line for line in status.splitlines()
        if line.startswith(("VmRSS:", "VmHWM:", "Threads:"))) + "\n"
    return value


class Client:
    def __init__(self, bench, controller, directory, protocol, deadline):
        self.bench, self.controller, self.directory = bench, controller, directory
        self.protocol, self.deadline = protocol, deadline
        self.lock = threading.Lock()
        self.journal = (directory / "async-rpc-evidence.jsonl").open("xb")
        self.ids = set()
        self.partial_cell = None

    def rpc(self, tool, arguments, purpose, refuse=False, deadline=None):
        need(tool in {"operation_start", "operation_status", "operation_result"}, "unreviewed async API")
        remaining = min(self.deadline, deadline if deadline is not None else self.deadline) - time.monotonic()
        need(remaining > 0, "supplement budget exhausted; no next submission")
        row = {"tool": tool, "arguments": arguments, "purpose": purpose, "automatic_retry": False, "rpc": {}}
        try:
            reply = self.controller.rpc("tools/call", {"name": tool, "arguments": arguments},
                timeout=min(45, remaining), evidence=row["rpc"])
            row["response_sha256"] = self.bench.digest(self.bench.canonical(reply))
            if refuse:
                # Transport failure, timeout, and unrelated audit failure never prove owner isolation.
                need("error" not in reply and reply["result"].get("isError") is True,
                     "expected explicit native scope/argument refusal")
                message = "\n".join(item.get("text", "") for item in reply["result"].get("content", []) if item.get("type") == "text")
                need("unavailable to this scope" in message or "unavailable to this operation" in message,
                     "refusal was not the reviewed owner/key binding refusal")
                row["refusal_text"] = message
                row["expected_refusal"] = row["okay"] = True
                return row, None
            need("error" not in reply, "native RPC failed; never replay a start")
            value = json_text(reply["result"])
            row["okay"] = True
            return row, value
        except BaseException as error:
            row["okay"] = False
            row["error"] = {"type": type(error).__name__, "reason": str(error)[:1000]}
            raise
        finally:
            with self.lock:
                self.journal.write(self.bench.canonical(row))

    def start(self, item):
        evidence, receipt = self.rpc("operation_start", item["arguments"], item["label"] + "/new")
        scope(receipt)
        operation_id = receipt["operation_id"]
        need(HEX64.fullmatch(operation_id) and receipt["tool_name"] == item["tool"]
             and receipt["reused"] is False and receipt["idempotency_binding_retained"] is True
             and receipt["automatic_retry"] is False and receipt["admission_is_not_dispatch_completion"] is True,
             "new background read admission differs")
        with self.lock:
            need(operation_id not in self.ids, "distinct original keys shared an operation id")
            self.ids.add(operation_id)
        item.update(operation_id=operation_id, admission_receipt=receipt, admission_rpc=evidence["rpc"],
                    admission_ms=(evidence["rpc"]["rpc_end_monotonic_ns"] - evidence["rpc"]["rpc_start_monotonic_ns"]) / 1e6)
        return item

    def original(self, operation_id, purpose, deadline=None):
        raw = bytearray()
        identity = None
        pages = []
        while True:
            _, value = self.rpc("operation_result", {"operation_id": operation_id, "offset": len(raw),
                "limit": self.protocol["result_page_bytes"]}, purpose, deadline=deadline)
            part, identity = result_page(value, operation_id, len(raw), identity, self.protocol["maximum_result_bytes"])
            raw.extend(part)
            pages.append({key: value[key] for key in ("offset", "next_offset", "eof", "total_bytes", "result_sha256")})
            if value["eof"]:
                break
        need(len(raw) == identity["total_bytes"] and self.bench.digest(raw) == identity["result_sha256"],
             "complete serialized original payload SHA differs")
        return bytes(raw), identity, pages

    def settle(self, item):
        until = min(self.deadline, item["admission_rpc"]["rpc_start_monotonic_ns"] / 1e9
                    + self.protocol["operation_deadline_seconds"])
        polls = 0
        while True:
            need(time.monotonic() < until, "background read terminal deadline; no replay")
            _, status = self.rpc("operation_status", {"operation_id": item["operation_id"]}, item["label"] + "/status", deadline=until)
            polls += 1
            if completed(status, item["operation_id"], item["tool"]):
                break
            time.sleep(self.protocol["poll_seconds"])
        original, identity, pages = self.original(item["operation_id"], item["label"] + "/original", deadline=until)
        validate_original(original, item["job"], item["tool"])
        end = time.monotonic_ns()
        need(end / 1e9 <= until, "validated original result exceeded the end-to-end deadline")
        item.update(terminal=status, status_polls=polls, original_identity=identity, original_pages=pages,
                    settlement_end_monotonic_ns=end,
                    settlement_ms=(end - item["admission_rpc"]["rpc_start_monotonic_ns"]) / 1e6,
                    original_bytes=original)
        return item

    def idempotency(self, item):
        _, receipt = self.rpc("operation_start", item["arguments"], item["label"] + "/same-key-check")
        scope(receipt)
        need(receipt["operation_id"] == item["operation_id"] and receipt["reused"] is True
             and receipt["tool_name"] == item["tool"] and receipt["idempotency_binding_retained"] is True
             and receipt["automatic_retry"] is False,
             "identical-key admission did not retain the original identity")
        # A reused receipt may have live async_state=unknown after completion.
        _, status = self.rpc("operation_status", {"operation_id": item["operation_id"]}, item["label"] + "/same-key-status")
        need(completed(status, item["operation_id"], item["tool"]), "same-key original is no longer terminal")
        raw, identity, _ = self.original(item["operation_id"], item["label"] + "/same-key-original")
        need(raw == item["original_bytes"] and identity == item["original_identity"], "same-key original result changed")
        return {"operation_id": item["operation_id"], "reused": True, "original_result_unchanged": True,
                "admission_async_state": receipt["async_state"], "validation_outside_timing": True}

    def close(self):
        self.journal.flush()
        os.fsync(self.journal.fileno())
        self.journal.close()


def run_cell(client, jobs, concurrency, count, label):
    bench, controller = client.bench, client.controller
    before, sampled_before = endpoint(bench, controller), controller.resources.snapshot()
    start = time.monotonic_ns()
    rows, batches = [], []
    client.partial_cell = {"label": label, "concurrency": concurrency, "planned_reads": count,
        "start_monotonic_ns": start, "controller_before": before, "attempted": [], "completed_cohorts": batches}
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        for first in range(0, count, concurrency):
            items = []
            for index in range(first, min(first + concurrency, count)):
                job = jobs[index % 6]
                tool = "process_status" if (index // 6) % 2 == 0 else "process_read"
                arguments = {"host": job["host"], "job_id": job["id"]}
                if tool == "process_read":
                    arguments.update(stdout_offset=0, stderr_offset=0, limit=16384)
                key = label + "-" + str(index)
                items.append({"label": key, "tool": tool, "job": job,
                              "arguments": {"idempotency_key": key, "operation": {"tool": tool, "arguments": arguments}}})
            client.partial_cell["attempted"].extend(items)
            admitted = list(pool.map(client.start, items))
            admission_start = min(item["admission_rpc"]["rpc_start_monotonic_ns"] for item in admitted)
            admission_end = max(item["admission_rpc"]["rpc_end_monotonic_ns"] for item in admitted)
            settled = list(pool.map(client.settle, admitted))
            batches.append({"count": len(settled), "admission_start_monotonic_ns": admission_start,
                            "admission_end_monotonic_ns": admission_end,
                            "settlement_end_monotonic_ns": max(item["settlement_end_monotonic_ns"] for item in settled)})
            rows.extend(settled)
    end = time.monotonic_ns()
    after, sampled_after = endpoint(bench, controller), controller.resources.snapshot()
    client.partial_cell.update(end_monotonic_ns=end, controller_after=after)
    cpu_ticks = after["utime_ticks"] + after["stime_ticks"] - before["utime_ticks"] - before["stime_ticks"]
    need(cpu_ticks >= 0 and before["clock_ticks_per_second"] == after["clock_ticks_per_second"], "CPU counter changed")
    admission_ns = sum(row["admission_end_monotonic_ns"] - row["admission_start_monotonic_ns"] for row in batches)
    result = {"label": label, "concurrency": concurrency, "count": count, "all_originals_verified": True,
        "admission_latency": percentiles([row["admission_ms"] for row in rows]),
        "settlement_latency": percentiles([row["settlement_ms"] for row in rows]),
        "admission_window_seconds": admission_ns / 1e9, "admission_receipts_per_admission_window_second": count * 1e9 / admission_ns,
        "full_cell_seconds": (end - start) / 1e9, "verified_async_reads_per_cell_second": count * 1e9 / (end - start),
        "controller_cpu_seconds": cpu_ticks / before["clock_ticks_per_second"],
        "controller_cpu_ms_per_read": 1000 * cpu_ticks / before["clock_ticks_per_second"] / count,
        "raw_timing": {"start_monotonic_ns": start, "end_monotonic_ns": end,
                       "controller_before": before, "controller_after": after},
        "resources_before": sampled_before, "resources_after": sampled_after, "cohorts": batches,
        "raw_rows": [], "idempotency_checks": []}
    payloads = client.directory / "original-results"
    if not payloads.exists():
        payloads.mkdir(mode=0o700)
    for item in rows:
        path = payloads / (item["label"] + ".json")
        bench.create_file(path, item["original_bytes"])
        result["raw_rows"].append({key: value for key, value in item.items() if key not in {"job", "original_bytes"}})
        result["raw_rows"][-1]["original_file"] = str(path)
        result["idempotency_checks"].append(client.idempotency(item))
    # Reject a same-key change to the frozen job identity, without a new dispatch.
    changed = json.loads(json.dumps(rows[0]["arguments"]))
    changed["operation"]["arguments"]["job_id"] = jobs[1]["id"]
    changed["operation"]["arguments"]["host"] = jobs[1]["host"]
    refusal, _ = client.rpc("operation_start", changed, label + "/changed-key-arguments", refuse=True)
    result["changed_arguments_refused"] = refusal
    bench.create_file(client.directory / (label + ".json"), bench.canonical(result))
    client.partial_cell = None
    return result


def closed(bench, controller):
    identity = controller.birth
    pid = controller.child.pid
    value = controller.close()
    try:
        still_original = bench.process_stat(pid)[0] == identity
    except (FileNotFoundError, ProcessLookupError):
        still_original = False
    try:
        os.killpg(pid, 0)
        group_present = True
    except ProcessLookupError:
        group_present = False
    value.update(owned_process_absent=not still_original, owned_process_group_absent=not group_present)
    value["closure_passed"] = (value["exit_code"] == 0 and value["shutdown_method"] == "stdin_eof"
         and not value["observed_descendant_survivors"] and value["reader_error"] is None
         and value["resources"]["sampler_error"] is None and value["unmatched_responses"] == 0
         and value["transport_capture"]["reader_eof"] is True
         and value["owned_process_absent"] and value["owned_process_group_absent"])
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--launcher-sha256", required=True)
    parser.add_argument("--protocol-sha256", required=True)
    args = parser.parse_args()
    need(sys.platform == "linux" and os.geteuid() != 0, "native Linux operator required")
    raw = HELPER.read_bytes()
    need(hashlib.sha256(raw).hexdigest() == HELPER_SHA, "reviewed R36 receipt helper differs")
    parent = types.ModuleType("r36_async_verified_helpers")
    parent.__file__ = str(HELPER)
    exec(compile(raw, str(HELPER), "exec"), parent.__dict__)
    bindings = []
    def bind(path, expected=None, retain=False, maximum=128 * 1024 * 1024):
        result = parent.checked(path, expected, maximum, retain)
        bindings.append(result[0] if retain else result)
        return result
    protocol_id, raw = bind(PROTOCOL, args.protocol_sha256, retain=True)
    protocol = json.loads(raw)
    need(protocol["schema"] == "hepta-r36-async-read-supplement-protocol/v1" and protocol["sealed"] is True
         and protocol["order"] == "ABBA" and protocol["concurrency"] == [1, 8]
         and protocol["warmup_per_cell"] == 12 and protocol["measured_per_cell"] == 24
         and protocol["no_original_gate_changes"] is True and protocol["new_adoption_thresholds"] is None,
         "sealed supplement dimensions differ")
    bind(ROOT / "supplement-tools-01/held_async_read_supplement.py", args.launcher_sha256)
    bind(protocol["runner"]["path"], protocol["runner"])
    bind(HELPER, protocol["helper"])
    _, raw = bind(protocol["qualification_bindings"]["path"], protocol["qualification_bindings"], retain=True)
    proof = parent.bind_r36_candidate_preparation(json.loads(raw), bind)
    need(proof == protocol["qualification_proof"], "qualified source proof changed after sealing")
    for value in [*protocol["binaries"].values(), *protocol["native_tools"].values(),
                  protocol["profile_template"], protocol["topology"], *protocol["frozen_jobs"]]:
        bind(value["path"], value)
    need(not os.path.lexists(OUT) and not os.path.lexists(SOCKETS), "fresh supplement evidence/socket roots required")
    parent.private_directory(OUT, create_new=True)
    parent.private_directory(SOCKETS, create_new=True)
    sys.path.insert(0, str(parent.TOOLS))
    spec = importlib.util.spec_from_file_location("r36_original_native_observation", parent.TOOLS / "x230_observation_benchmark.py")
    bench = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bench)
    need(Path(bench.__file__).resolve() == parent.TOOLS / "x230_observation_benchmark.py", "native Controller import differs")
    for name in ("allocator_environment", "observation_resources"):
        module = sys.modules[name]
        need(Path(module.__file__).resolve() == parent.TOOLS / (name + ".py"), "native dependency import differs")
    jobs = bench.load_jobs(parent.FROZEN_JOBS)
    topology_raw, topology = bench.load_topology(parent.TOPOLOGY, parent.PROFILE)
    bench.create_file(OUT / "topology.json", topology_raw)
    agent = os.environ.get("SSH_AUTH_SOCK", "")
    need(agent.startswith("/"), "original holder's forwarded agent required")
    agent_id = bench.agent_identity(agent)
    profile, profile_proof = bench.fresh_profile(parent.PROFILE, OUT / "profile", SOCKETS, agent)
    report = {"schema": "hepta-r36-async-read-supplement/v1", "passed": False, "correctness_passed": False,
        "started_utc": parent.utc(), "protocol": protocol_id, "protocol_contents": protocol,
        "qualification_proof": proof, "profile": profile_proof, "topology": topology,
        "scope": protocol["scope"], "original_adoption_gates_modified": False, "adoption_passed": None,
        "automatic_retries": 0, "rounds": [], "inputs_unchanged": False}
    monitor = validator = monitor_proof = None
    body_start = time.monotonic_ns()
    active = client = None
    report_path = OUT / "report.json"
    def checkpoint():
        bench.save_report(report_path, report)
    try:
        monitor, validator, monitor_proof = parent.prepare_compiler_monitor(protocol, bind)
        need(monitor.start(), "compiler monitor did not become ready")
        body_start = time.monotonic_ns()
        for _ in range(protocol["quiescence_seconds"]):
            need(not parent.compiler_activity(), "compiler activity before supplement")
            time.sleep(1)
        deadline = time.monotonic() + protocol["workload_budget_seconds"]
        for number, arm in enumerate(protocol["order"]):
            need(time.monotonic() < deadline and bench.agent_identity(agent) == agent_id, "budget or held agent changed")
            directory = OUT / ("round-" + str(number) + "-" + arm)
            config = bench.fixture(directory, jobs, topology)
            first = directory / "first"
            first.mkdir(mode=0o700)
            row = {"index": number, "arm": arm, "cells": [], "passed": False}
            report["rounds"].append(row)
            checkpoint()
            active = bench.Controller(Path(protocol["binaries"][arm]["path"]), config, profile, first,
                protocol["tokio_workers"], allocator_values=bench.allocator.configured(protocol["malloc_arena_max"]))
            row["startup"] = active.startup
            row["preflight"] = []
            for job in jobs:
                for tool in ("process_status", "process_read"):
                    need(time.monotonic() < deadline, "supplement budget exhausted before preflight")
                    checked = active.call(tool, job, "supplement-original-preflight")
                    row["preflight"].append(checked)
                    need(checked["okay"], "original job failed preflight; no later preflight or retry")
            client = Client(bench, active, first, protocol, deadline)
            for concurrency in protocol["concurrency"]:
                cell = {"concurrency": concurrency}
                row["cells"].append(cell)
                for phase, count in (("warmup", 12), ("measured", 24)):
                    label = f"r36ar-r{number}-c{concurrency}-{phase}"
                    cell[phase] = run_cell(client, jobs, concurrency, count, label)
                    checkpoint()
                    print(json.dumps({"round": number, "arm": arm, "concurrency": concurrency,
                        "phase": phase, "verified_reads": count}), flush=True)
            representative = row["cells"][0]["measured"]["raw_rows"][0]["operation_id"]
            row["unique_background_reads"] = len(client.ids)
            need(len(client.ids) == 72, "unique operation execution inventory differs")
            client.close()
            client = None
            row["shutdown"] = closed(bench, active)
            active = None
            need(row["shutdown"]["closure_passed"], "original controller did not close cleanly")
            memory_windows(first, row)
            restart = directory / "owner-check"
            restart.mkdir(mode=0o700)
            need(time.monotonic() < deadline, "supplement budget exhausted before new-owner check")
            active = bench.Controller(Path(protocol["binaries"][arm]["path"]), config, profile, restart,
                protocol["tokio_workers"], allocator_values=bench.allocator.configured(protocol["malloc_arena_max"]))
            client = Client(bench, active, restart, protocol, deadline)
            row["owner_checks"] = [client.rpc(tool, {"operation_id": representative}, "new-stdio-owner", refuse=True)[0]
                                   for tool in ("operation_status", "operation_result")]
            client.close()
            client = None
            row["owner_check_shutdown"] = closed(bench, active)
            active = None
            need(row["owner_check_shutdown"]["closure_passed"], "new owner controller did not close cleanly")
            for job in jobs:
                need(bench.read_file(directory / "state/jobs" / (job["id"] + ".json"), 65536) == job["record_bytes"],
                     "copied original job metadata changed")
            row["passed"] = True
            checkpoint()
        report["summary"] = summarize(report["rounds"])
        need(sum(row["unique_background_reads"] for row in report["rounds"]) == 288,
             "original unique background read inventory differs")
        report["correctness_passed"] = report["passed"] = True
    except BaseException as error:
        report["error"] = {"type": type(error).__name__, "reason": str(error)[:2000]}
        bench.create_file(OUT / "error.txt", traceback.format_exc().encode())
        if client is not None and client.partial_cell is not None:
            partial = {key: value for key, value in client.partial_cell.items() if key != "attempted"}
            partial.update(failed=True, no_samples_retried=True, failure_monotonic_ns=time.monotonic_ns(), attempts=[])
            destination = OUT / "partial-originals"
            destination.mkdir(mode=0o700)
            for item in client.partial_cell["attempted"]:
                kept = {key: value for key, value in item.items() if key not in {"job", "original_bytes"}}
                kept["frozen_job"] = {"host": item["job"]["host"], "job_id": item["job"]["id"]}
                if "original_bytes" in item:
                    path = destination / (item["label"] + ".json")
                    bench.create_file(path, item["original_bytes"])
                    kept["original_file"] = str(path)
                partial["attempts"].append(kept)
            bench.create_file(OUT / "partial-cell.json", bench.canonical(partial))
            report["partial_cell"] = parent.checked(OUT / "partial-cell.json")
    finally:
        if client is not None:
            try:
                client.close()
            except BaseException as error:
                report["client_close_error"] = str(error)[:1000]
        if active is not None:
            try:
                report["interrupted_shutdown"] = closed(bench, active)
            except BaseException as error:
                report["controller_close_error"] = str(error)[:1000]
        try:
            for value in bindings:
                need(parent.checked(value["path"], value) == value, "sealed input changed")
            need(parent.source_inputs(parent.SOURCE)["sha256"] == proof["full_source_inputs_sha256"]
                 and parent.source_inputs(parent.BASELINE_ROOT / "source")["sha256"] == proof["baseline_full_source_inputs_sha256"],
                 "source changed during async supplement")
            need(bench.agent_identity(agent) == agent_id, "held agent changed")
            need(all(bench.read_file(job["path"], 65536) == job["record_bytes"] for job in jobs), "frozen original changed")
            report["inputs_unchanged"] = True
        except BaseException as error:
            report["input_finalization_error"] = str(error)[:1000]
            report["passed"] = report["correctness_passed"] = False
        parent.finish_compiler_monitor(monitor, validator, monitor_proof, body_start,
            time.monotonic_ns(), OUT, report, "correctness_passed")
        report["finished_utc"] = parent.utc()
        checkpoint()
    print(json.dumps({"report": str(report_path), "passed": report["passed"],
                      "adoption_gate": False, "error": report.get("error")}), flush=True)
    return 0 if report["passed"] else 1


def interrupted(number, frame):
    raise InterruptedError(signal.Signals(number).name)


if __name__ == "__main__":
    os.umask(0o077)
    for number in (signal.SIGINT, signal.SIGTERM):
        signal.signal(number, interrupted)
    sys.exit(main())

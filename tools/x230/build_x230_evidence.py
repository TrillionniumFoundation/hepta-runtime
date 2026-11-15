#!/usr/bin/env python3
"""Publish compact, privacy-safe x230 evidence without filtering failed calls.

One input report per invocation; supports observation ABBA, single-B soak,
lifecycle and read-only recovery reports. Output is create-only by default.
"""
import argparse
from collections import Counter
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import sys


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode() + b"\n"


class Sanitizer:
    """Keep evidence shapes and uncertainty; replace private identifiers."""
    private_path = re.compile(r"/(?:home|Users|root|tmp|var/tmp|private|run/user|workspace)(?:/[^\s\"'<>;,}\])]+)?")
    address = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
    ipv6_candidate = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f:.]*(?:%[\w.-]+)?(?![\w:])")
    identity_keys = {"pid", "parent_pid", "birth_ticks", "identity", "execmainpid",
                     "supervisor_pid", "child_pid", "launcher_pid", "main_pid", "mainpid"}
    secret_keys = {"token", "access_token", "refresh_token", "password", "private_key",
                   "known_hosts", "known_hosts_content", "ssh_config", "ssh_auth_sock",
                   "identity_agent", "username", "user", "ssh_target", "controller_hostname"}

    def __init__(self, report):
        serialized = json.dumps(report, ensure_ascii=False)
        self.users = set(re.findall(r"/(?:home|Users)/([^/\s\"'\\]+)", serialized))
        self.users.update(re.findall(r"\b([\w.-]+)@(?:[\w.-]+|\[[^\]]+\])", serialized))
        self.users.discard("user")

    @staticmethod
    def receipt(value):
        return {"redacted": True, "sha256": sha(canonical(value))}

    def string(self, value):
        value = re.sub(r"/proc/\d+(?=/|\b)", "/proc/<pid>", value)
        value = self.private_path.sub(lambda m: "<private-path:" + sha(m[0].encode())[:12] + ">", value)
        value = self.address.sub("<network-address>", value)
        def ipv6(match):
            try:
                ipaddress.IPv6Address(match[0].split("%", 1)[0])
                return "<network-address>"
            except ValueError:
                return match[0]
        value = self.ipv6_candidate.sub(ipv6, value)
        value = re.sub(r"\b[\w.-]+@(?:[\w.-]+\b|\[[^\]]+\])", "<ssh-target>", value)
        value = re.sub(r"(?:ssh-(?:ed25519|rsa)|ecdsa-sha2-\S+)\s+[A-Za-z0-9+/=]+", "<ssh-key-redacted>", value)
        for user in sorted(self.users, key=len, reverse=True):
            value = re.sub(r"(?<![\w.-])" + re.escape(user) + r"(?![\w.-])", "<user>", value)
        return value

    def __call__(self, value):
        if isinstance(value, list):
            return [self(item) for item in value]
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                if key in {"start_monotonic", "start_unix"}:
                    continue
                if key.lower() in self.identity_keys or key.lower() in self.secret_keys:
                    result[key + "_redaction"] = self.receipt(item)
                else:
                    result[self.string(key)] = self(item)
            return result
        return self.string(value) if isinstance(value, str) else value


def numeric(value):
    return type(value) in (float, int) and math.isfinite(value) and value >= 0


def observations(report, key="rounds"):
    return report.get(key, []) if isinstance(report.get(key, []), list) else []


def aggregate(cells, clean):
    rows = [row for cell in cells for row in cell.get("rows", [])]
    count = len(rows)
    successes = sum(row.get("okay") is True for row in rows)
    latency_values = [row.get("elapsed_ms") for row in rows]
    latency_complete = bool(rows) and all(numeric(value) for value in latency_values)
    latency = sorted(latency_values) if latency_complete else []
    seconds_values = [cell.get("seconds") for cell in cells]
    seconds = sum(seconds_values) if cells and all(numeric(value) and value > 0 for value in seconds_values) else None
    cpu_values = [cell.get("controller_cpu_seconds") for cell in cells]
    cpu = sum(cpu_values) if cells and all(numeric(value) for value in cpu_values) else None
    tree_values = [cell.get("sampled_tree_cpu_seconds_delta") for cell in cells]
    tree = sum(tree_values) if cells and all(numeric(value) for value in tree_values) else None
    issues = []
    for index, cell in enumerate(cells):
        if len(cell.get("rows", [])) != cell.get("calls"):
            issues.append({"cell_offset": index, "reason": "declared call count differs from retained rows"})
        if sum(row.get("okay") is True for row in cell.get("rows", [])) != cell.get("successes"):
            issues.append({"cell_offset": index, "reason": "declared successes differ from retained rows"})
    if count and not latency_complete:
        issues.append({"reason": "at least one call latency is missing or invalid; no subset quantile was calculated"})
    if cells and seconds is None:
        issues.append({"reason": "at least one complete cell elapsed duration is missing or invalid"})
    if cells and cpu is None:
        issues.append({"reason": "at least one controller CPU delta is missing or invalid"})
    result = {"cell_count": len(cells), "calls": count, "successes": successes,
              "failures": count - successes, "elapsed_cell_seconds_sum": seconds,
              "completion_rps": count / seconds if seconds else None,
              "successful_rps": successes / seconds if seconds else None,
              "controller_cpu_seconds_sum": cpu,
              "controller_cpu_ms_per_call": cpu * 1000 / count if cpu is not None and count else None,
              "sampled_tree_cpu_seconds_delta_sum": tree, "sampled_tree_cpu_is_lower_bound": True,
              "counts_by_tool": dict(sorted(Counter(row.get("tool", "<missing>") for row in rows).items())),
              "counts_by_host_alias": dict(sorted(Counter(row.get("host", "<missing>") for row in rows).items())),
              "latency_includes_failed_calls": True, "latency_complete": latency_complete,
              "integrity_issues": issues, "errors": [clean(row) for row in rows if row.get("okay") is not True]}
    for percentile in (50, 95, 99):
        result[f"p{percentile}_ms"] = latency[math.ceil(count * percentile / 100) - 1] if latency else None
    result["max_ms"] = max(latency) if latency else None
    return result


def sampling_summary(values, clean):
    values = [value for value in values if isinstance(value, dict)]
    peak_keys = sorted({key for value in values for key in value.get("peaks", {})})
    errors = [error for value in values for error in value.get("errors", [])]
    peaks = {}
    coverage = {}
    for key in peak_keys:
        numbers = [value.get("peaks", {}).get(key) for value in values]
        valid = [number for number in numbers if numeric(number)]
        peaks[key] = max(valid) if valid else None
        coverage[key] = {"controllers_with_sampled_peak": len(valid), "controllers": len(values)}
    return {"controller_count": len(values), "max_of_controller_lifetime_sampled_peaks": peaks,
            "sample_count_sum": sum(value.get("samples", 0) for value in values),
            "recorded_sampling_error_count": len(errors),
            "sampling_error_types": dict(Counter(str(error).split(":", 1)[0] for error in errors)),
            "sampling_errors": [{"type": str(error).split(":", 1)[0], "message": clean(error),
                                 "original_message_sha256": sha(str(error).encode())} for error in errors],
            "sampled_peaks_are_lower_bounds": True, "peak_coverage": coverage,
            "ssh_only_child_peak": None,
            "ssh_only_child_peak_reason": "The sampler records descendant PIDs without executable classification."}


def normal_shutdown(value):
    if not isinstance(value, dict):
        return None
    required = {"exit_code", "shutdown_method", "reader_error", "unmatched_responses", "observed_descendant_survivors"}
    if not required.issubset(value):
        return None
    return (value["exit_code"] == 0 and value["shutdown_method"] == "stdin_eof"
            and value["reader_error"] is None and value["unmatched_responses"] == 0
            and value["observed_descendant_survivors"] == [])


def row_summary(rows):
    return {"calls": len(rows), "successes": sum(row.get("okay") is True for row in rows),
            "failures": sum(row.get("okay") is not True for row in rows),
            "native_is_error_count": sum(row.get("isError") is True or "refusal" in row for row in rows)}


def percentage(candidate, baseline):
    return 100 * (candidate / baseline - 1) if numeric(candidate) and numeric(baseline) and baseline > 0 else None


def summarize_observation(report, names, clean):
    rounds = observations(report)
    order = report.get("order", [])
    order = list(order) if isinstance(order, (str, list)) else []
    expected = Counter(order)
    concurrency = report.get("concurrency", [])
    aggregates, verdicts = {}, {}
    originals = report.get("six_originals", [])
    common = {key: report.get(key) for key in ("source_originals_unchanged", "binary_hashes_unchanged")}
    for code, name in names.items():
        own = [item for item in rounds if item.get("version") == code]
        cells = [cell for item in own for cell in item.get("cells", [])]
        by_concurrency = sorted(set(concurrency) | {cell.get("concurrency") for cell in cells if type(cell.get("concurrency")) is int})
        aggregates[name] = {"by_concurrency": {str(n): aggregate([cell for cell in cells if cell.get("concurrency") == n], clean) for n in by_concurrency},
                            "all_serial_cells": aggregate(cells, clean),
                            "measurement_controller_resources": sampling_summary([item.get("shutdown", {}).get("resources") for item in own], clean),
                            "restart_controller_resources": sampling_summary([item.get("restart_shutdown", {}).get("resources") for item in own], clean)}
        incomplete, failures = [], []
        if len(own) != expected.get(code, 0):
            incomplete.append("observed round count differs from requested order")
        for item in own:
            tag = "round " + str(item.get("index")) + ": "
            if item.get("passed") is not True:
                failures.append(tag + "raw round did not pass")
            if Counter(cell.get("concurrency") for cell in item.get("cells", [])) != Counter(concurrency):
                incomplete.append(tag + "concurrency cells are incomplete or duplicated")
            for cell in item.get("cells", []):
                if len(cell.get("rows", [])) != report.get("calls_per_cell"):
                    incomplete.append(tag + "cell has incomplete requested call count")
                if any(row.get("okay") is not True for row in cell.get("rows", [])):
                    failures.append(tag + "timed call failed")
            for field, size in (("initial_complete_outputs", len(originals)), ("restart_checks", 2 * len(originals))):
                values = item.get(field, [])
                if not originals or len(values) != size:
                    incomplete.append(tag + field + " count differs from original-job count")
                if any(row.get("okay") is not True for row in values):
                    failures.append(tag + field + " contains a failed check")
            for field in ("startup", "restart_startup"):
                if not isinstance(item.get(field), dict):
                    incomplete.append(tag + field + " is missing")
            for field in ("shutdown", "restart_shutdown"):
                result = normal_shutdown(item.get(field))
                if result is None:
                    incomplete.append(tag + field + " receipt is incomplete")
                elif result is not True:
                    failures.append(tag + field + " did not confirm clean EOF shutdown")
        integrity = aggregates[name]["all_serial_cells"]["integrity_issues"]
        if integrity:
            failures.append("retained rows or metric coverage did not pass integrity checks")
        measured = bool(own)
        required = bool(expected.get(code, 0))
        common_pass = all(value is True for value in common.values())
        if measured or required:
            passed = measured and not incomplete and not failures and common_pass
            status = "passed" if passed else "incomplete" if incomplete else "failed"
        else:
            passed, status = None, "not_run"
        verdicts[name] = {"passed": passed, "status": status, "requested_rounds": expected.get(code, 0),
                          "recorded_rounds": len(own), "raw_round_passed": [item.get("passed") for item in own],
                          "common_immutability_fences": common, "incomplete_reasons": incomplete,
                          "failure_reasons": failures, "resource_sampling_errors_are_not_rpc_failures": True}
    measured = [row for item in rounds for cell in item.get("cells", []) for row in cell.get("rows", [])]
    initial = [row for item in rounds for row in item.get("initial_complete_outputs", [])]
    restarted = [row for item in rounds for row in item.get("restart_checks", [])]
    all_rows = measured + initial + restarted
    shutdowns = [item[field] for item in rounds for field in ("shutdown", "restart_shutdown") if isinstance(item.get(field), dict)]
    checks = {"raw_report_passed": report.get("passed"), "rounds": len(rounds),
              "requested_rounds": len(order), "cells": sum(len(item.get("cells", [])) for item in rounds),
              "measured_calls": len(measured), "measured_successes": sum(row.get("okay") is True for row in measured),
              "initial_full_output_checks": len(initial), "initial_full_output_successes": sum(row.get("okay") is True for row in initial),
              "restart_same_job_checks": len(restarted), "restart_same_job_successes": sum(row.get("okay") is True for row in restarted),
              "total_observation_calls": len(all_rows), "total_failed_observations": row_summary(all_rows)["failures"],
              "native_is_error_count": row_summary(all_rows)["native_is_error_count"],
              "normal_controller_restarts": sum(isinstance(item.get("restart_startup"), dict) for item in rounds),
              "controller_shutdowns": len(shutdowns),
              "zero_exit_stdin_eof_shutdowns": sum(item.get("exit_code") == 0 and item.get("shutdown_method") == "stdin_eof" for item in shutdowns),
              "reader_error_count": sum(item.get("reader_error") is not None for item in shutdowns),
              "unmatched_responses": sum(item.get("unmatched_responses", 0) for item in shutdowns),
              "observed_descendant_survivors": sum(len(item.get("observed_descendant_survivors", [])) for item in shutdowns),
              "recorded_resource_sampling_errors": sum(len(item.get("resources", {}).get("errors", [])) for item in shutdowns),
              **common}
    requested_verdicts = [verdicts[names[code]]["passed"] for code in expected if code in names]
    checks["independent_integrity_passed"] = (report.get("passed") is True and bool(requested_verdicts)
        and all(value is True for value in requested_verdicts) and len(rounds) == len(order)
        and all(code in names for code in expected) and all(item.get("version") in names for item in rounds))
    comparison = {}
    if verdicts[names["A"]]["status"] != "not_run" and verdicts[names["B"]]["status"] != "not_run":
        a_cells, b_cells = aggregates[names["A"]]["by_concurrency"], aggregates[names["B"]]["by_concurrency"]
        for key in sorted(a_cells.keys() & b_cells.keys(), key=int):
            a, b = a_cells[key], b_cells[key]
            comparison[key] = {"throughput_change_percent": percentage(b["successful_rps"], a["successful_rps"]),
                               "completion_rps_change_percent": percentage(b["completion_rps"], a["completion_rps"]),
                               "p50_change_percent": percentage(b["p50_ms"], a["p50_ms"]),
                               "p95_change_percent": percentage(b["p95_ms"], a["p95_ms"]),
                               "controller_cpu_per_call_change_percent": percentage(b["controller_cpu_ms_per_call"], a["controller_cpu_ms_per_call"]),
                               "baseline_failures": a["failures"], "candidate_failures": b["failures"]}
    return {"passed": checks["independent_integrity_passed"], "baseline_passed": verdicts[names["A"]]["passed"],
            "candidate_passed": verdicts[names["B"]]["passed"], "version_verdicts": verdicts,
            "verification": checks, "aggregates": aggregates, "candidate_change_vs_baseline": comparison}


def socket_summary(value, clean):
    if not isinstance(value, list):
        return {"observed": False, "artifact_directory_count": None, "socket_entry_count": None, "artifacts": None}
    return {"observed": True, "artifact_directory_count": len(value),
            "socket_entry_count": sum(entry.get("socket") is True for item in value for entry in item.get("entries", [])),
            "artifacts": clean(value), "paths_are_redacted_but_artifacts_are_not_removed": True}


def summarize_recovery(report, clean):
    descendant = report.get("descendant_observation", {})
    final_sockets = socket_summary(report.get("old_socket_artifacts_after_recovery"), clean)
    final = report.get("metadata_final", {})
    return {"passed": report.get("passed"), "read_only_recovery_passed": report.get("read_only_recovery_passed"),
            "abrupt_cleanup_complete": report.get("abrupt_cleanup_complete"),
            "sampled_descendants_all_exited": descendant.get("all_sampled_descendants_exited"),
            "sampled_descendant_remaining_count": len(descendant["remaining"]) if isinstance(descendant.get("remaining"), list) else None,
            "descendant_observation_errors": clean(descendant.get("observation_errors")),
            "sampled_process_observation_is_not_exhaustive_containment_proof": True,
            "sockets_before_death": socket_summary(report.get("socket_artifacts_before_death"), clean),
            "old_sockets_after_death": socket_summary(report.get("old_socket_artifacts_after_death"), clean),
            "old_sockets_after_recovery": final_sockets,
            "zero_old_socket_artifacts_observed": final_sockets["artifact_directory_count"] == 0 if final_sockets["observed"] else None,
            "before_observations": row_summary(report.get("before_checks", [])),
            "after_observations": row_summary(report.get("after_checks", [])),
            "normal_recovery_shutdown_passed": normal_shutdown(report.get("recovery_shutdown")),
            "controller_death_exit_code": report.get("controller_death_exit_code"),
            "binary_hash_unchanged": report.get("binary_hash_unchanged"), "metadata_final": clean(final),
            "resources": sampling_summary([report.get(key, {}).get("resources") for key in ("death_cleanup", "recovery_shutdown", "interrupted_shutdown")], clean),
            "meaning": "Read-only same-job recovery, sampled descendant exit and old socket cleanup are separate outcomes; raw passed does not assert that socket artifacts were removed."}


def summarize_lifecycle(report, clean):
    before, after, reuse = (report.get(key, {}) for key in ("before_crash_status", "first_recovered_status", "same_key_reuse"))
    terminal = report.get("terminal_status", {})
    receipt = report.get("terminal_publication_receipt", {})
    def equality(mapping, key, expected):
        return mapping[key] == expected if key in mapping else None
    return {"passed": report.get("passed"), "phase": report.get("phase"),
            "observations": row_summary(report.get("calls", [])),
            "running_before_owned_controller_death": equality(before, "state", "running"),
            "original_job_running_after_restart": equality(after, "state", "running"),
            "same_key_reused_original_id": (reuse.get("reused") is True and reuse.get("job_id") == report.get("job_id")) if reuse else None,
            "same_key_retried_launch": reuse.get("retried_launch"),
            "original_job_running_during_reuse": equality(reuse.get("status", {}), "state", "running"),
            "release_published": report.get("release_published"), "execution_count": report.get("execution_count"),
            "stdin_bytes": report.get("stdin_bytes"), "stdin_sha256": report.get("stdin_sha256"),
            "terminal_state": terminal.get("state"), "output_complete": terminal.get("output_complete"),
            "output_durable": terminal.get("output_durable"), "terminal_publication_confirmed": terminal.get("terminal_publication_confirmed"),
            "terminal_publication_receipt": clean(receipt) if receipt else None,
            "complete_outputs": clean(report.get("complete_outputs")),
            "normal_recovery_shutdown_passed": normal_shutdown(report.get("shutdown")),
            "binary_unchanged": report.get("binary_unchanged"), "source_record_unchanged": report.get("source_record_unchanged"),
            "current_agent_unchanged": report.get("current_agent_unchanged"),
            "resources": sampling_summary([report.get(key, {}).get("resources") for key in ("intentional_crash", "shutdown", "interrupted_shutdown")], clean),
            "meaning": "This experiment tests whether its release-gated private target job stays running across controller death and same-key reuse; the explicit fields above state what was actually observed. A matching visible publication witness attests to the prior exit synchronization barrier; it is not a power-loss test."}


METHOD = {
    "throughput": "Retained calls or successful calls divided by sum of full cell elapsed seconds; never an average of rates.",
    "latency": "Nearest-rank quantiles over all retained individual calls, including failures. Missing/invalid latencies make quantiles null rather than selecting a subset.",
    "controller_cpu": "Sum of recorded same-controller /proc stat CPU deltas divided by all retained calls; missing coverage makes the aggregate null.",
    "resources": "Sampled local controller/process-tree lifetime peaks; not per-cell or remote-host totals. Tree CPU and peaks are lower bounds. Descendant counts do not identify SSH executables.",
    "failures": "All rows and recorded sampling errors remain in the sanitized report. Raw report verdict and each version verdict are separate.",
    "missing_evidence": "Not run, incomplete, false and null are kept distinct; a single-B run has no baseline comparison.",
}


def build(report, raw, baseline, candidate, kind="auto", label=None, harness=None):
    if baseline == candidate:
        raise ValueError("baseline and candidate names must differ")
    clean = Sanitizer(report)
    schema = report.get("schema", "")
    if kind == "auto":
        kind = "lifecycle" if "lifecycle-canary" in schema else "recovery" if "readonly-recovery" in schema else "observation" if "rounds" in report else None
    if kind is None:
        raise ValueError("unrecognized report schema; select --kind explicitly")
    names = {"A": baseline, "B": candidate}
    summary = (summarize_observation(report, names, clean) if kind == "observation" else
               summarize_lifecycle(report, clean) if kind == "lifecycle" else summarize_recovery(report, clean))
    evidence = {"schema": "hepta-x230-public-evidence/v2", "kind": kind, "label": label,
                "baseline": baseline, "candidate": candidate, "controller_host_alias": "x230",
                "raw_report_passed": report.get("passed"), "raw_report_schema": schema,
                "source_report_sha256": sha(raw), "source_report_bytes": len(raw),
                "aggregation_script_sha256": sha(Path(__file__).read_bytes()),
                "harness_source_sha256": sha(harness.read_bytes()) if harness else None,
                "method": METHOD, **summary, "report": clean(report),
                "limitations": ["A bounded observation is not proof that all optimizations are exhausted.",
                    "Throughput includes host/network effects; order balancing is not a confidence interval.",
                    "Small completed-job output reads do not measure large-stream bandwidth or launch throughput.",
                    "Sampled resources can miss short-lived activity; all recorded sampling errors are retained.",
                    "Controller recovery does not test target reboot, physical power loss, or WAN partition."],
                "privacy": {"redacted": ["private paths and usernames", "network addresses and SSH targets", "SSH key/config content if present", "process identities"],
                    "retained": ["host aliases", "opaque job IDs and hashes", "all call outcomes and cell statistics", "all sampling errors", "uncertainty and socket artifact presence"]}}
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--kind", choices=("auto", "observation", "lifecycle", "recovery"), default="auto")
    parser.add_argument("--label")
    parser.add_argument("--harness", type=Path)
    args = parser.parse_args()
    raw = args.input.read_bytes()
    result = build(json.loads(raw), raw, args.baseline, args.candidate, args.kind, args.label, args.harness)
    serialized = canonical(result)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("xb") as destination:
        destination.write(serialized)
        destination.flush()
        os.fsync(destination.fileno())
    directory = os.open(args.output.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    print(json.dumps({"output": str(args.output), "sha256": sha(serialized), "bytes": len(serialized),
                      "kind": result["kind"], "raw_report_passed": result["raw_report_passed"],
                      "passed": result.get("passed"), "baseline_passed": result.get("baseline_passed"),
                      "candidate_passed": result.get("candidate_passed")}))
    return 0


if __name__ == "__main__":
    sys.exit(main())

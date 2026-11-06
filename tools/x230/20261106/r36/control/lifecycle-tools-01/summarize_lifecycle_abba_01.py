#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Recompute one bounded C6 ABBA from closed raw phase counters and old audits.

No workload, process signaling, network, compilation or automatic retry occurs.
The original per-round auditor runs once in the producer's control sequence.
This tool binds those audit outputs and independently recomputes phase timing.
"""
import argparse
from collections import Counter
import hashlib
import json
import math
import os
from pathlib import Path
import stat
import sys

sys.dont_write_bytecode = True
HOSTS = {"ai395", "mac", "main", "pocket4", "rog", "x230"}
PHASES = ("prepare", "launch", "before_crash_running", "after_transport_running",
          "after_crash_running", "same_key_after_crash", "concurrent_cancel", "terminal",
          "terminal_after_restart", "same_key_after_cancel", "cancel_after_terminal")
GENERATIONS = {
    "launch": ("first-controller", "first_startup"),
    "before_crash_running": ("first-controller", "first_startup"),
    "after_transport_running": ("first-controller", "first_startup"),
    "after_crash_running": ("after-crash-controller", "after_crash_startup"),
    "same_key_after_crash": ("after-crash-controller", "after_crash_startup"),
    "concurrent_cancel": ("after-crash-controller", "after_crash_startup"),
    "terminal": ("after-crash-controller", "after_crash_startup"),
    "terminal_after_restart": ("after-cancel-controller", "after_cancel_startup"),
    "same_key_after_cancel": ("after-cancel-controller", "after_cancel_startup"),
    "cancel_after_terminal": ("after-cancel-controller", "after_cancel_startup"),
}


def need(value, reason):
    if not value:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read(path, maximum=128 * 1024 * 1024):
    path = Path(path)
    need(path.is_absolute() and path.resolve() == path, "noncanonical input path: " + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and 0 <= before.st_size <= maximum, "unsafe/big input: " + str(path))
        with os.fdopen(os.dup(fd), "rb") as stream:
            raw = stream.read(maximum + 1)
        need(len(raw) == before.st_size and stamp(before) == stamp(os.fstat(fd))
             == stamp(path.lstat()), "input changed: " + str(path))
        return raw
    finally:
        os.close(fd)


def fingerprint(path):
    path = Path(path).absolute()
    raw = read(path)
    return {"path": str(path), "bytes": len(raw), "sha256": sha(raw)}


def bound(path, identity):
    raw = read(Path(path).absolute())
    need(type(identity["bytes"]) is int and len(raw) == identity["bytes"]
         and sha(raw) == identity["sha256"], "bound input differs: " + str(path))
    return raw


def create(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def verify_tools(directory, expected_sha):
    directory = Path(directory).absolute()
    manifest_path = directory / "lifecycle-tools-manifest-01.json"
    raw = read(manifest_path, 262144)
    need(sha(raw) == expected_sha, "lifecycle manifest SHA differs")
    manifest = json.loads(raw)
    need(manifest["schema"] == "hepta-r25-lifecycle-tools/v1"
         and isinstance(manifest["files"], dict) and len(manifest["files"]) >= 15,
         "lifecycle manifest schema/set differs")
    for name, identity in sorted(manifest["files"].items()):
        need(Path(name).name == name and name not in {".", "..", "lifecycle-tools-manifest-01.json"},
             "unsafe tool member")
        bound(directory / name, identity)
    return manifest


def counter(value):
    raw = value["raw_stat"]
    left, right = raw.find("("), raw.rfind(") ")
    fields = raw[right + 2:].split()
    need(left > 0 and right > left and len(fields) >= 20 and fields[0] not in {"Z", "X"},
         "malformed/dead raw process counter")
    parsed = {"pid": int(raw[:left].strip()), "comm": raw[left + 1:right],
              "ppid": int(fields[1]), "utime_ticks": int(fields[11]),
              "stime_ticks": int(fields[12]), "birth_ticks": int(fields[19])}
    need(all(value[key] == item for key, item in parsed.items()), "raw process counter fields differ")
    for key in ("pid", "birth_ticks", "clock_ticks_per_second", "read_start_monotonic_ns", "read_end_monotonic_ns"):
        need(type(value[key]) is int and value[key] > 0, "nonpositive process counter field")
    need(value["read_start_monotonic_ns"] <= value["read_end_monotonic_ns"]
         and value["utime_ticks"] >= 0 and value["stime_ticks"] >= 0, "invalid counter interval")
    return value


def phase_metrics(phase, report, expected_phase):
    """Pure raw arithmetic, also used by the local non-workload fixture."""
    need(phase["schema"] == "hepta-r25-lifecycle-phase/v1" and phase["phase"] == expected_phase
         and len(phase["hosts"]) == 6 and set(phase["hosts"]) == HOSTS
         and phase["concurrency"] == 6 and phase["successful_host_count"] == 6
         and phase["failed_hosts"] == [] and phase["measurement_errors"] == [], "incomplete phase")
    start, end = phase["start_monotonic_ns"], phase["end_monotonic_ns"]
    need(type(start) is int and type(end) is int and 0 < start < end, "invalid phase wall interval")
    need(type(phase["start_realtime_ns"]) is int and type(phase["end_realtime_ns"]) is int,
         "missing wall clock endpoints")
    low, high = phase["operation_sequence_before"], phase["operation_sequence_after"]
    need(type(low) is int and type(high) is int and 0 <= low < high, "invalid operation sequence interval")
    native = [r for r in report["native_calls"] if low < r["sequence"] <= high]
    ssh = [r for r in report["ssh_calls"] if low < r["sequence"] <= high]
    sequence = [r["sequence"] for r in native + ssh]
    need(len(sequence) == high - low and set(sequence) == set(range(low + 1, high + 1)),
         "phase operation sequence is incomplete/duplicated")
    need(all(r["phase"] == expected_phase and r["okay"] is True and r["automatic_retry"] is False
             and start <= r["start_monotonic_ns"] <= r["end_monotonic_ns"] <= end for r in native),
         "native call escaped phase clocks or failed")
    need(all(r["okay"] is True and r["automatic_retry"] is False for r in ssh), "SSH helper failed/retried")
    cpu = None
    identity = None
    if expected_phase == "prepare":
        need(all(phase[key] is None for key in ("controller_before", "controller_after", "counter_before", "counter_after"))
             and not native and len(ssh) == 6, "prepare must have no active Controller CPU sample")
    else:
        directory, startup_key = GENERATIONS[expected_phase]
        startup = report[startup_key]
        identity = {"pid": startup["pid"], "birth_ticks": startup["birth_ticks"], "directory": directory}
        need(phase["controller_before"] == phase["controller_after"] == identity,
             "active Controller generation differs")
        before, after = counter(phase["counter_before"]), counter(phase["counter_after"])
        need(before["pid"] == after["pid"] == identity["pid"]
             and before["birth_ticks"] == after["birth_ticks"] == identity["birth_ticks"]
             and before["clock_ticks_per_second"] == after["clock_ticks_per_second"], "CPU generation/clock differs")
        need(before["read_end_monotonic_ns"] <= start < end <= after["read_start_monotonic_ns"],
             "CPU counter samples do not bracket the whole C6 phase")
        need(all(row["controller_directory"] == directory for row in native), "native Controller generation differs")
        ticks = after["utime_ticks"] + after["stime_ticks"] - before["utime_ticks"] - before["stime_ticks"]
        need(ticks >= 0 and native, "negative CPU or empty active phase")
        cpu = ticks / before["clock_ticks_per_second"]
    wall = (end - start) / 1e9
    return {"phase": expected_phase, "wall_seconds": wall, "completed_hosts": 6,
            "hosts_per_second": 6 / wall, "native_calls": len(native), "independent_ssh_calls": len(ssh),
            "native_calls_by_tool": dict(sorted(Counter(r["tool"] for r in native).items())),
            "native_calls_per_second": len(native) / wall,
            "controller_identity": identity, "controller_cpu_seconds": cpu,
            "controller_cpu_ms_per_host": None if cpu is None else 1000 * cpu / 6,
            "controller_cpu_ms_per_native_call": None if cpu is None else 1000 * cpu / len(native),
            "operation_sequence_before": low, "operation_sequence_after": high,
            "raw_counter_interval_brackets_complete_phase": cpu is not None}


def summarize(index_path):
    index_path = Path(index_path).absolute()
    raw_index = read(index_path)
    index = json.loads(raw_index)
    need(index["schema"] == "hepta-r25-lifecycle-round-index/v1" and index["closed"] is True
         and index["order"] == "ABBA" and len(index["rounds"]) == 4, "not a closed four-round index")
    tools = verify_tools(Path(__file__).resolve().parent, index["tools_manifest"]["sha256"])
    rows = []
    for number, arm in enumerate("ABBA"):
        row = index["rounds"][number]
        name = f"round-{number}-{arm}"
        need(row["index"] == number and row["arm"] == arm and row["directory"] == name, "round order/path differs")
        directory = index_path.parent / name
        raw_report = bound(directory / "report.json", row["report"])
        report = json.loads(raw_report)
        raw_audit = bound(directory / "independent-summary.json", row["independent_analysis"])
        audit = json.loads(raw_audit)
        binary_sha = index["baseline" if arm == "A" else "candidate"]["sha256"]
        need(report["schema"] == "hepta-six-host-cancel-recovery/v2" and report["passed"] is True
             and report["candidate_sha256"] == binary_sha
             and report["script_sha256"] == tools["files"]["run_six_host_cancel_recovery_timed.py"]["sha256"]
             and not report.get("phase_measurement_write_errors"), "round producer identity/result differs")
        need(audit["schema"] == "hepta-six-host-cancel-recovery-independent-verification/v2"
             and audit["verified"] is True and audit["candidate_sha256"] == binary_sha
             and audit["source_sha256"] == sha(raw_report) and audit["source_bytes"] == len(raw_report)
             and audit["new_starts"] == 6 and audit["same_key_lookups"] == audit["cancellations"] == 12
             and audit["automatic_rpc_retries"] == report["automatic_rpc_retries"] == 0,
             "original independent audit identity/effect counts differ")
        need(report["transport_interruption"]["requested_host"] == "rog"
             and report["transport_interruption"]["passed"] is True, "ROG transport recovery omitted")
        for label, filename in (("original", "x230_six_running_recovery_canary.py"),
                                ("measurement", "run_native_observation.py"),
                                ("benchmark", "x230_observation_benchmark.py"),
                                ("interruption", "owned_ssh_interruption.py")):
            need(report["helper_hashes"][label] == tools["files"][filename]["sha256"], "original helper differs")
        expected_names = {"phase-" + phase + ".json" for phase in PHASES}
        phase_bindings = {Path(item["path"]).name: item for item in row["phase_files"]}
        need(len(row["phase_files"]) == len(phase_bindings) == 11 and set(phase_bindings) == expected_names
             and {p.name for p in directory.glob("phase-*.json")} == expected_names, "phase file set differs")
        measurements, last = [], 0
        for phase in PHASES:
            filename = "phase-" + phase + ".json"
            value = json.loads(bound(directory / filename, phase_bindings[filename]))
            need(value["operation_sequence_before"] == last, "phase sequence has a gap")
            metrics = phase_metrics(value, report, phase)
            last = value["operation_sequence_after"]
            measurements.append(metrics)
        need(last == len(report["native_calls"]) + len(report["ssh_calls"])
             and len(report["native_calls"]) == audit["native_calls"]
             and len(report["ssh_calls"]) == audit["independent_ssh_calls"], "round call totals differ")
        rows.append({"index": number, "arm": arm, "directory": name, "candidate_sha256": binary_sha,
                     "report_sha256": sha(raw_report), "independent_analysis_sha256": sha(raw_audit),
                     "new_starts": 6, "same_key_lookups": 12, "cancellations": 12,
                     "phase_count": 11, "measured_controller_phase_count": 10,
                     "native_calls": len(report["native_calls"]), "independent_ssh_calls": len(report["ssh_calls"]),
                     "phase_rows": measurements})
    comparisons = []
    for offset, phase in enumerate(PHASES):
        values = [r["phase_rows"][offset] for r in rows]
        item = {"phase": phase, "arm_a_rounds": [0, 3], "arm_b_rounds": [1, 2], "metrics": {}}
        for metric in ("wall_seconds", "hosts_per_second", "controller_cpu_seconds", "controller_cpu_ms_per_native_call"):
            a, b = [values[n][metric] for n in (0, 3)], [values[n][metric] for n in (1, 2)]
            if any(v is None for v in a + b):
                item["metrics"][metric] = {"A": a, "B": b, "B_over_A_mean": None,
                                           "reason": "no active Controller in this phase"}
                continue
            need(all(math.isfinite(v) and v >= 0 for v in a + b), "invalid derived metric")
            average_a, average_b = sum(a) / 2, sum(b) / 2
            item["metrics"][metric] = {"A": a, "B": b, "A_mean": average_a, "B_mean": average_b,
                                       "B_over_A_mean": average_b / average_a if average_a else None,
                                       "adjacent_B_over_A": [b[i] / a[i] if a[i] else None for i in range(2)]}
        comparisons.append(item)
    return {"schema": "hepta-r25-lifecycle-abba-summary/v1", "verified": True,
            "order": "ABBA", "round_count": 4, "total_new_starts": 24,
            "total_same_key_lookups": 48, "total_cancellations": 48,
            "round_index_sha256": sha(raw_index), "tools_manifest_sha256": index["tools_manifest"]["sha256"],
            "rounds": rows, "phase_comparisons": comparisons,
            "scope": {"phase_concurrency": 6, "one_abba_sequence": True, "automatic_retries": 0,
                      "controller_cpu": "same PID/start-ticks raw /proc utime+stime; excludes SSH/remote processes",
                      "phase_wall": "whole six-host phase including confirmations, polling and independent SSH inspections",
                      "cpu_window": "before counter read ends before phase; after read starts after phase",
                      "rss": "original controller/descendant sample traces retained; no new RSS peak estimator",
                      "performance_adoption": "descriptive only; two samples per arm, no significance or maximum-concurrency claim"}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    summary = summarize(args.index)
    create(args.output.absolute(), canonical(summary))
    print(json.dumps({"verified": True, "round_count": 4, "output": str(args.output)}))


if __name__ == "__main__":
    main()

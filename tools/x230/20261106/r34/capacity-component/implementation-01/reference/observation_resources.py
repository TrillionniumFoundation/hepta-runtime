#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Bounded /proc sampling of one private controller and its observed descendants.

CPU is separated by observed process generation and executable class. The trace
retains raw stat lines, selected status fields and FD numbers, never argv or env.
Sampling can miss short-lived/reparented children and is not a cluster CPU bill.
"""
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import threading
import time

INTERVAL = .1
SCOPES = ("controller", "ssh_descendants", "other_descendants",
          "unknown_descendants", "mixed_descendants")


def counters(pid):
    begin = time.monotonic_ns()
    raw = Path(f"/proc/{pid}/stat").read_text()
    end = time.monotonic_ns()
    left, right = raw.find("("), raw.rfind(") ")
    fields = raw[right + 2:].split()
    if left < 0 or right < left or len(fields) < 20:
        raise ValueError("malformed proc stat")
    if fields[0] in {"Z", "X"}:
        raise ProcessLookupError("process ended")
    return {"pid": int(raw[:left].strip()), "comm": raw[left + 1:right],
            "ppid": int(fields[1]), "birth_ticks": int(fields[19]),
            "utime_ticks": int(fields[11]), "stime_ticks": int(fields[12]),
            "clock_ticks_per_second": os.sysconf("SC_CLK_TCK"),
            "read_start_monotonic_ns": begin, "read_end_monotonic_ns": end,
            "raw_stat": raw}


def cpu_seconds(value):
    return (value["utime_ticks"] + value["stime_ticks"]) / value["clock_ticks_per_second"]


def open_new(path):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    return os.fdopen(fd, "wb", buffering=65536)


class Resources:
    def __init__(self, pid, directory, autostart=True):
        self.pid = pid
        self.birth = counters(pid)["birth_ticks"]
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.trace_path = Path(directory) / "resource-samples.jsonl"
        self.trace = open_new(self.trace_path)
        self.trace_digest = hashlib.sha256()
        self.trace_bytes = 0
        self.seen = {}
        self.kinds = {}
        self.samples = 0
        self.metric_samples = Counter()
        self.error_counts = Counter()
        self.errors = []
        self.peaks = {key: 0 for key in ("controller_rss_kib", "controller_hwm_kib",
                                        "controller_fd", "tree_rss_kib", "tree_fd", "descendants")}
        for scope in SCOPES[1:]:
            self.peaks[scope + "_rss_kib"] = 0
            self.peaks[scope + "_fd"] = 0
        self.first_sample_monotonic_ns = None
        self.last_sample_monotonic_ns = None
        self.sampler_error = None
        self.closed = False
        self.started = autostart
        self.thread = threading.Thread(target=self.run, daemon=True)
        if autostart:
            self.thread.start()

    def optional(self, record, stage, pid, callback):
        try:
            return callback()
        except (OSError, ValueError, RuntimeError) as error:
            record["missing"].append({"stage": stage, "pid": pid,
                "type": type(error).__name__,
                "expected_exit_race": isinstance(error, (FileNotFoundError, ProcessLookupError)),
                "reason": str(error)[:160]})
            return None

    def sample(self):
        sample = {"sample": self.samples, "start_monotonic_ns": time.monotonic_ns(),
                  "processes": [], "missing": []}
        # Each discovered PID is bound to its still-observed parent generation.
        pending, visited = [(self.pid, None, None)], set()
        while pending:
            pid, parent, parent_birth = pending.pop()
            if pid in visited:
                continue
            visited.add(pid)
            before = self.optional(sample, "identity_before", pid, lambda: counters(pid))
            if before is None:
                continue
            if pid == self.pid:
                if before["birth_ticks"] != self.birth:
                    sample["missing"].append({"stage": "ownership", "pid": pid,
                        "type": "GenerationMismatch", "expected_exit_race": False})
                    continue
            else:
                owner = self.optional(sample, "parent_identity", parent, lambda: counters(parent))
                if owner is None or owner["birth_ticks"] != parent_birth or before["ppid"] != parent:
                    sample["missing"].append({"stage": "ownership", "pid": pid,
                        "type": "ParentChanged", "expected_exit_race": True})
                    continue
            root = Path("/proc") / str(pid)
            status = self.optional(sample, "status", pid, lambda: dict(
                line.split(":", 1) for line in (root / "status").read_text().splitlines()
                if line.startswith(("VmRSS:", "VmHWM:"))))
            values = {}
            for key in ("VmRSS", "VmHWM"):
                if status is not None and key in status:
                    values[key] = self.optional(sample, key, pid, lambda: int(status[key].split()[0]))
                else:
                    values[key] = None
                    sample["missing"].append({"stage": key, "pid": pid,
                        "type": "UnavailableStatusField", "expected_exit_race": True})
            fds = self.optional(sample, "fd", pid, lambda: sorted(int(p.name) for p in (root / "fd").iterdir()))
            executable = self.optional(sample, "executable", pid, lambda: Path(os.readlink(root / "exe")).name)
            tasks = self.optional(sample, "tasks", pid, lambda: list((root / "task").iterdir()))
            children = []
            for task in tasks or []:
                ids = self.optional(sample, "children", pid, lambda: list(map(int, (task / "children").read_text().split())))
                if ids is not None:
                    children.extend(ids)
            after = self.optional(sample, "identity_after", pid, lambda: counters(pid))
            if after is None or before["birth_ticks"] != after["birth_ticks"] or before["ppid"] != after["ppid"]:
                sample["missing"].append({"stage": "identity_after", "pid": pid,
                    "type": "GenerationOrParentChanged", "expected_exit_race": True})
                continue
            scope = ("controller" if pid == self.pid else "unknown_descendants" if executable is None
                     else "ssh_descendants" if executable.removesuffix(" (deleted)") == "ssh"
                     else "other_descendants")
            sample["processes"].append({"before": before, "after": after, "scope": scope,
                "parent_birth_ticks": parent_birth, "executable_basename": executable,
                "status_fields": status, "rss_kib": values["VmRSS"], "hwm_kib": values["VmHWM"],
                "fd_numbers": fds, "fd_count": None if fds is None else len(fds),
                "children_pids": sorted(set(children))})
            pending.extend((child, pid, before["birth_ticks"]) for child in children)
        sample["end_monotonic_ns"] = time.monotonic_ns()
        encoded = (json.dumps(sample, sort_keys=True, separators=(",", ":")) + "\n").encode()
        with self.lock:
            self.trace.write(encoded)
            self.trace_digest.update(encoded)
            self.trace_bytes += len(encoded)
            self.samples += 1
            self.first_sample_monotonic_ns = self.first_sample_monotonic_ns or sample["start_monotonic_ns"]
            self.last_sample_monotonic_ns = sample["end_monotonic_ns"]
            for missing in sample["missing"]:
                self.error_counts[missing["stage"] + ":" + missing["type"]] += 1
                if len(self.errors) < 16:
                    self.errors.append(missing)
            totals, counts = Counter(), Counter()
            for process in sample["processes"]:
                before, scope = process["before"], process["scope"]
                identity = (before["pid"], before["birth_ticks"])
                self.seen[identity] = max(cpu_seconds(before), self.seen.get(identity, 0))
                previous = self.kinds.get(identity, scope)
                self.kinds[identity] = scope if scope == previous else "mixed_descendants"
                self.metric_samples[scope + "_cpu"] += 1
                for metric, field in (("rss_kib", "rss_kib"), ("fd", "fd_count")):
                    value = process[field]
                    if value is not None:
                        totals[scope + "_" + metric] += value
                        counts[scope + "_" + metric] += 1
                        totals["tree_" + metric] += value
                        counts["tree_" + metric] += 1
                if scope == "controller" and process["hwm_kib"] is not None:
                    totals["controller_hwm_kib"] = process["hwm_kib"]
                    counts["controller_hwm_kib"] = 1
            for key, count in counts.items():
                self.peaks[key] = max(self.peaks.get(key, 0), totals[key])
                self.metric_samples[key] += 1
                self.metric_samples[key + "_process_observations"] += count
            descendants = sum(p["scope"] != "controller" for p in sample["processes"])
            self.peaks["descendants"] = max(self.peaks["descendants"], descendants)

    def run(self):
        try:
            while not self.stop_event.is_set():
                self.sample()
                self.stop_event.wait(INTERVAL)
        except Exception as error:
            self.sampler_error = type(error).__name__ + ": " + str(error)[:200]

    def snapshot(self):
        with self.lock:
            cpu = {scope: 0.0 for scope in SCOPES}
            counts = Counter()
            for identity, seconds in self.seen.items():
                scope = self.kinds[identity]
                cpu[scope] += seconds
                counts[scope] += 1
            return {"samples": self.samples, "peaks": dict(self.peaks),
                "metric_samples": dict(self.metric_samples),
                "sampled_cpu_seconds_by_scope": cpu,
                "sampled_process_generations_by_scope": dict(counts),
                "sampled_tree_cpu_seconds": sum(cpu.values()),
                "sampled_process_generations": len(self.seen),
                "errors": list(self.errors), "error_counts": dict(self.error_counts),
                "first_sample_monotonic_ns": self.first_sample_monotonic_ns,
                "last_sample_monotonic_ns": self.last_sample_monotonic_ns,
                "sampler_error": self.sampler_error, "sample_interval_seconds": INTERVAL,
                "sampled_peaks_and_tree_cpu_are_lower_bounds": False,
                "sampled_tree_cpu_is_partial_lifetime_accumulation": True,
                "sampled_tree_cpu_delta_has_endpoint_error_of_either_sign": True,
                "zero_without_metric_samples_is_unavailable": True,
                "tree_samples_are_not_simultaneous_or_complete": True,
                "limitations": ["Only observed descendants of this controller; no remote/cluster CPU.",
                    "100 ms sampling can miss short-lived or reparented descendants.",
                    "RSS is a non-atomic sum and can double-count shared pages.",
                    "FD failure does not discard other metrics; all missing observations are in the trace.",
                    "SSH classification uses executable basename; generations changing class are mixed.",
                    "Lifetime CPU includes activity before first observation; interval deltas are diagnostic.",
                    "Sampler and transport capture run in the Python harness; their CPU is not controller CPU."]}

    def stop(self):
        self.stop_event.set()
        if self.started:
            self.thread.join(5)
            if self.thread.is_alive():
                raise RuntimeError("resource sampler did not stop")
        if not self.closed:
            self.trace.flush()
            os.fsync(self.trace.fileno())
            self.trace.close()
            self.closed = True
        value = self.snapshot()
        value["trace"] = {"file": self.trace_path.name, "bytes": self.trace_bytes,
                          "sha256": self.trace_digest.hexdigest(), "records": self.samples}
        return value

#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""R12 read-only ABBA using the established native MCP controller and fixtures.

Every concurrency cell gets the same balanced status/read warmup before timing.
A failed FD observation does not discard separately readable RSS/CPU data or
prevent descendant discovery. Sampling remains incomplete and is never used as
the controller CPU numerator, which the original driver measures synchronously.
Only this file's private controllers are observed; no runtime policy is changed.
"""
import argparse
from collections import Counter
import hashlib
from pathlib import Path
import sys
import threading

sys.dont_write_bytecode = True
HELPER = Path(__file__).resolve().parent.parent / "recovery" / "x230_observation_benchmark.py"
sys.path.insert(0, str(HELPER.parent))
import x230_observation_benchmark as bench

INTERVAL = .1
WARMUP_CALLS = 24
ORIGINAL_CELL = bench.cell
ORIGINAL_SAVE = bench.save_report
SCRIPT_HASHES = {"wrapper": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                 "helper": hashlib.sha256(HELPER.read_bytes()).hexdigest()}


class Resources:
    """Independent process metrics; missing observations stay explicitly counted."""
    def __init__(self, pid, autostart=True):
        self.pid = pid
        self.birth = bench.process_stat(pid)[0]
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.peaks = {key: 0 for key in (
            "controller_rss_kib", "tree_rss_kib", "controller_fd", "tree_fd",
            "descendants", "controller_hwm_kib")}
        self.seen = {}
        self.samples = 0
        self.metric_samples = Counter()
        self.error_counts = Counter()
        self.errors = []
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.started = autostart
        if autostart:
            self.thread.start()

    def error(self, metric, pid, error):
        # Ended processes are normal when sampling a live tree. Permission or
        # parsing failures are retained without suppressing unrelated metrics.
        if isinstance(error, (FileNotFoundError, ProcessLookupError)):
            return
        with self.lock:
            self.error_counts[metric + ":" + type(error).__name__] += 1
            if len(self.errors) < 12:
                self.errors.append({"metric": metric, "pid": pid,
                                    "type": type(error).__name__, "reason": str(error)[:200]})

    def optional(self, metric, pid, callback):
        try:
            return callback()
        except (OSError, ValueError, RuntimeError) as error:
            self.error(metric, pid, error)
            return None

    def sample(self):
        pending, visited = [self.pid], set()
        totals = {"rss": 0, "fd": 0}
        counts = {"rss": 0, "fd": 0, "process": 0}
        while pending:
            pid = pending.pop()
            if pid in visited:
                continue
            visited.add(pid)
            before = self.optional("identity", pid, lambda: bench.process_stat(pid))
            if before is None:
                continue
            born, cpu = before
            if pid == self.pid and born != self.birth:
                self.error("identity", pid, RuntimeError("controller PID generation changed"))
                continue
            root = Path("/proc") / str(pid)
            status = self.optional("status", pid, lambda: dict(
                line.split(":", 1) for line in (root / "status").read_text().splitlines()
                if ":" in line))
            rss = hwm = None
            if status is not None:
                rss = self.optional("rss", pid, lambda: int(status["VmRSS"].split()[0])
                                    if "VmRSS" in status else None)
                hwm = self.optional("hwm", pid, lambda: int(status["VmHWM"].split()[0])
                                    if "VmHWM" in status else None)
            fd = self.optional("fd", pid, lambda: len(list((root / "fd").iterdir())))
            tasks = self.optional("tasks", pid, lambda: list((root / "task").iterdir()))
            children = []
            if tasks is not None:
                for task in tasks:
                    values = self.optional("children", pid, lambda: list(
                        map(int, (task / "children").read_text().split())))
                    if values is not None:
                        children.extend(values)
            after = self.optional("identity", pid, lambda: bench.process_stat(pid))
            if after is None or after[0] != born:
                continue
            pending.extend(children)
            with self.lock:
                self.seen[(pid, born)] = max(cpu, self.seen.get((pid, born), 0))
                self.metric_samples["process_cpu"] += 1
                if pid == self.pid:
                    for key, value in (("controller_rss_kib", rss),
                                       ("controller_hwm_kib", hwm), ("controller_fd", fd)):
                        if value is not None:
                            self.peaks[key] = max(self.peaks[key], value)
                            self.metric_samples[key] += 1
            counts["process"] += 1
            for key, value in (("rss", rss), ("fd", fd)):
                if value is not None:
                    totals[key] += value
                    counts[key] += 1
        with self.lock:
            self.samples += 1
            self.peaks["descendants"] = max(self.peaks["descendants"], max(0, counts["process"] - 1))
            for key in ("rss", "fd"):
                if counts[key]:
                    metric = "tree_rss_kib" if key == "rss" else "tree_fd"
                    self.peaks[metric] = max(self.peaks[metric], totals[key])
                    self.metric_samples[metric] += 1
                    self.metric_samples[metric + "_process_observations"] += counts[key]

    def run(self):
        while not self.stop_event.is_set():
            try:
                self.sample()
            except Exception as error:
                self.error("sampler", self.pid, error)
            self.stop_event.wait(INTERVAL)

    def snapshot(self):
        with self.lock:
            return {"samples": self.samples, "peaks": dict(self.peaks),
                    "metric_samples": dict(self.metric_samples),
                    "sampled_tree_cpu_seconds": sum(self.seen.values()),
                    "sampled_process_generations": len(self.seen),
                    "errors": list(self.errors), "error_counts": dict(self.error_counts),
                    "sample_interval_seconds": INTERVAL,
                    "sampled_peaks_and_tree_cpu_are_lower_bounds": False,
                    "controller_rss_peak_is_sampled_lower_bound": True,
                    "tree_rss_and_fd_are_nonatomic_sample_sums": True,
                    "sampled_tree_cpu_is_partial_lifetime_accumulation": True,
                    "missing_metrics_do_not_discard_other_metrics": True,
                    "zero_without_metric_samples_is_unavailable": True,
                    "tree_samples_are_not_simultaneous_or_complete": True,
                    "sampled_tree_cpu_delta_has_endpoint_error_of_either_sign": True}

    def stop(self):
        self.stop_event.set()
        if self.started:
            self.thread.join(5)
        return self.snapshot()


def cell(controller, jobs, concurrency, count):
    warmup = ORIGINAL_CELL(controller, jobs, concurrency, WARMUP_CALLS)
    bench.need(warmup["successes"] == warmup["calls"], "balanced cell warmup failed")
    result = ORIGINAL_CELL(controller, jobs, concurrency, count)
    result["warmup"] = warmup
    # The retained raw samples are diagnostic only. Subtracting asynchronous
    # lower-bound counters does not create a lower-bound interval estimate.
    for row in (result, warmup):
        row["sampled_tree_cpu_seconds_delta_is_lower_bound"] = False
        row["sampled_tree_cpu_seconds_delta_is_performance_numerator"] = False
    return result


def save_report(path, report):
    unchanged = (hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == SCRIPT_HASHES["wrapper"]
                 and hashlib.sha256(HELPER.read_bytes()).hexdigest() == SCRIPT_HASHES["helper"])
    report["r12_measurement"] = {
        "wrapper_sha256": SCRIPT_HASHES["wrapper"],
        "helper_sha256": SCRIPT_HASHES["helper"],
        "scripts_unchanged": unchanged,
        "balanced_warmup_calls_per_cell": WARMUP_CALLS,
        "warmup_included_in_performance_denominator": False,
        "sampler_version": "independent-metric-errors/v1",
        "cpu_numerator": "same controller PID/start ticks synchronous utime+stime delta",
        "sampled_tree_cpu_used_for_performance": False,
    }
    if not unchanged:
        report["passed"] = False
    ORIGINAL_SAVE(path, report)


def main():
    global WARMUP_CALLS
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--warmup-calls", type=int, default=24)
    args, remaining = parser.parse_known_args()
    bench.need(12 <= args.warmup_calls <= 120 and args.warmup_calls % 12 == 0,
               "warmup must be a balanced multiple of 12 from 12 to 120")
    WARMUP_CALLS = args.warmup_calls
    bench.Resources = Resources
    bench.cell = cell
    bench.save_report = save_report
    sys.argv = [sys.argv[0], *remaining]
    return bench.main()


if __name__ == "__main__":
    sys.exit(main())

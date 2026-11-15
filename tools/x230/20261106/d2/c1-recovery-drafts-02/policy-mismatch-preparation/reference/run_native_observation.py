#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""R16 read-only ABBA with matched allocator, raw transport, clocks and resources.

Every concurrency cell gets the same balanced status/read warmup before timing.
A failed FD observation does not discard separately readable RSS/CPU data or
prevent descendant discovery. Sampling remains incomplete and is never used as
the controller CPU numerator, which the original driver measures synchronously.
Only this file's private controllers are observed; no runtime policy is changed.
"""
import argparse
import hashlib
from pathlib import Path
import sys

sys.dont_write_bytecode = True
HELPER = Path(__file__).resolve().parent / "x230_observation_benchmark.py"
sys.path.insert(0, str(HELPER.parent))
import x230_observation_benchmark as bench

WARMUP_CALLS = 24
ORIGINAL_CELL = bench.cell
ORIGINAL_SAVE = bench.save_report
SCRIPT_PATHS = {"wrapper": Path(__file__), "helper": HELPER,
                "resources": HELPER.with_name("observation_resources.py"),
                "allocator": HELPER.with_name("allocator_environment.py")}
SCRIPT_HASHES = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in SCRIPT_PATHS.items()}



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
    unchanged = all(hashlib.sha256(source.read_bytes()).hexdigest() == SCRIPT_HASHES[name]
                    for name, source in SCRIPT_PATHS.items())
    report["r16_measurement"] = {
        "wrapper_sha256": SCRIPT_HASHES["wrapper"],
        "helper_sha256": SCRIPT_HASHES["helper"],
        "script_sha256": SCRIPT_HASHES,
        "scripts_unchanged": unchanged,
        "balanced_warmup_calls_per_cell": WARMUP_CALLS,
        "warmup_included_in_performance_denominator": False,
        "sampler_version": "owned-generation-trace/v1",
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
    bench.cell = cell
    bench.save_report = save_report
    sys.argv = [sys.argv[0], *remaining]
    return bench.main()


if __name__ == "__main__":
    sys.exit(main())


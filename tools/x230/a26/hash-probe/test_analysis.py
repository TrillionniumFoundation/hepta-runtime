#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Pure synthetic classifier checks; never executes the Rust probe or a compiler."""
import copy
import json

from summarize_hash_probe import HEADER, summarize


PIN = {"dev": 1, "ino": 2, "uid": 0, "mode": 0o100755, "nlink": 1,
       "len": 1024, "mtime": [1, 2], "ctime": [1, 2]}
SHA = "a" * 64


def evidence(cpu_b=96000, wall_b=96000):
    rows = [copy.deepcopy(HEADER), {"event": "reference", "stamp": copy.deepcopy(PIN),
            "sha256": SHA, "bytes": 1024, "read_calls": 2, "interrupted_reads": 0}]
    for offset in range(34):
        warm = offset < 2
        ordinal = offset if warm else offset - 2
        slot = "AB"[ordinal] if warm else "ABBA"[ordinal % 4]
        count = 8 if warm else 128
        cpu, wall = (100000, 100000) if slot == "A" else (cpu_b, wall_b)
        iterations = [{"index": index, "before_fd": copy.deepcopy(PIN),
                       "after_fd": copy.deepcopy(PIN), "after_path": copy.deepcopy(PIN),
                       "read_hash_wall_ns": wall, "read_hash_thread_cpu_ns": cpu,
                       "read": {"bytes": 1024, "read_calls": 2, "interrupted_reads": 0,
                                "sha256": SHA, "failure": None}, "verified": True, "failure": None}
                      for index in range(count)]
        rows.append({"event": "cell", "phase": "warmup" if warm else "measured",
                     "block": None if warm else ordinal // 4, "slot": slot, "ordinal": ordinal,
                     "buffer_bytes": HEADER["variants"][slot], "requested_iterations": count,
                     "completed_iterations": count, "passed": True,
                     "read_hash_thread_cpu_ns": cpu * count, "read_hash_wall_ns": wall * count,
                     "whole_cell_wall_ns": wall * count + 10000, "iterations": iterations})
    rows.append({"event": "complete", "passed": True, "measured_cells": 32,
                 "measured_full_file_hashes": 4096, "warmup_cells": 2, "warmup_full_file_hashes": 16,
                 "final_stamp": copy.deepcopy(PIN), "reference_sha256": SHA})
    return rows


def apply(rows, code=0, expected=SHA):
    raw = b"".join(json.dumps(row).encode() + b"\n" for row in rows)
    return summarize(raw, code, expected)


def main():
    checks = []

    def check(name, result, valid, eligible):
        assert result["valid_complete_experiment"] is valid, (name, result["errors"])
        assert result["eligible_for_separate_runtime_candidate"] is eligible, name
        checks.append(name)

    good = evidence()
    check("complete_pass", apply(good), True, True)
    check("threshold_equality", apply(evidence(97000, 102000)), True, True)
    check("small_gain_rejected", apply(evidence(98000)), True, False)
    check("wall_regression_rejected", apply(evidence(96000, 103000)), True, False)
    check("missing_cell_rejected", apply(good[:-2] + good[-1:]), False, False)
    check("failed_exit_rejected", apply(good, 1), False, False)
    check("independent_hash_mismatch_rejected", apply(good, 0, "b" * 64), False, False)
    changed = copy.deepcopy(good)
    changed[4]["iterations"][0]["read"]["sha256"] = "b" * 64
    check("digest_mismatch_rejected", apply(changed), False, False)
    changed = copy.deepcopy(good)
    changed[4]["iterations"][0]["after_fd"]["ino"] = 4
    check("stamp_change_rejected", apply(changed), False, False)
    changed = copy.deepcopy(good)
    changed[4]["read_hash_thread_cpu_ns"] += 1
    check("cpu_sum_mismatch_rejected", apply(changed), False, False)
    changed = copy.deepcopy(good)
    changed[4]["iterations"][0]["read"]["failure"] = {"stage": "read", "errno": 5}
    check("nested_read_failure_rejected", apply(changed), False, False)
    for percentages, name in (([5, 5, 5, 5, 5, 5, 0, 0], "fewer_than_7_blocks_rejected"),
                              ([1, 6, 1, 6, 1, 6, 1, 6], "MAD_noise_rejected")):
        changed = copy.deepcopy(good)
        for block, percent in enumerate(percentages):
            for offset in (1, 2):
                cell = changed[4 + block * 4 + offset]
                cpu = int(100000 * (1 - percent / 100))
                cell["read_hash_thread_cpu_ns"] = cpu * 128
                for iteration in cell["iterations"]:
                    iteration["read_hash_thread_cpu_ns"] = cpu
        check(name, apply(changed), True, False)
    print(json.dumps({"synthetic_checks": checks, "count": len(checks),
                      "rust_compiled": False, "probe_executed": False}))


if __name__ == "__main__":
    main()

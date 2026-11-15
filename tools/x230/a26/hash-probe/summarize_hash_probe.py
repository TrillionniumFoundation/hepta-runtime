#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Validate every retained hash-probe receipt and apply the frozen decision rule."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import statistics
import sys

from prepare_hash_probe import receipt, write_new


HEADER = {
    "event": "plan", "schema": "hepta-x230-full-file-hash-microprobe/v1",
    "target": "/usr/bin/ssh", "maximum_file_bytes": 16777216,
    "variants": {"A": 16384, "B": 65536}, "reference_reads": 1,
    "warmup_order": "AB", "warmup_iterations_per_cell": 8, "blocks": 8,
    "order_per_block": "ABBA", "iterations_per_cell": 128,
    "measured_cells": 32, "measured_full_file_hashes": 4096,
}


def integer(value, minimum=0):
    return type(value) is int and value >= minimum


def summarize(raw, exit_code, expected_sha256):
    out = {"schema": "hepta-x230-full-file-hash-microprobe-analysis/v1",
           "raw_jsonl_sha256": hashlib.sha256(raw).hexdigest(), "raw_jsonl_bytes": len(raw),
           "process_exit_code": exit_code, "expected_target_sha256": expected_sha256,
           "valid_complete_experiment": False, "eligible_for_separate_runtime_candidate": False,
           "runtime_performance_conclusion": None, "decision": "no decision: incomplete or invalid experiment",
           "errors": [], "blocks": [], "no_success_filtering": True}
    errors, records = out["errors"], []

    def check(value, message):
        if not value:
            errors.append(message)
        return bool(value)

    check(type(exit_code) is int and exit_code == 0, "probe did not exit successfully")
    check(isinstance(expected_sha256, str) and re.fullmatch("[0-9a-f]{64}", expected_sha256) is not None,
          "independent complete-file SHA256 is missing")
    for number, line in enumerate(raw.splitlines(), 1):
        try:
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError("object expected")
            records.append(row)
        except (ValueError, UnicodeError) as error:
            errors.append("JSONL line " + str(number) + ": " + str(error))
    out["parsed_event_count"] = len(records)
    out["failure_events"] = [row for row in records if row.get("event") == "failure"]
    out["observed_cells"] = [{key: row.get(key) for key in
        ("phase", "block", "slot", "ordinal", "requested_iterations", "completed_iterations", "passed")}
        for row in records if row.get("event") == "cell"]
    expected_events = ["plan", "reference", *(["cell"] * 34), "complete"]
    check([row.get("event") for row in records] == expected_events,
          "event sequence is not exactly reference, two warmup cells, 32 measured cells, completion")
    if len(records) != len(expected_events):
        return out
    check(records[0] == HEADER, "fixed probe plan differs")
    reference = records[1]
    pin = reference.get("stamp")
    digest = reference.get("sha256")
    check(reference.get("event") == "reference" and digest == expected_sha256,
          "reference digest differs from independent target hash")
    check(isinstance(pin, dict) and set(pin) == {"dev", "ino", "uid", "mode", "nlink", "len", "mtime", "ctime"},
          "reference stamp is incomplete")
    if not isinstance(pin, dict):
        return out
    check(integer(pin.get("len"), 1) and pin["len"] <= 16777216
          and reference.get("bytes") == pin["len"], "reference byte bound or complete length differs")
    check(pin.get("uid") == 0 and pin.get("nlink") == 1 and integer(pin.get("mode"))
          and pin["mode"] & 0o6022 == 0 and pin["mode"] & 0o111 != 0, "reference inode policy differs")
    cells = records[2:-1]
    for offset, cell in enumerate(cells):
        warmup = offset < 2
        ordinal = offset if warmup else offset - 2
        block = None if warmup else ordinal // 4
        slot = "AB"[ordinal] if warmup else "ABBA"[ordinal % 4]
        count = 8 if warmup else 128
        label = ("warmup " if warmup else "measured ") + str(ordinal)
        check(cell.get("event") == "cell" and cell.get("phase") == ("warmup" if warmup else "measured")
              and cell.get("ordinal") == ordinal and cell.get("block") == block and cell.get("slot") == slot
              and cell.get("buffer_bytes") == HEADER["variants"][slot], label + " identity or order differs")
        check(cell.get("requested_iterations") == count and cell.get("completed_iterations") == count
              and cell.get("passed") is True, label + " did not complete all iterations")
        iterations = cell.get("iterations")
        if not check(isinstance(iterations, list) and len(iterations) == count, label + " iteration set differs"):
            continue
        cpu_values, wall_values = [], []
        for index, iteration in enumerate(iterations):
            if not check(isinstance(iteration, dict), label + " invalid iteration"):
                continue
            prefix = label + " iteration " + str(index)
            check(iteration.get("index") == index and iteration.get("verified") is True
                  and iteration.get("failure") is None, prefix + " failed or wrong index")
            check(all(iteration.get(key) == pin for key in ("before_fd", "after_fd", "after_path")),
                  prefix + " original fd/path stamp changed")
            read = iteration.get("read")
            check(isinstance(read, dict) and read.get("bytes") == pin.get("len")
                  and read.get("sha256") == digest and read.get("failure") is None
                  and integer(read.get("read_calls"), 1) and integer(read.get("interrupted_reads"))
                  and read["interrupted_reads"] < read["read_calls"], prefix + " complete read/hash differs")
            cpu, wall = iteration.get("read_hash_thread_cpu_ns"), iteration.get("read_hash_wall_ns")
            if check(integer(cpu, 1) and integer(wall, 1), prefix + " timing missing or nonpositive"):
                cpu_values.append(cpu)
                wall_values.append(wall)
        check(len(cpu_values) == count and cell.get("read_hash_thread_cpu_ns") == sum(cpu_values),
              label + " CPU total differs from all raw iterations")
        check(len(wall_values) == count and cell.get("read_hash_wall_ns") == sum(wall_values),
              label + " wall total differs from all raw iterations")
        check(integer(cell.get("whole_cell_wall_ns"), 1)
              and cell["whole_cell_wall_ns"] >= sum(wall_values), label + " whole-cell wall is inconsistent")
    final = records[-1]
    check(final == {"event": "complete", "passed": True, "measured_cells": 32,
                   "measured_full_file_hashes": 4096, "warmup_cells": 2, "warmup_full_file_hashes": 16,
                   "final_stamp": pin, "reference_sha256": digest}, "completion receipt differs")
    if errors:
        return out
    measured = cells[2:]
    for block in range(8):
        values = measured[block * 4:(block + 1) * 4]
        pair = {"block": block, "cell_ordinals": [row["ordinal"] for row in values]}
        for key, metric in (("read_hash_thread_cpu_ns", "cpu"), ("read_hash_wall_ns", "wall")):
            a = (values[0][key] + values[3][key]) / 2
            b = (values[1][key] + values[2][key]) / 2
            pair[metric + "_A_mean_ns"] = a
            pair[metric + "_B_mean_ns"] = b
            pair[metric + "_improvement_percent"] = 100 * (a - b) / a
        out["blocks"].append(pair)
    cpu = [row["cpu_improvement_percent"] for row in out["blocks"]]
    median = statistics.median(cpu)
    mad = statistics.median(abs(value - median) for value in cpu)
    wall = statistics.median(row["wall_improvement_percent"] for row in out["blocks"])
    gates = {"median_cpu_improvement_at_least_3_percent": median >= 3,
             "at_least_7_blocks_cpu_improve": sum(value > 0 for value in cpu) >= 7,
             "median_cpu_improvement_strictly_exceeds_2_MAD": median > 2 * mad,
             "median_wall_regression_at_most_2_percent": wall >= -2}
    eligible = all(gates.values())
    out.update(valid_complete_experiment=True, eligible_for_separate_runtime_candidate=eligible,
               decision="eligible for a separately qualified runtime candidate" if eligible else "keep the current 16 KiB buffer",
               median_paired_cpu_improvement_percent=median, paired_cpu_improvement_MAD_percent=mad,
               median_paired_wall_improvement_percent=wall,
               positive_cpu_blocks=sum(value > 0 for value in cpu), gates=gates)
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-jsonl", type=Path, required=True)
    parser.add_argument("--exit-code", type=int, required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    args.output_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    source, raw = receipt(args.raw_jsonl.absolute(), True)
    write_new(args.output_dir / "raw.jsonl", raw)
    result = summarize(raw, args.exit_code, args.expected_sha256)
    result["source"] = source
    result["analyzer_sha256"] = receipt(Path(__file__))['sha256']
    write_new(args.output_dir / "analysis.json", (json.dumps(result, indent=2, sort_keys=True) + "\n").encode())
    print(json.dumps({"analysis": str(args.output_dir / "analysis.json"),
                      "valid_complete_experiment": result["valid_complete_experiment"],
                      "eligible_for_separate_runtime_candidate": result["eligible_for_separate_runtime_candidate"]}))
    return 0 if result["valid_complete_experiment"] else 1


if __name__ == "__main__":
    sys.exit(main())

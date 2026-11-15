#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Recompute the fixed CString CPU gates from public rows, without a workload."""
import argparse
import gzip
import hashlib
import json
import math
from pathlib import Path
import statistics

RUN_SHA = "29dbfcb249c66c6b69237be51bd0ae10bcd9dbabd8c0a964b7391b5b9ed35b09"
ANALYSIS_SHA = "65aabcf7d03573ab4b56bffb1d42e99098608397a36eb138398056f068344b91"
METRICS = ("process_cpu_ns", "owner_thread_cpu_ns", "wall_ns")


def need(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    root = Path(__file__).resolve().parents[3]
    default = root / "docs/evidence/x230-a27-followup/prepared-path"
    parser.add_argument("--public-run", type=Path, default=default / "run-r02.complete.sanitized.json.gz")
    parser.add_argument("--public-analysis", type=Path, default=default / "analysis-r02.complete.sanitized.json")
    parser.add_argument("--output", type=Path, help="Fresh receipt path; otherwise print the receipt")
    args = parser.parse_args()
    compressed, raw_analysis = args.public_run.read_bytes(), args.public_analysis.read_bytes()
    sha = lambda value: hashlib.sha256(value).hexdigest()
    need(sha(compressed) == RUN_SHA and sha(raw_analysis) == ANALYSIS_SHA, "fixed public inputs differ")
    raw = gzip.decompress(compressed)
    run, analysis = json.loads(raw), json.loads(raw_analysis)
    need(run["completed"] is True and run["error"] is None and run["retries"] == 0, "reported completion differs")
    need(run["inputs_unchanged"] is True and run["binaries_unchanged"] is True, "reported fences differ")
    need(analysis["valid_complete_experiment"] is True and analysis["eligible_for_runtime_candidate"] is False,
         "reported decision differs")
    cells = run["cells"]
    need(len(cells) == 32 and len(run["semantics"]) == 2, "complete public cell/preflight set required")
    for arm, child in zip("AB", run["semantics"]):
        record = child["record"]
        need(child["variant"] == record["variant"] == arm and child["returncode"] == 0
             and child["stderr_bytes"] == 0 and record["passed"] is True, "semantic outcome differs")
        need(len(record["checks"]) == 17 and len({r["case"] for r in record["checks"]}) == 17,
             "semantic cases omitted or duplicated")
        need(all(any(r.get(k) is True for k in ("passed", "rejected", "lexically_rejected"))
                 for r in record["checks"]), "semantic failure")
    need(run["semantics"][0]["record"]["checks"] == run["semantics"][1]["record"]["checks"],
         "public semantic cases differ between arms")
    totals = []
    for sequence, cell in enumerate(cells):
        need((cell["sequence"], cell["block"], cell["position"], cell["variant"]) ==
             (sequence, sequence // 4, sequence % 4, "ABBA"[sequence % 4]), "fixed ABBA order differs")
        record = cell["record"]
        need(cell["returncode"] == 0 and cell["stderr_bytes"] == 0 and record["passed"] is True,
             "failed or incomplete cell")
        need(record["worker_drain_succeeded"] is True and record["agent_requests"] == 69,
             "reported worker/agent accounting differs")
        rows = record["rows"]
        phases = [("warmup", i) for i in range(4)] + [("measured", i) for i in range(64)]
        need([(r["phase"], r["index"]) for r in rows] == phases, "missing, duplicated or reordered row")
        for row in rows:
            need(row["attempted"] is True and row["passed"] is True and row["stop_cancelled"] is False
                 and row["clock_error"] is None and row["validation_error"] is None, "row failure")
            need(all(type(row[m]) is int and row[m] > 0 for m in METRICS), "invalid timing value")
        value = {m: sum(r[m] for r in rows if r["phase"] == "measured") for m in METRICS}
        totals.append(value)
        need(all(analysis["cell_totals"][sequence][m] == value[m] for m in METRICS), "cell total differs")
    summaries = {}
    for metric in METRICS:
        gains = []
        for block in range(8):
            group = totals[block * 4:block * 4 + 4]
            a, b = group[0][metric] + group[3][metric], group[1][metric] + group[2][metric]
            gain = 100 * (a - b) / a
            gains.append(gain)
            expected = analysis["blocks"][block]["metrics"][metric]
            need(expected["A_ns_per_operation"] == a / 128 and expected["B_ns_per_operation"] == b / 128
                 and math.isclose(expected["improvement_percent"], gain, abs_tol=1e-12), "block arithmetic differs")
        median = statistics.median(gains)
        mad = statistics.median(abs(v - median) for v in gains)
        actual = {"paired_improvements_percent": gains, "median_improvement_percent": median,
                  "median_absolute_deviation_percent": mad, "positive_blocks": sum(v > 0 for v in gains)}
        expected = analysis["summaries"][metric]
        need(actual["positive_blocks"] == expected["positive_blocks"], "positive block count differs")
        for key in ("median_improvement_percent", "median_absolute_deviation_percent"):
            need(math.isclose(actual[key], expected[key], abs_tol=1e-12), "summary arithmetic differs")
        need(all(math.isclose(a, b, abs_tol=1e-12) for a, b in zip(gains, expected["paired_improvements_percent"])),
             "paired improvement vector differs")
        summaries[metric] = actual
    cpu, wall = summaries["process_cpu_ns"], summaries["wall_ns"]
    gates = {"median_process_cpu_at_least_3_percent": cpu["median_improvement_percent"] >= 3,
             "at_least_7_of_8_process_cpu_blocks_improve": cpu["positive_blocks"] >= 7,
             "median_process_cpu_strictly_above_2_mad": cpu["median_improvement_percent"] > 2 * cpu["median_absolute_deviation_percent"],
             "median_wall_regression_at_most_2_percent": wall["median_improvement_percent"] >= -2}
    need(gates == analysis["gates"] and not all(gates.values()), "predeclared gate outcome differs")
    receipt = {"schema": "hepta-a27-prepared-path-public-arithmetic/v1", "passed": True,
               "public_compressed_run_sha256": sha(compressed), "public_run_bytes_sha256": sha(raw),
               "public_analysis_sha256": sha(raw_analysis), "measured_operations": 2048,
               "warmup_operations": 128, "all_operation_rows_verified": 2176,
               "semantic_cases_per_arm": 17, "cells": 32, "summaries": summaries, "gates": gates,
               "new_workload": False, "candidate_adopted": False,
               "private_authority_verification_repeated": False,
               "scope": "Public metric/schema arithmetic and recorded flags only; private file pins, original binary/dependency bodies and remote authority checks are not reconstructed.",
               "full_private_analyzer_on_redacted_run": "Refuses fixture pin coverage because private fixture hashes are opaque; no check is weakened here."}
    body = json.dumps(receipt, sort_keys=True, indent=2) + "\n"
    if args.output:
        with args.output.open("x") as output:
            output.write(body)
        print(json.dumps({"passed": True, "receipt_sha256": sha(body.encode()), "gates": gates}))
    else:
        print(body, end="")


if __name__ == "__main__":
    main()

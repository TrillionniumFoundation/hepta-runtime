#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Independently verify actual retained rows and arithmetic; starts no workload."""
from pathlib import Path
import argparse
import hashlib
import json
import math
import statistics


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-root", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    base = args.evidence_root.resolve()
    run_dir = base / "a27-prepared-path-probe-run-r02"
    run_raw = (run_dir / "run.json").read_bytes()
    build_raw = (base / "a27-prepared-path-probe-build-r02/build.json").read_bytes()
    analysis_raw = (run_dir / "analysis.json").read_bytes()
    digest = lambda value: hashlib.sha256(value).hexdigest()
    assert digest(run_raw) == "63f68e3e349f921c32c77b3c024d5d015f34fe8eb01e58a7acf2a86471bf24f1"
    assert digest(build_raw) == "ed8f5057fe3af03e9f0bb2431996ff6406b55fae284eb15b84dc82415b0e7cba"
    assert digest(analysis_raw) == "43996a5d684c76ed6254d8d689fecbf04d45ee077ad474af10b17fc9d045896b"
    run, build, analysis = map(json.loads, (run_raw, build_raw, analysis_raw))
    plan_sha = "847067fc03948f0ce05924604132f2e783529d371c75544facdd421dc4bc1485"
    assert run["completed"] is True and run["error"] is None and run["retries"] == 0
    assert run["inputs_unchanged"] and not run["input_fence_errors"]
    assert run["binaries_unchanged"] and not run["binary_fence_errors"]
    assert run["plan_sha256"] == build["plan"]["sha256"] == plan_sha
    assert run["build"]["sha256"] == digest(build_raw)
    assert build["prepared"] and build["compiled"] and "error" not in build
    assert build["inputs_before"] == build["inputs_after"] == run["input_receipts_before"] == run["input_receipts_after"]
    assert build["binaries"] == run["binary_receipts"]
    assert {row["path"]: row for row in run["binary_receipts"].values()} == run["binary_receipts_after"]
    assert len(run["cells"]) == 32 and len(run["semantics"]) == 2
    remote_run = Path("/home/qian/hepta-runtime-optimization-20261023/a27-prepared-path-probe-run-r02")
    ledger_count = 0
    for child in run["cells"] + run["semantics"]:
        assert child["returncode"] == 0 and child["stderr_bytes"] == 0 and child["parse_error"] is None
        assert not child["interrupted"] and not child["signal_forwarded"]
        assert child["record"]["passed"] and child["record"]["plan_sha256"] == plan_sha
        for name in ("stdout.json", "stderr.log"):
            receipt = child[name]
            path = run_dir / Path(receipt["path"]).relative_to(remote_run)
            data = path.read_bytes()
            assert len(data) == receipt["bytes"] and digest(data) == receipt["sha256"]
            if name == "stdout.json":
                assert json.loads(data) == child["record"]
                ledger = json.loads(path.with_name("child.json").read_bytes())
                assert all(child[key] == value for key, value in ledger.items())
                ledger_count += 1
    assert ledger_count == 34
    cases = ["regular_leaf", "nested_directory", "file_as_directory", "file_intermediate",
             "leaf_symlink", "intermediate_symlink", "missing_leaf", "relative",
             "parent_component", "dot_component", "whitespace", "nul", "invalid_utf8",
             "owned_lexical_bytes", "fresh_descriptor_after_replacement", "late_leaf_symlink",
             "late_intermediate_symlink"]
    semantic_rows = []
    for arm, value in zip("AB", run["semantics"]):
        record = value["record"]
        assert value["variant"] == record["variant"] == arm
        assert [row["case"] for row in record["checks"]] == cases
        assert all(any(row.get(key) is True for key in ("passed", "rejected", "lexically_rejected"))
                   for row in record["checks"])
        assert record["root_readable"] and record["leaf_bytes_match"] and record["repeated_separator_same_inode"]
        assert record["recursive_cleanup"] is False
        semantic_rows.append(record["checks"])
    assert semantic_rows[0] == semantic_rows[1]
    for sequence, cell in enumerate(run["cells"]):
        assert (cell["sequence"], cell["block"], cell["position"], cell["variant"]) == (
            sequence, sequence // 4, sequence % 4, "ABBA"[sequence % 4])
        record = cell["record"]
        assert record["variant"] == cell["variant"] and record["caller_deadline_ms"] == 5000
        assert record["agent_requests"] == record["agent_requests_expected"] == 69
        assert record["worker_drain_succeeded"] is True
        assert all(record[key] is None for key in ("agent_error", "bind_error", "cleanup_error"))
        rows = record["rows"]
        assert len(rows) == 68
        assert [(row["phase"], row["index"]) for row in rows] == (
            [("warmup", index) for index in range(4)] + [("measured", index) for index in range(64)])
        assert all(row["attempted"] and row["passed"] and not row["stop_cancelled"]
                   and row["clock_error"] is None and row["validation_error"] is None for row in rows)
    metrics = {}
    for name in ("process_cpu_ns", "owner_thread_cpu_ns", "wall_ns"):
        gains = []
        for block in range(8):
            totals = {arm: sum(row[name] for cell in run["cells"]
                              if cell["block"] == block and cell["variant"] == arm
                              for row in cell["record"]["rows"] if row["phase"] == "measured")
                      for arm in "AB"}
            assert totals["A"] > 0 and totals["B"] > 0
            gains.append(100 * (totals["A"] - totals["B"]) / totals["A"])
        median = statistics.median(gains)
        mad = statistics.median(abs(value - median) for value in gains)
        metrics[name] = {"median_improvement_percent": median, "mad_percentage_points": mad,
                         "positive_blocks": sum(value > 0 for value in gains),
                         "paired_improvements_percent": gains}
        expected = analysis["summaries"][name]
        assert all(math.isclose(value, other, abs_tol=1e-12) for value, other in
                   zip(gains, expected["paired_improvements_percent"]))
        assert math.isclose(median, expected["median_improvement_percent"], abs_tol=1e-12)
        assert math.isclose(mad, expected["median_absolute_deviation_percent"], abs_tol=1e-12)
        assert metrics[name]["positive_blocks"] == expected["positive_blocks"]
    cpu, wall = metrics["process_cpu_ns"], metrics["wall_ns"]
    gates = {"median_process_cpu_at_least_3_percent": cpu["median_improvement_percent"] >= 3,
             "at_least_7_of_8_process_cpu_blocks_improve": cpu["positive_blocks"] >= 7,
             "median_process_cpu_strictly_above_2_mad": cpu["median_improvement_percent"] > 2 * cpu["mad_percentage_points"],
             "median_wall_regression_at_most_2_percent": wall["median_improvement_percent"] >= -2}
    assert gates == analysis["gates"] and not all(gates.values())
    assert analysis["valid_complete_experiment"] and not analysis["eligible_for_runtime_candidate"]
    result = {"schema": "hepta-x230-a27-prepared-path-root-recomputation/v1",
              "verified_raw_experiment": True, "raw_run_sha256": digest(run_raw),
              "raw_build_sha256": digest(build_raw), "raw_analysis_sha256": digest(analysis_raw),
              "plan_sha256": plan_sha, "child_stdout_stderr_receipts_verified": 68,
              "child_ledgers_verified": ledger_count, "semantic_cases_per_arm": 17,
              "semantic_results_equal": True, "measured_operations": 2048, "warmup_operations": 128,
              "all_2176_operations_attempted_and_passed": True, "no_retry": True,
              "original_worker_drains_succeeded": 32, "synthetic_agent_requests": 2208,
              "input_and_binary_receipts_unchanged": True, "external_dependency_and_binary_bodies_downloaded": False,
              "receipt_scope": "Local raw bytes and recorded before/after fences; external dependency bodies were checked by the remote runner, not re-downloaded here.",
              "metrics": metrics, "gates": gates, "adopted": False,
              "decision": "reject prepared CString representation; retain A26",
              "scope": "Whole isolated owner verification with local agent; not SSH/RPC throughput or full runtime qualification."}
    target = args.output or base / "ROOT_RECOMPUTATION.json"
    with target.open("x") as output:
        json.dump(result, output, sort_keys=True, indent=2)
        output.write("\n")
    print(json.dumps({"verified": True, "measured": 2048, "warmup": 128, "gates": gates,
                      "receipt_sha256": digest(target.read_bytes())}))


if __name__ == "__main__":
    main()

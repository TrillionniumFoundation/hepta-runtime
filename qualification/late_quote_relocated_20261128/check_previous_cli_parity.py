#!/usr/bin/env python3
"""Compare durable MCP full outputs to expectations frozen before that execution.

This is a read-only engineering cross-interface check. It performs no model work
and cannot turn already observed checkpoint batches into a new scientific test.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path

EXPECTATIONS_SHA256 = "6ac8f55b431b7613acf60caa2eac28a37ee229e829c9fd55dfcaafc6ee5eb895"
EXPECTATIONS = Path(__file__).resolve().parent / "PARITY_EXPECTATIONS.json"
ORIGINAL_SOURCE_ROOT = Path("/workspace/scratch/cd3dbf666179")
KEYS = ("artifact_sha256", "graph", "request_route", "raw_input_sha256")


def require(value, message):
    if not value:
        raise ValueError(message)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON field")
        result[key] = value
    return result


def read(path):
    raw = Path(path).read_bytes()
    require(len(raw) < 4 * 1024**2, "bounded engineering evidence required")
    return raw, json.loads(raw, object_pairs_hook=unique)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--archive-root", type=Path, help="Relocate source-evidence paths without changing its frozen bytes")
    args = parser.parse_args()
    if args.archive_root is not None:
        require(args.archive_root.is_absolute() and args.archive_root.resolve(strict=True) == args.archive_root,
                "canonical absolute archive root required")
    exp_raw, exp = read(EXPECTATIONS)
    require(hashlib.sha256(exp_raw).hexdigest() == EXPECTATIONS_SHA256, "frozen prior expectation identity changed")
    for row in exp["sources"]:
        source_path = Path(row["path"])
        if args.archive_root is not None:
            source_path = args.archive_root / source_path.relative_to(ORIGINAL_SOURCE_ROOT)
        source, _ = read(source_path)
        require(hashlib.sha256(source).hexdigest() == row["sha256"], "prior executed CLI evidence changed")
    result_raw, result = read(args.result)
    require(result["status"] == "PASS" and result["engineering_replay_of_already_observed_batches"] is True,
            "complete actual MCP engineering result required")
    expected = {tuple(row[key] for key in KEYS): row for row in exp["expectations"]}
    require(len(expected) == len(exp["expectations"]) == 15, "frozen expectation uniqueness changed")
    observed, matched = [], set()
    cases = [(f"case-{i + 1}", case["initial"]) for i, case in enumerate(result["cases"])]
    require(len(cases) == 3, "three observed checkpoint cases required")
    cases.append(("actual-crash-recovery", result["crash_recovery"]))
    for case, report in cases:
        for phase in ("parent_evaluation", "candidate_evaluation", "restored_evaluation"):
            value = report[phase]
            if value is None:
                continue
            for row in value["observations"]:
                function = row["function"]
                key = tuple(function[name] if name != "raw_input_sha256" else row[name] for name in KEYS)
                require(key in expected, "MCP executed an unexpected function/input pair")
                want = expected[key]
                require(all(row["metrics"][name] == want[name] for name in ("output_sha256", "correct", "queries")),
                        "MCP complete numeric output differs from frozen CLI expectation")
                matched.add(key)
                observed.append({"case": case, "phase": phase, "observation": row["name"],
                                 "seed": want["seed"], "function": function,
                                 "raw_input_sha256": row["raw_input_sha256"],
                                 "output_sha256": row["metrics"]["output_sha256"],
                                 "correct": row["metrics"]["correct"], "queries": row["metrics"]["queries"]})
    unmatched = [row for key, row in expected.items() if key not in matched]
    # The finite MCP plan never evaluates the unselected bridge-only candidate's
    # unconditional normal route on seed83. Do not add work or claim that case ran.
    require(len(unmatched) == 1 and unmatched[0]["seed"] == 83
            and unmatched[0]["artifact_sha256"] == "f248653cc821a05440598200ac7af1d5e76bdbb574627bda5a914046d7a5b64e"
            and unmatched[0]["graph"] == "final_tick_tied_receiver_mark"
            and unmatched[0]["request_route"] == "research_unconditional_negative_control",
            "actual finite-plan coverage differs from its declared 14 pairs")
    require(len(observed) == result["complete_forward_results_observed"], "durable observation count disagrees with MCP receipt")
    value = {"schema": "hepta.late-quote.cli-mcp-parity.v1", "status": "PASS",
             "expectations_sha256": EXPECTATIONS_SHA256,
             "actual_mcp_result": str(args.result.resolve(strict=True)),
             "actual_mcp_result_sha256": hashlib.sha256(result_raw).hexdigest(),
             "prior_cli_executable_sha256": exp["prior_cli_executable_sha256"],
             "actual_mcp_executable_sha256": result["ci_identity"]["binary_sha256"],
             "all_observed_complete_outputs_byte_equal": True,
             "complete_observations_compared_including_duplicate_functions": len(observed),
             "distinct_function_input_pairs_compared": len(matched),
             "previous_cli_only_pair_not_executed_by_mcp": unmatched,
             "source_identity_changed_between_interfaces": True,
             "source_evidence_path_relocation": str(args.archive_root) if args.archive_root else None,
             "new_model_forward_calls": 0, "scientific_holdout_claim": False,
             "observations": observed}
    encoded = (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(encoded); f.flush(); os.fsync(f.fileno())
    print(json.dumps({"status": "PASS", "distinct_pairs": len(matched), "new_forward_calls": 0,
                      "output": str(args.output), "sha256": hashlib.sha256(encoded).hexdigest()}))


if __name__ == "__main__":
    main()

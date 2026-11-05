#!/usr/bin/env python3
"""Inspect committed evidence; never launch Runtime, a model, or a new replay."""
import argparse
import hashlib
import json
from pathlib import Path


def require(condition, detail):
    if not condition:
        raise ValueError(detail)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(root, name):
    return json.loads((root / name).read_text())


def check_file(root, item, path_key="path", hash_key="sha256", size_key="bytes"):
    relative = Path(item[path_key])
    require(not relative.is_absolute() and ".." not in relative.parts, "unsafe manifest path")
    path = root / relative
    require(path.is_file(), str(relative))
    require(path.stat().st_size == item[size_key], "size: " + str(relative))
    require(sha(path) == item[hash_key], "SHA: " + str(relative))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, help="Also check all fourteen sources and Cargo.lock in a full checkout")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    manifest = read(root, "MANIFEST.json")
    for item in manifest["files"]:
        check_file(root, item)
    protocol = read(root, "EXECUTION_PROTOCOL.json")
    local_protocol = read(root, "LOCAL_PROTOCOL.json")
    local = read(root, "qualification/local_attempt_1.json")
    sources = read(root, "qualification/source_manifest.json")
    require(len(sources) == 14, "source count")
    require(local["completed"] and local["passed"] and local["source_unchanged_after_format"], "local result")
    require(len(local["commands"]) == 6 and all(x["exit_code"] == 0 and not x["timed_out"] for x in local["commands"]), "local gates")
    require(sources == local["source_after_format"] == local["source_after_last_command"], "source qualification")
    require(sha(root / "qualification/source_manifest.json") == protocol["qualified_source_manifest_sha256"], "source manifest binding")
    require(sha(root / "qualification/local_attempt_1.json") == protocol["local_qualification_sha256"], "local receipt binding")
    require(sha(root / "LOCAL_PROTOCOL.json") == local["protocol_sha256"], "local protocol binding")
    require(sha(root / "run_local_qualification.py") == local_protocol["runner_sha256"], "local runner binding")
    binary = local["binary"]["sha256"]
    require(binary == protocol["binary_sha256"] == manifest["binary_sha256"], "binary identity")
    require(local["cargo_lock_sha256"] == protocol["cargo_lock_sha256"], "lock identity")
    script_paths = {"driver": "run_native_corpus.py", "supervisor": "supervise_native_corpus.py",
                    "bridge_io": "bridge_io.py", "mcp_fixture_client": "mcp_fixture_client.py",
                    "source_health": "verify_source_health.py"}
    for key, path in script_paths.items():
        require(sha(root / path) == protocol["script_sha256"][key], "frozen helper: " + path)
    require(sha(root / "prepare_execution_protocol.py") == protocol["preparer_sha256"], "preparer")
    for phase in ("trust_regression", "journal_contract", "bellman_corpus"):
        health = read(root, "qualification/post-" + phase + "-source-health.json")
        require(health["passed"] and health["phase"] == phase, "post-phase health")
        require(health["qualification_sha256"] == protocol["local_qualification_sha256"], "health qualification")
        require(health["checker_sha256"] == protocol["script_sha256"]["source_health"], "health checker")
        require(len(health["source_files"]) == len(sources), "health source count")
        for current, qualified in zip(health["source_files"], sources):
            require(current["path"] == qualified["path"] and current["bytes"] == qualified["bytes"], "health path/size")
            require(current["sha256"] == current["expected_sha256"] == qualified["sha256"], "health SHA")
            require(current["stable_during_read"] and current["matched"], "unstable source")
        require(health["binary"]["sha256"] == binary and health["binary"]["matched"] and health["binary"]["stable_during_read"], "health binary")
        require(health["cargo_lock"]["sha256"] == local["cargo_lock_sha256"] and health["cargo_lock"]["matched"], "health lock")
    redactions = read(root, "qualification/logs/LOG_REDACTION.json")
    for item, command_index in zip(redactions["files"], (1, 2, 3, 4)):
        check_file(root / "qualification", item, "file", "published_sha256", "published_bytes")
        command = local["commands"][command_index]
        require(item["original_sha256"] == command["log_sha256"] and item["original_bytes"] == command["log_bytes"], "raw log binding")
    for index in (2, 4):
        log = (root / ("qualification/logs/command-" + str(index) + ".sanitized.log")).read_text()
        require("75 passed; 0 failed; 2 ignored" in log, "focused test count")
    trust = read(root, "qualification/trust_regression_attempt_1.json")
    trust_outer = read(root, "qualification/trust_regression_outer_attempt_1.json")
    require(trust["passed"] and trust["completed"] and trust["failure"] is None and trust["executed_binary_unchanged"], "trust result")
    require(len(trust["plans"]) == 7 and len(trust["norm_checks"]) == 60 and len(trust["negative_controls"]) == 4 and len(trust["public_head_guards"]) == 2, "trust counts")
    require(trust["binary_sha256"] == trust_outer["binary_sha256"] == binary, "trust binary")
    require(trust_outer["exit_code"] == 0 and not trust_outer["timed_out"] and trust_outer["pr92_frozen_driver_unchanged"] and trust_outer["pr92_frozen_helper_unchanged"], "trust outer health")
    require(trust_outer["internal_receipt_sha256"] == sha(root / "qualification/trust_regression_attempt_1.json"), "trust receipt")
    corpus_root = root / "qualification/native_corpus"
    corpus = read(corpus_root, "NATIVE_CORPUS_MANIFEST.json")
    require(corpus["binary_sha256"] == binary and corpus["execution_succeeded"] and corpus["fatal"] is None, "corpus success")
    require(corpus["planned_worlds"] == corpus["attempted_worlds"] == 320 and corpus["failed_worlds"] == corpus["unattempted_worlds"] == 0, "corpus denominator")
    require(corpus["all_requests_completed_without_rpc_error"] and corpus["outer_process_succeeded"], "corpus execution flags")
    require(not corpus["references_loaded_by_native_driver"] and not corpus["new_scientific_efficacy_evidence"] and not corpus["production_eligible"], "scope flags")
    require(sha(corpus_root / "EXECUTION_PROTOCOL.json") == sha(root / "EXECUTION_PROTOCOL.json") == corpus["native_execution_protocol_sha256"], "corpus protocol")
    for field in ("internal_execution_receipt", "internal_manifest", "local_qualification", "qualified_source_manifest", "whole_process_receipt"):
        require(sha(corpus_root / corpus[field + "_file"]) == corpus[field + "_sha256"], field)
    for name, item in corpus["files"].items():
        check_file(corpus_root, {"path": name, **item})
    require(sorted(corpus["files"]) == protocol["expected_groups"], "output groups")
    internal = read(corpus_root, corpus["internal_execution_receipt_file"])
    outer = read(corpus_root, corpus["whole_process_receipt_file"])
    require(internal["executed_binary_unchanged"] and internal["fatal"] is None and internal["binary_sha256"] == binary, "internal health")
    require(outer["exit_code"] == 0 and not outer["timed_out"] and outer["sources_unchanged"], "whole-process health")
    for name, item in outer["logs"].items():
        check_file(root / "qualification/native_outer_logs", {"path": name, **item})
    handoff = read(root, "fixtures/requests/REQUEST_HANDOFF.json")
    require(sha(root / "fixtures/requests/REQUEST_HANDOFF.json") == protocol["request_handoff_sha256"] == corpus["request_handoff_sha256"], "input handoff")
    for path, item in handoff["group_files"].items():
        check_file(root / "fixtures", {"path": path, **item})
    require(handoff["planned_worlds"] == 320 and handoff["total_nodes"] == 246160 and handoff["total_edges"] == 277892, "input graph dimensions")
    independent_root = root / "qualification/independent_replay"
    link = read(independent_root, "RESEARCH_PACKAGE_LINK.json")
    for item in link["files"]:
        check_file(independent_root, item, "runtime_relative_path")
    result = read(independent_root, "RESULTS.json")
    replay = read(independent_root, "PROCESS_RECEIPT.json")
    freeze = read(independent_root, "VERIFIER_FREEZE.json")
    require(result["passed"] and result["native_execution_provenance_healthy"], "independent result")
    require(result["planned_worlds"] == result["compared_worlds"] == result["reevaluated_worlds"] == 320, "independent denominator")
    require(result["total_compared_nodes"] == 246160 and result["total_compared_legal_Q"] == 928200, "independent comparisons")
    require(all(result[key] == 0 for key in ("max_reference_Q_absolute_error", "max_scalar_graph_Q_absolute_error", "max_utility_absolute_error")), "independent errors")
    require(all(not result[key] for key in ("production_qualified", "new_scientific_efficacy_qualification", "actual_packet_IO_qualified", "full_economic_net_value_qualified")), "independent scope")
    require(replay["exit_code"] == 0 and replay["worker_source_sha256"] == freeze["verifier_source_sha256"], "independent worker")
    require(freeze["acceptance_protocol_sha256"] == sha(independent_root / "ACCEPTANCE_PROTOCOL.json") == protocol["independent_acceptance_protocol_sha256"], "independent protocol")
    require(freeze["native_execution_protocol_sha256"] == corpus["native_execution_protocol_sha256"] and freeze["frozen_utc"] < outer["started_utc"], "pre-execution freeze")
    if args.repo is not None:
        for item in sources:
            check_file(args.repo, item)
        require(sha(args.repo / "Cargo.lock") == local["cargo_lock_sha256"], "checkout lock")
    print(json.dumps({"status": "PASS_RECORDS_ONLY", "manifest_files": len(manifest["files"]),
                      "qualified_sources": len(sources), "recorded_mcp_worlds": 320,
                      "recorded_compared_nodes": 246160, "recorded_compared_legal_Q": 928200,
                      "repository_source_verified": args.repo is not None,
                      "new_runtime_execution": False, "new_scientific_efficacy_claim": False}, sort_keys=True))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Local pure checks for the new receipt binder; never touch the X230."""
import ast
import copy
import hashlib
import json
from pathlib import Path
import types

HERE = Path(__file__).resolve().parent
REFERENCE = HERE.parent / "r35-runner-reference"


def load(name, path):
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
    return module


def main():
    parent = load("r36_pure_review", HERE / "tools-01/r36_campaign.py")
    materializer = load("r36_sealer_pure_review", HERE / "materialize_control_inputs.py")
    frozen = json.loads((HERE.parent / "r36-qualification-input.json").read_bytes())
    assert set(frozen["changed_paths"]) == parent.R36_CHANGED_PATHS
    baseline = {"schema": "hepta-x230-composed-qualification/v1", "qualified": True, "finished_utc": "synthetic",
        "source": str(parent.BASELINE_ROOT / "source"), "source_tested": frozen["baseline_compile_inputs"],
        "source_after": frozen["baseline_compile_inputs"], "harness_before": frozen["qualification_harness_sha256"],
        "harness_after": frozen["qualification_harness_sha256"]}
    candidate_map = frozen["candidate_compile_inputs"]
    zeros = "0" * 64
    qualified = {"schema": "hepta-x230-composed-qualification/v1", "qualified": True, "finished_utc": "synthetic",
        "source": str(parent.SOURCE), "jobs": 2, "automatic_test_retries": 0, "service_changes": False,
        "source_input": candidate_map, "source_tested": candidate_map, "source_after": candidate_map,
        "harness_before": frozen["qualification_harness_sha256"], "harness_after": frozen["qualification_harness_sha256"],
        "stages": [{"name": name, "command": ["synthetic-check-only"], "returncode": 0,
                    "stdout_sha256": zeros, "stderr_sha256": zeros} for name in parent.R36_QUALIFICATION_STAGES],
        "binaries": {name: {"path": str(parent.CANDIDATE_DIR / name), "sha256": zeros} for name in parent.BINARY_NAMES}}
    command = ["/usr/bin/python3", "-B", "-u", str(parent.SOURCE / "tools/x230/20261028/qualify.py"),
               "--source", str(parent.SOURCE), "--output", str(parent.CANDIDATE_DIR),
               "--target", str(parent.ROOT / "target-build"), "--cargo-home",
               "/home/qian/hepta-runtime-optimization-20261023/cargo-home-a32-a33-r02", "--jobs", "2",
               "--stage-timeout", "3600"]
    preparation = {"schema": "hepta-x230-r36-preparation/v1", "passed": True, "finished_utc": "synthetic",
        "qualification_returncode": 0, "automatic_retries": 0, "production_services_modified": False,
        "source_baseline": parent.R36_BASELINE_COMMIT, "target_fresh_before_start": True,
        "qualification_started": True, "owned_child_closed": True, "owned_group_absent": True,
        "qualification_command": command}
    job_id = "00000000000-0000-0000"
    terminal = {"job_id": job_id, "state": "succeeded", "exit_code": 0,
        "automatic_retry": False, "timed_out": False, "cancelled": False, "output_complete": True,
        "output_durable": True, "terminal_publication_confirmed": True, "terminal_publication_protocol": 1,
        "log_synced": {"stdout": True, "stderr": True}, "log_errors": {"stdout": None, "stderr": None},
        "log_truncated": {"stdout": False, "stderr": False},
        "log_bytes": {"stdout": {"seen": 0, "stored": 0}, "stderr": {"seen": 0, "stored": 0}}}
    tests = {"schema": "hepta-isolated-libtest/v1", "success": True, "filter": "", "retries": 0,
        "failed": 0, "enumeration_errors": [], "passed": 7, "ignored": 2, "selected": 9}
    audit = {"schema": "hepta-isolated-libtest-audit/v1", "success": True, "expected_filter": "", "errors": [],
        "evidence": str(parent.CANDIDATE_DIR / "isolated-tests"),
        "auditor_sha256": frozen["qualification_harness_sha256"]["audit_isolated_tests.py"],
        "passed": 7, "failed": 0, "ignored": 2, "selected": 9, "executed": 7,
        "binaries": [{"recorded_before_sha256": zeros, "current_after_sha256": zeros}]}
    fixture = [preparation, terminal, job_id, qualified, tests, audit, frozen, frozen, baseline, candidate_map]
    assert parent.verify_r36_candidate_documents(*fixture)["tests"] == dict(passed=7, failed=0, ignored=2, selected=9, retries=0)
    checks = ["accepts actual input schema and dynamic reconciled test counts"]
    def rejects(label, mutate):
        values = copy.deepcopy(fixture)
        mutate(values)
        try:
            parent.verify_r36_candidate_documents(*values)
        except (RuntimeError, KeyError, TypeError, ValueError):
            checks.append(label)
        else:
            raise AssertionError("invalid fixture was accepted: " + label)
    rejects("rejects an unreviewed source digest", lambda v: v[6]["candidate_compile_inputs"].__setitem__("Cargo.toml", zeros))
    rejects("rejects a missing owned-child closure", lambda v: v[0].__setitem__("owned_child_closed", False))
    rejects("rejects a surviving owned process group", lambda v: v[0].__setitem__("owned_group_absent", False))
    rejects("rejects reused target", lambda v: v[0].__setitem__("target_fresh_before_start", False))
    rejects("rejects truncated native output", lambda v: v[1]["log_truncated"].__setitem__("stdout", True))
    rejects("rejects lost native output bytes", lambda v: v[1]["log_bytes"]["stdout"].__setitem__("seen", 1))
    rejects("rejects retried qualification", lambda v: v[3].__setitem__("automatic_test_retries", 1))
    rejects("rejects changed postqualification source", lambda v: v[3].__setitem__("source_after", {"Cargo.toml": zeros}))
    rejects("rejects incomplete test counts", lambda v: v[4].__setitem__("selected", 10))
    # Assert every generated file parses; compile() only produces code objects.
    count = 0
    for path in HERE.rglob("*.py"):
        compile(path.read_bytes(), str(path), "exec")
        count += 1
    ci = (HERE / "ci-templates/materialize_rust_ci_plan_01.py").read_text()
    for name in ("JOB_ID", "SOURCE_MAP_SHA", "ISOLATED_SUMMARY_SHA", "ISOLATED_AUDIT_SHA",
                 "QUALIFICATION_REPORT_SHA", "PREPARATION_SHA", "NATIVE_TERMINAL_SHA",
                 "PARENT_SHA", "QUALIFICATION_BINDINGS_SHA", "FROZEN_COUNTS"):
        ci = materializer.assign_frozen(ci, name, {"passed": 7} if name == "FROZEN_COUNTS" else zeros)
    ast.parse(ci)
    launcher = materializer.assign_frozen((HERE / "ci-templates/launch_exact_rust_ci_01.py").read_text(), "SPEC", {"synthetic": True})
    ast.parse(launcher)
    checks.append("seals each late-bound CI constant exactly once without executing CI")
    checked_script = (HERE / "tools-01/r36_lifecycle_campaign.py").read_text()
    assert checked_script == (REFERENCE / "tools-01/r35_lifecycle_campaign.py").read_text().replace("R35", "R36").replace("r35", "r36")
    checks.append("lifecycle control body unchanged except round identity")
    result = {"schema": "hepta-r36-control-local-review/v1", "passed": True, "pure_checks": checks,
              "python_files_parsed": count, "synthetic_receipts_are_not_qualification_evidence": True,
              "remote_commands_executed": 0, "candidate_commands_executed": 0}
    (HERE / "local-review.json").write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()

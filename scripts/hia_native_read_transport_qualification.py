#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Rebuild and qualify HIA read bootstrap, SSH transport and owned-worker retirement."""
from __future__ import annotations
import os
import sys
if __name__ == "__main__" and not sys.flags.isolated:
    os.execv(sys.executable, [sys.executable, "-I", "-B", os.path.abspath(__file__), *sys.argv[1:]])
import argparse
import json
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import hia_native_local_read_qualification as local
from hia_native_build import NativeBuild

EXTRA = (
    "scripts/hia_native_read_transport_qualification.py", "scripts/author_native_read_bootstrap.py",
    "scripts/native_read_bootstrap.pseudo", "native/native_read_bootstrap_wire.json",
    "native/native_read_bootstrap.hepta", "native/native_read_bootstrap_composition.json",
    "native/composition_ready_reap.json", "scripts/author_composition_reap.py",
    "scripts/native_read_ready_reap.S", "tests/hia_native/test_native_read_bootstrap.py",
    "tests/hia_native/test_native_read_bootstrap_state.py", "tests/hia_native/test_file_info_ready_reap.py",
    "tests/hia_native/test_file_info_guard.py", "tests/hia_native/info_guard_supervisor.py",
    "tests/hia_native/io_fault_supervisor.py",
)
TRANSPORT_COUNTS = {"actual_elf_responses": 15, "binary_read_original_comparisons": 3,
    "file_info_original_comparisons": 3, "invalid_elf_refusals": 1,
    "multi_read_original_comparisons": 3, "native_bootstrap_calls": 32,
    "ssh_invocations": 5, "truncated_elf_refusals": 1}
TEST_COUNTS = {"test_native_read_bootstrap_state.py": 3, "test_native_read_bootstrap.py": 5,
               "test_file_info_ready_reap.py": 3, "test_file_info_guard.py": 4}
GUARD_COUNTS = {"closed_stderr_controls": 1, "deadline_requests": 2,
    "kernel_notification_holds": 2, "original_info_comparisons": 9,
    "original_read_comparisons": 2, "parent_resource_controls": 12,
    "root_fd2_controls": 3, "root_rebind_controls": 2,
    "setup_failure_controls": 5, "setup_recovery_controls": 5,
    "worker_cancellations": 2, "worker_reap_controls": 2}


def require(value, message):
    if not value:
        raise ValueError(message)


def run_test(output, test, result_key, env):
    label = Path(test).stem
    result_path = output / (label + ".result.json")
    require(not result_path.exists(), "stale qualification result: " + label)
    started = time.monotonic()
    command = [sys.executable, "-I", "-B", str(ROOT / "tests/hia_native" / test)]
    with (output / (label + ".stdout")).open("xb") as out, (output / (label + ".stderr")).open("xb") as err:
        done = subprocess.run(command, env=dict(env, **{result_key: str(result_path)}),
                              cwd=ROOT, stdout=out, stderr=err, timeout=180, check=False)
    row = {"test": test, "returncode": done.returncode, "seconds": time.monotonic()-started}
    if result_path.exists():
        row["result"] = json.loads(result_path.read_bytes())
        row["result_sha256"] = local.digest(result_path.read_bytes())
    print(json.dumps({"test": test, "returncode": done.returncode}), flush=True)
    require(done.returncode == 0 and row.get("result", {}).get("status") == "pass",
            "qualification failed: " + label)
    completeness = {"tests_run": TEST_COUNTS[test], "skipped": 0, "errors": 0, "failures": 0,
                    "expected_failures": 0, "unexpected_successes": 0,
                    "python_isolated": 1, "python_optimize": 0}
    for field, expected in completeness.items():
        require(type(row["result"].get(field)) is int and row["result"][field] == expected,
                "qualification completeness/isolation mismatch: " + label + "." + field)
    return row


def qualify(hepta, output, report):
    require(sys.flags.isolated == 1 and sys.flags.optimize == 0, "isolated unoptimized Python required")
    report["sources"] = local.freeze(ROOT)
    report["sources"].update({name: local.file_identity(ROOT/name) for name in EXTRA})
    report["local"] = {}
    local.qualify(ROOT, hepta, output/"local", report["local"])
    build = NativeBuild(hepta, output/"bootstrap")
    bootstrap = build.compile("native-read-bootstrap", ROOT/"native/native_read_bootstrap.hepta",
                              standalone=None)
    bootstrap_metadata = json.loads(bootstrap.read_bytes())
    report["bootstrap_manifest"] = str(bootstrap)
    report["bootstrap_manifest_sha256"] = local.digest(bootstrap.read_bytes())
    report["bootstrap_source_sha256"] = bootstrap_metadata["source_sha256"]
    report["bootstrap_image_sha256"] = bootstrap_metadata["image_sha256"]
    env = {key: value for key, value in os.environ.items() if not key.startswith(("HIA_", "PYTHON"))}
    env.update(HIA_RUNTIME_REPO=str(ROOT), HIA_RUNTIME_REFERENCE=report["local"]["original_reference"],
               HIA_HEPTA_DIR=str(hepta), HIA_SERVICE_MANIFEST=report["local"]["manifest"],
               HIA_BOOTSTRAP_MANIFEST=str(bootstrap), HIA_READ_TRANSPORT_FIXTURE_ROOT=str(output),
               HIA_INFO_FIXTURE_ROOT=str(output))
    report["suites"] = []
    for test, key in (
        ("test_native_read_bootstrap_state.py", "HIA_READ_BOOTSTRAP_STATE_RESULT"),
        ("test_native_read_bootstrap.py", "HIA_READ_TRANSPORT_RESULT"),
        ("test_file_info_ready_reap.py", "HIA_READY_REAP_RESULT"),
        ("test_file_info_guard.py", "HIA_INFO_GUARD_RESULT"),
    ):
        row = run_test(output, test, key, env)
        report["suites"].append(row)
        proof = row["result"]
        if test == "test_native_read_bootstrap_state.py":
            require(proof["tests_run"] == 3 and proof["skipped"] == 0 and proof["counts"] == {
                "native_calls": 34, "accepted": 20, "admission_refusals": 12, "capacity_refusals": 2},
                "bootstrap admission domain changed")
            require(proof["runtime_source_sha256"] == report["bootstrap_source_sha256"] and
                    proof["runtime_image_sha256"] == report["bootstrap_image_sha256"],
                    "bootstrap admission image differs")
        elif test == "test_native_read_bootstrap.py":
            require(proof["tests_run"] == 5 and proof["skipped"] == 0 and
                    proof["counts"] == TRANSPORT_COUNTS, "SSH qualification domain changed")
            require(proof["read_executable_sha256"] == report["local"]["executable_sha256"] and
                    proof["bootstrap_image_sha256"] == report["bootstrap_image_sha256"],
                    "SSH native image identity differs")
            require(proof["remote_sessions"] == {"sessions": 14, "responses": 413} and
                    proof["direct_eof_responses_in_retained_suite"] == 2, "SSH response domain changed")
            suites = proof["complete_original_service_suites"]
            require([p["name"] for p in suites] == list(local.SUITES), "complete original suites missing")
            for item in suites:
                local.admit_suite(item["name"], item, report["local"]["manifest_sha256"],
                                  report["local"]["executable_sha256"])
        elif test == "test_file_info_ready_reap.py":
            require(proof["tests_run"] == 3 and proof["skipped"] == 0 and
                    proof["actual_elf_responses"] == 8, "owned-worker retirement suite changed")
            expected = {"controlled_wnohang_zeroes": 8, "original_info_comparisons": 4,
                        "poll_eintr_controls": 1, "ready_worker_reaped_before_response": 2}
            require(all(proof["counts"][k] == v for k, v in expected.items()) and
                    proof["counts"]["bounded_polls"] >= 8, "owned-worker control counts changed")
            require(proof["executable_sha256"] == report["local"]["executable_sha256"],
                    "owned-worker native image differs")
        else:
            require(proof["counts"] == GUARD_COUNTS and proof["actual_elf_responses"] == 34,
                    "original fixed-deadline domain changed")
            require(proof["executable_sha256"] == report["local"]["executable_sha256"],
                    "fixed-deadline native image differs")
    local.check_unchanged(ROOT, report["sources"])
    local.check_unchanged(Path(report["local"]["original_reference"]), report["local"]["original_sources"])
    report["status"] = "pass"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta", type=Path, required=True)
    parser.add_argument("--build-root", type=Path, required=True)
    args = parser.parse_args()
    output = args.build_root.absolute()
    require(not output.exists(), "qualification output must be fresh")
    output.mkdir(parents=True)
    report = {"schema": "hepta.runtime.native-read-transport-qualification.v1", "status": "running",
              "default_public_route": False, "configured_host_alias_mapping": False,
              "ssh_cancellation_qualified": False, "remote_parent_death_qualified": False,
              "whole_runtime_replaced": False, "old_stack_removal_qualified": False,
              "default_tools_registered": 136, "default_tools_routed": 13,
              "default_tools_unrouted": 123}
    try:
        qualify(args.hepta.resolve(strict=True), output, report)
    except BaseException as exc:
        report.update(status="fail", error=repr(exc))
        raise
    finally:
        (output/"qualification.json").write_text(json.dumps(report, indent=2, sort_keys=True)+"\n")
    print(json.dumps({"status": report["status"], "report": str(output/"qualification.json")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

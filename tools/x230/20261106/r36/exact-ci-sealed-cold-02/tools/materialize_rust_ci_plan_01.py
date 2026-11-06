#!/usr/bin/env python3
"""Bind successful qualification01 to the two exact workflow commands; never run them."""
import argparse
import datetime
import hashlib
import json
import os
import re
from pathlib import Path
import shlex
import stat

ROOT = Path("/home/qian/hepta-runtime-validation-scratch-20261106-r36-cold-02")
SOURCE = ROOT / "source"
QUALIFICATION = ROOT / "qualification-01"
CANDIDATE_DIR = QUALIFICATION
JOB_ID = '1a1b1cb4862-fc05-7ad9'
SOURCE_MAP_SHA = 'b9eff66ea8b14eca80d16069a59588a551fcf6feff0ac4c991690425df65462a'
ISOLATED_SUMMARY_SHA = '38571b98196196dc7c6af43c61e3cecbb823f22f098353e31e5ee107e4625b41'
ISOLATED_AUDIT_SHA = '6c33faf1b73d34a1a5ac5bcc8e5570c8a409f3fc8adc106321196ea40c4570c7'
CI_MANIFEST_SHA = "bf0df5f7d19ebd149854fbf75887fb0fb136f18a63a0c240abf8420655fb195e"
NEXTEST_ROOT = Path("/home/qian/hepta-runtime-optimization-20261105-r25/ci-toolchain/nextest-0.9.137")
NEXTEST_RECEIPT_SHA = "2bbae481b3fbc6ac6d06a22bfe22e9500f5190b97ccddb16e8aba1ef1ed34f9d"
NEXTEST_BINARY = {
    "path": str(NEXTEST_ROOT / "bin/cargo-nextest"),
    "bytes": 33831936,
    "sha256": "9c05bd3c7c5da1286b193873f12b37db386485fa483d8fa0554e68a53d9df550",
}
QUALIFICATION_REPORT_SHA = 'd8af06696cbd7a1bbf0595bf628a18c112e82598cafb1b45b609a7955ced5e08'
PREPARATION_SHA = '20ae4a6b83454d2079e23f012c62fddcf88434cce488d0935576d5aa83309035'
NATIVE_TERMINAL_SHA = 'd064a939e5707b9694a0853b87bd2fff92887966b1daea5b988fe8a5229fc1bb'
STAGES = ["format", "fmt-check", "harness-tests", "clippy", "test-build", "isolated-tests", "audit-isolated-tests", "release"]
COMMANDS = [
    {"workflow_step": "Check all targets", "argv": ["cargo", "check", "--locked", "--all-targets", "--all-features"]},
    {"workflow_step": "Test in isolated processes", "argv": ["cargo", "nextest", "run", "--locked", "--all-targets", "--all-features", "--test-threads", "1", "--retries", "0", "--no-fail-fast"]},
]
INVENTORY_COMMAND = ["cargo", "nextest", "list", "--locked", "--all-targets", "--all-features", "--message-format", "json"]
BINARY_NAMES = {"hepta-runtime", "hepta-runtime-jobctl", "native_process_driver"}


def need(value, message):
    if not value:
        raise RuntimeError(message)


def require_frozen_qualification():
    pins = [SOURCE_MAP_SHA, ISOLATED_SUMMARY_SHA, ISOLATED_AUDIT_SHA,
            QUALIFICATION_REPORT_SHA, PREPARATION_SHA, NATIVE_TERMINAL_SHA,
            PARENT_SHA, QUALIFICATION_BINDINGS_SHA]
    need(all(type(pin) is str and len(pin) == 64
             and all(char in "0123456789abcdef" for char in pin) for pin in pins)
         and type(JOB_ID) is str and JOB_ID != "UNBOUND_ACTUAL_QUALIFICATION_JOB_ID"
         and len(JOB_ID.split("-")) == 3
         and type(FROZEN_COUNTS) is dict
         and set(FROZEN_COUNTS) == {"passed", "failed", "ignored", "selected", "retries"}
         and all(type(value) is int and value >= 0 for value in FROZEN_COUNTS.values())
         and FROZEN_COUNTS["passed"] > 0 and FROZEN_COUNTS["failed"] == FROZEN_COUNTS["retries"] == 0
         and FROZEN_COUNTS["selected"] == FROZEN_COUNTS["passed"] + FROZEN_COUNTS["ignored"],
         "R36 qualification has not been frozen from actual original receipts; no plan or command may run")


ADDITIONAL_PREPARATION_BINDINGS = []
PREPARATION_PROOF = None
PARENT_PATH = ROOT / "tools-01/r36_campaign.py"
PARENT_SHA = '070f53cec7359bfa3f390f45edd135f417d0013dbf091e35dd7334e0cefc0045'
QUALIFICATION_BINDINGS_PATH = ROOT / "rust-ci-qualification-bindings-01.json"
QUALIFICATION_BINDINGS_SHA = '4e1810535fa9a7e4a2945f962fcbc3b3a1918e88f7e670d44ce2e815a3ba2890'
FROZEN_COUNTS = {'failed': 0, 'ignored': 34, 'passed': 1647, 'retries': 0, 'selected': 1681}


def verify_preparation(value, qualified, qualification_identity, terminal):
    """Reuse the actual sealed R36 qualification binder, without starting a campaign."""
    import types
    global PREPARATION_PROOF
    parent_id, parent_raw = read_file(PARENT_PATH, retain=True)
    need(parent_id["sha256"] == PARENT_SHA, "sealed R36 receipt binder changed")
    parent = types.ModuleType("r36_ci_receipt_only_parent")
    parent.__file__ = str(PARENT_PATH)
    exec(compile(parent_raw, parent.__file__, "exec"), parent.__dict__)
    inputs_id, inputs_raw = read_file(QUALIFICATION_BINDINGS_PATH, retain=True)
    need(inputs_id["sha256"] == QUALIFICATION_BINDINGS_SHA, "actual R36 qualification bindings changed")
    inputs = json.loads(inputs_raw)
    need(set(inputs) == {"qualification_launcher", "qualification_input", "candidate_patch",
         "qualification_preparation", "qualification_terminal_status", "qualification_reports"},
         "independent R36 qualification bindings inventory differs")
    bindings = [parent_id, inputs_id]
    def bind(path, expected=None, retain=False, maximum=128 * 1024 * 1024):
        result = parent.checked(path, expected, maximum, retain)
        bindings.append(result[0] if retain else result)
        return result
    proof = parent.bind_r36_candidate_preparation(inputs, bind)
    need(proof["passed"] is True and proof["original_job_id"] == JOB_ID
         and proof["qualification"] == qualification_identity
         and proof["preparation"]["sha256"] == PREPARATION_SHA
         and proof["terminal"]["sha256"] == NATIVE_TERMINAL_SHA,
         "R36 qualification proof differs from exact CI inputs")
    need(json.loads(parent.checked(ROOT / "preparation.json", retain=True)[1]) == value
         and json.loads(parent.checked(QUALIFICATION / "report.json", retain=True)[1]) == qualified
         and json.loads(parent.checked(ROOT / "qualification-terminal-status-01.json", retain=True)[1]) == terminal,
         "caller-provided R36 qualification documents differ")
    ADDITIONAL_PREPARATION_BINDINGS[:] = bindings
    PREPARATION_PROOF = proof


def read_file(path, retain=False):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path, "indirect input: " + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode), "nonregular input: " + str(path))
        with os.fdopen(os.dup(fd), "rb") as stream:
            if retain:
                raw = stream.read()
                digest = hashlib.sha256(raw).hexdigest()
            else:
                raw = None
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
        after = os.fstat(fd)
        fields = ("st_dev", "st_ino", "st_size", "st_mode", "st_uid", "st_mtime_ns", "st_ctime_ns")
        need(tuple(getattr(before, k) for k in fields) == tuple(getattr(after, k) for k in fields)
             == tuple(getattr(path.lstat(), k) for k in fields), "input changed: " + str(path))
    finally:
        os.close(fd)
    return {"path": str(path), "bytes": before.st_size, "sha256": digest}, raw


def verify_terminal(value):
    need(value.get("job_id") == JOB_ID and value.get("state") == "succeeded"
         and type(value.get("exit_code")) is int and value["exit_code"] == 0
         and all(value.get(k) is False for k in ("automatic_retry", "cancelled", "timed_out"))
         and all(value.get(k) is True for k in ("output_complete", "output_durable", "terminal_publication_confirmed"))
         and type(value.get("terminal_publication_protocol")) is int and value["terminal_publication_protocol"] == 1
         and value.get("log_synced") == {"stdout": True, "stderr": True}
         and value.get("log_errors") == {"stdout": None, "stderr": None}
         and value.get("log_truncated") == {"stdout": False, "stderr": False},
         "original qualification01 job lacks complete successful terminal proof")


def verify_qualification(value):
    need(value.get("schema") == "hepta-x230-composed-qualification/v1"
         and value.get("qualified") is True and value.get("finished_utc")
         and value.get("source") == str(SOURCE), "qualification01 is not completed and successful")
    need([row["name"] for row in value["stages"]] == STAGES
         and all(type(row["returncode"]) is int and row["returncode"] == 0 for row in value["stages"]),
         "all eight original qualification stages must pass")
    need(type(value.get("automatic_test_retries")) is int and value["automatic_test_retries"] == 0,
         "qualification retries must be zero")
    need(value["source_tested"] == value["source_after"] and len(value["source_after"]) == 220,
         "qualified source changed or inventory differs")
    need(value["harness_before"] == value["harness_after"] and len(value["harness_after"]) == 19,
         "original 19 qualification harness inputs changed")
    need(set(value["binaries"]) == BINARY_NAMES, "retained qualified binary set differs")


CANONICAL_WORKFLOW = {'bytes': 7631,
 'path': '/home/qian/hepta-runtime-validation-scratch-20261106-r36-cold-02/rust-ci-tools-01/canonical-workflow.yml',
 'sha256': 'b9061fd671ac5fff33ad47d7ec5787f82cfadd88f5e71d54a8825cb55a02cd51'}
CANONICAL_WORKFLOW_GIT_BLOB = '34afc29edffd3130df158601c6a14fee5efbf79c'
PRIVATE_SOURCE_WORKFLOW = {'bytes': 7235,
 'path': '/home/qian/hepta-runtime-validation-scratch-20261106-r36-cold-02/source/.github/workflows/ci.yml',
 'sha256': '5574840f604a3c7963a274592ac2468a43fdd04cdaa7122851c271188a11065d'}

# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0


def verify_canonical_workflow(ci, canonical_identity, canonical_raw, source_identity):
    blob = hashlib.sha1(b"blob " + str(len(canonical_raw)).encode() + b"\0" + canonical_raw).hexdigest()
    need(canonical_identity == CANONICAL_WORKFLOW and source_identity == PRIVATE_SOURCE_WORKFLOW,
         "private or canonical workflow identity differs")
    need(ci["workflow_path"] == ".github/workflows/ci.yml" and blob == CANONICAL_WORKFLOW_GIT_BLOB
         and ci["workflow_git_blob"] == blob, "canonical workflow does not match the original CI manifest Git object")
    rows = [row for row in ci["input_files"] if row["path"] == ci["workflow_path"]]
    need(rows == [{"path": ci["workflow_path"], "bytes": len(canonical_raw),
         "sha256": canonical_identity["sha256"], "git_blob": blob, "git_mode": "100644"}],
         "canonical workflow differs from the original 85-file CI input closure")
    return {"canonical": canonical_identity, "canonical_git_blob": blob,
        "canonical_publication_commit": "c039688312ceb09b3d26d1cdd50f9118eb11129f",
        "private_source": source_identity, "private_source_workflow_is_canonical": False,
        "qualified_source_modified": False,
        "scope": "exact commands from the published workflow; private qualified source workflow remains unchanged"}



def main():
    require_frozen_qualification()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qualification", type=Path, default=QUALIFICATION / "report.json")
    parser.add_argument("--qualification-sha256", required=True)
    parser.add_argument("--terminal-status", type=Path, default=ROOT / "qualification-terminal-status-01.json")
    parser.add_argument("--terminal-status-sha256", required=True)
    parser.add_argument("--ci-manifest", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    need(args.qualification == QUALIFICATION / "report.json", "qualification path must be attempt01")
    need(args.terminal_status == ROOT / "qualification-terminal-status-01.json", "terminal path must be attempt01")
    need(args.out.is_absolute() and args.out.parent.resolve(strict=True) == args.out.parent
         and args.out.is_relative_to(ROOT) and not os.path.lexists(args.out), "fresh private plan output required")
    need(args.qualification_sha256 == QUALIFICATION_REPORT_SHA
         and args.terminal_status_sha256 == NATIVE_TERMINAL_SHA, "frozen actual R36 report or terminal pin differs")
    bindings = []

    def bind(path, digest=None, json_value=False, retain=False):
        identity, raw = read_file(path, retain=json_value or retain)
        need(digest is None or identity["sha256"] == digest, "bound SHA differs: " + str(path))
        bindings.append(identity)
        return identity, json.loads(raw) if json_value else raw

    terminal_identity, terminal = bind(args.terminal_status, args.terminal_status_sha256, json_value=True)
    verify_terminal(terminal)
    qualification_identity, qualified = bind(args.qualification, args.qualification_sha256, json_value=True)
    verify_qualification(qualified)
    preparation_identity, preparation = bind(ROOT / "preparation.json", PREPARATION_SHA, json_value=True)
    verify_preparation(preparation, qualified, qualification_identity, terminal)
    for expected in ADDITIONAL_PREPARATION_BINDINGS:
        actual_preparation_input, _ = bind(Path(expected["path"]), expected["sha256"])
        need(actual_preparation_input == expected, "actual R36 preparation input differs")
    ci_identity, ci = bind(args.ci_manifest, CI_MANIFEST_SHA, json_value=True)
    workflow_identity, workflow_raw = bind(Path(CANONICAL_WORKFLOW["path"]), CANONICAL_WORKFLOW["sha256"], retain=True)
    private_workflow_identity, _ = bind(Path(PRIVATE_SOURCE_WORKFLOW["path"]), PRIVATE_SOURCE_WORKFLOW["sha256"])
    workflow_binding = verify_canonical_workflow(ci, workflow_identity, workflow_raw, private_workflow_identity)
    map_identity, source_map = bind(QUALIFICATION / "source-map.json", SOURCE_MAP_SHA, json_value=True)
    need(source_map == qualified["source_after"], "actual qualification source map differs")
    files = [SOURCE / name for name in ("Cargo.toml", "Cargo.lock", "rustfmt.toml")]
    for directory in ("src", "examples"):
        files.extend(path for path in (SOURCE / directory).rglob("*") if path.is_file())
    actual = {path.relative_to(SOURCE).as_posix(): bind(path)[0]["sha256"] for path in sorted(files)}
    need(actual == source_map, "actual compiler inputs differ from successful qualification01")
    harness = {path.name: bind(path)[0]["sha256"] for path in sorted((SOURCE / "tools/x230/20261028").glob("*.py"))}
    need(harness == qualified["harness_after"], "actual qualification harness differs")
    binaries = {}
    for name, expected in qualified["binaries"].items():
        path = Path(expected["path"])
        need(path == QUALIFICATION / name and os.access(path, os.X_OK), "qualified executable path differs")
        binaries[name] = bind(path, expected["sha256"])[0]

    summary_identity, summary = bind(QUALIFICATION / "isolated-tests/summary.json", ISOLATED_SUMMARY_SHA, json_value=True)
    need(PREPARATION_PROOF["tests"] == {key: summary[key] for key in ("passed", "failed", "ignored", "selected", "retries")}, "bound preparation tests differ from the actual isolated summary")
    audit_identity, audit = bind(QUALIFICATION / "isolated-tests.audit.json", ISOLATED_AUDIT_SHA, json_value=True)
    need(summary.get("schema") == "hepta-isolated-libtest/v1" and summary.get("success") is True
         and summary.get("filter") == "" and summary.get("enumeration_errors") == []
         and summary.get("retries") == 0 and summary.get("failed") == 0,
         "isolated suite must be complete, unfiltered, successful and unretried")
    need(audit.get("schema") == "hepta-isolated-libtest-audit/v1" and audit.get("success") is True
         and audit.get("errors") == [] and "fatal_error" not in audit and audit.get("expected_filter") == "",
         "independent isolated-suite audit did not pass")
    counts = {key: summary[key] for key in ("passed", "failed", "ignored", "selected", "retries")}
    need(all(type(value) is int and value >= 0 for value in counts.values())
         and counts["passed"] > 0 and counts["selected"] == counts["passed"] + counts["ignored"],
         "invalid complete test counts")
    need(counts == FROZEN_COUNTS,
         "full selected R36 suite counts differ")
    need(all(audit[key] == counts[key] for key in ("passed", "failed", "ignored", "selected"))
         and audit["executed"] == counts["passed"], "audited test counts differ")
    need(summary["source_manifest_path"] == str(QUALIFICATION / "source-map.json")
         and summary["source_manifest_sha256"] == map_identity["sha256"], "suite source binding differs")
    need(audit["input_sha256"]["summary.json"] == summary_identity["sha256"], "audited summary changed")
    for filename, digest in audit["input_sha256"].items():
        need(Path(filename).name == filename and filename not in {".", ".."}, "unsafe audit input name")
        bind(QUALIFICATION / "isolated-tests" / filename, digest)
    need(summary["artifacts_path"] == str(QUALIFICATION / "retained-artifacts.jsonl"), "Cargo artifact path differs")
    bind(QUALIFICATION / "retained-artifacts.jsonl", summary["artifacts_sha256"])
    target_inventory = []
    targets = {}
    for row in summary["binaries"]:
        path = Path(row["path"])
        need(path.parent == QUALIFICATION / "test-binaries", "retained test executable outside qualification01")
        test_binary = bind(path, row["sha256"])[0]
        target = {"target_name": row["target"]["name"], "target_kind": row["target"]["kind"]}
        need(str(path) not in targets, "duplicate test executable")
        targets[str(path)] = target
        target_inventory.append(dict(target, inventory_count=row["inventory_count"], ignored_names=row["ignored_names"], qualified_test_binary=test_binary))
    _, raw = bind(QUALIFICATION / "isolated-tests/tests.jsonl", audit["input_sha256"]["tests.jsonl"], retain=True)
    cases = []
    for line in raw.splitlines():
        row = json.loads(line)
        ignored = row["status"] == "ignored"
        need(row["status"] in {"passed", "ignored"} and row["attempt"] == (0 if ignored else 1)
             and row["executed"] is (not ignored), "invalid or retried case record")
        cases.append(dict(targets[row["binary"]], name=row["name"], ignored=ignored))
    cases.sort(key=lambda row: (row["target_name"], row["target_kind"], row["name"]))
    need(len(cases) == counts["selected"] and sum(row["ignored"] for row in cases) == counts["ignored"],
         "complete case ledger counts differ")
    need(len({(row["target_name"], tuple(row["target_kind"]), row["name"]) for row in cases}) == len(cases),
         "duplicate exact qualified case")

    for job_name in ("runtime-head-ci", "runtime-merge-ci"):
        commands = []
        for step in ci["workflow"]["jobs"][job_name]["steps"]:
            for line in step.get("run", "").replace("\\\n", " ").splitlines():
                if line.startswith("cargo check ") or line.startswith("cargo nextest run "):
                    commands.append({"workflow_step": step["name"], "argv": shlex.split(line)})
        need(commands == COMMANDS, "workflow Cargo check/nextest commands differ")
    nextest_identity, nextest = bind(NEXTEST_ROOT / "receipt.json", NEXTEST_RECEIPT_SHA, json_value=True)
    need(nextest.get("schema") == "hepta-r25-private-nextest-install-v1" and nextest.get("passed") is True
         and nextest["release_id"] == 329695549 and nextest["asset_id"] == 430502414
         and nextest["archive"]["sha256"] == "38fd6275e111b200bbbed1bd2ae91cbb0d7edd28504879875cff2b3d96f3f311"
         and nextest["nextest_version"]["returncode"] == 0
         and nextest["nextest_version"]["stdout"].startswith("cargo-nextest 0.9.137 (75ddba7e9 2026-05-26)"),
         "installed nextest receipt differs")
    need({key: nextest["binary"][key] for key in NEXTEST_BINARY} == NEXTEST_BINARY, "installed binary receipt differs")
    nextest_binary, _ = bind(Path(NEXTEST_BINARY["path"]), NEXTEST_BINARY["sha256"])
    need(nextest_binary == NEXTEST_BINARY and os.access(nextest_binary["path"], os.X_OK), "installed nextest binary differs")

    config_inventory = []
    for name in (".cargo/config", ".cargo/config.toml", ".config/nextest.toml", "rust-toolchain", "rust-toolchain.toml"):
        path = SOURCE / name
        config_inventory.append({"path": str(path), "exists": os.path.lexists(path),
                                 "identity": bind(path)[0] if os.path.lexists(path) else None})
    for expected in bindings:
        need(read_file(Path(expected["path"]))[0] == expected, "input changed before plan publication")
    for row in config_inventory:
        need(os.path.lexists(row["path"]) is row["exists"], "tool configuration appeared or disappeared")
    report = {
        "schema": "hepta-r36-materialized-exact-rust-ci-plan/v1", "attempt": "01",
        "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "executed": False, "hosted_actions_passed": False,
        "workflow_binding": workflow_binding,
        "preparation": preparation_identity,
        "qualification": qualification_identity, "qualification_terminal_status": terminal_identity,
        "qualification_job_id": JOB_ID, "source_map": map_identity,
        "source": str(SOURCE), "source_files": actual, "qualified_binaries": binaries,
        "qualification_harness": harness, "qualification_summary": summary_identity,
        "qualification_independent_audit": audit_identity, "qualification_counts": counts,
        "workflow_head": ci["head_commit"], "workflow_git_blob": ci["workflow_git_blob"], "ci_manifest": ci_identity,
        "commands": [dict(row, cwd=str(SOURCE)) for row in COMMANDS],
        "inventory_command": {"argv": INVENTORY_COMMAND, "cwd": str(SOURCE), "timeout_seconds": 900,
            "scope": "One unfiltered structured inventory; Cargo may build and test binaries execute --list, but no test case is executed by this command."},
        "nextest_install_receipt": nextest_identity, "nextest_binary": nextest_binary,
        "expected_nextest": {"passed": counts["passed"], "failed": 0, "skipped": counts["ignored"],
            "total": counts["selected"], "retries": 0, "test_target_inventory": target_inventory,
            "exact_cases": cases,
            "case_inventory_sha256": hashlib.sha256(json.dumps(cases, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
            "comparison": "Require full exact unfiltered case inventory and ignored set, plus footer counts; zero-test targets may be omitted from a runner's display, but no nonempty target or case may disappear."},
        "environment": {"PATH": str(NEXTEST_ROOT / "bin") + ":/home/qian/.cargo/bin:/usr/local/bin:/usr/bin:/bin",
            "RUSTUP_TOOLCHAIN": "1.95.0", "CARGO_HOME": "/home/qian/.cargo",
            "CARGO_TARGET_DIR": str(ROOT / "target-build"), "CARGO_BUILD_JOBS": "2", "CARGO_INCREMENTAL": "0",
            "CARGO_NET_OFFLINE": "true", "RUST_TEST_THREADS": "1", "TOKIO_WORKER_THREADS": "2",
            "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1",
            "CARGO_TERM_COLOR": "never", "NEXTEST_STATUS_LEVEL": "pass",
            "NEXTEST_FINAL_STATUS_LEVEL": "fail", "NEXTEST_SUCCESS_OUTPUT": "never"},
        "reporting_environment_note": "Pinned nextest0.9.137 supported reporting-only environment settings preserve original run argv, emit every completed success once, suppress successful test stdout and keep color-free evidence. They do not alter case selection, retries or execution concurrency.",
        "remove_environment_prefixes": ["HEPTA_", "SSH_", "RUST_TEST_", "NEXTEST_"],
        "remove_environment_keys": ["RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTDOCFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "PYTHONPATH", "PYTHONHOME", "RUST_LOG"],
        "tool_configuration_inventory": config_inventory, "umask": "0022", "input_bindings": bindings,
        "execution_contract": {"fresh_evidence_directory": str(ROOT / "rust-ci-01"), "automatic_retries": 0,
            "cargo_clean": False, "check_timeout_seconds": 1800, "nextest_timeout_seconds": 3600,
            "combined_timeout_seconds": 5400, "inventory_timeout_seconds": 900,
            "outer_budget_seconds": 6600, "retain_full_original_stdout_stderr": True,
            "no_extra_nextest_filters_or_weaker_flags": True, "no_candidate_workload_or_service_change": True,
            "exact_version_preflight": "Record cargo/rustc 1.95.0 and cargo nextest 0.9.137; verify which cargo-nextest resolves to the bound private binary.",
            "scheduling": "Run only after the bound original qualification01 terminal success, with no overlapping compiler or measurement campaign.",
            "ownership": "Record original Popen PID/birth/group, supervise and wait/reap only that owned process group; unknown cleanup or timed-out dispatch must be reconciled before any resubmission.",
            "identity": "Recheck every bound input and configuration presence immediately before and after; require unchanged source, retained qualified binaries and nextest executable.",
            "pass_requires": "Both exact commands exit0, no timeout or automatic retry, complete case/count match to actual qualified inventory, unchanged inputs, and original owned child/group absent."},
        "limits": ["External command evidence does not mark hosted GitHub Actions passed.",
            "Offline Cargo, private completed qualification01 target/cache and prebuilt pinned nextest are explicit environment differences from GitHub's online clean runner and cargo-install step.",
            "Publishing the tested source and prospective-merge Git tree binding remain separate.",
            "No measurement, deployment or candidate adoption is implied by materializing this plan."],
    }
    with args.out.open("x") as stream:
        json.dump(report, stream, sort_keys=True, indent=2)
        stream.write("\n")
    print(json.dumps({"plan": read_file(args.out)[0], "executed": False, "qualification_counts": counts}))


if __name__ == "__main__":
    main()

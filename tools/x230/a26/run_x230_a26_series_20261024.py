#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""One immutable A26 series; baseline failure never selects a passing comparison.

Run only on x230, after qualification and its independent successful receipt.
Frozen drivers own their entire stage and cleanup. Decisions are made after
driver exit, never by interrupting a stage on its first failed call. No trial,
RPC, launch, or canary is retried by this runner.
"""

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time


ROOT = Path("/home/qian/hepta-runtime-optimization-20261023")
ORIGINAL = Path("/home/qian/.local/state/hepta-runtime-native-dev-20261018/goal-20261023-a17-native-observation-r01")
HOSTS = {"ai395", "mac", "main", "pocket4", "rog", "x230"}
BASELINE_SHA256 = "727c4661450fdb2a2a44b63f7f9442a5cd20ad854f1c26b043ac710b6fa2ea06"
EXPECTED_HELPERS = {
    "x230_observation_benchmark.py": "efdf18dc4ded1193884cc7c529ca652ae22c1d7178e2fd29973463cceffa6db0",
    "x230_observation_fairness.py": "31fe9a9c44082d57f78cb75de060736eaffb1fa903532236071aab62508f30af",
    "x230_observation_soak.py": "9aed77048e91757034877c9d117781e6f36873db5c9e8d70fe0dfca76eb098ff",
    "x230_observation_soak_resources_20261024.py": "cae4325451ecfdd62842e2f13a3db880d21a76c95427472548434f324eb1ff46",
    "x230_controller_recovery_check.py": "24bf4c4b7ea8f5eea84e60ec87ffef93097866ef721ab2325ccd8c9905cc969b",
    "x230_native_lifecycle_canary.py": "4645e72113430a62d201f2d60ffcb7397ce127e994b351d187ad849203a9d2b6",
    "x230_six_running_recovery_canary.py": "817ba6a1ca8d1fca55e5bdc6a52b5e3d79c7a1e9a1615d46f8c646e8be21324a",
}
CAPACITY_ERROR = "observation pool capacity unavailable; no fallback or automatic retry"
QUAL_STAGES = ["format", "fmt-check", "clippy", "test", "release"]
CELL_NAMES = {"balanced", "hot_only", "skew"}
COVERAGE = ["C1", "C4", "C8", "C16", "fairness", "calibration", "soak", "completed_recovery", "single_running", "six_running"]
MAX_SOAK_CALLS = 60000
PROOF_PREFIX = b"HEPTA_X230_SPAWN_PROOF_FAILURE_JSON "
MAX_STDERR_SCAN = 1024 * 1024
BASELINE_ABORT_REASONS = {
    "six-host output preflight failed", "original readback failed after restart",
    "six-host warmup/output verification failed",
    "initial private session history differs from exactly six completed warmups",
    "wave metadata incomplete; stop without another admission/retry",
}


def need(value, reason):
    if not value:
        raise RuntimeError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def file_receipt(path):
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode), "non-regular or symlink input: " + str(path))
    digest, size = hashlib.sha256(), 0
    with path.open("rb") as source:
        opened = os.fstat(source.fileno())
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
            size += len(block)
        finished = os.fstat(source.fileno())
    after = path.lstat()
    def identity(row):
        return (row.st_dev, row.st_ino, row.st_mode, row.st_size, row.st_mtime_ns, row.st_ctime_ns)
    need(identity(before) == identity(opened) == identity(finished) == identity(after)
         and size == before.st_size, "input changed during complete hashing: " + str(path))
    return {"sha256": digest.hexdigest(), "bytes": size}


def source_map(root):
    result = {}
    for path in sorted(root.rglob("*")):
        need(not path.is_symlink(), "source/input tree contains a symlink")
        if path.is_file():
            result[str(path.relative_to(root))] = file_receipt(path)["sha256"]
    return result


def fsync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def save_new(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(canonical(value) + b"\n")
        output.flush()
        os.fsync(output.fileno())
    fsync_directory(path.parent)


def checkpoint(path, value):
    temporary = path.with_suffix(".next")
    save_new(temporary, value)
    os.replace(temporary, path)
    fsync_directory(path.parent)


def clean_shutdown(value):
    return (isinstance(value, dict) and value.get("exit_code") == 0
            and value.get("shutdown_method") == "stdin_eof"
            and value.get("observed_descendant_survivors") == []
            and value.get("reader_error") is None and "reader_error" in value
            and value.get("unmatched_responses") == 0)


def rows_ok(rows, count=None):
    return (isinstance(rows, list) and bool(rows) and (count is None or len(rows) == count)
            and all(isinstance(row, dict) and row.get("okay") is True for row in rows))


def capacity_refusal(row):
    return (row.get("okay") is False and row.get("isError") is True
            and row.get("native_error") == CAPACITY_ERROR and "rpc_error" not in row
            and row.get("automatic_retry") is False)


def observation_round(row, spec, allow_capacity):
    cells = row.get("cells", [])
    if (not rows_ok(row.get("initial_complete_outputs"), 6)
            or not rows_ok(row.get("restart_checks"), 12)
            or not clean_shutdown(row.get("shutdown"))
            or not clean_shutdown(row.get("restart_shutdown"))
            or len(cells) != len(spec["concurrency"])
            or [cell.get("concurrency") for cell in cells] != spec["concurrency"]):
        return False
    refused = 0
    for cell in cells:
        calls = cell.get("rows", [])
        if (len(calls) != spec["calls"] or cell.get("calls") != spec["calls"]
                or cell.get("successes") != sum(call.get("okay") is True for call in calls)
                or cell.get("no_success_filtering") is not True
                or not isinstance(cell.get("seconds"), (int, float)) or cell["seconds"] <= 0):
            return False
        for call in calls:
            if call.get("okay") is not True:
                if not (allow_capacity and capacity_refusal(call)):
                    return False
                refused += 1
    return row.get("passed") is (refused == 0)


def fairness_round(row):
    cells = row.get("cells", [])
    if (row.get("passed") is not True or not rows_ok(row.get("initial_complete_outputs"), 6)
            or not rows_ok(row.get("final_complete_outputs"), 6)
            or not rows_ok(row.get("metadata_observations"), 1)
            or not clean_shutdown(row.get("shutdown"))
            or row.get("private_originals_unchanged") is not True
            or len(cells) != 3 or {cell.get("name") for cell in cells} != CELL_NAMES
            or row.get("cell_order") != (["balanced", "hot_only", "skew"] if row.get("index", 0) % 2 == 0
                                         else ["skew", "hot_only", "balanced"])
            or [cell.get("name") for cell in cells] != row.get("cell_order")):
        return False
    for cell in cells:
        waves = cell.get("waves", [])
        if (cell.get("passed") is not True or cell.get("requested_waves") != 8
                or len(waves) != 8 or cell.get("calls") != 80 or cell.get("successes") != 80
                or cell.get("gate_failures") != 0 or cell.get("metadata_failures") != 0
                or cell.get("maximum_submitted_calls_per_wave") != 10
                or cell.get("native_gate_required_count") != 8 or cell.get("gate_budget_ms") != 120
                or [wave.get("index") for wave in waves] != list(range(8))):
            return False
        for wave in waves:
            if (not rows_ok(wave.get("rows"), 10) or not rows_ok(wave.get("metadata_observations"))
                    or any(wave.get(key) is not True for key in
                           ("passed", "gate_passed", "final_metadata_consistent", "all_final_metadata_completed"))
                    or wave.get("tail_calls_submitted") != 2):
                return False
    return True


def has_failed_observation(value):
    if isinstance(value, dict):
        if value.get("okay") is False or value.get("gate_passed") is False:
            return True
        return any(has_failed_observation(item) for item in value.values())
    return isinstance(value, list) and any(has_failed_observation(item) for item in value)


def attempted_round_clean(row, report, last, fairness):
    # A constructor without a startup receipt cannot establish owned-child cleanup.
    if not isinstance(row.get("startup"), dict):
        return False
    closing = [row.get("shutdown")]
    if not fairness and ("restart_startup" in row or "restart_shutdown" in row):
        if not isinstance(row.get("restart_startup"), dict):
            return False
        closing.append(row.get("restart_shutdown"))
    missing = [i for i, value in enumerate(closing) if value is None]
    if last and len(missing) == 1:
        closing[missing[0]] = report.get("interrupted_shutdown")
    return bool(closing) and all(clean_shutdown(value) for value in closing)


def assess_observation(report, spec, candidate_sha, baseline_sha, returncode):
    fairness = spec["kind"] == "fairness"
    rounds = report.get("rounds", [])
    roles = spec["role_by_slot"]
    expected_hashes = {slot: candidate_sha if role == "A26" else baseline_sha for slot, role in roles.items()}
    shared = []
    expected_schema = "hepta-x230-readonly-observation-" + ("fairness" if fairness else "abba") + "/v1"
    if (report.get("schema") != expected_schema or report.get("order") != spec["order"]
            or report.get("binary_sha256") != expected_hashes or report.get("tokio_workers") != 2
            or any(report.get(key) != 0 for key in ("effect_starts", "remote_mutation_tool_calls", "automatic_rpc_retries"))
            or any(report.get(key) is not True for key in ("source_originals_unchanged", "binary_hashes_unchanged"))):
        shared.append("report scope, binary, originals, or worker fence differs")
    if fairness:
        if (any(report.get(key) is not True for key in ("private_originals_unchanged", "current_agent_unchanged"))
                or report.get("waves_per_cell") != 8 or report.get("calls_per_wave") != 10
                or report.get("wave_retry_count") != 0):
            shared.append("fairness scope or final integrity differs")
    elif report.get("calls_per_cell") != spec["calls"] or report.get("concurrency") != spec["concurrency"]:
        shared.append("observation dimensions differ")
    if (not isinstance(rounds, list) or not rounds or len(rounds) > len(spec["order"])
            or [row.get("version") for row in rounds] != list(spec["order"][:len(rounds)])
            or [row.get("index") for row in rounds] != list(range(len(rounds)))):
        shared.append("missing or unexpected round sequence")
        rounds = []
    assessments = []
    for index, row in enumerate(rounds):
        role = roles[row["version"]]
        allow_capacity = spec.get("capacity_exception", False) and role == "A20"
        complete = fairness_round(row) if fairness else observation_round(row, spec, allow_capacity)
        assessments.append({"index": index, "slot": row["version"], "role": role,
                            "complete_for_scope": complete,
                            "has_failed_observation": has_failed_observation(row),
                            "cleanup_confirmed": attempted_round_clean(row, report, index == len(rounds) - 1, fairness)})
    if any(not row["cleanup_confirmed"] for row in assessments):
        shared.append("an attempted controller lacks clean EOF cleanup")
    if any(key in report for key in ("cleanup_error", "final_check_error", "report_save_error", "fallback_save_error",
                                      "source_originals_final_check_error", "binary_hashes_final_check_error")):
        shared.append("driver cleanup, final-check, or persistence failure")
    candidate = [row for row in assessments if row["role"] == "A26"]
    baseline_failed = [row for row in assessments if row["role"] == "A20" and not row["complete_for_scope"]]
    candidate_failed = any(not row["complete_for_scope"] for row in candidate)
    if any(not row["has_failed_observation"] for row in baseline_failed):
        shared.append("incomplete baseline round without a concrete failed observation")
    error = report.get("error")
    if error is not None:
        attributable = (assessments and assessments[-1]["role"] == "A20" and baseline_failed
                        and assessments[-1]["has_failed_observation"] and isinstance(error, dict)
                        and error.get("reason") in BASELINE_ABORT_REASONS)
        if not attributable:
            shared.append("driver error is not a recognized failed baseline observation")
    full = len(assessments) == len(spec["order"])
    expected_candidate_rounds = sum(roles[slot] == "A26" for slot in spec["order"])
    covered = (len(candidate) == expected_candidate_rounds and bool(candidate)
               and all(row["complete_for_scope"] for row in candidate))
    all_scope = full and all(row["complete_for_scope"] for row in assessments)
    if not baseline_failed and not candidate_failed and not all_scope:
        shared.append("incomplete stage without an attributable baseline failure")
    if all_scope and error is not None:
        shared.append("unexpected error accompanying otherwise complete rounds")
    if report.get("passed") is True and not all_scope:
        shared.append("raw passed flag contradicts complete coverage")
    capacity_refusals = sum(capacity_refusal(call) for row in rounds if roles[row["version"]] == "A20"
                           for cell in row.get("cells", []) for call in cell.get("rows", []))
    if all_scope and report.get("passed") is not (capacity_refusals == 0):
        shared.append("raw passed flag contradicts the exact capacity-refusal count")
    if returncode != (0 if report.get("passed") is True else 1):
        shared.append("driver return code contradicts final report")
    baseline_only = (bool(baseline_failed) or capacity_refusals > 0) and not candidate_failed and not shared
    return {"complete_for_scope": all_scope and not shared and not candidate_failed,
            "candidate_coverage_complete": covered and not shared and not candidate_failed,
            "candidate_not_exercised": not candidate, "candidate_failure": candidate_failed,
            "baseline_only_failure": baseline_only, "shared_failures": shared,
            "exact_A20_capacity_refusals": capacity_refusals,
            "rounds": assessments, "safe_to_continue": not shared and not candidate_failed
            and (all_scope or baseline_only)}


def assess_recovery(report, spec, candidate_sha, returncode):
    checks = {"raw_passed": report.get("passed") is True, "driver_returncode": returncode == 0,
              "no_report_error": not any(key in report for key in
                 ("error", "cleanup_error", "final_check_error", "report_save_error", "fallback_save_error")),
              "automatic_rpc_retries": report.get("automatic_rpc_retries") == 0}
    kind = spec["kind"]
    if kind == "completed_recovery":
        checks.update(schema=report.get("schema") == "hepta-x230-controller-abrupt-readonly-recovery/v1",
                      binary=report.get("binary_sha256") == candidate_sha and report.get("binary_hash_unchanged") is True,
                      before=rows_ok(report.get("before_checks"), 12), after=rows_ok(report.get("after_checks"), 12),
                      recovered=report.get("read_only_recovery_passed") is True,
                      descendants=report.get("descendant_observation", {}).get("all_sampled_descendants_exited") is True,
                      shutdown=clean_shutdown(report.get("recovery_shutdown")))
        checks["metadata"] = all(report.get(name, {}).get(key) is True
            for name in ("metadata_before_death", "metadata_after_death", "metadata_after_recovery", "metadata_final")
            for key in ("source_originals_unchanged", "private_originals_unchanged"))
    elif kind == "single_running":
        publication = report.get("terminal_publication_receipt", {})
        reuse = report.get("same_key_reuse", {})
        checks.update(schema=report.get("schema") == "hepta-x230-native-lifecycle-canary/v2",
                      binary=report.get("candidate_sha256") == candidate_sha,
                      calls=rows_ok(report.get("calls")), start_requests=report.get("job_start_requests") == 2,
                      execution_count=report.get("execution_count") == 1, stdin=report.get("stdin_bytes") == 4096,
                      original_reused=reuse.get("reused") is True and reuse.get("retried_launch") is False
                          and reuse.get("job_id") == report.get("job_id"),
                      publication=all(publication.get(key) is True for key in (
                          "strict_integer_protocol_verified", "request_exit_witness_identity_matches",
                          "status_matches_persisted_exit", "terminal_publication_confirmed")),
                      shutdown=clean_shutdown(report.get("shutdown")),
                      final_integrity=all(report.get(key) is True for key in (
                          "binary_unchanged", "source_record_unchanged", "current_agent_unchanged")))
    else:
        hosts = report.get("hosts", {})
        checks.update(schema=report.get("schema") == "hepta-six-running-controller-recovery/v1",
                      binary=report.get("candidate_sha256") == candidate_sha,
                      hosts=set(hosts) == HOSTS, native_calls=rows_ok(report.get("native_calls")),
                      ssh_calls=rows_ok(report.get("ssh_calls")), stdin=report.get("stdin_bytes") == 4096,
                      start_requests=report.get("new_start_call_count") == 6,
                      same_key_requests=report.get("same_key_lookup_call_count") == 6,
                      shutdown=clean_shutdown(report.get("shutdown")),
                      final_integrity=all(report.get(key) is True for key in (
                          "source_originals_unchanged", "binary_unchanged", "current_agent_unchanged",
                          "distinct_reported_hostnames", "controller_records_unchanged_after_shutdown")))
        checks["six_terminal_identities"] = set(hosts) == HOSTS and all(
            row.get("terminal", {}).get("execution_count") == 1
            and row.get("terminal", {}).get("original_identity_preserved") is True
            and row.get("terminal", {}).get("terminal_publication_confirmed") is True for row in hosts.values())
    accepted = bool(checks) and all(checks.values())
    return {"complete_for_scope": accepted, "candidate_coverage_complete": accepted,
            "candidate_failure": not accepted, "candidate_not_exercised": False,
            "baseline_only_failure": False, "safe_to_continue": accepted,
            "checks": checks, "shared_failures": [],
            "abrupt_cleanup_complete": report.get("abrupt_cleanup_complete")}


def collect_artifacts(directory):
    receipts, events, errors = {}, [], []
    if not directory.exists():
        return receipts, events, ["driver output directory is missing"]
    for path in sorted(directory.rglob("*")):
        if not path.is_file():
            continue
        relative = str(path.relative_to(directory))
        receipts[relative] = file_receipt(path)
        if path.name == "stderr.log":
            if receipts[relative]["bytes"] > MAX_STDERR_SCAN:
                errors.append("stderr exceeds bounded complete event scan: " + relative)
                continue
            for number, line in enumerate(path.read_bytes().splitlines(), 1):
                if PROOF_PREFIX in line:
                    slot = next((part.rsplit("-", 1)[-1] for part in path.parts
                                 if re.fullmatch(r"round-[0-9]+-[AB]", part)), "B")
                    events.append({"path": relative, "line": number, "slot": slot,
                                   "line_sha256": sha(line)})
    return receipts, events, errors


def private_records_match(directory, original_records, rounds):
    if not isinstance(rounds, list) or not rounds or len(original_records) != 6:
        return False
    expected = {"round-" + str(row["index"]) + "-" + row["version"] for row in rounds}
    if len(expected) != len(rounds) or {path.name for path in directory.glob("round-*")} != expected:
        return False
    for name in expected:
        folder = directory / name / "state/jobs"
        if not folder.is_dir() or folder.is_symlink() or folder.resolve() != folder:
            return False
        entries = list(folder.iterdir())
        if len(entries) != 6 or any(not stat.S_ISREG(path.lstat().st_mode) for path in entries):
            return False
        actual = {path.name: file_receipt(path)["sha256"] for path in entries}
        if actual != original_records:
            return False
    return True


def expected_stderr(report, spec):
    paths = []
    if spec["kind"] in ("observation", "fairness"):
        for row in report.get("rounds", []):
            base = "round-" + str(row["index"]) + "-" + row["version"]
            if "startup" in row:
                paths.append(base + ("/controller/stderr.log" if spec["kind"] == "fairness" else "/first/stderr.log"))
            if "restart_startup" in row:
                paths.append(base + "/restart/stderr.log")
    elif spec["kind"] == "completed_recovery":
        for field, folder in (("initial_startup", "before-death"), ("recovery_startup", "after-death")):
            if field in report:
                paths.append("fixture/" + folder + "/stderr.log")
    else:
        for field, folder in (("first_startup", "first-controller"), ("restart_startup", "restarted-controller")):
            if field in report:
                paths.append(folder + "/stderr.log")
    return paths


def wait_owned_driver(child, row):
    while True:
        if row["interrupted"] and not row["sigint_forwarded"]:
            row["sigint_forwarded"] = True
            try:
                child.send_signal(signal.SIGINT)
            except OSError as error:
                row["sigint_forward_error"] = {"type": type(error).__name__, "reason": str(error)}
        try:
            row["driver_returncode"] = child.wait()
            return
        except KeyboardInterrupt:
            row["interrupted"] = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qualification", type=Path, required=True)
    parser.add_argument("--qualification-receipt", type=Path, required=True)
    parser.add_argument("--suffix", default="r01")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--profile-template", type=Path, default=ORIGINAL / "ssh-profile/profile.json")
    parser.add_argument("--frozen-jobs", type=Path, default=ORIGINAL / "frozen-originals")
    parser.add_argument("--socket-parent", type=Path, default=Path("/home/qian/hx230-opt-20261023"))
    args = parser.parse_args()
    need(sys.platform == "linux" and args.root == ROOT and ROOT.resolve() == ROOT and ROOT.is_dir(),
         "frozen helpers require the original x230 development root")
    need(re.fullmatch(r"[A-Za-z0-9]{1,24}", args.suffix), "simple bounded output suffix required")
    qualification = json.loads(args.qualification.read_bytes())
    receipt = json.loads(args.qualification_receipt.read_bytes())
    qualification_hash = file_receipt(args.qualification)["sha256"]
    need(qualification.get("schema") == "runtime-candidate-qualification/v1"
         and qualification.get("qualified") is True
         and qualification.get("source_tested") == qualification.get("source_after")
         and bool(qualification.get("source_tested")), "successful immutable qualification required")
    need(receipt.get("schema") == "hepta-x230-qualification-independent-receipt/v1"
         and receipt.get("candidate") == "A26" and receipt.get("qualified") is True
         and receipt.get("source_report_sha256") == qualification_hash
         and receipt.get("success_checks_evaluated") is True
         and receipt.get("unmet_checks") == [] and bool(receipt.get("verification"))
         and all(value is True for value in receipt["verification"].values()),
         "successful independently bound A26 qualification receipt required")
    source = Path(qualification["source"])
    need(source.is_absolute() and source.is_relative_to(ROOT) and source.resolve() == source,
         "candidate source must remain in the private development root")
    candidate = Path(qualification["binary"]["path"])
    baseline = ROOT / "qualification-a20-r01/hepta-runtime"
    candidate_sha = qualification["binary"]["sha256"]
    need(candidate.is_absolute() and candidate.is_relative_to(ROOT)
         and file_receipt(candidate)["sha256"] == candidate_sha
         and file_receipt(baseline)["sha256"] == BASELINE_SHA256, "qualified candidate or A20 binary differs")
    need([stage.get("name") for stage in qualification.get("stages", [])] == QUAL_STAGES
         and all(type(stage.get("returncode")) is int and stage["returncode"] == 0
                 for stage in qualification["stages"]), "exact five successful qualification stages required")
    static_paths = [Path(__file__).absolute(), args.qualification, args.qualification_receipt,
                    candidate, baseline, args.profile_template]
    for key in ("binary", "test_binary"):
        binary = qualification[key]
        need(Path(binary["compiler_source"]) == source / "src/main.rs"
             and file_receipt(Path(binary["path"]))["sha256"] == binary["sha256"]
             and receipt[key].get("verified") is True
             and receipt[key].get("reported_sha256") == binary["sha256"], "independent binary binding differs")
        static_paths.append(Path(binary["path"]))
    for stage in qualification["stages"]:
        path = args.qualification.parent / (stage["name"] + ".log")
        need(file_receipt(path)["sha256"] == stage["log_sha256"], "qualification raw log differs")
        static_paths.append(path)
    for name, expected in EXPECTED_HELPERS.items():
        path = ROOT / name
        need(file_receipt(path)["sha256"] == expected, "frozen helper differs: " + name)
        static_paths.append(path)
    profile = json.loads(args.profile_template.read_bytes())
    for key in ("ssh_config", "known_hosts"):
        path = Path(profile[key])
        need(file_receipt(path)["sha256"] == profile[key + "_sha256"], "profile supporting file differs")
        static_paths.append(path)
    records = sorted(args.frozen_jobs.glob("*.json"))
    documents = [json.loads(path.read_bytes()) for path in records]
    need(len(records) == 6 and {doc.get("host") for doc in documents} == HOSTS,
         "exact six original host records required")
    original_records = {doc["id"] + ".json": file_receipt(path)["sha256"] for path, doc in zip(records, documents)}
    need(len(original_records) == 6, "original job identities are not distinct")
    x230_record = next(path for path, doc in zip(records, documents) if doc["host"] == "x230")
    held_agent = os.environ.get("SSH_AUTH_SOCK", "")
    need(held_agent.startswith("/"), "held parent SSH_AUTH_SOCK required")
    def snapshot():
        info = Path(held_agent).lstat()
        need(stat.S_ISSOCK(info.st_mode) and info.st_uid == os.getuid(), "held agent is not an owned socket")
        files = {str(path): file_receipt(path) for path in sorted(set(static_paths))}
        return {"source": source_map(source), "files": files, "frozen_jobs": source_map(args.frozen_jobs),
                "held_agent_socket_identity": [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid]}
    initial = snapshot()
    need(initial["source"] == qualification["source_tested"], "complete qualified source set/hash differs")
    map_sha = sha(canonical(initial["source"]))
    need(receipt.get("source", {}).get("actual_map_sha256") == map_sha,
         "independent source map binding differs")
    out = ROOT / ("a26-series-" + args.suffix)
    need(not os.path.lexists(out), "series directory must be create-only")
    common = ["--candidate", str(candidate), "--profile-template", str(args.profile_template),
              "--socket-parent", str(args.socket_parent), "--workers", "2"]
    def observation_arguments(standalone):
        return ["--baseline", str(candidate if standalone else baseline), *common,
                "--frozen-jobs", str(args.frozen_jobs)]
    specs = []
    def add(stage_id, kind, helper, standalone=False, order=None, calls=None, concurrency=None, condition="always"):
        value = {"stage_id": stage_id, "kind": kind, "helper": helper,
                 "output_directory": str(ROOT / (stage_id.replace("_", "-") + "-a26-" + args.suffix)),
                 "condition": condition, "role_by_slot": {"A": "A26" if standalone else "A20", "B": "A26"}}
        if order is not None:
            value.update(order=order, calls=calls, concurrency=concurrency)
        if kind == "fairness":
            value.update(waves=8, gate_budget_ms=120)
        specs.append(value)
        return value
    for kind, concurrency in (("standard", [1, 4, 8]), ("capacity", [16])):
        add(kind + "_compare", "observation", "x230_observation_benchmark.py", order="ABBA", calls=96,
            concurrency=concurrency, condition="comparison remains eligible")
        if kind == "capacity":
            specs[-1]["capacity_exception"] = True
        add(kind + "_candidate", "observation", "x230_observation_soak.py", True, "B", 96, concurrency,
            "baseline-only failure made comparison invalid and candidate coverage is missing")
    add("fairness_compare", "fairness", "x230_observation_fairness.py", order="ABBA",
        condition="comparison remains eligible")
    add("fairness_candidate", "fairness", "x230_observation_fairness.py", True, "ABBA",
        condition="comparison invalid and complete candidate fairness coverage is missing")
    add("calibration", "observation", "x230_observation_soak.py", True, "B", 192, [8])
    add("soak", "observation", "x230_observation_soak_resources_20261024.py", True, "B", None, [8])
    add("completed_recovery", "completed_recovery", "x230_controller_recovery_check.py", True)
    add("single_running", "single_running", "x230_native_lifecycle_canary.py", True)
    add("six_running", "six_running", "x230_six_running_recovery_canary.py", True)
    need(all(not os.path.lexists(spec["output_directory"]) for spec in specs), "all planned outputs must be new")
    out.mkdir(mode=0o700)
    save_new(out / "inputs-before.json", initial)
    plan = {"schema": "hepta-x230-a26-series-plan/v1", "created_unix": time.time(), "candidate": "A26",
            "runner_sha256": file_receipt(Path(__file__))["sha256"], "qualification_sha256": qualification_hash,
            "qualification_receipt_sha256": file_receipt(args.qualification_receipt)["sha256"],
            "inputs_before_sha256": file_receipt(out / "inputs-before.json")["sha256"],
            "source_map_sha256": map_sha, "source_file_count": len(initial["source"]),
            "candidate_sha256": candidate_sha, "baseline_sha256": BASELINE_SHA256,
            "helpers": EXPECTED_HELPERS, "specs": specs, "workers": 2,
            "automatic_rpc_retries": 0, "trial_retries": 0, "stop_boundary": "completed_driver_stage",
            "stop_rule": "After frozen driver exit and retained final report, any A26 failure or uncertain common integrity/cleanup stops every following stage. The frozen driver may finish its whole declared workload after a failed call.",
            "baseline_failure_rule": "Attributable A20-only observation failure permanently invalidates every performance comparison. After the current frozen driver exits, never start another stage containing A20; that driver may finish its declared A20 rounds. Run only predeclared missing candidate coverage with the frozen single-B soak helper or same-A26-binary fairness ABBA slots; preserve every failed comparison.",
            "capacity_exception": "Only exact native A20 capacity refusals in the C16 measured cell permit continuation for candidate validation; these also invalidate performance comparison and prohibit later A20 stages. Never accept a refusal in A26 or warmup/restart/fairness.",
            "fairness_same_binary_slots": "A/B are scheduling slots, both A26, with no version comparison.",
            "calibration_rule": "Always one independent A26-only C8 cell of 192 calls, not a selected successful comparison subset.",
            "soak_count_rule": "ceil(calibration successes / C8 cell seconds * 600 / 12) * 12; refuse if outside 12..60000; one run only",
            "soak_target_seconds": 600, "soak_minimum_cell_seconds": 540, "soak_maximum_calls": MAX_SOAK_CALLS,
            "resource_scope": "Retain the complete sampled timeline, cap flag and sampling errors. Missing/capped/errorful samples degrade resource evidence; sampling errors alone are not RPC failures or proof-event attribution.",
            "recovery_rule": "One completed-original recovery, one single-running lifecycle, one six-running canary; never reopen or retry failed canary jobs/keys.",
            "socket_residue_rule": "Preserve original completed-recovery abrupt_cleanup_complete separately; existing socket residue is not deleted or silently called complete cleanup.",
            "performance_adoption": "This runner makes no performance adoption decision.", "production_services_changed": False}
    save_new(out / "plan.json", plan)
    result = {"schema": "hepta-x230-a26-series-execution/v1", "started_unix": time.time(),
              "candidate": "A26", "runner_sha256": plan["runner_sha256"],
              "plan_sha256": file_receipt(out / "plan.json")["sha256"],
              "inputs_before_sha256": plan["inputs_before_sha256"], "qualification_sha256": qualification_hash,
              "qualification_receipt_sha256": plan["qualification_receipt_sha256"],
              "candidate_sha256": candidate_sha, "baseline_sha256": BASELINE_SHA256,
              "comparison_valid": False, "candidate_validation_passed": False,
              "comparison_invalid_reasons": [], "experiments": [], "completed": False,
              "coverage": {key: {"state": "not-run", "evidence_stage_ids": []} for key in COVERAGE},
              "stages": {spec["stage_id"]: {"state": "not-run", "reason": "conditional or not reached"} for spec in specs}}
    checkpoint(out / "series.json", result)
    by_id = {spec["stage_id"]: spec for spec in specs}
    comparison_eligible = True

    def mark(keys, stage_id):
        for key in keys:
            result["coverage"][key] = {"state": "passed", "evidence_stage_ids": [stage_id]}

    def run(stage_id, calls=None):
        spec = dict(by_id[stage_id])
        if calls is not None:
            spec["calls"] = calls
        need(snapshot() == initial, "qualification/source/binary/helper/profile/original/agent fence changed before stage")
        directory = Path(spec["output_directory"])
        need(not os.path.lexists(directory), "stage output appeared before its single execution")
        if spec["kind"] in ("observation", "fairness"):
            arguments = observation_arguments(spec["role_by_slot"]["A"] == "A26")
            if spec["kind"] == "fairness":
                arguments += ["--waves", "8", "--gate-budget-ms", "120"]
            else:
                arguments += ["--calls", str(spec["calls"]), "--concurrency", *map(str, spec["concurrency"])]
            arguments += ["--order", spec["order"]]
        else:
            arguments = [*common, *( ["--x230-record", str(x230_record)] if spec["kind"] == "single_running"
                                   else ["--frozen-jobs", str(args.frozen_jobs)] )]
        command = [sys.executable, str(ROOT / spec["helper"]), *arguments, "--out", str(directory)]
        row = {"stage_id": stage_id, "kind": spec["kind"], "spec": spec,
               "role_by_slot": spec["role_by_slot"], "order": spec.get("order"),
               "output_directory": str(directory), "command": command, "started_unix": time.time(),
               "driver_returncode": None, "interrupted": False, "sigint_forwarded": False,
               "report_path": str(directory / "report.json"), "raw_passed": None}
        result["stages"][stage_id] = {"state": "running"}
        checkpoint(out / "series.json", result)
        print(json.dumps({"starting_stage": stage_id, "role_by_slot": spec["role_by_slot"]}), flush=True)
        report = child = None
        try:
            with (out / (stage_id + ".stdout.log")).open("xb") as stdout, (out / (stage_id + ".stderr.log")).open("xb") as stderr:
                child = subprocess.Popen(command, stdout=stdout, stderr=stderr, start_new_session=True)
                wait_owned_driver(child, row)
                stdout.flush()
                stderr.flush()
                os.fsync(stdout.fileno())
                os.fsync(stderr.fileno())
            path = directory / "report.json"
            raw = path.read_bytes()
            row["report_sha256"] = sha(raw)
            report = json.loads(raw)
            need(isinstance(report, dict) and type(report.get("passed")) is bool
                 and isinstance(report.get("finished_unix"), (int, float))
                 and isinstance(report.get("started_unix"), (int, float))
                 and report["finished_unix"] >= report["started_unix"], "canonical final report is missing or unfinished")
            row["raw_passed"] = report["passed"]
            if spec["kind"] in ("observation", "fairness"):
                row["assessment"] = assess_observation(report, spec, candidate_sha, BASELINE_SHA256, row["driver_returncode"])
                need(private_records_match(directory, original_records, report.get("rounds")),
                     "private original record directory, exact file set, or bytes changed")
            else:
                row["assessment"] = assess_recovery(report, spec, candidate_sha, row["driver_returncode"])
            if stage_id == "soak":
                cells = [cell for rnd in report.get("rounds", []) for cell in rnd.get("cells", [])
                         if cell.get("concurrency") == 8]
                sustained = len(cells) == 1 and cells[0].get("seconds", 0) >= 540
                row["assessment"]["minimum_540_second_C8_cell"] = sustained
                resources = report.get("rounds", [{}])[0].get("shutdown", {}).get("resources", {})
                timeline = resources.get("timeline", [])
                row["assessment"]["resource_observation"] = {
                    "timeline_sample_count": len(timeline) if isinstance(timeline, list) else 0,
                    "timeline_capped": resources.get("timeline_capped"),
                    "sampling_error_count": resources.get("error_count"),
                    "observed_master_generation_count": len(resources.get("observed_master_generations", [])),
                    "sampled_lower_bound": True, "sampling_errors_are_not_RPC_failures": True,
                    "complete_sampled_resource_coverage": isinstance(timeline, list) and bool(timeline)
                    and resources.get("timeline_capped") is False and resources.get("error_count") == 0}
                if not sustained:
                    row["assessment"].update(safe_to_continue=False, complete_for_scope=False,
                                             candidate_coverage_complete=False, candidate_failure=True)
            need(not row["interrupted"], "interrupted driver completed cleanup; no following workload allowed")
        except BaseException as error:
            row["runner_error"] = {"type": type(error).__name__, "reason": str(error)}
            if child is not None:
                # Even an interrupt just after Popen returns must reach the
                # owned driver's actual exit before collecting its evidence.
                row["interrupted"] = row["interrupted"] or isinstance(error, KeyboardInterrupt)
                wait_owned_driver(child, row)
        finally:
            row["finished_unix"] = time.time()
            try:
                row["artifact_hashes"], events, collection_errors = collect_artifacts(directory)
                row["spawn_proof_events"] = events
                row["collection_errors"] = collection_errors
                if row.get("report_sha256") != row["artifact_hashes"].get("report.json", {}).get("sha256"):
                    collection_errors.append("canonical final report missing or changed after parsing")
                if not any(Path(name).name == "stderr.log" for name in row["artifact_hashes"]):
                    collection_errors.append("no native controller stderr evidence retained")
                required_stderr = expected_stderr(report, spec) if isinstance(report, dict) else []
                row["expected_controller_stderr"] = required_stderr
                for name in required_stderr:
                    if name not in row["artifact_hashes"]:
                        collection_errors.append("attempted controller stderr evidence missing: " + name)
                if any(Path(name).name != "report.json" and Path(name).name.startswith("report")
                       for name in row["artifact_hashes"]):
                    collection_errors.append("extra report/staging file means final persistence is uncertain")
                for event in events:
                    if spec["role_by_slot"].get(event["slot"]) != "A20":
                        collection_errors.append("candidate spawn-proof failure event retained")
                    elif row.get("assessment", {}).get("baseline_only_failure") is not True:
                        collection_errors.append("baseline proof event lacks matching baseline-only failure classification")
                row["inputs_after"] = snapshot()
                row["inputs_unchanged"] = row["inputs_after"] == initial
                row["driver_logs"] = {name: file_receipt(out / (stage_id + "." + name + ".log"))
                                      for name in ("stdout", "stderr")}
            except BaseException as error:
                row["final_collection_error"] = {"type": type(error).__name__, "reason": str(error)}
            accepted = ("runner_error" not in row and "final_collection_error" not in row
                        and row.get("inputs_unchanged") is True and not row.get("collection_errors")
                        and row.get("assessment", {}).get("safe_to_continue") is True)
            row["accepted_for_continuation"] = accepted
            save_new(out / (stage_id + ".receipt.json"), row)
            row["receipt_path"] = str(out / (stage_id + ".receipt.json"))
            row["receipt_sha256"] = file_receipt(Path(row["receipt_path"]))["sha256"]
            result["experiments"].append(row)
            result["stages"][stage_id] = {"state": "completed" if accepted else "failed",
                                         "raw_passed": row["raw_passed"], "accepted_for_continuation": accepted}
            checkpoint(out / "series.json", result)
        need(accepted, "stage failed or has uncertain shared integrity/cleanup: " + stage_id)
        return report, row

    try:
        for prefix, keys in (("standard", ["C1", "C4", "C8"]), ("capacity", ["C16"]), ("fairness", ["fairness"])):
            covered = False
            if comparison_eligible:
                report, row = run(prefix + "_compare")
                assessment = row["assessment"]
                if assessment["baseline_only_failure"]:
                    comparison_eligible = False
                    result["comparison_invalid_reasons"].append({"stage_id": row["stage_id"],
                        "reason": "exact A20 C16 capacity refusals" if assessment.get("exact_A20_capacity_refusals", 0)
                                  else "attributable A20-only observation failure",
                        "exact_A20_capacity_refusals": assessment.get("exact_A20_capacity_refusals", 0),
                        "action": "No further A20 stage, no successful-subset comparison; retain all raw observations."})
                covered = assessment["candidate_coverage_complete"]
                if covered:
                    mark(keys, row["stage_id"])
            if not covered:
                need(not comparison_eligible, "candidate comparison coverage unexpectedly incomplete")
                report, row = run(prefix + "_candidate")
                need(row["assessment"]["candidate_coverage_complete"], "standalone candidate coverage incomplete")
                mark(keys, row["stage_id"])
        result["comparison_valid"] = comparison_eligible
        calibration, row = run("calibration")
        mark(["calibration"], "calibration")
        cell = calibration["rounds"][0]["cells"][0]
        count = math.ceil(cell["successes"] / cell["seconds"] * 600 / 12) * 12
        need(12 <= count <= MAX_SOAK_CALLS, "calibrated count exceeds the immutable bounded plan")
        save_new(out / "soak-plan.json", {"calls": count, "concurrency": 8, "target_seconds": 600,
                 "minimum_cell_seconds": 540, "maximum_calls": MAX_SOAK_CALLS,
                 "basis_stage_id": "calibration", "basis_report_sha256": row["report_sha256"],
                 "basis_successes": cell["successes"], "basis_seconds": cell["seconds"], "trial_retries": 0})
        run("soak", count)
        mark(["soak"], "soak")
        for stage_id in ("completed_recovery", "single_running", "six_running"):
            run(stage_id)
            mark([stage_id], stage_id)
        result["completed"] = True
    except BaseException as error:
        result["error"] = {"type": type(error).__name__, "reason": str(error)}
        if not result["comparison_invalid_reasons"]:
            result["comparison_invalid_reasons"].append({"reason": "series stopped on candidate or shared failure; no adoption claim"})
        result["comparison_valid"] = False
    finally:
        try:
            after = snapshot()
            save_new(out / "inputs-after.json", after)
            result["inputs_after_sha256"] = file_receipt(out / "inputs-after.json")["sha256"]
            result["final_inputs_unchanged"] = after == initial
        except BaseException as error:
            result["final_inputs_unchanged"] = False
            result["final_error"] = {"type": type(error).__name__, "reason": str(error)}
        result["candidate_validation_passed"] = (result["completed"] and result["final_inputs_unchanged"]
            and set(result["coverage"]) == set(COVERAGE)
            and all(value["state"] == "passed" and bool(value["evidence_stage_ids"]) for value in result["coverage"].values()))
        result["comparison_valid"] = result["comparison_valid"] and result["candidate_validation_passed"]
        result["completed"] = result["candidate_validation_passed"]
        result["finished_unix"] = time.time()
        result["performance_adoption_decision"] = "not made by this runner"
        checkpoint(out / "series.json", result)
    print(json.dumps({"series": str(out / "series.json"), "comparison_valid": result["comparison_valid"],
                      "candidate_validation_passed": result["candidate_validation_passed"], "error": result.get("error")}), flush=True)
    return 0 if result["candidate_validation_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

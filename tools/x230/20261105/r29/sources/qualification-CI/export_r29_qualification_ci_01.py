#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Fixed R29 qualification/CI originals; XZ transport does not change any outcome."""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import traceback

ROOT = Path("/home/qian/hepta-runtime-optimization-20261105-r29")
STAGE_ROOT = Path("/home/qian/hepta-runtime-optimization-20261105-r25")
SOURCE = ROOT / "source"
CANDIDATE_DIR = ROOT / "qualification-01"
OUT = ROOT / "qualification-ci-evidence-01"
EXPORTER = STAGE_ROOT / "tools/export_r29_qualification_ci_01.py"
HELPER = STAGE_ROOT / "tools/r29_qualification_ci_stable_xz_01.py"
INPUT = STAGE_ROOT / "tools/r29-qualification-ci-export-input-01.json"
HELPER_SHA256 = "8b7aa7ef3b3772da13ea4f7009d8c478e0c92bc207d65db3f45c23453097d7a2"
ARCHIVE_NAME = "qualification-ci-01.tar.xz"
HEX = re.compile(r"[0-9a-f]{64}\Z")
JOB = re.compile(r"[0-9a-f]+-[0-9a-f]+-[0-9a-f]+\Z")
NATIVE_TERMINAL_STATES = {"succeeded", "failed", "cancelled", "timed_out", "effect_unknown"}
PRIVATE_NAMES = {"ssh_config", "known_hosts", "profile.json", "runtime.json"}
STAGES = ("qualification01", "rust_ci01", "python_ci01")
NATIVE_PATHS = {
    "qualification01": ROOT / "qualification-terminal-status-01.json",
    "rust_ci01": ROOT / "rust-ci-terminal-status-01.json",
    "python_ci01": ROOT / "python-ci-terminal-status-01.json",
}
REPORT_PATHS = {
    "qualification01": ROOT / "qualification-01/report.json",
    "rust_ci01": ROOT / "rust-ci-01/report.json",
    "python_ci01": ROOT / "python-ci-launch-01/receipt.json",
}
REPORT_SCHEMAS = {
    "qualification01": "hepta-x230-composed-qualification/v1",
    "rust_ci01": "hepta-r29-external-rust-ci/v1",
    "python_ci01": "hepta-r29-python-ci-one-time-launch-v1",
}
QUALIFICATION_STAGES = ("format", "fmt-check", "harness-tests", "clippy", "test-build", "isolated-tests", "audit-isolated-tests", "release")
DIRECTORIES = {
    "qualification": ROOT / "qualification-01",
    "rust-ci": ROOT / "rust-ci-01",
    "rust-ci-tools": ROOT / "rust-ci-tools-01",
    "python-ci01": ROOT / "python-ci-01",
    "python-launch01": ROOT / "python-ci-launch-01",
    "python-tools01": ROOT / "python-ci-tools-01",
    "published-python-inputs": STAGE_ROOT / "ci-gates",
}
OPTIONAL_TREES = {"rust-ci", "rust-ci-tools", "python-ci01", "python-launch01", "python-tools01"}
UNEXECUTED_OUTPUTS = {
    "rust_ci01": (ROOT / "rust-ci-01",),
    "python_ci01": (ROOT / "python-ci-launch-01", ROOT / "python-ci-01"),
}
ROOT_FILES = ("preparation-01.json", "qualification-input-01.json", "target-transfer-01.json",
              "rust-ci-plan-01.json", "rust-ci-tools-install-01.json", "python-ci-tools-install-01.json")
OPTIONAL_ROOT_FILES = {"rust-ci-plan-01.json", "rust-ci-tools-install-01.json", "python-ci-tools-install-01.json"}
QUALIFIER_ASSETS = (
    STAGE_ROOT / "tools/prepare_and_qualify_r29_01.py",
    STAGE_ROOT / "tools/r29-qualification-01-input.json",
    STAGE_ROOT / "tool-package-install-01.json",
    STAGE_ROOT / "ci-toolchain/nextest-0.9.137/receipt.json",
)

def need(value, reason):
    if not value:
        raise RuntimeError(reason)


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def descriptor(value, expected_path):
    need(isinstance(value, dict) and set(value) == {"path", "bytes", "sha256"}
         and value["path"] == str(expected_path)
         and type(value["bytes"]) is int and 0 <= value["bytes"] <= 16 * 1024**2
         and isinstance(value["sha256"], str) and HEX.fullmatch(value["sha256"]),
         "actual bounded input identity required: " + str(expected_path))
    return value


def validate_terminal(value, job_id):
    """Require an authoritative terminal, while preserving negative original fields."""
    need(value.get("job_id") == job_id and value.get("state") in NATIVE_TERMINAL_STATES,
         "same original authoritative native terminal required")
    need(value.get("terminal_publication_confirmed") is True
         and type(value.get("terminal_publication_protocol")) is int
         and value["terminal_publication_protocol"] == 1
         and value.get("automatic_retry") is False,
         "unresolved/retried original terminal cannot authorize stable evidence capture")
    need((type(value.get("exit_code")) is int or value.get("exit_code") is None)
         and all(type(value.get(key)) is bool for key in ("cancelled", "timed_out", "output_complete", "output_durable")),
         "native outcome fields are missing")
    if value["state"] == "succeeded":
        need(value["exit_code"] == 0 and value["cancelled"] is False and value["timed_out"] is False,
             "successful native state contradicts original flags")
    log_complete = value["output_complete"] and value["output_durable"]
    for stream in ("stdout", "stderr"):
        counts = value["log_bytes"][stream]
        need(type(counts.get("seen")) is int and type(counts.get("stored")) is int
             and 0 <= counts["stored"] <= counts["seen"], "invalid original log byte counts")
        need(type(value["log_synced"][stream]) is bool and type(value["log_truncated"][stream]) is bool
             and (value["log_errors"][stream] is None or isinstance(value["log_errors"][stream], str)),
             "invalid original log metadata")
        log_complete = (log_complete and value["log_synced"][stream]
                        and not value["log_truncated"][stream] and value["log_errors"][stream] is None
                        and counts["stored"] == counts["seen"])
    return {"state": value["state"], "exit_code": value["exit_code"],
            "cancelled": value["cancelled"], "timed_out": value["timed_out"],
            "native_logs_lossless_complete": bool(log_complete), "automatic_retry": False}


def omission_reason(path, group, identity):
    if identity["is_elf"]:
        return "ELF body omitted; complete observed file identity retained"
    if path.name in PRIVATE_NAMES or (path.parent.name == "bin" and path.name in ("ssh", "ssh-original")):
        return "private transport configuration or session wrapper body omitted; identity retained"
    if path.name in ("id_rsa", "id_ed25519", "id_ecdsa", "id_dsa") or path.suffix in (".key", ".pem", ".plist"):
        return "private credential or service configuration body is outside approved export scope"
    if path.name == "cargo-nextest-0.9.137.tar.gz.partial":
        return "verified upstream tool archive body omitted; recorded identity and install receipt retained"
    return None


def load_helper(digest):
    """Only the exact reviewed local helper definitions may be loaded."""
    need(isinstance(digest, str) and HEX.fullmatch(digest) and HELPER.resolve(strict=True) == HELPER,
         "fixed hash-bound archive helper required")
    fd = os.open(HELPER, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
             and before.st_nlink == 1 and before.st_size <= 128 * 1024,
             "unsafe archive helper")
        raw = b""
        while block := os.read(fd, 65536):
            raw += block
            need(len(raw) <= before.st_size, "archive helper grew")
        fields = ("st_dev", "st_ino", "st_uid", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        stamp = lambda item: tuple(getattr(item, key) for key in fields)
        need(len(raw) == before.st_size and stamp(before) == stamp(os.fstat(fd)) == stamp(HELPER.lstat())
             and hashlib.sha256(raw).hexdigest() == digest, "archive helper differs")
    finally:
        os.close(fd)
    # Execute the checked in-memory bytes, not a second path read after hashing.
    spec = importlib.util.spec_from_loader("r29_bound_stable_xz_archive", loader=None)
    module = importlib.util.module_from_spec(spec)
    module.__file__ = str(HELPER)
    exec(compile(raw, str(HELPER), "exec"), module.__dict__)
    return module


def validate_input(value):
    need(isinstance(value, dict) and value.get("schema") == "hepta-r29-qualification-ci-export-input/v1"
         and value.get("root") == str(ROOT) and value.get("actual_outcomes_supplied") is True
         and value.get("adoption_decision_made_here") is False
         and value.get("native_raw_companion_required") is True
         and set(value.get("stages", {})) == set(STAGES), "actual fixed R29 outcomes are required")
    for name in STAGES:
        row = value["stages"][name]
        need(isinstance(row, dict) and set(row) == {"executed", "job_id", "native_terminal", "report", "reason"}
             and type(row["executed"]) is bool, "unresolved or unexpected stage declaration: " + name)
        if row["executed"]:
            need(isinstance(row["job_id"], str) and JOB.fullmatch(row["job_id"]), "actual original native job required")
            descriptor(row["native_terminal"], NATIVE_PATHS[name])
            if row["report"] is not None:
                descriptor(row["report"], REPORT_PATHS[name])
                need(row["reason"] is None, "present original report retains its own outcome")
            else:
                need(isinstance(row["reason"], str) and row["reason"].strip(), "missing original report needs a reason")
        else:
            need(name in UNEXECUTED_OUTPUTS and row["job_id"] is row["native_terminal"] is row["report"] is None
                 and isinstance(row["reason"], str) and row["reason"].strip(), "known original operation may not be erased")
        if name == "qualification01":
            need(row["executed"] is True and row["report"] is not None,
                 "this fixed capture requires an actual complete R29 qualification")
    for key, path in (("preparation", ROOT / "preparation-01.json"),
                      ("source_map", ROOT / "qualification-01/source-map.json")):
        descriptor(value.get(key), path)
    return value["stages"]


def verify_r29_candidate_preparation(preparation, terminal, job_id, qualified, tests):
    """Verify actual R29 source/qualification/cache custody; never infer future passes."""
    import hashlib
    import json
    # Filled only from the reviewed final entry and its actual cache/QC/window
    # input. An unbound template cannot qualify any existing or future version.
    expected_launcher = {'path': '/home/qian/hepta-runtime-optimization-20261105-r25/tools/prepare_and_qualify_r29_01.py', 'bytes': 67635, 'sha256': '7ce339aa261fdf6acbc8e0ca8cf67f5c5d3a7b56fcc34d51ed4ee56ea4fe389a'}
    expected_input = {'path': '/home/qian/hepta-runtime-optimization-20261105-r25/tools/r29-qualification-01-input.json', 'bytes': 311502, 'sha256': '60bfe1ef593ad58d528f6e508d3f6e0a1e4f76183f1293b40f36b7ee6bb3f8a8'}
    need(isinstance(expected_launcher, dict) and isinstance(expected_input, dict),
         "R29 actual qualification entry/input identities remain unbound")
    need(isinstance(job_id, str) and re.fullmatch(r"[0-9a-f]{11,16}-[0-9a-f]{4}-[0-9a-f]{4}", job_id)
         and job_id not in {"1a1aa7fa690-fc05-43af", "1a1aaa6552d-fc05-459f", "1a1ab4cb0fc-fc05-4c3c",
                            "1a1ac274e49-fc05-5286", "1a1ac456b07-fc05-532a", "1a1ac5d5a29-fc05-53d9",
                            "1a1acfe317a-fc05-57ee"},
         "the actual new R29 qualification job is required")
    need(terminal.get("job_id") == job_id and terminal.get("state") == "succeeded"
         and type(terminal.get("exit_code")) is int and terminal["exit_code"] == 0
         and all(terminal.get(key) is False for key in ("automatic_retry", "timed_out", "cancelled"))
         and all(terminal.get(key) is True for key in ("output_complete", "output_durable", "terminal_publication_confirmed"))
         and type(terminal.get("terminal_publication_protocol")) is int and terminal["terminal_publication_protocol"] == 1
         and terminal.get("log_synced") == {"stdout": True, "stderr": True}
         and terminal.get("log_errors") == {"stdout": None, "stderr": None}
         and terminal.get("log_truncated") == {"stdout": False, "stderr": False},
         "original R29 qualification has no complete successful native terminal proof")
    for stream in ("stdout", "stderr"):
        counts = terminal["log_bytes"][stream]
        need(set(counts) == {"seen", "stored"} and all(type(value) is int and value >= 0 for value in counts.values())
             and counts["seen"] == counts["stored"], "qualification native log byte custody differs")
    need(preparation["schema"] == "hepta-r29-qualified-parent-preparation/v1"
         and preparation["selected_proposal"] == "shared unfiltered ToolRouter"
         and preparation.get("optional_pidfd_selected") is False and preparation.get("finished_utc")
         and all(preparation.get(key) is True for key in ("passed", "candidate_qualified", "parent_source_qualified",
             "parent_observation_rejection_preserved", "parent_inputs_unchanged", "cache_reused",
             "cache_source_source_qualified", "cache_moved_by_single_no_replace_rename"))
         and all(preparation.get(key) is False for key in ("candidate_adopted", "parent_candidate_adopted",
             "production_services_modified", "shared_hardlinks_created", "cache_copy_executed", "cache_cleanup_executed")),
         "actual R29 preparation is incomplete or changed the private cache scope")
    need(preparation["source"] == str(SOURCE) and preparation["target"] == str(ROOT / "target-build")
         and preparation["qualification_output"] == str(CANDIDATE_DIR)
         and preparation["launcher"] == expected_launcher and preparation["input"] == expected_input,
         "R29 qualification launcher, actual input or private paths differ")
    need(expected_launcher["path"] == "/home/qian/hepta-runtime-optimization-20261105-r25/tools/prepare_and_qualify_r29_01.py"
         and expected_input["path"] == "/home/qian/hepta-runtime-optimization-20261105-r25/tools/r29-qualification-01-input.json",
         "R29 entry belongs to another runtime attempt")
    source_cache = "/home/qian/hepta-runtime-optimization-20261105-r28/target-build"
    need(preparation["cache_source"] == source_cache and preparation["unchanged_disk_reserve_bytes"] == 3221225472
         and preparation["new_full_cache_copy_bytes"] == 0, "R29 cache reuse weakened allocation or reserve policy")
    admission = preparation["admission"]
    need(admission["original_failed_probe01_preserved_as_failed"] is True
         and admission["original_failed_probe01_error"] == {"type": "RuntimeError", "message": "directory outside exact task parent"}
         and admission["original_failed_probe01"]["job_id"] == "1a1acfe317a-fc05-57ee"
         and admission["original_failed_probe01"]["stdout_identity"] == {
             "bytes": 21898, "sha256": "7d96f345114fcad140b40f69804df679f68b8e67d57a1c46941d809cedb3c58f"}
         and admission["readonly_probe_does_not_authorize_transfer"] is True
         and admission["all_user_process_channels_readable_claimed"] is False,
         "original failed readonly probe or reference limits were promoted")
    need(admission["downloaded_QC_full_verification"] == {
        "bytes": 9585, "sha256": "7342eed4ed17389eb57f5f40111438c5c4e339591ebb77c450a4fb1fe3ae2614"}
         and admission["downloaded_QC_archive"] == {
        "bytes": 1915620, "sha256": "442586ded13a4cfde54531e6f05ddddcf26c2f53d40d15b04c5993ece5f04186"},
         "R28 full downloaded QC archive was not independently verified")
    writer = admission["root_writer_admission"]
    need(writer["schema"] == "hepta-r29-owned-cache-writer-admission/v1"
         and writer["source_cache"] == source_cache and writer["destination_cache"] == str(ROOT / "target-build")
         and writer["exclusive_compilation_window_held"] is True
         and writer["no_later_R28_cache_use_scheduled"] is True
         and writer["original_native_raw_custody_retained"] is True
         and writer["same_owner_unknowns_reviewed_without_claiming_all_channels_readable"] is True
         and writer["fd_and_mmap_reference_channels_not_covered"] is True
         and writer["root_reviewed_readonly_probe_stdout"] == admission["original_probe_stdout"]
         and writer["root_reviewed_downloaded_QC_verification"] == admission["downloaded_QC_full_verification"],
         "the actual root execution window is not bound to the preserved original evidence")
    transfer = preparation["cache_transfer"]
    need(transfer["schema"] == "hepta-r29-owned-cache-transfer/v1"
         and transfer["source_cache"] == source_cache and transfer["destination_cache"] == str(ROOT / "target-build")
         and transfer["root_writer_admission"] == writer and transfer["original_cache_probe"] == admission["original_probe_stdout"]
         and all(transfer.get(key) is True for key in ("passed", "rename_attempted", "rename_returned_success",
             "old_path_absent", "destination_is_original_inode", "descendants_metadata_unchanged"))
         and all(transfer.get(key) is False for key in ("copy_executed", "cleanup_executed", "automatic_retry", "automatic_rollback"))
         and transfer.get("finished_utc") and "error" not in transfer and "rename_errno" not in transfer,
         "the one original no-replace cache transfer did not close")
    before, immediate, after = (transfer[key] for key in ("metadata_before", "immediate_metadata_before", "metadata_after"))
    for row in (before, immediate, after):
        need(row["all_entries_traversed"] is True and row["all_regular_links_accounted_within_target"] is True
             and row["external_or_unaccounted_hardlink_inodes"] == 0 and row["retained_qualification_elf_aliases"] == []
             and row["anomaly_examples_maximum_32"] == []
             and all(row["counts"][key] == 0 for key in ("symlinks", "other_nonregular", "other_device_entries", "other_owner_entries")),
             "cache metadata escaped the original owned regular/directory scope")
    need(before["path"] == immediate["path"] == source_cache and after["path"] == str(ROOT / "target-build")
         and before["counts"] == immediate["counts"] == after["counts"]
         and before["root_identity"] == immediate["root_identity"]
         and before["metadata_sha256"] == immediate["metadata_sha256"]
         and before["descendants_metadata_sha256"] == immediate["descendants_metadata_sha256"] == after["descendants_metadata_sha256"],
         "cache descendants or pre-transfer identity changed")
    root_fields = ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_nlink", "st_size", "st_mtime_ns")
    need(all(immediate["root_identity"][key] == after["root_identity"][key] for key in root_fields)
         and after["root_identity"]["st_ctime_ns"] >= immediate["root_identity"]["st_ctime_ns"]
         and transfer["root_ctime_before"] == immediate["root_identity"]["st_ctime_ns"]
         and transfer["root_ctime_after"] == after["root_identity"]["st_ctime_ns"],
         "cache root identity changed beyond rename ctime")
    need(preparation["cache_bytes"] == before["counts"]["regular_logical_bytes"]
         and preparation["cache_file_count"] == before["counts"]["regular_files"], "cache size accounting differs")
    for scan in (preparation["cache_reference_scan_before_source"], transfer["immediate_reference_scan"]):
        need(scan["matched_live_processes"] == [] and scan["raw_argv_or_environment_or_unrelated_cwd_emitted"] is False,
             "an observed cache reference was ignored")
    for samples in (preparation["compiler_quiescence"], preparation["compiler_quiescence_immediately_before_move"]):
        need(isinstance(samples, list) and samples and samples[-1]["compiler_processes"] == [],
             "compiler quiet admission did not finish")
    for disk in (preparation["disk_after_fresh_source_before_move"], transfer["disk_before_move"],
                 preparation["disk_immediately_before_compiler"]):
        need(disk["unchanged_required_headroom_bytes"] == 3221225472
             and type(disk["available_bytes"]) is int and disk["available_bytes"] >= 3221225472
             and disk["new_full_cache_copy_bytes"] == 0 and disk["move_frees_bytes"] is False
             and disk["future_build_growth_guaranteed_to_fit"] is False,
             "the unchanged 3 GiB reserve was not checked at the actual admission boundaries")
    retained = preparation["retained_parent_ELFs_before"]
    need(len(retained) == 8 and len({row["path"] for row in retained}) == 8
         and retained == preparation["retained_parent_ELFs_after_qualification"]
         == transfer["retained_parent_ELFs_before"] == transfer["retained_parent_ELFs_after"],
         "the eight retained R28 ELF copies were not preserved")
    for row in retained:
        d = row["current_identity"]
        need(row["path"].startswith("/home/qian/hepta-runtime-optimization-20261105-r28/qualification-01/")
             and d["st_uid"] == 1000 and d["st_nlink"] == 1 and d["st_mode"] & 0o170000 == 0o100000
             and d["st_size"] == row["bytes"] and row["full_export_identity_unchanged"] is True
             and row["sha256_recomputed_by_this_metadata_probe"] is False and row["payload_read_bytes"] == 0,
             "an original retained ELF descriptor was substituted or reclassified")
    transfer_raw = (json.dumps(transfer, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
    need(preparation["cache_transfer_receipt"] == {"path": str(ROOT / "target-transfer-01.json"),
         "bytes": len(transfer_raw), "sha256": hashlib.sha256(transfer_raw).hexdigest()},
         "embedded transfer proof differs from the original closed receipt")
    expected_changes = [
        {"path": "src/mcp/server.rs", "before": {"bytes": 118630, "sha256": "875785604d51feba6b02fdf1a6699b8d361d065a44cc4ef7bee6f931521e7e71"},
         "after": {"bytes": 118947, "sha256": "e6f34ef9ace819f72ceafaeee40a957210362f87cc4317d6ebfe4b76ba2fa4d4"}},
        {"path": "src/mcp/server_tests.rs", "before": {"bytes": 38983, "sha256": "003fa3365b3af0302c4a8e19f9230cea35f3366878898c1cf0920b2b6d47cddb"},
         "after": {"bytes": 49832, "sha256": "f4dfdc9c26ef3fdbba4dd2b5d0cfe3f239230a43cb78162bbba21a1c0499cc7f"}}]
    need(preparation["source_changes"] == expected_changes, "R29 is not the exact selected two-file router change")
    before_map = preparation["source_before"]
    expected = dict(before_map)
    changed_paths = {change["path"] for change in expected_changes}
    need(len(before_map) == 221 and len(changed_paths) == 2, "R29 source/change inventory differs")
    for change in expected_changes:
        need(before_map[change["path"]] == change["before"]["sha256"], "R29 qualified parent preimage differs")
        expected[change["path"]] = change["after"]["sha256"]
    need(hashlib.sha256((json.dumps(before_map, sort_keys=True, indent=2) + "\n").encode()).hexdigest()
         == "da8cbdfef75c1c9fc5861e4fe0bd96aeb98f635e95fc122610021cd725db1d28",
         "the R29 parent is not the actual complete qualified R28 map")
    need(preparation["candidate_compilation_inputs"] == expected
         and hashlib.sha256((json.dumps(expected, sort_keys=True, indent=2) + "\n").encode()).hexdigest()
         == "ce3e814a7bfeb7f0d168782dc325e643550cc0c768b606d90c4d45693fbe4853",
         "R29 pre-format compilation input differs")
    stages = ["format", "fmt-check", "harness-tests", "clippy", "test-build", "isolated-tests", "audit-isolated-tests", "release"]
    need(qualified["schema"] == "hepta-x230-composed-qualification/v1" and qualified["qualified"] is True
         and qualified.get("finished_utc") and qualified["source"] == str(SOURCE)
         and qualified["jobs"] == 2 and qualified["service_changes"] is False
         and type(qualified["automatic_test_retries"]) is int and qualified["automatic_test_retries"] == 0
         and [row["name"] for row in qualified["stages"]] == stages
         and all(type(row["returncode"]) is int and row["returncode"] == 0 for row in qualified["stages"]),
         "all eight original R29 qualification stages must pass")
    need(qualified["source_input"] == expected and qualified["source_tested"] == qualified["source_after"] == preparation["source_tested"]
         and set(qualified["source_after"]) == set(expected)
         and all(qualified["source_after"][name] == value for name, value in expected.items() if name not in changed_paths),
         "actual formatted R29 source differs from its qualification")
    need(preparation["formatter_changed_paths"] == [name for name in expected if qualified["source_after"][name] != expected[name]]
         and qualified["harness_before"] == qualified["harness_after"] == preparation["harness_before"]
         and len(qualified["harness_after"]) == 19, "qualification formatter or original harness binding differs")
    counts = ("passed", "failed", "ignored", "selected", "retries")
    need(all(type(tests[key]) is int for key in counts) and [tests[key] for key in counts] == [1655, 0, 34, 1689, 0]
         and tests["success"] is True and tests["filter"] == "" and not tests["enumeration_errors"]
         and preparation["tests"] == tests and preparation["qualification_returncode"] == 0
         and preparation["automatic_test_retries"] == 0, "original full R29 isolated result is incomplete")
    new_names = ["mcp::server::server_tests::cached_router_keeps_mcp_sessions_and_teardown_independent",
                 "mcp::server::server_tests::cached_router_rechecks_runtime_mode_and_native_session_owner"]
    need([row["name"] for row in preparation["new_exact_tests"]] == new_names
         and all(row["status"] == "passed" and row["executed"] is True and row["attempt"] == 1
                 and row["exit_code"] == 0 and row["timed_out"] is False for row in preparation["new_exact_tests"]),
         "the two new original exact cases were not executed once successfully")
    need(preparation["qualification_argv"] == ["/usr/bin/python3", "-B", str(SOURCE / "tools/x230/20261028/qualify.py"),
         "--source", str(SOURCE), "--output", str(CANDIDATE_DIR), "--target", str(ROOT / "target-build"),
         "--cargo-home", "/home/qian/hepta-runtime-optimization-20261023/cargo-home-a32-a33-r02",
         "--jobs", "2", "--stage-timeout", "3600"], "the original qualification argv was weakened")
    return {"passed": True, "original_job_id": job_id, "selected_proposal": "shared unfiltered ToolRouter",
            "optional_pidfd_selected": False, "qualified_source_files": 221, "harness_files": 19, "stages": stages,
            "tests": {key: tests[key] for key in counts}, "candidate_adopted": False,
            "qualified_parent_R28_observation_rejection_preserved": True,
            "original_failed_readonly_probe01_preserved": True, "single_no_replace_cache_move_verified": True,
            "cache_copy_executed": False, "cache_cleanup_executed": False, "unchanged_disk_reserve_bytes": 3221225472}


def report_projection(value):
    if not isinstance(value, dict):
        return {"object": False, "original_value_type": type(value).__name__}
    keys = ("schema", "passed", "qualified", "finished_utc", "finished_unix", "error", "current_stage",
            "automatic_retries", "automatic_test_retries", "retry_count", "runner_returncode",
            "gates_executed", "failed_gates", "owned_children_closed", "source_inputs_unchanged",
            "original_preflight_failure_preserved", "original_preflight_failure")
    return {"object": True, **{key: value[key] for key in keys if key in value}}


def original_outcome(name, declaration, terminal, original):
    if not declaration["executed"]:
        return {"executed": False, "reason": declaration["reason"], "success_inferred": False}
    native = validate_terminal(terminal, declaration["job_id"])
    projection = report_projection(original)
    finished = (isinstance(original, dict)
                and ((isinstance(original.get("finished_utc"), str) and bool(original["finished_utc"].strip()))
                     or (type(original.get("finished_unix")) in (int, float) and original["finished_unix"] > 0)))
    schema_matches = isinstance(original, dict) and original.get("schema") == REPORT_SCHEMAS[name]
    flag = original.get("qualified" if name == "qualification01" else "passed") if isinstance(original, dict) else None
    positive = (native["state"] == "succeeded" and native["exit_code"] == 0
                and native["native_logs_lossless_complete"] and finished and schema_matches and flag is True)
    return {"executed": True, "job_id": declaration["job_id"], "native_outcome": native,
            "original_report": projection, "original_report_finished": bool(finished),
            "original_report_schema_matches": bool(schema_matches),
            "original_positive_report_and_closed_native": bool(positive),
            "original_report_absence_reason": declaration["reason"]}


def check_original_bindings(get_json, identities, stages, outcomes):
    """Original producer declarations and full source/log bodies; no tests are rerun."""
    def row(path):
        need(str(path) in identities, "required original body/identity absent: " + str(path))
        return identities[str(path)]
    def same(path, recorded):
        actual = row(path)
        need(actual["sha256"] == recorded["sha256"]
             and ("bytes" not in recorded or actual["bytes"] == recorded["bytes"]),
             "original producer recorded a different file: " + str(path))
    qualification = get_json(ROOT / "qualification-01/report.json")
    preparation = get_json(ROOT / "preparation-01.json")
    source_map = get_json(ROOT / "qualification-01/source-map.json")
    need(isinstance(qualification, dict) and qualification.get("qualified") is True
         and qualification.get("schema") == REPORT_SCHEMAS["qualification01"]
         and qualification.get("source") == str(SOURCE)
         and qualification.get("automatic_test_retries") == 0
         and [s["name"] for s in qualification["stages"]] == list(QUALIFICATION_STAGES)
         and all(s["returncode"] == 0 for s in qualification["stages"]), "original full qualification differs")
    need(isinstance(source_map, dict) and len(source_map) == 221
         and qualification["source_tested"] == qualification["source_after"] == source_map
         and preparation["source_tested"] == source_map
         and preparation["passed"] is True and preparation["candidate_qualified"] is True
         and preparation["selected_proposal"] == "shared unfiltered ToolRouter"
         and preparation["optional_pidfd_selected"] is False
         and preparation["parent_observation_rejection_preserved"] is True
         and preparation["parent_candidate_adopted"] is False,
         "original qualification/preparation/source lineage differs")
    for name, expected in source_map.items():
        need(not Path(name).is_absolute() and ".." not in Path(name).parts, "unsafe original compiler input")
        same(SOURCE / name, {"sha256": expected})
    harness = qualification["harness_before"]
    need(len(harness) == 19 and qualification["harness_after"] == harness == preparation["harness_before"],
         "original 19-file qualification harness differs")
    for name, expected in harness.items():
        need(Path(name).name == name, "unsafe harness name")
        same(SOURCE / "tools/x230/20261028" / name, {"sha256": expected})
    for stage in qualification["stages"]:
        out = "cargo-no-run.jsonl" if stage["name"] == "test-build" else stage["name"] + ".stdout"
        same(ROOT / "qualification-01" / out, {"sha256": stage["stdout_sha256"]})
        same(ROOT / "qualification-01" / (stage["name"] + ".stderr"), {"sha256": stage["stderr_sha256"]})
    for name, record in qualification["binaries"].items():
        need(record["path"] == str(ROOT / "qualification-01" / name), "qualified ELF path differs")
        same(Path(record["path"]), record)
        need(row(Path(record["path"]))["is_elf"] is True, "qualified executable is not an ELF")
    summary = get_json(ROOT / "qualification-01/isolated-tests/summary.json")
    audit = get_json(ROOT / "qualification-01/isolated-tests.audit.json")
    need(summary["success"] is True and audit["success"] is True
         and summary["passed"] == audit["passed"] == 1655
         and summary["failed"] == audit["failed"] == 0
         and summary["ignored"] == audit["ignored"] == 34
         and summary["selected"] == audit["selected"] == 1689 and summary["retries"] == 0,
         "original complete isolated-test counts differ")
    preparation_contract = verify_r29_candidate_preparation(
        preparation, get_json(NATIVE_PATHS["qualification01"]), stages["qualification01"]["job_id"], qualification, summary)
    same(ROOT / "qualification-01/report.json", preparation["qualification_report"])
    same(ROOT / "target-transfer-01.json", preparation["cache_transfer_receipt"])
    need(get_json(ROOT / "target-transfer-01.json") == preparation["cache_transfer"],
         "actual closed transfer receipt differs from the preserved preparation")
    same(ROOT / "qualification-01/isolated-tests/tests.jsonl", preparation["original_test_ledger"])
    need(preparation["original_test_ledger"]["sha256"] == audit["input_sha256"]["tests.jsonl"],
         "two new original cases are not bound to the full audited test ledger")
    isolated = ROOT / "qualification-01/isolated-tests"
    for filename, expected_sha in audit["input_sha256"].items():
        need(Path(filename).name == filename, "unsafe original isolated input name")
        same(isolated / filename, {"sha256": expected_sha})
    for command in audit["commands"]:
        filename = command["stdout_gzip"]
        need(Path(filename).name == filename and filename.count(".stdout.") == 1,
             "unsafe or unrecognized original case-log filename")
        same(isolated / filename, {"sha256": command["stdout"]["gzip_sha256"]})
        same(isolated / filename.replace(".stdout.", ".stderr."),
             {"sha256": command["stderr"]["gzip_sha256"]})
    for binary in audit["binaries"]:
        path = Path(binary["path"])
        need(path.parent == ROOT / "qualification-01/test-binaries"
             and binary["recorded_before_sha256"] == binary["current_after_sha256"],
             "original retained test ELF path/hash differs")
        same(path, {"sha256": binary["current_after_sha256"]})
        need(row(path)["is_elf"] is True, "original retained test executable is not ELF")
    for prep in (preparation,):
        for key in ("launcher", "input"):
            original = prep[key]
            need(Path(original["path"]) in QUALIFIER_ASSETS, "original qualifier asset escaped scope")
            same(Path(original["path"]), original)
    rust_positive = outcomes["rust_ci01"].get("original_positive_report_and_closed_native") is True
    python_positive = outcomes["python_ci01"].get("original_positive_report_and_closed_native") is True
    if rust_positive:
        rust = get_json(ROOT / "rust-ci-01/report.json")
        need(rust["schema"] == REPORT_SCHEMAS["rust_ci01"] and rust["passed"] is True
             and rust["automatic_retries"] == 0 and rust["owned_children_closed"] is True
             and rust["source_inputs_unchanged"] is True and len(rust["stages"]) == 6,
             "original exact Rust CI result differs")
        for name in ("launcher", "materializer", "auditor", "plan"):
            recorded = rust[name]
            path = Path(recorded["path"])
            need(path.parent == ROOT / "rust-ci-tools-01" or path == ROOT / "rust-ci-plan-01.json",
                 "original Rust CI tool escaped fixed scope")
            same(path, recorded)
        for stage in rust["stages"]:
            need(stage["returncode"] == 0 and stage["passed"] is True, "original Rust CI stage failed")
            for stream in ("stdout", "stderr"):
                record = stage[stream]
                need(Path(record["path"]).parent == ROOT / "rust-ci-01", "Rust CI stream escaped fixed scope")
                same(Path(record["path"]), record)
        n = rust["nextest_output_audit"]
        need(n["verified"] is True and n["passed"] == 1655 and n["failed"] == 0 and n["ignored"] == 34
             and n["selected"] == 1689 and n["retries"] == 0 and n["success_status_counts"] == {"PASS": 1655},
             "original exact nextest output audit differs")
    manifest = get_json(STAGE_ROOT / "ci-gates/ci-gate-manifest.json")
    same(STAGE_ROOT / "ci-gates/ci-gate-manifest.json",
         {"sha256": "bf0df5f7d19ebd149854fbf75887fb0fb136f18a63a0c240abf8420655fb195e"})
    need(len(manifest["input_files"]) == 85 and len(manifest["python_gates"]) == 18,
         "original Python workflow/dependency inventory differs")
    for item in manifest["input_files"]:
        same(STAGE_ROOT / "ci-gates/ci-inputs" / item["path"], item)
    for kind in ("rust", "python"):
        if str(ROOT / (kind + "-ci-tools-install-01.json")) not in identities:
            continue
        installed = get_json(ROOT / (kind + "-ci-tools-install-01.json"))
        destination = ROOT / (kind + "-ci-tools-01")
        need(installed["passed"] is True and installed["destination"] == str(destination)
             and installed["original_file_count"] == len(installed["files"]) == 5,
             "original five-file tool installation differs")
        for filename, pin in installed["files"].items():
            need(Path(filename).name == filename, "unsafe original tool name")
            same(destination / filename, pin)
    for name in ("python_ci01",):
        if not stages[name]["executed"]:
            continue
        if stages[name]["report"] is None:
            continue
        try:
            parent = get_json(REPORT_PATHS[name])
        except (ValueError, UnicodeError):
            continue
        terminal = validate_terminal(get_json(NATIVE_PATHS[name]), stages[name]["job_id"])
        if terminal["state"] != "succeeded" or terminal["exit_code"] != 0:
            continue
        if not isinstance(parent, dict) or parent.get("passed") is not True:
            continue
        attempt = "01"
        report = get_json(ROOT / ("python-ci-" + attempt) / "report.json")
        same(ROOT / ("python-ci-launch-" + attempt) / "runner.stdout.log", parent["runner_stdout"])
        same(ROOT / ("python-ci-launch-" + attempt) / "runner.stderr.log", parent["runner_stderr"])
        same(ROOT / ("python-ci-" + attempt) / "report.json", parent["report"])
        need(parent["runner_returncode"] == 0 and parent["retry_count"] == 0
             and report["passed"] is True and report["retry_count"] == 0
             and len(report["gates"]) == 18 and all(g["passed"] is True for g in report["gates"])
             and report["manifest_sha256"] == "bf0df5f7d19ebd149854fbf75887fb0fb136f18a63a0c240abf8420655fb195e"
             and report["final_inputs_unchanged"] is True, "Python positive original lacks its complete 18-command result")
        for gate, expected_gate in zip(report["gates"], manifest["python_gates"], strict=True):
            need({key: gate.get(key) for key in ("id", "argv", "workflow_step")} == expected_gate
                 and gate["returncode"] == 0, "original Python gate command or result differs")
            for stream in ("stdout", "stderr"):
                filename = gate[stream + "_file"]
                need(isinstance(filename, str) and Path(filename).name == filename
                     and filename == gate["id"] + "." + stream,
                     "unsafe or different original Python gate stream name")
                same(ROOT / ("python-ci-" + attempt) / filename,
                     {"bytes": gate[stream + "_bytes"], "sha256": gate[stream + "_sha256"]})
    return {"qualified_compiler_inputs": 221, "qualification_harness_inputs": 19,
            "qualification_stages": 8, "isolated_passed": 1655, "isolated_ignored": 34,
            "isolated_failed": 0, "isolated_retries": 0, "preparation_contract": preparation_contract,
            "exact_Rust_CI_stages": 6 if rust_positive else None,
            "nextest_plain_PASS": 1655 if rust_positive else None,
            "nextest_ignored": 34 if rust_positive else None,
            "nextest_retries": 0 if rust_positive else None,
            "published_Python_dependencies_preserved": 85,
            "published_Python_workflow_commands": 18,
            "actual_positive_Python_commands": 18 if python_positive else None,
            "original_Rust_CI_positive_producer_bindings_verified": rust_positive,
            "original_Python_CI_positive_producer_bindings_verified": python_positive,
            "negative_or_unexecuted_CI_outcomes_preserved": True, "tests_reexecuted": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exporter-sha256", required=True)
    parser.add_argument("--archive-helper-sha256", required=True)
    parser.add_argument("--input-sha256", required=True)
    args = parser.parse_args()
    need(sys.platform == "linux" and os.geteuid() != 0 and Path(__file__).resolve() == EXPORTER,
         "fixed native operator exporter path required")
    need(args.archive_helper_sha256 == HELPER_SHA256, "reviewed archive helper pin differs")
    helper = load_helper(args.archive_helper_sha256)
    source_identity = helper.read(EXPORTER)[0]
    need(HEX.fullmatch(args.exporter_sha256) and source_identity["sha256"] == args.exporter_sha256,
         "actual exporter source differs")
    input_identity, input_raw = helper.read(INPUT, retain=True)
    need(HEX.fullmatch(args.input_sha256) and input_identity["sha256"] == args.input_sha256, "actual input differs")
    value = json.loads(input_raw)
    declarations = validate_input(value)
    helper.direct(ROOT)
    need(stat.S_ISDIR(ROOT.lstat().st_mode) and ROOT.lstat().st_uid == os.geteuid()
         and not os.path.lexists(OUT), "fresh fixed owned evidence output required")
    OUT.mkdir(mode=0o700)
    report = {"schema": "hepta-r29-qualification-ci-evidence-export/v1", "passed": False,
              "started_utc": utc(), "exporter": source_identity, "input": input_identity,
              "archive_helper": helper.read(HELPER)[0], "original_outcomes": {}, "archive": None,
              "no_workload_executed": True, "automatic_retries": 0, "candidate_adopted": False,
              "performance_or_lifecycle_result_inferred": False, "hosted_actions_passed_inferred": False,
              "native_original_raw_companion_required": True}
    identities, payloads, omitted, inventories, absent = {}, {}, {}, {}, []
    def remember(record):
        key = record["source_path"]
        need(key not in identities or identities[key] == record, "original changed between reads")
        identities[key] = record
        return record
    def expect_absent(path):
        need(not os.path.lexists(path), "declared absent original output now exists: " + str(path))
        absent.append(str(path))
    def include(path, name, scan=False):
        helper.safe_name(name)
        need(name not in payloads and name not in omitted, "duplicate archive member")
        identity = remember(helper.read(path)[0])
        reason = omission_reason(path, "qualification_ci", identity)
        # ELF/config classification deliberately precedes text marker scanning.
        if reason:
            omitted[name] = {"identity": identity, "reason": reason}
        else:
            if scan:
                remember(helper.read(path, expected=identity, scan_private_markers=True)[0])
            payloads[name] = identity
        return identity
    def bound(pin):
        identity, raw = helper.read(Path(pin["path"]), retain=True)
        need(all(identity[k] == pin[k] for k in ("bytes", "sha256")), "actual original receipt identity differs")
        remember(identity)
        return raw
    def get_json(path):
        record, raw = helper.read(path, retain=True, expected=identities.get(str(path)))
        remember(record)
        return json.loads(raw)
    try:
        for name in STAGES:
            row = declarations[name]
            if not row["executed"]:
                for path in (NATIVE_PATHS[name],) + UNEXECUTED_OUTPUTS[name]:
                    expect_absent(path)
                report["original_outcomes"][name] = original_outcome(name, row, None, None)
                continue
            terminal = json.loads(bound(row["native_terminal"]))
            original = None
            if row["report"] is None:
                expect_absent(REPORT_PATHS[name])
            else:
                raw = bound(row["report"])
                try:
                    original = json.loads(raw)
                except (ValueError, UnicodeError):
                    original = None
            report["original_outcomes"][name] = original_outcome(name, row, terminal, original)
            include(NATIVE_PATHS[name], "native-terminals/" + NATIVE_PATHS[name].name)
        need(report["original_outcomes"]["qualification01"]["original_positive_report_and_closed_native"] is True,
             "actual complete qualification and its original strong terminal are required")
        for label, directory in DIRECTORIES.items():
            if not os.path.lexists(directory):
                need(label in OPTIONAL_TREES, "required original directory is absent: " + label)
                expect_absent(directory)
                continue
            snapshot = helper.listing(directory)
            inventories[str(directory)] = snapshot
            for pathname in snapshot["files"]:
                path = Path(pathname)
                include(path, label + "/" + path.relative_to(directory).as_posix(),
                        label in {"qualification", "rust-ci", "python-ci01", "python-launch01"})
        for filename in ROOT_FILES:
            path = ROOT / filename
            if not os.path.lexists(path):
                need(filename in OPTIONAL_ROOT_FILES, "required fixed root evidence absent: " + filename)
                expect_absent(path)
            else:
                include(path, "root-receipts/" + filename)
        for path in QUALIFIER_ASSETS:
            include(path, "fixed-support/" + path.name)
        for pin in (value["preparation"], value["source_map"]):
            bound(pin)
        source_map = get_json(ROOT / "qualification-01/source-map.json")
        qualification = get_json(ROOT / "qualification-01/report.json")
        for relative in sorted(source_map):
            helper.safe_name(relative)
            include(SOURCE / relative, "qualified-source/" + relative)
        for filename in sorted(qualification["harness_before"]):
            need(Path(filename).name == filename, "unsafe original harness filename")
            include(SOURCE / "tools/x230/20261028" / filename, "qualification-harness/" + filename)
        include(EXPORTER, "capture-tools/export_r29_qualification_ci_01.py")
        include(HELPER, "capture-tools/stable_xz_archive.py")
        include(INPUT, "capture-tools/actual-input.json")
        bindings = check_original_bindings(get_json, identities, declarations, report["original_outcomes"])
        manifest = {"schema": "hepta-r29-qualification-ci-archive-manifest/v1", "root": str(ROOT),
                    "archive_name": ARCHIVE_NAME, "exporter": source_identity,
                    "archive_helper": report["archive_helper"], "input": input_identity,
                    "declarations": declarations, "original_outcomes": report["original_outcomes"],
                    "original_bindings": bindings, "payloads": payloads, "omissions": omitted,
                    "fixed_directory_inventories": inventories, "observed_absent_paths": sorted(set(absent)),
                    "exact_original_bytes_preserved": True, "compiler_cache_body_outside_scope": str(ROOT / "target-build"),
                    "external_parent_bindings_recorded_in_original_preparation": True,
                    "external_parent_bodies_reaudited_here": False, "native_original_raw_companion_required": True,
                    "performance_and_lifecycle_outside_this_fixed_scope": True, "candidate_adopted": False}
        raw, archive_proof = helper.write_archive(OUT / ARCHIVE_NAME, manifest, payloads,
            secret_prefixes=("qualification/", "rust-ci/", "python-ci01/", "python-launch01/"))
        helper.create(OUT / "manifest.json", raw)
        report["manifest"] = helper.read(OUT / "manifest.json")[0]
        report["archive"] = archive_proof
        report["transfer"] = helper.transfer_chunks(OUT / ARCHIVE_NAME, OUT)
        for pathname, expected in identities.items():
            helper.read(Path(pathname), expected=expected)
        for pathname, expected in inventories.items():
            need(helper.listing(Path(pathname)) == expected, "fixed original inventory changed during capture")
        for pathname in absent:
            need(not os.path.lexists(pathname), "original absent path appeared during capture")
        report.update(passed=True, original_bindings=bindings, payload_count=len(payloads),
                      omission_count=len(omitted), original_inputs_unchanged=True,
                      original_negative_outcomes_preserved=True)
    except Exception as error:
        report["error"] = {"type": type(error).__name__, "message": str(error), "traceback": traceback.format_exc()}
    report["finished_utc"] = utc()
    helper.create(OUT / "report.json", helper.encode(report))
    report_identity = helper.read(OUT / "report.json")[0]
    print(json.dumps({"report": report_identity, "passed": report["passed"],
                      "candidate_adopted": False, "no_workload_executed": True}), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())



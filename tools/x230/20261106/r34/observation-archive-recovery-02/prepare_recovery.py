#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Create collector02 from original failed collector01 and actual old receipts.

This executes static file/identity/source checks only. It does not execute an
installer, collector, auditor, lifecycle materializer, measurement or compiler.
"""
import ast
import hashlib
import json
import os
from pathlib import Path
import pprint

HERE = Path(__file__).resolve().parent
BASE = HERE.parent
ROOT = "/home/qian/hepta-runtime-optimization-20261106-r34"
OLD_SOURCE = BASE / "r34-observation-archive-template-01/sealed-01/archive_r34_observation.py"
OLD_SHA = "dfe08662dd65995a0e27edc6c06bf4e1754a1fc936a81c10657f2ff4e8c1695b"
ORIGINALS = BASE / "r34-observation-archive-failure-01"
FAILURE_JOB = "1a1af44cd02-fc05-6739"
DIAGNOSTIC_JOB = "1a1af47b4a8-fc05-674c"
CORRECTIONS = {
    "lifecycle-tools-01/run_lifecycle_abba_01.py": {
        "bytes": 14787, "inherited_r33_sha256": "574c4eedf2688eb1786a60dcc1c96a9f2f61ffee46778ad457257f535fd31940",
        "actual_r34_sha256": "3ae83b59414edd39f98f489ea0e60722bd59715e782a30b1f47a323460e48fff"},
    "lifecycle-tools-01/run_six_host_cancel_recovery_timed.py": {
        "bytes": 30163, "inherited_r33_sha256": "ac4b39f797f4311e6b63393cd12dc799956f1eaf713fc269f6c9b995515f2141",
        "actual_r34_sha256": "e0f2f2bc9e3656da2d941936f572d24001a340c4ab6219de37991b998ef21a86"},
    "lifecycle-tools-01/lifecycle-tools-manifest-01.json": {
        "bytes": 4066, "inherited_r33_sha256": "00100ba87ab41ac3fb415ca38957590a085d925086ac8ab607475c891326760d",
        "actual_r34_sha256": "86522df4c3a9870bc877f208f774c4f7e8cafc9560df658dd8048b3700be1c40"},
}
FILE_PINS = {
    "archive-failed-native-01.json": "05e63545e78aac2ca96451fe6964daa6ad2d88c3bc6bc5912dc81e8bd8e922ad",
    "archive-failed-read-01.json": "cd9042a81f3641250584347eafc4c166e8b010888edb3a6db2a62b3a21b4f0bf",
    "observation-archive-pin-diagnostic-01.json": "a30b955e31f142c7e833c006138bc434e14e1c4eda3bb8bb11bb211de528cb30",
    "parent-tools-install-01.json": "b783a85e4b41e5202305b7739e63eace75c71d4ea65f14fcbe7d05e5ceef30a2",
    "diagnostic-native-01.json": "e9ecdbcafd046c1cd9fbaad1d92ea864720a29da7202f50a51564196923f9000",
    "diagnostic-read-01.json": "8621911e4238793689b9c6af46b18fd82b339998fed5931cba38adb341e01af2",
    "pin-diagnostic.py": "757ad12a1244d871e7cae72fecd754c8fc53cb9be833451518fb89d95ca18fb7",
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def create(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def streams(native, read, job, code):
    assert native["job_id"] == read["job_id"] == job and native["exit_code"] == code
    assert native["state"] == ("succeeded" if code == 0 else "failed")
    assert native["terminal_publication_confirmed"] and native["output_complete"] and native["output_durable"]
    assert native["automatic_retry"] is False and native["timed_out"] is False and native["cancelled"] is False
    assert native["log_errors"] == {"stdout": None, "stderr": None}
    assert native["log_synced"] == {"stdout": True, "stderr": True}
    assert native["log_truncated"] == {"stdout": False, "stderr": False}
    result = {}
    for name in ("stdout", "stderr"):
        row = read[name]
        raw = bytes.fromhex(row["bytes_hex"])
        assert row["offset"] == 0 and row["size"] == row["next_offset"] == len(raw) and row["eof"] is True
        assert raw == row["text"].encode() and native["log_bytes"][name] == {"seen": len(raw), "stored": len(raw)}
        result[name] = {"bytes": len(raw), "sha256": sha(raw)}
    return result


def main():
    old = OLD_SOURCE.read_bytes()
    assert len(old) == 59309 and sha(old) == OLD_SHA
    originals = {name: (ORIGINALS / name).read_bytes() for name in FILE_PINS}
    assert all(sha(originals[name]) == digest for name, digest in FILE_PINS.items())
    docs = {name: json.loads(raw) for name, raw in originals.items() if name.endswith(".json")}
    diagnostic = docs["observation-archive-pin-diagnostic-01.json"]
    install = docs["parent-tools-install-01.json"]
    assert diagnostic["schema"] == "hepta-r34-observation-archive-pin-diagnostic/v1"
    assert diagnostic["pins_checked"] == 99 and diagnostic["original_failed_archive_job_id"] == FAILURE_JOB
    assert diagnostic["collector"] == {"path": ROOT + "/archive_r34_observation.py", "bytes": 59309, "sha256": OLD_SHA}
    assert diagnostic["original_archive_outputs_exist"] == {".tar.gz": False, ".manifest.json": False, ".compact.json": False}
    rows = {row["name"]: row for row in diagnostic["all_rows"]}
    assert len(rows) == 99 and sum(row["matches"] is True for row in rows.values()) == 96
    mismatches = {row["name"]: row for row in diagnostic["mismatches"]}
    assert set(mismatches) == set(CORRECTIONS)
    for name, expected in CORRECTIONS.items():
        row = mismatches[name]
        assert row["bytes"] == expected["bytes"] and row["expected_sha256"] == expected["inherited_r33_sha256"]
        assert row["sha256"] == expected["actual_r34_sha256"] and row["matches"] is False
        assert install["files"][ROOT + "/" + name] == {
            "path": ROOT + "/" + name, "bytes": expected["bytes"], "sha256": expected["actual_r34_sha256"]}
    assert install["passed"] and install["source_files_modified"] == 0 and install["workloads_started"] == 0
    failure_streams = streams(docs["archive-failed-native-01.json"], docs["archive-failed-read-01.json"], FAILURE_JOB, 1)
    assert docs["archive-failed-read-01.json"]["stderr"]["text"] == "ValueError: frozen original input differs\n"
    assert failure_streams["stdout"]["bytes"] == 0 and failure_streams["stderr"]["bytes"] == 42
    diagnostic_streams = streams(docs["diagnostic-native-01.json"], docs["diagnostic-read-01.json"], DIAGNOSTIC_JOB, 0)
    output_receipt = json.loads(docs["diagnostic-read-01.json"]["stdout"]["text"])
    assert output_receipt["receipt"] == {
        "path": ROOT + "/observation-archive-pin-diagnostic-01.json", "bytes": 44679,
        "sha256": FILE_PINS["observation-archive-pin-diagnostic-01.json"]}
    assert output_receipt["pins_checked"] == 99 and output_receipt["mismatches"] == diagnostic["mismatches"]
    recovery = {"original_failed_job_id": FAILURE_JOB, "original_diagnostic_job_id": DIAGNOSTIC_JOB,
        "original_failed_collector_sha256": OLD_SHA,
        "original_failed_collector_git_blob": "f837d6b053573445065a7e9e5729cc40ccdb9873",
        "failure_streams": failure_streams, "diagnostic_streams": diagnostic_streams,
        "corrections": CORRECTIONS,
        "cause": "Three materialized R33 lifecycle-tool pins were wrongly inherited; original R34 installer rewrote two root constants and their manifest before any measurement.",
        "original_01_preserved": True, "observation_reexecuted": False,
        "lifecycle_materializer_executed": False, "threshold_or_guard_weakened": False,
        "independent_reconstruction_receipt_sha256": "3b58a0e889508f6b812f3e238988ccef119ef08cdf5a5cc7a9358a92651b703b"}
    recovery_pins = {
        "observation-archive-native-failed-01.json": FILE_PINS["archive-failed-native-01.json"],
        "observation-archive-read-failed-01.json": FILE_PINS["archive-failed-read-01.json"],
        "observation-archive-pin-diagnostic-01.json": FILE_PINS["observation-archive-pin-diagnostic-01.json"],
    }
    source = old.decode()

    def change(before, after):
        nonlocal source
        assert source.count(before) == 1, before[:100]
        source = source.replace(before, after, 1)

    for row in CORRECTIONS.values():
        change(row["inherited_r33_sha256"], row["actual_r34_sha256"])
    change("PINNED = {**STATIC_PINS, **(ACTUAL['sha256'] if ACTUAL is not None else {})}\nREQUIRED = tuple(sorted(set(STATIC_PINS) | set(DYNAMIC_REQUIRED)))",
        "RECOVERY = " + pprint.pformat(recovery, sort_dicts=True, width=120) + "\n"
        "RECOVERY_PINS = " + pprint.pformat(recovery_pins, sort_dicts=True, width=120) + "\n"
        "PINNED = {**STATIC_PINS, **(ACTUAL['sha256'] if ACTUAL is not None else {}), **RECOVERY_PINS}\n"
        "REQUIRED = tuple(sorted(set(STATIC_PINS) | set(DYNAMIC_REQUIRED) | set(RECOVERY_PINS)))")
    change("    base = ROOT / 'observation-evidence-01'", "    base = ROOT / 'observation-evidence-02'")
    change("    if monitor.get('sample_count') != len(monitor.get('samples', [])):\n", """    archive_failure_native = read('observation-archive-native-failed-01.json')
    archive_failure_read = read('observation-archive-read-failed-01.json')
    archive_failure = terminal(archive_failure_native, RECOVERY['original_failed_job_id'])
    archive_failure['original_streams'] = streams_from_reads(archive_failure_native, [archive_failure_read])
    archive_failure['stderr_text'] = archive_failure_read['stderr']['text']
    diagnostic = read('observation-archive-pin-diagnostic-01.json')
    install = read('parent-tools-install-01.json')
    if (archive_failure['state'] != 'failed' or archive_failure['exit_code'] != 1
            or archive_failure['stderr_text'] != 'ValueError: frozen original input differs\\n'
            or diagnostic.get('pins_checked') != 99
            or diagnostic.get('original_failed_archive_job_id') != RECOVERY['original_failed_job_id']
            or diagnostic.get('original_archive_outputs_exist') != {'.tar.gz': False, '.manifest.json': False, '.compact.json': False}):
        errors.append('original archive01 failure/diagnostic differs')
    mismatch_rows = {row['name']: row for row in diagnostic['mismatches']}
    if set(mismatch_rows) != set(RECOVERY['corrections']):
        errors.append('original diagnostic correction inventory differs')
    for name, change in RECOVERY['corrections'].items():
        binding(install['files'][str(ROOT / name)], 'original installer corrected pin ' + name)
        row = mismatch_rows.get(name, {})
        if (row.get('bytes') != len(data[name]) or row.get('sha256') != sha(data[name])
                or row.get('expected_sha256') != change['inherited_r33_sha256']
                or sha(data[name]) != change['actual_r34_sha256']):
            errors.append('original install/diagnostic/materialized bytes differ: ' + name)
    if monitor.get('sample_count') != len(monitor.get('samples', [])):
""")
    change("        'normal_lifecycle': {'materialization_job_id': None,", "        'archive_preparation_recovery': {'binding': RECOVERY, 'original_failed_native': archive_failure,\n            'diagnostic_sha256': sha(data['observation-archive-pin-diagnostic-01.json']),\n            'original_measurement_reexecuted': False},\n        'normal_lifecycle': {'materialization_job_id': None,")
    before_tree, after_tree = ast.parse(old), ast.parse(source)
    before_functions = {node.name: ast.get_source_segment(old.decode(), node) for node in before_tree.body if isinstance(node, ast.FunctionDef)}
    after_functions = {node.name: ast.get_source_segment(source, node) for node in after_tree.body if isinstance(node, ast.FunctionDef)}
    stable = {name: before_functions[name] == after_functions[name]
              for name in before_functions if name not in {"summary", "create_archive"}}
    assert all(stable.values())
    assert after_functions["create_archive"].replace("observation-evidence-02", "observation-evidence-01") == before_functions["create_archive"]
    output = HERE / "sealed-02"
    assert not os.path.lexists(output)
    output.mkdir(mode=0o700)
    package = {"archive_r34_observation_02.py": source.encode(), "recovery-binding-02.json": encoded(recovery),
        "static-checks-02.json": encoded({"unchanged_functions": stable, "create_only_output_name_delta": True,
            "selected_pin_corrections": 3, "preserved_original_dynamic_pins": 29,
            "failed_native_read_and_diagnostic_added": True, "collector_or_original_auditors_executed": False})}
    for name, raw in package.items():
        create(output / name, raw)
    manifest = {"schema": "hepta-r34-observation-archive-recovery-seal/v1", "sealed": True,
        "original_failed_collector": {"bytes": len(old), "sha256": OLD_SHA},
        "files": {name: {"bytes": len(raw), "sha256": sha(raw)} for name, raw in package.items()},
        "recovery_inputs": {name: {"bytes": len(raw), "sha256": sha(raw)} for name, raw in originals.items()},
        "collector_executed_by_preparation": False, "observation_reexecuted": False,
        "archive02_job_or_result": None}
    create(output / "seal-manifest-02.json", encoded(manifest))
    print(json.dumps(manifest, sort_keys=True))


if __name__ == "__main__":
    main()

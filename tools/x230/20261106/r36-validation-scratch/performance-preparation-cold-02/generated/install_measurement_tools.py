#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Copy the pinned measurement tools and freeze R36 input templates once.

This installer does no SSH, builds, tests, waits, workload submissions, or source
changes. Existing R24/R29 evidence and directories are read only. It is run by
the operator after the five reviewed parent scripts and their manifest arrive.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import types

sys.dont_write_bytecode = True
ROOT = Path("/home/qian/hepta-runtime-validation-scratch-20261106-r36-cold-02")
OLD = Path("/home/qian/hepta-runtime-optimization-20261106-r35")
HERE = ROOT / "tools-01"
LIFECYCLE = ROOT / "lifecycle-tools-01"
HEX = re.compile(r"[0-9a-f]{64}\Z")
BUNDLE_NAMES = {"r36_campaign.py", "r36_lifecycle_campaign.py", "prepare_campaign_inputs.py",
                "prepare_lifecycle_inputs.py", "install_measurement_tools.py"}
COPY_PINS = {
    "compiler_monitor.py": "afb514362a9d8dd573b806f0dc87df16bd3a906e4574d10d91bf483b2e76cdcf",
    "compiler_state.py": "9da718654db04a646e081d2d719a2d6d4655ffe337bc0e3f906e736e4d77a251",
    "validate_compiler_monitor.py": "d2cd009adf1f35a394ffddcc8f8646cc0c1b856b78181ca321ea68f6468218b2",
    "compiler-monitor-policy-01.json": "ddb2e03d4a1a1610466a5dc2d1a544f554ad12fc31412483101b48a235402368",
    "summarize_r25_campaign.py": "2418bad36fe4aef75d52c5a00c898ff93fef9bb4b6efb10028105143106a1864",
}
OLD_INPUT_SHA = "eec0348217f6c679d1f965004f1bd8ecded2886fc1c654d45a9ad6ea700391e4"
OLD_LIFECYCLE_MANIFEST_SHA = "eb50cd7ab0376c4b3dc768e8d184fdc23eeaa90c2ce5bdd4b9e9ac551448504e"


def need(value, reason):
    if not value:
        raise RuntimeError(reason)


def bootstrap(path, expected):
    path = Path(path)
    need(path.is_absolute() and path.resolve() == path, "direct bootstrap path required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= 262144,
             "unsafe or oversized bootstrap input")
        with os.fdopen(os.dup(fd), "rb") as stream:
            raw = stream.read(262145)
        fields = ("st_dev", "st_ino", "st_uid", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        stamp = lambda value: tuple(getattr(value, key) for key in fields)
        need(len(raw) == before.st_size and stamp(before) == stamp(os.fstat(fd)) == stamp(path.lstat()),
             "bootstrap input changed")
    finally:
        os.close(fd)
    identity = {"path": str(path), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    digest = expected if isinstance(expected, str) else expected["sha256"]
    need(isinstance(digest, str) and HEX.fullmatch(digest) and identity["sha256"] == digest,
         "bootstrap SHA differs: " + str(path))
    if isinstance(expected, dict):
        need(identity["bytes"] == expected["bytes"] and expected.get("path", str(path)) == str(path),
             "bootstrap path/size differs: " + str(path))
    return identity, raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle-sha256", required=True)
    args = parser.parse_args()
    need(sys.platform == "linux" and os.geteuid() != 0
         and Path(__file__).resolve() == HERE / "install_measurement_tools.py", "fixed Linux operator installer required")
    manifest_id, raw = bootstrap(HERE / "runner-bundle-manifest.json", args.bundle_sha256)
    bundle = json.loads(raw)
    need(bundle.get("sealed") is True
         and bundle["schema"] == "hepta-r36-parent-runner-bundle/v1" and bundle["runtime_root"] == str(ROOT)
         and set(bundle["files"]) == BUNDLE_NAMES
         and set(bundle["qualification_inputs"]) == {"prepare_qualify.py", "qualification-input.json", "candidate/candidate.patch"},
         "reviewed R36 bundle identity/set differs")
    bindings = [manifest_id]
    parent_raw = None
    for name, expected in sorted(bundle["files"].items()):
        identity, data = bootstrap(HERE / name, expected)
        bindings.append(identity)
        if name == "r36_campaign.py":
            parent_raw = data
    for name, expected in sorted(bundle["qualification_inputs"].items()):
        identity, _ = bootstrap(ROOT / name, expected)
        bindings.append(identity)
    parent = types.ModuleType("r36_install_bound_parent")
    parent.__file__ = str(HERE / "r36_campaign.py")
    exec(compile(parent_raw, parent.__file__, "exec"), parent.__dict__)
    parent.require_r36_preparation_seal()
    parent.private_directory(HERE)
    old_input_id, raw = parent.checked(OLD / "campaign-inputs-01.json", OLD_INPUT_SHA, retain=True)
    old_inputs = json.loads(raw)
    bindings.append(old_input_id)
    original_manifest_id, raw = parent.checked(OLD / "lifecycle-tools-01/lifecycle-tools-manifest-01.json",
                                               OLD_LIFECYCLE_MANIFEST_SHA, retain=True)
    bindings.append(original_manifest_id)
    lifecycle_manifest = json.loads(raw)
    need(lifecycle_manifest["schema"] == "hepta-r25-lifecycle-tools/v1"
         and len(lifecycle_manifest["files"]) == 27, "original 27-file lifecycle harness required")
    payloads, copies = {}, []
    for name, expected_sha in COPY_PINS.items():
        identity, data = parent.checked(OLD / "tools-01" / name, expected_sha, retain=True)
        bindings.append(identity)
        payloads[HERE / name] = data
        copies.append({"source": identity, "destination": str(HERE / name), "changed": False})
    changed = {"run_lifecycle_abba_01.py", "run_six_host_cancel_recovery_timed.py"}
    need(set(bundle["changed_lifecycle_measurement_files"]) == changed, "unexpected measurement source change set")
    for name, expected in sorted(lifecycle_manifest["files"].items()):
        need(Path(name).name == name and name not in {".", "..", "lifecycle-tools-manifest-01.json"},
             "unsafe original harness member")
        identity, data = parent.checked(OLD / "lifecycle-tools-01" / name, expected, retain=True)
        bindings.append(identity)
        if name in changed:
            need(data.count(str(OLD).encode()) == 1, "expected single lifecycle output-root constant missing")
            data = data.replace(str(OLD).encode(), str(ROOT).encode(), 1)
            compile(data, str(LIFECYCLE / name), "exec")
        payloads[LIFECYCLE / name] = data
        lifecycle_manifest["files"][name] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        copies.append({"source": identity, "destination": str(LIFECYCLE / name), "changed": name in changed})
    fixture_root = ROOT / "measurement-fixtures-01"
    fixture_names = {"topology.json", *["jobs/" + name for name in bundle["frozen_job_names"]]}
    need(len(bundle["frozen_job_names"]) == 6 and len(fixture_names) == 7
         and set(bundle["fixture_inputs"]) == fixture_names,
         "seven frozen recovered fixture inputs required")
    for name, expected in sorted(bundle["fixture_inputs"].items()):
        relative = Path(name)
        need(not relative.is_absolute() and ".." not in relative.parts
             and (name == "topology.json" or (len(relative.parts) == 2 and relative.parts[0] == "jobs"
                  and relative.name.endswith(".json"))), "unsafe fixed fixture member")
        identity, data = parent.checked(HERE / "frozen-fixture-inputs" / relative,
                                        expected, maximum=65536, retain=True)
        bindings.append(identity)
        payloads[fixture_root / relative] = data
        copies.append({"source": identity, "destination": str(fixture_root / relative), "changed": False})
    need(hashlib.sha256(payloads[fixture_root / "topology.json"]).hexdigest() == parent.TOPOLOGY_SHA,
         "recovered topology differs from the fixed parent")
    lifecycle_manifest_path = LIFECYCLE / "lifecycle-tools-manifest-01.json"
    payloads[lifecycle_manifest_path] = parent.canonical(lifecycle_manifest)

    def pending_identity(path):
        data = payloads[path]
        return {"path": str(path), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}

    def uploaded_identity(name):
        return dict(bundle["files"][name], path=str(HERE / name))

    def future(path, **extra):
        return {"path": str(path), "bytes": None, "sha256": None, **extra}

    monitor = {key: pending_identity(path) for key, path in parent.COMPILER_MONITOR_PATHS.items()}
    static_inputs = {
        "attempt": "01", "candidate_release": "R36", "source_inputs_sha256": None,
        "candidate_binaries": {name: {"bytes": None, "sha256": None} for name in parent.BINARY_NAMES},
        "compiler_monitor": monitor,
        "qualification_launcher": bundle["qualification_inputs"]["prepare_qualify.py"],
        "qualification_input": bundle["qualification_inputs"]["qualification-input.json"],
        "candidate_patch": bundle["qualification_inputs"]["candidate/candidate.patch"],
        "qualification_preparation": future(ROOT / "preparation.json"),
        "qualification_terminal_status": future(ROOT / "qualification-terminal-status-01.json", job_id=None),
    }
    observation_template = dict(static_inputs,
        schema="hepta-r25-campaign-inputs/v1", baseline=old_inputs["baseline"],
        launcher_sha256=bundle["files"]["r36_campaign.py"]["sha256"],
        summary_sha256=COPY_PINS["summarize_r25_campaign.py"],
        qualification_reports=[future(ROOT / "qualification-01/report.json", success_field="qualified")])
    lifecycle_template = dict(static_inputs,
        schema="hepta-r25-lifecycle-inputs/v1",
        launcher_sha256=bundle["files"]["r36_lifecycle_campaign.py"]["sha256"],
        campaign_helpers=uploaded_identity("r36_campaign.py"),
        qualification_report=future(ROOT / "qualification-01/report.json"),
        observation_campaign=future(ROOT / "campaign-01/report.json"),
        tools_manifest=pending_identity(lifecycle_manifest_path))
    payloads[ROOT / "campaign-inputs-01.example.json"] = parent.canonical(observation_template)
    payloads[ROOT / "lifecycle-inputs-01.example.json"] = parent.canonical(lifecycle_template)
    receipt_path = ROOT / "parent-tools-install-01.json"
    need(not any(os.path.lexists(path) for path in [LIFECYCLE, fixture_root, receipt_path, *payloads,
         ROOT / "campaign-inputs-01.json", ROOT / "lifecycle-inputs-01.json", ROOT / "campaign-01",
         ROOT / "lifecycle-campaign-01", ROOT / "lifecycle-abba-01"]),
         "fresh R36 tool/template/output paths required; no overwrite or automatic retry")
    for identity in bindings:
        need(parent.checked(identity["path"], identity) == identity, "input changed before tool installation")
    parent.private_directory(LIFECYCLE, create_new=True)
    parent.private_directory(fixture_root, create_new=True)
    parent.private_directory(fixture_root / "jobs", create_new=True)
    for path, data in sorted(payloads.items()):
        parent.create(path, data)
    files = {str(path): parent.checked(path, pending_identity(path)) for path in payloads}
    receipt = {"schema": "hepta-r36-parent-tools-install/v1", "passed": True,
        "bundle": manifest_id, "original_lifecycle_manifest": original_manifest_id,
        "copies": copies, "files": files, "qualification_inputs": bundle["qualification_inputs"],
        "source_files_modified": 0, "workloads_started": 0, "monitor_started": False,
        "automatic_retries": 0, "adoption_scope": parent.R36_ADOPTION_SCOPE,
        "saturated_cancellation_verified": False, "open_blockers": parent.R36_OPEN_BLOCKERS}
    parent.create(receipt_path, parent.canonical(receipt))
    print(json.dumps({"installed": True, "receipt": parent.checked(receipt_path),
        "campaign_example": files[str(ROOT / "campaign-inputs-01.example.json")],
        "lifecycle_example": files[str(ROOT / "lifecycle-inputs-01.example.json")],
        "campaign_preparer": uploaded_identity("prepare_campaign_inputs.py"),
        "lifecycle_preparer": uploaded_identity("prepare_lifecycle_inputs.py"),
        "workloads_started": 0}), flush=True)


if __name__ == "__main__":
    os.umask(0o077)
    main()

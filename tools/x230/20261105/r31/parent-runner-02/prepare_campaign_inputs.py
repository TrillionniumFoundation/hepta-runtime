#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Materialize one R31 observation input after the actual qualification closes.

All future receipt/job/binary identities stay null in the reviewed example.
The invocation must supply the actual original job, terminal SHA and preparation
SHA. This program performs file checks only: no waiting, SSH, workload or retry.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

sys.dont_write_bytecode = True
ROOT = Path("/home/qian/hepta-runtime-optimization-20261105-r31")
BASE = Path("/home/qian/hepta-runtime-optimization-20261105-r24")
EXAMPLE = ROOT / "campaign-inputs-02.example.json"
OUTPUT = ROOT / "campaign-inputs-02.json"
COMPACT = ROOT / "qualification-compact-02.json"
HELPERS = ROOT / "tools-02/r31_campaign.py"
PREPARER = ROOT / "tools-02/prepare_campaign_inputs.py"
HEX = re.compile(r"[0-9a-f]{64}\Z")
NAMES = ("hepta-runtime", "hepta-runtime-jobctl", "native_process_driver")


def need(value, reason):
    if not value:
        raise RuntimeError(reason)


def bootstrap(path, expected_sha):
    need(path.is_absolute() and path.resolve() == path and HEX.fullmatch(expected_sha),
         "direct, hash-bound bootstrap path required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= 262144,
             "unsafe bootstrap input")
        with os.fdopen(os.dup(fd), "rb") as stream:
            raw = stream.read(262145)
        fields = ("st_dev", "st_ino", "st_uid", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
        stamp = lambda value: tuple(getattr(value, key) for key in fields)
        need(len(raw) == before.st_size and stamp(before) == stamp(os.fstat(fd)) == stamp(path.lstat()),
             "bootstrap input changed")
    finally:
        os.close(fd)
    identity = {"path": str(path), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    need(identity["sha256"] == expected_sha, "bootstrap identity differs")
    return identity, raw


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    need(Path(module.__file__).resolve() == path, "imported module path differs")
    return module


def validate_template(value):
    need(value["schema"] == "hepta-r25-campaign-inputs/v1" and value["attempt"] == "02"
         and value["candidate_release"] == "R31", "one frozen R31 observation attempt required")
    need(HEX.fullmatch(value["launcher_sha256"]) and HEX.fullmatch(value["summary_sha256"])
         and value["source_inputs_sha256"] is None, "future source identity must remain unknown")
    need(set(value["candidate_binaries"]) == set(NAMES)
         and all(row == {"bytes": None, "sha256": None} for row in value["candidate_binaries"].values()),
         "future candidate binary identities must remain null")
    need(len(value["qualification_reports"]) == 1, "one actual qualification report required")
    reports = {"qualification_preparation": (value["qualification_preparation"], ROOT / "preparation-02.json"),
               "qualification_terminal_status": (value["qualification_terminal_status"], ROOT / "qualification-terminal-status-01.json"),
               "qualification_report": (value["qualification_reports"][0], ROOT / "qualification-01/report.json")}
    for label, (row, path) in reports.items():
        need(row["path"] == str(path) and row["bytes"] is None and row["sha256"] is None,
             "future receipt must remain unresolved: " + label)
    need(value["qualification_terminal_status"]["job_id"] is None
         and value["qualification_reports"][0]["success_field"] == "qualified",
         "future native job identity must be supplied by the actual launch receipt")
    need(value["baseline"]["source"] == str(BASE / "source")
         and value["baseline"]["publication_readback"]["commit"] == "baab4def80be7af015b2e7a594cb302f66c4130e",
         "formal baseline remains accepted R24")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("example-sha256", "preparer-sha256", "preparation-sha256", "qualification-terminal-sha256", "qualification-job-id"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    need(sys.platform == "linux" and os.geteuid() != 0 and Path(__file__).resolve() == PREPARER,
         "fixed native Linux operator materializer required")
    need(all(HEX.fullmatch(value) for key, value in vars(args).items() if key.endswith("sha256")),
         "all actual receipt and tool SHAs are required")
    example_identity, raw = bootstrap(EXAMPLE, args.example_sha256)
    inputs = json.loads(raw)
    validate_template(inputs)
    own_identity, _ = bootstrap(PREPARER, args.preparer_sha256)
    helper_identity, _ = bootstrap(HELPERS, inputs["launcher_sha256"])
    need(not any(os.path.lexists(path) for path in (OUTPUT, COMPACT, ROOT / "campaign-02")),
         "fresh observation input, compact receipt and campaign paths required")
    parent = load_module("r26_bound_campaign_helpers_for_materialization", HELPERS)
    bindings = [example_identity, own_identity, helper_identity]

    def bind(path, expected=None, retain=False, maximum=128 * 1024 * 1024):
        result = parent.checked(path, expected, maximum, retain)
        bindings.append(result[0] if retain else result)
        return result

    _, monitor_binding = parent.bind_compiler_monitor_inputs(inputs, bind)
    preparation_identity, raw = bind(ROOT / "preparation-02.json", args.preparation_sha256, retain=True)
    preparation = json.loads(raw)
    terminal_identity = bind(ROOT / "qualification-terminal-status-01.json", args.qualification_terminal_sha256)
    qualification_identity, raw = bind(ROOT / "qualification-01/report.json", retain=True)
    qualified = json.loads(raw)
    inputs["qualification_preparation"] = preparation_identity
    inputs["qualification_terminal_status"] = dict(terminal_identity, job_id=args.qualification_job_id)
    inputs["qualification_reports"] = [dict(qualification_identity, success_field="qualified")]
    proof = parent.bind_r31_candidate_preparation(inputs, bind)
    candidate_source = parent.source_inputs(parent.SOURCE)
    baseline_source = parent.source_inputs(BASE / "source")
    need(qualified["source_after"] == parent.qualification_projection(candidate_source),
         "current candidate source differs from actual completed qualification")
    binaries = {"A": {}, "B": {}}
    need(set(qualified["binaries"]) == set(NAMES), "three actual candidate artifacts required")
    for name in NAMES:
        binaries["A"][name] = bind(inputs["baseline"]["binaries"][name]["path"], inputs["baseline"]["binaries"][name])
        value = qualified["binaries"][name]
        need(value["path"] == str(parent.CANDIDATE_DIR / name), "candidate artifact is outside actual qualification")
        binaries["B"][name] = bind(value["path"], value["sha256"])
        need(os.access(value["path"], os.X_OK), "actual candidate artifact is not executable")
    parent.verify_composed_qualification(qualified, parent.SOURCE, binaries["B"])
    for item in inputs["baseline"]["qualification_reports"]:
        _, raw = bind(item["path"], item, retain=True)
        value = json.loads(raw)
        parent.verify_composed_qualification(value, BASE / "source", binaries["A"])
        need(value.get("finished_utc") and value["source_after"] == parent.qualification_projection(baseline_source),
             "accepted baseline source differs from its actual qualification")
    baseline = {}
    for label in ("campaign_report", "publication_readback"):
        item = inputs["baseline"][label]
        _, raw = bind(item["path"], item, retain=True)
        baseline[label] = json.loads(raw)
    parent.verify_baseline_enablement(baseline["campaign_report"], baseline["publication_readback"], binaries["A"],
        inputs["baseline"]["publication_readback"]["commit"], inputs["baseline"]["campaign_report"]["sha256"])
    need(baseline_source["sha256"] == baseline["campaign_report"]["source_inputs_sha256"],
         "formal R24 source differs from its adopted campaign")
    bind(parent.SUMMARY, inputs["summary_sha256"])
    for item in bindings:
        need(parent.checked(item["path"], item) == item, "prerequisite changed before materialization")
    need(parent.source_inputs(parent.SOURCE) == candidate_source and parent.source_inputs(BASE / "source") == baseline_source,
         "source changed before materialization")
    inputs.update(source_inputs_sha256=candidate_source["sha256"],
        candidate_binaries={name: {key: binaries["B"][name][key] for key in ("bytes", "sha256")} for name in NAMES},
        materialization={"created_utc": parent.utc(), "example": example_identity, "preparer": own_identity,
                         "qualification_gate": proof, "compiler_monitor_inputs": monitor_binding,
                         "monitor_started": False, "remote_effects": 0, "automatic_retries": 0})
    parent.create(OUTPUT, parent.canonical(inputs))
    compact = {"schema": "hepta-r31-qualification-compact/v1", "qualified": True,
               "qualification_gate": proof, "candidate_binaries": inputs["candidate_binaries"],
               "source_inputs_sha256": candidate_source["sha256"], "baseline_commit": inputs["baseline"]["publication_readback"]["commit"],
               "campaign_inputs": parent.checked(OUTPUT), "workloads_started": 0, "automatic_retries": 0}
    parent.create(COMPACT, parent.canonical(compact))
    print(json.dumps(compact), flush=True)


if __name__ == "__main__":
    os.umask(0o077)
    main()

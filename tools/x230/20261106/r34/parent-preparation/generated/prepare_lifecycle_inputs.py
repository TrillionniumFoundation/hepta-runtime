#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Create one lifecycle input receipt after actual qualification and observation.

This is a one-shot, local-file prerequisite check. It does not wait, contact SSH,
start a workload, or retry any effect. Future candidate hashes remain null in the
template until all real prerequisites have been read and independently matched.
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
ROOT = Path("/home/qian/hepta-runtime-optimization-20261106-r34")
EXAMPLE = ROOT / "lifecycle-inputs-01.example.json"
OUTPUT = ROOT / "lifecycle-inputs-01.json"
LAUNCHER = ROOT / "tools-01/r34_lifecycle_campaign.py"
HELPERS = ROOT / "tools-01/r34_campaign.py"
PREPARER = ROOT / "tools-01/prepare_lifecycle_inputs.py"
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
    need(value["schema"] == "hepta-r25-lifecycle-inputs/v1" and value["attempt"] == "01"
         and value["candidate_release"] == "R34",
         "one frozen lifecycle attempt required")
    need(HEX.fullmatch(value["launcher_sha256"]) and value["source_inputs_sha256"] is None,
         "candidate source identity must be obtained from actual completed work")
    need(set(value["candidate_binaries"]) == set(NAMES) and all(
         row == {"bytes": None, "sha256": None} for row in value["candidate_binaries"].values()),
         "future candidate binary identities must remain null in the reviewed template")
    paths = {"qualification_preparation": ROOT / "preparation.json",
             "qualification_terminal_status": ROOT / "qualification-terminal-status-01.json",
             "qualification_report": ROOT / "qualification-01/report.json",
             "observation_campaign": ROOT / "campaign-01/report.json"}
    for label, path in paths.items():
        row = value[label]
        need(row["path"] == str(path) and row["bytes"] is None and row["sha256"] is None,
             "future prerequisite receipt must remain null in the reviewed template: " + label)
    need(value["qualification_terminal_status"]["job_id"] is None,
         "future qualification job remains unknown until the actual observation input is read")
    need(value["campaign_helpers"]["path"] == str(HELPERS)
         and type(value["campaign_helpers"]["bytes"]) is int and HEX.fullmatch(value["campaign_helpers"]["sha256"])
         and value["tools_manifest"]["path"] == str(ROOT / "lifecycle-tools-01/lifecycle-tools-manifest-01.json")
         and type(value["tools_manifest"]["bytes"]) is int and HEX.fullmatch(value["tools_manifest"]["sha256"]),
         "actual reviewed helper and tool identities required")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--example-sha256", required=True)
    parser.add_argument("--preparer-sha256", required=True)
    args = parser.parse_args()
    need(sys.platform == "linux" and os.geteuid() != 0, "native Linux operator required")
    need(Path(__file__).resolve() == PREPARER, "fixed reviewed materializer path required")
    example_identity, raw = bootstrap(EXAMPLE, args.example_sha256)
    inputs = json.loads(raw)
    validate_template(inputs)
    own_identity, _ = bootstrap(PREPARER, args.preparer_sha256)
    launcher_identity, _ = bootstrap(LAUNCHER, inputs["launcher_sha256"])
    helper_identity, _ = bootstrap(HELPERS, inputs["campaign_helpers"]["sha256"])
    need(helper_identity == inputs["campaign_helpers"], "helper byte identity differs")
    need(not os.path.lexists(OUTPUT), "original lifecycle input receipt already exists; no overwrite or retry")
    parent = load_module("r25_bound_campaign_helpers_for_materialization", HELPERS)
    launcher = load_module("r25_bound_lifecycle_launcher_for_materialization", LAUNCHER)
    bindings = [example_identity, own_identity, launcher_identity, helper_identity]

    def bind(path, expected=None, retain=False, maximum=128 * 1024 * 1024):
        result = parent.checked(path, expected, maximum, retain)
        bindings.append(result[0] if retain else result)
        return result

    terminal_identity, raw = bind(ROOT / "qualification-terminal-status-01.json", retain=True)
    terminal_value = json.loads(raw)
    observation_identity, raw = bind(ROOT / "campaign-01/report.json", retain=True)
    observation = json.loads(raw)
    launcher.completed_observation(observation)
    monitor_binding = parent.verify_completed_compiler_monitor(observation, inputs, bind, ROOT / "campaign-01")
    _, raw = bind(observation["summary"]["path"], observation["summary"], retain=True)
    launcher.completed_observation(observation, json.loads(raw))
    _, raw = bind(observation["input_receipt"]["path"], observation["input_receipt"], retain=True)
    prior = json.loads(raw)
    need(prior["schema"] == "hepta-r25-campaign-inputs/v1" and prior["attempt"] == "01"
         and prior["launcher_sha256"] == helper_identity["sha256"],
         "completed observation campaign used different reviewed helpers")
    need(all(inputs[name] == prior[name] for name in ("qualification_launcher", "qualification_input", "candidate_patch")),
         "lifecycle template differs from the reviewed R34 qualification inputs")
    job_id = prior["qualification_terminal_status"]["job_id"]
    launcher.terminal_qualification(terminal_value, job_id)
    need(terminal_identity == {key: prior["qualification_terminal_status"][key] for key in terminal_identity},
         "qualification terminal differs from the successful observation input")
    preparation_gate = parent.bind_r34_candidate_preparation(prior, bind)
    binaries = {"A": {}, "B": {}}
    for name in NAMES:
        binaries["A"][name] = bind(launcher.BASE / "qualification-01" / name, observation["binaries"]["A"][name])
        binaries["B"][name] = bind(parent.CANDIDATE_DIR / name, observation["binaries"]["B"][name])
    need(binaries == observation["binaries"]
         and binaries["A"]["hepta-runtime"]["sha256"] == launcher.BASELINE_SHA,
         "actual runtime set differs from completed observation campaign")
    candidate_source = parent.source_inputs(parent.SOURCE)
    baseline_source = parent.source_inputs(launcher.BASE / "source")
    need(candidate_source["sha256"] == observation["source_inputs_sha256"]
         and baseline_source["sha256"] == observation["baseline_source_inputs_sha256"],
         "actual source differs from completed observation campaign")
    qualification_identity, raw = bind(ROOT / "qualification-01/report.json", retain=True)
    qualified = json.loads(raw)
    parent.verify_composed_qualification(qualified, parent.SOURCE, binaries["B"])
    need(qualified.get("finished_utc") and qualified["source_after"] == parent.qualification_projection(candidate_source),
         "candidate source is not the exact completed qualification source")
    need(any({key: row[key] for key in qualification_identity} == qualification_identity
             for row in prior["qualification_reports"]), "actual qualification differs from accepted observation receipt")
    for row in prior["baseline"]["qualification_reports"]:
        _, raw = bind(row["path"], row, retain=True)
        baseline_qualification = json.loads(raw)
        parent.verify_composed_qualification(baseline_qualification, launcher.BASE / "source", binaries["A"])
        need(baseline_qualification.get("finished_utc") and baseline_qualification["source_after"]
             == parent.qualification_projection(baseline_source), "baseline qualified source changed")
    baseline_evidence = {}
    for label in ("campaign_report", "publication_readback"):
        row = prior["baseline"][label]
        _, raw = bind(row["path"], row, retain=True)
        baseline_evidence[label] = json.loads(raw)
    parent.verify_baseline_enablement(baseline_evidence["campaign_report"], baseline_evidence["publication_readback"],
        binaries["A"], prior["baseline"]["publication_readback"]["commit"], prior["baseline"]["campaign_report"]["sha256"])
    _, raw = bind(inputs["tools_manifest"]["path"], inputs["tools_manifest"], retain=True)
    manifest = json.loads(raw)
    need(manifest["schema"] == "hepta-r25-lifecycle-tools/v1" and len(manifest["files"]) == 27,
         "frozen lifecycle tool set differs")
    for name, item in sorted(manifest["files"].items()):
        need(Path(name).name == name and name not in {".", "..", "lifecycle-tools-manifest-01.json"}, "unsafe tool member")
        bind(launcher.TOOLS / name, item, maximum=262144)
    for path in (launcher.OUT, launcher.ABBA, launcher.TOOL_TESTS, launcher.SOCKET_PREFIX):
        need(path.resolve() == path and not os.path.lexists(path), "lifecycle output/socket is not fresh")
    for number, arm in enumerate("ABBA"):
        path = launcher.SOCKET_PREFIX.with_name(launcher.SOCKET_PREFIX.name + f"-{number}-{arm}")
        need(path.resolve() == path and not os.path.lexists(path), "lifecycle round socket is not fresh")
    for item in bindings:
        need(parent.checked(item["path"], item) == item, "prerequisite changed before input materialization")
    need(parent.source_inputs(parent.SOURCE) == candidate_source
         and parent.source_inputs(launcher.BASE / "source") == baseline_source, "source changed during materialization")
    inputs.update(qualification_preparation=preparation_gate["preparation"],
                  qualification_terminal_status=dict(terminal_identity, job_id=job_id),
                  qualification_report=qualification_identity, observation_campaign=observation_identity,
                  source_inputs_sha256=candidate_source["sha256"],
                  candidate_binaries={name: {key: binaries["B"][name][key] for key in ("bytes", "sha256")} for name in NAMES},
                  materialization={"created_utc": parent.utc(), "example": example_identity, "preparer": own_identity,
                                   "launcher": launcher_identity, "observation_compiler_monitor_gate": monitor_binding,
                                   "monitor_started": False, "remote_effects": 0, "automatic_retries": 0})
    parent.create(OUTPUT, parent.canonical(inputs))
    print(json.dumps({"created": True, "input_receipt": parent.checked(OUTPUT),
                      "qualification_job_id": job_id, "candidate_binaries": inputs["candidate_binaries"],
                      "source_inputs_sha256": inputs["source_inputs_sha256"], "workloads_started": 0,
                      "remote_effects": 0, "automatic_retries": 0}), flush=True)


if __name__ == "__main__":
    os.umask(0o077)
    main()

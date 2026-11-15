#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Seal R36 performance/CI inputs from actual qualification; run no commands."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import types

sys.dont_write_bytecode = True
ROOT = Path("/home/qian/hepta-runtime-optimization-20261106-r36")
SELF = ROOT / "materialize_control_inputs.py"
MANIFEST = ROOT / "control-package-manifest-01.json"
HELPER = ROOT / "tools-01/r36_campaign.py"
HEX = re.compile(r"[0-9a-f]{64}\Z")


def need(value, reason):
    if not value:
        raise RuntimeError(reason)


def bootstrap(path, expected=None):
    need(path.is_absolute() and path.resolve(strict=True) == path, "direct input required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and before.st_uid == os.geteuid() and before.st_size <= 16 * 1024 * 1024,
             "unsafe bootstrap input")
        raw = stream.read(before.st_size + 1)
        after = os.fstat(stream.fileno())
    fields = ("st_dev", "st_ino", "st_uid", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
    need(len(raw) == before.st_size and all(getattr(before, field) == getattr(after, field)
         == getattr(path.lstat(), field) for field in fields), "bootstrap input changed")
    identity = {"path": str(path), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    if expected is not None:
        need(HEX.fullmatch(expected) and identity["sha256"] == expected, "bootstrap SHA differs")
    return identity, raw


def assign_frozen(text, name, value):
    nodes = [n for n in ast.parse(text).body if isinstance(n, ast.Assign)
             and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)
             and n.targets[0].id == name]
    need(len(nodes) == 1 and isinstance(nodes[0].value, ast.Constant)
         and nodes[0].value.value is None, "expected one unbound assignment: " + name)
    old = ast.get_source_segment(text, nodes[0])
    need(text.count(old) == 1, "ambiguous unbound assignment")
    return text.replace(old, name + " = " + repr(value))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("manifest-sha256", "qualification-input-sha256", "preparation-sha256",
                 "qualification-terminal-sha256", "qualification-job-id"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    need(sys.platform == "linux" and os.geteuid() != 0 and Path(__file__).resolve() == SELF,
         "fixed native Linux operator materializer required")
    manifest_id, raw = bootstrap(MANIFEST, args.manifest_sha256)
    manifest = json.loads(raw)
    need(manifest["schema"] == "hepta-r36-control-package/v1"
         and manifest["workloads_started"] == 0 and manifest["qualification_executed"] is False,
         "reviewed control package required")
    need("materialize_control_inputs.py" in manifest["files"]
         and "tools-01/r36_campaign.py" in manifest["files"], "bootstrap members missing")
    package = {}
    for name, expected in manifest["files"].items():
        path = ROOT / name
        need(isinstance(name, str) and not Path(name).is_absolute()
             and ".." not in Path(name).parts and path.is_relative_to(ROOT), "unsafe package member")
        actual, raw = bootstrap(path, expected["sha256"])
        need(actual["bytes"] == expected["bytes"], "package byte length differs")
        package[name] = (actual, raw)
    parent = types.ModuleType("r36_control_receipt_only_parent")
    parent.__file__ = str(HELPER)
    exec(compile(package["tools-01/r36_campaign.py"][1], parent.__file__, "exec"), parent.__dict__)
    bindings = [manifest_id] + [row[0] for row in package.values()]

    def bind(path, expected=None, retain=False, maximum=128 * 1024 * 1024):
        result = parent.checked(path, expected, maximum, retain)
        bindings.append(result[0] if retain else result)
        return result

    input_id, raw = bind(ROOT / "qualification-input.json", args.qualification_input_sha256, retain=True)
    source_input = json.loads(raw)
    launcher_id = bind(ROOT / "prepare_qualify.py", source_input["preparation_tool"])
    patch_id = bind(ROOT / "candidate/candidate.patch", source_input["candidate_patch"])
    preparation_id = bind(ROOT / "preparation.json", args.preparation_sha256)
    terminal_id = bind(ROOT / "qualification-terminal-status-01.json", args.qualification_terminal_sha256)
    qualification_id = bind(ROOT / "qualification-01/report.json")
    inputs = {"qualification_launcher": launcher_id, "qualification_input": input_id,
              "candidate_patch": patch_id, "qualification_preparation": preparation_id,
              "qualification_terminal_status": dict(terminal_id, job_id=args.qualification_job_id),
              "qualification_reports": [dict(qualification_id, success_field="qualified")]}
    proof = parent.bind_r36_candidate_preparation(inputs, bind)
    parent.need(proof["passed"] is True, "actual candidate qualification binding did not pass")
    outputs = [ROOT / name for name in ("campaign-inputs-01.example.json", "lifecycle-inputs-01.example.json",
        "rust-ci-qualification-bindings-01.json", "rust-ci-tools-01", "control-materialization-01.json")]
    need(not any(os.path.lexists(path) for path in outputs), "fresh control outputs required; do not retry")

    example_bytes = {}
    for filename in ("campaign-inputs-01.example.json", "lifecycle-inputs-01.example.json"):
        value = json.loads(package["input-templates/" + filename][1])
        for name in ("qualification_launcher", "qualification_input", "candidate_patch"):
            value[name] = inputs[name]
        example_bytes[filename] = parent.canonical(value)
    bindings_raw = parent.canonical(inputs)
    actual_pins = {
        "JOB_ID": proof["original_job_id"], "SOURCE_MAP_SHA": proof["source_map"]["sha256"],
        "ISOLATED_SUMMARY_SHA": proof["isolated_summary"]["sha256"],
        "ISOLATED_AUDIT_SHA": proof["isolated_audit"]["sha256"],
        "QUALIFICATION_REPORT_SHA": qualification_id["sha256"], "PREPARATION_SHA": preparation_id["sha256"],
        "NATIVE_TERMINAL_SHA": terminal_id["sha256"], "PARENT_SHA": package["tools-01/r36_campaign.py"][0]["sha256"],
        "QUALIFICATION_BINDINGS_SHA": hashlib.sha256(bindings_raw).hexdigest(), "FROZEN_COUNTS": proof["tests"],
    }
    materializer = package["ci-templates/materialize_rust_ci_plan_01.py"][1].decode()
    for name, value in actual_pins.items():
        materializer = assign_frozen(materializer, name, value)
    contents = {name: package["ci-templates/" + name][1]
                for name in ("run_rust_ci_01.py", "audit_nextest_0137.py", "canonical-workflow.yml")}
    contents["materialize_rust_ci_plan_01.py"] = materializer.encode()
    tool_ids = {name: {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
                for name, raw in contents.items()}
    ci_manifest = {"schema": "hepta-r36-exact-rust-ci-tools/v1", "attempt": "01",
                   "actual_qualification_job_id": proof["original_job_id"], "qualification_report": qualification_id,
                   "executed": False, "hosted_actions_passed": False, "files": tool_ids}
    ci_manifest_raw = parent.canonical(ci_manifest)
    spec = {"actual_pins": actual_pins, "qualification_report": qualification_id, "tools": tool_ids,
            "manifest": {"bytes": len(ci_manifest_raw), "sha256": hashlib.sha256(ci_manifest_raw).hexdigest()}}
    launcher = assign_frozen(package["ci-templates/launch_exact_rust_ci_01.py"][1].decode(), "SPEC", spec)
    contents["launch_exact_rust_ci_01.py"] = launcher.encode()
    contents["package-manifest-01.json"] = ci_manifest_raw
    for name, raw in contents.items():
        if name.endswith(".py"):
            ast.parse(raw, filename=name)
    for row in bindings:
        need(parent.checked(row["path"], row) == row, "bound input changed before sealing")
    need(parent.source_inputs(parent.SOURCE)["sha256"] == proof["full_source_inputs_sha256"],
         "candidate source changed before sealing")
    need(parent.source_inputs(parent.BASELINE_ROOT / "source")["sha256"] == proof["baseline_full_source_inputs_sha256"],
         "baseline source changed before sealing")
    for name, raw in example_bytes.items():
        parent.create(ROOT / name, raw)
    parent.create(ROOT / "rust-ci-qualification-bindings-01.json", bindings_raw)
    parent.private_directory(ROOT / "rust-ci-tools-01", create_new=True)
    for name, raw in contents.items():
        parent.create(ROOT / "rust-ci-tools-01" / name, raw)
    result = {"schema": "hepta-r36-control-materialization/v1", "passed": True, "created_utc": parent.utc(),
              "qualification_gate": proof, "package_manifest": manifest_id,
              "automatic_retries": 0, "commands_run": 0, "workloads_started": 0,
              "hosted_actions_passed": False,
              "outputs": {path.name: parent.checked(path) for path in outputs if path.suffix == ".json"
                          and path.name != "control-materialization-01.json"},
              "ci_tools": {name: parent.checked(ROOT / "rust-ci-tools-01" / name) for name in contents}}
    parent.create(ROOT / "control-materialization-01.json", parent.canonical(result))
    print(json.dumps(result, sort_keys=True), flush=True)


if __name__ == "__main__":
    os.umask(0o077)
    main()

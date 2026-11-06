#!/usr/bin/env python3
"""Seal fresh R34 exact-CI tools from actual receipt copies; never run CI or a campaign."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import pprint
import re
import stat

BASE = Path(__file__).resolve().parent
ROOT = Path("/home/qian/hepta-runtime-optimization-20261106-r34")
GIT_PARENT = "baab4def80be7af015b2e7a594cb302f66c4130e"
EXPECTED_PATHS = {
    "qualification_report": ROOT / "qualification-01/report.json",
    "qualification_terminal_status": ROOT / "qualification-terminal-status-01.json",
    "qualification_preparation": ROOT / "preparation.json",
    "qualification_launcher": ROOT / "prepare_qualify.py",
    "qualification_input": ROOT / "qualification-input.json",
    "candidate_patch": ROOT / "candidate/candidate.patch",
    "qualification_source_map": ROOT / "qualification-01/source-map.json",
    "qualification_isolated_summary": ROOT / "qualification-01/isolated-tests/summary.json",
    "qualification_isolated_audit": ROOT / "qualification-01/isolated-tests.audit.json",
    "parent_binder": ROOT / "tools-01/r34_campaign.py",
}
FIXED_FILES = {
    "audit_nextest_0137.py": {"bytes": 8563, "sha256": "03fc242ae6ba3f5fa2fc948d3401e5f93a7a388ee9edb5b703183d6410aab8d2"},
    "canonical-workflow.yml": {"bytes": 7631, "sha256": "b9061fd671ac5fff33ad47d7ec5787f82cfadd88f5e71d54a8825cb55a02cd51"},
}
TEMPLATE_PINS = {'launch_exact_rust_ci_01.py': {'bytes': 4628,
                                'sha256': '9edd6839c50399c6b7b9d118346895277622add0cce17aae0c95e121225932c5'},
 'materialize_rust_ci_plan_01.py': {'bytes': 25140,
                                    'sha256': '4e328b2fa3534e99e432f1aa0824f7c2f57547c5bb29374a0c70ee4cdcc9405d'},
 'run_rust_ci_01.py': {'bytes': 15182,
                       'sha256': '908f78d284d84935d5b3efecfe8b3be7bbaaf5893e51107c11cdd8b770d2159b'}}
STAGES = ["format", "fmt-check", "harness-tests", "clippy", "test-build", "isolated-tests", "audit-isolated-tests", "release"]
COUNTS = ("passed", "failed", "ignored", "selected", "retries")


def need(value, reason):
    if not value:
        raise ValueError(reason)


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def identity(body):
    return {"bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()}


def read(path):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path, "direct absolute local input required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= 16 * 1024 * 1024,
             "nonregular, empty or oversized input")
        body = stream.read(before.st_size + 1)
        after = os.fstat(stream.fileno())
    fields = ("st_dev", "st_ino", "st_size", "st_mode", "st_uid", "st_nlink", "st_mtime_ns", "st_ctime_ns")
    final = path.lstat()
    need(len(body) == before.st_size and all(getattr(before, key) == getattr(after, key)
         == getattr(final, key) for key in fields), "local input changed during read")
    return body



def read_template(name):
    body = read(BASE / "templates" / name)
    need(identity(body) == TEMPLATE_PINS[name], "frozen unsealed template changed: " + name)
    return body

def bind_actual(pin, path):
    need(type(pin) is dict and set(pin) == {"local_path", "path", "bytes", "sha256"}
         and pin["path"] == str(path) and type(pin["local_path"]) is str
         and type(pin["bytes"]) is int and pin["bytes"] > 0
         and type(pin["sha256"]) is str and re.fullmatch("[0-9a-f]{64}", pin["sha256"]),
         "missing actual receipt location or identity: " + str(path))
    body = read(pin["local_path"])
    need(identity(body) == {key: pin[key] for key in ("bytes", "sha256")}, "actual original receipt differs: " + str(path))
    return {"path": str(path), **identity(body)}, body


def replace_none(source, name, value):
    tree = ast.parse(source)
    found = [node for node in tree.body if isinstance(node, ast.Assign)
             and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
             and node.targets[0].id == name]
    need(len(found) == 1 and isinstance(found[0].value, ast.Constant)
         and found[0].value.value is None, "unsealed assignment missing or already changed: " + name)
    node = found[0]
    lines = source.splitlines(keepends=True)
    lines[node.lineno - 1:node.end_lineno] = [name + " = " + pprint.pformat(value, sort_dicts=True) + "\n"]
    return "".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pins", type=Path, required=True, help="Actual original R34 receipt copies with their pinned identities")
    parser.add_argument("--out", type=Path, required=True, help="Absent local output directory; no remote action")
    args = parser.parse_args()
    pins_body = read(args.pins)
    pins = json.loads(pins_body)
    need(pins.get("schema") == "hepta-r34-exact-rust-ci-actual-pins/v1"
         and type(pins.get("qualification_job_id")) is str
         and re.fullmatch("[0-9a-f]+-[0-9a-f]+-[0-9a-f]+", pins["qualification_job_id"])
         and type(pins.get("files")) is dict and set(pins["files"]) == set(EXPECTED_PATHS),
         "actual completed qualification pins are still unbound")
    job_id = pins["qualification_job_id"]
    actual, documents = {}, {}
    for key, path in EXPECTED_PATHS.items():
        actual[key], documents[key] = bind_actual(pins["files"][key], path)

    terminal = json.loads(documents["qualification_terminal_status"])
    need(terminal.get("job_id") == job_id and terminal.get("state") == "succeeded"
         and type(terminal.get("exit_code")) is int and terminal["exit_code"] == 0
         and all(terminal.get(key) is False for key in ("automatic_retry", "cancelled", "timed_out"))
         and all(terminal.get(key) is True for key in ("output_complete", "output_durable", "terminal_publication_confirmed"))
         and type(terminal.get("terminal_publication_protocol")) is int and terminal["terminal_publication_protocol"] == 1
         and terminal.get("log_synced") == {"stdout": True, "stderr": True}
         and terminal.get("log_errors") == {"stdout": None, "stderr": None}
         and terminal.get("log_truncated") == {"stdout": False, "stderr": False},
         "actual qualification lacks complete successful native terminal evidence")
    qualification = json.loads(documents["qualification_report"])
    need(qualification.get("schema") == "hepta-x230-composed-qualification/v1"
         and qualification.get("qualified") is True and qualification.get("finished_utc")
         and qualification.get("source") == str(ROOT / "source")
         and type(qualification.get("automatic_test_retries")) is int and qualification["automatic_test_retries"] == 0
         and [row["name"] for row in qualification["stages"]] == STAGES
         and all(type(row["returncode"]) is int and row["returncode"] == 0 for row in qualification["stages"]),
         "all original R34 qualification stages must have completed successfully")
    preparation = json.loads(documents["qualification_preparation"])
    need(preparation.get("schema") == "hepta-x230-r34-preparation/v1"
         and preparation.get("passed") is True and preparation.get("finished_utc")
         and "error" not in preparation and preparation.get("qualification_started") is True
         and type(preparation.get("qualification_returncode")) is int and preparation["qualification_returncode"] == 0
         and preparation["qualification_report_sha256"] == actual["qualification_report"]["sha256"],
         "actual R34 preparation is incomplete, unsuccessful or binds another qualification report")
    source_map = json.loads(documents["qualification_source_map"])
    need(type(source_map) is dict and len(source_map) == 220
         and source_map == qualification["source_after"] == qualification["source_tested"]
         and qualification["harness_before"] == qualification["harness_after"]
         and len(qualification["harness_after"]) == 19
         and set(qualification["binaries"]) == {"hepta-runtime", "hepta-runtime-jobctl", "native_process_driver"},
         "actual formatted 220-input source map, original harness or retained binary inventory differs")
    summary = json.loads(documents["qualification_isolated_summary"])
    audit = json.loads(documents["qualification_isolated_audit"])
    counts = {key: summary[key] for key in COUNTS}
    need(summary.get("schema") == "hepta-isolated-libtest/v1" and summary.get("success") is True
         and summary.get("filter") == "" and summary.get("enumeration_errors") == []
         and all(type(value) is int and value >= 0 for value in counts.values())
         and counts["passed"] > 0 and counts["failed"] == counts["retries"] == 0
         and counts["selected"] == counts["passed"] + counts["ignored"]
         and summary["source_manifest_path"] == str(EXPECTED_PATHS["qualification_source_map"])
         and summary["source_manifest_sha256"] == actual["qualification_source_map"]["sha256"],
         "actual complete isolated test counts or source binding differs")
    need(audit.get("schema") == "hepta-isolated-libtest-audit/v1" and audit.get("success") is True
         and audit.get("errors") == [] and "fatal_error" not in audit and audit.get("expected_filter") == ""
         and all(audit[key] == counts[key] for key in ("passed", "failed", "ignored", "selected"))
         and audit["executed"] == counts["passed"]
         and audit["input_sha256"]["summary.json"] == actual["qualification_isolated_summary"]["sha256"],
         "actual independent qualification audit differs")
    parent_tree = ast.parse(documents["parent_binder"])
    need(sum(isinstance(node, ast.FunctionDef) and node.name == "bind_r34_candidate_preparation"
         for node in parent_tree.body) == 1, "actual R34 receipt binder is absent")

    bindings = {key: actual[key] for key in ("qualification_launcher", "qualification_input",
               "candidate_patch", "qualification_preparation")}
    bindings["qualification_terminal_status"] = dict(actual["qualification_terminal_status"], job_id=job_id)
    bindings["qualification_reports"] = [dict(actual["qualification_report"], success_field="qualified")]
    bindings_body = encoded(bindings)
    bindings_id = {"path": str(ROOT / "rust-ci-qualification-bindings-01.json"), **identity(bindings_body)}
    seal_values = {
        "JOB_ID": job_id,
        "SOURCE_MAP_SHA": actual["qualification_source_map"]["sha256"],
        "ISOLATED_SUMMARY_SHA": actual["qualification_isolated_summary"]["sha256"],
        "ISOLATED_AUDIT_SHA": actual["qualification_isolated_audit"]["sha256"],
        "QUALIFICATION_REPORT_SHA": actual["qualification_report"]["sha256"],
        "PREPARATION_SHA": actual["qualification_preparation"]["sha256"],
        "NATIVE_TERMINAL_SHA": actual["qualification_terminal_status"]["sha256"],
        "PARENT_SHA": actual["parent_binder"]["sha256"],
        "QUALIFICATION_BINDINGS_SHA": bindings_id["sha256"],
        "FROZEN_COUNTS": counts,
    }
    generated = {}
    for name, expected in FIXED_FILES.items():
        body = read(BASE / "fixed" / name)
        need(identity(body) == expected, "fixed original CI input changed: " + name)
        generated[name] = body
    materializer = read_template("materialize_rust_ci_plan_01.py").decode("utf-8")
    for name, value in seal_values.items():
        materializer = replace_none(materializer, name, value)
    generated["materialize_rust_ci_plan_01.py"] = materializer.encode("utf-8")
    generated["run_rust_ci_01.py"] = read_template("run_rust_ci_01.py")
    tool_ids = {name: identity(body) for name, body in sorted(generated.items())}
    workflow = {"path": str(ROOT / "rust-ci-tools-01/canonical-workflow.yml"), **FIXED_FILES["canonical-workflow.yml"]}
    private_workflow = {"path": str(ROOT / "source/.github/workflows/ci.yml"), "bytes": 7235,
                        "sha256": "5574840f604a3c7963a274592ac2468a43fdd04cdaa7122851c271188a11065d"}
    manifest = {
        "schema": "hepta-r34-exact-rust-ci-tools/v1", "attempt": "01",
        "actual_qualification_job_id": job_id, "qualification_report": actual["qualification_report"],
        "qualification_counts": counts, "canonical_workflow": workflow, "private_source_workflow": private_workflow,
        "qualification_bindings": bindings_id, "parent_binder": actual["parent_binder"],
        "git_parent": GIT_PARENT, "files": tool_ids, "executed": False, "hosted_actions_passed": False,
    }
    manifest_body = encoded(manifest)
    spec = {"actual_pins": seal_values, "manifest": identity(manifest_body),
            "qualification_report": actual["qualification_report"], "tools": tool_ids}
    launcher = replace_none(read_template("launch_exact_rust_ci_01.py").decode("utf-8"), "SPEC", spec)
    generated["launch_exact_rust_ci_01.py"] = launcher.encode("utf-8")
    generated["package-manifest-01.json"] = manifest_body
    for name, body in generated.items():
        if name.endswith(".py"):
            ast.parse(body, filename=name)
    for key in EXPECTED_PATHS:
        need(identity(read(pins["files"][key]["local_path"])) == {field: actual[key][field]
             for field in ("bytes", "sha256")}, "actual input changed before seal publication")
    need(read(args.pins) == pins_body, "actual pins file changed")
    out = args.out
    need(out.is_absolute() and out.parent.resolve(strict=True) == out.parent
         and not os.path.lexists(out), "absent direct local output required; never replace an earlier attempt")
    os.umask(0o077)
    out.mkdir(mode=0o700)
    (out / "tools").mkdir(mode=0o700)
    for name, body in generated.items():
        with (out / "tools" / name).open("xb") as stream:
            stream.write(body)
    with (out / "rust-ci-qualification-bindings-01.json").open("xb") as stream:
        stream.write(bindings_body)
    with (out / "actual-pins.json").open("xb") as stream:
        stream.write(pins_body)
    report = {
        "schema": "hepta-r34-exact-rust-ci-sealed-delivery/v1", "status": "sealed_not_executed",
        "root": str(ROOT), "git_parent": GIT_PARENT, "actual_qualification_job_id": job_id,
        "actual_inputs": actual, "qualification_counts": counts, "compiler_input_count": 220,
        "files": {name: identity(body) for name, body in sorted(generated.items())},
        "qualification_bindings": bindings_id,
        "parent_dependency": "Install the exact bound ROOT/tools-01/r34_campaign.py before running CI; non-main import only calls its qualification binder.",
        "detailed_preparation_validation": "The reviewed R34 binder checks original preparation, formatter-adjusted map and closed cache owner on x230 before any CI command.",
        "ci_executed": False, "campaign_executed": False, "hosted_actions_passed": False,
    }
    with (out / "seal-manifest.json").open("xb") as stream:
        stream.write(encoded(report))
    print(json.dumps({"status": report["status"], "out": str(out), "qualification_counts": counts,
                      "launcher": identity(generated["launch_exact_rust_ci_01.py"]), "ci_executed": False}))


if __name__ == "__main__":
    main()

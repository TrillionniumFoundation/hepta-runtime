#!/usr/bin/env python3
"""Seal only parent input identities from actual local qualification originals.
No generated parent, binder, installer, auditor, compiler, or workload is executed.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import pprint
import re
import stat

HERE = Path(__file__).resolve().parent
ROOT = Path('/home/qian/hepta-runtime-validation-scratch-20261106-r36-cold-02')
HEX = re.compile(r"[0-9a-f]{64}\Z")
STAGES = ['format', 'fmt-check', 'harness-tests', 'clippy', 'test-build', 'isolated-tests', 'audit-isolated-tests', 'release']
CHANGED = {'src/mcp/runtime/ssh_observation_profile.rs', 'src/mcp/runtime/ssh_observation_reference_tests.rs'}

def need(value, message):
    if not value:
        raise RuntimeError(message)


def checked(path, expected=None, maximum=128 * 1024 * 1024, retain=False):
    path = Path(path)
    need(path.is_absolute() and path.resolve() == path, "indirect input path: " + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= maximum,
             "unsafe or oversized file: " + str(path))
        chunks, count, digest = [], 0, hashlib.sha256()
        while count <= maximum:
            block = os.read(fd, min(1024 * 1024, maximum + 1 - count))
            if not block:
                break
            digest.update(block)
            count += len(block)
            if retain:
                chunks.append(block)
        fields = ("st_dev", "st_ino", "st_uid", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        stamp = lambda value: tuple(getattr(value, name) for name in fields)
        need(count == before.st_size and count <= maximum and
             stamp(before) == stamp(os.fstat(fd)) == stamp(path.lstat()), "file changed while reading: " + str(path))
    finally:
        os.close(fd)
    identity = {"path": str(path), "bytes": count, "sha256": digest.hexdigest()}
    if expected is not None:
        pin = expected if isinstance(expected, str) else expected["sha256"]
        need(isinstance(pin, str) and HEX.fullmatch(pin) and identity["sha256"] == pin, "SHA differs: " + str(path))
        if isinstance(expected, dict):
            need(type(expected["bytes"]) is int and identity["bytes"] == expected["bytes"], "byte length differs: " + str(path))
    return (identity, b"".join(chunks)) if retain else identity


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def create(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def private_directory(path, create_new=False):
    need(path.is_absolute() and path.resolve() == path, "indirect private directory")
    if create_new:
        path.mkdir(mode=0o700)
    value = path.lstat()
    need(stat.S_ISDIR(value.st_mode) and value.st_uid == os.geteuid()
         and stat.S_IMODE(value.st_mode) == 0o700, "private directory ownership/mode differs: " + str(path))


def verify_r36_terminal(terminal, job_id):
    """Keep the original native job's complete terminal/log requirements."""
    need(isinstance(job_id, str) and re.fullmatch(r"[0-9a-f]{11,16}-[0-9a-f]{4}-[0-9a-f]{4}", job_id),
         "actual original R36 qualification job identity required")
    need(terminal.get("job_id") == job_id and terminal.get("state") == "succeeded"
         and type(terminal.get("exit_code")) is int and terminal["exit_code"] == 0
         and all(terminal.get(key) is False for key in ("automatic_retry", "timed_out", "cancelled"))
         and all(terminal.get(key) is True for key in ("output_complete", "output_durable", "terminal_publication_confirmed"))
         and type(terminal.get("terminal_publication_protocol")) is int and terminal["terminal_publication_protocol"] == 1
         and terminal.get("log_synced") == {"stdout": True, "stderr": True}
         and terminal.get("log_errors") == {"stdout": None, "stderr": None}
         and terminal.get("log_truncated") == {"stdout": False, "stderr": False},
         "original R36 qualification has no complete successful native terminal proof")
    for stream in ("stdout", "stderr"):
        counts = terminal["log_bytes"][stream]
        need(set(counts) == {"seen", "stored"}
             and all(type(value) is int and value >= 0 for value in counts.values())
             and counts["seen"] == counts["stored"], "qualification native log byte custody differs")


def r36_owner_native_streams(value, terminal):
    """Bind a complete original single-page native read to its terminal byte counts."""
    assert value['job_id'] == terminal['job_id'] and value['audit_recorded'] is True
    result = {}
    for name in ('stdout', 'stderr'):
        channel = value[name]
        raw = bytes.fromhex(channel['bytes_hex'])
        assert channel['offset'] == 0 and channel['eof'] is True
        assert channel['size'] == channel['next_offset'] == len(raw)
        assert len(raw) == terminal['log_bytes'][name]['stored']
        assert channel['text'] == raw.decode('utf-8', errors='replace')
        result[name] = raw
    return result


def identity(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def assigned(text, name):
    found = [node for node in ast.parse(text).body if isinstance(node, ast.Assign)
             and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
             and node.targets[0].id == name]
    need(len(found) == 1, "unique literal assignment required: " + name)
    return found[0]


def inject(text, name, value):
    node = assigned(text, name)
    need(ast.literal_eval(node.value) is None, "already sealed parent")
    lines = text.splitlines(keepends=True)
    lines[node.lineno - 1:node.end_lineno] = [name + " = " + pprint.pformat(value, sort_dicts=True) + "\n"]
    result = "".join(lines)
    before, after = ast.parse(text), ast.parse(result)
    indices = [index for index, item in enumerate(after.body) if isinstance(item, ast.Assign)
               and len(item.targets) == 1 and isinstance(item.targets[0], ast.Name)
               and item.targets[0].id == name]
    need(len(indices) == 1, "sealed assignment is not unique")
    after.body[indices[0]] = node
    need(ast.dump(before, include_attributes=False) == ast.dump(after, include_attributes=False),
         "parent changed beyond the single seal assignment")
    return result.encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    request_id, data = checked(args.request, retain=True, maximum=65536)
    request = json.loads(data)
    need(request["schema"] == "hepta-r36-scratch-parent-sealing-request/v1"
         and request["runtime_root"] == str(ROOT), "sealing request is for another candidate")
    output = args.output.absolute()
    need(output.resolve() == output and not os.path.lexists(output), "new direct seal output required")
    bundle_id, data = checked(HERE / "generated/runner-bundle-manifest.json", retain=True, maximum=65536)
    bundle = json.loads(data)
    need(bundle["schema"] == "hepta-r36-parent-runner-bundle/v1"
         and bundle["runtime_root"] == str(ROOT) and bundle["sealed"] is False,
         "unsealed cold-only source bundle required")
    names = {"r36_campaign.py", "r36_lifecycle_campaign.py", "prepare_campaign_inputs.py",
             "prepare_lifecycle_inputs.py", "install_measurement_tools.py"}
    need(set(bundle["files"]) == names, "fixed five parent tools required")
    source, observed = {}, [request_id, bundle_id]
    for name, pin in sorted(bundle["files"].items()):
        item, source[name] = checked(HERE / "generated" / name, pin, retain=True, maximum=262144)
        ast.parse(source[name])
        observed.append(item)
    fixtures = {}
    need(set(bundle["fixture_inputs"]) == {"topology.json", *["jobs/" + name for name in bundle["frozen_job_names"]]},
         "frozen fixture inventory differs")
    for name, pin in sorted(bundle["fixture_inputs"].items()):
        need(not Path(name).is_absolute() and ".." not in Path(name).parts, "unsafe fixture member")
        item, fixtures[name] = checked(HERE / "frozen-fixture-inputs" / name, pin, retain=True, maximum=65536)
        observed.append(item)
    holder_id, holder_raw = checked(HERE / "mac-launchers-01/held_agent_campaign_02.py",
                                   bundle["original_held_agent_sha256"], retain=True, maximum=65536)
    observed.append(holder_id)
    candidate_id, raw = checked(HERE / "candidate-input.reference.json",
                               bundle["candidate_input_reference"], retain=True, maximum=65536)
    candidate = json.loads(raw)
    observed.append(candidate_id)

    runtime_paths = {
        "qualification_launcher": ROOT / "prepare_qualify.py",
        "qualification_input": ROOT / "qualification-input.json",
        "owner_closure_input": ROOT / "cache-owner-closure-inputs.json",
        "preparation": ROOT / "preparation.json",
        "qualification_report": ROOT / "qualification-01/report.json",
        "source_map": ROOT / "qualification-01/source-map.json",
        "isolated_summary": ROOT / "qualification-01/isolated-tests/summary.json",
        "isolated_audit": ROOT / "qualification-01/isolated-tests.audit.json",
        "native_terminal": ROOT / "qualification-terminal-status-01.json",
        "native_read": ROOT / "qualification-native-read-01.json",
    }
    need(set(request["artifacts"]) == set(runtime_paths), "ten actual original artifacts required")
    raw_artifacts, documents, actual = {}, {}, {}
    for name, path in runtime_paths.items():
        item = request["artifacts"][name]
        need(set(item) == {"local_path", "bytes", "sha256"}
             and type(item["bytes"]) is int and item["bytes"] > 0
             and isinstance(item["sha256"], str) and HEX.fullmatch(item["sha256"]),
             "actual artifact is unresolved: " + name)
        local_id, raw = checked(item["local_path"], item, retain=True, maximum=8 * 1024 * 1024)
        observed.append(local_id)
        raw_artifacts[name] = raw
        actual[name] = dict(identity(raw), path=str(path))
        if name != "qualification_launcher":
            documents[name] = json.loads(raw)
    for name in ("qualification_launcher", "qualification_input", "owner_closure_input"):
        need(actual[name] == bundle["preparation_reference"][name], "reviewed preparation artifact differs: " + name)
    prep_source = raw_artifacts["qualification_launcher"].decode()
    root_node = assigned(prep_source, "ROOT").value
    cargo_node = assigned(prep_source, "CARGO_HOME").value
    need(isinstance(root_node, ast.Call) and isinstance(cargo_node, ast.Call)
         and ast.literal_eval(root_node.args[0]) == str(ROOT)
         and ast.literal_eval(cargo_node.args[0]) == bundle["preparation_reference"]["cargo_home"],
         "reviewed preparer's root or Cargo home differs")
    inputs, closure = documents["qualification_input"], documents["owner_closure_input"]
    need(inputs["schema"] == "hepta-r36-direct-qualification-input/v1"
         and closure["schema"] == "hepta-r36-d2-cache-owner-closure/v1"
         and inputs["sealed"] is True and closure["sealed"] is True
         and inputs["required_missing_bindings"] == closure["required_missing_bindings"] == []
         and inputs["owner_closure_input_sha256"] == actual["owner_closure_input"]["sha256"],
         "actual preparation input closure differs")
    need(inputs["preparation_tool"] == dict(identity(raw_artifacts["qualification_launcher"]), path="prepare_qualify.py"),
         "qualification input names another reviewed preparer")
    preparation, qualified = documents["preparation"], documents["qualification_report"]
    need(preparation["schema"] == "hepta-x230-r36-preparation/v1"
         and preparation.get("passed") is True and preparation.get("finished_utc")
         and "error" not in preparation and preparation["qualification_returncode"] == 0
         and preparation["qualification_started"] is True
         and preparation["build_mode"] == "cold-only" and preparation["preparation_attempt"] == "cold-02"
         and preparation["cache_reused"] is False and preparation["cache_transferred_by_rename"] is False
         and preparation["ownership_transfer_applicable"] is False
         and preparation["new_empty_target_created"] is True and preparation["cache_to_transfer"] is None,
         "the original cold-only qualification has not closed successfully")
    need(preparation["input_binding"] == actual["qualification_input"]
         and preparation["cache_owner_closure_input"] == actual["owner_closure_input"]
         and preparation["qualification_report_sha256"] == actual["qualification_report"]["sha256"],
         "actual preparation does not bind these original artifacts")
    need(qualified["schema"] == "hepta-x230-composed-qualification/v1"
         and qualified["qualified"] is True and qualified.get("finished_utc") and "error" not in qualified
         and qualified["source"] == str(ROOT / "source") and qualified["jobs"] == 2
         and qualified["automatic_test_retries"] == 0 and qualified["service_changes"] is False
         and [row["name"] for row in qualified["stages"]] == STAGES
         and all(type(row["returncode"]) is int and row["returncode"] == 0 for row in qualified["stages"]),
         "the original eight-stage qualification has not passed")
    final_map = documents["source_map"]
    need(preparation["source_before_qualification"] == qualified["source_input"] == candidate["candidate_compile_inputs"]
         and preparation["source_after_qualification"] == qualified["source_tested"] == qualified["source_after"] == final_map
         and set(final_map) == set(candidate["baseline_compile_inputs"]) and len(final_map) == 220
         and {name for name in final_map if final_map[name] != candidate["baseline_compile_inputs"][name]} == CHANGED
         and qualified["harness_before"] == qualified["harness_after"] == inputs["qualification_harness_sha256"],
         "actual source/harness custody differs from the two-file candidate")
    tests, audit = documents["isolated_summary"], documents["isolated_audit"]
    counts = {key: tests[key] for key in ("passed", "failed", "ignored", "selected", "retries")}
    need(tests["schema"] == "hepta-isolated-libtest/v1" and tests["success"] is True
         and tests["filter"] == "" and tests["enumeration_errors"] == [] and not tests.get("fatal_error")
         and all(type(value) is int and value >= 0 for value in counts.values())
         and counts["passed"] > 0 and counts["failed"] == counts["retries"] == 0
         and counts["selected"] == counts["passed"] + counts["ignored"]
         and audit["schema"] == "hepta-isolated-libtest-audit/v1" and audit["success"] is True
         and audit["errors"] == [] and audit["expected_filter"] == ""
         and all(audit[key] == counts[key] for key in ("passed", "failed", "ignored", "selected"))
         and audit["input_sha256"]["summary.json"] == actual["isolated_summary"]["sha256"]
         and audit["input_sha256"]["source-manifest.input"] == actual["source_map"]["sha256"],
         "actual isolated counts or original audit bindings differ")
    terminal, read = documents["native_terminal"], documents["native_read"]
    job = terminal["job_id"]
    verify_r36_terminal(terminal, job)
    r36_owner_native_streams(read, terminal)

    seal = {"schema": "hepta-r36-scratch-parent-preparation-seal/v1", "runtime_root": str(ROOT),
            **{name: actual[name] for name in ("qualification_launcher", "qualification_input", "owner_closure_input")},
            "cargo_home": bundle["preparation_reference"]["cargo_home"]}
    source["r36_campaign.py"] = inject(source["r36_campaign.py"].decode(), "R36_PREPARATION_SEAL", seal)
    bundle["files"] = {name: identity(raw) for name, raw in sorted(source.items())}
    bundle["sealed"] = True
    bundle["status"] = "ACTUAL_QUALIFICATION_BOUND_MEASUREMENT_NOT_STARTED"
    bundle["actual_qualification"] = {"original_job_id": job, "artifacts": actual, "tests": counts,
                                      "formatted_source_map_sha256": actual["source_map"]["sha256"]}
    bundle.pop("future_qualification", None)
    bundle["exact_ci_result"] = bundle["observation_result"] = bundle["normal_lifecycle_result"] = None
    payloads = {"x230/tools-01/" + name: raw for name, raw in source.items()}
    payloads["x230/tools-01/runner-bundle-manifest.json"] = canonical(bundle)
    payloads.update({"x230/tools-01/frozen-fixture-inputs/" + name: raw for name, raw in fixtures.items()})
    payloads.update({"mac/held_agent_campaign_02.py": holder_raw,
                     "mac/r36_campaign.py": source["r36_campaign.py"],
                     "mac/r36_lifecycle_campaign.py": source["r36_lifecycle_campaign.py"]})
    for item in observed:
        need(checked(item["path"], item) == item, "sealing input changed")
    receipt = {"schema": "hepta-r36-scratch-parent-bundle-seal/v1", "runtime_root": str(ROOT),
               "actual_qualification": bundle["actual_qualification"], "preparation_seal": seal,
               "template_bundle": bundle_id, "request": request_id,
               "files": {name: identity(raw) for name, raw in sorted(payloads.items())},
               "only_parent_assignment_changed": "R36_PREPARATION_SEAL",
               "target_functions_executed": 0, "compiler_or_workload_started": False,
               "exact_ci_result": None, "observation_result": None, "normal_lifecycle_result": None}
    payloads["sealing-receipt.json"] = canonical(receipt)
    private_directory(output, create_new=True)
    directories = {Path(name).parent for name in payloads}
    ancestors = set()
    for relative in directories:
        while str(relative) != ".":
            ancestors.add(relative)
            relative = relative.parent
    for relative in sorted(ancestors, key=lambda path: (len(path.parts), str(path))):
        private_directory(output / relative, create_new=True)
    for name, raw in sorted(payloads.items()):
        create(output / name, raw)
        checked(output / name, identity(raw))
    print(json.dumps({"sealed": True, "output": str(output), "files": len(payloads),
                      "receipt": checked(output / "sealing-receipt.json"), "original_job_id": job,
                      "compiler_or_workload_started": False}, sort_keys=True), flush=True)


if __name__ == "__main__":
    os.umask(0o077)
    main()

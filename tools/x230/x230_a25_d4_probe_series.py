#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Run one fixed same-binary D4 diagnostic series, then one conditional extension.

This runner changes no harness or runtime source and makes no adoption decision.
Its fresh output directory contains the predeclared plan, immutable receipts,
and untouched driver reports/logs. It must inherit the held SSH_AUTH_SOCK.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time


HELPERS = {
    "initial": "efdf18dc4ded1193884cc7c529ca652ae22c1d7178e2fd29973463cceffa6db0",
    "extended": "9aed77048e91757034877c9d117781e6f36873db5c9e8d70fe0dfca76eb098ff",
}
STAGES = (("initial", "ABBA", 192, [1, 4, 8]),
          ("extended", "B", 12000, [8]))
QUAL_STAGES = ["format", "fmt-check", "clippy", "test", "release"]
PREFIX = b"HEPTA_X230_SPAWN_PROOF_FAILURE_JSON "
EVENT_SCHEMA = "hepta-x230-spawn-proof-failure/v2-d4"
STDERR_PARSE_LIMIT = 1024 * 1024


def need(condition, message):
    if not condition:
        raise RuntimeError(message)


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def sha_bytes(value):
    return hashlib.sha256(value).hexdigest()


def stamp(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def file_receipt(path, prefix_limit=0):
    """Hash all bytes with bounded memory; retain at most prefix_limit bytes."""
    path = Path(path)
    need(not path.is_symlink(), "symlink input refused: " + str(path))
    before = path.stat()
    need(stat.S_ISREG(before.st_mode), "nonregular input refused: " + str(path))
    hashed, prefix, length = hashlib.sha256(), bytearray(), 0
    with path.open("rb") as stream:
        need(stamp(os.fstat(stream.fileno())) == stamp(before), "input changed while opening")
        while True:
            chunk = stream.read(65536)
            if not chunk:
                break
            hashed.update(chunk)
            length += len(chunk)
            if len(prefix) < prefix_limit:
                prefix.extend(chunk[:prefix_limit - len(prefix)])
        need(stamp(os.fstat(stream.fileno())) == stamp(before), "input changed while reading")
    need(stamp(path.stat()) == stamp(before) and length == before.st_size,
         "input changed after reading")
    return {"bytes": length, "sha256": hashed.hexdigest()}, bytes(prefix)


def json_input(path, limit=128 * 1024 * 1024):
    receipt, content = file_receipt(path, limit + 1)
    need(receipt["bytes"] <= limit, "JSON input exceeds read bound")
    return json.loads(content), receipt


def save_new(path, value):
    content = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    with path.open("xb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return {"bytes": len(content), "sha256": sha_bytes(content)}


def source_snapshot(root):
    need(root.is_dir() and not root.is_symlink(), "source must be a direct directory")
    files = {}
    for path in sorted(root.rglob("*")):
        need(not path.is_symlink(), "source symlink refused")
        if path.is_dir():
            continue
        receipt, _ = file_receipt(path)
        files[path.relative_to(root).as_posix()] = receipt["sha256"]
    need(files, "empty source snapshot")
    again = set()
    for path in root.rglob("*"):
        need(not path.is_symlink(), "source symlink appeared during enumeration")
        if not path.is_dir():
            again.add(path.relative_to(root).as_posix())
    need(set(files) == again, "source file set changed during enumeration")
    return files


def verify_inputs(args):
    report, qualification = json_input(args.qualification)
    need(report.get("schema") == "runtime-candidate-qualification/v1"
         and report.get("qualified") is True, "qualification did not pass")
    stages = report.get("stages", [])
    need([s.get("name") for s in stages] == QUAL_STAGES
         and all(s.get("returncode") == 0 for s in stages), "qualification stages differ")
    logs = {}
    for stage in stages:
        receipt, _ = file_receipt(args.qualification.parent / (stage["name"] + ".log"))
        need(receipt["sha256"] == stage.get("log_sha256"), "qualification log changed")
        logs[stage["name"]] = receipt
    source = Path(report["source"])
    need(source.is_absolute(), "qualification source must be absolute")
    need(not args.out.is_relative_to(source), "output cannot be inside qualified source")
    tested = report.get("source_tested")
    need(isinstance(tested, dict) and tested and tested == report.get("source_after"),
         "tested and final source maps differ")
    actual = source_snapshot(source)
    need(actual == tested, "actual source differs from qualified source/file set")
    binaries = {}
    for kind in ("binary", "test_binary"):
        declared = report[kind]
        binary = Path(declared["path"])
        need(binary.is_absolute() and os.access(binary, os.X_OK), "qualified binary unavailable")
        need(Path(declared["compiler_source"]) == source / "src/main.rs", "compiler source differs")
        receipt, _ = file_receipt(binary)
        need(receipt["sha256"] == declared["sha256"], "qualified binary changed")
        binaries[kind] = {"path": str(binary), **receipt}
    diagnostic = source / "src/mcp/runtime/ssh_observation_spawn_diagnostic.rs"
    _, diagnostic_bytes = file_receipt(diagnostic, 1024 * 1024)
    need(EVENT_SCHEMA.encode() in diagnostic_bytes and PREFIX.rstrip() in diagnostic_bytes,
         "qualified source does not contain D4 event schema")
    pool = source / "src/mcp/runtime/ssh_observation_pool.rs"
    _, pool_bytes = file_receipt(pool, 1024 * 1024)
    need(b"mod spawn_diagnostic;" in pool_bytes
         and b"spawn_diagnostic::initialize();" in pool_bytes
         and b"spawn_diagnostic::finish_cleanup(&cleanup);" in pool_bytes,
         "D4 owner hooks missing")
    validation = source / "src/mcp/runtime/ssh_observation_validation.rs"
    _, validation_bytes = file_receipt(validation, 1024 * 1024)
    need(re.search(rb"const\s+WORKERS\s*:\s*usize\s*=\s*2\s*;", validation_bytes),
         "validation worker bound differs from two")
    helpers = {}
    for name, path in (("initial", args.benchmark), ("extended", args.soak)):
        receipt, _ = file_receipt(path)
        need(receipt["sha256"] == HELPERS[name], "frozen helper hash mismatch: " + name)
        helpers[name] = receipt
    inputs = {}
    template, inputs["profile_template"] = json_input(args.profile_template, 262144)
    for name in ("ssh_config", "known_hosts"):
        inputs[name], _ = file_receipt(Path(template[name]))
        need(inputs[name]["sha256"] == template[name + "_sha256"], "historical SSH input changed")
    # The frozen harness consumes a DIRECTORY of six original record files.
    records = source_snapshot(args.frozen_jobs)
    need(len(records) == 6 and all(name.endswith(".json") and "/" not in name for name in records),
         "exactly six direct frozen JSON records are required")
    inputs["frozen_job_records"] = records
    agent = os.environ.get("SSH_AUTH_SOCK", "")
    need(agent.startswith("/") and stat.S_ISSOCK(os.stat(agent).st_mode),
         "held parent SSH_AUTH_SOCK required")
    need(args.socket_parent.is_dir(), "socket parent unavailable")
    return {"qualification": qualification, "stage_logs": logs,
            "source_files": actual, "source_file_count": len(actual),
            "source_map_sha256": sha_bytes(json.dumps(actual, sort_keys=True,
                                                       separators=(",", ":")).encode()),
            "binaries": binaries, "helpers": helpers, "inputs": inputs,
            "parent_agent_inherited": True, "validation_workers": 2}


def command(args, binary, spec):
    name, order, calls, concurrency = spec
    helper = args.benchmark if name == "initial" else args.soak
    return [sys.executable, str(helper), "--baseline", binary, "--candidate", binary,
            "--profile-template", str(args.profile_template), "--frozen-jobs", str(args.frozen_jobs),
            "--socket-parent", str(args.socket_parent), "--out", str(args.out / name),
            "--calls", str(calls), "--concurrency", *map(str, concurrency),
            "--workers", "2", "--order", order]


def collect_events(directory, order):
    expected = {f"round-{i}-{label}/{phase}/stderr.log"
                for i, label in enumerate(order) for phase in ("first", "restart")}
    actual = {p.relative_to(directory).as_posix() for phase in ("first", "restart")
              for p in directory.glob("*/" + phase + "/stderr.log")}
    output = {"logs": [], "events": [], "errors": [], "missing_logs": sorted(expected - actual)}
    for relative in sorted(actual):
        try:
            receipt, content = file_receipt(directory / relative, STDERR_PARSE_LIMIT)
            truncated = receipt["bytes"] > STDERR_PARSE_LIMIT
            row = {"path": relative, **receipt, "parse_limit_bytes": STDERR_PARSE_LIMIT,
                   "truncated": truncated}
            output["logs"].append(row)
            if truncated:
                output["errors"].append({"path": relative, "reason": "stderr_parse_bound_exceeded"})
            for line_number, line in enumerate(content.splitlines(), 1):
                if PREFIX.rstrip() not in line:
                    continue
                try:
                    need(line.startswith(PREFIX), "event prefix not at line start")
                    event = json.loads(line[len(PREFIX):])
                    need(isinstance(event, dict), "event is not an object")
                    output["events"].append({"path": relative, "line": line_number,
                                              "line_sha256": sha_bytes(line), "event": event})
                    need(event.get("schema") == EVENT_SCHEMA, "unexpected event schema")
                except (ValueError, RuntimeError) as error:
                    output["errors"].append({"path": relative, "line": line_number,
                                             "line_sha256": sha_bytes(line), "reason": str(error)})
        except Exception as error:
            output["errors"].append({"path": relative, "reason": str(error)})
    output["event_count"] = len(output["events"])
    output["complete"] = not output["missing_logs"] and not output["errors"] and actual == expected
    return output


def driver_report_gate(report, spec, binary_sha):
    _, order, calls, concurrency = spec
    need(report.get("passed") is True, "driver report did not pass")
    need(report.get("order") == order and report.get("calls_per_cell") == calls
         and report.get("concurrency") == concurrency and report.get("tokio_workers") == 2,
         "driver dimensions differ from plan")
    need(report.get("binary_sha256") == {"A": binary_sha, "B": binary_sha},
         "driver did not use the same qualified binary for both labels")
    need(report.get("source_originals_unchanged") is True
         and report.get("binary_hashes_unchanged") is True, "driver input integrity failed")
    need(all(report.get(k) == 0 for k in ("effect_starts", "remote_mutation_tool_calls",
                                        "automatic_rpc_retries")), "driver effect/retry contract differs")
    rounds = report.get("rounds", [])
    need(len(rounds) == len(order), "incomplete driver rounds")
    for i, row in enumerate(rounds):
        need(row.get("index") == i and row.get("version") == order[i] and row.get("passed") is True,
             "driver round did not pass")
        cells = row.get("cells", [])
        need([c.get("concurrency") for c in cells] == concurrency
             and all(c.get("calls") == calls and c.get("successes") == calls for c in cells),
             "driver calls failed or are missing")
        for key, expected_count in (("initial_complete_outputs", 6), ("restart_checks", 12)):
            checks = row.get(key, [])
            need(len(checks) == expected_count and all(c.get("okay") is True for c in checks),
                 "original output/restart verification failed")
        for key in ("shutdown", "restart_shutdown"):
            shutdown = row.get(key, {})
            need(shutdown.get("exit_code") == 0 and shutdown.get("shutdown_method") == "stdin_eof"
                 and shutdown.get("observed_descendant_survivors") == []
                 and shutdown.get("reader_error") is None and shutdown.get("unmatched_responses") == 0,
                 "controller did not complete clean EOF shutdown")


def run_stage(args, before, spec):
    name, order, _, _ = spec
    binary = before["binaries"]["binary"]
    argv = command(args, binary["path"], spec)
    result = {"stage": name, "started_utc": now(), "command": argv,
              "gate_passed": False, "automatic_retries": 0, "driver_exit_observed": False,
              "sigint_forward_attempted": False, "sigint_forward_call_completed": False}
    stdout_path = args.out / (name + ".driver.stdout.log")
    stderr_path = args.out / (name + ".driver.stderr.log")
    started = time.monotonic()
    try:
        with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
            env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
            process = subprocess.Popen(argv, cwd=args.root, env=env, stdin=subprocess.DEVNULL,
                                       stdout=stdout, stderr=stderr)
            result["interrupted"] = False
            # Never scan a live driver's logs or replace its own EOF cleanup.
            while True:
                try:
                    result["returncode"] = process.wait()
                    result["driver_exit_observed"] = True
                    break
                except KeyboardInterrupt:
                    result["interrupted"] = True
                    if not result["sigint_forward_attempted"]:
                        result["sigint_forward_attempted"] = True
                        try:
                            process.send_signal(signal.SIGINT)
                            result["sigint_forward_call_completed"] = True
                        except OSError as error:
                            result["sigint_forward_error"] = str(error)
                    # One signal through the original Popen only. A completed
                    # send_signal call is not a delivery/cleanup acknowledgment;
                    # keep waiting, including the driver's ThreadPool cleanup.
            for stream in (stdout, stderr):
                stream.flush()
                os.fsync(stream.fileno())
    except Exception as error:
        result["driver_launch_error"] = str(error)
    result["seconds"] = time.monotonic() - started
    result["finished_utc"] = now()
    result["stderr_evidence"] = (collect_events(args.out / name, order)
        if result["driver_exit_observed"] else {
            "complete": False, "event_count": 0, "events": [], "logs": [],
            "errors": [{"reason": "driver_exit_not_observed_logs_not_scanned"}], "missing_logs": []})
    result["driver_logs"] = {}
    for key, path in (("stdout", stdout_path), ("stderr", stderr_path)):
        try:
            result["driver_logs"][key], _ = file_receipt(path)
        except Exception as error:
            result["driver_logs"][key] = {"error": str(error)}
    report = None
    try:
        need(result["driver_exit_observed"], "driver exit not observed; report not scanned")
        report, result["raw_report"] = json_input(args.out / name / "report.json")
        result["raw_report"]["path"] = name + "/report.json"
        result["reported_passed"] = report.get("passed")
    except Exception as error:
        result["raw_report_error"] = str(error)
    try:
        after = verify_inputs(args)
        result["inputs_after"] = after
        need(after == before, "qualified source/binaries/helpers/inputs changed during stage")
        result["inputs_unchanged"] = True
    except Exception as error:
        result["inputs_unchanged"] = False
        result["inputs_after_error"] = str(error)
    try:
        need(result["driver_exit_observed"], "driver exit not observed; no extension")
        need(report is not None, "driver report missing or unreadable")
        need(result["inputs_unchanged"], "input integrity failed after driver")
        need(result.get("returncode") == 0 and not result.get("interrupted"), "driver failed or interrupted")
        driver_report_gate(report, spec, binary["sha256"])
        evidence = result["stderr_evidence"]
        need(evidence["complete"], "D4 stderr collection is incomplete or invalid")
        need(evidence["event_count"] == 0, "D4 postspawn proof failure event captured")
        result["gate_passed"] = True
    except Exception as error:
        result["gate_error"] = str(error)
    save_new(args.out / (name + ".receipt.json"), result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("qualification", "root", "profile-template", "frozen-jobs", "socket-parent", "out"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--benchmark", type=Path, help="default: ROOT/x230_observation_benchmark.py")
    parser.add_argument("--soak", type=Path, help="default: ROOT/x230_observation_soak.py")
    args = parser.parse_args()
    args.root = args.root.absolute()
    need(args.root.is_dir() and args.root.resolve() == args.root, "root must be a direct directory")
    for name in ("qualification", "profile_template", "frozen_jobs", "socket_parent", "out", "benchmark", "soak"):
        path = getattr(args, name)
        if path is None:
            path = Path("x230_observation_" + ("benchmark" if name == "benchmark" else "soak") + ".py")
        path = path if path.is_absolute() else args.root / path
        need(path.resolve() == path, "paths must be direct, without symlink or parent traversal")
        setattr(args, name, path)
    os.umask(0o077)
    args.out.mkdir(mode=0o700, exist_ok=False)
    summary = {"schema": "hepta-x230-a25-d4-probe-series/v1", "started_utc": now(),
               "diagnostic_gate_passed": False, "same_binary_only": True,
               "performance_adoption": False, "performance_comparison_generated": False,
               "automatic_retries": 0, "stages": []}
    try:
        before = verify_inputs(args)
        source_receipt, _ = file_receipt(Path(__file__).resolve())
        inputs_receipt = save_new(args.out / "inputs-before.json", before)
        binary = before["binaries"]["binary"]
        plan = {"schema": "hepta-x230-a25-d4-probe-plan/v1", "created_utc": now(),
                "kind": "predeclared_plan_not_an_outcome", "runner_source": source_receipt,
                "qualified_inputs_receipt": inputs_receipt, "binary_sha256": binary["sha256"],
                "both_labels_use_same_binary": True, "frozen_helper_sha256": HELPERS,
                "tokio_workers": 2, "validation_workers": 2, "automatic_retries": 0,
                "performance_adoption": False, "performance_comparison_generated": False,
                "event_schema": EVENT_SCHEMA, "stderr_parse_limit_per_file": STDERR_PARSE_LIMIT,
                "oversized_stderr": "retain unchanged, hash completely, refuse extension",
                "extended_gate": "initial report passes, rc zero, unchanged inputs, complete stderr, zero D4 events",
                "commands": [command(args, binary["path"], spec) for spec in STAGES]}
        summary["plan"] = save_new(args.out / "plan.json", plan)
        for spec in STAGES:
            # No retry loop: exactly one initial stage and at most one extension.
            result = run_stage(args, before, spec)
            summary["stages"].append({"stage": spec[0], "gate_passed": result["gate_passed"],
                                      "event_count": result["stderr_evidence"]["event_count"],
                                      "receipt": spec[0] + ".receipt.json"})
            if not result["gate_passed"]:
                summary["stopped_after"] = spec[0]
                summary["stop_reason"] = result.get("gate_error", "diagnostic stage failed")
                break
        summary["diagnostic_gate_passed"] = (len(summary["stages"]) == len(STAGES)
                                               and all(s["gate_passed"] for s in summary["stages"]))
    except (Exception, KeyboardInterrupt) as error:
        summary["error"] = {"type": type(error).__name__, "reason": str(error)}
    summary["finished_utc"] = now()
    save_new(args.out / "series.json", summary)
    print(json.dumps({"receipt": str(args.out / "series.json"),
                      "diagnostic_gate_passed": summary["diagnostic_gate_passed"],
                      "performance_adoption": False}))
    return 0 if summary["diagnostic_gate_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())

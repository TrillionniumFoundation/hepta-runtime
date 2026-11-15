#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Validate an explicitly qualified candidate against the retained A62 release.

Eight serial stages: small-archive ABBA, inherited pipes, six running jobs across
controller SIGKILL, a fixed six-host file ABBA, and a 120-second C8 file soak.
The source-pinned historical protocol library supplies original-child custody,
canary assertions and strict SSH input provenance; its historical main is never
called. No old report is edited and no failed stage or external effect is retried.
"""
import argparse
from collections import Counter
import importlib.util
import json
import os
from pathlib import Path
import secrets
import signal
import stat
import sys
import threading
import time


DEV_ROOT = Path("/home/qian/hepta-runtime-optimization-20261023")
HISTORY = DEV_ROOT / "a28-a31-budget-r01-g0"
A62 = DEV_ROOT / "a41-phase-timing-20261025-r01/a62-jobctl-start-durability-20261027-r01"
PROTOCOL_SHA = "2a88c03591908b1054b492d2d717027cb180d176c78eed4de280d7a6a193e956"
BASELINE_REPORT_SHA = "8a97541d019f4b92f21f1073d4849b98f4e9db8c3a27ff536fc267e09d3ee651"
BASELINE_ELF_SHA = "fbc9cb15fb425e0d17ce570b52b9ba3e70d689c7c5d1ec68b99ac742d4879dde"
TOOLS = {
    "x230_file_pool_benchmark.py": "b733091aa1b73df60ba5dc2c3a3febdc9313c56bb2166acc282e113ee13fa7e9",
    "x230_inherited_pipe_canary_a40.py": "197d009acc0fd3b6984db42bb586846f2b47636396cf9806b58a5661d43b6219",
    "x230_observation_benchmark.py": "0c4a06ed1613039d703bb575a8440c9030eac2dc51fcc2c96e96fc90a609da3e",
    "x230_six_running_recovery_canary.py": "817ba6a1ca8d1fca55e5bdc6a52b5e3d79c7a1e9a1615d46f8c646e8be21324a",
    "x230_small_archive_benchmark.py": "98413b4b177ec3bf68b7fe67de153376465374a9e74690c337633b3b4a912ffb",
}
BUSY_NAMES = {"cargo", "cargo-clippy", "clippy-driver", "rustc", "heptabao_server"}
SOAK_SECONDS = 120


def need(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(path):
    import hashlib
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def load_protocol(path):
    need(path.is_absolute() and path.resolve(strict=True) == path, "direct protocol-library path required")
    need(sha(path) == PROTOCOL_SHA, "reviewed protocol library SHA differs")
    spec = importlib.util.spec_from_file_location("hepta_pinned_native_protocol", path)
    need(spec is not None and spec.loader is not None, "cannot load protocol library")
    protocol = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(protocol)
    need(sha(path) == PROTOCOL_SHA, "protocol library changed during import")
    return protocol


def candidate_sources(p, source):
    paths = [source / name for name in ("Cargo.toml", "Cargo.lock", "rustfmt.toml")]
    for directory in ("src", "examples"):
        for path in (source / directory).rglob("*"):
            need(not path.is_symlink(), "candidate source symlink refused: " + str(path))
            if path.is_file():
                paths.append(path)
    return {str(path.relative_to(source)): p.receipt(p.direct(path))["sha256"]
            for path in sorted(paths)}


def harness_files(p, source):
    directory = p.direct(source / "tools/x230/20261028")
    return {path.name: p.receipt(p.direct(path)) for path in sorted(directory.glob("*.py"))}


def load_candidate(p, args, output):
    path = p.direct(args.qualification)
    info, raw = p.receipt(path, contents=True)
    need(info["sha256"] == args.qualification_sha256, "candidate qualification SHA differs")
    value = json.loads(raw)
    p.create(output / "candidate-qualification.original.json", raw)
    need(value.get("schema") == "hepta-x230-composed-qualification/v1"
         and value.get("qualified") is True and not value.get("error")
         and value.get("automatic_test_retries") == 0,
         "candidate qualification is not complete and successful")
    source = p.direct(Path(value["source"]))
    tested = value.get("source_tested")
    need(isinstance(tested, dict) and tested and tested == value.get("source_after")
         and candidate_sources(p, source) == tested, "candidate tested/current source maps differ")
    stages = value["stages"]
    by_name = {stage["name"]: stage for stage in stages}
    required = {"format", "fmt-check", "harness-tests", "clippy", "test-build", "isolated-tests", "audit-isolated-tests", "release"}
    need(set(by_name) == required and len(stages) == len(required)
         and all(stage.get("returncode") == 0 for stage in stages),
         "candidate qualification has missing, repeated or unsuccessful gates")
    pinned = {str(path): info}
    harness = harness_files(p, source)
    harness_map = {name: row["sha256"] for name, row in harness.items()}
    need({"qualify.py", "run_isolated_tests.py", "audit_isolated_tests.py"} <= set(harness)
         and harness_map == value.get("harness_before") == value.get("harness_after"),
         "qualification harness before/after/current file maps differ")
    pinned.update({row["path"]: row for row in harness.values()})
    for name, stage in by_name.items():
        for stream in ("stdout", "stderr"):
            filename = "cargo-no-run.jsonl" if (name, stream) == ("test-build", "stdout") else name + "." + stream
            log = p.direct(path.parent / filename)
            row = p.receipt(log)
            need(row["sha256"] == stage[stream + "_sha256"], "candidate qualification log changed: " + filename)
            pinned[str(log)] = row
    artifacts = value["binaries"]
    need(set(artifacts) == {"hepta-runtime", "hepta-runtime-jobctl", "native_process_driver"},
         "candidate release artifact inventory differs")
    for name, artifact in artifacts.items():
        binary = p.direct(Path(artifact["path"]))
        row = p.receipt(binary)
        need(binary.parent == path.parent and binary.name == name and os.access(binary, os.X_OK)
             and row["sha256"] == artifact["sha256"], "candidate release artifact changed: " + name)
        pinned[str(binary)] = row
    audit_path = p.direct(args.test_audit)
    need(audit_path == path.parent / "isolated-tests.audit.json", "audit must be the original qualification output")
    audit_info, audit_raw = p.receipt(audit_path, contents=True)
    need(audit_info["sha256"] == args.test_audit_sha256, "candidate test audit SHA differs")
    audit = json.loads(audit_raw)
    need(audit.get("schema") == "hepta-isolated-libtest-audit/v1"
         and audit.get("success") is True and audit.get("expected_filter") == ""
         and audit.get("failed") == 0 and audit.get("executed") == audit.get("passed", 0) > 0
         and audit.get("auditor_sha256") == harness_map["audit_isolated_tests.py"]
         and not audit.get("errors") and not audit.get("fatal_error"), "candidate exact-case audit failed/incomplete")
    evidence = p.direct(Path(audit["evidence"]))
    need(evidence == path.parent / "isolated-tests", "test audit belongs to another qualification")
    pinned[str(audit_path)] = audit_info
    p.create(output / "candidate-test-audit.original.json", audit_raw)
    for name, expected in audit["input_sha256"].items():
        need(Path(name).name == name, "unsafe audit input name")
        row = p.receipt(p.direct(evidence / name))
        need(row["sha256"] == expected, "audited test evidence changed: " + name)
        pinned[row["path"]] = row
    manifest_path = evidence / "source-manifest.input"
    need(json.loads(manifest_path.read_bytes()) == tested, "test audit is not bound to the candidate source map")
    for binary in audit["binaries"]:
        row = p.receipt(p.direct(Path(binary["path"])))
        need(row["sha256"] == binary["recorded_before_sha256"] == binary["current_after_sha256"],
             "audited test executable changed")
        pinned[row["path"]] = row
    for command in audit["commands"]:
        stdout = command["stdout_gzip"]
        need(Path(stdout).name == stdout and stdout.endswith(".stdout.log.gz"), "unsafe audited output name")
        for stream, name in (("stdout", stdout), ("stderr", stdout.removesuffix(".stdout.log.gz") + ".stderr.log.gz")):
            row = p.receipt(p.direct(evidence / name))
            need(row["sha256"] == command[stream]["gzip_sha256"], "audited original test log changed: " + name)
            pinned[row["path"]] = row
    return {"label": "candidate", "report": info, "source": str(source), "source_map": tested,
            "harness_map": harness_map,
            "binary": pinned[artifacts["hepta-runtime"]["path"]], "pinned": pinned,
            "test_audit": {"report": audit_info, "passed": audit["passed"], "ignored": audit["ignored"]}}


def load_gate(p):
    load = p.host_load()
    busy = [row for row in load["processes"] if row["comm"] in BUSY_NAMES and row["state"] not in ("Z", "X", "x")]
    return load, {"clear": load["required_fields_present"] and not load["errors"] and not busy,
                  "matching_live_processes": busy,
                  "scope": "local /proc sample; no remote-host load or between-sample guarantee"}


class LoadSamples:
    """Observe load every two seconds without signaling any unrelated workload."""
    def __init__(self, p, path):
        self.p, self.path = p, path
        self.stop = threading.Event()
        self.errors, self.samples, self.failures = [], 0, 0
        self.thread = threading.Thread(target=self.run, name="native-load-evidence")

    def run(self):
        try:
            with self.path.open("xb") as stream:
                while not self.stop.is_set():
                    load, gate = load_gate(self.p)
                    stream.write(json.dumps({"load": load, "gate": gate}).encode() + b"\n")
                    stream.flush()
                    self.samples += 1
                    self.failures += not gate["clear"]
                    if self.stop.wait(2):
                        break
                os.fsync(stream.fileno())
        except BaseException as error:
            self.errors.append(type(error).__name__ + ": " + str(error))

    def start(self):
        self.thread.start()

    def finish(self):
        self.stop.set()
        self.thread.join(timeout=10)
        need(not self.thread.is_alive(), "load sampler did not finish")
        return {"interval_seconds": 2, "samples": self.samples, "unclear_samples": self.failures,
                "errors": self.errors, "clear": self.samples > 0 and self.failures == 0 and not self.errors,
                "report": self.p.receipt(self.path)}


def validate_files(p, stage, value, output, expected):
    checks, details = {}, {}
    def check(name, condition):
        checks[name] = bool(condition)
    try:
        check("schema_complete_binary", value["schema"] == "hepta-x230-file-pool-abba/v1"
              and value["complete"] is True and not value.get("error") and value["binary_sha256"] == expected)
        check("read_only_unchanged", value["remote_writes"] is False
              and value["binary_unchanged"] is True and value["agent_unchanged"] is True)
        check("pool_on_only", value["order"] == ["on"] and len(value["rounds"]) == 1)
        item = value["rounds"][0]
        cells = item["cells"]
        concurrency = [1, 4, 8] if stage["kind"] == "file_abba" else [8]
        check("fixed_inventory", value["calls_per_cell"] == 96 and value["concurrency"] == concurrency
              and item["index"] == 0 and item["mode"] == "on"
              and bool(cells) and all(x["calls"] == x["success"] == 96 and x["seconds"] > 0 for x in cells))
        actual_cells = [(x["iteration"], x["concurrency"]) for x in cells]
        if stage["kind"] == "file_abba":
            check("one_fixed_iteration", actual_cells == [(0, x) for x in concurrency])
        else:
            check("configured_120_second_soak_finished", actual_cells == [(i, 8) for i in range(len(cells))]
                  and stage["helper_elapsed_seconds"] >= SOAK_SECONDS)
        check("warmup_and_negative_coverage", len(item["warmup"]) == len(item["negative"]) == 12
              and all(x["okay"] is True for x in item["warmup"] + item["negative"])
              and Counter((x["host"], x["expected_error"]) for x in item["negative"])
              == Counter((host, reason) for host in p.HOSTS for reason in ("stale_version", "outside_root")))
        shutdown = item["shutdown"]
        check("owned_shutdown", shutdown["exit_code"] == 0 and not shutdown["observed_descendant_survivors"]
              and shutdown["reader_error"] is None and shutdown["unmatched_responses"] == 0)
        info, raw = p.receipt(output / "calls.jsonl", contents=True)
        calls = [json.loads(line) for line in raw.splitlines()]
        measured = [x for x in calls if x["phase"] == "measured"]
        check("original_calls_hash_and_count", info["sha256"] == value["calls_sha256"]
              and len(calls) == len(measured) + 24 and len(measured) == 96 * len(cells)
              and all(x["okay"] is True and x["round"] == 0 and x["mode"] == "on" for x in calls))
        keys = {(x["iteration"], x["concurrency"], i) for x in cells for i in range(96)}
        check("exact_balanced_calls", len(keys) == len(measured)
              and {(x["iteration"], x["concurrency"], x["index"]) for x in measured} == keys
              and all(x["host"] == p.HOSTS[(x["index"] // 2) % 6]
                      and x["tool"] == ("file_info" if x["index"] % 2 == 0 else "binary_read") for x in measured))
        with (output / "round-0-on/controller/stderr.log").open("rb") as stream:
            check("trace_disabled", not any(line.startswith(p.TRACE_PREFIX) for line in stream))
        details = {"measured_calls": len(measured), "cells": [{k: v for k, v in cell.items() if k != "resources"} for cell in cells],
                   "waited_process_tree_cpu_seconds": item["waited_process_tree_cpu_seconds"],
                   "sampled_resource_peaks": shutdown["resources"].get("peaks", {}),
                   "resource_observation_error_count": len(shutdown["resources"].get("errors", [])),
                   "configured_soak_seconds": SOAK_SECONDS if stage["kind"] == "soak" else None,
                   "measured_cell_seconds": sum(x["seconds"] for x in cells),
                   "resource_scope": "original controller and observed local descendants; remote CPU excluded; RSS peaks are sampled",
                   "workload_scope": "six immutable 44-48 byte synthetic outputs; file_info/binary_read, not bulk bandwidth"}
    except (KeyError, IndexError, TypeError, ValueError, OSError) as error:
        checks["contract_readable"] = False
        details["error"] = type(error).__name__ + ": " + str(error)
    return {"passed": bool(checks) and all(checks.values()), "assertions": checks, "details": details}


def make_plan(p, args, bundles, nonce):
    layout = [("small-archive-abba", "small", "both", 300), ("inherited-pipes", "pipe", "candidate", 400),
              ("six-running-recovery", "recovery", "candidate", 480)]
    layout += [(f"file-abba-{index}-{arm}", "file_abba", arm, 250)
               for index, arm in enumerate(("baseline", "candidate", "candidate", "baseline"))]
    layout += [("candidate-c8-soak-120s", "soak", "candidate", 300)]
    rows = []
    for index, (name, kind, arm, budget) in enumerate(layout):
        output = args.out / name
        socket_parent = args.socket_parent / ("s" + str(index))
        shared = ["--candidate", bundles["candidate" if arm == "both" else arm]["binary"]["path"],
                  "--profile-template", str(args.profile_template), "--frozen-jobs", str(args.frozen_jobs),
                  "--socket-parent", str(socket_parent)]
        if kind == "small":
            script = "x230_small_archive_benchmark.py"
            options = ["--baseline", bundles["baseline"]["binary"]["path"], "--candidate", bundles["candidate"]["binary"]["path"],
                       "--measured", "1024", "--workers", "2"]
        elif kind == "pipe":
            script = "x230_inherited_pipe_canary_a40.py"
            output = DEV_ROOT / ("x230-20261028-" + nonce + "-pipes")
            options = shared + ["--expected-binary-sha256", bundles["candidate"]["binary"]["sha256"], "--cancel-during-drain"]
        elif kind == "recovery":
            script = "x230_six_running_recovery_canary.py"
            output = DEV_ROOT / ("x230-20261028-" + nonce + "-recovery")
            options = shared + ["--workers", "2"]
        else:
            script = "x230_file_pool_benchmark.py"
            options = shared + ["--calls", "96", "--concurrency"] + (["1", "4", "8"] if kind == "file_abba" else ["8"])
            options += ["--soak-seconds", "1" if kind == "file_abba" else str(SOAK_SECONDS)]
        p.direct(output, exists=False)
        rows.append({"index": index, "name": name, "kind": kind, "arm": arm, "budget_seconds": budget,
                     "output": str(output), "socket_parent": None if kind == "small" else str(socket_parent),
                     "argv": ["/usr/bin/python3", "-B", "-s", str(args.tools_dir / script), *options, "--out", str(output)],
                     "trace": False, "cancel_during_drain": kind == "pipe", "status": "unexecuted",
                     "executed": False, "execution_count": 0})
    return rows


def comparison(stages):
    result = {}
    for concurrency in (1, 4, 8):
        arms = {}
        for arm in ("baseline", "candidate"):
            cells = [cell for stage in stages if stage["kind"] == "file_abba" and stage["arm"] == arm
                     for cell in stage["validation"]["details"]["cells"] if cell["concurrency"] == concurrency]
            calls, seconds = sum(x["calls"] for x in cells), sum(x["seconds"] for x in cells)
            arms[arm] = {"calls": calls, "cell_seconds": seconds, "calls_per_second": calls / seconds}
        result[str(concurrency)] = {**arms, "candidate_rate_change_percent": 100 * (arms["candidate"]["calls_per_second"] / arms["baseline"]["calls_per_second"] - 1)}
    return {"concurrency": result, "performance_improvement_claimed": False,
            "method": "sum of measured calls divided by sum of original cell wall times; all ABBA cells retained",
            "limits": "one short ABBA block; local load sampled every 2s; remote/background load uncontrolled; tiny immutable files"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("qualification", "test-audit", "out", "socket-parent"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--qualification-sha256", required=True)
    parser.add_argument("--test-audit-sha256", required=True)
    parser.add_argument("--protocol-library", type=Path, default=Path(__file__).absolute().with_name("pinned_native_protocol.py"))
    parser.add_argument("--baseline-qualification", type=Path, default=A62 / "qualification/report.json")
    parser.add_argument("--tools-dir", type=Path, default=DEV_ROOT / "a41-phase-timing-20261025-r01/tools")
    parser.add_argument("--profile-template", type=Path, default=HISTORY / "profile/profile.json")
    parser.add_argument("--frozen-jobs", type=Path, default=HISTORY / "round-0-A/state/jobs")
    args = parser.parse_args()
    sys.dont_write_bytecode = True
    os.umask(0o077)
    p = load_protocol(args.protocol_library)
    args.out = p.direct(args.out, exists=False)
    args.out.mkdir(mode=0o700)
    report = {"schema": "hepta-x230-composed-native-validation/v1", "passed": False, "complete": False,
              "started_utc": p.utc(), "nonce": secrets.token_hex(12), "stages": [], "automatic_retries": 0,
              "production_services_changed": False, "soak_seconds": SOAK_SECONDS,
              "baseline_version": "A62-jobctl-start-durability", "candidate_version": "source-bound-composed-20261028",
              "not_covered": ["target reboot", "physical power loss", "production owner transfer", "WAN partition", "bulk bandwidth", "600-second soak"],
              "library_scope": "pinned historical custody, SSH provenance and canary validation functions; historical main not called"}
    report_path = args.out / "report.json"
    def checkpoint():
        report["unexecuted"] = [x["name"] for x in report["stages"] if not x["executed"]]
        p.save(report_path, report)
    checkpoint()
    try:
        need(sys.platform == "linux" and hasattr(os, "pidfd_open") and hasattr(os, "WNOWAIT")
             and hasattr(signal, "pidfd_send_signal"), "Linux original-child custody primitives required")
        args.socket_parent = p.direct(args.socket_parent, exists=False)
        need(len(os.fsencode(args.socket_parent / "s8")) + 49 + 9 + 17 + 1 <= 108, "socket parent path too long")
        need(args.socket_parent != args.out and not args.socket_parent.is_relative_to(args.out), "socket parent must be separate from evidence")
        tools = {str(p.direct(args.tools_dir / name)): p.receipt(args.tools_dir / name) for name in TOOLS}
        for name, expected in TOOLS.items():
            need(tools[str(args.tools_dir / name)]["sha256"] == expected, "reviewed tool SHA differs: " + name)
        tools[str(args.protocol_library)] = p.receipt(args.protocol_library)
        tools[str(Path(__file__).absolute())] = p.receipt(Path(__file__).absolute())
        baseline = p.load_qualification(args.baseline_qualification, "baseline", args.out)
        need(baseline["report"]["sha256"] == BASELINE_REPORT_SHA and baseline["binary"]["sha256"] == BASELINE_ELF_SHA,
             "A62 baseline qualification or release SHA differs")
        candidate = load_candidate(p, args, args.out)
        bundles = {"baseline": baseline, "candidate": candidate}
        need(baseline["binary"]["sha256"] != candidate["binary"]["sha256"], "same executable cannot form a cross-version ABBA")
        for bundle in bundles.values():
            source = Path(bundle["source"])
            need(not args.out.is_relative_to(source) and not args.socket_parent.is_relative_to(source), "evidence must not mutate qualified sources")
        inputs = p.input_manifest(args)
        agent = Path(os.environ.get("SSH_AUTH_SOCK", ""))
        need(agent.is_absolute() and stat.S_ISSOCK(agent.stat().st_mode), "held current forwarded SSH agent required")
        agent_stamp = p.stamp(agent.stat())
        report.update(qualifications=bundles, tools=tools, frozen_inputs=inputs,
                      agent_socket={"path": str(agent), "identity": list(agent_stamp)})
        args.socket_parent.mkdir(mode=0o700)
        report["stages"] = make_plan(p, args, bundles, report["nonce"])
        expected = {"A40": baseline["binary"]["sha256"], "A41": candidate["binary"]["sha256"]}
        def check_inputs():
            p.assert_bundle_unchanged(baseline)
            need(candidate_sources(p, Path(candidate["source"])) == candidate["source_map"], "candidate source changed")
            current_harness = harness_files(p, Path(candidate["source"]))
            need({name: row["sha256"] for name, row in current_harness.items()} == candidate["harness_map"],
                 "candidate qualification harness file set/content changed")
            p.check_manifest(candidate["pinned"])
            p.check_manifest(tools)
            p.check_manifest(inputs)
            need(p.stamp(agent.stat()) == agent_stamp, "original forwarded agent socket changed")
        for stage in report["stages"]:
            stage.update(status="checking", started_utc=p.utc(), start_monotonic_ns=time.monotonic_ns())
            checkpoint()
            sampler = None
            try:
                check_inputs()
                output = p.direct(Path(stage["output"]), exists=False)
                if stage["socket_parent"]:
                    p.direct(Path(stage["socket_parent"]), exists=False).mkdir(mode=0o700)
                load, gate = load_gate(p)
                before = args.out / (stage["name"] + ".hostload-before.json")
                p.create(before, p.canonical(load))
                stage.update(hostload_before=p.receipt(before), hostload_before_gate=gate)
                need(gate["clear"], "compiler/heptabao active or incomplete local load snapshot; helper not started")
                env = dict(os.environ)
                for key in ("HEPTA_OBSERVATION_TRACE", "PYTHONPATH", "PYTHONHOME"):
                    env.pop(key, None)
                env.update(PYTHONDONTWRITEBYTECODE="1", PYTHONNOUSERSITE="1")
                sampler = LoadSamples(p, args.out / (stage["name"] + ".hostload-samples.jsonl"))
                sampler.start()
                stage["status"] = "running"
                checkpoint()
                print(json.dumps({"stage": stage["name"], "status": "started"}), flush=True)
                with (args.out / (stage["name"] + ".stdout")).open("xb") as stdout, (args.out / (stage["name"] + ".stderr")).open("xb") as stderr:
                    p.run_owned(stage["argv"], env, args.tools_dir, stdout, stderr, stage["budget_seconds"], stage, checkpoint)
                info, raw = p.receipt(output / "report.json", contents=True)
                stage["original_report"] = info
                value = json.loads(raw)
                validation = (validate_files(p, stage, value, output, bundles[stage["arm"]]["binary"]["sha256"])
                              if stage["kind"] in ("file_abba", "soak") else p.validate_stage(stage, value, output, expected))
                stage["validation"] = validation
                need(stage["original_child_reaped"] and stage["returncode"] == 0 and not stage["timed_out"], "original helper failed/timed out")
                need(validation["passed"], "stage coverage/integrity failed: " + ", ".join(k for k, v in validation["assertions"].items() if not v))
                check_inputs()
                stage["status"] = "passed"
            except BaseException as error:
                stage.update(status="failed", error=type(error).__name__ + ": " + str(error))
            finally:
                evidence_errors = []
                try:
                    if sampler is not None:
                        stage["hostload_samples"] = sampler.finish()
                        need(stage["hostload_samples"]["clear"], "local load samples contain interference or observation errors")
                except BaseException as error:
                    evidence_errors.append(str(error))
                try:
                    load, gate = load_gate(p)
                    after = args.out / (stage["name"] + ".hostload-after.json")
                    p.create(after, p.canonical(load))
                    stage.update(hostload_after=p.receipt(after), hostload_after_gate=gate)
                    if not gate["clear"]:
                        evidence_errors.append("after-stage local load gate failed")
                    for stream in ("stdout", "stderr"):
                        path = args.out / (stage["name"] + "." + stream)
                        if path.exists():
                            stage[stream] = p.receipt(path)
                    manifest = p.artifact_manifest(Path(stage["output"]))
                    path = args.out / (stage["name"] + ".artifacts.json")
                    p.create(path, p.canonical(manifest))
                    stage["original_artifacts_manifest"] = p.receipt(path)
                    stage["original_artifact_count"] = len(manifest)
                except BaseException as error:
                    evidence_errors.append(type(error).__name__ + ": " + str(error))
                if evidence_errors:
                    stage.update(status="failed", evidence_errors=evidence_errors)
                stage.update(finished_utc=p.utc(), end_monotonic_ns=time.monotonic_ns())
                checkpoint()
                print(json.dumps({"stage": stage["name"], "status": stage["status"], "returncode": stage.get("returncode"), "error": stage.get("error")}), flush=True)
            if stage["status"] != "passed":
                report["failed_stage"] = stage["name"]
                raise RuntimeError("series stopped; original failure retained and later stages not executed")
        check_inputs()
        need(set(p.input_manifest(args)) == set(inputs), "frozen input set changed")
        for stage in report["stages"]:
            pinned = [stage[key] for key in ("stdout", "stderr", "original_report", "original_artifacts_manifest", "hostload_before", "hostload_after")]
            pinned.append(stage["hostload_samples"]["report"])
            p.check_manifest({row["path"]: row for row in pinned})
            recorded = json.loads(Path(stage["original_artifacts_manifest"]["path"]).read_bytes())
            current = p.artifact_manifest(Path(stage["output"]))
            need({k: v["sha256"] for k, v in recorded.items()} == {k: v["sha256"] for k, v in current.items()}, "earlier stage artifacts changed")
        stages = report["stages"]
        need(len(stages) == 8 and all(x["status"] == "passed" and x["execution_count"] == 1 and x.get("custody_retained_until_reap") for x in stages), "series incomplete")
        need(all(stages[i]["end_monotonic_ns"] <= stages[i + 1]["start_monotonic_ns"] for i in range(7)), "stage order overlaps")
        report.update(passed=True, complete=True, final_input_integrity_passed=True,
                      descriptive_file_abba=comparison(stages))
    except BaseException as error:
        report["error"] = type(error).__name__ + ": " + str(error)
    finally:
        report["finished_utc"] = p.utc()
        checkpoint()
        print(json.dumps({"report": str(report_path), "passed": report["passed"], "failed_stage": report.get("failed_stage"), "error": report.get("error")}), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    def stop_requested(signum, _frame):
        raise KeyboardInterrupt("native driver received signal " + str(signum))
    signal.signal(signal.SIGTERM, stop_requested)
    raise SystemExit(main())

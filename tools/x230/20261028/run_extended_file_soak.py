#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""One source-bound, six-host C8 read-only file soak; no retries or remote effects.

This independent report supplements, and never rewrites, the native eight stages.
Configured helper duration and measured cell seconds are separate observations.
"""
import argparse
from collections import Counter
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import signal
import stat
import sys
import time


NATIVE_SHA = "309afefe719d63e52377930db5d997b3ac3c244873fbb83055e9950b956903f6"
HELPER_SHA = "b733091aa1b73df60ba5dc2c3a3febdc9313c56bb2166acc282e113ee13fa7e9"
SCHEMA = "hepta-x230-extended-file-soak/v1"


def load_native():
    path = Path(__file__).absolute().with_name("run_native_validation.py")
    def verify():
        if path.resolve(strict=True) != path or hashlib.sha256(path.read_bytes()).hexdigest() != NATIVE_SHA:
            raise RuntimeError("frozen native validator path/SHA differs")
    verify()
    spec = importlib.util.spec_from_file_location("hepta_extended_frozen_native", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    verify()
    return module


def soak_seconds(value):
    seconds = int(value)
    if not 360 <= seconds <= 900:
        raise argparse.ArgumentTypeError("soak duration must be 360..900 seconds")
    return seconds


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("qualification", "test-audit", "out", "socket-parent"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("qualification-sha256", "test-audit-sha256"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--soak-seconds", type=soak_seconds, default=360)
    return parser.parse_args(argv)


def validate_extended(n, p, stage, value, output, expected, seconds):
    structural = n.validate_files(p, stage, value, output, expected)
    result = {"passed": False, "native_structure": structural, "assertions": {}, "details": {
        "native_structure_minimum_seconds": n.SOAK_SECONDS,
        "configured_helper_soak_seconds": seconds,
        "duration_scope": "argv duration and helper lifetime; measured cell seconds exclude setup and gaps",
        "generation_scope": "total sampled local SSH masters only; no per-host rotation inference"}}
    checks, details = result["assertions"], result["details"]
    try:
        argv = stage["argv"]
        checks["actual_configuration"] = (360 <= seconds <= 900 and
            all(argv.count(flag) == 1 and argv[argv.index(flag) + 1] == wanted for flag, wanted in
                (("--calls", "96"), ("--concurrency", "8"), ("--soak-seconds", str(seconds)))))
        elapsed = stage["helper_elapsed_seconds"]
        cells = value["rounds"][0]["cells"]
        times = [cell["seconds"] for cell in cells]
        checks["elapsed_and_cell_times"] = (math.isfinite(elapsed) and elapsed >= seconds and
            bool(times) and all(math.isfinite(x) and x > 0 for x in times) and sum(times) <= elapsed)
        details.update(helper_elapsed_seconds=elapsed, measured_cell_seconds=sum(times), measured_cells=len(cells))
        info, raw = p.receipt(output / "calls.jsonl", contents=True)
        calls = [json.loads(line) for line in raw.splitlines()]
        phases = Counter(row["phase"] for row in calls)
        checks["all_raw_samples"] = (info["sha256"] == value["calls_sha256"] and
            phases == {"warmup": 12, "negative": 12, "measured": 96 * len(cells)} and
            all(row.get("automatic_retry") is not True for row in calls))
        distribution = {}
        for host in p.HOSTS:
            distribution[host] = {}
            for phase in ("warmup", "negative", "measured"):
                rows = [row for row in calls if row["host"] == host and row["phase"] == phase]
                passed = sum(row["okay"] is True for row in rows)
                distribution[host][phase] = {"calls": len(rows), "success": passed, "failures": len(rows) - passed}
        checks["six_host_balanced_success"] = (set(row["host"] for row in calls) == set(p.HOSTS) and
            all(row[phase]["calls"] == row[phase]["success"] == count for row in distribution.values()
                for phase, count in (("warmup", 2), ("negative", 2), ("measured", 16 * len(cells)))))
        resources = value["rounds"][0]["shutdown"]["resources"]
        generations = resources.get("observed_master_generations")
        checks["generation_field_if_present"] = generations is None or isinstance(generations, list)
        details.update(calls=info, raw_call_count=len(calls), per_host=distribution,
            observed_master_generations_total=len(generations) if isinstance(generations, list) else None,
            master_generation_evidence="sampled total" if isinstance(generations, list) else "unknown: helper field absent",
            resource_observation_errors=resources.get("error_count", len(resources.get("errors", []))))
    except (KeyError, IndexError, TypeError, ValueError, OSError) as error:
        checks["contract_readable"] = False
        details["error"] = type(error).__name__ + ": " + str(error)
    result["passed"] = structural["passed"] and bool(checks) and all(checks.values())
    return result


def main(argv=None):
    args = parse_args(argv)
    sys.dont_write_bytecode = True
    os.umask(0o077)
    n = load_native()
    library = Path(__file__).absolute().with_name("pinned_native_protocol.py")
    p = n.load_protocol(library)
    args.tools_dir = n.DEV_ROOT / "a41-phase-timing-20261025-r01/tools"
    args.profile_template = n.HISTORY / "profile/profile.json"
    args.frozen_jobs = n.HISTORY / "round-0-A/state/jobs"
    args.out = p.direct(args.out, exists=False)
    args.out.mkdir(mode=0o700)
    report = {"schema": SCHEMA, "passed": False, "complete": False, "started_utc": p.utc(),
        "automatic_retries": 0, "soak_seconds": args.soak_seconds, "production_services_changed": False,
        "remote_writes": False, "remote_jobs_started": False, "stages": [],
        "scope": "one additional six-host C8 read-only file helper; independent of the native eight-stage series"}
    report_path = args.out / "report.json"
    def checkpoint():
        p.save(report_path, report)
    checkpoint()
    try:
        n.need(sys.platform == "linux" and hasattr(os, "pidfd_open") and hasattr(os, "WNOWAIT")
               and hasattr(signal, "pidfd_send_signal"), "Linux original-child custody primitives required")
        args.socket_parent = p.direct(args.socket_parent, exists=False)
        n.need(len(os.fsencode(args.socket_parent / "s0")) + 49 + 9 + 17 + 1 <= 108, "socket parent too long")
        n.need(not args.socket_parent.is_relative_to(args.out), "sockets must be separate from retained evidence")
        candidate = n.load_candidate(p, args, args.out)
        source = Path(candidate["source"])
        driver = p.direct(Path(__file__).absolute())
        n.need(driver.parent == source / "tools/x230/20261028", "runner must belong to the qualified harness")
        n.need(not args.out.is_relative_to(source) and not args.socket_parent.is_relative_to(source), "evidence must not mutate qualified source")
        tools = {str(p.direct(args.tools_dir / name)): p.receipt(args.tools_dir / name) for name in n.TOOLS}
        for name, expected in n.TOOLS.items():
            n.need(tools[str(args.tools_dir / name)]["sha256"] == expected, "reviewed helper dependency SHA differs: " + name)
        helper = args.tools_dir / "x230_file_pool_benchmark.py"
        n.need(tools[str(helper)]["sha256"] == HELPER_SHA, "reviewed file helper SHA differs")
        for path in (driver, driver.with_name("run_native_validation.py"), library):
            tools[str(path)] = p.receipt(path)
        inputs = p.input_manifest(args)
        agent = Path(os.environ.get("SSH_AUTH_SOCK", ""))
        n.need(agent.is_absolute() and stat.S_ISSOCK(agent.stat().st_mode), "held forwarded SSH agent required")
        agent_stamp = p.stamp(agent.stat())
        report.update(qualifications={"candidate": candidate}, tools=tools, frozen_inputs=inputs,
            agent_socket={"path": str(agent), "identity": list(agent_stamp)})
        def check_inputs():
            n.need(n.candidate_sources(p, source) == candidate["source_map"], "qualified source changed")
            n.need({k: v["sha256"] for k, v in n.harness_files(p, source).items()} == candidate["harness_map"], "qualified harness changed")
            for manifest in (candidate["pinned"], tools, inputs):
                p.check_manifest(manifest)
            n.need(set(p.input_manifest(args)) == set(inputs), "frozen input inventory changed")
            n.need(p.stamp(agent.stat()) == agent_stamp, "held agent socket changed")
        args.socket_parent.mkdir(mode=0o700)
        sockets = args.socket_parent / "s0"
        sockets.mkdir(mode=0o700)
        output = args.out / "file-soak"
        stage = {"name": "candidate-c8-extended-file-soak", "kind": "soak", "status": "unexecuted",
            "executed": False, "execution_count": 0, "output": str(output), "budget_seconds": args.soak_seconds + 240,
            "argv": ["/usr/bin/python3", "-B", "-s", str(helper), "--candidate", candidate["binary"]["path"],
                "--profile-template", str(args.profile_template), "--frozen-jobs", str(args.frozen_jobs),
                "--socket-parent", str(sockets), "--calls", "96", "--concurrency", "8",
                "--soak-seconds", str(args.soak_seconds), "--out", str(output)]}
        report["stages"] = [stage]
        sampler = None
        stage.update(started_utc=p.utc(), start_monotonic_ns=time.monotonic_ns())
        try:
            check_inputs()
            p.direct(output, exists=False)
            load, gate = n.load_gate(p)
            before = args.out / "hostload-before.json"
            p.create(before, p.canonical(load))
            stage.update(hostload_before=p.receipt(before), hostload_before_gate=gate)
            n.need(gate["clear"], "local load gate failed; helper not started")
            env = dict(os.environ)
            for key in ("HEPTA_OBSERVATION_TRACE", "PYTHONPATH", "PYTHONHOME"):
                env.pop(key, None)
            env.update(PYTHONDONTWRITEBYTECODE="1", PYTHONNOUSERSITE="1")
            sampler = n.LoadSamples(p, args.out / "hostload-samples.jsonl")
            sampler.start()
            stage["status"] = "running"
            checkpoint()
            with (args.out / "helper.stdout").open("xb") as stdout, (args.out / "helper.stderr").open("xb") as stderr:
                p.run_owned(stage["argv"], env, args.tools_dir, stdout, stderr, stage["budget_seconds"], stage, checkpoint)
            info, raw = p.receipt(output / "report.json", contents=True)
            stage["original_report"] = info
            stage["validation"] = validate_extended(n, p, stage, json.loads(raw), output, candidate["binary"]["sha256"], args.soak_seconds)
            n.need(stage["original_child_reaped"] and stage["custody_retained_until_reap"] and stage["returncode"] == 0
                   and not stage["timed_out"] and stage["execution_count"] == 1, "original helper failed/timed out/lost custody")
            n.need(stage["validation"]["passed"], "extended soak coverage/integrity failed")
            check_inputs()
            stage["status"] = "passed"
        except BaseException as error:
            stage.update(status="failed", error=type(error).__name__ + ": " + str(error))
        finally:
            evidence_errors = []
            try:
                if sampler is not None:
                    stage["hostload_samples"] = sampler.finish()
                    n.need(stage["hostload_samples"]["clear"], "local load sampling gate failed")
            except BaseException as error:
                evidence_errors.append(str(error))
            try:
                load, gate = n.load_gate(p)
                after = args.out / "hostload-after.json"
                p.create(after, p.canonical(load))
                stage.update(hostload_after=p.receipt(after), hostload_after_gate=gate)
                if not gate["clear"]:
                    evidence_errors.append("after-helper local load gate failed")
                for stream in ("stdout", "stderr"):
                    path = args.out / ("helper." + stream)
                    if path.exists():
                        stage[stream] = p.receipt(path)
                manifest = args.out / "helper.artifacts.json"
                p.create(manifest, p.canonical(p.artifact_manifest(output)))
                stage["original_artifacts_manifest"] = p.receipt(manifest)
            except BaseException as error:
                evidence_errors.append(type(error).__name__ + ": " + str(error))
            if evidence_errors:
                stage.update(status="failed", evidence_errors=evidence_errors)
            stage.update(finished_utc=p.utc(), end_monotonic_ns=time.monotonic_ns())
            checkpoint()
        n.need(stage["status"] == "passed", "extended soak failed; original failure retained, no retry")
        check_inputs()
        records = [stage[key] for key in ("stdout", "stderr", "original_report", "original_artifacts_manifest", "hostload_before", "hostload_after")]
        records.append(stage["hostload_samples"]["report"])
        p.check_manifest({row["path"]: row for row in records})
        recorded = json.loads(Path(stage["original_artifacts_manifest"]["path"]).read_bytes())
        current = p.artifact_manifest(output)
        n.need({k: v["sha256"] for k, v in recorded.items()} == {k: v["sha256"] for k, v in current.items()}, "helper artifacts changed")
        report.update(passed=True, complete=True, final_input_integrity_passed=True)
    except BaseException as error:
        report["error"] = type(error).__name__ + ": " + str(error)
    finally:
        report["finished_utc"] = p.utc()
        checkpoint()
        print(json.dumps({"report": str(report_path), "passed": report["passed"], "complete": report["complete"], "error": report.get("error")}), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    def stop_requested(signum, _frame):
        raise KeyboardInterrupt("extended soak received signal " + str(signum))
    signal.signal(signal.SIGTERM, stop_requested)
    raise SystemExit(main())

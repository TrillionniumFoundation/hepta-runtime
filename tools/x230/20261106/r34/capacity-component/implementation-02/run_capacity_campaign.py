#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""One fixed eight-cell capacity campaign under the original Mac agent holder.

The original holder transmits these bytes and supplies --launcher-sha256.
Unsealed/future dependencies refuse before output creation or a child launch.
The external holder's eventual native/agent cleanup is closed separately.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import statistics
import subprocess
import sys
import time
import traceback
import types

sys.dont_write_bytecode = True
ROOT = Path("/home/qian/hepta-runtime-optimization-20261106-r34")
PACKAGE = ROOT / "capacity-component-tools-02"
INPUT = ROOT / "capacity-campaign-inputs-01.json"
OUTPUT = ROOT / "capacity-campaign-01"
PARENT = {"path": str(ROOT / "tools-01/r34_campaign.py"), "bytes": 81762,
          "sha256": "c7508892959e9393f7ade10948ef7a96a18f1930d7308e293b74a321435f4cee"}
HOLDER_SHA = "715e996217c7d33a7483354f16f2d39c9a033f51f3a20a52484495a00262dd65"
ORDER = [(round_name + "-" + victim, round_name[0], victim)
         for round_name in ("A1", "B1", "B2", "A2") for victim in ("x230", "mac")]
HOSTS = {"ai395", "mac", "main", "pocket4", "rog", "x230"}
QUIESCENCE_SECONDS = 90
CAMPAIGN_SECONDS = 3300
CELL_SECONDS = 420
SOCKETS = [Path(f"/home/qian/h34g{index + 1:02}") for index in range(8)]
MAX_ARTIFACTS = 32768
MAX_ARTIFACT_BYTES = 256 * 1024 * 1024
CI_STAGES = ["cargo-version", "rustc-version", "nextest-version", "cargo-check", "nextest-list", "nextest-run"]


def need(value, reason):
    if not value:
        raise RuntimeError(reason)


def bootstrap_read(path, expected=None, maximum=16 * 1024 * 1024):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path, "indirect bootstrap input")
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= maximum,
             "unsafe bootstrap input")
        with os.fdopen(os.dup(fd), "rb") as stream:
            raw = stream.read(maximum + 1)
        fields = ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        stamp = lambda info: tuple(getattr(info, key) for key in fields)
        need(len(raw) == before.st_size and stamp(before) == stamp(os.fstat(fd)) == stamp(path.lstat()),
             "bootstrap input changed")
    finally:
        os.close(fd)
    if expected is not None:
        need(expected["path"] == str(path) and expected["bytes"] == len(raw)
             and expected["sha256"] == hashlib.sha256(raw).hexdigest(), "bootstrap identity differs")
    return raw


def module_from_bytes(name, path, raw):
    need(name not in sys.modules, "a bound component module was already imported")
    module = types.ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


def bootstrap(inputs, launcher_sha):
    need(inputs.get("schema") == "hepta-r34-capacity-campaign/v1"
         and inputs.get("status") == "sealed_actual_inputs" and inputs.get("attempt") == "01",
         "capacity campaign inputs remain unsealed")
    need(inputs.get("launcher_sha256") == launcher_sha and re.fullmatch(r"[0-9a-f]{64}", launcher_sha) is not None,
         "original held-agent launcher binding differs")
    need(inputs.get("control_parent") == PARENT and inputs.get("holder_sha256") == HOLDER_SHA,
         "reviewed original control/holder source differs")
    pin = inputs["component_source_manifest"]
    need(pin["path"] == str(PACKAGE / "source-manifest.json"), "component manifest path differs")
    manifest_raw = bootstrap_read(pin["path"], pin)
    manifest = json.loads(manifest_raw)
    need(manifest.get("schema") == "hepta-r34-capacity-component-source/v1"
         and manifest.get("rust_source_state") == "formatted_source_frozen",
         "an actual formatted and frozen component source revision is required")
    rows = {row["path"]: row for row in manifest["files"]}
    need(len(rows) == len(manifest["files"]), "duplicate component source identity")
    for name in rows:
        need(not Path(name).is_absolute() and ".." not in Path(name).parts and str(Path(name)) == name,
             "unsafe component source path")
    need(rows["run_capacity_campaign.py"]["sha256"] == launcher_sha
         and rows["held_agent_campaign_02.py"]["sha256"] == HOLDER_SHA, "transmitted source/holder differs from compiled revision")
    modules = {}
    for file, name in (("prepare_build.py", "prepare_build"),
                       ("benchmark_primitives.py", "_r34_capacity_benchmark"),
                       ("coordinate.py", "_r34_capacity_coordinate")):
        row = rows[file]
        raw = bootstrap_read(PACKAGE / file, dict(row, path=str(PACKAGE / file)))
        modules[file] = module_from_bytes(name, PACKAGE / file, raw)
    parent_raw = bootstrap_read(PARENT["path"], PARENT)
    modules["parent"] = module_from_bytes("_r34_capacity_original_parent", Path(PARENT["path"]), parent_raw)
    parent = modules["parent"]
    need(parent.ROOT == ROOT and parent.QUIESCENCE_SECONDS == QUIESCENCE_SECONDS
         and parent.CAMPAIGN_SECONDS == CAMPAIGN_SECONDS, "original control namespace/budgets differ")
    return modules, manifest


def native_original(parent, terminal, read, job_id):
    parent.verify_r34_terminal(terminal, job_id)
    need(terminal.get("audit_recorded") is True and read.get("audit_recorded") is True
         and read.get("job_id") == job_id, "original native observation/audit differs")
    decoded = {}
    for stream in ("stdout", "stderr"):
        row = read[stream]
        raw = bytes.fromhex(row["bytes_hex"])
        need(row["offset"] == 0 and row["eof"] is True
             and row["next_offset"] == row["size"] == len(raw)
             and terminal["log_bytes"][stream] == {"seen": len(raw), "stored": len(raw)},
             "original native full-read/log custody differs")
        decoded[stream] = raw
    return decoded


def prerequisites(inputs, modules, manifest, bind):
    binding, parent = modules["prepare_build.py"], modules["parent"]
    for row in manifest["files"]:
        bind(PACKAGE / row["path"], dict(row, path=str(PACKAGE / row["path"])))
    need(len(inputs["cells"]) == len(ORDER), "exact eight cells required")
    nonces = []
    for index, ((label, arm, victim), row) in enumerate(zip(ORDER, inputs["cells"])):
        need(set(row) == {"index", "label", "arm", "victim", "nonce"}
             and (row["index"], row["label"], row["arm"], row["victim"]) == (index, label, arm, victim)
             and re.fullmatch(r"[0-9a-f]{24}", row["nonce"]) is not None, "fixed cell order/identity differs")
        nonces.append(row["nonce"])
    need(len(set(nonces)) == 8, "a private fixture nonce was reused")
    need(inputs["automatic_retries"] == 0 and inputs["on_failure"] == "stop_remaining_cells"
         and inputs["quiet_seconds"] == 90 and inputs["cell_timeout_seconds"] == CELL_SECONDS,
         "capacity control policy differs")
    need(set(inputs["runtime_arms"]) == {"A", "B"}, "actual two runtime dependencies required")
    for arm in ("A", "B"):
        runtime = inputs["runtime_arms"][arm]
        binding.full_map(runtime["source_root"], runtime["compile_inputs"])
        binding.full_map(runtime["source_root"], runtime["include_inputs"])
        binding.qualified_arm(arm, runtime)
        bind(runtime["qualification_report"]["path"], runtime["qualification_report"])
    _, pair_raw = bind(inputs["component_pair_report"]["path"], inputs["component_pair_report"], retain=True)
    pair = json.loads(pair_raw)
    need(pair.get("schema") == "hepta-r34-capacity-component-arm-build/v1" and pair.get("passed") is True
         and pair.get("pair_closed") is True and pair.get("arm") == "B", "actual B pair closure required")
    _, a_raw = bind(pair["baseline_arm_report"]["path"], pair["baseline_arm_report"], retain=True)
    a = json.loads(a_raw)
    builds = {"A": a, "B": pair}
    build_pins = {"A": pair["baseline_arm_report"], "B": inputs["component_pair_report"]}
    need(a.get("schema") == pair["schema"] and a.get("arm") == "A" and a.get("passed") is True
         and a.get("clock") == pair.get("clock") and pair["clock"]["kind"] == "linux:CLOCK_MONOTONIC"
         and a["binary_preserved_monotonic_ns"] < pair["first_build_submitted_monotonic_ns"],
         "actual A preserve-before-B same-boot order differs")
    for arm, value in builds.items():
        need(value["component_source_manifest"] == inputs["component_source_manifest"]
             and value["runtime_compile_inputs"] == inputs["runtime_arms"][arm]["compile_inputs"]
             and value["runtime_include_inputs"] == inputs["runtime_arms"][arm]["include_inputs"],
             "actual ELF source binding differs")
        bind(value["binary"]["path"], value["binary"])
    need(a["graph_receipt"] == pair["graph_receipt"] and a["plan_sha256"] == pair["plan_sha256"],
         "two component arm build plans differ")
    bind(pair["graph_receipt"]["path"], pair["graph_receipt"])
    _, q_terminal_raw = bind(inputs["qualification_terminal"]["path"], inputs["qualification_terminal"], retain=True)
    q_terminal = json.loads(q_terminal_raw)
    parent.verify_r34_terminal(q_terminal, inputs["qualification_job_id"])
    ci = inputs["exact_ci"]
    values = {}
    for name in ("report", "plan", "terminal", "native_read", "nextest_output_audit"):
        _, raw = bind(ci[name]["path"], ci[name], retain=True, maximum=32 * 1024 * 1024)
        values[name] = json.loads(raw)
    report, plan, audit = values["report"], values["plan"], values["nextest_output_audit"]
    native_original(parent, values["terminal"], values["native_read"], ci["job_id"])
    need(report.get("schema") == "hepta-r34-external-rust-ci/v1" and report.get("passed") is True
         and report.get("finished_utc") and not report.get("error") and not report.get("interrupts")
         and report.get("automatic_retries") == 0 and report.get("production_services_modified") is False
         and report.get("source_inputs_unchanged") is True and report.get("owned_children_closed") is True
         and report.get("plan") == ci["plan"]
         and report.get("original_qualification_job_id") == inputs["qualification_job_id"],
         "actual complete R34 exact CI is required before capacity")
    stages = report["stages"]
    need([row["name"] for row in stages] == CI_STAGES
         and all(row.get("passed") is True and type(row.get("returncode")) is int and row["returncode"] == 0
                 and row.get("waited_and_reaped") is True and row.get("owned_process_absent") is True
                 and row.get("owned_process_group_absent") is True and row.get("timed_out") is False
                 and not row.get("error") and not row.get("cleanup_error") for row in stages),
         "exact CI stages/owned cleanup do not close")
    need(plan.get("schema") == "hepta-r34-materialized-exact-rust-ci-plan/v1"
         and plan.get("qualification_job_id") == inputs["qualification_job_id"]
         and plan.get("qualification") == inputs["runtime_arms"]["B"]["qualification_report"]
         and plan.get("source_files") == inputs["runtime_arms"]["B"]["compile_inputs"]
         and report.get("nextest_output_audit") == audit and audit.get("verified") is True,
         "exact CI result does not bind this actual qualified R34 source")
    counts = plan["qualification_counts"]
    need(all(type(counts[key]) is int for key in ("passed", "failed", "ignored", "selected", "retries"))
         and counts["failed"] == counts["retries"] == 0
         and all(audit[key] == counts[key] for key in ("passed", "failed", "ignored", "selected", "retries"))
         and audit["retries"] == 0, "actual exact CI dynamic counts differ")
    for row in stages:
        for stream in ("stdout", "stderr"):
            bind(row[stream]["path"], row[stream], maximum=32 * 1024 * 1024)
    profile_pin, topology_pin = inputs["profile_template"], inputs["topology"]
    need(profile_pin["path"] == str(parent.PROFILE) and profile_pin["sha256"] == parent.PROFILE_SHA
         and topology_pin["path"] == str(parent.TOPOLOGY) and topology_pin["sha256"] == parent.TOPOLOGY_SHA,
         "original six-host profile/topology differs")
    _, profile_raw = bind(profile_pin["path"], profile_pin, retain=True)
    profile = json.loads(profile_raw)
    bind(topology_pin["path"], topology_pin)
    _, topology = modules["benchmark_primitives.py"].load_topology(topology_pin["path"], profile_pin["path"])
    bind(profile["ssh_config"], profile["ssh_config_sha256"])
    bind(profile["known_hosts"], profile["known_hosts_sha256"])
    _, config_raw = bind(inputs["runtime_config_template"]["path"], inputs["runtime_config_template"], retain=True)
    config = json.loads(config_raw)
    need(set(config["hosts"]) == HOSTS and set(inputs["source_records"]) == HOSTS, "six original host policies/records required")
    records = {}
    for host in sorted(HOSTS):
        pin = inputs["source_records"][host]
        need(Path(pin["path"]).parent == parent.FROZEN_JOBS, "different original fixture provenance directory")
        _, raw = bind(pin["path"], pin, retain=True)
        record = json.loads(raw)
        row = config["hosts"][host]
        need(record["host"] == host and record["launch_state"] == "launched"
             and record["execution_mode"] == "operator" and record["system_jobctl"] is False
             and row["execution_mode"] == "operator" and row["allow_execute"] is True
             and row["allow_job_network"] is True and row["allow_pty"] is False
             and row["allow_write"] is False and row.get("privileged_actions", []) == []
             and row["ssh_target"] == record["ssh_target"]
             and row["platform"] == topology["hosts"][host]["platform"],
             "original operator profile or six-host alias policy differs")
        records[host] = record
    need(len({row["ssh_target"] for row in config["hosts"].values()}) == 6, "duplicate target aliases")
    allowed = {"MALLOC_ARENA_MAX", "MALLOC_TRIM_THRESHOLD_", "MALLOC_MMAP_THRESHOLD_", "RAYON_NUM_THREADS", "TOKIO_WORKER_THREADS"}
    need(isinstance(inputs["environment"], dict) and set(inputs["environment"]) <= allowed
         and all(isinstance(value, str) and value.isdigit() for value in inputs["environment"].values()),
         "one fixed component environment required")
    return {"builds": builds, "build_pins": build_pins, "config": config, "records": records,
            "ci_counts": counts, "ci_job_id": ci["job_id"]}


def materialize_cells(inputs, modules, verified, out, agent):
    binding, bench, coordinate = modules["prepare_build.py"], modules["benchmark_primitives.py"], modules["coordinate.py"]
    slots = out / "cell-inputs"
    slots.mkdir(mode=0o700)
    plans = []
    for index, identity in enumerate(inputs["cells"]):
        label, arm, victim = ORDER[index]
        cell_inputs = slots / label
        cell_inputs.mkdir(mode=0o700)
        socket_parent = SOCKETS[index]
        need(not os.path.lexists(socket_parent), "fixed private capacity socket namespace was already used")
        socket_parent.mkdir(mode=0o700)
        profile_path, profile_proof = bench.fresh_profile(inputs["profile_template"]["path"], cell_inputs / "profile", socket_parent, agent)
        profile = json.loads(binding.regular(profile_path))
        wrapper, _ = coordinate.expected_wrapper(profile)
        executable_dir = cell_inputs / "bin"
        executable_dir.mkdir(mode=0o700)
        binding.create(executable_dir / "ssh", wrapper, 0o700)
        config = json.loads(json.dumps(verified["config"]))
        cell_output = out / label
        config["state_dir"] = str(cell_output / "runtime-state")
        for host, record in verified["records"].items():
            original_job = Path(record["remote_job_dir"])
            need(original_job.name == record["id"] and original_job.parent.name == "jobs", "original remote job path differs")
            config["hosts"][host]["remote_state_dir"] = str(original_job.parent.parent / ("r34-capacity-" + identity["nonce"] + "-" + host))
        config_path = cell_inputs / "runtime-config.json"
        binding.create(config_path, binding.encoded(config))
        pin = lambda path: {"path": str(path), "bytes": len(binding.regular(path)), "sha256": binding.sha(binding.regular(path))}
        plan = {"schema": "hepta-r34-capacity-coordinator/v1", "status": "sealed_actual_inputs",
                "arm": arm, "victim": victim, "nonce": identity["nonce"], "output_directory": str(cell_output),
                "driver_binary": verified["builds"][arm]["binary"],
                "component_build_report": verified["build_pins"][arm], "component_pair_report": inputs["component_pair_report"],
                "component_source_manifest": inputs["component_source_manifest"],
                "runtime_arm": inputs["runtime_arms"][arm], "runtime_config": pin(config_path),
                "observation_profile": pin(profile_path), "ssh_wrapper": pin(executable_dir / "ssh"),
                "source_records": inputs["source_records"], "environment": inputs["environment"]}
        plan_path = cell_inputs / "input.json"
        binding.create(plan_path, binding.encoded(plan))
        coordinate.load_plan(plan_path)  # Read-only validation; no fixture or runtime launch.
        plans.append({"identity": identity, "input": pin(plan_path), "profile_proof": profile_proof,
                      "socket_parent": str(socket_parent), "output": str(cell_output)})
    return plans


def summarize(cells, bindings):
    complete = len(cells) == 8 and all(row["status"] == "closed" and row.get("passed") is True for row in cells)
    result = {"schema": "hepta-r34-capacity-descriptive-summary/v1", "comparison_complete": complete,
              "scope": "same-process native direct-transport component; no full MCP throughput claim",
              "cells": [], "victims": {}, "automatic_retries": 0, "failed_or_unrun_cells_discarded": False,
              "normal_performance_gate_passed": None, "candidate_adopted": False}
    result["attribution_requires_original_control_and_held_agent_closure"] = True
    for row in cells:
        value = {key: row[key] for key in ("index", "label", "arm", "victim", "status", "passed")}
        value["raw_report"] = row.get("raw_report")
        value["cancel_timing"] = row.get("cancel_timing")
        value["resources"] = row.get("resources")
        result["cells"].append(value)
    if complete:
        for victim in ("x230", "mac"):
            values = {}
            for arm in ("A", "B"):
                selected = [row for row in cells if row["arm"] == arm and row["victim"] == victim]
                timings = [row["cancel_timing"] for row in selected]
                elapsed = [(row["finished_monotonic_ns"] - row["entry_monotonic_ns"]) / 1e6 for row in timings]
                values[arm] = {"samples": 2, "library_call_ms": elapsed, "median_library_call_ms": statistics.median(elapsed),
                               "raw_reports": [row["raw_report"] for row in selected]}
            result["victims"][victim] = {"arms": values,
                "median_b_over_a": values["B"]["median_library_call_ms"] / values["A"]["median_library_call_ms"],
                "interpretation": "two observations per arm; individual values and descriptive median only, no population p95"}
    result["build_pair"] = bindings
    return result


def inventory(out, checked):
    rows = []
    total = 0
    excluded = {"report.json", "report.json.next", "artifact-inventory.json"}
    for directory, names, files in os.walk(out, followlinks=False):
        for name in names:
            need(not (Path(directory) / name).is_symlink(), "symlink in private evidence inventory")
        for name in sorted(files):
            path = Path(directory) / name
            relative = path.relative_to(out).as_posix()
            if relative in excluded:
                continue
            row = checked(path, maximum=32 * 1024 * 1024)
            total += row["bytes"]
            need(len(rows) < MAX_ARTIFACTS and total <= MAX_ARTIFACT_BYTES, "bounded raw evidence inventory exceeded")
            rows.append(dict(row, relative_path=relative))
    return {"schema": "hepta-r34-capacity-artifact-inventory/v1", "files": rows, "file_count": len(rows),
            "total_bytes": total, "root_report_excluded_to_avoid_self_reference": True,
            "files_deleted": False, "content_uploaded_by_this_tool": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--launcher-sha256", required=True)
    parser.add_argument("--inputs", type=Path, default=INPUT)
    args = parser.parse_args()
    need(args.inputs == INPUT, "fixed first capacity input required; no automatic attempt increment")
    raw = bootstrap_read(args.inputs)
    inputs = json.loads(raw)
    modules, manifest = bootstrap(inputs, args.launcher_sha256)
    parent, binding = modules["parent"], modules["prepare_build.py"]
    checked, create, save, private_directory = parent.checked, parent.create, parent.save, parent.private_directory
    utc, canonical, machine_snapshot = parent.utc, parent.canonical, parent.machine_snapshot
    compiler_activity, process_identity, group_present = parent.compiler_activity, parent.process_identity, parent.group_present
    input_identity = checked(args.inputs)
    out = OUTPUT
    private_directory(out, create_new=True)
    create(out / "input.json", raw)
    report_path = out / "report.json"
    deadline = time.monotonic() + CAMPAIGN_SECONDS
    report = {"schema": "hepta-r34-capacity-campaign-control/v1", "attempt": "01", "passed": False,
              "capacity_gate_passed": False, "started_utc": utc(), "launcher_sha256": args.launcher_sha256,
              "launcher_identity_origin": "original Mac holder hashes transmitted stdin bytes; not a remote self-hash",
              "input_receipt": input_identity, "stages": [], "input_bindings": [], "automatic_retries": 0,
              "production_services_modified": False, "inputs_unchanged": False, "source_inputs_unchanged": False,
              "campaign_budget_seconds": CAMPAIGN_SECONDS, "recommended_holder_timeout_seconds": 3600,
              "cells": [dict(row, status="not_submitted", passed=None, raw_report=None) for row in inputs["cells"]],
              "candidate_adopted": False, "full_mcp_capacity_established": False,
              "external_held_agent_cleanup_closed": False,
              "external_holder_closure_required": True}
    compiler_monitor = monitor_validator = monitor_proof = None
    monitored_body_start = None
    agent_identity = None
    agent = os.environ.get("SSH_AUTH_SOCK", "")
    plans = []

    def checkpoint():
        save(report_path, report)

    def bind(path, expected=None, maximum=128 * 1024 * 1024, retain=False):
        result = checked(path, expected, maximum, retain)
        report["input_bindings"].append(result[0] if retain else result)
        return result

    def unchanged():
        need(checked(args.inputs) == input_identity, "capacity input changed")
        for pin in report["input_bindings"]:
            need(checked(pin["path"], pin) == pin, "capacity bound input changed")
        if agent_identity is not None:
            need(modules["benchmark_primitives.py"].agent_identity(agent) == agent_identity,
                 "held SSH agent identity changed between cells")
        for runtime in inputs["runtime_arms"].values():
            binding.full_map(runtime["source_root"], runtime["compile_inputs"])
            binding.full_map(runtime["source_root"], runtime["include_inputs"])

    def run_stage(spec):
        remaining = deadline - time.monotonic() - 160
        need(remaining > 0, "campaign deadline exhausted before a new stage")
        timeout = min(spec["timeout_seconds"], remaining)
        row = dict(spec, effective_timeout_seconds=timeout, started_utc=utc(), start_monotonic_ns=time.monotonic_ns(),
                   returncode=None, waited_and_reaped=False, cleanup_signals=[], machine_before=machine_snapshot(),
                   cleanup_scope="owned stage process group only; independent controller sessions are proved by original reports/audits")
        report["stages"].append(row)
        checkpoint()
        stdout_path, stderr_path = out / (spec["name"] + ".stdout"), out / (spec["name"] + ".stderr")
        child, birth, primary = None, None, None
        print(json.dumps({"stage": spec["name"], "status": "started", "out": str(out)}), flush=True)
        try:
            with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
                child = subprocess.Popen(spec["argv"], stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                         cwd=ROOT, start_new_session=True)
                row["pid"] = child.pid
                birth = process_identity(child.pid)
                need(birth is not None and birth["process_group"] == child.pid, "owned stage identity unavailable")
                row["identity"] = birth
                checkpoint()
                row["returncode"] = child.wait(timeout=timeout)
                row["waited_and_reaped"] = True
                need(row["returncode"] == 0, spec["name"] + " returned nonzero; original output retained")
        except BaseException as error:
            primary = error
            row["error"] = {"type": type(error).__name__, "reason": str(error)[:3000]}
            row["timed_out"] = isinstance(error, subprocess.TimeoutExpired)
        finally:
            if child is not None:
                try:
                    if child.poll() is None:
                        # Leave time for the original 30+10+10 second Controller
                        # close path, reader join and an in-flight RPC. Even a
                        # reaped stage group does not prove its separate runtime
                        # sessions are gone; failures retain that uncertainty.
                        for sig, seconds in ((signal.SIGINT, 120), (signal.SIGTERM, 10), (signal.SIGKILL, 10)):
                            need(birth is not None and process_identity(child.pid) == birth, "owned stage identity changed before cleanup")
                            os.killpg(child.pid, sig)
                            row["cleanup_signals"].append({"signal": sig.name, "utc": utc()})
                            try:
                                child.wait(timeout=seconds)
                                break
                            except subprocess.TimeoutExpired:
                                continue
                    row["returncode"] = child.wait(timeout=1)
                    row["waited_and_reaped"] = True
                    row["owned_process_absent"] = process_identity(child.pid) is None
                    row["owned_process_group_absent"] = not group_present(child.pid)
                    need(row["owned_process_absent"] and row["owned_process_group_absent"], "owned stage/session remains; no next stage")
                except BaseException as error:
                    row["cleanup_error"] = {"type": type(error).__name__, "reason": str(error)[:3000]}
                    primary = primary or error
            row["finished_utc"] = utc()
            row["end_monotonic_ns"] = time.monotonic_ns()
            row["elapsed_seconds"] = (row["end_monotonic_ns"] - row["start_monotonic_ns"]) / 1e9
            row["machine_after"] = machine_snapshot()
            for name, path in (("stdout", stdout_path), ("stderr", stderr_path)):
                if path.exists():
                    row[name] = checked(path)
            row["output_bindings"] = [checked(Path(path)) for path in spec["outputs"] if Path(path).is_file()]
            row["passed"] = primary is None and len(row["output_bindings"]) == len(spec["outputs"])
            if not row["passed"] and spec["name"] in {"native-observation", "native-boundary", "cancel-recovery"}:
                row["independent_controller_cleanup"] = "unknown; stage-group absence is insufficient and no workload is retried"
            checkpoint()
            print(json.dumps({"stage": spec["name"], "passed": row["passed"], "returncode": row["returncode"]}), flush=True)
        if primary is not None:
            raise primary
        need(row["passed"], "expected stage output missing")

    try:
        checkpoint()
        compiler_monitor, monitor_validator, monitor_proof = parent.prepare_compiler_monitor(inputs, bind)
        monitor_ready = compiler_monitor.start()
        monitored_body_start = time.monotonic_ns()
        need(monitor_ready, "initial compiler monitor sample failed; no workload submitted")
        report["compiler_monitor_scope"] = parent.COMPILER_MONITOR_POLICY["guarded_interval"]
        report["machine_initial"] = machine_snapshot()
        verified = prerequisites(inputs, modules, manifest, bind)
        report["runtime_exact_ci"] = {"job_id": verified["ci_job_id"], "actual_counts": verified["ci_counts"]}
        need(agent.startswith("/"), "current forwarded SSH agent required")
        agent_identity = modules["benchmark_primitives.py"].agent_identity(agent)
        report["agent_identity"] = agent_identity
        need(all(not os.path.lexists(path) for path in SOCKETS), "a capacity socket parent already exists")
        plans = materialize_cells(inputs, modules, verified, out, agent)
        for plan in plans:
            _, plan_raw = bind(plan["input"]["path"], plan["input"], retain=True)
            configured = json.loads(plan_raw)
            for key in ("runtime_config", "observation_profile", "ssh_wrapper"):
                bind(configured[key]["path"], configured[key])
            profile = json.loads(binding.bound_file(configured["observation_profile"]))
            bind(profile["ssh_config"], profile["ssh_config_sha256"])
            bind(profile["known_hosts"], profile["known_hosts_sha256"])
        report["cell_plan"] = plans
        report["stage_plan"] = [{"name": row["identity"]["label"], "argv": ["/usr/bin/python3", "-B", str(PACKAGE / "coordinate.py"), "--input", row["input"]["path"]],
                                 "timeout_seconds": CELL_SECONDS, "outputs": [str(Path(row["output"]) / "report.json")]} for row in plans]
        checkpoint()
        cooling = {"seconds_planned": QUIESCENCE_SECONDS, "checks": [], "start_monotonic_ns": time.monotonic_ns()}
        report["quiescence"] = cooling
        until = time.monotonic() + QUIESCENCE_SECONDS
        while True:
            busy = compiler_activity()
            cooling["checks"].append({"machine": machine_snapshot(), "compiler_processes": busy})
            checkpoint()
            need(not busy, "compiler activity overlaps the campaign; no workload started")
            remaining = until - time.monotonic()
            if remaining <= 0:
                break
            print(json.dumps({"stage": "quiescence", "remaining_seconds": round(remaining, 1)}), flush=True)
            time.sleep(min(15, remaining))
        cooling["end_monotonic_ns"] = time.monotonic_ns()
        cooling["passed"] = True
        for index, (spec, plan) in enumerate(zip(report["stage_plan"], plans)):
            unchanged()
            need(not compiler_activity(), "compiler activity overlaps a capacity cell")
            row = report["cells"][index]
            row["status"] = "submitted"
            row["submitted_monotonic_ns"] = time.monotonic_ns()
            checkpoint()
            try:
                run_stage(spec)
                report_identity, cell_raw = checked(Path(plan["output"]) / "report.json", retain=True)
                cell = json.loads(cell_raw)
                executed_input = checked(Path(plan["output"]) / "input.json")
                need(all(executed_input[key] == plan["input"][key] for key in ("bytes", "sha256")),
                     "cell did not execute the exact preregistered input bytes")
                need(cell.get("schema") == "hepta-r34-native-direct-capacity-cell/v1" and cell.get("passed") is True
                     and not cell.get("primary_error") and not cell.get("cleanup_errors")
                     and (cell["arm"], cell["victim"], cell["nonce"]) == (row["arm"], row["victim"], row["nonce"])
                     and cell["automatic_retries"] == 0 and cell["candidate_adopted"] is False,
                     "original cell identity/correctness/cleanup did not close")
                need(cell["driver_process"]["actual_waitpid_reaped"] is True
                     and not cell["observed_descendant_cleanup"]["observed_survivors_before_forced_cleanup"]
                     and all(value.get("actual_waitpid_reaped") is True for value in cell["coordinator_ssh_cleanup"]),
                     "cell original process ownership remains uncertain")
                need(not any(Path(plan["socket_parent"]).iterdir()), "original observation socket namespace did not close")
                row.update(status="closed", passed=True, raw_report=report_identity,
                           executed_input=executed_input,
                           cancel_timing=cell["cancel_timing"], resources=cell["resources"],
                           closed_monotonic_ns=time.monotonic_ns())
            except BaseException as error:
                row.update(status="failed_or_incomplete", passed=False,
                           error={"type": type(error).__name__, "reason": str(error)[:3000]},
                           closed_monotonic_ns=time.monotonic_ns(),
                           owner_closure="only original stage and cell receipts can prove closure; absence alone is insufficient")
                if Path(spec["outputs"][0]).is_file():
                    row["raw_report"] = checked(spec["outputs"][0])
                checkpoint()
                raise
            checkpoint()
        unchanged()
        report["inputs_unchanged"] = report["source_inputs_unchanged"] = True
        report["capacity_gate_passed"] = report["passed"] = True
    except BaseException as error:
        report["error"] = {"type": type(error).__name__, "reason": str(error)[:4000]}
        report["passed"] = report["capacity_gate_passed"] = False
        report["uncertain_effects_are_not_retried"] = True
        create(out / "campaign.error.txt", traceback.format_exc().encode())
    finally:
        try:
            unchanged()
            report["inputs_unchanged"] = report["source_inputs_unchanged"] = True
        except BaseException as error:
            report["final_input_error"] = {"type": type(error).__name__, "reason": str(error)[:3000]}
            report["passed"] = report["capacity_gate_passed"] = False
        summary = summarize(report["cells"], inputs["component_pair_report"])
        create(out / "summary.json", canonical(summary))
        report["summary"] = checked(out / "summary.json")
        monitored_body_end = time.monotonic_ns()
        parent.finish_compiler_monitor(compiler_monitor, monitor_validator, monitor_proof,
            monitored_body_start, monitored_body_end, out, report, "capacity_gate_passed")
        report["finished_utc"] = utc()
        report["machine_final"] = machine_snapshot()
        report["remaining_cells_not_submitted"] = [row["label"] for row in report["cells"] if row["status"] == "not_submitted"]
        try:
            raw_inventory = inventory(out, checked)
            create(out / "artifact-inventory.json", canonical(raw_inventory))
            report["artifact_inventory"] = checked(out / "artifact-inventory.json")
        except BaseException as error:
            report["inventory_error"] = {"type": type(error).__name__, "reason": str(error)[:3000]}
            report["passed"] = report["capacity_gate_passed"] = False
        checkpoint()
        print(json.dumps({"passed": report["passed"], "capacity_gate_passed": report["capacity_gate_passed"],
                          "external_holder_closure_required": True, "report": str(report_path)}), flush=True)
    return 0 if report["passed"] else 1


def interrupted(signum, _frame):
    raise RuntimeError("capacity campaign interrupted by signal " + str(signum))


if __name__ == "__main__":
    os.umask(0o077)
    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, interrupted)
    raise SystemExit(main())

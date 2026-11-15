#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""One R31 campaign using unchanged, pinned native/boundary/recovery harnesses.

The existing Mac held_agent_campaign_02.py transmits this file on stdin and
supplies --launcher-sha256. Its explicit input receipt binds actual adopted R24
baseline artifacts and qualification, a completed R24 adoption campaign and its
publication readback, plus the new qualified R31 candidate. No future R24 binary
SHA is assumed. Every attempt is fresh; uncertain stages are never retried.
"""
import argparse
import ast
import datetime
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time
import traceback
import types

sys.dont_write_bytecode = True
ROOT = Path("/home/qian/hepta-runtime-optimization-20261105-r31")
R16 = Path("/home/qian/hepta-runtime-optimization-20261104-r16")
BASELINE_ROOT = Path("/home/qian/hepta-runtime-optimization-20261105-r24")
SOURCE = ROOT / "source"
TOOLS = R16 / "measurement-tools"
BOUNDARY_ORIGINAL = R16 / "boundary-tools"
BOUNDARY_TOOLS = ROOT / "boundary-tools-02"
SUMMARY = ROOT / "tools-02/summarize_r25_campaign.py"
PROFILE = Path("/home/qian/hepta-runtime-optimization-20261023/r11-native-observation-abba-20261103-02/profile/profile.json")
TOPOLOGY = R16 / "benchmark-topology.json"
FROZEN_JOBS = Path("/home/qian/hepta-runtime-optimization-20261023/a31-frozen-originals-r01")
CANDIDATE_DIR = ROOT / "qualification-01"
CANDIDATE = CANDIDATE_DIR / "hepta-runtime"
BINARY_NAMES = ("hepta-runtime", "hepta-runtime-jobctl", "native_process_driver")
PROFILE_SHA = "fe1e9551b5b8812ad6ed3da018c282b7261f7caeb2f49e4dcfefba7ff784ab08"
TOPOLOGY_SHA = "8c0767d3318131a7d470d9cde8e327a59ce18adf022c8bc1b1d5a0fa9a865287"
HARNESS_FILES = {
    "allocator_environment.py": "f5c8e879c540b3f7cb1b7d3a7a0f5002c2f40c1a87963174b0b00470fa3a4525",
    "allocator_environment_audit.py": "4b082ce343ae3943e3098baa58af2f5def7198881b9c087d63d88360e9763727",
    "analyze_native_observation.py": "cc7f6884d581cd1ced430437350e808de51931c50d12441797205501b20cae66",
    "audit_native_evidence.py": "b69f6902d2de81eab41b21506f024c002d2f8264d60e86df6b1086623a77fd28",
    "observation_resources.py": "f3402d51cb37b2fe20f4351b3a81ec5990a9fdaff93a846d21c07ccd557cb894",
    "owned_ssh_interruption.py": "1989c57f0b944afae1ed759d6529b8f1cc26197e269e2c34c4fd49e43a32aa7b",
    "run_native_observation.py": "7606648c99b2ff2bbf0bba58384e8cab609ac3899f838c0b80ba54d6288d20bb",
    "run_six_host_cancel_recovery.py": "698eb7801cde3f2bd5ff202412c0833fc218fd7e912c3c949d2b37fde7a56a12",
    "test_native_harness.py": "2b450175b9e6122248ac1bcb51860aa8a6d3eff55f6ac8c877c0a905e3dd7d00",
    "verify_cancel_recovery.py": "0116652a0b489dc462f005e01d7c943feda9ba784563d7317c92bb5beb9a701c",
    "x230_observation_benchmark.py": "4d96f0bf2da2562e788f48be7c37589ab3a513be5f9d8b2d741afe5c08ea9eed",
    "x230_six_running_recovery_canary.py": "6219bc556b0ac6d142bd4c731466b959e8a410f0b4b55f3d8b303f8fdbfbaaf4",
}
BOUNDARY_FILES = {
    "run_native_boundary.py": "2af83ebba8b7ea5550e7549da795556eb8328622bcfbf563019654e202a53329",
    "audit_native_boundary.py": "8ad8f6d97a5bd2e4850b02cd66fa5d2ac7d237ea0eef043daf9c88d3c9c152ee",
    "test_native_boundary.py": "cda0bbef1704c374b49cc3cf5ea7b9a873687e547eed5c927bed801cf15156bd",
    "harness-freeze.json": "77ea90d5d2f45ed4d724f087353a3c8e603abcd0a8bd1d4bceb31179bef174b1",
    "capacity-policy.json": "206d1a99abc328948d8df893daa77a862b25de878a8b97379090da7ce84393d3",
}
HOSTS = {"ai395", "mac", "main", "pocket4", "rog", "x230"}
HEX = re.compile(r"[0-9a-f]{64}\Z")
QUIESCENCE_SECONDS = 90
CAMPAIGN_SECONDS = 3300  # Leave the 3600-second holder time for bounded cleanup.
COMPILER_MONITOR_PATHS = {
    "module": ROOT / "tools-02/compiler_monitor.py",
    "reader": ROOT / "tools-02/compiler_state.py",
    "validator": ROOT / "tools-02/validate_compiler_monitor.py",
    "policy": ROOT / "tools-02/compiler-monitor-policy-01.json",
}
COMPILER_MONITOR_LIMITS = {
    "period_ns": 1_000_000_000,
    "maximum_lateness_ns": 750_000_000,
    "maximum_start_gap_ns": 2_000_000_000,
    "maximum_scan_ns": 500_000_000,
    "maximum_duration_ns": 3_600_000_000_000,
    "maximum_samples": 3603,
    "maximum_serialized_sample_bytes": 8 * 1024 * 1024,
    "maximum_compiler_records": 8192,
    "maximum_process_directories_per_scan": 16384,
    "maximum_error_records": 64,
    "maximum_cpu_seconds_per_wall_second": 0.02,
    "ready_timeout_seconds": 5.0,
    "join_timeout_seconds": 10.0,
}
COMPILER_MONITOR_POLICY = {
    "schema": "hepta-r26-compiler-monitor-policy/v1",
    "tool_revision": "03",
    "runtime_attempt": "01",
    "limits": COMPILER_MONITOR_LIMITS,
    "guarded_interval": "before prerequisite body and quiescence through original child cleanup and final source checks",
    "signals_sent": 0,
    "extra_processes_spawned": 0,
    "hot_loop_file_writes": 0,
    "absence_between_samples_is_not_proved": True,
    "measurement_matrix_and_performance_thresholds_unchanged": True,
    "invalid_monitor_forbids_performance_attribution": True,
}


def need(value, message):
    if not value:
        raise RuntimeError(message)


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def bind_compiler_monitor_inputs(inputs, bind):
    pins = inputs.get("compiler_monitor")
    need(isinstance(pins, dict) and set(pins) == set(COMPILER_MONITOR_PATHS),
         "four frozen compiler monitor inputs required")
    raw, identities = {}, {}
    for name, path in COMPILER_MONITOR_PATHS.items():
        pin = pins[name]
        need(isinstance(pin, dict) and set(pin) == {"path", "bytes", "sha256"}
             and pin["path"] == str(path) and type(pin["bytes"]) is int and 0 < pin["bytes"] <= 65536
             and isinstance(pin["sha256"], str) and HEX.fullmatch(pin["sha256"]),
             "compiler monitor source/policy identity differs: " + name)
        identities[name], raw[name] = bind(path, pin, retain=True, maximum=65536)
    need(json.loads(raw["policy"]) == COMPILER_MONITOR_POLICY, "frozen compiler monitor policy differs")
    return raw, {"schema": "hepta-r26-compiler-monitor-input-binding/v1",
                 "sources": identities, "limits": COMPILER_MONITOR_LIMITS}


def monitor_module(name, raw, path):
    module = types.ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    # The checked bytes are executed directly; no hash-then-path-import window.
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


def prepare_compiler_monitor(inputs, bind):
    raw, proof = bind_compiler_monitor_inputs(inputs, bind)
    module = monitor_module("_r26_bound_compiler_monitor", raw["module"], COMPILER_MONITOR_PATHS["module"])
    validator = monitor_module("_r26_bound_compiler_monitor_validator", raw["validator"], COMPILER_MONITOR_PATHS["validator"])
    limits = module.Limits(**COMPILER_MONITOR_LIMITS)
    need(module.asdict(limits) == COMPILER_MONITOR_LIMITS, "compiler monitor limit construction differs")
    snapshot = module.reader_from_pinned_source(COMPILER_MONITOR_PATHS["reader"],
        proof["sources"]["reader"]["sha256"], COMPILER_MONITOR_LIMITS["maximum_process_directories_per_scan"])
    return module.CompilerMonitor(snapshot, limits=limits), validator, proof


def finish_compiler_monitor(monitor, validator, proof, body_start, body_end, out, report, gate_key):
    report["result_before_compiler_monitor"] = {key: report[key] for key in ("passed", gate_key)}
    report["measurement_attribution_valid"] = False
    report["compiler_monitor"] = {"passed": False}
    try:
        need(monitor is not None and validator is not None and proof is not None,
             "compiler monitor was not initialized; no successful guarded experiment")
        ledger = monitor.stop(body_start, body_end)
        ledger["source_bindings"] = proof
        ledger_path = out / "compiler-monitor.json"
        ledger_bytes = canonical(ledger)
        create(ledger_path, ledger_bytes)
        ledger_identity, retained_ledger = checked(ledger_path,
            {"bytes": len(ledger_bytes), "sha256": hashlib.sha256(ledger_bytes).hexdigest()},
            maximum=16 * 1024 * 1024, retain=True)
        validation = validator.validate(json.loads(retained_ledger), COMPILER_MONITOR_LIMITS, body_start, body_end)
        source_errors = []
        for expected in proof["sources"].values():
            try:
                need(checked(expected["path"], expected) == expected, "compiler monitor source changed")
            except BaseException as error:
                source_errors.append({"path": expected["path"], "type": type(error).__name__, "reason": str(error)[:1000]})
        audit = {"schema": "hepta-r26-compiler-monitor-audit/v1", "ledger": ledger_identity,
                 "validator": proof["sources"]["validator"], "validation": validation,
                 "monitor_sources_unchanged": not source_errors, "source_recheck_errors": source_errors}
        audit_path = out / "compiler-monitor.audit.json"
        create(audit_path, canonical(audit))
        valid = ledger["passed"] is True and validation["passed"] is True and not source_errors
        if source_errors:
            report["inputs_unchanged"] = False
        report["compiler_monitor"] = {"passed": valid, "ledger": ledger_identity,
            "independent_audit": checked(audit_path), "sources": proof["sources"],
            "limits": COMPILER_MONITOR_LIMITS, "monitor_sources_unchanged": not source_errors,
            "guarded_body_start_monotonic_ns": body_start, "guarded_body_end_monotonic_ns": body_end}
        report["measurement_attribution_valid"] = valid
    except BaseException as error:
        report["compiler_monitor_finalization_error"] = {"type": type(error).__name__, "reason": str(error)[:3000]}
    if not report["measurement_attribution_valid"]:
        report["passed"] = report[gate_key] = False
        if gate_key == "observation_gate_passed":
            report["rejection_reasons"] = list(report.get("rejection_reasons") or []) + ["compiler monitor invalid"]


def verify_completed_compiler_monitor(observed, inputs, bind, expected_output):
    need(expected_output in (ROOT / "campaign-02", ROOT / "lifecycle-campaign-02"),
         "fixed R31 monitored output required")
    need(observed.get("measurement_attribution_valid") is True,
         "observation compiler monitoring did not authorize performance attribution")
    monitor = observed["compiler_monitor"]
    need(monitor["passed"] is True and monitor["monitor_sources_unchanged"] is True
         and monitor["limits"] == COMPILER_MONITOR_LIMITS, "completed compiler monitor gate differs")
    raw, proof = bind_compiler_monitor_inputs(inputs, bind)
    need(monitor["sources"] == proof["sources"], "observation monitor source set differs")
    need(monitor["ledger"]["path"] == str(expected_output / "compiler-monitor.json")
         and monitor["independent_audit"]["path"] == str(expected_output / "compiler-monitor.audit.json"),
         "completed compiler monitor evidence paths differ")
    ledger_identity, ledger_raw = bind(monitor["ledger"]["path"], monitor["ledger"], retain=True,
                                       maximum=16 * 1024 * 1024)
    audit_identity, audit_raw = bind(monitor["independent_audit"]["path"], monitor["independent_audit"], retain=True)
    ledger, audit = json.loads(ledger_raw), json.loads(audit_raw)
    need(ledger["source_bindings"] == proof, "retained compiler ledger source binding differs")
    validator = monitor_module("_r26_bound_prior_monitor_validator", raw["validator"], COMPILER_MONITOR_PATHS["validator"])
    validation = validator.validate(ledger, COMPILER_MONITOR_LIMITS,
        monitor["guarded_body_start_monotonic_ns"], monitor["guarded_body_end_monotonic_ns"])
    need(validation["passed"] is True and audit == {
        "schema": "hepta-r26-compiler-monitor-audit/v1", "ledger": ledger_identity,
        "validator": proof["sources"]["validator"], "validation": validation,
        "monitor_sources_unchanged": True, "source_recheck_errors": []}, "independent compiler monitor ledger verification failed")
    return {"passed": True, "ledger": ledger_identity, "independent_audit": audit_identity,
            "validator": proof["sources"]["validator"], "validation": validation}


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


def create(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def save(path, value):
    pending = path.with_name(path.name + ".next")
    create(pending, canonical(value))
    os.replace(pending, path)


def private_directory(path, create_new=False):
    need(path.is_absolute() and path.resolve() == path, "indirect private directory")
    if create_new:
        path.mkdir(mode=0o700)
    value = path.lstat()
    need(stat.S_ISDIR(value.st_mode) and value.st_uid == os.geteuid()
         and stat.S_IMODE(value.st_mode) == 0o700, "private directory ownership/mode differs: " + str(path))


def source_inputs(source):
    need(source.is_absolute() and source.resolve() == source and source.is_dir(), "direct qualified source directory missing")
    paths = {source / "Cargo.toml", source / "Cargo.lock"}
    for relative in ("build.rs", "rustfmt.toml", "rust-toolchain", "rust-toolchain.toml", ".cargo/config", ".cargo/config.toml"):
        path = source / relative
        if os.path.lexists(path):
            paths.add(path)
    for relative in ("src", "examples"):
        root = source / relative
        need(root.is_dir() and root.resolve() == root, "source input subtree missing or indirect")
        for directory, subdirs, names in os.walk(root, followlinks=False):
            for name in subdirs:
                need(not (Path(directory) / name).is_symlink(), "symlinked source directory")
            paths.update(Path(directory) / name for name in names)
    files = {}
    for path in sorted(paths):
        identity = checked(path, maximum=16 * 1024 * 1024)
        files[path.relative_to(source).as_posix()] = {key: identity[key] for key in ("bytes", "sha256")}
    return {"root": str(source), "file_count": len(files), "files": files,
            "sha256": hashlib.sha256(canonical(files)).hexdigest(),
            "scope": "Cargo manifests, optional build/toolchain/config inputs, complete src and examples trees"}


def machine_snapshot():
    paths = [Path("/proc/loadavg"), Path("/proc/meminfo"), Path("/proc/uptime"), Path("/proc/sys/kernel/perf_event_paranoid")]
    paths += sorted(Path("/sys/devices/system/cpu").glob("cpu[0-9]*/cpufreq/scaling_cur_freq"))
    paths += sorted(Path("/sys/class/thermal").glob("thermal_zone*/temp"))
    values = {}
    for path in paths:
        try:
            values[str(path)] = path.read_text()[:32768]
        except OSError as error:
            values[str(path)] = {"error": type(error).__name__, "errno": error.errno}
    disk = os.statvfs(ROOT)
    return {"utc": utc(), "monotonic_ns": time.monotonic_ns(), "loadavg": list(os.getloadavg()),
            "disk_available_bytes": disk.f_bavail * disk.f_frsize, "cpu_count": os.cpu_count(),
            "values": values, "machine_settings_changed": False}


def compiler_activity():
    busy = []
    names = {"cargo", "rustc", "rust-lld", "ld.lld", "cc", "gcc", "clang", "clang++"}
    for path in Path("/proc").iterdir():
        if not path.name.isdigit():
            continue
        try:
            if path.stat().st_uid != os.geteuid():
                continue
            name = (path / "comm").read_text().strip()
            raw = (path / "stat").read_text()
            state = raw[raw.rfind(") ") + 2:].split()[0]
            if name in names and state not in {"Z", "X"}:
                busy.append({"pid": int(path.name), "comm": name, "state": state})
        except (OSError, IndexError):
            continue
    return busy


def process_identity(pid):
    try:
        raw = Path(f"/proc/{pid}/stat").read_text()
    except FileNotFoundError:
        return None
    end = raw.rfind(") ")
    parts = raw[end + 2:].split()
    need(end > 0 and len(parts) >= 20 and int(raw.split("(", 1)[0]) == pid, "malformed owned process identity")
    return {"pid": pid, "start_ticks": int(parts[19]), "process_group": int(parts[2])}


def group_present(pid):
    try:
        os.killpg(pid, 0)
        return True
    except ProcessLookupError:
        return False


def verify_composed_qualification(value, source, binaries):
    need(value["schema"] == "hepta-x230-composed-qualification/v1" and value["qualified"] is True
         and value["source"] == str(source)
         and isinstance(value["source_tested"], dict) and value["source_tested"]
         and value["source_tested"] == value["source_after"]
         and isinstance(value["stages"], list) and value["stages"]
         and all(type(stage.get("returncode")) is int and stage["returncode"] == 0 for stage in value["stages"]),
         "composed qualification source/stages do not close successfully")
    need(set(value["binaries"]) == set(BINARY_NAMES), "qualification binary set differs")
    for name, expected in binaries.items():
        actual = value["binaries"][name]
        need(actual["path"] == expected["path"] and actual["sha256"] == expected["sha256"],
             "qualified binary differs from the supplied input receipt: " + name)


def qualification_projection(snapshot):
    return {name: value["sha256"] for name, value in snapshot["files"].items()
            if name in {"Cargo.toml", "Cargo.lock", "rustfmt.toml"} or name.startswith(("src/", "examples/"))}


def verify_baseline_enablement(campaign, publication, binaries, expected_commit, expected_campaign_sha):
    """Accept only actual R24 adoption and post-push readback, never placeholders.

    The readback keeps the existing success fields and explicitly binds this
    campaign/source. Positive R24 values require the actual completed publication.
    This function performs no Git/network operations or publication itself.
    """
    need(campaign["schema"] == "hepta-r24-campaign-control/v1"
         and campaign["passed"] is True and campaign["adoption_passed"] is True
         and campaign["inputs_unchanged"] is True and campaign["source_inputs_unchanged"] is True
         and campaign["correctness_stages_completed"] is True and campaign["binaries"]["B"] == binaries,
         "R24 has not closed as an adopted, unchanged baseline with these exact binaries")
    need(isinstance(expected_campaign_sha, str) and HEX.fullmatch(expected_campaign_sha)
         and publication["schema"] == "hepta-r24-final-publication-readback/v1"
         and publication["campaign_report_sha256"] == expected_campaign_sha
         and isinstance(campaign["source_inputs_sha256"], str) and HEX.fullmatch(campaign["source_inputs_sha256"])
         and publication["source_inputs_sha256"] == campaign["source_inputs_sha256"]
         and isinstance(expected_commit, str) and re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", expected_commit)
         and publication["verified"] is True
         and publication["repository"] == "TrillionniumFoundation/hepta-runtime"
         and publication["commit"] == expected_commit
         and publication["candidate_adopted"] is True and publication["source_changes_published"] is True
         and publication["branch_and_pr_heads_match"] is True,
         "R24 adoption has no matching actual GitHub publication readback")


# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""R31-specific receipt checks, inserted into the unchanged campaign parent.

This fragment uses the parent's checked/bind primitives. It performs no builds,
remote calls, retries, cache operations, or candidate workload submissions.
"""

R31_BASELINE_COMMIT = "baab4def80be7af015b2e7a594cb302f66c4130e"
R31_ADDED_PATHS = {"src/mcp/runtime/jobs_cancel_wait_tests.rs", "src/mcp/runtime/jobs_cancel_wait_fixture.py"}
R31_CHANGED_PATHS = R31_ADDED_PATHS | {"src/mcp/runtime/jobs.rs"}
R31_CACHE_OWNER = Path("/home/qian/hepta-runtime-optimization-20261105-r30")
R31_PRIOR_QUALIFICATION_SHA = "24cd58c6194ab94f1d5b7f33c409bd901a06ca5f39ad33d53aa0ec339dcb6a76"
R31_PRIOR_TERMINAL_SHA = "74a312bc03e765ac3883fac0f38c7c149ec2ec36870381c2c5452f052597e79a"
R31_PRIOR_OBSERVATION_SHA = "3b7ced2475a579f4a6c9f9f61605a7e4756c31884ec8cb505e74da176e8a0f5c"
R31_QUALIFICATION_STAGES = ["format", "fmt-check", "harness-tests", "clippy",
    "test-build", "isolated-tests", "audit-isolated-tests", "release"]
R31_BASELINE_QUALIFICATION = {
    "path": "/home/qian/hepta-runtime-optimization-20261105-r24/qualification-01/report.json",
    "bytes": 83365,
    "sha256": "bf0c5814d28b163e4a90405026cd4d90e399370d1f910f8ac48cb580af1e4971",
}
R31_ADOPTION_SCOPE = "accepted R24 plus pidfd cancellation readiness wait only"
R31_OPEN_BLOCKERS = [{
    "id": "saturated-cancellation-capacity",
    "status": "open",
    "scope": "not included in the R31 source change or normal lifecycle adoption",
    "reason": "R31 does not add cancellation reserve capacity; no saturated cancellation proof is claimed",
}]


def verify_r31_terminal(terminal, job_id, expected_state="succeeded", expected_exit=0):
    """Keep the original native job's complete terminal/log requirements."""
    need(isinstance(job_id, str) and re.fullmatch(r"[0-9a-f]{11,16}-[0-9a-f]{4}-[0-9a-f]{4}", job_id),
         "actual original R31 qualification job identity required")
    need(terminal.get("job_id") == job_id and terminal.get("state") == expected_state
         and type(terminal.get("exit_code")) is int and terminal["exit_code"] == expected_exit
         and all(terminal.get(key) is False for key in ("automatic_retry", "timed_out", "cancelled"))
         and all(terminal.get(key) is True for key in ("output_complete", "output_durable", "terminal_publication_confirmed"))
         and type(terminal.get("terminal_publication_protocol")) is int and terminal["terminal_publication_protocol"] == 1
         and terminal.get("log_synced") == {"stdout": True, "stderr": True}
         and terminal.get("log_errors") == {"stdout": None, "stderr": None}
         and terminal.get("log_truncated") == {"stdout": False, "stderr": False},
         "original R31 qualification has no complete expected native terminal proof")
    for stream in ("stdout", "stderr"):
        counts = terminal["log_bytes"][stream]
        need(set(counts) == {"seen", "stored"}
             and all(type(value) is int and value >= 0 for value in counts.values())
             and counts["seen"] == counts["stored"], "qualification native log byte custody differs")


def r31_known_nondumpable_helper(name, command, cgroup, uids):
    """Classify only observed non-build system helpers using readable metadata.

    Do not try to read protected proc links through another identity. Unknown
    opaque processes still stop preparation. All compiler names remain global.
    """
    if uids != [1000, 1000, 1000, 1000]:
        return False
    command = command.replace(b'\0', b' ').strip()
    group = cgroup.strip()
    if name == '(sd-pam)':
        return command == b'(sd-pam)' and group == '0::/user.slice/user-1000.slice/user@1000.service/init.scope'
    if name == 'sshd':
        return command == b'sshd: qian@notty' and re.fullmatch(r'0::/user.slice/user-1000.slice/session-[0-9]+\.scope', group) is not None
    if name == 'gpg-agent':
        return command == b'/usr/bin/gpg-agent --supervised' and group == '0::/user.slice/user-1000.slice/user@1000.service/app.slice/gpg-agent.service'
    if name == 'ssh-agent':
        return command == b'/usr/bin/ssh-agent -D -a /run/user/1000/gcr/.ssh' and group == '0::/user.slice/user-1000.slice/user@1000.service/app.slice/gcr-ssh-agent.service'
    return False


# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Inserted receipt-only checks for the preserved failed R31 preflight.

The exact helper classifier is copied from the pinned preparation-v2 source.
Opaque fields remain an explicitly recorded limitation; they are not probed.
"""

R31_FAILED_PREPARATION_SHA = "0f9ea821eeab65ebc555b9cb30f12188949454ce4d1ce4b3c5a8db8a1cd5f88c"
R31_FAILED_PREPARATION_JOB = "1a1ae1597f5-fc05-5d3e"
R31_FAILED_PREPARATION_REASON = "PermissionError: [Errno 13] Permission denied: '/proc/3766/cwd'"


def verify_r31_preparation_recovery(preparation):
    prior = preparation.get("prior_preparation_failure", {})
    need(prior.get("report_path") == str(ROOT / "preparation.json")
         and prior.get("report_sha256") == R31_FAILED_PREPARATION_SHA
         and prior.get("native_path") == str(ROOT / "preparation-attempt-01-native.json")
         and isinstance(prior.get("native_sha256"), str) and HEX.fullmatch(prior["native_sha256"])
         and prior.get("job_id") == R31_FAILED_PREPARATION_JOB
         and prior.get("qualification_started") is False
         and prior.get("reason") == R31_FAILED_PREPARATION_REASON
         and prior.get("recovery") == "record exact known nondumpable non-build system helpers; reject unknown opaque processes",
         "R31 recovery must preserve the original failure before cache transfer and qualification")
    processes = preparation.get("process_check", {})
    need(processes.get("matched_processes") == [] and processes.get("compiler_processes") == []
         and isinstance(processes.get("opaque_system_helpers"), list)
         and processes.get("scope") == "all readable same-user cmdline/cwd/exe/fd plus global compiler names; exact known non-build system helpers recorded when proc access is denied",
         "R31 recovery process-check scope or idle receipt differs")
    pids = set()
    for row in processes["opaque_system_helpers"]:
        fields = row.get("unreadable_fields")
        need(type(row.get("pid")) is int and row["pid"] > 0 and row["pid"] not in pids
             and isinstance(row.get("start_ticks"), str) and row["start_ticks"].isdigit()
             and isinstance(row.get("comm"), str) and isinstance(row.get("command"), str)
             and isinstance(row.get("cgroup"), str)
             and row.get("classification") == "observed non-build system helper"
             and isinstance(fields, list) and fields and all(isinstance(item, str) for item in fields)
             and len(fields) == len(set(fields))
             and all(item in {"cwd", "exe", "fd"} or re.fullmatch(r"fd/[0-9]+", item) for item in fields)
             and r31_known_nondumpable_helper(row["comm"], row["command"].encode(), row["cgroup"], row.get("uids")),
             "unknown or incompletely identified opaque process in the R31 preparation receipt")
        pids.add(row["pid"])
    return {"revision": 2, "prior_failed_job_id": R31_FAILED_PREPARATION_JOB,
        "prior_qualification_started": False, "opaque_system_helpers": processes["opaque_system_helpers"],
        "process_visibility_scope": processes["scope"], "automatic_retry": False}


def verify_r31_failed_preparation(preparation, terminal):
    verify_r31_terminal(terminal, R31_FAILED_PREPARATION_JOB, expected_state="failed", expected_exit=1)
    need(preparation.get("schema") == "hepta-x230-r31-preparation/v1"
         and preparation.get("passed") is False and preparation.get("finished_utc")
         and preparation.get("error") == R31_FAILED_PREPARATION_REASON
         and preparation.get("source_baseline") == R31_BASELINE_COMMIT
         and type(preparation.get("automatic_retries")) is int and preparation["automatic_retries"] == 0
         and type(preparation.get("cache_deletions")) is int and preparation["cache_deletions"] == 0
         and preparation.get("production_services_modified") is False
         and all(key not in preparation for key in ("qualification_command", "qualification_returncode",
             "source_before_qualification", "cache_transferred_by_rename")),
         "original R31 attempt was not the preserved failure before cache transfer/qualification")



def verify_r31_candidate_documents(preparation, terminal, job_id, qualified, tests,
                                   audit, build_inputs, baseline, source_map):
    """Check the R24 ablation and the qualifier's pre/post-format custody."""
    verify_r31_terminal(terminal, job_id)
    need(preparation["schema"] == "hepta-x230-r31-preparation/v2"
         and preparation.get("passed") is True and preparation.get("finished_utc")
         and "error" not in preparation
         and type(preparation.get("qualification_returncode")) is int
         and preparation["qualification_returncode"] == 0
         and type(preparation.get("automatic_retries")) is int and preparation["automatic_retries"] == 0
         and preparation.get("production_services_modified") is False
         and preparation.get("source_baseline") == R31_BASELINE_COMMIT
         and preparation.get("proposal") == "R24 plus pidfd cancellation readiness wait only",
         "actual R31 preparation did not close successfully for the selected ablation")
    recovery = verify_r31_preparation_recovery(preparation)
    expected_command = ["/usr/bin/python3", "-B", "-u", str(SOURCE / "tools/x230/20261028/qualify.py"),
        "--source", str(SOURCE), "--output", str(CANDIDATE_DIR), "--target", str(ROOT / "target-build"),
        "--cargo-home", "/home/qian/hepta-runtime-optimization-20261023/cargo-home-a32-a33-r02", "--jobs", "2"]
    need(preparation["qualification_command"] == expected_command,
         "the original eight-gate qualifier command differs")
    prior = preparation.get("prior_measurement_terminal", {})
    need(type(preparation.get("cache_deletions")) is int and preparation["cache_deletions"] == 0
         and preparation.get("cache_transferred_by_rename") is True
         and preparation.get("new_full_cache_copy_bytes") == 0
         and preparation.get("cache_to_transfer") == str(R31_CACHE_OWNER / "target-build")
         and preparation.get("free_bytes_before", -1) >= 3 * 1024 ** 3
         and prior.get("passed") is False and prior.get("controllers_closed") is True
         and prior.get("observation_report_sha256") == R31_PRIOR_OBSERVATION_SHA
         and isinstance(prior.get("campaign_report_sha256"), str)
         and HEX.fullmatch(prior["campaign_report_sha256"]),
         "R31 must reuse only the completed R30 cache by rename, with no cache deletion")
    need(build_inputs["baseline_commit"] == R31_BASELINE_COMMIT
         and isinstance(build_inputs.get("git_parent"), str)
         and re.fullmatch(r"[0-9a-f]{40}", build_inputs["git_parent"])
         and HEX.fullmatch(build_inputs["patch_sha256"]), "R31 source input receipt differs")
    before = build_inputs["baseline_compile_inputs"]
    candidate = build_inputs["candidate_compile_inputs"]
    need(isinstance(before, dict) and before and isinstance(candidate, dict)
         and set(candidate) == set(before) | R31_ADDED_PATHS
         and all(isinstance(value, str) and HEX.fullmatch(value) for value in before.values())
         and all(isinstance(value, str) and HEX.fullmatch(value) for value in candidate.values())
         and {name for name in candidate if before.get(name) != candidate[name]}
         == set(build_inputs["changed_paths"]) == R31_CHANGED_PATHS,
         "R31 must change only the selected pidfd wait source and tests from R24")
    need(baseline["schema"] == "hepta-x230-composed-qualification/v1"
         and baseline.get("qualified") is True and baseline.get("finished_utc")
         and baseline["source"] == str(BASELINE_ROOT / "source")
         and baseline["source_tested"] == baseline["source_after"] == before,
         "R31 input preimage is not the actual accepted R24 qualification")
    need(qualified["schema"] == "hepta-x230-composed-qualification/v1"
         and qualified.get("qualified") is True and qualified.get("finished_utc")
         and "error" not in qualified and qualified["source"] == str(SOURCE)
         and type(qualified["jobs"]) is int and qualified["jobs"] == 2
         and type(qualified["automatic_test_retries"]) is int and qualified["automatic_test_retries"] == 0
         and qualified["service_changes"] is False,
         "actual R31 composed qualification is incomplete or used another configuration")
    stages = qualified["stages"]
    need([row["name"] for row in stages] == R31_QUALIFICATION_STAGES
         and all(type(row.get("returncode")) is int and row["returncode"] == 0
                 and isinstance(row.get("command"), list) and row["command"]
                 and HEX.fullmatch(row["stdout_sha256"]) and HEX.fullmatch(row["stderr_sha256"])
                 for row in stages), "all eight original R31 qualification stages must pass once")
    need(preparation["source_before_qualification"] == candidate == qualified["source_input"],
         "R31 pre-format compilation inputs differ from the reviewed patch input")
    final_map = qualified["source_after"]
    need(preparation["source_after_qualification"] == qualified["source_tested"] == final_map == source_map
         and set(final_map) == set(before) | R31_ADDED_PATHS
         and {name for name in final_map if final_map[name] != before.get(name)} == R31_CHANGED_PATHS,
         "R31 final tested source does not preserve the three-file R24 pidfd ablation")
    need(qualified["harness_before"] == qualified["harness_after"]
         == baseline["harness_before"] == baseline["harness_after"]
         and qualified["harness_after"].get("qualify.py")
         == "95717717fd5421f2e31dbce24e2f8821696f57d779ce93e988ed66764159552d",
         "the original qualification harness differs from accepted R24")
    need(set(qualified["binaries"]) == set(BINARY_NAMES)
         and all(row["path"] == str(CANDIDATE_DIR / name) and HEX.fullmatch(row["sha256"])
                 for name, row in qualified["binaries"].items()), "qualification runtime copy identities differ")
    need(tests["schema"] == "hepta-isolated-libtest/v1" and tests.get("success") is True
         and tests.get("filter") == "" and type(tests.get("retries")) is int
         and tests["retries"] == 0 and tests.get("failed") == 0
         and tests.get("enumeration_errors") == [] and not tests.get("fatal_error"),
         "the complete original isolated test inventory did not pass without retry")
    counts = {name: tests[name] for name in ("passed", "failed", "ignored", "selected")}
    need(all(type(value) is int and value >= 0 for value in counts.values())
         and counts["passed"] > 0
         and counts["selected"] == counts["passed"] + counts["failed"] + counts["ignored"],
         "isolated inventory counts do not reconcile")
    need(audit["schema"] == "hepta-isolated-libtest-audit/v1" and audit.get("success") is True
         and audit.get("expected_filter") == "" and audit.get("errors") == [] and not audit.get("fatal_error")
         and audit.get("evidence") == str(CANDIDATE_DIR / "isolated-tests")
         and audit["auditor_sha256"] == qualified["harness_after"]["audit_isolated_tests.py"]
         and all(audit[name] == value for name, value in counts.items())
         and audit["executed"] == counts["passed"] + counts["failed"],
         "original independent isolated test audit does not match the full successful inventory")
    need(audit["binaries"] and all(row["recorded_before_sha256"] == row["current_after_sha256"]
         and HEX.fullmatch(row["current_after_sha256"]) for row in audit["binaries"]),
         "the original test auditor did not verify test executable custody")
    return {"passed": True, "original_job_id": job_id, "preparation_recovery": recovery,
        "selected_proposal": "pidfd cancellation readiness wait on accepted R24",
        "source_baseline_commit": R31_BASELINE_COMMIT,
        "qualified_source_files": len(final_map), "harness_files": len(qualified["harness_after"]),
        "changed_paths": sorted(R31_CHANGED_PATHS), "stages": R31_QUALIFICATION_STAGES,
        "tests": dict(counts, retries=0), "candidate_adopted": False,
        "adoption_scope": R31_ADOPTION_SCOPE, "saturated_cancellation_verified": False,
        "open_blockers": R31_OPEN_BLOCKERS}


# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Read-only binding of the original zero-stage R31 preflight failure.

The original parent is loaded from hash-checked retained bytes only to reuse its
pure completed-monitor verifier with its original tools-01 paths. Its main,
monitor start, quiescence, and workload entry points are never called here.
"""
R31_FAILED_CAMPAIGN_JOB = "1a1ae37dda9-fc05-5e42"
R31_FAILED_CAMPAIGN_FILES = {
    "report": {"path": str(ROOT / "campaign-01/report.json"), "bytes": 44604,
        "sha256": "8fb90cf4358b210942343c9da76f40d3c3fe61d751c8c68ab00d65110abc46df"},
    "inputs": {"path": str(ROOT / "campaign-inputs-01.json"), "bytes": 15870,
        "sha256": "d9b18804f1e0ced459ef59af53d3245f24bf8bf416b74a9790d9a9280593bfe2"},
    "parent": {"path": str(ROOT / "tools-01/r31_campaign.py"), "bytes": 71126,
        "sha256": "26b9aa885e049074c2170026ce3bbc9d8a5c2ffed6726899b74f836f9a977e93"},
    "native_terminal": {"path": str(ROOT / "observation-holder-native-01.json"), "bytes": 727,
        "sha256": "33b1f440fa260db903c66d8c4472a19abc0a86d07ec9dfde883a4f481b253e96"},
}


def verify_r31_failed_campaign_documents(report, terminal):
    verify_r31_terminal(terminal, R31_FAILED_CAMPAIGN_JOB, "failed", 1)
    need(report.get("schema") == "hepta-r25-observation-campaign-control/v1"
         and report.get("attempt") == "01" and report.get("candidate_release") == "R31"
         and report.get("passed") is False and report.get("observation_gate_passed") is False
         and report.get("stages") == [] and report.get("started_utc") and report.get("finished_utc")
         and report.get("error") == {"type": "RuntimeError", "reason": "private socket directory already exists"}
         and not any(key in report for key in ("stage_plan", "quiescence", "summary", "correctness_stages_completed"))
         and report.get("automatic_retries") == 0 and report.get("production_services_modified") is False
         and all(report.get(key) is True for key in ("inputs_unchanged", "source_inputs_unchanged",
             "baseline_source_inputs_unchanged", "baseline_enablement_verified", "measurement_attribution_valid"))
         and report.get("input_receipt") == R31_FAILED_CAMPAIGN_FILES["inputs"]
         and report.get("launcher_sha256") == R31_FAILED_CAMPAIGN_FILES["parent"]["sha256"],
         "original R31 failure was not the closed, unchanged zero-stage socket preflight")
    need(report["candidate_preparation_gate"]["passed"] is True
         and report["candidate_preparation_gate"]["original_job_id"] == "1a1ae1c32b8-fc05-5d7a",
         "the failed preflight must retain the original successful R31 qualification")


def bind_r31_prior_campaign_failure(inputs, bind):
    need(inputs.get("attempt") == "02", "only the separately named corrected R31 campaign is authorized")
    identities, raw = {}, {}
    for name, pin in R31_FAILED_CAMPAIGN_FILES.items():
        identities[name], raw[name] = bind(pin["path"], pin, retain=True)
    report, terminal, prior = (json.loads(raw[name]) for name in ("report", "native_terminal", "inputs"))
    verify_r31_failed_campaign_documents(report, terminal)
    need(prior.get("attempt") == "01" and prior.get("candidate_release") == "R31"
         and prior["launcher_sha256"] == identities["parent"]["sha256"],
         "the retained failed input is not the original R31 parent attempt")
    for key in ("qualification_launcher", "qualification_input", "candidate_patch",
                "qualification_preparation", "qualification_terminal_status"):
        need(inputs[key] == prior[key], "R31 qualification changed after the failed preflight: " + key)
    reports = inputs.get("qualification_reports", [inputs.get("qualification_report")])
    need(len(reports) == 1 and all(reports[0][key] == prior["qualification_reports"][0][key]
         for key in ("path", "bytes", "sha256")), "corrected campaign must use the same qualified candidate")
    if "baseline" in inputs:
        need(inputs["baseline"] == prior["baseline"], "accepted R24 baseline changed after the failed preflight")
    for key in ("source_inputs", "baseline_source_inputs"):
        expected = report[key]
        need(expected["path"] == str(ROOT / "campaign-01" / (key.replace("_", "-") + ".json")),
             "original preflight source snapshot path differs")
        bind(expected["path"], expected)
    # A failed namespace check precedes all stage directory creation. Retain that
    # fact without deleting, renaming, touching, or adopting any R30 socket path.
    for path in (ROOT / "campaign-01/native-observation", ROOT / "campaign-01/native-boundary",
                 R16 / "r31-cancel-recovery-01"):
        need(not os.path.lexists(path), "original R31 preflight has unexpected workload output")
    original = monitor_module("_r31_original_parent_01_for_receipt_audit", raw["parent"],
                              Path(identities["parent"]["path"]))
    monitor = original.verify_completed_compiler_monitor(report, prior, bind, ROOT / "campaign-01")
    return {"schema": "hepta-r31-campaign-preflight-recovery/v1", "passed": True,
        "original_job_id": R31_FAILED_CAMPAIGN_JOB, "original_files": identities,
        "original_error": report["error"], "original_stages_started": 0,
        "original_quiescence_started": False, "original_monitor_gate": monitor,
        "corrected_attempt": "02", "automatic_retries": 0,
        "correction": "fresh h31 socket namespace and separately named campaign/input/tool/output paths",
        "candidate_source_recompiled": False, "candidate_adopted": False,
        "original_performance_result_available": False,
        "holder_native_scope": "original failed holder job terminal and complete persisted stdout/stderr accounting"}



def bind_r31_candidate_preparation(inputs, bind):
    """Bind actual R31 documents with the parent's stable file reader."""
    def document(path, expected=None):
        identity, raw = bind(path, expected, retain=True)
        return identity, json.loads(raw)

    fixed = {"qualification_launcher": ROOT / "prepare_qualify_v2.py",
             "qualification_input": ROOT / "input.json",
             "candidate_patch": ROOT / "candidate.patch"}
    for name, path in fixed.items():
        need(inputs[name]["path"] == str(path), "R31 qualification input path differs: " + name)
    launcher_id = bind(fixed["qualification_launcher"], inputs["qualification_launcher"])
    input_id, build_inputs = document(fixed["qualification_input"], inputs["qualification_input"])
    patch_id = bind(fixed["candidate_patch"], inputs["candidate_patch"])
    need(patch_id["sha256"] == build_inputs["patch_sha256"], "reviewed R31 patch bytes differ")
    preparation_pin, terminal_pin = inputs["qualification_preparation"], inputs["qualification_terminal_status"]
    reports = inputs.get("qualification_reports", [inputs.get("qualification_report")])
    need(preparation_pin["path"] == str(ROOT / "preparation-02.json")
         and terminal_pin["path"] == str(ROOT / "qualification-terminal-status-01.json")
         and len(reports) == 1 and reports[0]["path"] == str(CANDIDATE_DIR / "report.json"),
         "qualification receipts must identify the fresh R31 attempt")
    prep_id, preparation = document(preparation_pin["path"], preparation_pin)
    terminal_id, terminal = document(terminal_pin["path"], terminal_pin)
    qualified_id, qualified = document(reports[0]["path"], reports[0])
    baseline_id, baseline = document(R31_BASELINE_QUALIFICATION["path"], R31_BASELINE_QUALIFICATION)
    source_map_id, source_map = document(CANDIDATE_DIR / "source-map.json")
    test_id, tests = document(CANDIDATE_DIR / "isolated-tests/summary.json")
    audit_id, audit = document(CANDIDATE_DIR / "isolated-tests.audit.json")
    proof = verify_r31_candidate_documents(preparation, terminal, terminal_pin["job_id"], qualified,
        tests, audit, build_inputs, baseline, source_map)
    failed_id, failed_preparation = document(ROOT / "preparation.json", R31_FAILED_PREPARATION_SHA)
    failed_terminal_id, failed_terminal = document(ROOT / "preparation-attempt-01-native.json",
        preparation["prior_preparation_failure"]["native_sha256"])
    verify_r31_failed_preparation(failed_preparation, failed_terminal)
    proof["failed_preparation_attempt_01"] = {"preparation": failed_id, "native_terminal": failed_terminal_id,
        "job_id": R31_FAILED_PREPARATION_JOB, "qualification_started": False, "cache_transferred": False}
    proof["prior_campaign_preflight_failure"] = bind_r31_prior_campaign_failure(inputs, bind)
    current = source_inputs(SOURCE)
    need(qualification_projection(current) == source_map, "current R31 source differs from the actually tested source map")
    baseline_current = source_inputs(BASELINE_ROOT / "source")
    need(set(current["files"]) == set(baseline_current["files"]) | R31_ADDED_PATHS
         and {name for name in current["files"] if current["files"][name] != baseline_current["files"].get(name)}
         == R31_CHANGED_PATHS,
         "R31 changed additional build/config/source inputs outside the selected pidfd wait files")
    harness = SOURCE / "tools/x230/20261028"
    need({path.name for path in harness.glob("*.py")} == set(qualified["harness_after"]),
         "the qualified Python harness file set changed")
    for name, expected_sha in qualified["harness_after"].items():
        need(Path(name).name == name, "unsafe qualification harness member")
        bind(harness / name, expected_sha)
    for stage in qualified["stages"]:
        name = stage["name"]
        bind(CANDIDATE_DIR / ("cargo-no-run.jsonl" if name == "test-build" else name + ".stdout"), stage["stdout_sha256"])
        bind(CANDIDATE_DIR / (name + ".stderr"), stage["stderr_sha256"])
    isolated_inputs = {"summary.json", "cargo-artifacts.jsonl", "source-manifest.input", "commands.jsonl", "tests.jsonl"}
    need(set(audit["input_sha256"]) == isolated_inputs,
         "original independent test audit is missing input identities")
    for name, expected_sha in audit["input_sha256"].items():
        bind(CANDIDATE_DIR / "isolated-tests" / name, expected_sha)
    need(audit["input_sha256"]["summary.json"] == test_id["sha256"]
         and audit["input_sha256"]["source-manifest.input"] == source_map_id["sha256"]
         == tests["source_manifest_sha256"], "the isolated test inventory binds another source manifest")
    prior_qualified_id, prior_qualified = document(R31_CACHE_OWNER / "qualification-01/report.json", R31_PRIOR_QUALIFICATION_SHA)
    prior_terminal_id, prior_terminal = document(R31_CACHE_OWNER / "qualification-terminal-status-01.json", R31_PRIOR_TERMINAL_SHA)
    verify_r31_terminal(prior_terminal, "1a1ade0d4f4-fc05-5b52")
    need(prior_qualified.get("qualified") is True, "previous cache owner qualification did not close")
    previous = preparation["prior_measurement_terminal"]
    prior_parent_id, prior_parent = document(R31_CACHE_OWNER / "campaign-01/report.json", previous["campaign_report_sha256"])
    prior_native_id, prior_native = document(R31_CACHE_OWNER / "campaign-01/native-observation/report.json", R31_PRIOR_OBSERVATION_SHA)
    need(prior_parent.get("finished_utc") and prior_parent.get("passed") is False
         and prior_native.get("finished_unix") and prior_native.get("passed") is False
         and len(prior_native["rounds"]) == 4, "original failed R30 measurement has not closed")
    for row in prior_native["rounds"]:
        for label in ("shutdown", "restart_shutdown"):
            closed = row[label]
            need(closed["exit_code"] == 0 and closed["shutdown_method"] == "stdin_eof"
                 and not closed["observed_descendant_survivors"] and closed["reader_error"] is None
                 and closed["transport_capture"]["reader_eof"] is True
                 and closed["unmatched_responses"] == 0, "an original R30 controller did not close")
    proof["previous_cache_owner_evidence"] = {"qualification": prior_qualified_id, "native_terminal": prior_terminal_id,
        "failed_campaign": prior_parent_id, "failed_native_observation": prior_native_id,
        "cache_deletions": 0, "previous_candidate_adopted": False}
    proof.update(preparation=prep_id, terminal=terminal_id, qualification=qualified_id,
        qualification_launcher=launcher_id, qualification_input=input_id, candidate_patch=patch_id,
        baseline_qualification=baseline_id, isolated_summary=test_id, isolated_audit=audit_id,
        source_map=source_map_id, full_source_inputs_sha256=current["sha256"],
        baseline_full_source_inputs_sha256=baseline_current["sha256"],
        original_auditor_scope="the unchanged qualifier audited the complete inventory and compressed case logs")
    return proof


def commands(out, attempt, baseline_runtime, baseline_sha, candidate_sha):
    shared = ["--profile-template", str(PROFILE), "--topology", str(TOPOLOGY), "--frozen-jobs", str(FROZEN_JOBS)]
    native, boundary = out / "native-observation", out / "native-boundary"
    # The unchanged original canary deliberately restricts its output parent to
    # R16. A fresh R31-labelled sibling preserves that guard and every old file.
    lifecycle = R16 / ("r31-cancel-recovery-" + attempt)
    sockets = {name: Path("/home/qian") / ("h31" + prefix + attempt)
               for name, prefix in (("native", "n"), ("boundary", "b"), ("lifecycle", "c"))}
    py = ["/usr/bin/python3", "-B"]
    rows = [
        ("native-observation", py + [str(TOOLS / "run_native_observation.py"), "--baseline", str(baseline_runtime),
         "--candidate", str(CANDIDATE), "--arena-max", "1", *shared, "--socket-parent", str(sockets["native"]),
         "--out", str(native), "--calls", "192", "--concurrency", "1", "8", "16", "--workers", "2",
         "--order", "ABBA", "--warmup-calls", "24"], 1800, [native / "report.json"]),
        ("native-audit", py + [str(TOOLS / "analyze_native_observation.py"), "--report", str(native / "report.json"),
         "--output", str(native / "independent-summary.json")], 180, [native / "independent-summary.json"]),
        ("native-boundary", py + [str(BOUNDARY_TOOLS / "run_native_boundary.py"), "--binary", str(CANDIDATE), *shared,
         "--socket-parent", str(sockets["boundary"]), "--out", str(boundary), "--bursts", "2", "--harness-root", str(TOOLS)],
         600, [boundary / "report.json"]),
        ("boundary-audit", py + [str(BOUNDARY_TOOLS / "audit_native_boundary.py"), "--report", str(boundary / "report.json"),
         "--output", str(boundary / "independent-summary.json"), "--harness-root", str(TOOLS)], 180, [boundary / "independent-summary.json"]),
        ("cancel-recovery", py + [str(TOOLS / "run_six_host_cancel_recovery.py"), "--candidate", str(CANDIDATE), *shared,
         "--socket-parent", str(sockets["lifecycle"]), "--out", str(lifecycle), "--workers", "2",
         "--candidate-arena-max", "1", "--interrupt-host", "rog"], 600, [lifecycle / "report.json"]),
        ("recovery-audit", py + [str(TOOLS / "verify_cancel_recovery.py"), "--report", str(lifecycle / "report.json"),
         "--output", str(lifecycle / "independent-summary.json")], 180, [lifecycle / "independent-summary.json"]),
        ("observation-summary", py + [str(SUMMARY), "--native-report", str(native / "report.json"),
         "--native-analysis", str(native / "independent-summary.json"), "--boundary-report", str(boundary / "report.json"),
         "--boundary-analysis", str(boundary / "independent-summary.json"), "--lifecycle-report", str(lifecycle / "report.json"),
         "--lifecycle-analysis", str(lifecycle / "independent-summary.json"), "--expected-baseline-sha256", baseline_sha,
         "--expected-candidate-sha256", candidate_sha, "--output", str(out / "summary.json")], 180, [out / "summary.json"]),
    ]
    return [{"name": name, "argv": argv, "timeout_seconds": timeout, "outputs": [str(path) for path in outputs]}
            for name, argv, timeout, outputs in rows], sockets, lifecycle


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--launcher-sha256", required=True, help="SHA receipt supplied by the unchanged Mac holder")
    parser.add_argument("--inputs", type=Path, default=ROOT / "campaign-inputs-02.json")
    args = parser.parse_args()
    need(sys.platform == "linux" and os.geteuid() != 0 and HEX.fullmatch(args.launcher_sha256), "Linux operator and holder receipt required")
    need(args.inputs.is_relative_to(ROOT), "input receipt must be within R31")
    input_identity, input_raw = checked(args.inputs, maximum=262144, retain=True)
    inputs = json.loads(input_raw)
    need(inputs["schema"] == "hepta-r25-campaign-inputs/v1" and inputs["launcher_sha256"] == args.launcher_sha256
         and inputs["attempt"] == "02", "input schema, attempt or holder binding differs")
    attempt = inputs["attempt"]
    out = ROOT / ("campaign-" + attempt)
    private_directory(out, create_new=True)
    create(out / "inputs.json", input_raw)
    report_path = out / "report.json"
    deadline = time.monotonic() + CAMPAIGN_SECONDS
    report = {"schema": "hepta-r25-observation-campaign-control/v1", "attempt": attempt, "passed": False, "observation_gate_passed": False,
              "started_utc": utc(), "launcher_sha256": args.launcher_sha256,
              "launcher_identity_origin": "Mac holder hashes the transmitted stdin bytes; this is not a remote self-hash",
              "input_receipt": input_identity, "stages": [], "automatic_retries": 0, "production_services_modified": False,
              "input_bindings": [], "campaign_budget_seconds": CAMPAIGN_SECONDS, "recommended_holder_timeout_seconds": 3600,
              "lifecycle_scope": "one unchanged candidate C6 canary; six fresh bounded fixtures; no lifecycle performance ABBA claim",
              "final_candidate_adoption_requires": ["normal lifecycle ABBA nonregression", "qualified source", "complete resource evidence"],
              "adoption_scope": R31_ADOPTION_SCOPE, "saturated_cancellation_verified": False,
              "open_blockers": R31_OPEN_BLOCKERS,
              "thresholds": None, "inputs_unchanged": False, "source_inputs_unchanged": False,
              "baseline_source_inputs_unchanged": False, "baseline_enablement_verified": False}
    candidate_source = baseline_source = baseline_source_path = None
    bench = None
    agent_identity = None
    compiler_monitor = monitor_validator = monitor_proof = None
    monitored_body_start = None
    agent = os.environ.get("SSH_AUTH_SOCK", "")

    def checkpoint():
        save(report_path, report)

    def bind(path, expected=None, maximum=128 * 1024 * 1024, retain=False):
        result = checked(path, expected, maximum, retain)
        identity = result[0] if retain else result
        report["input_bindings"].append(identity)
        return result

    def qualifications(items, root, source, binaries):
        need(isinstance(items, list) and items, "qualified success receipt is required before workload")
        composed = []
        for item in items:
            path = Path(item["path"])
            field = item.get("success_field", "qualified")
            need(path.is_relative_to(root) and field in ("passed", "verified", "accepted", "qualified", "success"),
                 "unsupported qualification success binding")
            _, raw = bind(path, item, retain=True)
            value = json.loads(raw)
            need(value.get(field) is True, "qualification receipt does not report success: " + str(path))
            if field == "qualified":
                verify_composed_qualification(value, source, binaries)
                composed.append(value)
        need(composed, "the actual qualified:true composed report is required for each arm")
        return composed

    def unchanged():
        need(checked(args.inputs) == input_identity, "campaign input receipt changed")
        for identity in report["input_bindings"]:
            need(checked(identity["path"], identity) == identity, "campaign input changed")
        need(bench.agent_identity(agent) == agent_identity, "held SSH agent identity changed between stages")

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
        compiler_monitor, monitor_validator, monitor_proof = prepare_compiler_monitor(inputs, bind)
        monitor_ready = compiler_monitor.start()
        monitored_body_start = time.monotonic_ns()
        need(monitor_ready, "initial compiler monitor sample failed; no workload submitted")
        report["compiler_monitor_scope"] = COMPILER_MONITOR_POLICY["guarded_interval"]
        report["machine_initial"] = machine_snapshot()
        report["candidate_release"] = "R31"
        report["candidate_preparation_gate"] = bind_r31_candidate_preparation(inputs, bind)
        baseline = inputs["baseline"]
        need(isinstance(baseline, dict) and set(baseline["binaries"]) == set(BINARY_NAMES)
             and set(inputs["candidate_binaries"]) == set(BINARY_NAMES), "three explicit qualified artifacts per arm required")
        baseline_source_path = Path(baseline["source"])
        need(baseline_source_path.is_relative_to(BASELINE_ROOT), "baseline source must be the actual R24 source")
        report["binaries"] = {"A": {}, "B": {}}
        for name in BINARY_NAMES:
            pin = baseline["binaries"][name]
            path = Path(pin["path"])
            need(path.is_relative_to(BASELINE_ROOT) and path.name == name, "explicit R24 baseline artifact path differs")
            report["binaries"]["A"][name] = bind(path, pin)
            report["binaries"]["B"][name] = bind(CANDIDATE_DIR / name, inputs["candidate_binaries"][name])
            need(os.access(path, os.X_OK) and os.access(CANDIDATE_DIR / name, os.X_OK), "qualification copy is not executable")
        baseline_qualifications = qualifications(baseline["qualification_reports"], BASELINE_ROOT,
                                                 baseline_source_path, report["binaries"]["A"])
        candidate_qualifications = qualifications(inputs["qualification_reports"], ROOT, SOURCE, report["binaries"]["B"])
        prior = {}
        for label in ("campaign_report", "publication_readback"):
            item = baseline[label]
            path = Path(item["path"])
            need(path.is_relative_to(BASELINE_ROOT), "R24 enablement evidence must remain within R24")
            identity, raw = bind(path, item, retain=True)
            prior[label] = json.loads(raw)
            report["baseline_" + label] = identity
        verify_baseline_enablement(prior["campaign_report"], prior["publication_readback"],
                                   report["binaries"]["A"], baseline["publication_readback"]["commit"],
                                   report["baseline_campaign_report"]["sha256"])
        summary_binding = prior["campaign_report"]["summary"]
        need(Path(summary_binding["path"]).is_relative_to(BASELINE_ROOT), "R24 summary path differs")
        _, adopted_summary_raw = bind(summary_binding["path"], summary_binding, retain=True)
        adopted_summary = json.loads(adopted_summary_raw)
        need(adopted_summary["schema"] == "hepta-r24-campaign-gates/v1" and adopted_summary["evidence_verified"] is True
             and adopted_summary["correctness_verified"] is True and adopted_summary["adoption_gate_passed"] is True
             and adopted_summary["binary_sha256"]["B"] == report["binaries"]["A"]["hepta-runtime"]["sha256"],
             "R24 adoption summary does not bind this actual baseline")
        report["baseline_enablement_verified"] = True
        report["baseline_publication_commit"] = prior["publication_readback"]["commit"]
        bind(PROFILE, PROFILE_SHA)
        bind(TOPOLOGY, TOPOLOGY_SHA)
        for name, expected in HARNESS_FILES.items():
            bind(TOOLS / name, expected, maximum=262144)
        if not BOUNDARY_TOOLS.exists():
            private_directory(BOUNDARY_TOOLS, create_new=True)
            for name, expected in BOUNDARY_FILES.items():
                _, raw = bind(BOUNDARY_ORIGINAL / name, expected, maximum=262144, retain=True)
                create(BOUNDARY_TOOLS / name, raw)
        private_directory(BOUNDARY_TOOLS)
        for name, expected in BOUNDARY_FILES.items():
            bind(BOUNDARY_TOOLS / name, expected, maximum=262144)
        _, summary_raw = bind(SUMMARY, inputs["summary_sha256"], maximum=262144, retain=True)
        assignments = [node for node in ast.parse(summary_raw).body if isinstance(node, ast.Assign)
                       and any(isinstance(target, ast.Name) and target.id == "GATES" for target in node.targets)]
        need(len(assignments) == 1, "summary gate declaration missing")
        gates = ast.literal_eval(assignments[0].value)
        need(gates["all_concurrency"] == [1, 8, 16] and gates["throughput_b_over_a_min"] == 0.95
             and gates["p95_b_over_a_max"] == 1.10 and gates["primary_concurrency"] == 8
             and gates["controller_cpu_b_over_a_max"] == 1.10
             and gates["controller_rss_extra_kib_max"] == 512 and gates["controller_rss_b_over_a_max"] == 1.05
             and gates["ssh_cache_target"] == "/usr/bin/ssh" and gates["ssh_cache_target_bytes"] == 846888
             and gates["ssh_cache_hard_cap_bytes"] == 2097152, "summary thresholds differ from the preregistered protocol")
        report["thresholds"] = gates
        ssh = bind(Path("/usr/bin/ssh"))
        need(ssh["bytes"] == gates["ssh_cache_target_bytes"] <= gates["ssh_cache_hard_cap_bytes"], "cache target input size changed")
        frozen = sorted(FROZEN_JOBS.glob("*.json"))
        need(len(frozen) == 6, "exactly six frozen originals required")
        hosts = set()
        for path in frozen:
            _, raw = bind(path, maximum=65536, retain=True)
            job = json.loads(raw)
            need(path.name == job["id"] + ".json" and job["launch_state"] == "launched"
                 and job["execution_mode"] == "operator" and job["system_jobctl"] is False, "frozen original identity differs")
            hosts.add(job["host"])
        need(hosts == HOSTS, "fixed six-host set differs")
        baseline_source, candidate_source = source_inputs(baseline_source_path), source_inputs(SOURCE)
        need(all(value["source_after"] == qualification_projection(baseline_source) for value in baseline_qualifications)
             and all(value["source_after"] == qualification_projection(candidate_source) for value in candidate_qualifications),
             "current source inputs differ from their actually qualified source maps")
        need(baseline_source["sha256"] == prior["campaign_report"]["source_inputs_sha256"],
             "R24 source inputs differ from the adopted campaign")
        report["qualified_source_maps_match_current_inputs"] = {"A": True, "B": True}
        if inputs.get("source_inputs_sha256") is not None:
            need(candidate_source["sha256"] == inputs["source_inputs_sha256"], "qualified R31 source input snapshot differs")
        create(out / "source-inputs.json", canonical(candidate_source))
        create(out / "baseline-source-inputs.json", canonical(baseline_source))
        report["source_inputs"] = checked(out / "source-inputs.json")
        report["source_inputs_sha256"] = candidate_source["sha256"]
        report["baseline_source_inputs"] = checked(out / "baseline-source-inputs.json")
        report["baseline_source_inputs_sha256"] = baseline_source["sha256"]
        need(agent.startswith("/"), "current forwarded SSH agent required")
        sys.path.insert(0, str(TOOLS))
        bench = importlib.import_module("x230_observation_benchmark")
        need(Path(bench.__file__).resolve() == TOOLS / "x230_observation_benchmark.py", "another harness module was imported")
        agent_identity = bench.agent_identity(agent)
        report["agent_identity"] = agent_identity
        plan, sockets, lifecycle = commands(out, attempt, report["binaries"]["A"]["hepta-runtime"]["path"],
                                           report["binaries"]["A"]["hepta-runtime"]["sha256"],
                                           report["binaries"]["B"]["hepta-runtime"]["sha256"])
        need(not os.path.lexists(lifecycle) and lifecycle.resolve() == lifecycle, "fresh original-canary output required")
        for path in sockets.values():
            need(not os.path.lexists(path) and path.resolve() == path, "private socket directory already exists")
        report["stage_plan"] = plan
        report["lifecycle_raw_directory"] = str(lifecycle)
        report["socket_directories"] = {key: str(path) for key, path in sockets.items()}
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
        workload_sockets = {"native-observation": sockets["native"], "native-boundary": sockets["boundary"], "cancel-recovery": sockets["lifecycle"]}
        for spec in plan:
            unchanged()
            need(not compiler_activity(), "compiler activity overlaps a campaign stage")
            if spec["name"] in workload_sockets:
                private_directory(workload_sockets[spec["name"]], create_new=True)
            run_stage(spec)
        unchanged()
        report["inputs_unchanged"] = True
        report["source_inputs_unchanged"] = source_inputs(SOURCE) == candidate_source
        report["baseline_source_inputs_unchanged"] = source_inputs(baseline_source_path) == baseline_source
        need(report["source_inputs_unchanged"] and report["baseline_source_inputs_unchanged"], "qualified source changed during the campaign")
        summary_identity, summary_raw = checked(out / "summary.json", retain=True)
        summary = json.loads(summary_raw)
        need(summary["evidence_verified"] is True and summary["correctness_verified"] is True
             and summary["thresholds"] == report["thresholds"], "summary identity or protocol differs")
        report.update(passed=True, summary=summary_identity, observation_gate_passed=summary["observation_gate_passed"],
                      rejection_reasons=summary["rejection_reasons"], correctness_stages_completed=True)
    except BaseException as error:
        report["error"] = {"type": type(error).__name__, "reason": str(error)[:4000]}
        report["passed"] = report["observation_gate_passed"] = False
        report["uncertain_effects_are_not_retried"] = True
        create(out / "campaign.error.txt", traceback.format_exc().encode())
    finally:
        if bench is not None and agent_identity is not None:
            try:
                unchanged()
                report["inputs_unchanged"] = True
            except BaseException as error:
                report["input_finalization_error"] = {"type": type(error).__name__, "reason": str(error)[:3000]}
                report["passed"] = report["observation_gate_passed"] = False
                report["inputs_unchanged"] = False
        if candidate_source is not None:
            try:
                report["source_inputs_unchanged"] = source_inputs(SOURCE) == candidate_source
                if not report["source_inputs_unchanged"]:
                    report["passed"] = report["observation_gate_passed"] = False
            except BaseException as error:
                report["source_finalization_error"] = {"type": type(error).__name__, "reason": str(error)[:3000]}
                report["passed"] = report["observation_gate_passed"] = False
                report["source_inputs_unchanged"] = False
        if baseline_source is not None:
            try:
                report["baseline_source_inputs_unchanged"] = source_inputs(baseline_source_path) == baseline_source
                if not report["baseline_source_inputs_unchanged"]:
                    report["passed"] = report["observation_gate_passed"] = False
            except BaseException as error:
                report["baseline_source_finalization_error"] = {"type": type(error).__name__, "reason": str(error)[:3000]}
                report["passed"] = report["observation_gate_passed"] = False
                report["baseline_source_inputs_unchanged"] = False
        monitored_body_end = time.monotonic_ns()
        finish_compiler_monitor(compiler_monitor, monitor_validator, monitor_proof,
            monitored_body_start, monitored_body_end, out, report, "observation_gate_passed")
        report["finished_utc"] = utc()
        report["machine_final"] = machine_snapshot()
        checkpoint()
        print(json.dumps({"passed": report["passed"], "observation_gate_passed": report["observation_gate_passed"],
                          "rejection_reasons": report.get("rejection_reasons"), "error": report.get("error"),
                          "report": str(report_path)}), flush=True)
    # A performance rejection is a completed, retained experiment, not a signal
    # to repeat it. Nonzero means incomplete/failed evidence, never an auto retry.
    return 0 if report["passed"] else 1


def interrupted(signum, _frame):
    raise RuntimeError("campaign interrupted by signal " + str(signum))


if __name__ == "__main__":
    os.umask(0o077)
    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, interrupted)
    raise SystemExit(main())

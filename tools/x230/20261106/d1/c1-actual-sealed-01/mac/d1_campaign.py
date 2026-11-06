#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Unsealed D1 C1 parent: original held-agent, quiet90, monitor and stage owner.

Only same-feature-ELF OFF/ON/ON/OFF C1 diagnostics and the unchanged native
auditor are scheduled. No boundary, lifecycle, capacity or adoption gate runs.
The unchanged Mac holder supplies --launcher-sha256 for the transmitted bytes.
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
ROOT = Path("/home/qian/hepta-runtime-phase-cost-20261106-d1")
BASELINE_ROOT = Path("/home/qian/hepta-runtime-optimization-20261105-r24")
SOURCE = ROOT / "source"
TOOLS = ROOT / "c1-tools-01"
REFERENCE = TOOLS / "reference"
CANDIDATE_DIR = ROOT / "qualification-01"
BINDER = TOOLS / "d1_prerequisites.py"
ADAPTER = TOOLS / "run_c1_phase_cost.py"
PREREQUISITES = ROOT / "c1-prerequisites-01.json"
ORDINARY_VERIFIER = ROOT / "ordinary-tools-02/verify_ordinary_02.py"
ORDINARY_INPUT = ROOT / "ordinary-verification-input-02.json"
ORDINARY_POSTFLIGHT = ROOT / "ordinary-postflight-02.json"
INPUTS = ROOT / "c1-campaign-inputs-01.json"
OUTPUT = ROOT / "c1-campaign-01"
NATIVE = ROOT / "c1-observation-01"
ADAPTER_OUTPUT = ROOT / "c1-adapter-evidence-01"
SOCKET_PARENT = Path("/home/qian/hd1c01")
ACTUAL = {'sealed': True, 'prerequisites': {'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/c1-prerequisites-01.json', 'bytes': 5063, 'sha256': '9d5ca9b3d4e276d8f7b830cf028eac9eded76ab3b0f560758279451989c966cb'}, 'qualification_binder': {'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/c1-tools-01/d1_prerequisites.py', 'bytes': 58168, 'sha256': '623c8678fe2ed89dae7fb8cdf188e34e009e8d73fee10275f51b753fe3d41b98'}, 'ordinary': {'verifier': {'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/ordinary-tools-02/verify_ordinary_02.py', 'bytes': 27238, 'sha256': 'bcf8551a7523fb051a9987433fa0210303d575c540ae14341648e4d2afe6b7e3'}, 'verification_input': {'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/ordinary-verification-input-02.json', 'bytes': 2166, 'sha256': 'c3b66fe04ec09c54dfc1104cbf050f408dd68c72a24dbd0062a0c86607d57136'}, 'postflight': {'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/ordinary-postflight-02.json', 'bytes': 223078, 'sha256': 'db8a2cddf7e13b48ad9dbcf8ebdf03664dd604114acb7e36dafe176598b17ed5'}}, 'adapter': {'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/c1-tools-01/run_c1_phase_cost.py', 'bytes': 34274, 'sha256': '0902f5a9bf4c085172a61010deb54c74d7b89516fb9cfe1255722ad97b25dea9'}, 'adapter_spec': {'schema': 'hepta-d1-c1-phase-cost-input/v1', 'sealed': True, 'root': '/home/qian/hepta-runtime-phase-cost-20261106-d1', 'reference_directory': '/home/qian/hepta-runtime-phase-cost-20261106-d1/c1-tools-01/reference', 'qualified_feature_binary': {'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/qualification-01/hepta-runtime', 'bytes': 14456088, 'sha256': '1d6f38950eefe34891827b5e0f71cb7b388ddbbb2f3fc339c3a0325e27ef11ad'}, 'qualification_report': {'bytes': 83976, 'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/qualification-01/report.json', 'sha256': '0fd74793651afcf0b24f010d4371a04c422da8fd4711cb288da40cf4d69ee437'}, 'qualification_terminal': {'bytes': 731, 'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/qualification-terminal-status-01.json', 'sha256': 'c06e447a3adf5eb6f8afd0533e898a3f6417ce61d52e0a31b66f5277a991f303'}, 'qualified_source_map': {'bytes': 24368, 'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/qualification-01/source-map.json', 'sha256': '98824381ae2009e909fc28e07087d8646d3131229e146c04ecd9f58c60a14133'}, 'outer_input_manifest': {'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/c1-prerequisites-01.json', 'bytes': 5063, 'sha256': '9d5ca9b3d4e276d8f7b830cf028eac9eded76ab3b0f560758279451989c966cb'}, 'profile_template': {'path': '/home/qian/hepta-runtime-optimization-20261023/r11-native-observation-abba-20261103-02/profile/profile.json', 'bytes': 836, 'sha256': 'fe1e9551b5b8812ad6ed3da018c282b7261f7caeb2f49e4dcfefba7ff784ab08'}, 'topology': {'path': '/home/qian/hepta-runtime-optimization-20261104-r16/benchmark-topology.json', 'bytes': 796, 'sha256': '8c0767d3318131a7d470d9cde8e327a59ce18adf022c8bc1b1d5a0fa9a865287'}, 'frozen_jobs': [{'path': '/home/qian/hepta-runtime-optimization-20261023/a31-frozen-originals-r01/1a16a4035ad-b1270-1.json', 'bytes': 880, 'sha256': 'a8982325aea4833461e2b6a76ca83f846b80b99a227298e97a0b279e2d9dfdb8'}, {'path': '/home/qian/hepta-runtime-optimization-20261023/a31-frozen-originals-r01/1a16a403e55-b1270-2.json', 'bytes': 877, 'sha256': 'bbb8a86161837ff0f197b345c25bc66224e3404473dea2ac46d1f44f3af43609'}, {'path': '/home/qian/hepta-runtime-optimization-20261023/a31-frozen-originals-r01/1a16a4046ac-b1270-3.json', 'bytes': 881, 'sha256': '4badc323518a6db1567162a2d7ef5d1209aa88375aba201ec6f3aab34bec61a8'}, {'path': '/home/qian/hepta-runtime-optimization-20261023/a31-frozen-originals-r01/1a16a40534e-b1270-4.json', 'bytes': 890, 'sha256': '79e18b1a42d84f8024b692dfd98a9f06fa1d6886bf5dc230248cfbde674f011c'}, {'path': '/home/qian/hepta-runtime-optimization-20261023/a31-frozen-originals-r01/1a16a405d21-b1270-5.json', 'bytes': 877, 'sha256': '9c89c598f35f6bc94572852fcc03feed6e8c798ee34db5095bd3b48813562dc6'}, {'path': '/home/qian/hepta-runtime-optimization-20261023/a31-frozen-originals-r01/1a16a40671b-b1270-6.json', 'bytes': 878, 'sha256': '5b737330fa5a75a458138e1848a044d2a77c062175d8eb9694a510ff20b53cde'}], 'benchmark_output': '/home/qian/hepta-runtime-phase-cost-20261106-d1/c1-observation-01', 'evidence_output': '/home/qian/hepta-runtime-phase-cost-20261106-d1/c1-adapter-evidence-01', 'socket_parent': '/home/qian/hd1c01'}, 'compiler_monitor': {'module': {'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/c1-tools-01/compiler_monitor.py', 'bytes': 12510, 'sha256': 'afb514362a9d8dd573b806f0dc87df16bd3a906e4574d10d91bf483b2e76cdcf'}, 'reader': {'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/c1-tools-01/compiler_state.py', 'bytes': 6243, 'sha256': '9da718654db04a646e081d2d719a2d6d4655ffe337bc0e3f906e736e4d77a251'}, 'validator': {'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/c1-tools-01/validate_compiler_monitor.py', 'bytes': 7055, 'sha256': 'd2cd009adf1f35a394ffddcc8f8646cc0c1b856b78181ca321ea68f6468218b2'}, 'policy': {'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/c1-tools-01/compiler-monitor-policy-01.json', 'bytes': 1001, 'sha256': 'ddb2e03d4a1a1610466a5dc2d1a544f554ad12fc31412483101b48a235402368'}}}
HEX = re.compile(r"[0-9a-f]{64}\Z")
BINARY_NAMES = ("hepta-runtime", "hepta-runtime-jobctl", "native_process_driver")
DIAGNOSTIC_ENV = ("HEPTA_RUNTIME_PHASE_COST_MODE", "HEPTA_RUNTIME_PHASE_COST_OUTPUT",
                  "HEPTA_RUNTIME_PHASE_COST_ELF_SHA256")


QUIESCENCE_SECONDS = 90
CAMPAIGN_SECONDS = 3300  # Leave the 3600-second holder time for bounded cleanup.
COMPILER_MONITOR_PATHS = {
    "module": ROOT / "c1-tools-01/compiler_monitor.py",
    "reader": ROOT / "c1-tools-01/compiler_state.py",
    "validator": ROOT / "c1-tools-01/validate_compiler_monitor.py",
    "policy": ROOT / "c1-tools-01/compiler-monitor-policy-01.json",
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


STATIC_INPUTS = {
    "reference/run_native_observation.py": [
        3279,
        "7606648c99b2ff2bbf0bba58384e8cab609ac3899f838c0b80ba54d6288d20bb"
    ],
    "reference/x230_observation_benchmark.py": [
        37006,
        "4d96f0bf2da2562e788f48be7c37589ab3a513be5f9d8b2d741afe5c08ea9eed"
    ],
    "reference/allocator_environment.py": [
        5879,
        "f5c8e879c540b3f7cb1b7d3a7a0f5002c2f40c1a87963174b0b00470fa3a4525"
    ],
    "reference/observation_resources.py": [
        12382,
        "f3402d51cb37b2fe20f4351b3a81ec5990a9fdaff93a846d21c07ccd557cb894"
    ],
    "reference/summarize_trace.py": [
        15057,
        "f6e65c2e206d4aa90143a17893e5e57c158bca9f8eec5f74897b19c3596e32c5"
    ],
    "reference/analyze_native_observation.py": [
        8708,
        "cc7f6884d581cd1ced430437350e808de51931c50d12441797205501b20cae66"
    ],
    "reference/audit_native_evidence.py": [
        17065,
        "b69f6902d2de81eab41b21506f024c002d2f8264d60e86df6b1086623a77fd28"
    ],
    "reference/allocator_environment_audit.py": [
        6709,
        "4b082ce343ae3943e3098baa58af2f5def7198881b9c087d63d88360e9763727"
    ],
    "compiler_monitor.py": [
        12510,
        "afb514362a9d8dd573b806f0dc87df16bd3a906e4574d10d91bf483b2e76cdcf"
    ],
    "compiler_state.py": [
        6243,
        "9da718654db04a646e081d2d719a2d6d4655ffe337bc0e3f906e736e4d77a251"
    ],
    "validate_compiler_monitor.py": [
        7055,
        "d2cd009adf1f35a394ffddcc8f8646cc0c1b856b78181ca321ea68f6468218b2"
    ],
    "compiler-monitor-policy-01.json": [
        1001,
        "ddb2e03d4a1a1610466a5dc2d1a544f554ad12fc31412483101b48a235402368"
    ],
    "pre-execution-clarification-01.json": [
        3821,
        "7848ccc640e8d44fd042632eda69a93d2b24e07cabb65e83aeef683faeeb8704"
    ]
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


def qualification_projection(snapshot):
    return {name: value["sha256"] for name, value in snapshot["files"].items()
            if name in {"Cargo.toml", "Cargo.lock", "rustfmt.toml"} or name.startswith(("src/", "examples/"))}


def verify_completed_compiler_monitor(observed, inputs, bind, expected_output):
    need(expected_output == OUTPUT,
         "fixed D1 C1 monitored output required")
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



def require_sealed():
    need(isinstance(ACTUAL, dict) and ACTUAL.get("sealed") is True,
         "D1 outer parent is unsealed; no output, monitor or workload was started")
    need(set(ACTUAL) == {"sealed", "prerequisites", "qualification_binder", "ordinary", "adapter", "adapter_spec", "compiler_monitor"},
         "D1 sealed outer input shape differs")
    need(isinstance(ACTUAL["ordinary"], dict)
         and set(ACTUAL["ordinary"]) == {"verifier", "verification_input", "postflight"}
         and all(isinstance(pin, dict) and set(pin) == {"path", "bytes", "sha256"}
                 and isinstance(pin["path"], str) and type(pin["bytes"]) is int and pin["bytes"] > 0
                 and isinstance(pin["sha256"], str) and HEX.fullmatch(pin["sha256"])
                 for pin in ACTUAL["ordinary"].values()),
         "actual ordinary closure is mandatory before any output or monitor")
    need(not any(name in os.environ for name in DIAGNOSTIC_ENV),
         "diagnostic environment may only be added to the original controller children")
    return ACTUAL


def expected_inputs(launcher_sha256):
    return {"schema": "hepta-d1-c1-campaign-inputs/v1", "sealed": True, "attempt": "01",
            "launcher_sha256": launcher_sha256, "prerequisites": ACTUAL["prerequisites"],
            "qualification_binder": ACTUAL["qualification_binder"], "ordinary": ACTUAL["ordinary"],
            "adapter": ACTUAL["adapter"],
            "compiler_monitor": ACTUAL["compiler_monitor"]}


def command_plan():
    py = ["/usr/bin/python3", "-B"]
    return [
        {"name": "native-observation", "argv": py + [str(ADAPTER)], "timeout_seconds": 1800,
         "outputs": [str(NATIVE / "report.json"), str(ADAPTER_OUTPUT / "adapter-report.json")]},
        {"name": "native-audit", "argv": py + [str(REFERENCE / "analyze_native_observation.py"),
            "--report", str(NATIVE / "report.json"), "--output", str(NATIVE / "independent-summary.json")],
         "timeout_seconds": 180, "outputs": [str(NATIVE / "independent-summary.json")]},
    ]


def bind_static_sources(bind):
    for relative, (size, sha) in STATIC_INPUTS.items():
        bind(TOOLS / relative, {"bytes": size, "sha256": sha}, maximum=262144)
    expected_python = {Path(name).name for name in STATIC_INPUTS if name.startswith("reference/") and name.endswith(".py")}
    need({path.name for path in REFERENCE.glob("*.py")} == expected_python,
         "unbound Python source appeared in the original reference directory")


def bind_ordinary_prerequisite(pins, bind, foundation, qualified):
    """Re-read original ordinary evidence; never compile, test or re-audit."""
    need(isinstance(pins, dict) and set(pins) == {"verifier", "verification_input", "postflight"},
         "actual ordinary verifier/input/postflight identities are mandatory")
    paths = {"verifier": ORDINARY_VERIFIER, "verification_input": ORDINARY_INPUT,
             "postflight": ORDINARY_POSTFLIGHT}
    originals, bodies = {}, {}
    for name, path in paths.items():
        pin = pins[name]
        need(isinstance(pin, dict) and set(pin) == {"path", "bytes", "sha256"}
             and pin["path"] == str(path), "fixed actual ordinary input differs: " + name)
        originals[name], bodies[name] = bind(path, pin, retain=True,
            maximum=16 * 1024 * 1024 if name == "postflight" else 4 * 1024 * 1024)
    verifier = monitor_module("_d1_bound_ordinary_verifier", bodies["verifier"], ORDINARY_VERIFIER)
    inputs = json.loads(bodies["verification_input"])
    validation = verifier.verify_ordinary(inputs, bind, foundation, qualified)
    postflight = json.loads(bodies["postflight"])
    need(validation.get("schema") == "hepta-d1-ordinary-supplement-validation/v3"
         and validation.get("passed") is True and validation.get("ordinary_five_stages_passed") is True
         and validation.get("source_maps_unchanged") is True
         and validation["verifier"] == originals["verifier"]
         and validation["qualified_feature_programs_before"] == qualified["binaries"]
         and validation["qualified_feature_programs_after"] == qualified["binaries"]
         and set(validation["ordinary_programs"]) == set(BINARY_NAMES)
         and all(validation["ordinary_programs"][name]["path"] == str(ROOT / "ordinary-02" / name)
                 for name in BINARY_NAMES), "actual ordinary supplement did not close with both ELF sets")
    need(postflight.get("schema") == "hepta-d1-ordinary-supplement-postflight/v3"
         and postflight.get("validation_schema") == validation["schema"]
         and postflight.get("verification_input") == originals["verification_input"]
         and postflight.get("report_written_create_only") is True
         and all(postflight.get(name) == value for name, value in validation.items() if name != "schema"),
         "original ordinary postflight does not match fresh read-only validation")
    return {"schema": "hepta-d1-c1-ordinary-prerequisite/v1", "passed": True,
            "inputs": originals, "validation": validation,
            "original_postflight_revalidated": True, "compiler_test_auditor_or_workload_started": False}


def bind_adapter(bind, prerequisites, qualified):
    need(ACTUAL["adapter"]["path"] == str(ADAPTER)
         and ACTUAL["prerequisites"]["path"] == str(PREREQUISITES), "fixed adapter/foundation path differs")
    adapter_id, raw = bind(ADAPTER, ACTUAL["adapter"], retain=True, maximum=262144)
    declarations = [n for n in ast.parse(raw).body if isinstance(n, ast.Assign)
                    and any(isinstance(t, ast.Name) and t.id == "SPEC" for t in n.targets)]
    need(len(declarations) == 1 and ast.literal_eval(declarations[0].value) == ACTUAL["adapter_spec"],
         "the sealed adapter SPEC differs from the full outer input")
    spec = ACTUAL["adapter_spec"]
    need(spec["schema"] == "hepta-d1-c1-phase-cost-input/v1" and spec["sealed"] is True
         and spec["root"] == str(ROOT) and spec["reference_directory"] == str(REFERENCE)
         and spec["qualified_feature_binary"] == qualified["binaries"]["hepta-runtime"]
         and spec["outer_input_manifest"] == ACTUAL["prerequisites"]
         and spec["benchmark_output"] == str(NATIVE) and spec["evidence_output"] == str(ADAPTER_OUTPUT)
         and spec["socket_parent"] == str(SOCKET_PARENT),
         "same qualified feature ELF or planned C1-only namespaces differ")
    for field in ("qualification_report", "qualification_terminal", "qualified_source_map", "profile_template", "topology"):
        pin = spec[field]
        bind(pin["path"], pin)
    need(spec["qualification_report"]["path"] == str(CANDIDATE_DIR / "report.json")
         and spec["qualified_source_map"]["path"] == str(CANDIDATE_DIR / "source-map.json")
         and spec["qualification_terminal"]["path"] == str(ROOT / "qualification-terminal-status-01.json"),
         "adapter references a different qualification attempt")
    for pin in spec["frozen_jobs"]:
        bind(pin["path"], pin, maximum=65536)
    return adapter_id


def diagnostic_result(bind, qualified, adapter_id):
    native_id, native_raw = bind(NATIVE / "report.json", retain=True, maximum=16 * 1024 * 1024)
    audit_id, audit_raw = bind(NATIVE / "independent-summary.json", retain=True, maximum=16 * 1024 * 1024)
    adapter_report_id, adapter_report_raw = bind(ADAPTER_OUTPUT / "adapter-report.json", retain=True, maximum=16 * 1024 * 1024)
    native, audit, adapted = json.loads(native_raw), json.loads(audit_raw), json.loads(adapter_report_raw)
    elf = qualified["binaries"]["hepta-runtime"]
    need(native["schema"] == "hepta-x230-readonly-observation-abba/v2" and native["passed"] is True
         and native["order"] == "ABBA" and native["concurrency"] == [1] and native["calls_per_cell"] == 192
         and native["tokio_workers"] == 2 and native["binary_sha256"] == {"A": elf["sha256"], "B": elf["sha256"]},
         "original same-ELF C1 ABBA did not close")
    need(audit["schema"] == "hepta-native-observation-independent-analysis/v3" and audit["verified"] is True
         and audit["original_bytes"] == native_id["bytes"] and audit["original_sha256"] == native_id["sha256"]
         and audit["measured_calls"] == 768 and audit["warmup_calls"] == 96
         and audit["preflight_restart_calls"] == 72 and audit["total_calls"] == 936 and audit["failed_calls"] == 0
         and [case["concurrency"] for case in audit["cases"]] == [1]
         and audit["binary_sha256"] == native["binary_sha256"],
         "unchanged original native auditor did not verify the fixed C1 matrix")
    need(adapted["schema"] == "hepta-d1-c1-phase-cost-adapter/v1"
         and adapted["sealed_input"] == ACTUAL["adapter_spec"]
         and adapted["original_returncode"] == 0 and adapted["original_wrapper_returned"] is True
         and adapted["controller_close_evidence_complete"] is True
         and adapted["analysis_complete"] is True and adapted["errors"] == []
         and adapted["all_trace_reads_after_original_matrix"] is True
         and adapted["original_report"] == native_id and adapted["adapter_source"] == adapter_id
         and len(adapted["bindings"]) == len(adapted["traces"]) == 8,
         "adapter's original-close/trace binding is incomplete")
    for i, trace in enumerate(adapted["traces"]):
        arm = "ABBA"[i // 2]
        phase = "first" if i % 2 == 0 else "restart"
        expected_counts = dict.fromkeys(("preflight", "warmup", "measured", "restart"), 0)
        if arm == "B":
            expected_counts.update({"preflight": 6, "warmup": 24, "measured": 192}
                                   if phase == "first" else {"restart": 12})
        binding = trace["binding"]
        need(binding == adapted["bindings"][i] and binding["round"] == i // 2
             and binding["arm"] == arm and binding["phase"] == phase
             and binding["mode"] == ("off" if arm == "A" else "on")
             and trace["selected_on_counts"] == expected_counts,
             "trace grouping differs from original preflight/warmup/measured/restart intervals")
        bind(trace["trace"]["path"], trace["trace"], maximum=32 * 1024 * 1024)
    return {"schema": "hepta-d1-c1-diagnostic-evidence/v1", "evidence_verified": True,
            "native_report": native_id, "native_audit": audit_id, "adapter_report": adapter_report_id,
            "feature_elf": elf, "same_elf": True, "mode_order": ["off", "on", "on", "off"],
            "concurrency": [1], "counts": {key: audit[key] for key in
                ("measured_calls", "warmup_calls", "preflight_restart_calls", "total_calls", "failed_calls")},
            "original_raw_cases": audit["cases"], "original_resource_evidence": audit["resources"],
            "trace_cost_scope": "recorded synchronous spans selected by original native request IDs and original intervals",
            "performance_acceptance_claim": False, "candidate_adopted": False,
            "normal_lifecycle_or_capacity_gate_required": False,
            "compiler_monitor_finalization_still_required": True,
            "parent_final_report_and_original_holder_native_receipts_required": True,
            "original_holder_native_completion_and_owned_agent_reap_still_required": True}


def main():
    require_sealed()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--launcher-sha256", required=True)
    parser.add_argument("--inputs", type=Path, default=INPUTS)
    args = parser.parse_args()
    need(sys.platform == "linux" and os.geteuid() != 0 and HEX.fullmatch(args.launcher_sha256),
         "Linux operator and original holder receipt required")
    need(args.inputs == INPUTS, "fixed first D1 C1 input required")
    input_identity, input_raw = checked(args.inputs, maximum=262144, retain=True)
    inputs = json.loads(input_raw)
    need(inputs == expected_inputs(args.launcher_sha256), "sealed input or transmitted parent binding differs")
    for path in (OUTPUT, NATIVE, ADAPTER_OUTPUT, SOCKET_PARENT):
        need(path.is_absolute() and path.resolve() == path and not os.path.lexists(path),
             "fresh D1 C1 namespace required; existing evidence is never cleaned")
    out = OUTPUT
    private_directory(out, create_new=True)
    create(out / "inputs.json", input_raw)
    report_path = out / "report.json"
    deadline = time.monotonic() + CAMPAIGN_SECONDS
    report = {"schema": "hepta-d1-c1-campaign-control/v1", "attempt": "01",
              "passed": False, "diagnostic_evidence_passed": False, "started_utc": utc(),
              "launcher_sha256": args.launcher_sha256,
              "launcher_identity_origin": "unchanged Mac holder hashes transmitted stdin bytes; not a remote self-hash",
              "input_receipt": input_identity, "stages": [], "input_bindings": [],
              "automatic_retries": 0, "production_services_modified": False,
              "campaign_budget_seconds": CAMPAIGN_SECONDS, "recommended_holder_timeout_seconds": 3600,
              "inputs_unchanged": False, "source_inputs_unchanged": False,
              "candidate_adopted": False, "performance_acceptance_claim": False,
              "scope": "same feature ELF; C1 OFF/ON/ON/OFF only",
              "stop_semantics": "original fixed-count/round behavior; any measured failure rejects whole stage; no successful trace interpretation or replay",
              "normal_lifecycle_started": False, "capacity_workload_started": False}
    candidate_source = baseline_source = None
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
        bind_static_sources(bind)
        foundation_id, foundation_raw = bind(PREREQUISITES, ACTUAL["prerequisites"], retain=True, maximum=4 * 1024 * 1024)
        prerequisites = json.loads(foundation_raw)
        need(ACTUAL["qualification_binder"]["path"] == str(BINDER), "fixed D1 qualification binder required")
        binder_id, binder_raw = bind(BINDER, ACTUAL["qualification_binder"], retain=True, maximum=262144)
        binder = monitor_module("_d1_bound_qualification_binding", binder_raw, BINDER)
        qualified = binder.bind_d1_prerequisites(prerequisites, bind)
        need(qualified["passed"] is True and set(qualified["binaries"]) == set(BINARY_NAMES)
             and len(qualified["source_tested"]) == 222, "actual D1 qualification/CI closure required")
        report["prerequisite_gate"] = qualified
        report["prerequisite_inputs"] = foundation_id
        report["qualification_binder"] = binder_id
        report["ordinary_supplement"] = bind_ordinary_prerequisite(ACTUAL["ordinary"], bind, binder, qualified)
        adapter_id = bind_adapter(bind, prerequisites, qualified)
        report["adapter"] = adapter_id
        spec = ACTUAL["adapter_spec"]
        for name, pin in qualified["binaries"].items():
            need(pin["path"] == str(CANDIDATE_DIR / name), "retained qualified artifact path differs")
            bind(pin["path"], pin)
            need(os.access(pin["path"], os.X_OK), "retained qualified binary is not executable")
        candidate_source = source_inputs(SOURCE)
        baseline_source = source_inputs(BASELINE_ROOT / "source")
        need(qualification_projection(candidate_source) == qualified["source_tested"],
             "current source differs from the final actually qualified D1 source map")
        added = set(qualified["added_paths"])
        changed = set(qualified["changed_paths"])
        need(len(added) == 2 and len(changed) == 13
             and set(candidate_source["files"]) == set(baseline_source["files"]) | added
             and {name for name in candidate_source["files"]
                  if candidate_source["files"][name] != baseline_source["files"].get(name)} == changed,
             "D1 added or changed an unqualified build/config/source input outside the reviewed diagnostic patch")
        create(out / "source-inputs.json", canonical(candidate_source))
        create(out / "baseline-source-inputs.json", canonical(baseline_source))
        report["source_inputs"] = checked(out / "source-inputs.json")
        report["source_inputs_sha256"] = candidate_source["sha256"]
        report["baseline_source_inputs"] = checked(out / "baseline-source-inputs.json")
        report["baseline_source_inputs_sha256"] = baseline_source["sha256"]
        report["qualified_source_maps_match_current_inputs"] = True
        need(agent.startswith("/"), "current forwarded SSH agent required")
        sys.path.insert(0, str(REFERENCE))
        bench = importlib.import_module("x230_observation_benchmark")
        need(Path(bench.__file__).resolve() == REFERENCE / "x230_observation_benchmark.py",
             "another original benchmark module was imported")
        agent_identity = bench.agent_identity(agent)
        report["agent_identity"] = agent_identity
        plan = command_plan()
        report["stage_plan"] = plan
        report["socket_directory"] = str(SOCKET_PARENT)
        report["pre_execution_clarification"] = checked(TOOLS / "pre-execution-clarification-01.json")
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
        for spec in plan:
            unchanged()
            need(not compiler_activity(), "compiler activity overlaps a campaign stage")
            if spec["name"] == "native-observation":
                private_directory(SOCKET_PARENT, create_new=True)
            run_stage(spec)
        unchanged()
        report["inputs_unchanged"] = True
        report["source_inputs_unchanged"] = source_inputs(SOURCE) == candidate_source
        report["baseline_source_inputs_unchanged"] = source_inputs(BASELINE_ROOT / "source") == baseline_source
        need(report["source_inputs_unchanged"] and report["baseline_source_inputs_unchanged"],
             "qualified or accepted baseline source changed during campaign")
        summary = diagnostic_result(bind, qualified, adapter_id)
        create(out / "summary.json", canonical(summary))
        report.update(passed=True, diagnostic_evidence_passed=True, summary=checked(out / "summary.json"))
    except BaseException as error:
        report["error"] = {"type": type(error).__name__, "reason": str(error)[:4000]}
        report["passed"] = report["diagnostic_evidence_passed"] = False
        report["uncertain_effects_are_not_retried"] = True
        create(out / "campaign.error.txt", traceback.format_exc().encode())
    finally:
        if bench is not None and agent_identity is not None:
            try:
                unchanged()
                report["inputs_unchanged"] = True
            except BaseException as error:
                report["input_finalization_error"] = {"type": type(error).__name__, "reason": str(error)[:3000]}
                report["passed"] = report["diagnostic_evidence_passed"] = False
                report["inputs_unchanged"] = False
        if candidate_source is not None:
            try:
                report["source_inputs_unchanged"] = source_inputs(SOURCE) == candidate_source
                if not report["source_inputs_unchanged"]:
                    report["passed"] = report["diagnostic_evidence_passed"] = False
            except BaseException as error:
                report["source_finalization_error"] = {"type": type(error).__name__, "reason": str(error)[:3000]}
                report["passed"] = report["diagnostic_evidence_passed"] = False
                report["source_inputs_unchanged"] = False
        if baseline_source is not None:
            try:
                report["baseline_source_inputs_unchanged"] = source_inputs(BASELINE_ROOT / "source") == baseline_source
                if not report["baseline_source_inputs_unchanged"]:
                    report["passed"] = report["diagnostic_evidence_passed"] = False
            except BaseException as error:
                report["baseline_source_finalization_error"] = {"type": type(error).__name__, "reason": str(error)[:3000]}
                report["passed"] = report["diagnostic_evidence_passed"] = False
                report["baseline_source_inputs_unchanged"] = False
        monitored_body_end = time.monotonic_ns()
        finish_compiler_monitor(compiler_monitor, monitor_validator, monitor_proof,
            monitored_body_start, monitored_body_end, out, report, "diagnostic_evidence_passed")
        report["finished_utc"] = utc()
        report["machine_final"] = machine_snapshot()
        checkpoint()
        print(json.dumps({"passed": report["passed"], "diagnostic_evidence_passed": report["diagnostic_evidence_passed"],
                          "error": report.get("error"), "report": str(report_path)}), flush=True)
    return 0 if report["passed"] else 1


def interrupted(signum, _frame):
    raise RuntimeError("campaign interrupted by signal " + str(signum))



if __name__ == "__main__":
    os.umask(0o077)
    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, interrupted)
    raise SystemExit(main())

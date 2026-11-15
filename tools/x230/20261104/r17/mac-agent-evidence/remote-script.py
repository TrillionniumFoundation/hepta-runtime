#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""One gated R14-versus-R17 final campaign on X230; no retries or rebuilds.

The Mac holder sends these exact source bytes to a single foreground SSH session.
Selection is written separately by the parent only after qualification and the
configuration evidence are complete. All experiment output remains under R16
so the unchanged recovery harness retains its existing DEV_ROOT contract.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import traceback

sys.dont_write_bytecode = True
R16 = Path("/home/qian/hepta-runtime-optimization-20261104-r16")
R17 = Path("/home/qian/hepta-runtime-optimization-20261104-r17")
TOOLS = R16 / "measurement-tools"
SELECTION = R17 / "final-measurement-selection.json"
QUALIFICATION = R17 / "qualification-01/report.json"
READY = R17 / "implementation-ready.json"
SOURCE_FREEZE = R17 / "source-freeze.json"
BASELINE = Path("/home/qian/hepta-runtime-optimization-20261103-r14/qualification-01/hepta-runtime")
CANDIDATE = R17 / "qualification-01/hepta-runtime"
BASELINE_SHA = "51480b3cf630a95419d3afeb571eec17c90cffa5944101920d05333673de031d"
READY_SHA = "acc9d0a095f43e6ea66d2f1b017a21c3eaf481dfe204c30da85a7d9378a40aef"
SOURCE_FREEZE_SHA = "5fc473e65ac9d278f88f844a3b6e25e44c7462c079efa93ecccab4fe8770f4c2"
TOPOLOGY = R16 / "benchmark-topology.json"
TOPOLOGY_SHA = "8c0767d3318131a7d470d9cde8e327a59ce18adf022c8bc1b1d5a0fa9a865287"
PROFILE = Path("/home/qian/hepta-runtime-optimization-20261023/r11-native-observation-abba-20261103-02/profile/profile.json")
PROFILE_SHA = "fe1e9551b5b8812ad6ed3da018c282b7261f7caeb2f49e4dcfefba7ff784ab08"
FROZEN_JOBS = Path("/home/qian/hepta-runtime-optimization-20261023/a31-frozen-originals-r01")
OUTPUT = R16 / "r17-final-campaign-01"
NATIVE_OUT = R16 / "r17-native-observation-01"
RECOVERY_OUT = R16 / "r17-cancel-recovery-01"
NATIVE_SOCKET = Path("/home/qian/h17n1")
RECOVERY_SOCKET = Path("/home/qian/h17c1")
SELECTION_SCHEMA = "hepta-x230-r17-final-measurement-selection/v1"
HEX = re.compile(r"[0-9a-f]{64}\Z")


def need(value, reason):
    if not value:
        raise RuntimeError(reason)


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read_bound(entry, expected_path=None):
    need(isinstance(entry, dict) and isinstance(entry.get("path"), str)
         and isinstance(entry.get("sha256"), str) and HEX.fullmatch(entry["sha256"]), "invalid selected artifact identity")
    path = Path(entry["path"])
    need(path.is_absolute() and path.resolve() == path and stat.S_ISREG(path.lstat().st_mode), "selected artifact must be a direct regular file")
    if expected_path is not None:
        need(path == expected_path, "selected artifact path differs from the declared campaign")
    raw = path.read_bytes()
    need(hashlib.sha256(raw).hexdigest() == entry["sha256"], "selected artifact changed: " + str(path))
    return raw


def verify_selection():
    raw = SELECTION.read_bytes()
    selection = json.loads(raw)
    need(selection.get("schema") == SELECTION_SCHEMA, "unsupported final-measurement selection")
    workers = selection.get("selected_workers")
    need(type(workers) is int and workers in (1, 2, 4) and selection.get("arena_max") == 1,
         "workers must be explicitly selected from 1/2/4 with arena1")
    need(isinstance(selection.get("selection_reason"), str) and selection["selection_reason"].strip(), "selection rationale missing")
    need(selection["baseline"] == {"path": str(BASELINE), "sha256": BASELINE_SHA}, "baseline is not the preserved R14 release")
    need(selection["implementation_ready"] == {"path": str(READY), "sha256": READY_SHA}, "R17 implementation-ready identity differs")
    need(selection["source_freeze"] == {"path": str(SOURCE_FREEZE), "sha256": SOURCE_FREEZE_SHA}, "R17 source freeze identity differs")
    ready = json.loads(read_bound(selection["implementation_ready"], READY))
    read_bound(selection["source_freeze"], SOURCE_FREEZE)
    qualification = json.loads(read_bound(selection["qualification_report"], QUALIFICATION))
    need(qualification.get("qualified") is True, "R17 has not completed qualification")
    inputs = qualification["source_tested"]
    need(isinstance(inputs, dict) and inputs and inputs == qualification["source_after"] == ready["source_inputs"],
         "qualified source_tested/source_after differs from frozen R17 inputs")
    for relative, expected in inputs.items():
        path = Path(relative)
        need(not path.is_absolute() and ".." not in path.parts and isinstance(expected, str) and HEX.fullmatch(expected),
             "unsafe source input identity")
        source = R17 / "source" / path
        need(source.resolve() == source and sha(source) == expected, "frozen R17 source changed: " + relative)
    need(selection["candidate"]["path"] == str(CANDIDATE), "candidate is not the R17 qualification artifact")
    need(selection["candidate"]["sha256"] == qualification["binaries"]["hepta-runtime"]["sha256"],
         "selected candidate does not bind to qualification")
    read_bound(selection["baseline"], BASELINE)
    read_bound(selection["candidate"], CANDIDATE)
    need(sha(TOPOLOGY) == TOPOLOGY_SHA and sha(PROFILE) == PROFILE_SHA, "frozen historical topology/profile changed")
    validation = json.loads((TOOLS / "harness-validation-02.json").read_bytes())
    need(validation.get("success") is True and len(validation["files"]) == 12, "frozen measurement harness validation missing")
    for name, expected in validation["files"].items():
        need(Path(name).name == name and name.endswith(".py") and sha(TOOLS / name) == expected,
             "frozen measurement script changed: " + name)
    basis = selection.get("configuration_basis")
    need(isinstance(basis, list) and 1 <= len(basis) <= 4, "verified configuration evidence is required")
    supporting, receipts = 0, []
    for item in basis:
        need(item.get("role") in {"selection", "context"}, "configuration basis role differs")
        for field in ("report", "independent_analysis"):
            need(Path(item[field]["path"]).is_relative_to(R16), "configuration evidence is outside the R16 campaign tree")
        config_raw = read_bound(item["report"])
        config = json.loads(config_raw)
        analysis = json.loads(read_bound(item["independent_analysis"]))
        proof = analysis["configuration_verification"]
        native = analysis["native_analysis"]
        need(config.get("passed") is True and analysis.get("schema") == "hepta-x230-workers-independent-analysis/v1"
             and analysis.get("verified") is True and proof.get("verified") is True
             and native.get("verified") is True and native["original_sha256"] == item["report"]["sha256"]
             and native["failed_calls"] == 0, "configuration basis is not a completed independently audited campaign")
        mapping = config["worker_configuration_experiment"]["workers_by_arm"]
        need(config["binary_sha256"] == {"A": BASELINE_SHA, "B": BASELINE_SHA}
             and proof["binary_sha256"] == BASELINE_SHA and native["binary_sha256"] == config["binary_sha256"]
             and mapping == proof["workers_by_arm"] == config["tokio_workers"]
             and proof["controllers_with_live_workers"] == 8 and proof["allocator_environment"] == {"MALLOC_ARENA_MAX": "1"},
             "configuration basis changed binary/allocator/live worker identity")
        if item["role"] == "selection":
            arm = item.get("selected_arm")
            need(arm in mapping and mapping[arm] == workers, "selected workers lack a directly observed supporting arm")
            supporting += 1
        receipts.append({"role": item["role"], "report": item["report"], "independent_analysis": item["independent_analysis"],
                         "workers_by_arm": mapping, "selected_arm": item.get("selected_arm")})
    need(supporting >= 1, "no configuration campaign directly supports the selected workers")
    return raw, {"selection_sha256": hashlib.sha256(raw).hexdigest(), "selected_workers": workers, "arena_max": 1,
                 "candidate_qualification_verified": True,
                 "baseline": selection["baseline"], "candidate": selection["candidate"],
                 "qualification_report": selection["qualification_report"], "implementation_ready": selection["implementation_ready"],
                 "source_freeze": selection["source_freeze"], "source_inputs": inputs,
                 "configuration_basis": receipts, "selection_reason": selection["selection_reason"],
                 "harness_validation_sha256": sha(TOOLS / "harness-validation-02.json"),
                 "measurement_script_sha256": validation["files"], "topology_sha256": TOPOLOGY_SHA,
                 "profile_template_sha256": PROFILE_SHA}


def snapshot():
    paths = [Path("/proc/loadavg"), Path("/proc/meminfo"), Path("/proc/stat")]
    for pattern in ("cpu[0-9]*/cpufreq/scaling_governor", "cpu[0-9]*/cpufreq/scaling_cur_freq",
                    "cpu[0-9]*/cpufreq/scaling_max_freq", "cpu[0-9]*/cpufreq/scaling_min_freq"):
        paths.extend(sorted(Path("/sys/devices/system/cpu").glob(pattern)))
    paths.extend(sorted(Path("/sys/class/thermal").glob("thermal_zone*/temp")))
    values = {}
    for path in paths:
        try:
            values[str(path)] = path.read_text()
        except OSError as error:
            values[str(path)] = {"error": type(error).__name__, "errno": error.errno}
    return {"monotonic_ns": time.monotonic_ns(), "utc": utc(), "values": values}


def write_new(path, raw):
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--launcher-sha256", required=True)
    args = parser.parse_args()
    need(HEX.fullmatch(args.launcher_sha256), "Mac source-byte receipt is required")
    need(sys.platform == "linux" and os.geteuid() == 1000, "campaign is bound to the verified non-root X230 account")
    need(OUTPUT.resolve() == OUTPUT, "campaign path must be direct")
    OUTPUT.mkdir(mode=0o700)
    report = {"schema": "hepta-x230-r17-final-campaign/v1", "started_utc": utc(),
              "remote_launcher_sha256_reported_by_mac": args.launcher_sha256,
              "selection_path": str(SELECTION), "candidate_qualification_verified": False,
              "automatic_campaign_retries": 0, "automatic_rpc_retries": 0,
              "production_service_changes": False, "builds_started": 0, "stages": [], "passed": False}
    selection_raw = None
    gate = None

    def save():
        temporary = OUTPUT / "report.next"
        write_new(temporary, (json.dumps(report, indent=2) + "\n").encode())
        os.replace(temporary, OUTPUT / "report.json")

    def unchanged_gate():
        current_raw, current_gate = verify_selection()
        need(current_raw == selection_raw and current_gate == gate, "selection, qualification or frozen inputs changed during campaign")

    def stage(name, command, timeout, expected_artifacts):
        unchanged_gate()
        row = {"name": name, "argv": command, "cwd": str(TOOLS), "timeout_seconds": timeout,
               "script_sha256": sha(Path(command[2])), "before": snapshot(), "returncode": None,
               "start_monotonic_ns": time.monotonic_ns(), "automatic_retry": False}
        report["stages"].append(row)
        save()
        print(json.dumps({"stage": name, "state": "started"}), flush=True)
        process = None
        try:
            with (OUTPUT / (name + ".stdout")).open("xb") as stdout, (OUTPUT / (name + ".stderr")).open("xb") as stderr:
                process = subprocess.Popen(command, cwd=TOOLS, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr)
                row["pid"] = process.pid
                try:
                    row["returncode"] = process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    row["timed_out"] = True
                    process.kill()  # Exact direct stage child, never a shared service or process group.
                    row["returncode"] = process.wait(timeout=30)
                    raise
        except BaseException as error:
            row["error"] = {"type": type(error).__name__, "reason": str(error)}
            write_new(OUTPUT / (name + ".error.txt"), traceback.format_exc().encode())
            raise
        finally:
            row["end_monotonic_ns"] = time.monotonic_ns()
            row["seconds"] = (row["end_monotonic_ns"] - row["start_monotonic_ns"]) / 1e9
            row["after"] = snapshot()
            for suffix in ("stdout", "stderr", "error.txt"):
                path = OUTPUT / (name + "." + suffix)
                if path.exists():
                    row[suffix] = {"file": path.name, "bytes": path.stat().st_size, "sha256": sha(path)}
            row["artifacts"] = [{"path": str(path), "bytes": path.stat().st_size, "sha256": sha(path)}
                                for path in expected_artifacts if path.is_file()]
            save()
        need(row["returncode"] == 0, name + " failed; original stdout/stderr retained without retry")
        need(len(row["artifacts"]) == len(expected_artifacts), name + " did not leave its expected complete artifacts")
        unchanged_gate()
        print(json.dumps({"stage": name, "returncode": row["returncode"], "seconds": row["seconds"]}), flush=True)

    try:
        save()
        need(not NATIVE_OUT.exists() and not RECOVERY_OUT.exists() and not NATIVE_SOCKET.exists() and not RECOVERY_SOCKET.exists(),
             "declared output or socket parent already exists; automatic resume/retry is forbidden")
        selection_raw, gate = verify_selection()
        write_new(OUTPUT / "selection.json", selection_raw)
        report["gate"] = gate
        report["candidate_qualification_verified"] = True
        workers = str(gate["selected_workers"])
        shared = ["--profile-template", str(PROFILE), "--topology", str(TOPOLOGY), "--frozen-jobs", str(FROZEN_JOBS)]
        NATIVE_SOCKET.mkdir(mode=0o700)
        stage("native-observation", ["/usr/bin/python3", "-B", str(TOOLS / "run_native_observation.py"),
              "--baseline", str(BASELINE), "--candidate", str(CANDIDATE), "--arena-max", "1", *shared,
              "--socket-parent", str(NATIVE_SOCKET), "--out", str(NATIVE_OUT), "--calls", "96",
              "--concurrency", "1", "8", "16", "--workers", workers, "--order", "ABBA", "--warmup-calls", "24"],
              1800, [NATIVE_OUT / "report.json"])
        stage("native-independent-audit", ["/usr/bin/python3", "-B", str(TOOLS / "analyze_native_observation.py"),
              "--report", str(NATIVE_OUT / "report.json"), "--output", str(NATIVE_OUT / "independent-summary.json")],
              180, [NATIVE_OUT / "independent-summary.json"])
        native = json.loads((NATIVE_OUT / "report.json").read_bytes())
        analysis = json.loads((NATIVE_OUT / "independent-summary.json").read_bytes())
        need(native["passed"] is True and native["binary_sha256"] == {"A": BASELINE_SHA, "B": gate["candidate"]["sha256"]}
             and native["tokio_workers"] == gate["selected_workers"] and native["calls_per_cell"] == 96
             and native["concurrency"] == [1, 8, 16] and native["order"] == "ABBA"
             and analysis["verified"] is True and analysis["original_sha256"] == sha(NATIVE_OUT / "report.json"),
             "native stage identity or independent verdict differs")
        RECOVERY_SOCKET.mkdir(mode=0o700)
        stage("cancel-recovery", ["/usr/bin/python3", "-B", str(TOOLS / "run_six_host_cancel_recovery.py"),
              "--candidate", str(CANDIDATE), "--candidate-arena-max", "1", *shared,
              "--socket-parent", str(RECOVERY_SOCKET), "--out", str(RECOVERY_OUT),
              "--workers", workers, "--interrupt-host", "rog"], 600, [RECOVERY_OUT / "report.json"])
        stage("recovery-independent-audit", ["/usr/bin/python3", "-B", str(TOOLS / "verify_cancel_recovery.py"),
              "--report", str(RECOVERY_OUT / "report.json"), "--output", str(RECOVERY_OUT / "independent-summary.json")],
              180, [RECOVERY_OUT / "independent-summary.json"])
        recovery = json.loads((RECOVERY_OUT / "independent-summary.json").read_bytes())
        need(recovery["verified"] is True and recovery["candidate_sha256"] == gate["candidate"]["sha256"]
             and recovery["source_sha256"] == sha(RECOVERY_OUT / "report.json"), "recovery independent verdict/identity differs")
        unchanged_gate()
        report["passed"] = True
    except BaseException as error:
        report["error"] = {"type": type(error).__name__, "reason": str(error)}
        write_new(OUTPUT / "campaign.error.txt", traceback.format_exc().encode())
    finally:
        report["finished_utc"] = utc()
        save()
        print(json.dumps({"passed": report["passed"], "selected_workers": None if gate is None else gate["selected_workers"],
                          "error": report.get("error"), "report": str(OUTPUT / "report.json")}), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

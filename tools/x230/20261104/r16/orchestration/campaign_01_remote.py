#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""One declared, sequential R16 ABBA and six-host recovery campaign on X230."""
from pathlib import Path
import datetime
import hashlib
import json
import os
import subprocess
import sys
import time

ROOT = Path("/home/qian/hepta-runtime-optimization-20261104-r16")
TOOLS = ROOT / "measurement-tools"
PROFILE = Path("/home/qian/hepta-runtime-optimization-20261023/r11-native-observation-abba-20261103-02/profile/profile.json")
FROZEN = Path("/home/qian/hepta-runtime-optimization-20261023/a31-frozen-originals-r01")
BASELINE = Path("/home/qian/hepta-runtime-optimization-20261103-r14/qualification-01/hepta-runtime")
CANDIDATE = ROOT / "qualification-01/hepta-runtime"


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def snapshot():
    values = {}
    paths = [Path("/proc/loadavg"), Path("/proc/meminfo"), Path("/proc/stat")]
    for pattern in ("cpu[0-9]*/cpufreq/scaling_governor", "cpu[0-9]*/cpufreq/scaling_cur_freq",
                    "cpu[0-9]*/cpufreq/scaling_max_freq", "cpu[0-9]*/cpufreq/scaling_min_freq"):
        paths.extend(sorted(Path("/sys/devices/system/cpu").glob(pattern)))
    paths.extend(sorted(Path("/sys/class/thermal").glob("thermal_zone*/temp")))
    for path in paths:
        try:
            values[str(path)] = path.read_text()
        except OSError as error:
            values[str(path)] = {"error": type(error).__name__, "errno": error.errno}
    return {"monotonic_ns": time.monotonic_ns(), "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "values": values}


def main():
    if sys.platform != "linux" or os.geteuid() != 1000:
        raise RuntimeError("this campaign is bound to the verified non-root X230 account")
    qualification = json.loads((ROOT / "qualification-01/report.json").read_text())
    freeze = json.loads((ROOT / "implementation-ready.json").read_text())
    if not qualification["qualified"] or qualification["source_tested"] != qualification["source_after"]:
        raise RuntimeError("complete unchanged-source qualification is required")
    if qualification["source_tested"] != freeze["source_inputs"]:
        raise RuntimeError("qualification differs from the frozen candidate")
    for relative, expected in freeze["source_inputs"].items():
        if sha(ROOT / "source" / relative) != expected:
            raise RuntimeError("a frozen source input changed: " + relative)
    if sha(CANDIDATE) != qualification["binaries"]["hepta-runtime"]["sha256"]:
        raise RuntimeError("candidate differs from its qualified release binary")
    if sha(BASELINE) != "51480b3cf630a95419d3afeb571eec17c90cffa5944101920d05333673de031d":
        raise RuntimeError("baseline differs from the preserved R14 release")
    if sha(ROOT / "benchmark-topology.json") != "8c0767d3318131a7d470d9cde8e327a59ce18adf022c8bc1b1d5a0fa9a865287":
        raise RuntimeError("frozen six-machine topology changed")
    validation = json.loads((TOOLS / "harness-validation-02.json").read_text())
    if not validation["success"]:
        raise RuntimeError("measurement harness has not passed its self-checks")
    for name, expected in validation["files"].items():
        if sha(TOOLS / name) != expected:
            raise RuntimeError("a frozen measurement helper changed: " + name)
    output = ROOT / "campaign-01"
    output.mkdir(mode=0o700)
    report = {
        "schema": "hepta-x230-r16-campaign-launch/v1",
        "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "qualification_report_sha256": sha(ROOT / "qualification-01/report.json"),
        "implementation_freeze_sha256": sha(ROOT / "implementation-ready.json"),
        "harness_validation_sha256": sha(TOOLS / "harness-validation-02.json"),
        "topology_sha256": sha(ROOT / "benchmark-topology.json"),
        "binary_sha256": {"baseline": sha(BASELINE), "candidate": sha(CANDIDATE)},
        "automatic_campaign_retries": 0,
        "production_service_changes": False,
        "stages": [], "passed": False,
    }

    def save():
        temporary = output / "report.next"
        temporary.write_text(json.dumps(report, indent=2) + "\n")
        os.replace(temporary, output / "report.json")

    def stage(name, command, timeout):
        row = {"name": name, "argv": command, "before": snapshot(), "returncode": None}
        report["stages"].append(row)
        save()
        print(json.dumps({"stage": name, "state": "started"}), flush=True)
        started_ns = time.monotonic_ns()
        try:
            with (output / (name + ".stdout")).open("xb") as stdout, \
                    (output / (name + ".stderr")).open("xb") as stderr:
                result = subprocess.run(command, cwd=TOOLS, stdout=stdout, stderr=stderr, timeout=timeout)
            row["returncode"] = result.returncode
        finally:
            row["seconds"] = (time.monotonic_ns() - started_ns) / 1e9
            row["after"] = snapshot()
            for stream in ("stdout", "stderr"):
                path = output / (name + "." + stream)
                row[stream] = {"bytes": path.stat().st_size, "sha256": sha(path)}
            save()
        print(json.dumps({"stage": name, "returncode": row["returncode"], "seconds": row["seconds"]}), flush=True)
        if row["returncode"] != 0:
            raise RuntimeError(name + " failed; original results retained without retry")

    shared = ["--profile-template", str(PROFILE), "--topology", str(ROOT / "benchmark-topology.json"),
              "--frozen-jobs", str(FROZEN)]
    native_out = ROOT / "native-observation-01"
    recovery_out = ROOT / "cancel-recovery-01"
    try:
        Path("/home/qian/h16n1").mkdir(mode=0o700)
        stage("native-observation", ["/usr/bin/python3", "-B", str(TOOLS / "run_native_observation.py"),
              "--baseline", str(BASELINE), "--candidate", str(CANDIDATE), "--arena-max", "1",
              *shared, "--socket-parent", "/home/qian/h16n1", "--out", str(native_out),
              "--calls", "192", "--concurrency", "1", "4", "8", "16", "--workers", "2",
              "--order", "ABBA", "--warmup-calls", "24"], 1800)
        stage("native-independent-audit", ["/usr/bin/python3", "-B", str(TOOLS / "analyze_native_observation.py"),
              "--report", str(native_out / "report.json"), "--output", str(native_out / "independent-summary.json")], 180)
        Path("/home/qian/h16c1").mkdir(mode=0o700)
        stage("cancel-recovery", ["/usr/bin/python3", "-B", str(TOOLS / "run_six_host_cancel_recovery.py"),
              "--candidate", str(CANDIDATE), "--candidate-arena-max", "1", *shared,
              "--socket-parent", "/home/qian/h16c1", "--out", str(recovery_out),
              "--workers", "2", "--interrupt-host", "rog"], 600)
        stage("recovery-independent-audit", ["/usr/bin/python3", "-B", str(TOOLS / "verify_cancel_recovery.py"),
              "--report", str(recovery_out / "report.json"), "--output", str(recovery_out / "independent-summary.json")], 180)
        report["passed"] = True
    except BaseException as error:
        report["error"] = {"type": type(error).__name__, "reason": str(error)[:1000]}
    finally:
        report["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        save()
        print(json.dumps({"passed": report["passed"], "error": report.get("error"),
                          "report": str(output / "report.json")}), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

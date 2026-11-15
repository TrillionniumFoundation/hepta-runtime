#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Two separate worker-count ABBA experiments on the retained R14 reference."""
from pathlib import Path
import datetime
import hashlib
import json
import os
import subprocess
import sys
import time

ROOT = Path("/home/qian/hepta-runtime-optimization-20261104-r16")
TOOLS = ROOT / "configuration-tools"
BASELINE = Path("/home/qian/hepta-runtime-optimization-20261103-r14/qualification-01/hepta-runtime")
BINARY_SHA256 = "51480b3cf630a95419d3afeb571eec17c90cffa5944101920d05333673de031d"
PROFILE = Path("/home/qian/hepta-runtime-optimization-20261023/r11-native-observation-abba-20261103-02/profile/profile.json")
FROZEN = Path("/home/qian/hepta-runtime-optimization-20261023/a31-frozen-originals-r01")


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def snapshot():
    paths = [Path("/proc/loadavg"), Path("/proc/meminfo"), Path("/proc/stat")]
    paths.extend(sorted(Path("/sys/devices/system/cpu").glob("cpu[0-9]*/cpufreq/scaling_cur_freq")))
    paths.extend(sorted(Path("/sys/class/thermal").glob("thermal_zone*/temp")))
    values = {}
    for path in paths:
        try:
            values[str(path)] = path.read_text()
        except OSError as error:
            values[str(path)] = {"error": type(error).__name__, "errno": error.errno}
    return {"utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "monotonic_ns": time.monotonic_ns(), "values": values}


def main():
    assert sys.platform == "linux" and os.geteuid() == 1000
    qualification_path = BASELINE.parent / "report.json"
    qualification = json.loads(qualification_path.read_text())
    assert qualification["qualified"] and qualification["source_tested"] == qualification["source_after"]
    assert sha(BASELINE) == qualification["binaries"]["hepta-runtime"]["sha256"] == BINARY_SHA256
    assert sha(qualification_path) == "d6a46164b30c6677cf49ec7eea156748a8445589c71034795d016a62795610cd"
    assert sha(ROOT / "benchmark-topology.json") == "8c0767d3318131a7d470d9cde8e327a59ce18adf022c8bc1b1d5a0fa9a865287"
    for campaign in ("native-observation-01", "native-observation-02"):
        assert json.loads((ROOT / campaign / "independent-summary.json").read_text())["verified"] is True
    validation = json.loads((TOOLS / "configuration-validation-01.json").read_text())
    assert validation["success"] is True
    freeze = json.loads((TOOLS / "harness-freeze.json").read_text())
    for name, expected in freeze["files"].items():
        assert sha(ROOT / "measurement-tools" / name) == expected, name
    source_names = ("run_worker_configuration.py", "verify_worker_configuration.py",
                    "test_worker_configuration.py", "harness-freeze.json")
    source_hashes = {name: sha(TOOLS / name) for name in source_names}
    output = ROOT / "configuration-campaign-01"
    output.mkdir(mode=0o700)
    report = {
        "schema": "hepta-x230-r16-worker-campaign-launch/v1", "passed": False,
        "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "binary_sha256": BINARY_SHA256, "qualification_report_sha256": sha(qualification_path),
        "selection": "Retain qualified R14 reference; R16 profile candidate lacks a consistent overall gain and has a C16 tail tradeoff",
        "native_source_comparisons": {name: sha(ROOT / name / "independent-summary.json")
                                      for name in ("native-observation-01", "native-observation-02")},
        "comparison_policy": "Two separate same-binary arena1 ABBA campaigns; no pooling between worker comparisons",
        "configuration_validation_sha256": sha(TOOLS / "configuration-validation-01.json"),
        "configuration_source_sha256": source_hashes,
        "topology_sha256": sha(ROOT / "benchmark-topology.json"),
        "automatic_campaign_retries": 0, "production_service_changes": False, "stages": [],
    }

    def save():
        temporary = output / "report.next"
        temporary.write_text(json.dumps(report, indent=2) + "\n")
        os.replace(temporary, output / "report.json")

    def stage(name, command, timeout):
        assert all(sha(TOOLS / name) == expected for name, expected in source_hashes.items())
        row = {"name": name, "argv": command, "before": snapshot(), "returncode": None}
        report["stages"].append(row)
        save()
        print(json.dumps({"stage": name, "state": "started"}), flush=True)
        started = time.monotonic_ns()
        try:
            with (output / (name + ".stdout")).open("xb") as stdout, (output / (name + ".stderr")).open("xb") as stderr:
                result = subprocess.run(command, cwd=TOOLS, stdout=stdout, stderr=stderr, timeout=timeout)
            row["returncode"] = result.returncode
        finally:
            row["seconds"] = (time.monotonic_ns() - started) / 1e9
            row["after"] = snapshot()
            for stream in ("stdout", "stderr"):
                path = output / (name + "." + stream)
                row[stream] = {"bytes": path.stat().st_size, "sha256": sha(path)}
            save()
        print(json.dumps({"stage": name, "returncode": row["returncode"], "seconds": row["seconds"]}), flush=True)
        if row["returncode"] != 0:
            raise RuntimeError(name + " failed; original results retained without retry")

    try:
        for workers in (1, 4):
            directory = ROOT / ("workers2-vs" + str(workers) + "-01")
            socket = Path("/home/qian/h16w" + str(workers))
            socket.mkdir(mode=0o700)
            label = "workers2-vs" + str(workers)
            stage(label, ["/usr/bin/python3", "-B", str(TOOLS / "run_worker_configuration.py"),
                  "--binary", str(BASELINE), "--workers-b", str(workers),
                  "--profile-template", str(PROFILE), "--topology", str(ROOT / "benchmark-topology.json"),
                  "--frozen-jobs", str(FROZEN), "--socket-parent", str(socket), "--out", str(directory),
                  "--calls", "96", "--concurrency", "1", "8", "16", "--warmup-calls", "24"], 1200)
            stage(label + "-independent-audit", ["/usr/bin/python3", "-B", str(TOOLS / "verify_worker_configuration.py"),
                  "--report", str(directory / "report.json"),
                  "--output", str(directory / "independent-configuration-analysis.json")], 180)
        assert sha(BASELINE) == BINARY_SHA256
        assert all(sha(TOOLS / name) == expected for name, expected in source_hashes.items())
        report["passed"] = True
    except BaseException as error:
        report["error"] = {"type": type(error).__name__, "reason": str(error)[:1000]}
    finally:
        report["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        save()
        print(json.dumps({"passed": report["passed"], "error": report.get("error"), "report": str(output / "report.json")}), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

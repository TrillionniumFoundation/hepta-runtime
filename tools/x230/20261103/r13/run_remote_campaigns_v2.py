#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Run bounded native/recovery campaigns after the current qualification and local gate."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path("/home/qian/hepta-runtime-optimization-20261103-r13")
OLD = Path("/home/qian/hepta-runtime-optimization-20261103-r12")
QUAL = ROOT / "qualification-03"
TOOLS = OLD / "source/tools/x230/20261103/r12"
BASELINE = Path("/home/qian/hepta-runtime-optimization-20261103-r11/qualification-01/hepta-runtime")
BASELINE_SHA = "660d64674fe3422006c0c2a82bc31f3f36edf19baf6613df7cdce51e8f3f8e4c"
PROFILE = Path("/home/qian/hepta-runtime-optimization-20261023/r11-native-observation-abba-20261103-02/profile/profile.json")
FROZEN = Path("/home/qian/hepta-runtime-optimization-20261023/a31-frozen-originals-r01")

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def sha(path):
    with Path(path).open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()

def need(value, reason):
    if not value:
        raise RuntimeError(reason)

def source_map(source):
    files = [source / n for n in ("Cargo.toml", "Cargo.lock", "rustfmt.toml")]
    for name in ("src", "examples"):
        files.extend(p for p in (source / name).rglob("*") if p.is_file())
    return {str(p.relative_to(source)): sha(p) for p in sorted(files) if p.is_file()}

def environment():
    row = {"utc": now(), "loadavg": Path("/proc/loadavg").read_text().strip()}
    row["memory"] = {k: v.strip() for k, v in
        (line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines())
        if k in ("MemTotal", "MemAvailable", "SwapTotal", "SwapFree")}
    row["temperature_millidegrees"] = {}
    for p in Path("/sys/class/thermal").glob("thermal_zone*/temp"):
        try:
            row["temperature_millidegrees"][str(p)] = p.read_text().strip()
        except OSError as error:
            row["temperature_millidegrees"][str(p)] = type(error).__name__
    row["frequency_khz"] = {}
    for p in Path("/sys/devices/system/cpu").glob("cpu[0-9]*/cpufreq/scaling_cur_freq"):
        try:
            row["frequency_khz"][str(p)] = p.read_text().strip()
        except OSError as error:
            row["frequency_khz"][str(p)] = type(error).__name__
    return row

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wait-seconds", type=int, default=3600)
    args = parser.parse_args()
    need(1 <= args.wait_seconds <= 7200, "invalid bounded gate wait")
    out = ROOT / "remote-campaigns-02"
    out.mkdir(mode=0o700, exist_ok=False)
    report = {"schema": "hepta-x230-r13-remote-campaigns/v1", "success": False,
        "state": "waiting_local_gate", "started_utc": now(), "stages": [],
        "automatic_retries": 0, "production_service_mutations": 0,
        "script_sha256": sha(__file__), "gate_wait_limit_seconds": args.wait_seconds}
    def save():
        tmp = out / "report.next"
        tmp.write_text(json.dumps(report, indent=2) + "\n")
        os.replace(tmp, out / "report.json")
    def run(name, command, timeout):
        stage = {"name": name, "command": command, "started_utc": now(),
                 "environment_before": environment(), "returncode": None}
        report["state"] = name
        report["stages"].append(stage)
        save()
        print(json.dumps({"stage": name, "state": "started"}), flush=True)
        start = time.monotonic()
        stdout, stderr = out / (name + ".stdout"), out / (name + ".stderr")
        try:
            with stdout.open("xb") as a, stderr.open("xb") as b:
                result = subprocess.run(command, stdout=a, stderr=b, timeout=timeout)
            stage["returncode"] = result.returncode
        finally:
            stage["seconds"] = time.monotonic() - start
            stage["environment_after"] = environment()
            stage["stdout_sha256"] = sha(stdout)
            stage["stderr_sha256"] = sha(stderr)
            save()
        need(stage["returncode"] == 0, name + " failed; original evidence retained")
    save()
    try:
        deadline = time.monotonic() + args.wait_seconds
        while True:
            q = json.loads((QUAL / "report.json").read_text())
            need(not q.get("error"), "qualification failed before remote experiments")
            local_path = ROOT / "local-campaigns-02/report.json"
            if local_path.exists():
                local = json.loads(local_path.read_text())
                need(not local.get("error"), "local campaign failed before remote experiments")
                if local.get("finished_utc"):
                    need(local.get("success") is True, "local terminal campaign is not successful")
                    need(q.get("qualified") is True and q.get("finished_utc"), "qualification gate incomplete")
                    local_qualification = [row for row in local.get("bound_inputs", [])
                        if row.get("path") == str(QUAL / "report.json")]
                    need(len(local_qualification) == 1
                        and local_qualification[0].get("sha256") == sha(QUAL / "report.json"),
                        "local qualification report binding differs")
                    report["local_gate_sha256"] = sha(local_path)
                    break
            need(time.monotonic() < deadline, "bounded local gate wait expired")
            time.sleep(10)
        source = ROOT / "source"
        need(q["source_tested"] == q["source_after"] == source_map(source), "qualified source mismatch")
        for name, binding in q["binaries"].items():
            need(sha(binding["path"]) == binding["sha256"], "qualified binary mismatch: " + name)
        candidate = Path(q["binaries"]["hepta-runtime"]["path"])
        need(sha(BASELINE) == BASELINE_SHA, "R11 baseline binary differs")
        report["qualification_report_sha256"] = sha(QUAL / "report.json")
        report["candidate_sha256"] = sha(candidate)
        report["baseline_sha256"] = BASELINE_SHA
        report["source_count"] = len(q["source_tested"])
        report["profile_template_sha256"] = sha(PROFILE)
        report["harness_before"] = {p.name: sha(p) for p in sorted(TOOLS.glob("*.py"))}
        need(os.environ.get("SSH_AUTH_SOCK"), "a held current forwarded agent is required")
        native_socket = Path("/home/qian/hepta-r13-ns1")
        native_socket.mkdir(mode=0o700, exist_ok=False)
        native_out = ROOT / "native-r11-r13-01"
        common = ["--profile-template", str(PROFILE), "--frozen-jobs", str(FROZEN)]
        run("native-observation", [sys.executable, "-B", str(TOOLS / "run_native_observation.py"),
            "--baseline", str(BASELINE), "--candidate", str(candidate), *common,
            "--socket-parent", str(native_socket), "--out", str(native_out),
            "--calls", "96", "--concurrency", "1", "4", "8", "--workers", "2",
            "--order", "ABBA", "--warmup-calls", "24"], 1200)
        native = json.loads((native_out / "report.json").read_text())
        need(native.get("passed") is True, "native observation report is not successful")
        run("analyze-native", [sys.executable, "-B", str(TOOLS / "analyze_native_observation.py"),
            "--report", str(native_out / "report.json"), "--output",
            str(native_out / "independent-summary.json")], 60)
        recovery_socket = Path("/home/qian/hepta-r13-cs1")
        recovery_socket.mkdir(mode=0o700, exist_ok=False)
        recovery_out = OLD / "r13-candidate-cancel-recovery-01"
        run("six-host-cancel-recovery", [sys.executable, "-B",
            str(TOOLS / "run_six_host_cancel_recovery.py"), "--candidate", str(candidate),
            *common, "--socket-parent", str(recovery_socket), "--out", str(recovery_out),
            "--workers", "2", "--interrupt-host", "rog"], 600)
        recovery = json.loads((recovery_out / "report.json").read_text())
        need(recovery.get("passed") is True, "recovery report is not successful")
        run("verify-recovery", [sys.executable, "-B", str(TOOLS / "verify_cancel_recovery.py"),
            "--report", str(recovery_out / "report.json"), "--output",
            str(recovery_out / "independent-summary.json")], 60)
        need(q["source_tested"] == source_map(source), "source changed during campaigns")
        need(sha(candidate) == report["candidate_sha256"] and sha(BASELINE) == BASELINE_SHA,
             "runtime changed during campaigns")
        need(report["harness_before"] == {p.name: sha(p) for p in sorted(TOOLS.glob("*.py"))},
             "campaign harness changed")
        need(sha(__file__) == report["script_sha256"], "runner changed")
        report["native_report_sha256"] = sha(native_out / "report.json")
        report["recovery_report_sha256"] = sha(recovery_out / "report.json")
        report["success"] = True
        report["state"] = "completed"
    except BaseException as error:
        report["error"] = {"type": type(error).__name__, "reason": str(error)[:1200]}
        report["state"] = "failed"
    finally:
        report["finished_utc"] = now()
        save()
        print(json.dumps({"success": report["success"], "report": str(out / "report.json"),
                          "error": report.get("error")}), flush=True)
    return 0 if report["success"] else 1

if __name__ == "__main__":
    sys.exit(main())

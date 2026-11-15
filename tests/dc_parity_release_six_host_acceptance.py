#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Qualify one frozen candidate executable on six genuine SSH targets.

Runs existing isolated controller+SSH operator_acceptance.py on independent,
disposable per-target fixtures, never the installed production runtime or DC.
This is local-origin acceptance, never ChatGPT-origin write approval.
"""
import argparse
import concurrent.futures
import datetime
import hashlib
import json
import os
import pathlib
import stat
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
HOSTS = (
    ("main", "localhost"),
    ("pocket4", "pocket4"),
    ("rog", "rog"),
    ("mac", "macbook-pro"),
    ("x230", "x230-ts"),
    ("ai395", "ai395"),
)
PROTECTED = (
    "hepta-runtime-operator.service",
    "desktop-commander-remote.service",
    "hepta-openai-full-operator.service",
)

def digest(path):
    with path.open("rb") as data:
        h = hashlib.sha256()
        for block in iter(lambda: data.read(1024 * 1024), b""):
            h.update(block)
        return h.hexdigest()

def services():
    env = dict(os.environ)
    runtime = f"/run/user/{os.getuid()}"
    env.update(XDG_RUNTIME_DIR=runtime, DBUS_SESSION_BUS_ADDRESS=f"unix:path={runtime}/bus")
    values = {}
    for unit in PROTECTED:
        result = subprocess.run(
            ["systemctl", "--user", "show", unit, "-p", "MainPID", "-p", "ActiveState"],
            capture_output=True, text=True, env=env, timeout=10, check=True)
        fields = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        if not fields.get("MainPID", "0").isdigit():
            raise RuntimeError("unreadable protected service PID")
        values[unit] = fields
    return values

def test_host(name, ssh, binary, receipt_dir):
    path = receipt_dir / f"{name}.json"
    log = receipt_dir / f"{name}.log"
    cmd = [sys.executable, str(ROOT / "tests/operator_acceptance.py"),
           "--binary", str(binary), "--ssh-target", ssh, "--out", str(path)]
    if name == "main":
        cmd.append("--sudo-smoke")
    with log.open("x", encoding="utf-8") as writer:
        p = subprocess.run(cmd, stdout=writer, stderr=subprocess.STDOUT, timeout=360)
    data = json.loads(path.read_text()) if path.exists() else {}
    return {"host": name, "ssh_target": ssh, "exit": p.returncode,
            "passed": data.get("passed"), "complete": data.get("complete", False),
            "receipt": str(path), "log_sha256": digest(log),
            "required_sudo_smoke": name == "main"}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--contract", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--receipt-dir", required=True)
    ap.add_argument("--expected-head", required=True)
    args = ap.parse_args()
    binary = pathlib.Path(args.binary).resolve(strict=True)
    if binary.is_symlink() or not stat.S_ISREG(binary.stat().st_mode) or not os.access(binary, os.X_OK):
        raise ValueError("a real executable candidate file is required")
    source_head = subprocess.check_output(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip()
    if source_head != args.expected_head:
        raise ValueError("head moved; do not mix source and binary receipts")
    contract = pathlib.Path(args.contract).resolve(strict=True)
    tool_catalog = json.loads(contract.read_text())
    if tool_catalog["tool_count"] != 50 or len(tool_catalog["tools"]) != 50:
        raise ValueError("frozen v4 50-tool contract required")
    directory = pathlib.Path(args.receipt_dir)
    directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    baseline = services()
    if any(v.get("ActiveState") != "active" or v.get("MainPID") == "0" for v in baseline.values()):
        raise RuntimeError("refusing acceptance when protective production services are not active")
    report = {
        "schema": "hepta-dc-v4-six-real-target-release-v1",
        "recorded_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source_head": source_head,
        "binary_path": str(binary),
        "binary_sha256": digest(binary),
        "contract_sha256": digest(contract),
        "tool_count": 50,
        "model_origin": False,
        "public_gateway_started": False,
        "runtime_or_DC_restarted": False,
        "protected_services_before": baseline,
        "results": [],
        "complete": False,
    }
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            jobs = {executor.submit(test_host, name, ssh, binary, directory): name
                    for name, ssh in HOSTS}
            for future in concurrent.futures.as_completed(jobs):
                result = future.result()
                report["results"].append(result)
                print("TARGET", result["host"], "exit", result["exit"],
                      "checks", result["passed"], flush=True)
    finally:
        report["protected_services_after"] = services()
        report["service_identity_stable"] = report["protected_services_after"] == baseline
        report["results"].sort(key=lambda row: next(
            i for i, entry in enumerate(HOSTS) if entry[0] == row["host"]))
        report["complete"] = (
            len(report["results"]) == len(HOSTS) and
            all(r["exit"] == 0 and r["complete"] for r in report["results"]) and
            report["service_identity_stable"])
        dest = pathlib.Path(args.out)
        with dest.open("x", encoding="utf-8") as f:
            f.write(json.dumps(report, indent=2) + "\n")
        print("MATRIX_COMPLETE", report["complete"], flush=True)
    if not report["complete"]:
        sys.exit(1)

if __name__ == "__main__":
    main()

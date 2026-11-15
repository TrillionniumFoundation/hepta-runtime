#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run sequential evidence inventory/pack commands and preserve every attempt."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--plan", required=True)
    p.add_argument("--tools-dir", required=True)
    p.add_argument("--run-root", required=True)
    p.add_argument("--stage-root", required=True)
    p.add_argument("--packages", nargs="*")
    a = p.parse_args()
    root = Path(a.run_root)
    root.mkdir(parents=True, exist_ok=False)
    plan_raw = Path(a.plan).read_bytes()
    plan = json.loads(plan_raw)
    selected = [x for x in plan["packages"] if x["state"] == "complete"
                and (not a.packages or x["id"] in a.packages)]
    if a.packages and {x["id"] for x in selected} != set(a.packages):
        raise ValueError("requested package is missing or pending")
    report = {"schema": "hepta-publication-batch/v1", "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "plan_path": a.plan, "plan_sha256": hashlib.sha256(plan_raw).hexdigest(), "packages": [],
              "runtime_workloads_started": False, "builds_started": False, "automatic_retries": 0}
    script = str(Path(a.tools_dir) / "package_x230_evidence.py")
    for package in selected:
        directory = root / package["id"]
        directory.mkdir()
        inventory = directory / "inventory.json"
        stages = []
        commands = [("inventory", [sys.executable, script, "inventory", "--plan", a.plan, "--package", package["id"], "--output", str(inventory)]),
                    ("pack", [sys.executable, script, "pack", "--inventory", str(inventory), "--output-dir", str(Path(a.stage_root) / package["repo_dir"])])]
        for label, command in commands:
            started = time.monotonic()
            stdout, stderr = directory / (label + ".stdout"), directory / (label + ".stderr")
            with stdout.open("xb") as out, stderr.open("xb") as err:
                result = subprocess.run(command, stdout=out, stderr=err, timeout=1800)
            stage = {"name": label, "command": command, "returncode": result.returncode,
                     "seconds": time.monotonic() - started, "stdout": str(stdout), "stderr": str(stderr),
                     "stdout_sha256": hashlib.sha256(stdout.read_bytes()).hexdigest(),
                     "stderr_sha256": hashlib.sha256(stderr.read_bytes()).hexdigest()}
            stages.append(stage)
            print(json.dumps({"package": package["id"], "stage": label, "returncode": result.returncode,
                              "seconds": stage["seconds"]}), flush=True)
            if result.returncode:
                break
        entry = {"id": package["id"], "stages": stages, "passed": len(stages) == 2 and all(s["returncode"] == 0 for s in stages)}
        report["packages"].append(entry)
        (directory / "status.json").write_text(json.dumps(entry, sort_keys=True, indent=2) + "\n")
        (root / "report.in-progress.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    report["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    report["passed"] = bool(selected) and all(x["passed"] for x in report["packages"])
    (root / "report.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"passed": report["passed"], "report": str(root / "report.json"),
                      "failed_packages": [x["id"] for x in report["packages"] if not x["passed"]]}), flush=True)
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()

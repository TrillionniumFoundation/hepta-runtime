#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Record a bounded quiet interval after compilation without changing host policy."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import time

def cpu():
    fields = Path("/proc/stat").read_text().splitlines()[0].split()[1:]
    values = list(map(int, fields[:8]))
    return {"total": sum(values), "idle": values[3], "iowait": values[4]}

def snapshot():
    errors = []
    temperatures = {}
    for path in sorted(Path("/sys/class/thermal").glob("thermal_zone*/temp")):
        try:
            temperatures[str(path.parent.name)] = int(path.read_text().strip()) / 1000
        except (OSError, ValueError) as error:
            errors.append({"sensor": str(path), "error": type(error).__name__})
    available = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        name, value = line.split(":", 1)
        if name in {"MemTotal", "MemAvailable", "SwapTotal", "SwapFree"}:
            available[name + "_kib"] = int(value.split()[0])
    return {"elapsed_seconds": time.monotonic(), "cpu_ticks": cpu(),
            "load_average": list(map(float, Path("/proc/loadavg").read_text().split()[:3])),
            "temperatures_c": temperatures, "memory": available, "sensor_errors": errors}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seconds", type=int, default=60)
    args = parser.parse_args()
    if not 10 <= args.seconds <= 60 or os.path.lexists(args.output):
        parser.error("10..60 seconds and a new output path are required")
    start = time.monotonic()
    samples = []
    while True:
        item = snapshot()
        item["elapsed_seconds"] -= start
        samples.append(item)
        if time.monotonic() - start >= args.seconds:
            break
        time.sleep(max(0.0, min(1, args.seconds - (time.monotonic() - start))))
    first, last = samples[0]["cpu_ticks"], samples[-1]["cpu_ticks"]
    total = last["total"] - first["total"]
    idle = last["idle"] - first["idle"]
    iowait = last["iowait"] - first["iowait"]
    report = {"schema": "hepta-x230-post-build-environment/v1",
        "finished_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "elapsed_seconds": time.monotonic() - start,
        "aggregate_cpu_busy_fraction": (total - idle - iowait) / total if total else None,
        "aggregate_iowait_fraction": iowait / total if total else None,
        "samples": samples, "policy_changes": False,
        "meaning": "Read-only context before measurement; not a stability guarantee or benchmark sample."}
    raw = (json.dumps(report, sort_keys=True, indent=2) + "\n").encode()
    with args.output.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(args.output.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    print(json.dumps({"output": str(args.output), "sha256": hashlib.sha256(raw).hexdigest(),
        "elapsed_seconds": report["elapsed_seconds"],
        "aggregate_cpu_busy_fraction": report["aggregate_cpu_busy_fraction"],
        "last_temperatures_c": samples[-1]["temperatures_c"]}), flush=True)

if __name__ == "__main__":
    main()

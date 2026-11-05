#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Independently recompute saved projection ABBA logs; never execute a benchmark."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import re
import statistics as stats

PREFIX = "OPERATION_PROJECTION_BENCH "


def need(value, message):
    if not value:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def analyze(path):
    raw = path.read_bytes()
    report = json.loads(raw)
    root = path.parent.resolve()
    need(report["schema"] == "hepta-operation-projection-abba/v1" and report["passed"] is True,
         "incomplete or unsupported campaign")
    need(report["automatic_retries"] == report["remote_effects"] == 0
         and report["pins"] == [8, 32]
         and report["order"] == ["owned", "projected", "projected", "owned"], "campaign design differs")
    need(len(report["samples"]) == 16 and 1 <= report["rounds"] <= 4, "sample count/rounds differ")
    snapshot = (root / "fixture-manifest.json").read_bytes()
    need(sha(snapshot) == report["fixture_manifest_sha256"]
         and json.loads(snapshot)["fixtures"] == report["fixtures"], "fixture snapshot differs")
    fixture_hashes = {r["payload"]: r["sha256"] for r in report["fixtures"]}
    need(set(fixture_hashes) == {"plain", "escaped"}, "fixture identities differ")
    groups, seen = {}, set()
    for sample in report["samples"]:
        key = (sample["payload"], sample["pins"], sample["position"])
        need(key not in seen and key[0] in fixture_hashes and key[1] in (8, 32)
             and 0 <= key[2] < 4, "unexpected or duplicate sample")
        seen.add(key)
        need(sample["mode"] == report["order"][key[2]] and sample["returncode"] == 0, "arm or exit differs")
        contents = {}
        for field in ("stdout", "stderr", "native_usage"):
            source = root / sample[field]
            need(source.resolve().is_relative_to(root), "evidence path escaped campaign")
            contents[field] = source.read_bytes()
            need(sha(contents[field]) == sample[field+"_sha256"], "saved evidence digest differs")
        text = contents["stdout"].decode()
        rows = [json.loads(line.split(PREFIX, 1)[1]) for line in text.splitlines() if PREFIX in line]
        need(len(rows) == 1 and re.search(r"test result: ok\. 1 passed; 0 failed; 0 ignored;", text),
             "exact benchmark pass missing")
        result = rows[0]
        need(result == sample["result"] and result["schema"] == "hepta-operation-projection-bench/v1",
             "embedded benchmark result differs from original stdout")
        count = sample["pins"] * report["rounds"]
        need(result["mode"] == sample["mode"] and result["pins"] == sample["pins"]
             and result["rounds"] == report["rounds"] and result["successes"] == count
             and result["failures"] == result["remote_effects"] == 0
             and result["fixture_sha256"] == fixture_hashes[sample["payload"]] == sample["fixture_sha256"],
             "result dimensions or source identity differ")
        for value in (result["wall_seconds"], result["cpu_seconds"]):
            need(math.isfinite(value) and value > 0, "invalid time")
        need(math.isclose(result["calls_per_second"], count/result["wall_seconds"], rel_tol=1e-12)
             and math.isclose(result["cpu_seconds_per_call"], result["cpu_seconds"]/count, rel_tol=1e-12),
             "benchmark reported rate or CPU/call is incorrect")
        fields = contents["native_usage"].decode().strip().split("\t")
        need(len(fields) == 6 and fields[0] == "HEPTA_TIME" and int(fields[5]) == 0, "native usage invalid")
        native = {"wall_seconds": float(fields[1]), "user_seconds": float(fields[2]),
                  "system_seconds": float(fields[3]), "max_rss_kib": int(fields[4]), "exit_code": int(fields[5])}
        need(native == sample["native"] and 0 < native["max_rss_kib"] < 300 * 1024, "usage or budget differs")
        groups.setdefault((sample["payload"], sample["pins"], sample["mode"]), []).append((result, native))
    cases = []
    for payload in ("plain", "escaped"):
        for pins in (8, 32):
            arms = {}
            for mode in ("owned", "projected"):
                rows = groups[(payload, pins, mode)]
                need(len(rows) == 2, "ABBA arm incomplete")
                count = sum(r["successes"] for r, _ in rows)
                arms[mode] = {
                    "processes": 2, "calls": count,
                    "calls_per_second": count / math.fsum(r["wall_seconds"] for r, _ in rows),
                    "cpu_us_per_call": 1e6 * math.fsum(r["cpu_seconds"] for r, _ in rows) / count,
                    "resident_before_kib_median": stats.median(r["resident_before_kib"] for r, _ in rows),
                    "resident_pinned_max_kib_median": stats.median(r["resident_pinned_max_kib"] for r, _ in rows),
                    "native_child_peak_rss_kib_median": stats.median(n["max_rss_kib"] for _, n in rows),
                    "individual_native_peak_rss_kib": [n["max_rss_kib"] for _, n in rows],
                }
            a, b = arms["owned"], arms["projected"]
            metrics = ("calls_per_second", "cpu_us_per_call", "resident_pinned_max_kib_median",
                       "native_child_peak_rss_kib_median")
            cases.append({"payload": payload, "pins": pins, "arms": arms,
                          "change_percent": {k: 100 * (b[k]/a[k]-1) for k in metrics}})
    return {"schema": "hepta-operation-projection-independent-analysis/v1", "verified": True,
            "source_sha256": sha(raw), "binary_sha256": report["binary_sha256"],
            "fixture_manifest_sha256": report["fixture_manifest_sha256"], "cases": cases,
            "measurement_processes": len(report["samples"]),
            "successful_calls": sum(s["result"]["successes"] for s in report["samples"]),
            "failed_calls": 0, "automatic_retries": 0,
            "limitations": [
                "Same qualified candidate binary; owned baseline code path, not an older release.",
                "Local warm receipt decoding/retention; no network or release-server throughput claim.",
                "CPU/rate pooled across two processes per arm; RSS medians of whole-child/current cohort values.",
                "GNU time directly parents Rust; Python wrapper high-water is not used.",
                "Owned fixture pre-read affects process baseline and peak in both arms.",
                "300 MiB is a checked child peak budget, not a hard total process-tree memory bound.",
                "Finite shared-host ABBA does not establish statistical significance or a general memory bound."
            ]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = analyze(args.report)
    with args.output.open("x") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(json.dumps({k: result[k] for k in ("verified", "measurement_processes", "successful_calls")}))


if __name__ == "__main__":
    main()

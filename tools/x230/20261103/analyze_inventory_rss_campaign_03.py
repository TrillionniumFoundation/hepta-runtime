#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Recompute four retained RSS campaign cases; never launch a benchmark."""
import argparse
import gzip
import hashlib
import itertools
import json
import math
from pathlib import Path
import statistics

from analyze_inventory_campaign_02 import canonical, changes, recompute

TIME_SHA = "3b11dec50514a8473e9f6efa7a34d584d0657538c09988f61b72d38ad4991a10"
BENCH = "src/mcp/runtime/jobs_inventory_read_bench.rs"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[3])
    args = parser.parse_args()
    root = args.repo / "tests/evidence/20261103-x230-r11"
    names = {"plain": "inventory-rss-plain.json.gz", "escaped": "inventory-rss-escaped.json.gz",
             "campaign": "inventory-rss-campaign-03.json.gz"}
    raw = {key: gzip.decompress((root / name).read_bytes()) for key, name in names.items()}
    reports = {key: json.loads(value) for key, value in raw.items()}
    campaign = reports["campaign"]
    assert campaign["passed"] and len(campaign["stages"]) == 2
    assert all(stage["returncode"] == 0 for stage in campaign["stages"])
    assert campaign["baseline_matches_r10e_except_identical_benchmark_module"]
    assert campaign["candidate_compiler_inputs_match_qualification"]
    qraw = gzip.decompress((root / "r11-qualification.json.gz").read_bytes())
    qualification = json.loads(qraw)
    assert sha(qraw) == campaign["candidate_qualification_sha256"]
    assert qualification["qualified"]
    source = qualification["source_tested"]
    assert len(source) == 213 and source == qualification["source_after"]
    assert all(sha((args.repo / name).read_bytes()) == digest for name, digest in source.items())
    comparisons = {"numeric_fields": 0, "maximum_absolute_difference": 0.0}

    def compare(actual, expected):
        if isinstance(actual, dict):
            assert set(actual) == set(expected)
            for key in actual:
                compare(actual[key], expected[key])
        elif isinstance(actual, list):
            assert len(actual) == len(expected)
            for left, right in zip(actual, expected):
                compare(left, right)
        elif isinstance(actual, (float, int)) and not isinstance(actual, bool):
            comparisons["numeric_fields"] += 1
            comparisons["maximum_absolute_difference"] = max(
                comparisons["maximum_absolute_difference"], abs(actual - expected))
            assert math.isclose(actual, expected, rel_tol=1e-12, abs_tol=1e-9)
        else:
            assert actual == expected

    receipts, cases, increases = [], [], []
    total_calls = total_samples = 0
    variants = reports["plain"]["variants"]
    for style in ("plain", "escaped"):
        report = reports[style]
        assert report["passed"] and report["automatic_retries"] == 0
        assert report["rss_measurement"] == "gnu_time_direct_child"
        assert report["order_per_case"] == "ABBA" and report["calls_per_worker"] == 2
        assert report["temporary_fixtures_removed"] and report["payload_style"] == style
        assert len(report["samples"]) == 8 and len(report["enumerations"]) == 2
        assert report["variants"] == variants
        assert report["runner_sha256"] == sha((args.repo / "tools/x230/20261103/run_inventory_read_abba.py").read_bytes())
        assert report["native_rss_launcher"] == {
            "path": "/usr/bin/time", "sha256": TIME_SHA,
            "usage_format": '{"maxrss_kib":%M,"exit_code":%x}'}
        assert variants["A"]["source_map"][BENCH] == variants["B"]["source_map"][BENCH]
        assert all(source[name] == digest for name, digest in variants["B"]["source_map"].items())
        for fixture in report["fixtures"].values():
            manifest = fixture["manifest"]
            assert sha(canonical(manifest)) == fixture["manifest_sha256"]
            assert len(manifest["files"]) == manifest["records"] == 128
            assert fixture["bytes"] == sum(entry["bytes"] for entry in manifest["files"].values())
            assert fixture["bytes"] < report["fixture_source_byte_limit"]
        processes = report["enumerations"] + [sample["process"] for sample in report["samples"]]
        for process in processes:
            assert process["exit_code"] == 0 and not process["timed_out"] and not process["interrupted"]
            assert not process["signals"] and process["original_child_reaped"]
            assert process["stderr"]["bytes"] == 0
            native = process["native_rss"]
            assert native["source"] == "gnu_time_direct_child" and native["launcher_path"] == "/usr/bin/time"
            assert native["launcher_sha256"] == native["launcher_sha256_before"] == native["launcher_sha256_after"] == TIME_SHA
            usage_bytes = native["usage_text"].encode("utf-8")
            assert len(usage_bytes) == native["usage"]["bytes"]
            assert sha(usage_bytes) == native["usage"]["sha256"]
            assert json.loads(usage_bytes) == {"maxrss_kib": native["maxrss_kib"], "exit_code": 0}
            assert native["exit_code"] == 0
            assert process["launcher_argv"][:2] == ["/usr/bin/time", "-o"]
            assert process["launcher_argv"][3:6] == ["-f", native["usage_format"], "--"]
            assert process["launcher_argv"][6:] == process["argv"]
            receipts.append({"style": style, **native["usage"], "maxrss_kib": native["maxrss_kib"], "exit_code": 0})
        grouped = {}
        for sample in report["samples"]:
            block, process = sample["benchmark"], sample["process"]
            assert sample["executed"] and sample["passed"]
            assert sample["concurrency"] == block["concurrency"] == 4
            assert block["successes"] == 8 and block["failures"] == block["remote_effects"] == 0
            assert block["physical_read_workers"] == 4 and block["tokio_workers"] == 2
            assert block["fixture_unchanged"] and block["public_identity_checked_each_call"]
            fixture = report["fixtures"][str(sample["payload_bytes"])]
            assert block["fixture_sha256"] == fixture["manifest_sha256"]
            assert block["fixture_bytes"] == fixture["bytes"] and block["records"] == 128
            assert [(v["worker"], v["call"]) for v in block["latencies"]] == list(itertools.product(range(4), range(2)))
            early, final = block["process_lifetime_maxrss_kib"], process["native_rss"]["maxrss_kib"]
            assert early <= final
            if early < final:
                increases.append({"style": style, "sample_index": sample["index"], "early_kib": early, "final_kib": final})
            grouped.setdefault(sample["mode"], []).append(sample)
            total_calls += block["successes"]
            total_samples += 1
        assert set(grouped) == {"list", "page"}
        for mode, members in grouped.items():
            assert [sample["arm"] for sample in members] == list("ABBA")
            assert len({sample["benchmark"]["response_sha256"] for sample in members}) == 1
            arms = {}
            for arm in ("A", "B"):
                samples = [sample for sample in members if sample["arm"] == arm]
                values = recompute(samples)
                peaks = [sample["process"]["native_rss"]["maxrss_kib"] for sample in samples]
                values["wrapper_wait4_maxrss_kib"] = values["whole_child_maxrss_kib"]
                values["whole_child_maxrss_kib"] = peaks
                values["median_whole_child_maxrss_kib"] = statistics.median(peaks)
                values["rss_source"] = "gnu_time_direct_child"
                arms[arm] = values
            case = {"mode": mode, "payload_bytes": members[0]["payload_bytes"],
                    "payload_style": style, "concurrency": 4, "arms": arms,
                    "candidate_change": changes(arms["A"], arms["B"])}
            compare(case, next(entry for entry in report["statistics"] if entry["mode"] == mode))
            cases.append(case)
    assert len(cases) == 4 and total_samples == 16 and total_calls == 128 and len(receipts) == 20
    summary = {
        "schema": "hepta-r11-inventory-rss-independent-analysis/v1", "passed": True,
        "cases": cases, "totals": {"cases": 4, "measurement_children": 16, "calls": 128,
                                   "enumeration_children": 4, "verified_usage_receipts": 20},
        "statistics_comparison": comparisons,
        "compiler_inputs": {"qualified_and_after_and_local_equal": True, "count": 213,
                            "observed_candidate_map_count": len(variants["B"]["source_map"])},
        "launcher_sha256": TIME_SHA,
        "variants": {arm: {"binary_sha256": variant["sha256"], "source_map_count": len(variant["source_map"])}
                     for arm, variant in variants.items()},
        "matching_libtest_profiles": campaign["matching_libtest_profiles"],
        "benchmark_module_sha256": variants["A"]["source_map"][BENCH],
        "raw_inputs": {key: {"file": names[key], "raw_sha256": sha(value),
                             "gzip_sha256": sha((root / names[key]).read_bytes())} for key, value in raw.items()},
        "native_usage_receipts": receipts, "early_to_final_peak_increases": increases,
        "environment": {key: campaign[key] for key in ("before", "after")},
        "scope": ["GNU time RSS is the direct libtest child lifetime peak, including fixture verification and warmup.",
                  "CPU, wall and latency retain the Rust timed intervals; wrapper wait4 is retained but excluded from child RSS aggregation.",
                  "Two processes and sixteen calls per arm per case; descriptive observations, not significance claims.",
                  "Campaign 02 CPU/rate evidence remains unchanged; its wrapper RSS has an inherited parent floor.",
                  "Plain 768 KiB improves RSS; escaped 64 KiB regresses RSS in both modes. No universal memory reduction."]}
    output = root / "inventory-rss-campaign-03-summary.json"
    output.write_text(json.dumps(summary, indent=2) + "\n")
    lines = ["# Inventory RSS campaign 03: independent recomputation", "",
             "All 16 retained measurement samples reproduce the runner statistics; 128 successful calls, four cases, ABBA order. All 20 GNU time receipts (including four enumeration children) pass text/hash/exit checks. The qualified 213 compiler inputs equal the after map and local source. No benchmark was launched by this analyzer.", "",
             "A is R10e with the identical benchmark module; B is the qualified R11 candidate. RSS is the median of two direct-child lifetime peaks per arm, in KiB. CPU and calls/s use the existing Rust timed interval. Percent changes are B/A − 1.", "",
             "| Payload / C4 | Mode | RSS A → B KiB | Δ RSS | CPU A → B ms/call | Δ CPU | Calls/s A → B | Δ calls/s |",
             "|---|---|---:|---:|---:|---:|---:|---:|"]
    for case in cases:
        a, b, d = case["arms"]["A"], case["arms"]["B"], case["candidate_change"]
        lines.append(f'| {case["payload_style"]} {case["payload_bytes"] // 1024} KiB | {case["mode"]} | '
                     f'{a["median_whole_child_maxrss_kib"]:.0f} → {b["median_whole_child_maxrss_kib"]:.0f} | {d["median_whole_child_maxrss_kib_percent"]:+.2f}% | '
                     f'{a["cpu_ms_per_call"]:.3f} → {b["cpu_ms_per_call"]:.3f} | {d["cpu_ms_per_call_percent"]:+.2f}% | '
                     f'{a["calls_per_second"]:.3f} → {b["calls_per_second"]:.3f} | {d["calls_per_second_percent"]:+.2f}% |')
    lines += ["", "| Payload / C4 | Mode | Direct peaks A KiB | Direct peaks B KiB | p50 A → B ms | p95 A → B ms |",
              "|---|---|---|---|---:|---:|"]
    for case in cases:
        a, b = case["arms"]["A"], case["arms"]["B"]
        lines.append(f'| {case["payload_style"]} {case["payload_bytes"] // 1024} KiB | {case["mode"]} | '
                     f'{a["whole_child_maxrss_kib"]} | {b["whole_child_maxrss_kib"]} | '
                     f'{a["p50_ms"]:.3f} → {b["p50_ms"]:.3f} | {a["p95_ms"]:.3f} → {b["p95_ms"]:.3f} |')
    lines += ["", "## Limits and regressions", "",
              "Plain 768 KiB RSS falls 17.42% for list and 10.51% for page. Escaped 64 KiB RSS rises 2.06% and 1.89%. Escaped list calls/s falls 6.43% and its p50 rises 10.38%; plain list p50 rises 0.56%. These results do not support universal improvement. With sixteen latencies per arm, nearest-rank p95 equals the maximum.", "",
              "RSS includes fixture verification, warmup, measurement and teardown. Twelve final GNU time peaks exceed the earlier Rust snapshot by 128–384 KiB. Wrapper wait4 floors remain 25,572 KiB (plain) and 20,916 KiB (escaped); those values are retained for audit and excluded from native RSS aggregation.", "",
              "The before/after snapshots retain cargo PID 1950444 and no rustc entry; this was not a background-free host. Thermal readings changed from 68/69 °C to 74/71 °C. Endpoint observations are not continuous monitoring. The small ABBA sample is descriptive and does not establish statistical significance or a production TPS result.", "",
              "The earlier campaign 02 CPU/rate/latency results are unchanged. Its wrapper RSS comparison cannot establish direct-child memory behavior because of the demonstrated inherited RSS floor. This four-case follow-up changes neither the qualified Rust source nor the CPU/wall timing boundaries.", "",
              "## Reproduce from retained evidence", "",
              "From the repository root: `python3 -B tools/x230/20261103/analyze_inventory_rss_campaign_03.py`.", "",
              "Inputs: [plain](inventory-rss-plain.json.gz), [escaped](inventory-rss-escaped.json.gz), [campaign](inventory-rss-campaign-03.json.gz), [qualification](r11-qualification.json.gz). Complete values, usage hashes, raw hashes and environment: [summary](inventory-rss-campaign-03-summary.json). RSS floor evidence: [probe](rss-floor-probe.json.gz).", ""]
    table = root / "inventory-rss-campaign-03-tables.md"
    table.write_text("\n".join(lines))
    print(json.dumps({"passed": True, "comparison": comparisons, "files": [
        {"path": str(path.relative_to(args.repo)), "bytes": path.stat().st_size, "sha256": sha(path.read_bytes())}
        for path in (output, table, Path(__file__))]}, indent=2))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Independently audit retained R11 inventory samples without running a benchmark."""
import argparse
import gzip
import hashlib
import itertools
import json
import math
from pathlib import Path
import statistics

BENCH = "src/mcp/runtime/jobs_inventory_read_bench.rs"
KEYS = ("calls_per_second", "cpu_ms_per_call", "p50_ms", "p95_ms", "median_whole_child_maxrss_kib")


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def quantile(values, fraction):
    ordered = sorted(values)
    return ordered[max(0, math.ceil(fraction * len(ordered)) - 1)]


def changes(first, second):
    return {key + "_percent": 100 * (second[key] / first[key] - 1) if first[key] else None for key in KEYS}


def recompute(members):
    blocks = [row["benchmark"] for row in members]
    count = sum(block["successes"] for block in blocks)
    wall = math.fsum(block["wall_seconds"] for block in blocks)
    cpu = math.fsum(block["user_cpu_seconds"] + block["system_cpu_seconds"] for block in blocks)
    latencies = [value["latency_ms"] for block in blocks for value in block["latencies"]]
    rss = [row["process"]["wait4"]["maxrss_kib"] for row in members]
    return {
        "processes": len(members), "calls": count, "wall_seconds": wall,
        "calls_per_second": count / wall, "cpu_ms_per_call": 1000 * cpu / count,
        "p50_ms": quantile(latencies, 0.50), "p95_ms": quantile(latencies, 0.95),
        "max_ms": max(latencies), "whole_child_maxrss_kib": rss,
        "median_whole_child_maxrss_kib": statistics.median(rss),
    }


def label(case):
    return f'{case["payload_style"]} {case["payload_bytes"] // 1024}KiB {case["mode"]} C{case["concurrency"]}'


def table(cases):
    lines = [
        "| Payload | Mode | C | CPU ms/call A → B | Calls/s A → B | RSS median KiB A → B | p50 ms A → B | p95 ms A → B |",
        "|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    for row in cases:
        a, b = row["arms"]["A"], row["arms"]["B"]
        pair = lambda key, digits=3: f'{a[key]:.{digits}f} → {b[key]:.{digits}f}'
        lines.append(
            f'| {row["payload_style"]} {row["payload_bytes"] // 1024} KiB | {row["mode"]} | {row["concurrency"]} | '
            + " | ".join([pair("cpu_ms_per_call"), pair("calls_per_second", 2),
                          pair("median_whole_child_maxrss_kib", 0), pair("p50_ms"), pair("p95_ms")]) + " |"
        )
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--download-manifest", type=Path)
    args = parser.parse_args()
    root = args.evidence
    raw = {name: gzip.decompress((root / file).read_bytes()) for name, file in
           [("plain", "inventory-plain.json.gz"), ("escaped", "inventory-escaped.json.gz"),
            ("campaign", "inventory-campaign-02.json.gz")]}
    reports = {key: json.loads(value) for key, value in raw.items()}
    campaign = reports["campaign"]
    assert campaign["passed"] is True and all(s["returncode"] == 0 for s in campaign["stages"])
    assert campaign["baseline_matches_r10e_except_identical_benchmark_module"] is True
    assert campaign["candidate_compiler_inputs_match_qualification"] is True
    assert campaign["matching_libtest_profiles"] == {
        "opt_level": "1", "debuginfo": 0, "debug_assertions": True, "overflow_checks": True, "test": True
    }
    checks = {"numeric_fields_compared": 0, "maximum_absolute_difference": 0.0, "mismatches": []}

    def compare(actual, expected, path):
        if isinstance(actual, dict):
            assert set(actual) == set(expected), path
            for key in actual:
                compare(actual[key], expected[key], path + "." + key)
        elif isinstance(actual, list):
            assert len(actual) == len(expected), path
            for index, (left, right) in enumerate(zip(actual, expected)):
                compare(left, right, path + f"[{index}]")
        elif isinstance(actual, (int, float)) and not isinstance(actual, bool):
            delta = abs(actual - expected)
            checks["numeric_fields_compared"] += 1
            checks["maximum_absolute_difference"] = max(checks["maximum_absolute_difference"], delta)
            if not math.isclose(actual, expected, rel_tol=1e-12, abs_tol=1e-9):
                checks["mismatches"].append({"path": path, "actual": actual, "runner": expected})
        else:
            assert actual == expected, path

    cases, total_calls, total_samples, regression_rows = [], 0, 0, []
    rss_endpoint_differences = []
    fixture_count = 0
    per_style = {}
    variants = None
    for style in ("plain", "escaped"):
        report = reports[style]
        assert report["passed"] is True and report["automatic_retries"] == 0
        assert report["payload_style"] == style and report["order_per_case"] == "ABBA"
        assert report["calls_per_worker"] == 2 and report["temporary_fixtures_removed"] is True
        assert report["variants"]["A"]["source_map"][BENCH] == report["variants"]["B"]["source_map"][BENCH]
        if variants is None:
            variants = report["variants"]
        else:
            assert variants == report["variants"]
        for fixture in report["fixtures"].values():
            manifest = fixture["manifest"]
            assert fixture["manifest_sha256"] == hashlib.sha256(canonical(manifest)).hexdigest()
            assert len(manifest["files"]) == manifest["records"] == 128
            assert fixture["bytes"] == sum(item["bytes"] for item in manifest["files"].values())
            assert fixture["bytes"] < report["fixture_source_byte_limit"]
            fixture_count += 1
        expected_cases = set(itertools.product(["list", "page"], [1024, 65536, 786432], [1, 4, 8])) if style == "plain" else {("list", 65536, 4), ("page", 65536, 4)}
        grouped = {}
        style_calls = 0
        assert [s["index"] for s in report["samples"]] == list(range(len(report["samples"])))
        for sample in report["samples"]:
            key = sample["mode"], sample["payload_bytes"], sample["concurrency"]
            grouped.setdefault(key, []).append(sample)
            assert sample["executed"] is True and sample["passed"] is True
            assert sample["payload_style"] == style
            process, block = sample["process"], sample["benchmark"]
            assert process["exit_code"] == 0 and process["timed_out"] is False and not process["interrupted"]
            assert process["signals"] == [] and process["original_child_reaped"] is True
            assert process["stderr"]["bytes"] == 0
            assert process["argv"][0] == report["variants"][sample["arm"]]["binary"]
            assert (block["mode"], block["payload_bytes"], block["concurrency"]) == key
            assert block["calls_per_worker"] == 2 and block["successes"] == sample["concurrency"] * 2
            assert block["records"] == 128 and block["failures"] == block["remote_effects"] == 0
            assert block["physical_read_workers"] == 4 and block["tokio_workers"] == 2
            assert block["fixture_unchanged"] is True and block["public_identity_checked_each_call"] is True
            fixture = report["fixtures"][str(sample["payload_bytes"])]
            assert block["fixture_sha256"] == fixture["manifest_sha256"]
            assert block["fixture_bytes"] == fixture["bytes"]
            assert block["process_lifetime_maxrss_kib"] <= process["wait4"]["maxrss_kib"]
            if block["process_lifetime_maxrss_kib"] != process["wait4"]["maxrss_kib"]:
                rss_endpoint_differences.append({"style": style, "sample_index": sample["index"],
                    "arm": sample["arm"], "mode": sample["mode"], "payload_bytes": sample["payload_bytes"],
                    "concurrency": sample["concurrency"], "in_process_maxrss_kib": block["process_lifetime_maxrss_kib"],
                    "wait4_maxrss_kib": process["wait4"]["maxrss_kib"]})
            assert [(x["worker"], x["call"]) for x in block["latencies"]] == list(itertools.product(range(sample["concurrency"]), range(2)))
            numeric = [block[x] for x in ("wall_seconds", "user_cpu_seconds", "system_cpu_seconds")]
            numeric += [x["latency_ms"] for x in block["latencies"]]
            assert all(isinstance(x, (int, float)) and math.isfinite(x) and x >= 0 for x in numeric)
            assert block["wall_seconds"] > 0
            style_calls += block["successes"]
        assert set(grouped) == expected_cases
        runner_cases = {(c["mode"], c["payload_bytes"], c["concurrency"]): c for c in report["statistics"]}
        assert set(runner_cases) == expected_cases
        for key, samples in grouped.items():
            assert [s["arm"] for s in samples] == list("ABBA")
            assert len({s["benchmark"]["response_sha256"] for s in samples}) == 1
            assert len({s["benchmark"]["fixture_sha256"] for s in samples}) == 1
            arms = {arm: recompute([s for s in samples if s["arm"] == arm]) for arm in "AB"}
            computed = {"mode": key[0], "payload_bytes": key[1], "payload_style": style,
                        "concurrency": key[2], "arms": arms, "candidate_change": changes(arms["A"], arms["B"])}
            compare(computed, runner_cases[key], style + "/" + str(key))
            blocks = []
            for sample in samples:
                metrics = recompute([sample])
                blocks.append({"index": sample["index"], "arm": sample["arm"], "pid": sample["process"]["pid"], **metrics})
            regressions = {k: v for k, v in computed["candidate_change"].items()
                           if v is not None and (v < 0 if k == "calls_per_second_percent" else v > 0)}
            row = {**computed, "order": "ABBA", "response_sha256": samples[0]["benchmark"]["response_sha256"],
                   "fixture_sha256": samples[0]["benchmark"]["fixture_sha256"],
                   "fixture_bytes": samples[0]["benchmark"]["fixture_bytes"], "sample_metrics": blocks,
                   "directional_regressions": regressions}
            row["within_arm_calls_per_second_range"] = {
                arm: {"min": min(x["calls_per_second"] for x in blocks if x["arm"] == arm),
                      "max": max(x["calls_per_second"] for x in blocks if x["arm"] == arm)}
                for arm in "AB"}
            row["within_arm_calls_per_second_range_percent_of_min"] = {
                arm: 100 * (value["max"] / value["min"] - 1)
                for arm, value in row["within_arm_calls_per_second_range"].items()}
            cases.append(row)
            if regressions:
                regression_rows.append({"case": label(row), "changes_percent": regressions})
        per_style[style] = {"cases": len(grouped), "samples": len(report["samples"]), "calls": style_calls,
                            "report_elapsed_seconds": report["elapsed_seconds"],
                            "wall_scope": report["latency_note"], "rss_scope": report["rss_note"],
                            "cpu_scope": report["cpu_note"]}
        total_calls += style_calls
        total_samples += len(report["samples"])
    assert len(cases) == 20 and total_samples == 80 and total_calls == 688
    assert checks["mismatches"] == []
    assert variants["A"]["sha256"] == "cd5e73d1df2a6def1385dd6699711ffeeeef78feea3ae7e2e0106fc360e26597"
    assert variants["B"]["sha256"] == "664e821762647be2bea2224aa566be2fb9d9983131c77af22f6f085cb556668b"
    assert variants["A"]["source_map"][BENCH] == "e0bd1eb185404122773c11415413e631d21bd04970ed1fb2764d654bdd3d1f56"
    qualified = json.loads(gzip.decompress((root / "r11-qualification.json.gz").read_bytes()))
    assert hashlib.sha256(gzip.decompress((root / "r11-qualification.json.gz").read_bytes())).hexdigest() == campaign["candidate_qualification_sha256"]
    assert all(qualified["source_tested"][path] == digest for path, digest in variants["B"]["source_map"].items())
    qualified_tests = json.loads((root / "r11-isolated-summary.json").read_text())
    assert any(binary["sha256"] == variants["B"]["sha256"] for binary in qualified_tests["binaries"])
    metric_counts = {}
    for metric in KEYS:
        values = [c["candidate_change"][metric + "_percent"] for c in cases]
        metric_counts[metric] = {"increased": sum(v > 0 for v in values), "equal": sum(v == 0 for v in values),
                                 "decreased": sum(v < 0 for v in values), "min_percent": min(values), "max_percent": max(values)}
    widest = sorted([{"case": label(c), "arm": arm, "spread_percent_of_min": value}
                     for c in cases for arm, value in c["within_arm_calls_per_second_range_percent_of_min"].items()],
                    key=lambda row: row["spread_percent_of_min"], reverse=True)
    notes = [
        "CPU ms/call = 1000 * sum(measured user+system CPU deltas) / sum(successful calls) over both processes of each arm.",
        "Calls/s = sum(successful calls) / sum(measured wall seconds); it is not the median of per-process throughputs.",
        "p50/p95 use the nearest-rank quantile over all raw call latencies of an arm, not a percentile of process medians.",
        "RSS is the median of two wait4 whole-child maximum-RSS values in Linux KiB; includes fixture checks/warmup and is not measurement-only or retained heap.",
        "Two plain 768 KiB list C8 baseline samples have wait4 maxrss 128 KiB above the earlier in-process high-water reading. All comparisons consistently use wait4, not a mixture of those endpoints.",
        "20 cases, only two processes per arm/case. C1/C4/C8 have 4/16/32 call latencies per arm; C1 and C4 p95 is the observed maximum.",
        "Warm fixture hash checks and a warmup precede timing. No cold-disk, disk-write, SSH, six-host, or full MCP throughput claim.",
        "Campaign endpoint snapshots both contain cargo PID 1950444, with no rustc entry. They are not proof of an idle machine or continuous absence of compiler work.",
        "Temperatures increased from 65/69 C to 74/73 C at the observed endpoints. Only endpoint environment observations are retained.",
        "Fixture bytes are no longer present after the campaign. This audit checks canonical manifest hashes and every sample's retained before/after verification, not a new read of deleted fixtures.",
        "Child stdout/stderr digests are retained in source reports; this audit operates on their retained parsed benchmark blocks, not separately downloaded stdout files.",
    ]
    summary = {
        "schema": "hepta-r11-inventory-independent-summary/v1", "audit_passed": True,
        "recommendation": "Retain R11 for the measured large-plain-payload CPU/read-projection benefit, while retaining every regression and making no universal throughput or material RSS-reduction claim. Native multi-host results remain a separate decision input.",
        "raw_reports": {key: {"bytes": len(value), "sha256": hashlib.sha256(value).hexdigest()} for key, value in raw.items()},
        "download_manifest": json.loads(args.download_manifest.read_text()) if args.download_manifest else None,
        "totals": {"cases": len(cases), "samples": total_samples, "successful_calls": total_calls,
                   "failed_calls": 0, "automatic_retries": 0, "canonical_fixture_manifests_checked": fixture_count},
        "per_style": per_style, "runner_statistics_comparison": checks,
        "rss_endpoint_differences": rss_endpoint_differences,
        "builds": {"baseline_sha256": variants["A"]["sha256"], "candidate_sha256": variants["B"]["sha256"],
                   "benchmark_sha256": variants["A"]["source_map"][BENCH],
                   "matching_profiles_recorded_in_campaign": campaign["matching_libtest_profiles"],
                   "candidate_source_entries_checked_against_qualification": len(variants["B"]["source_map"])},
        "environment": {"before": campaign["before"], "after": campaign["after"]},
        "metric_direction_counts": metric_counts, "directional_regressions": regression_rows,
        "largest_within_arm_throughput_spreads": widest, "interpretation_notes": notes, "cases": cases,
    }
    (root / "inventory-campaign-02-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    lines = [
        "# R11 inventory campaign 02 — independent recomputation", "",
        "**Recommendation:** retain the measured large-payload read/projection changes; do not claim every workload is faster or that RSS materially falls.",
        "This is local warm-inventory evidence from matching libtest profiles, not release-binary, SSH, six-host, or full MCP throughput.", "",
        f"Verified: **20 cases, 80 executed sample processes, 688 successful measured calls, 0 failed calls, 0 automatic retries**. Plain: 18/72/624; escaped: 2/8/64.",
        f"All ABBA orders, within-case response hashes, fixture manifest hashes, fixture-unchanged flags, raw latency identities, process exits, and wait4 RSS >= in-process sampled high-water checks agree.",
        f"Independent recomputation matched all {checks['numeric_fields_compared']} numeric runner-statistic fields (max absolute difference {checks['maximum_absolute_difference']:.12g}; tolerance 1e-12 relative / 1e-9 absolute).", "",
        "A = immutable R10e behavior plus the identical benchmark module; B = qualified R11. CPU and throughput aggregate both arm processes; RSS is their whole-child peak median.",
        f"- A binary: `{variants['A']['sha256']}`.",
        f"- B binary: `{variants['B']['sha256']}`.",
        f"- Identical benchmark module: `{variants['A']['source_map'][BENCH]}`.",
        "- Profile recorded equal: opt-level 1, debuginfo 0, debug assertions and overflow checks on, test=true.", "",
        "## C4 emphasis", "", table([c for c in cases if c["concurrency"] == 4]), "",
        "## All 20 cases", "", table(cases), "",
        "## Every directional regression", "",
        "These are descriptive differences, including sub-percent movements; two processes per arm do not establish statistical significance.", "",
        "| Case | Regressed metric(s), candidate change |", "|---|---|",
    ]
    display = {"calls_per_second_percent": "calls/s", "cpu_ms_per_call_percent": "CPU/call",
               "p50_ms_percent": "p50", "p95_ms_percent": "p95", "median_whole_child_maxrss_kib_percent": "RSS"}
    for row in regression_rows:
        lines.append("| " + row["case"] + " | " + "; ".join(f"{display[k]} {v:+.3f}%" for k, v in row["changes_percent"].items()) + " |")
    lines += ["", "## Noise and scope", ""]
    lines += ["- " + text for text in notes]
    lines += ["", "Largest within-arm throughput spreads (max/min - 1; only two process observations):", ""]
    lines += [f"- {row['case']}, arm {row['arm']}: {row['spread_percent_of_min']:.2f}%." for row in widest[:5]]
    lines += [
        "", "CPU/call decreased in 18/20 cases; throughput increased in 17/20. RSS was identical in 19/20, with only a 1.50% decrease for plain 768 KiB list C8.",
        "For all six plain 768 KiB cases CPU/call decreased 16.45–20.27%, while calls/s increased 9.38–23.37%.",
        "The clearest throughput regressions are plain 64 KiB list C8 (-9.60%, p95 +37.37%) and page C4 (-6.56%), despite lower measured CPU/call.",
        "The escaped 64 KiB diagnostic retains owned-string fallback: list C4 shows CPU -2.66%, calls/s +2.20%, p95 +0.80%; page C4 shows CPU -6.84%, calls/s +27.11%.",
        "Large wall changes with small CPU changes are sensitive to scheduling/background conditions. The cargo process and temperature drift must remain visible.", "",
        "## Retained inputs", "",
        "- [Plain original report, lossless gzip](inventory-plain.json.gz)",
        "- [Escaped original report, lossless gzip](inventory-escaped.json.gz)",
        "- [Campaign environment/commands, lossless gzip](inventory-campaign-02.json.gz)",
        "- [Complete independent 20-case summary](inventory-campaign-02-summary.json)", "",
    ]
    (root / "inventory-campaign-02-tables.md").write_text("\n".join(lines))
    print(json.dumps({key: summary[key] for key in ("totals", "runner_statistics_comparison", "metric_direction_counts", "directional_regressions")}, indent=2))
    print("LARGEST_SPREADS", json.dumps(widest[:5]))
    print("C4_TABLE\n" + table([c for c in cases if c["concurrency"] == 4]))


if __name__ == "__main__":
    main()

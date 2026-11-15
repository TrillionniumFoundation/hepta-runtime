#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Validate every ABBA cell before comparing actual receipt encoder costs."""

import argparse
import hashlib
import json
import math
import statistics
from pathlib import Path


def stats(values):
    assert values and all(math.isfinite(v) and v >= 0 for v in values)
    return {
        "samples": len(values),
        "median": statistics.median(values),
        "minimum": min(values),
        "maximum": max(values),
        "mean": statistics.mean(values),
        "stdev": statistics.stdev(values) if len(values) > 1 else 0.0,
    }


def percentage(before, after):
    assert before > 0
    return 100.0 * (after / before - 1.0)


def analyze(source):
    encoded = source.read_bytes()
    result = json.loads(encoded)
    assert result["schema"] in {
        "hepta-bounded-receipt-encoding-v1", "hepta-reserved-receipt-encoding-v1"
    }
    flag = "reserved" if result["schema"] == "hepta-reserved-receipt-encoding-v1" else "bounded"
    sizes = [1024, 65536, 786432, 4194304 - 32]
    cases = [(size, escaped) for size in sizes for escaped in [False, True]]
    pure = result["pure_rows"]
    durable = result["durable_rows"]
    buffers = result["buffer_rows"]
    assert len(pure) == 96 and len(durable) == 64 and len(buffers) == 16
    for rows, cycles in [(pure, 3), (durable, 2)]:
        expected = {
            (size, escaped, cycle, position, bounded)
            for size, escaped in cases
            for cycle in range(cycles)
            for position, bounded in enumerate([False, True, True, False])
        }
        observed = [
            (r["size"], r["escaped"], r["cycle"], r["position"], r[flag])
            for r in rows
        ]
        assert len(set(observed)) == len(observed)
        assert set(observed) == expected
        assert all(type(r[flag]) is bool for r in rows)
        assert all(type(r["escaped"]) is bool for r in rows)
        assert all(r["wall_seconds"] > 0 and r["cpu_seconds"] > 0 for r in rows)
    for row in pure:
        iterations = {1024: 512, 65536: 64, 786432: 8, 4194272: 3}[row["size"]]
        assert row["iterations"] == iterations
        assert math.isclose(
            row["cpu_seconds_per_call"], row["cpu_seconds"] / iterations,
            rel_tol=1e-12,
        )
    summaries = []
    for size, escaped in cases:
        item = {"size": size, "escaped": escaped}
        for bounded, name in [(False, "original"), (True, flag)]:
            match = lambda row: (
                row["size"] == size and row["escaped"] == escaped
                and row[flag] == bounded
            )
            cpu_rows = [row for row in pure if match(row)]
            durable_rows = [row for row in durable if match(row)]
            buffer_rows = [row for row in buffers if match(row)]
            assert len(buffer_rows) == 1
            buffer = buffer_rows[0]
            assert buffer["length"] == size
            assert buffer["final_vec_capacity"] >= size
            assert len(buffer["encoded_sha256"]) == 64
            item[name] = {
                "cpu_us_per_call": stats([
                    1e6 * row["cpu_seconds"] / row["iterations"] for row in cpu_rows
                ]),
                "wall_us_per_call": stats([
                    1e6 * row["wall_seconds"] / row["iterations"] for row in cpu_rows
                ]),
                "durable_cpu_ms": stats([1e3 * row["cpu_seconds"] for row in durable_rows]),
                "durable_wall_ms": stats([1e3 * row["wall_seconds"] for row in durable_rows]),
                "final_vec_capacity": buffer["final_vec_capacity"],
                "measured_capacity_above_encoded_limit": buffer["final_vec_capacity"] > 4194304,
                "encoded_sha256": buffer["encoded_sha256"],
            }
        assert item["original"]["encoded_sha256"] == item[flag]["encoded_sha256"]
        item["change_percent"] = {
            metric: percentage(item["original"][metric]["median"], item[flag][metric]["median"])
            for metric in ["cpu_us_per_call", "wall_us_per_call", "durable_cpu_ms", "durable_wall_ms"]
        }
        item["change_percent"]["final_vec_capacity"] = percentage(
            item["original"]["final_vec_capacity"], item[flag]["final_vec_capacity"]
        )
        summaries.append(item)
    return {
        "schema": "hepta-receipt-encoding-analysis-v2",
        "candidate_key": flag,
        "source_sha256": hashlib.sha256(encoded).hexdigest(),
        "source_bytes": len(encoded),
        "pure_waves": len(pure),
        "pure_calls": sum(row["iterations"] for row in pure),
        "durable_calls": len(durable),
        "cases": summaries,
        "measurement": result["measurement"],
        "interpretation": (
            "Finite same-binary ABBA observations of local encoding and durable saves. "
            "Final Vec capacity is observed retained byte-buffer capacity, not peak RSS, "
            "allocator allocation count or total process memory. All directional "
            "regressions and per-arm ranges are retained."
        ),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    summary = analyze(args.source)
    args.destination.write_text(json.dumps(summary, indent=2) + "\n")
    print(f"validated {summary['pure_calls']} encoding calls and {summary['durable_calls']} durable calls")
    candidate = summary["candidate_key"]
    print(f"bytes escaped CPU_us_original CPU_us_{candidate} CPU_% capacity_original capacity_{candidate} capacity_%")
    for case in summary["cases"]:
        print(
            case["size"], case["escaped"],
            f"{case['original']['cpu_us_per_call']['median']:.3f}",
            f"{case[candidate]['cpu_us_per_call']['median']:.3f}",
            f"{case['change_percent']['cpu_us_per_call']:+.2f}",
            case["original"]["final_vec_capacity"], case[candidate]["final_vec_capacity"],
            f"{case['change_percent']['final_vec_capacity']:+.2f}",
        )


if __name__ == "__main__":
    main()

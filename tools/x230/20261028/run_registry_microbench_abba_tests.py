#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Small failure-path checks for the fixed Rust benchmark record parser."""
import copy
import json
import unittest

import run_registry_microbench_abba as bench


def fixture():
    rows = []
    for repetition in range(4):
        kinds = bench.KINDS if repetition % 2 == 0 else tuple(reversed(bench.KINDS))
        widths = bench.WIDTHS if repetition % 2 == 0 else tuple(reversed(bench.WIDTHS))
        for kind in kinds:
            for width in widths:
                values = [float(index + 1) for index in range(width)]
                rows.append({"repetition": repetition, "kind": kind, "concurrency": width,
                    "primed_strict_bindings": width if kind == "known_invalidated" else 0,
                    "successes": width, "failures": 0, "latencies_ms": values,
                    "wall_seconds": float(width), "user_cpu_seconds": width * .25,
                    "system_cpu_seconds": 0., "calls_per_second": 1., "cpu_seconds_per_call": .25,
                    "p50_ms": bench.percentile(values, .5), "p95_ms": bench.percentile(values, .95)})
    return rows


def render(rows, final_rows=None):
    lines = ["test exact_name ... REGISTRY_CONCURRENCY_WAVE " + json.dumps(rows[0])]
    lines += ["REGISTRY_CONCURRENCY_WAVE " + json.dumps(row) for row in rows[1:]]
    lines += ["REGISTRY_CONCURRENCY_BENCH " + json.dumps({
        "schema": "hepta-registry-cold-concurrency-v1", "records": 6000, "actual_worker_limit": 4,
        "repetitions": 4, "remote_effects": 0, "rows": rows if final_rows is None else final_rows})]
    return "\n".join(lines)


class ParserTests(unittest.TestCase):
    def test_complete_36_wave_156_call_inventory_and_pooled_statistics(self):
        rows = bench.parse(render(fixture()))
        self.assertEqual(len(rows), 36)
        self.assertEqual(sum(row["successes"] for row in rows), 156)
        result = bench.aggregate([{"arm": arm, "waves": rows} for arm in "ABBA"])
        group = result["A"]["known_invalidated"]["8"]
        self.assertEqual(group["calls"], 64)
        self.assertEqual(group["waves"], 8)
        self.assertEqual(group["calls_per_second"], 1)
        self.assertEqual(group["cpu_ms_per_call"], 250)
        self.assertEqual(group["p99_ms"], 8)

    def test_duplicate_missing_and_inconsistent_final_records_are_refused(self):
        original = fixture()
        for change in ("duplicate", "missing", "final"):
            rows = copy.deepcopy(original)
            final = None
            if change == "duplicate":
                rows[1] = rows[0]
            elif change == "missing":
                rows.pop()
            else:
                final = rows[:-1]
            with self.subTest(change=change), self.assertRaises(ValueError):
                bench.parse(render(rows, final))

    def test_failed_nonfinite_and_unprimed_waves_are_refused(self):
        for field, value in (("failures", 1), ("wall_seconds", float("inf")),
                             ("primed_strict_bindings", 0), ("calls_per_second", 99.)):
            rows = fixture()
            target = next(row for row in rows if row["kind"] == "known_invalidated")
            target[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                bench.parse(render(rows))


if __name__ == "__main__":
    unittest.main()

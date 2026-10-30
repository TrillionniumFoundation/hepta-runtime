#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Parser checks keep incomplete or inconsistent benchmark records out of ratios."""
import copy
import json
import unittest

import run_record_idle_abba as bench


def receipt_rows():
    rows = []
    for repetition in range(4):
        sizes = bench.SIZES if repetition % 2 == 0 else tuple(reversed(bench.SIZES))
        modes = bench.MODES if repetition % 2 == 0 else tuple(reversed(bench.MODES))
        for size in sizes:
            for mode in modes:
                rows.append({"repetition": repetition, "receipt_bytes": size, "mode": mode,
                    "successes": 64, "failures": 0, "wall_seconds": 2., "user_cpu_seconds": .25,
                    "system_cpu_seconds": .25, "cpu_seconds_per_call": .5 / 64,
                    "calls_per_second": 32., "process_lifetime_maxrss_kib": 1000})
    return rows


def receipt_text(rows, final_rows=None):
    lines = ["test exact_name ... GUARDED_RECEIPT_WAVE " + json.dumps(rows[0])]
    lines += ["GUARDED_RECEIPT_WAVE " + json.dumps(row) for row in rows[1:]]
    lines.append("GUARDED_RECEIPT_BENCH " + json.dumps({
        "schema": "hepta-guarded-receipt-cpu-v1", "repetitions": 4, "calls_per_wave": 64,
        "remote_effects": 0, "allocations_measured": False,
        "rows": rows if final_rows is None else final_rows}))
    return "\n".join(lines)


def idle_row():
    return {"benchmark": "observation-empty-pool-idle/v1", "seconds": 10.001,
            "maintenance_passes": 100, "cpu_micros": 5000,
            "voluntary_context_switches": 101, "involuntary_context_switches": 0}


def idle_text(row):
    return "test exact_name ... " + json.dumps(row, separators=(",", ":"))


class ParserTests(unittest.TestCase):
    def test_full_receipt_inventory_is_2304_calls(self):
        result = bench.parse_receipt(receipt_text(receipt_rows()))
        self.assertEqual(len(result["waves"]), 36)
        self.assertEqual(sum(row["successes"] for row in result["waves"]), 2304)

    def test_missing_duplicate_reordered_and_mismatched_final_are_refused(self):
        original = receipt_rows()
        for change in ("missing", "duplicate", "reordered", "final"):
            rows = copy.deepcopy(original)
            final = None
            if change == "missing":
                rows.pop()
            elif change == "duplicate":
                rows[1] = rows[0]
            elif change == "reordered":
                rows[1], rows[2] = rows[2], rows[1]
            else:
                final = rows[:-1]
            with self.subTest(change=change), self.assertRaises(ValueError):
                bench.parse_receipt(receipt_text(rows, final))

    def test_failed_nonfinite_negative_and_false_derived_values_are_refused(self):
        for field, value in (("successes", True), ("failures", 1), ("wall_seconds", float("nan")),
                             ("user_cpu_seconds", -.01), ("calls_per_second", 999),
                             ("cpu_seconds_per_call", 999), ("process_lifetime_maxrss_kib", 0)):
            rows = receipt_rows()
            rows[0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                bench.parse_receipt(receipt_text(rows))

    def test_idle_record_retains_raw_counters(self):
        row = idle_row()
        self.assertEqual(bench.parse_idle(idle_text(row), 10), row)

    def test_duplicate_short_nonfinite_or_negative_idle_is_refused(self):
        row = idle_row()
        with self.assertRaises(ValueError):
            bench.parse_idle(idle_text(row) + "\n" + idle_text(row), 10)
        for field, value in (("seconds", 9.9), ("seconds", float("inf")),
                             ("cpu_micros", -1), ("maintenance_passes", True)):
            changed = {**row, field: value}
            with self.subTest(field=field), self.assertRaises(ValueError):
                bench.parse_idle(idle_text(changed), 10)

    def test_complete_abba_aggregates_raw_rows_and_idle_rates(self):
        samples = []
        for kind in ("receipt", "idle"):
            for arm in "ABBA":
                raw = (bench.parse_receipt(receipt_text(receipt_rows())) if kind == "receipt"
                       else idle_row())
                if kind == "idle" and arm == "B":
                    raw = {**raw, "maintenance_passes": 0, "cpu_micros": 1000,
                           "voluntary_context_switches": 1}
                samples.append({"index": len(samples), "arm": arm, "kind": kind, "raw": raw, "passed": True})
        result = bench.aggregate(samples)
        receipt = result["per_arm"]["A"]["receipt"]["fresh_lookup"]["786432"]
        self.assertEqual(receipt["wave_count"], 8)
        self.assertEqual(receipt["calls"], 512)
        self.assertEqual(len(receipt["raw_rows"]), 8)
        self.assertEqual(result["candidate_over_baseline"]["idle"]["maintenance_passes_per_second"], 0)
        self.assertAlmostEqual(result["candidate_over_baseline"]["idle"]["cpu_percent_one_core"], .2)
        self.assertIsNone(result["candidate_over_baseline"]["idle"]["involuntary_context_switches_per_second"])
        samples[-1]["passed"] = False
        with self.assertRaises(ValueError):
            bench.aggregate(samples)


if __name__ == "__main__":
    unittest.main()

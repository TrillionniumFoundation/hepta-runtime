#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Tests for direct-ABBA identity binding and complete, failure-retaining analysis."""
import gzip
import json
from pathlib import Path
import tempfile
import threading
import time
import types
import unittest
from unittest import mock

import run_registry_cohort_abba as cohort


class AnalysisTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def fixture(self):
        report = {"passed": True, "rounds": []}
        for index, arm in enumerate("ABBA"):
            row = cohort.planned_round(index, arm, 8, 48)
            row["events"] = str(self.root / f"events-{index}.gz")
            row["passed"] = row["started"] = True
            events = []
            for cell in row["phases"]:
                cell.update(completed=True, result={"passed": True, "seconds": 2.0,
                                                   "controller_cpu_seconds": .2})
                for number in range(cell["planned_calls"]):
                    events.append({"phase": cell["phase"], "index": number, "executed": True,
                                   "okay": True, "elapsed_ms": 10.0 if arm == "A" else 8.0})
                events.append({"kind": "ping", "phase": cell["phase"], "executed": True,
                               "okay": True, "elapsed_ms": 1.0})
            self.write_events(Path(row["events"]), events)
            report["rounds"].append(row)
        return report

    @staticmethod
    def write_events(path, events):
        with gzip.open(path, "wt", encoding="utf-8") as stream:
            for event in events:
                stream.write(json.dumps(event) + "\n")

    @staticmethod
    def read_events(path):
        with gzip.open(path, "rt", encoding="utf-8") as stream:
            return [json.loads(line) for line in stream]

    def test_plan_has_eight_separate_six_original_waves_and_48_warm_calls(self):
        plan = cohort.planned_round(0, "A", 8, 48)
        self.assertEqual(len(plan["phases"]), 3 * 8 * 2)
        for concurrency in cohort.CONCURRENCY:
            cells = [cell for cell in plan["phases"] if cell["concurrency"] == concurrency]
            self.assertEqual(sum(cell["planned_calls"] for cell in cells), 8 * (6 + 48))
            self.assertEqual(sum(cell["category"] == "cold_initial" for cell in cells), 1)
            self.assertEqual(sum(cell["category"] == "cold_steady" for cell in cells), 7)

    def test_complete_abba_separates_initial_steady_and_warm(self):
        result = cohort.summarize(self.fixture())
        for arm in ("A", "B"):
            for concurrency in cohort.CONCURRENCY:
                groups = result["per_arm"][arm][str(concurrency)]
                self.assertEqual(groups["cold_initial"]["successes"], 12)
                self.assertEqual(groups["cold_steady"]["successes"], 84)
                self.assertEqual(groups["cold_all"]["successes"], 96)
                self.assertEqual(groups["warm"]["successes"], 768)
                self.assertTrue(all(group["complete"] for group in groups.values()))
        comparison = result["comparison"]["4"]["cold_steady"]
        self.assertTrue(comparison["comparison_eligible"])
        self.assertAlmostEqual(comparison["candidate_over_baseline"]["p99_ms"], .8)

    def test_failed_attempt_is_kept_in_tail_and_refuses_comparison(self):
        report = self.fixture()
        report["passed"] = False
        path = Path(report["rounds"][1]["events"])
        rows = self.read_events(path)
        rows[0].update(okay=False, elapsed_ms=1000.0)
        self.write_events(path, rows)
        result = cohort.summarize(report)
        group = result["per_arm"]["B"]["1"]["cold_initial"]
        self.assertEqual(group["executed"], 12)
        self.assertEqual(group["successes"], 11)
        self.assertEqual(group["failed_executed"], 1)
        self.assertEqual(group["p99_ms"], 1000)
        self.assertFalse(result["comparison"]["1"]["cold_initial"]["comparison_eligible"])
        self.assertIsNone(result["comparison"]["1"]["cold_initial"]["candidate_over_baseline"]["p99_ms"])

    def test_duplicate_row_cannot_replace_missing_original_index(self):
        report = self.fixture()
        path = Path(report["rounds"][1]["events"])
        rows = self.read_events(path)
        rows[1] = dict(rows[0])
        self.write_events(path, rows)
        result = cohort.summarize(report)
        group = result["per_arm"]["B"]["1"]["cold_initial"]
        self.assertFalse(group["original_phase_indices_complete"])
        self.assertFalse(group["complete"])
        self.assertFalse(result["comparison"]["1"]["cold_initial"]["comparison_eligible"])

    def test_unexecuted_rounds_remain_planned_and_never_gain_partial_rates(self):
        report = self.fixture()
        report["passed"] = False
        report["rounds"][3] = cohort.planned_round(3, "A", 8, 48)
        result = cohort.summarize(report)
        group = result["per_arm"]["A"]["8"]["cold_all"]
        self.assertEqual(group["planned_calls"], 96)
        self.assertEqual(group["recorded_calls"], 48)
        self.assertEqual(group["unrecorded_calls"], 48)
        self.assertFalse(group["measured_time_complete"])
        self.assertIsNone(group["successful_calls_per_second"])
        self.assertIsNone(group["controller_cpu_ms_per_success"])

    def test_later_global_failure_revokes_ratios_for_other_complete_groups(self):
        result = cohort.summarize(self.fixture())
        self.assertTrue(result["comparison"]["1"]["warm"]["comparison_eligible"])
        cohort.invalidate_comparisons(result)
        for concurrency in result["comparison"].values():
            for group in concurrency.values():
                self.assertFalse(group["comparison_eligible"])
                self.assertTrue(all(value is None for value in group["candidate_over_baseline"].values()))
                self.assertIsNone(group["ping_p99_ratio"])


class BindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        modules = cohort.load_helpers()
        cls.protocol = modules["pinned_native_protocol"]
        cls.native = modules["run_native_validation"]

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "src").mkdir()
        for name in ("Cargo.toml", "Cargo.lock", "rustfmt.toml", "src/lib.rs"):
            (self.source / name).write_text(name)
        self.binary = self.root / "runtime"
        self.binary.write_bytes(b"not executed by the binding tests")
        self.binary.chmod(0o700)
        self.manifest = self.root / "source-map.json"
        self.manifest.write_text(json.dumps(self.native.candidate_sources(self.protocol, self.source)))
        self.output = self.root / "evidence"
        self.output.mkdir()
        self.args = types.SimpleNamespace(baseline=self.binary, baseline_sha256=cohort.sha(self.binary),
            baseline_source=self.source, baseline_source_manifest=self.manifest,
            baseline_source_manifest_sha256=cohort.sha(self.manifest))

    def tearDown(self):
        self.temporary.cleanup()

    def load(self):
        return cohort.load_variant(self.protocol, self.native, self.args, "baseline", self.output)

    def test_binding_is_explicit_without_claiming_compilation_or_qualification(self):
        bundle = self.load()
        self.assertFalse(bundle["qualification_claim"])
        self.assertEqual(bundle["source_files"], 4)
        cohort.verify_variant(self.protocol, self.native, bundle)

    def test_binary_hash_mismatch_is_refused(self):
        self.args.baseline_sha256 = "0" * 64
        with self.assertRaisesRegex(RuntimeError, "binary SHA"):
            self.load()

    def test_same_binary_under_different_paths_is_not_a_comparison(self):
        with self.assertRaisesRegex(RuntimeError, "same binary SHA256"):
            cohort.require_distinct_binaries({
                "A": {"binary": {"path": "/a", "sha256": "1" * 64}},
                "B": {"binary": {"path": "/b", "sha256": "1" * 64}},
            })

    def test_manifest_and_current_sources_must_match(self):
        (self.source / "src/lib.rs").write_text("changed compiler input")
        with self.assertRaisesRegex(RuntimeError, "current compiler-input"):
            self.load()

    def test_source_mutation_after_binding_is_refused(self):
        bundle = self.load()
        (self.source / "src/new.rs").write_text("new compiler input")
        with self.assertRaisesRegex(RuntimeError, "compiler inputs changed"):
            cohort.verify_variant(self.protocol, self.native, bundle)

    def test_registry_changes_are_detected_and_non_json_markers_are_allowed(self):
        registry = self.root / "jobs"
        registry.mkdir()
        (registry / "job.json").write_text("original")
        expected = {"job.json": cohort.sha(registry / "job.json")}
        (registry / "invalidation.marker").write_text("not a job")
        cohort.verify_registry(registry, expected)
        (registry / "job.json").write_text("altered")
        with self.assertRaisesRegex(RuntimeError, "receipts changed"):
            cohort.verify_registry(registry, expected)


class ResourceTests(unittest.TestCase):
    def test_raw_sample_fsync_does_not_block_the_bounded_stop_caller(self):
        modules = cohort.load_helpers()
        sampler = cohort.logged_resources(modules["pinned_resource_sampler"])
        entered, release = threading.Event(), threading.Event()
        with tempfile.TemporaryDirectory() as directory:
            proc = types.SimpleNamespace(stat=lambda pid: (123, 1.0, 1))
            resources = sampler.Resources(777, Path(directory) / "errors.jsonl", proc=proc, start=False)
            raw_fd = resources.sample_stream.fileno()
            actual_fsync = cohort.os.fsync

            def block_raw_fsync(fd):
                if fd == raw_fd:
                    entered.set()
                    if not release.wait(5):
                        raise TimeoutError("fixture raw fsync was not released")
                return actual_fsync(fd)

            try:
                with mock.patch.object(cohort.os, "fsync", side_effect=block_raw_fsync):
                    started = time.monotonic()
                    result = resources.stop(join_timeout=.05)
                    self.assertLess(time.monotonic() - started, 1)
                    self.assertTrue(entered.wait(1))
                    self.assertFalse(result["sampler_thread_stopped"])
                    self.assertFalse(result["raw_samples"]["finalized"])
                    release.set()
                    completed = resources.stop(join_timeout=5)
                    self.assertTrue(completed["sampler_thread_stopped"])
                    self.assertTrue(completed["raw_samples"]["finalized"])
            finally:
                release.set()
                resources.stop(join_timeout=5)

    def test_raw_samples_retain_current_fields_missing_values_and_final_digest(self):
        modules = cohort.load_helpers()
        sampler = cohort.logged_resources(modules["pinned_resource_sampler"])

        class Proc:
            rss = 100
            denied = False

            def stat(self, pid):
                return 123, 1.0, 1

            def status(self, pid):
                return {"rss_kib": self.rss, "hwm_kib": 200, "threads": 2}

            def fd_count(self, pid):
                if self.denied:
                    raise PermissionError("fixture metric unavailable")
                return 5

            def children(self, pid):
                return [], []

            def master(self, pid):
                return False

        with tempfile.TemporaryDirectory() as directory:
            proc = Proc()
            resources = sampler.Resources(777, Path(directory) / "errors.jsonl", proc=proc, start=False)
            resources.current_phase = "cold"
            resources.sample_once()
            proc.rss = 50
            proc.denied = True
            resources.current_phase = "warm"
            resources.sample_once()
            result = resources.stop()
            self.assertTrue(result["sampler_thread_stopped"])
            self.assertTrue(result["error_log_complete"])
            self.assertEqual(result["error_count"], 1)
            self.assertEqual(result["peaks"]["controller_rss_kib"], 100)
            raw = result["raw_samples"]
            self.assertTrue(raw["finalized"])
            self.assertIsNone(raw["error"])
            self.assertEqual(raw["rows"], 2)
            self.assertEqual(cohort.sha(raw["path"]), raw["sha256"])
            rows = [json.loads(line) for line in Path(raw["path"]).read_text().splitlines()]
            self.assertEqual(rows[0]["fields"]["controller_rss_kib"], 100)
            self.assertEqual(rows[1]["fields"]["controller_rss_kib"], 50)
            self.assertNotIn("controller_fd", rows[1]["fields"])
            self.assertIsNone(rows[1]["fields"]["tree_fd"])
            self.assertEqual(rows[1]["phase_start"], "warm")


if __name__ == "__main__":
    unittest.main()

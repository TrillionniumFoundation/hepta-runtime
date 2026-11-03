#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Regression checks for lost resource samples and asynchronous delta labeling."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_native_observation as driver


class ResourceMeasurements(unittest.TestCase):
    def test_fd_permission_failure_keeps_readable_metrics_and_child_discovery(self):
        paths = []
        def listing(path):
            paths.append(path)
            if path == Path("/proc/77/fd"):
                raise PermissionError("independent denied FD fixture")
            table = {"/proc/77/task": [Path("/proc/77/task/77")],
                     "/proc/88/task": [Path("/proc/88/task/88")],
                     "/proc/88/fd": [Path("/proc/88/fd/0"), Path("/proc/88/fd/1")]}
            return iter(table[str(path)])
        def reading(path):
            if path.name == "status":
                return "VmRSS: 1000 kB\nVmHWM: 1200 kB\n"
            return "88" if str(path) == "/proc/77/task/77/children" else ""
        with patch.object(driver.bench, "process_stat", return_value=(1, 2.0)), \
                patch.object(Path, "iterdir", listing), patch.object(Path, "read_text", reading):
            sampler = driver.Resources(77, autostart=False)
            sampler.sample()
        report = sampler.snapshot()
        self.assertEqual(report["samples"], 1)
        self.assertEqual(report["metric_samples"]["controller_rss_kib"], 1)
        self.assertEqual(report["metric_samples"]["controller_hwm_kib"], 1)
        self.assertEqual(report["metric_samples"]["process_cpu"], 2)
        self.assertEqual(report["peaks"]["controller_rss_kib"], 1000)
        self.assertEqual(report["peaks"]["tree_rss_kib"], 2000)
        self.assertEqual(report["peaks"]["tree_fd"], 2)
        self.assertNotIn("controller_fd", report["metric_samples"])
        self.assertEqual(report["error_counts"]["fd:PermissionError"], 1)
        self.assertIn(Path("/proc/77/task"), paths)
        self.assertTrue(report["sampled_tree_cpu_delta_has_endpoint_error_of_either_sign"])

    def test_changed_process_generation_cannot_publish_metrics(self):
        with patch.object(driver.bench, "process_stat", side_effect=[
                (1, 0.0), (1, 1.0), (2, 2.0)]), \
                patch.object(Path, "iterdir", return_value=iter(())), \
                patch.object(Path, "read_text", return_value="VmRSS: 1000 kB\nVmHWM: 1200 kB\n"):
            sampler = driver.Resources(77, autostart=False)
            sampler.sample()
        report = sampler.snapshot()
        self.assertEqual(report["metric_samples"], {})
        self.assertEqual(report["sampled_process_generations"], 0)

    def test_balanced_warmup_is_separate_from_measured_denominator(self):
        calls = []
        def measure(controller, jobs, concurrency, count):
            calls.append(count)
            return {"successes": count, "calls": count,
                    "sampled_tree_cpu_seconds_delta_is_lower_bound": True}
        with patch.object(driver, "ORIGINAL_CELL", measure):
            result = driver.cell(None, [], 4, 96)
        self.assertEqual(calls, [24, 96])
        self.assertEqual(result["calls"], 96)
        self.assertEqual(result["warmup"]["calls"], 24)
        self.assertFalse(result["sampled_tree_cpu_seconds_delta_is_lower_bound"])
        self.assertFalse(result["warmup"]["sampled_tree_cpu_seconds_delta_is_lower_bound"])

    def test_failed_warmup_cannot_create_successful_measurement(self):
        with patch.object(driver, "ORIGINAL_CELL", return_value={"successes": 23, "calls": 24}) as cell:
            with self.assertRaisesRegex(RuntimeError, "warmup failed"):
                driver.cell(None, [], 4, 96)
            cell.assert_called_once()


if __name__ == "__main__":
    unittest.main()

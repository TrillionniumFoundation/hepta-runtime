"""Post-storage output matching, degenerate controls and preservation tests."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "workers" / "weight"))
import torch
from safetensors.torch import load_file, save_file
from current100k_mechanism_controls import PLAN_SCHEMA, compare, validate_plan
from weight_runtime.artifacts import ArtifactStore, file_sha256
from weight_runtime.errors import WeightError, canonical
from weight_runtime.patches import tensor_sha256


class OutputControlsTests(unittest.TestCase):
    def setUp(self):
        torch.set_num_threads(1)
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.serial = 0
        self.features = torch.zeros((6, 768), dtype=torch.float32)
        self.features[:, :2] = torch.tensor([[1., 0.], [1., 0.], [1., 0.], [1., 0.], [0., 1.], [0., -1.]])
        self.parent = {"value.weight": torch.zeros((1, 768)), "value.bias": torch.tensor([.25])}
        self.full = {key: value.clone() for key, value in self.parent.items()}
        self.full["value.weight"][0, :2] = torch.tensor([.02, .01])
        self.plan = {"schema": PLAN_SCHEMA, "partition": "development", "information_cutoff_ms": 2000,
                     "doses": [0, .5, 1], "random_seed": 37, "random_controls": 2,
                     "norm_relative_tolerance": .02, "output_relative_tolerance": .02,
                     "output_absolute_tolerance_usd": 1e-5, "orthogonality_max_abs_cosine": .02,
                     "max_output_rms_scale": 1000000., "prediction_chunk_size": 2}
        self.lineage = {key + "_artifact_sha256": char * 64
                        for key, char in (("feature", "a"), ("parent", "b"), ("full", "c"))}

    def tearDown(self):
        self.temporary.cleanup()

    def screen(self, **changes):
        target = self.root / ("result-" + str(self.serial))
        self.serial += 1
        args = {"features": self.features, "parent_state": self.parent, "full_state": self.full,
                "plan": self.plan, "output_root": target, "lineage": self.lineage, **changes}
        return compare(**args), target

    def candidate(self, report, name):
        return next(row for row in report["candidates"] if row["name"] == name)

    def test_bias_matches_full_output_mean_without_changing_weights(self):
        report, _ = self.screen()
        bias = self.candidate(report, "bias-mean-match")
        state = load_file(bias["head"]["path"])
        self.assertEqual(tensor_sha256(state["value.weight"]), tensor_sha256(self.parent["value.weight"]))
        self.assertTrue(bias["mean_output_shift_match"]["passed"])
        self.assertLess(bias["centered_delta_rms_usd"], 1e-5)
        self.assertFalse(bias["labels_used"])

    def test_rms_control_does_not_silently_claim_same_parameter_norm(self):
        report, _ = self.screen()
        norm = self.candidate(report, "random-norm-0")
        rms = self.candidate(report, "random-rms-0")
        self.assertTrue(norm["parameter_norm_match"]["passed"])
        self.assertFalse(norm["output_rms_match"]["passed"])
        self.assertTrue(rms["output_rms_match"]["passed"])
        self.assertFalse(rms["parameter_norm_match"]["passed"])
        self.assertFalse(norm["joint_random_match_passed"])
        self.assertFalse(rms["joint_random_match_passed"])
        self.assertTrue(norm["orthogonality_passed"])
        self.assertTrue(rms["orthogonality_passed"])

    def test_doses_saved_precision_and_final_parent_are_exact(self):
        before = {key: tensor_sha256(value) for key, value in self.parent.items()}
        report, _ = self.screen()
        zero, half, full = [self.candidate(report, "dose-" + name) for name in ("0", "0.5", "1")]
        self.assertTrue(zero["zero_dose_exact_noop"])
        self.assertAlmostEqual(half["delta_rms_usd"] * 2, full["delta_rms_usd"], places=5)
        self.assertTrue(all(row["save_reload_exact"] for row in report["candidates"]))
        self.assertEqual(before, {key: tensor_sha256(value) for key, value in self.parent.items()})
        self.assertTrue(report["parent_restoration"]["final_parent_head_recomputed"])
        self.assertFalse(report["parent_restoration"]["final_encoder_recomputed"])
        self.assertTrue(report["parent_restoration"]["exact_output_bytes_equal"])
        self.assertFalse(report["prospective_evidence"])
        self.assertFalse(report["cost"]["end_to_end_cost_complete"])
        self.assertIsNone(report["cost"]["astra_seconds"])
        self.assertEqual(report["cost"]["head_forward_examples"], (len(report["candidates"]) + 2) * len(self.features))
        self.assertEqual(report["cost"]["head_forward_examples_attempted"], report["cost"]["head_forward_examples"])
        self.assertEqual(report["cost"]["head_forward_examples_completed"], report["cost"]["head_forward_examples"])
        self.assertEqual(report["cost"]["head_forward_examples_measurement"], "COMPLETED_CHUNK_EXAMPLES")

    def test_signed_zero_is_preserved_by_zero_dose(self):
        self.parent["value.weight"][0, 2] = -0.
        self.full["value.weight"][0, 2] = -0.
        report, _ = self.screen()
        state = load_file(self.candidate(report, "dose-0")["head"]["path"])
        self.assertTrue(bool(torch.signbit(state["value.weight"][0, 2])))

    def test_unselected_parameter_bytes_survive_half_and_random_construction(self):
        for state in (self.parent, self.full):
            state["value.weight"][0, 2] = -0.
            state["value.bias"][0] = -0.
        parent = torch.cat([self.parent[key].flatten() for key in ("value.weight", "value.bias")])
        full = torch.cat([self.full[key].flatten() for key in ("value.weight", "value.bias")])
        outside = full.double() - parent.double() == 0
        expected = tensor_sha256(parent[outside])
        report, _ = self.screen()
        for name in ("dose-0.5", "random-norm-0", "random-rms-0", "random-norm-1", "random-rms-1"):
            state = load_file(self.candidate(report, name)["head"]["path"])
            actual = torch.cat([state[key].flatten() for key in ("value.weight", "value.bias")])
            with self.subTest(name=name):
                self.assertEqual(tensor_sha256(actual[outside]), expected)
                self.assertTrue(bool(torch.signbit(state["value.weight"][0, 2])))
                self.assertTrue(bool(torch.signbit(state["value.bias"][0])))

    def test_degenerate_single_coordinate_is_retained_without_retry(self):
        self.full["value.weight"][0, 1] = 0.
        report, _ = self.screen()
        self.assertEqual(len(report["candidates"]), 5)
        self.assertEqual(len(report["random_constructions"]), 2)
        self.assertTrue(all(item["error"] == "NO_ORTHOGONAL_DIRECTION" for item in report["random_constructions"]))
        self.assertTrue(all(item["attempts"] == 1 for item in report["random_constructions"]))
        self.assertEqual(report["adaptive_retries"], 0)

    def test_nullspace_reference_cannot_be_counted_as_matched_output_control(self):
        self.full["value.weight"].zero_()
        self.full["value.weight"][0, 3:5] = torch.tensor([.01, .02])
        report, _ = self.screen()
        self.assertEqual(self.candidate(report, "dose-1")["delta_rms_usd"], 0.)
        self.assertFalse(any(row["output_rms_match"]["passed"] for row in report["candidates"]))
        self.assertTrue(all(item["error"] == "ZERO_REFERENCE_OR_CONTROL_OUTPUT_RMS"
                            for item in report["random_constructions"]))

    def test_numerical_bound_exposes_mean_direction_confound(self):
        self.features[:, :2] = torch.tensor([1., 1.]) / 2**.5
        self.full["value.weight"][0, :2] = .01
        report, _ = self.screen()
        bound = report["joint_match_feasibility"]
        self.assertTrue(bound["infeasible_under_numerical_bound"])
        self.assertLess(bound["numerical_upper_bound_usd"], bound["required_rms_lower_edge_usd"])
        self.assertFalse(bound["certified_interval_bound"])
        self.assertTrue(self.candidate(report, "bias-mean-match")["mean_output_shift_match"]["passed"])

    def test_scale_bound_retains_failed_attempt_and_norm_candidate(self):
        self.plan["max_output_rms_scale"] = 1.
        report, _ = self.screen()
        self.assertTrue(all(item["error"] == "SCALE_LIMIT" for item in report["random_constructions"]))
        self.assertEqual(sum(row["role"] == "parameter_norm_control" for row in report["candidates"]), 2)
        self.assertEqual(sum(row["role"] == "output_rms_control" for row in report["candidates"]), 0)

    def test_same_seed_and_inputs_reproduce_payloads_without_score_selection(self):
        first, _ = self.screen()
        second, _ = self.screen()
        self.assertEqual([(r["name"], r["head"]["sha256"], r["outputs"]["sha256"]) for r in first["candidates"]],
                         [(r["name"], r["head"]["sha256"], r["outputs"]["sha256"]) for r in second["candidates"]])

    def test_failed_reload_has_immutable_failure_and_no_completed_report(self):
        original = ArtifactStore.load_tensors
        def changed(store, artifact_id):
            state = original(store, artifact_id)
            if "value.bias" in state:
                state["value.bias"] += 1
            return state
        with patch.object(ArtifactStore, "load_tensors", changed):
            with self.assertRaises(WeightError) as raised:
                self.screen()
        self.assertEqual(raised.exception.code, "RELOAD_MISMATCH")
        target = self.root / "result-0"
        self.assertTrue((target / "failure.json").exists())
        self.assertFalse((target / "report.json").exists())
        with self.assertRaises(FileExistsError):
            self.screen(output_root=target)

    def test_partial_forward_failure_retains_attempted_completed_and_cpu_costs(self):
        original = torch.nn.functional.linear
        calls = 0
        def fail_second(features, *args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise RuntimeError("second chunk failure")
            return original(features, *args, **kwargs)
        with patch.object(torch.nn.functional, "linear", fail_second):
            with self.assertRaisesRegex(RuntimeError, "second chunk failure"):
                self.screen()
        target = self.root / "result-0"
        failure = json.loads((target / "failure.json").read_text())
        self.assertEqual(calls, 2)
        self.assertEqual(failure["head_forward_examples_attempted"], 4)
        self.assertEqual(failure["head_forward_examples_completed"], 2)
        self.assertEqual(failure["head_forward_examples"], 2)
        self.assertEqual(failure["head_forward_examples_measurement"], "COMPLETED_CHUNK_EXAMPLES")
        self.assertIsInstance(failure["process_cpu_seconds"], float)
        self.assertGreaterEqual(failure["process_cpu_seconds"], 0.)
        self.assertFalse(failure["completed"])
        self.assertFalse(failure["automatic_replay_allowed"])
        self.assertFalse((target / "report.json").exists())

    def test_invalid_features_plan_and_zero_delta_fail_before_output(self):
        for changes in ({"features": self.features.double()}, {"features": self.features * 2},
                        {"full_state": self.parent}, {"lineage": {}},
                        {"plan": {**self.plan, "partition": "future"}}):
            with self.assertRaises(WeightError):
                self.screen(**changes)
        for change in ({"doses": [False, .5, 1]}, {"random_controls": True},
                       {"output_relative_tolerance": float("nan")}, {"labels": []}):
            with self.assertRaises(WeightError):
                validate_plan({**self.plan, **change})
        self.assertEqual(list(self.root.iterdir()), [])

    def test_cli_hash_pins_and_final_source_audit(self):
        paths = {}
        for name, state in (("features", {"features": self.features}), ("parent", self.parent), ("full", self.full)):
            paths[name] = self.root / (name + ".safetensors")
            save_file(state, str(paths[name]))
        paths["plan"] = self.root / "plan.json"
        paths["plan"].write_bytes(canonical(self.plan))
        output = self.root / "cli"
        command = [sys.executable, str(Path(__file__).with_name("current100k_mechanism_controls.py"))]
        for name, path in paths.items():
            command += ["--" + name, str(path), "--" + name + "-sha256", file_sha256(path)]
        command += ["--output", str(output)]
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        audit = json.loads((output / "source-integrity.json").read_text())
        self.assertTrue(audit["passed"])
        self.assertEqual(set(audit["checks"]), {"features", "parent", "full", "plan"})
        paths["plan"].write_bytes(b"{}")
        failed = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("Input SHA256 differs", failed.stderr)


if __name__ == "__main__":
    unittest.main()

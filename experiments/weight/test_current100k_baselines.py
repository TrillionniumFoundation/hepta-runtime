"""Real closed-form, calibration and SGD comparisons over frozen CPU features."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "workers" / "weight"))
import torch
from safetensors.torch import load_file, save_file
from current100k_baselines import compare, validate_plan
from weight_runtime.artifacts import file_sha256
from weight_runtime.errors import WeightError
from weight_runtime.patches import tensor_sha256


class Current100kBaselinesTests(unittest.TestCase):
    def setUp(self):
        torch.set_num_threads(1)
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.serial = 0
        self.features = torch.zeros((4, 768), dtype=torch.float32)
        self.features[0, 0], self.features[1, 1] = 1, 1
        self.features[2, 0], self.features[3, 1] = -1, -1
        self.parent = {"value.weight": torch.zeros((1, 768)), "value.bias": torch.tensor([.1])}
        self.parent["value.weight"][0, :2] = torch.tensor([.5, -.25])
        self.labels = torch.tensor([500., 700., 100., -100.])
        self.plan = {"schema": "hepta.weight.current100k.baselines-plan.v1", "partition": "development",
                     "information_cutoff_ms": 2000, "max_label_resolved_at_ms": 1999,
                     "ridge_lambda": 2.0, "max_head_delta_l2": 10.0,
                     "sgd_budget_seconds": 2.0, "sgd_max_steps": 3, "sgd_learning_rate": .05}
        self.lineage = {}
        for name, tensors in (("feature", {"features": self.features}),
                              ("label", {"labels_usd": self.labels}), ("head", self.parent)):
            path = self.root / (name + ".safetensors")
            save_file(tensors, str(path))
            self.lineage[name + "_artifact_sha256"] = file_sha256(path)

    def tearDown(self):
        self.temporary.cleanup()

    def run_compare(self, features=None, labels=None, parent=None, plan=None, lineage=None):
        output = self.root / ("result-" + str(self.serial))
        self.serial += 1
        result = compare(self.features if features is None else features,
                         self.labels if labels is None else labels,
                         self.parent if parent is None else parent,
                         self.plan if plan is None else plan, output,
                         self.lineage if lineage is None else lineage)
        return result, output

    def candidate(self, result, name):
        return next(row for row in result["candidates"] if row["name"] == name)

    def state(self, candidate):
        self.assertEqual(file_sha256(candidate["head"]["path"]), candidate["head"]["sha256"])
        return load_file(candidate["head"]["path"], device="cpu")

    def test_closed_form_matches_analytic_centered_ridge_solution(self):
        result, _ = self.run_compare()
        fitted = self.state(self.candidate(result, "ridge_delta_capped"))
        # X is centered and X.T X = diag(2,2,0,...); lambda=2 halves
        # the residual coefficient. The unregularized intercept is 3.
        expected = self.parent["value.weight"].clone()
        expected[0, :2] += .5 * (torch.tensor([2., 4.]) - expected[0, :2])
        torch.testing.assert_close(fitted["value.weight"], expected, rtol=0, atol=1e-6)
        torch.testing.assert_close(fitted["value.bias"], torch.tensor([3.]), rtol=0, atol=1e-6)
        candidate = self.candidate(result, "ridge_delta_capped")
        self.assertEqual(candidate["construction_kind"], "LabelFittedClosedForm")
        self.assertEqual(candidate["gradient_steps"], 0)
        self.assertLess(candidate["rmse_usd"], self.candidate(result, "parent")["rmse_usd"])

    def test_mean_median_and_bias_calibration_have_distinct_semantics(self):
        labels = torch.tensor([-400., 100., 200., 10000.])
        result, _ = self.run_compare(labels=labels)
        mean, median = [self.candidate(result, name) for name in ("constant_mean", "constant_median")]
        for candidate, expected in ((mean, 2475.), (median, 150.)):
            state = self.state(candidate)
            self.assertEqual(torch.count_nonzero(state["value.weight"]).item(), 0)
            self.assertAlmostEqual(state["value.bias"].item() * 100., expected, places=4)
            self.assertEqual(candidate["prediction_std_usd"], 0)
            self.assertEqual(candidate["construction_kind"], "ConstantDiagnostic")
        self.assertLessEqual(median["mae_usd"], mean["mae_usd"])
        self.assertLessEqual(mean["rmse_usd"], median["rmse_usd"])
        calibrated = self.candidate(result, "bias_calibration")
        state = self.state(calibrated)
        self.assertTrue(torch.equal(state["value.weight"], self.parent["value.weight"]))
        predictions = (self.features @ state["value.weight"].T + state["value.bias"]).flatten() * 100.
        self.assertAlmostEqual((predictions - labels).mean().item(), 0., places=4)
        self.assertGreater(float(predictions.abs().max()), 15.)
        self.assertEqual(calibrated["construction_kind"], "LabelFittedCalibration")
        self.assertTrue(calibrated["labels_used_in_construction"])

    def test_real_backward_and_optimizer_calls_equal_reported_training_counts(self):
        steps, backwards = [], []
        original_step, original_backward = torch.optim.SGD.step, torch.autograd.backward
        def tracked_step(optimizer, *args, **kwargs):
            steps.append(1)
            return original_step(optimizer, *args, **kwargs)
        def tracked_backward(*args, **kwargs):
            backwards.append(1)
            return original_backward(*args, **kwargs)
        with patch.object(torch.optim.SGD, "step", tracked_step), patch.object(torch.autograd, "backward", tracked_backward):
            result, _ = self.run_compare()
        candidate = self.candidate(result, "sgd_head_capped")
        self.assertGreater(len(steps), 0)
        self.assertLessEqual(len(steps), self.plan["sgd_max_steps"])
        self.assertEqual(len(backwards), len(steps))
        self.assertEqual(candidate["gradient_steps"], len(steps))
        receipt = json.loads(Path(candidate["cost"]["path"]).read_text())
        self.assertEqual(receipt["gradient_steps"], len(steps))
        self.assertEqual(receipt["optimizer_calls"], len(steps))
        self.assertGreater(receipt["training_seconds"], 0.)
        self.assertEqual(receipt["encoder_forward_examples"], 0)
        self.assertIsNone(receipt["shared_encoding_seconds"])
        for other in result["candidates"]:
            if other["name"] != "sgd_head_capped":
                self.assertEqual(other["gradient_steps"], 0)
        self.assertFalse(result["encoding_cost_included"])
        self.assertFalse(result["prospective_evidence"])
        self.assertFalse(result["production_eligible"])

    def test_parent_frozen_inputs_and_their_gradients_are_unchanged(self):
        features = self.features.clone().requires_grad_(True)
        labels = self.labels.clone().requires_grad_(True)
        parent = {k: v.clone().requires_grad_(True) for k, v in self.parent.items()}
        hashes = {k: tensor_sha256(v) for k, v in parent.items()}
        feature_hash, label_hash = tensor_sha256(features), tensor_sha256(labels)
        self.run_compare(features=features, labels=labels, parent=parent)
        self.assertEqual({k: tensor_sha256(v) for k, v in parent.items()}, hashes)
        self.assertEqual(tensor_sha256(features), feature_hash)
        self.assertEqual(tensor_sha256(labels), label_hash)
        self.assertIsNone(features.grad)
        self.assertIsNone(labels.grad)
        self.assertTrue(all(v.grad is None and v.requires_grad for v in parent.values()))
        for name in ("feature", "label", "head"):
            self.assertEqual(file_sha256(self.root / (name + ".safetensors")), self.lineage[name + "_artifact_sha256"])

    def test_every_score_uses_saved_and_reloaded_fp32_head(self):
        result, output = self.run_compare()
        for candidate in result["candidates"]:
            state = self.state(candidate)
            self.assertEqual(set(state), {"value.weight", "value.bias"})
            self.assertTrue(all(v.dtype == torch.float32 and v.device.type == "cpu" for v in state.values()))
            predictions = (self.features @ state["value.weight"].T + state["value.bias"]).flatten() * 100.
            error = predictions.double() - self.labels.double()
            self.assertAlmostEqual(candidate["mae_usd"], float(error.abs().mean()), places=9)
            self.assertAlmostEqual(candidate["rmse_usd"], float(error.square().mean().sqrt()), places=9)
            self.assertFalse(candidate["production_eligible"])
        self.assertEqual(json.loads((output / "report.json").read_text()), result)

    def test_realized_norm_cap_applies_to_ridge_and_training_only(self):
        plan = copy.deepcopy(self.plan)
        plan["max_head_delta_l2"] = .01
        result, _ = self.run_compare(plan=plan)
        for name in ("ridge_delta_capped", "sgd_head_capped"):
            candidate = self.candidate(result, name)
            state = self.state(candidate)
            delta = torch.cat([(state[k].double() - self.parent[k].double()).flatten() for k in sorted(state)])
            self.assertLessEqual(float(delta.norm()), plan["max_head_delta_l2"] + 1e-7)
            self.assertAlmostEqual(candidate["actual_head_delta_l2"], float(delta.norm()), places=7)
            self.assertTrue(candidate["norm_cap_applies"])
        calibration = self.candidate(result, "bias_calibration")
        self.assertFalse(calibration["norm_cap_applies"])
        self.assertGreater(calibration["actual_head_delta_l2"], plan["max_head_delta_l2"])

    def test_future_labels_non_development_and_invalid_budget_rejected(self):
        for field, value in (("max_label_resolved_at_ms", 2001), ("partition", "holdout"),
                             ("ridge_lambda", 0.), ("sgd_max_steps", True),
                             ("sgd_budget_seconds", 2.1), ("sgd_learning_rate", float("nan"))):
            with self.subTest(field=field):
                plan = copy.deepcopy(self.plan)
                plan[field] = value
                with self.assertRaises(WeightError):
                    validate_plan(plan)
        plan = copy.deepcopy(self.plan)
        plan["max_label_resolved_at_ms"] = 2001
        with self.assertRaises(WeightError) as error:
            self.run_compare(plan=plan)
        self.assertEqual(error.exception.code, "INPUT_LINEAGE")
        self.assertFalse((self.root / "result-0").exists())

    def test_nonfinite_shape_precision_and_normalization_rejected(self):
        nan_features = self.features.clone()
        nan_features[0, 0] = float("nan")
        bad_labels = self.labels.clone()
        bad_labels[0] = float("inf")
        invalid = [{"features": nan_features}, {"labels": bad_labels},
                   {"features": self.features.double()}, {"features": self.features[:, :767]},
                   {"features": self.features * 2}, {"labels": self.labels[:, None]},
                   {"parent": {"value.weight": torch.zeros(1, 767), "value.bias": torch.zeros(1)}},
                   {"parent": {"value.weight": torch.zeros(1, 768), "value.bias": torch.zeros(1, dtype=torch.float16)}}]
        for index, args in enumerate(invalid):
            with self.subTest(index=index):
                with self.assertRaises(WeightError):
                    self.run_compare(**args)
                self.assertFalse((self.root / ("result-" + str(index))).exists())

    def test_finite_head_overflow_is_explicit_numeric_failure(self):
        parent = {"value.weight": torch.full((1, 768), torch.finfo(torch.float32).max), "value.bias": torch.zeros(1)}
        with self.assertRaises(WeightError) as error:
            self.run_compare(parent=parent)
        self.assertEqual(error.exception.code, "NONFINITE")
        self.assertFalse((self.root / "result-0" / "report.json").exists())

    def test_lineage_fields_required_and_existing_output_not_overwritten(self):
        for lineage in ({}, {**self.lineage, "other": "0" * 64}, {**self.lineage, "head_artifact_sha256": "not-a-hash"}):
            with self.assertRaises(WeightError):
                self.run_compare(lineage=lineage)
        output = self.root / "existing"
        output.mkdir()
        marker = output / "keep.txt"
        marker.write_text("untouched")
        with self.assertRaises(FileExistsError):
            compare(self.features, self.labels, self.parent, self.plan, output, self.lineage)
        self.assertEqual(marker.read_text(), "untouched")


if __name__ == "__main__":
    unittest.main()

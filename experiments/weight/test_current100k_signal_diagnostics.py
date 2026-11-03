"""Numerical, chronological and provenance checks for signal diagnostics."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import torch
import current100k_signal_diagnostics as diagnostics
from safetensors.torch import load_file
from current100k_signal_diagnostics import (compare, constrained_ridge, short_sgd,
    split_rows, standardize, structured_features, validate_plan, LABEL_AVAILABILITY_BASIS)
from weight_runtime.errors import WeightError


class SignalDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        torch.set_num_threads(1)
        self.rows = [{"row_id": str(i), "request_id": "r" + str(i),
                      "input_started_at_ms": 10 + i * 10, "label_resolved_at_ms": 11 + i * 10}
                     for i in range(6)]
        self.fold = {"fit_before_ms": 40, "score_start_ms": 40, "score_end_ms": 70, "embargo_ms": 0}
        self.plan = {"schema": "hepta.weight.current100k.signal-plan.v1", "partition": "previously_viewed_development",
                     "information_cutoff_ms": 100, "folds": [self.fold], "ridge_lambda": .1,
                     "absolute_parameter_l2": .1, "relative_parent_delta_l2": .01,
                     "sgd_budget_seconds": 2., "sgd_max_steps": 5,
                     "sgd_learning_rate": .05, "standardization_floor": 1e-6}

    def test_late_training_label_is_purged_and_not_assigned_hindsight_time(self):
        rows = copy.deepcopy(self.rows)
        rows.insert(0, {"row_id": "late", "request_id": "late", "input_started_at_ms": 2, "label_resolved_at_ms": 60})
        fit, score, purged = split_rows(rows, self.fold, 100)
        self.assertEqual(purged, [0])
        self.assertEqual(fit, [1, 2, 3])
        self.assertEqual(score, [4, 5, 6])

    def test_accounting_availability_bound_is_purged_without_guessing_exact_time(self):
        rows = copy.deepcopy(self.rows)
        rows.insert(0, {"row_id": "bounded", "request_id": "bounded", "input_started_at_ms": 2,
                        "label_available_by_ms": 60, "label_time_basis": LABEL_AVAILABILITY_BASIS})
        original = copy.deepcopy(rows)
        fit, score, purged = split_rows(rows, self.fold, 100)
        self.assertEqual(fit, [1, 2, 3])
        self.assertEqual(score, [4, 5, 6])
        self.assertEqual(purged, [0])
        self.assertEqual(rows, original)
        self.assertNotIn("label_resolved_at_ms", rows[0])
        # A bound exactly at the fit boundary remains unavailable under the
        # same strict rule used for exact-resolution metadata.
        rows[0]["label_available_by_ms"] = self.fold["fit_before_ms"]
        self.assertEqual(split_rows(rows, self.fold, 100)[2], [0])
        rows[0]["label_available_by_ms"] -= 1
        self.assertIn(0, split_rows(rows, self.fold, 100)[0])

    def test_unknown_or_mixed_label_time_provenance_is_rejected(self):
        for metadata in (
            {"label_available_by_ms": 11, "label_time_basis": "GUESSED_EXACT_TIME"},
            {"label_available_by_ms": 11},
            {"label_available_by_ms": 11, "label_time_basis": LABEL_AVAILABILITY_BASIS,
             "label_resolved_at_ms": 11},
            {"label_resolved_at_ms": 11, "label_time_basis": LABEL_AVAILABILITY_BASIS},
        ):
            rows = copy.deepcopy(self.rows)
            rows[0] = {"row_id": "0", "request_id": "r0", "input_started_at_ms": 10, **metadata}
            with self.assertRaises(WeightError):
                split_rows(rows, self.fold, 100)

    def test_report_preserves_upper_bound_basis_without_exact_resolution_field(self):
        generator = torch.Generator().manual_seed(7)
        f = torch.nn.functional.normalize(torch.randn(6, 768, generator=generator), dim=1)
        representations = {"masked_mean": f, "action": f.clone(), "grouped": f.clone(),
                           "structured": torch.randn(6, 8, generator=generator)}
        head = {"value.weight": torch.zeros(1, 768), "value.bias": torch.zeros(1)}
        lineage = {k + "_sha256": "a" * 64 for k in ("features", "labels", "head", "rows")}
        rows = copy.deepcopy(self.rows)
        for row in rows:
            row["label_available_by_ms"] = row.pop("label_resolved_at_ms")
            row["label_time_basis"] = LABEL_AVAILABILITY_BASIS
        with tempfile.TemporaryDirectory() as temp:
            report = compare(representations, torch.zeros(6), head, rows,
                             {**self.plan, "sgd_max_steps": 1}, Path(temp) / "bounded", lineage)
        self.assertEqual(len(report["label_time_metadata"]), len(rows))
        for source, retained in zip(rows, report["label_time_metadata"]):
            self.assertFalse(retained["label_time_is_exact"])
            self.assertEqual(retained["label_time_basis"], LABEL_AVAILABILITY_BASIS)
            self.assertEqual(retained["label_available_by_ms"], source["label_available_by_ms"])
            self.assertNotIn("label_resolved_at_ms", retained)

    def test_same_request_cannot_take_different_times(self):
        self.rows[-1]["request_id"] = self.rows[0]["request_id"]
        with self.assertRaises(WeightError):
            split_rows(self.rows, self.fold, 100)

    def test_overlapping_scoring_folds_and_invalid_embargo_are_rejected(self):
        for other in ({"fit_before_ms": 50, "score_start_ms": 60, "score_end_ms": 90, "embargo_ms": 0},
                      {"fit_before_ms": 65, "score_start_ms": 70, "score_end_ms": 90, "embargo_ms": 10}):
            plan = copy.deepcopy(self.plan)
            plan["folds"].append(other)
            with self.assertRaises(WeightError):
                validate_plan(plan)

    def test_standardization_never_uses_scoring_features(self):
        x = torch.tensor([[1., 4.], [3., 4.], [10000., -9000.]])
        z, mean, scale = standardize(x, [0, 1], 1e-6)
        torch.testing.assert_close(mean, torch.tensor([2., 4.], dtype=torch.float64))
        torch.testing.assert_close(scale, torch.tensor([1., 1.], dtype=torch.float64))
        x[-1] = 1e20
        _, mean2, scale2 = standardize(x, [0, 1], 1e-6)
        self.assertTrue(torch.equal(mean, mean2) and torch.equal(scale, scale2))
        torch.testing.assert_close(z[:2], torch.tensor([[-1., 0.], [1., 0.]]))

    def test_unconstrained_ridge_matches_independent_normal_equations(self):
        x = torch.tensor([[-2., 1.], [0., 2.], [3., -2.], [4., 1.]])
        y = torch.tensor([100., 300., -200., 400.])
        center = torch.tensor([.2, -.1, .5])
        theta, multiplier = constrained_ridge(x, y, center, None, .2)
        a = torch.cat((x.double(), torch.ones(4, 1, dtype=torch.float64)), 1)
        expected = torch.linalg.solve(a.T @ a + .8 * torch.eye(3, dtype=torch.float64), a.T @ (y.double() / 100.) + .8 * center.double())
        torch.testing.assert_close(theta.double(), expected, atol=1e-7, rtol=1e-6)
        self.assertEqual(multiplier, 0.)

    def test_constrained_solution_satisfies_kkt_and_beats_radial_projection(self):
        x = torch.tensor([[20., 0.], [-20., 0.], [0., 1.], [0., -1.]])
        y = torch.tensor([2000., -2000., 1000., -1000.])
        center = torch.zeros(3)
        theta, multiplier = constrained_ridge(x, y, center, .5, .01)
        full, _ = constrained_ridge(x, y, center, None, .01)
        radial = full.double() * (.5 / float(full.double().norm()))
        a = torch.cat((x.double(), torch.ones(4, 1, dtype=torch.float64)), 1)
        objective = lambda v: float((a @ v.double() - y.double()/100.).square().mean() + .01 * v.double().square().sum())
        self.assertLess(objective(theta), objective(radial))
        gradient = a.T @ (a @ theta.double() - y.double()/100.) / 4 + (.01 + multiplier) * theta.double()
        self.assertLess(float(gradient.norm()), 1e-4)
        self.assertAlmostEqual(float(theta.double().norm()), .5, places=6)

    def test_separate_penalty_center_retains_nullspace_in_normal_equations(self):
        x = torch.tensor([[2., 0., 1., 0.], [0., 3., 0., -1.]])
        y = torch.tensor([200., -100.])
        center = torch.tensor([.7, -.1, .4, -.8, .5])
        penalty = torch.tensor([.3, .9, -.6, .8, -.2])
        theta, multiplier = constrained_ridge(x, y, center, None, .4, penalty_center=penalty)
        a = torch.cat((x.double(), torch.ones(2, 1, dtype=torch.float64)), 1)
        expected = torch.linalg.solve(a.T @ a + .8 * torch.eye(5, dtype=torch.float64),
                                      a.T @ (y.double() / 100.) + .8 * penalty.double())
        torch.testing.assert_close(theta.double(), expected, rtol=1e-6, atol=1e-7)
        # With no ball, the same objective cannot depend on an arbitrary ball center.
        other, _ = constrained_ridge(x, y, center + 2., None, .4, penalty_center=penalty)
        torch.testing.assert_close(other, theta, rtol=0, atol=1e-6)
        self.assertEqual(multiplier, 0.)

    def test_separate_penalty_center_and_ball_satisfy_constrained_kkt(self):
        x = torch.tensor([[2., 0., 1., 0.], [0., 3., 0., -1.]])
        y = torch.tensor([200., -100.])
        center = torch.tensor([.7, -.1, .4, -.8, .5])
        penalty = torch.tensor([.3, .9, -.6, .8, -.2])
        theta, multiplier = constrained_ridge(x, y, center, .2, .4, penalty_center=penalty)
        a = torch.cat((x.double(), torch.ones(2, 1, dtype=torch.float64)), 1)
        gradient = (a.T @ (a @ theta.double() - y.double()/100.) / 2
                    + .4 * (theta.double() - penalty.double())
                    + multiplier * (theta.double() - center.double()))
        self.assertLess(float(gradient.norm()), 2e-6)
        self.assertGreater(multiplier, 0.)
        self.assertAlmostEqual(float((theta.double() - center.double()).norm()), .2, places=6)

    def test_sgd_penalty_uses_fixed_prior_while_projection_uses_ball_center(self):
        x = torch.tensor([[1., 0.], [-1., 0.], [0., 1.], [0., -1.]], requires_grad=True)
        y = torch.tensor([100., -100., 200., -200.], requires_grad=True)
        center = torch.tensor([.4, -.3, .2], requires_grad=True)
        penalty = torch.zeros(3, requires_grad=True)
        plan = {**self.plan, "sgd_max_steps": 1}
        meter = {}
        theta, steps, _, lr = short_sgd(x, y, center, .001, plan, penalty_center=penalty, meter=meter)
        a = torch.cat((x, torch.ones(4, 1)), 1)
        gradient = 2 * (a.T @ (a @ center - y/100.) / 4 + plan["ridge_lambda"] * (center - penalty))
        unprojected = center - lr * gradient
        displacement = unprojected.detach().double() - center.detach().double()
        expected = (center.detach().double() + displacement * (.001 / float(displacement.norm()))).float()
        torch.testing.assert_close(theta, expected, rtol=0, atol=1e-7)
        self.assertEqual(steps, 1)
        self.assertEqual(meter["completed_steps"], 1)
        self.assertEqual(meter["backward_calls_completed"], 1)
        self.assertEqual(meter["optimizer_calls_completed"], 1)
        self.assertFalse(meter["step_in_progress"])
        self.assertTrue(all(value.grad is None for value in (x, y, center, penalty)))

    def test_absolute_and_parent_delta_are_different_balls(self):
        x = torch.tensor([[-1.], [0.], [1.]])
        y = torch.zeros(3)
        parent = torch.tensor([1., 1.])
        absolute, _ = constrained_ridge(x, y, torch.zeros(2), .1, .1)
        relative, _ = constrained_ridge(x, y, parent, .1, .1)
        self.assertLess(float(absolute.norm()), 1e-6)
        self.assertGreater(float(relative.norm()), 1.)
        self.assertLessEqual(float((relative - parent).norm()), .100001)

    def test_input_only_lipschitz_rule_stabilizes_high_dimension_sgd(self):
        x = torch.ones((4, 2304))
        y = torch.full((4,), 100.)
        theta, steps, seconds, lr = short_sgd(x, y, torch.zeros(2305), None, self.plan)
        self.assertTrue(torch.isfinite(theta).all())
        self.assertLess(lr, .001)
        self.assertGreater(steps, 0)
        self.assertLessEqual(steps, 5)
        self.assertGreater(seconds, 0.)
        self.assertLess(float(((x @ theta[:-1] + theta[-1]) - 1.).square().mean()), 1.)

    def test_structured_features_use_original_quotes_and_action_only(self):
        quotes = [{"t": 10, "bid": 1., "ask": 1.0002}, {"t": 20, "bid": 1.001, "ask": 1.0012}]
        text = "Recent authoritative quotes=" + json.dumps(quotes) + " tail"
        buy = structured_features(text, "BUY", 30)
        sell = structured_features(text, "SELL", 30)
        self.assertEqual(len(buy), 8)
        torch.testing.assert_close(buy[[0, 2, 3, 4]], -sell[[0, 2, 3, 4]])
        torch.testing.assert_close(buy[[1, 5, 6, 7]], sell[[1, 5, 6, 7]])
        self.assertAlmostEqual(float(buy[-1]), .01, places=6)
        quotes[-1]["known_at_ms"] = 31
        with self.assertRaises(WeightError):
            structured_features("Recent authoritative quotes=" + json.dumps(quotes), "BUY", 30)

    def test_complete_family_serializes_scores_and_preserves_parent(self):
        generator = torch.Generator().manual_seed(7)
        f = torch.nn.functional.normalize(torch.randn(6, 768, generator=generator), dim=1)
        representations = {"masked_mean": f, "action": f.clone(), "grouped": f.clone(),
                           "structured": torch.randn(6, 8, generator=generator)}
        labels = torch.tensor([10., 20., -3., 40., -10., 60.])
        head = {"value.weight": torch.zeros(1, 768), "value.bias": torch.tensor([.05])}
        lineage = {k + "_sha256": "a" * 64 for k in ("features", "labels", "head", "rows")}
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "new"
            with patch.object(diagnostics, "_initialize_optimizer_runtime", wraps=diagnostics._initialize_optimizer_runtime) as initialize:
                report = compare(representations, labels, head, self.rows, self.plan, root, lineage)
            self.assertEqual(initialize.call_count, 1)
            candidates = report["folds"][0]["candidates"]
            self.assertEqual(len(candidates), 16)
            self.assertFalse(report["prospective_evidence"])
            self.assertFalse(report["production_eligible"])
            self.assertTrue(report["parent_recomputation_exact"])
            self.assertEqual(report["encoder_forward_examples"], 0)
            self.assertIsNone(report["astra_seconds"])
            startup = report["shared_optimizer_initialization"]
            self.assertEqual(startup["status"], "COMPLETED")
            self.assertEqual(startup["labels_read"], 0)
            self.assertEqual(startup["input_rows_read"], 0)
            self.assertEqual(startup["gradient_steps"], 0)
            self.assertGreaterEqual(startup["wall_seconds"], 0.)
            self.assertGreaterEqual(report["total_seconds"], startup["wall_seconds"])
            self.assertEqual(len(report["sgd_attempts"]), 6)
            self.assertEqual(report["total_gradient_steps"], sum(c["gradient_steps"] for c in candidates))
            self.assertTrue((root / "started.json").exists())
            self.assertFalse((root / "failure.json").exists())
            constrained = {c["name"]: c for c in candidates if c["joint_norm_radius"] is not None}
            absolute = constrained["masked_mean:absolute:ridge"]
            relative = constrained["masked_mean:parent_delta:ridge"]
            self.assertEqual(absolute["ridge_penalty_center_sha256"], relative["ridge_penalty_center_sha256"])
            self.assertNotEqual(absolute["constraint_center_sha256"], relative["constraint_center_sha256"])
            for candidate in candidates:
                state = load_file(candidate["head"]["path"])
                self.assertTrue(all(t.dtype == torch.float32 for t in state.values()))
                self.assertEqual(candidate["fit"]["rows"], 3)
                self.assertEqual(candidate["chronological_development_score"]["rows"], 3)
                if candidate["joint_norm_radius"] is not None:
                    self.assertLessEqual(candidate["actual_distance_to_center"], candidate["joint_norm_radius"] + candidate["norm_rounding_tolerance"])
            with self.assertRaises(FileExistsError):
                compare(representations, labels, head, self.rows, self.plan, root, lineage)
        self.assertTrue(torch.equal(head["value.bias"], torch.tensor([.05])))

    def test_interrupted_optimizer_retains_actual_partial_counts_and_failure_cost(self):
        generator = torch.Generator().manual_seed(7)
        f = torch.nn.functional.normalize(torch.randn(6, 768, generator=generator), dim=1)
        representations = {"masked_mean": f, "action": f.clone(), "grouped": f.clone(),
                           "structured": torch.randn(6, 8, generator=generator)}
        labels = torch.tensor([10., 20., -3., 40., -10., 60.])
        head = {"value.weight": torch.zeros(1, 768), "value.bias": torch.tensor([.05])}
        lineage = {k + "_sha256": "a" * 64 for k in ("features", "labels", "head", "rows")}
        calls = []
        original = torch.optim.SGD.step
        def interrupted(optimizer, *args, **kwargs):
            calls.append(1)
            if len(calls) == 3:
                raise RuntimeError("fixture third optimizer failure")
            return original(optimizer, *args, **kwargs)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "failed"
            with patch.object(torch.optim.SGD, "step", interrupted):
                with self.assertRaisesRegex(RuntimeError, "fixture third optimizer failure"):
                    compare(representations, labels, head, self.rows, self.plan, root, lineage)
            failure = json.loads((root / "failure.json").read_text())
            self.assertFalse(failure["completed"])
            self.assertFalse(failure["automatic_replay_allowed"])
            self.assertEqual(len(failure["completed_candidates"]), 5)
            self.assertEqual(failure["shared_optimizer_initialization"]["status"], "COMPLETED")
            attempt, = failure["sgd_attempts"]
            self.assertEqual(attempt["status"], "FAILED")
            self.assertEqual(attempt["backward_calls_started"], 3)
            self.assertEqual(attempt["backward_calls_completed"], 3)
            self.assertEqual(attempt["optimizer_calls_started"], 3)
            self.assertEqual(attempt["optimizer_calls_completed"], 2)
            self.assertEqual(attempt["completed_steps"], 2)
            self.assertTrue(attempt["step_in_progress"])
            self.assertGreater(failure["wall_seconds"], attempt["wall_seconds"])
            self.assertGreaterEqual(failure["process_cpu_seconds"], attempt["process_cpu_seconds"])
            self.assertFalse((root / "report.json").exists())
            with self.assertRaises(FileExistsError):
                compare(representations, labels, head, self.rows, self.plan, root, lineage)

    def test_shared_initialization_failure_has_no_unrecorded_training(self):
        generator = torch.Generator().manual_seed(7)
        f = torch.nn.functional.normalize(torch.randn(6, 768, generator=generator), dim=1)
        representations = {"masked_mean": f, "action": f.clone(), "grouped": f.clone(),
                           "structured": torch.randn(6, 8, generator=generator)}
        head = {"value.weight": torch.zeros(1, 768), "value.bias": torch.zeros(1)}
        lineage = {k + "_sha256": "a" * 64 for k in ("features", "labels", "head", "rows")}
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "startup-failed"
            with patch.object(torch.optim, "SGD", side_effect=RuntimeError("fixture runtime initialization failure")):
                with self.assertRaisesRegex(RuntimeError, "fixture runtime initialization failure"):
                    compare(representations, torch.zeros(6), head, self.rows, self.plan, root, lineage)
            failure = json.loads((root / "failure.json").read_text())
            self.assertEqual(failure["shared_optimizer_initialization"]["status"], "FAILED")
            self.assertGreater(failure["shared_optimizer_initialization"]["wall_seconds"], 0.)
            self.assertEqual(failure["sgd_attempts"], [])
            self.assertEqual(failure["completed_candidates"], [])
            self.assertFalse((root / "report.json").exists())


if __name__ == "__main__":
    unittest.main()

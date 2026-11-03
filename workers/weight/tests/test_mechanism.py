"""Real CPU tensor/model checks for fixed mechanism experiments and their controls."""
import copy
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch as mock_patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import torch
from safetensors.torch import save_file

from weight_runtime.artifacts import file_sha256
from weight_runtime.errors import WeightError, canonical, digest
from weight_runtime.mechanism import ExperimentPlan, norm_match, required_limits, run_experiment
from weight_runtime.patches import tensor_sha256
from weight_runtime.session import Session


class MechanismTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.session = None
        self.open(torch.tensor([[1., 1.], [0., 1.]]))

    def tearDown(self):
        if self.session is not None:
            self.session.close({})
        self.temporary.cleanup()

    def open(self, weights):
        if self.session is not None:
            self.session.close({})
        subroot = self.root / ("model-" + str(len(list(self.root.iterdir()))))
        subroot.mkdir()
        self.weights = weights
        path = subroot / "weights.safetensors"
        save_file({"0.weight": weights}, str(path))
        self.config = {"provider": "torch_sequential", "input_roots": [str(self.root)],
                       "output_root": str(subroot / "artifacts"), "cpu_threads": 1,
                       "limits": {"max_forward_examples": 18, "max_patch_candidates": 4},
                       "model": {"architecture": {"layers": [{"type": "Linear", "in_features": 2,
                                                                 "out_features": 2, "bias": False}]},
                                 "weights_path": str(path), "weights_sha256": file_sha256(path)}}
        self.session = Session("mechanism-test")
        self.opened = self.session.open(self.config)
        inputs = [{"x": [[1., 0.]]}, {"x": [[1., 1.]]}, {"x": [[2., -1.]]}]
        self.plan = {"schema": "hepta.weight.mechanism-plan.v1", "experiment_id": "test-plan",
                     "expected_model_id": self.opened["model_id"], "expected_backend_id": self.opened["backend_id"],
                     "data_role": "development", "input_lineage": {"source": "deterministic synthetic fixture"},
                     "target": {"tensor": "0.weight", "expected_tensor_sha256": tensor_sha256(weights),
                                "family": "additive_delta", "delta": [[0., -1.], [0., 0.]], "max_relative_norm": 1.0},
                     "cases": [{"case_id": "input-" + str(i), "inputs": value,
                                "input_sha256": digest(value), "expected_examples": 1}
                               for i, value in enumerate(inputs)],
                     "doses": [0, .5, 1], "random_controls": 1, "random_seed": 37,
                     "random_norm_rtol": .02, "output_names": ["output"], "probability_outputs": [],
                     "budgets": {"max_forward_examples": 18, "max_patch_candidates": 4}}

    def run_plan(self, plan=None, call=None):
        return run_experiment(call or self.session.dispatch, self.opened, plan or self.plan)

    def output(self, condition, case=0):
        ref = condition["observations"][case]["outputs"]
        return self.session.store.load_tensors(ref["artifact_id"])["output"]

    def test_same_input_dose_response_random_control_and_restoration(self):
        result = self.run_plan()
        zero, half, full, random = result["candidates"]
        self.assertTrue(zero["zero_dose_exact_noop"])
        self.assertEqual(self.output(zero, 1)[0, 0].item(), 2.)
        self.assertEqual(self.output(half, 1)[0, 0].item(), 1.5)
        self.assertEqual(self.output(full, 1)[0, 0].item(), 1.)
        # The synthetic mechanism removes x1 from output 0 while preserving x0.
        self.assertEqual(self.output(full, 0)[0, 0].item(), 1.)
        self.assertEqual(self.output(full, 2)[0, 0].item(), 2.)
        self.assertTrue(random["random_control"]["post_storage_norm_match"]["passed"])
        self.assertEqual(result["cost"]["forward_examples"], 18)
        self.assertEqual(result["cost"]["patch_candidates"], 4)
        self.assertGreater(result["cost"]["model_forward_seconds"], 0)
        self.assertTrue(result["parent_restoration"]["passed"])
        self.assertEqual(tensor_sha256(self.session.provider.get_tensor("0.weight")), tensor_sha256(self.weights))
        self.assertEqual(file_sha256(self.config["model"]["weights_path"]), self.config["model"]["weights_sha256"])
        self.assertFalse(result["production_eligible"])
        self.assertFalse(result["new_unseen_or_prospective_data"])
        self.assertFalse(result["diagnosis_present"])
        self.assertEqual(result["hypothesis_status"], "not_provided")
        self.assertTrue(all(p.grad is None for p in self.session.provider.module.parameters()))

    def test_preflight_binds_all_candidates_and_forward_examples(self):
        self.assertEqual(required_limits(self.plan), {"max_forward_examples": 18, "max_patch_candidates": 4})
        calls = []
        plan = copy.deepcopy(self.plan)
        plan["budgets"]["max_forward_examples"] = 17
        with self.assertRaises(WeightError) as error:
            self.run_plan(plan, lambda op, params: calls.append(op))
        self.assertEqual(error.exception.code, "EXPERIMENT_BUDGET")
        self.assertEqual(calls, [])
        self.assertEqual(self.session.forward_examples, 0)

    def test_structured_hypothesis_is_retained_without_claiming_verification(self):
        hypothesis = {"statement": "The first output contains an unwanted x1 contribution.",
                      "expected_observation": "Removing W[0,1] leaves the x0 response and removes x1 response.",
                      "falsifying_observation": "The x0 response changes or the x1 response remains.",
                      "diagnostic_evidence": [{"ref": "synthetic:known-linear-coefficients",
                                               "sha256": tensor_sha256(self.weights)}],
                      "author_model": "test-fixture"}
        self.plan["hypothesis"] = hypothesis
        result = self.run_plan()
        self.assertEqual(result["hypothesis"], hypothesis)
        self.assertTrue(result["diagnosis_present"])
        self.assertFalse(result["hypothesis_evidence_verified_by_runner"])
        self.assertEqual(result["hypothesis_status"], "declared_for_testing")

    def test_incomplete_hypotheses_are_rejected_before_any_forward(self):
        template = {"statement": "Cause", "expected_observation": "Effect", "falsifying_observation": "Failure",
                    "diagnostic_evidence": [{"ref": "artifact:example", "sha256": "a" * 64}], "author_model": "test-fixture"}
        for change in ({"statement": " "}, {"diagnostic_evidence": []}, {"author_model": 42},
                       {"diagnostic_evidence": [{"ref": "example", "sha256": "bad"}]}, {"unknown": True}):
            plan = copy.deepcopy(self.plan)
            plan["hypothesis"] = {**template, **change}
            with self.assertRaises(WeightError):
                ExperimentPlan.parse(plan)
        self.assertEqual(self.session.forward_examples, 0)

    def test_model_and_backend_pins_are_checked_before_work(self):
        for field in ("expected_model_id", "expected_backend_id"):
            plan = copy.deepcopy(self.plan)
            plan[field] = "f" * 64
            with self.assertRaises(WeightError) as error:
                self.run_plan(plan)
            self.assertEqual(error.exception.code, "IDENTITY_MISMATCH")
        self.assertEqual(self.session.forward_examples, 0)

    def test_mutating_caller_plan_does_not_change_frozen_inputs(self):
        original_plan_hash = digest(self.plan)
        changed = False
        def call(operation, params):
            nonlocal changed
            result = self.session.dispatch(operation, params)
            if operation == "probe" and not changed:
                self.plan["cases"][0]["inputs"] = {"x": [[999., 999.]]}
                changed = True
            return result
        result = self.run_plan(call=call)
        self.assertEqual(result["plan_sha256"], original_plan_hash)
        self.assertEqual(self.output(result["candidates"][2], 0)[0, 0].item(), 1.)
        self.assertTrue(result["parent_restoration"]["passed"])

    def test_encoded_input_drift_rejected_after_real_forward(self):
        def call(operation, params):
            result = self.session.dispatch(operation, params)
            if operation == "probe" and "patch_id" in params:
                result["input"]["model_input_id"] = "f" * 64
            return result
        with self.assertRaises(WeightError) as error:
            self.run_plan(call=call)
        self.assertEqual(error.exception.code, "INPUT_ENCODING_MISMATCH")
        self.assertEqual(tensor_sha256(self.session.provider.get_tensor("0.weight")), tensor_sha256(self.weights))

    def test_actual_batch_size_cannot_silently_exceed_plan(self):
        plan = copy.deepcopy(self.plan)
        case = plan["cases"][0]
        case["inputs"] = {"x": [[1., 0.], [2., 1.]]}
        case["input_sha256"] = digest(case["inputs"])
        with self.assertRaises(WeightError) as error:
            self.run_plan(plan)
        self.assertEqual(error.exception.code, "FORWARD_COUNT_MISMATCH")
        self.assertEqual(self.session.forward_examples, 2)
        self.assertEqual(self.session.patch_candidates, 0)

    def test_storage_precision_noop_does_not_validate_random_control(self):
        self.open(torch.full((2, 2), 1024., dtype=torch.bfloat16))
        self.plan["target"]["delta"] = [[1e-5, 0.], [0., 0.]]
        result = self.run_plan()
        full, random = result["candidates"][2:]
        self.assertEqual(full["patch"]["effective_changed_coordinates"], 0)
        self.assertEqual(full["patch"]["storage_changed_coordinates"], 0)
        self.assertTrue(full["patch"]["storage_bytes_unchanged"])
        match = random["random_control"]["post_storage_norm_match"]
        self.assertFalse(match["passed"])
        self.assertIsNone(match["effective"]["relative_error"])
        self.assertEqual(full["patch"]["measurements"][0]["final_dtype"], "torch.bfloat16")

    def test_zero_dose_preserves_signed_zero_bytes(self):
        self.open(torch.tensor([[1., -0.], [0., 1.]]))
        result = self.run_plan()
        self.assertTrue(result["candidates"][0]["patch"]["storage_bytes_unchanged"])
        self.assertTrue(result["candidates"][0]["zero_dose_exact_noop"])

    def test_writer_control_keeps_rank_and_checks_realized_norm(self):
        target = self.plan["target"]
        target.pop("delta")
        target.update(family="writer_projection", direction=[1., 0.])
        result = self.run_plan()
        full, random = result["candidates"][2:]
        self.assertTrue(torch.equal(self.output(full, 1), torch.tensor([[0., 1.]])))
        self.assertIn("rank-one", random["random_control"]["construction"])
        self.assertTrue(random["random_control"]["post_storage_norm_match"]["passed"])

    def test_effective_match_cannot_hide_storage_norm_mismatch(self):
        parent = {"measurements": [{"delta_l2": 1.0}], "storage_measurements": [{"storage_delta_l2": 2.0}]}
        control = {"measurements": [{"delta_l2": 1.0}], "storage_measurements": [{"storage_delta_l2": 3.0}]}
        result = norm_match(parent, control, .02)
        self.assertTrue(result["effective"]["matched"])
        self.assertFalse(result["storage"]["matched"])
        self.assertFalse(result["passed"])

    def test_current100k_counts_cached_work_and_recomputes_final_parent(self):
        from test_current100k_provider import EncoderFixture, TokenFixture, head, row
        from weight_runtime.artifacts import ArtifactStore
        from weight_runtime.current100k import Current100kProvider
        self.session.close({})
        self.session = Session("current100k-mechanism-test")
        rows = [row(), row("SELL", 1)]
        encoder = EncoderFixture()
        tokenizer = TokenFixture({rows[0]["feature_text"]: ([1, 2, 9], [1, 1, 0]),
                                  rows[1]["feature_text"]: ([3, 9], [1, 0])})
        store = ArtifactStore(self.root / "current100k")
        provider = Current100kProvider(encoder, tokenizer, head(), {"fixture": "mechanism-cache"}, store)
        self.session.provider, self.session.store = provider, store
        self.session.limits.update(max_forward_examples=18, max_patch_candidates=4)
        self.opened = {"model_id": provider.model_id, "backend_id": provider.backend_id,
                       "limits": self.session.limits, "model": provider.describe()}
        self.plan.update(expected_model_id=provider.model_id, expected_backend_id=provider.backend_id,
                         output_names=["value_usd"], probability_outputs=["value_usd"])
        self.plan["target"] = {"tensor": "value.weight", "expected_tensor_sha256": tensor_sha256(head()["value.weight"]),
                               "rows": [0], "columns": [0, 1], "family": "additive_delta",
                               "delta": [[.001, -.001]], "max_relative_norm": .1}
        inputs = {"rows": rows}
        self.plan["cases"] = [{"case_id": "paired", "inputs": inputs, "input_sha256": digest(inputs), "expected_examples": 2}]
        with self.assertRaises(WeightError) as error:
            self.run_plan()
        self.assertEqual(error.exception.code, "TASK_SEMANTICS")
        self.assertEqual(self.session.forward_examples, 0)
        self.plan["probability_outputs"] = []
        result = self.run_plan()
        self.assertEqual(result["cost"]["forward_examples"], 12)
        self.assertEqual(result["cost"]["encoder_forward_examples"], 4)
        self.assertEqual(result["cost"]["feature_cache_hits"], 8)
        self.assertEqual(len(encoder.calls), 4)
        self.assertTrue(result["parent_restoration"]["final_encoder_recomputed"])
        final = result["parent_after"][0]
        self.assertTrue(final["bypass_feature_cache"])
        self.assertEqual(final["computation"]["feature_cache_bypass_reason"], "explicit_recomputation")

    def test_final_operation_over_deadline_keeps_cost_and_cannot_complete(self):
        clock = [0.0]
        self.plan["budgets"]["max_wall_seconds"] = 1.0
        def call(operation, params):
            result = self.session.dispatch(operation, params)
            if operation == "inspect" and self.session.forward_examples == 18:
                clock[0] = 2.0
            return result
        with mock_patch("weight_runtime.mechanism.time.monotonic", side_effect=lambda: clock[0]):
            with self.assertRaises(WeightError) as error:
                self.run_plan(call=call)
        self.assertEqual(error.exception.code, "EXPERIMENT_BUDGET")
        self.assertEqual(error.exception.details["completed_operation"], "inspect")
        self.assertEqual(error.exception.details["partial_cost"]["forward_examples"], 18)
        self.assertEqual(error.exception.details["partial_cost"]["patch_candidates"], 4)

    def test_invalid_plan_fields_and_nonfinite_delta_fail_without_forward(self):
        for alteration in (lambda p: p.update(unexpected=True),
                           lambda p: p["cases"][0].update(expected_examples=True),
                           lambda p: p.update(doses=[0, 1, 2])):
            plan = copy.deepcopy(self.plan)
            alteration(plan)
            with self.assertRaises(WeightError):
                ExperimentPlan.parse(plan)
        self.plan["target"]["delta"] = [[0., 0.], [0., 0.]]
        with self.assertRaises(WeightError):
            self.run_plan()
        self.assertEqual(self.session.forward_examples, 0)

    def test_cli_completed_replay_and_incomplete_run_refusal(self):
        script = Path(__file__).resolve().parents[3] / "experiments" / "weight" / "mechanism_experiment.py"
        spec = importlib.util.spec_from_file_location("mechanism_cli", script)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        out = self.root / "cli"
        config = copy.deepcopy(self.config)
        config["output_root"] = str(out / "artifacts")
        config_path, plan_path = self.root / "config.json", self.root / "plan.json"
        config_path.write_bytes(canonical(config))
        plan_path.write_bytes(canonical(self.plan))
        args = (config_path, file_sha256(config_path), plan_path, file_sha256(plan_path), out)
        first = module.run(*args)
        second = module.run(*args)
        self.assertEqual(first, second)
        self.assertEqual(first["cost"]["forward_examples"], 18)
        self.assertTrue(first["close"]["closed"])
        other = self.root / "interrupted"
        other.mkdir()
        (other / "started.json").write_text("{}")
        config["output_root"] = str(other / "artifacts")
        config_path.write_bytes(canonical(config))
        with self.assertRaises(WeightError) as error:
            module.run(config_path, file_sha256(config_path), plan_path, file_sha256(plan_path), other)
        self.assertEqual(error.exception.code, "UNKNOWN_OPERATION_STATE")


if __name__ == "__main__":
    unittest.main()

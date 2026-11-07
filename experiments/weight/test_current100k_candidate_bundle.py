"""Real small-tensor bundle tests; synthetic provenance grants no source authority."""
import copy
from pathlib import Path
import sys
import tempfile
import unittest

sys.path[:0] = [str(Path(__file__).resolve().parent),
               str(Path(__file__).resolve().parents[2] / "workers" / "weight"),
               str(Path(__file__).resolve().parents[2] / "workers" / "weight" / "tests")]
import current100k_candidate_bundle as B
from weight_runtime.errors import WeightError, canonical, digest
try:
    import torch
    from safetensors.torch import load_file, save_file
except ModuleNotFoundError:
    torch = None


class DecimalLabelTests(unittest.TestCase):
    def test_real_decimal_strings_use_the_source_study_float_conversion(self):
        for value in ("-2.000000000000000000", "4.000000100000000000", "+1.25E-3", ".5", "-0.00", 3, 2.5):
            with self.subTest(value=value):
                self.assertEqual(B._net_usd_float(value), float(value))

    def test_nonfinite_invalid_and_boolean_labels_are_rejected(self):
        for value in (True, False, None, [], {}, "", " ", "NaN", "Infinity", "-inf", "1e309",
                      "1_000", "2 USD", float("nan"), float("inf"), 10 ** 400):
            with self.subTest(value=repr(value)), self.assertRaises(WeightError):
                B._net_usd_float(value)


class CostFairnessTests(unittest.TestCase):
    def args(self):
        mechanism = {"cost": {"wall_seconds": 9., "model_forward_seconds": 8.8}, "load_seconds": 2.,
                     "gradient_steps": 0, "optimizer_calls": 0}
        baseline = {"total_seconds": .8, "examples": 54,
                    "candidates": [{"name": n, "gradient_steps": 12 if n == "sgd_head_capped" else 0} for n in B.BASELINES]}
        candidates = [{"arm": "full", "origin": "mechanism", "role": "dose", "dose": 1.,
                       "actual_head_delta_l2": .02549, "constraint_scope": "mechanism target"}]
        receipts = []
        for c in baseline["candidates"]:
            value = {"schema": "hepta.weight.baseline-cost.v1", "candidate": c["name"], "construction_seconds": .05,
                     "serialization_reload_scoring_seconds": .01, "training_seconds": .04 if c["gradient_steps"] else 0.,
                     "gradient_steps": c["gradient_steps"], "optimizer_calls": c["gradient_steps"], "encoder_forward_examples": 0}
            receipts.append(({"path": "/synthetic/" + c["name"], "sha256": digest(value)}, value))
        return mechanism, baseline, {"max_head_delta_l2": .00721934}, candidates, receipts

    def test_overlapping_and_unknown_costs_and_distinct_caps(self):
        report = B.audit_costs(*self.args())
        self.assertEqual(report["mechanism"]["wall_seconds_after_open"], 9.)
        self.assertIsNone(report["end_to_end_total_seconds"])
        self.assertIsNone(report["astra_diagnosis_seconds"])
        self.assertIsNone(report["shared_historical_encoding_seconds"])
        self.assertFalse(report["speedup_established"])
        self.assertFalse(report["full_mechanism_within_baseline_cap"])
        self.assertFalse(report["same_constraint_comparison_established"])

    def test_duplicate_receipts_not_counted_twice(self):
        args = self.args();args[-1].append(copy.deepcopy(args[-1][0]))
        self.assertEqual(B.audit_costs(*args)["baselines"]["unique_cost_receipts"], 6)

    def test_nonfinite_negative_and_contradictory_costs_rejected(self):
        for field, value in (("training_seconds", -1.), ("construction_seconds", float("nan")), ("optimizer_calls", 1)):
            args = self.args();args[-1][0][1][field] = value
            with self.subTest(field=field), self.assertRaises(WeightError):
                B.audit_costs(*args)


class HistoricalEncoderQualificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = {"encoder_backend": "LAYA_HIP_FP32_SINGLE_ROW_MAX2048_NO_TRUNCATION_V1",
                       "encoder_threads": 2, "encoder_batch_size": 1,
                       "head_execution_backend": "TORCH_CPU_FP32", "hip_runtime_manifest_sha256": "f" * 64}
        self.evidence = {"schema": "heptatrader.current100k-hip-parity-benchmark.v1",
                         "scope": "KNOWN_DEVELOPMENT_REQUESTS_NOT_PROSPECTIVE",
                         "backend": self.config["encoder_backend"], "encoder_threads": 2, "encoder_batch_size": 1,
                         "heads_backend": "TORCH_CPU_FP32", "hip_runtime_manifest_sha256": "f" * 64,
                         "feature_cache_sha256": "a" * 64, "actual_loader_sha256": "b" * 64,
                         "candidate_bundle_sha256": "c" * 64, "cleanup_verified": True,
                         "allocation_after_close_bytes": 0, "cleanup_receipt": {"all_model_allocations_released": True},
                         "parity_limits": {"feature_max_abs": 2e-5, "all_heads_max_abs_usd": .001},
                         "samples": [{"row_index": i, "backend": self.config["encoder_backend"],
                                      "max_feature_abs_error": 3e-7, "total_encode_and_heads_seconds": 2.,
                                      "head_max_abs_usd_errors": {"old_parent": 3e-6}, "parity_passed": True}
                                     for i in (0, 18, 36, 53)]}
        self.bundle = {"request": self.write("request.json", {"features": {"sha256": "a" * 64}}),
                       "encoder_identity": {"loader_sha256": "b" * 64}, "development_examples": 54}
        self.qualification = {"schema": "heptatrader.weight-shadow-backend-qualification.v1",
                              "scope": "HISTORICAL_REPLAY_ONLY_NOT_FUTURE_PREOPEN_PROOF",
                              "backend": self.config["encoder_backend"], "encoder_threads": 2, "encoder_batch_size": 1,
                              "head_execution_backend": "TORCH_CPU_FP32", "hip_runtime_manifest_sha256": "f" * 64,
                              "tensor_cleanup_verified": True, "max_request_seconds": 2., "deadline_budget_seconds": 4.5}

    def write(self, name, value):
        path = self.root / name;path.write_bytes(canonical(value) + b"\n");return B.file_ref(path)

    def check(self):
        ref = self.write("evidence.json", self.evidence)
        return B.reused_encoder_qualification({**self.qualification, "evidence_path": ref["path"], "evidence_sha256": ref["sha256"]},
                                             self.bundle, self.config)

    def test_actual_historical_evidence_is_scoped_to_its_sample(self):
        result = self.check();self.assertTrue(result["verified"])
        self.assertEqual(result["sample_indices"], [0, 18, 36, 53])
        self.assertFalse(result["sample_maximum_is_global_input_bound"])
        self.assertFalse(result["old_head_results_count_as_new_family_results"])
        self.assertFalse(result["future_preopen_proof"])

    def test_backend_label_without_same_cache_and_loader_is_insufficient(self):
        self.evidence["actual_loader_sha256"] = "d" * 64
        self.assertFalse(self.check()["verified"])
        self.evidence["actual_loader_sha256"] = "b" * 64
        self.evidence["feature_cache_sha256"] = "e" * 64
        self.assertFalse(self.check()["verified"])

    def test_failed_sample_or_cleanup_cannot_be_reused(self):
        self.evidence["samples"][0]["max_feature_abs_error"] = .001
        self.assertFalse(self.check()["verified"])
        self.evidence["samples"][0]["max_feature_abs_error"] = 3e-7
        self.evidence["cleanup_verified"] = False
        self.assertFalse(self.check()["verified"])

    def test_missing_original_evidence_leaves_pending_status(self):
        self.qualification.update(evidence_path=str(self.root / "absent.json"), evidence_sha256="a" * 64)
        result = B.reused_encoder_qualification(self.qualification, self.bundle, self.config)
        self.assertFalse(result["verified"]);self.assertEqual(result["status"], "PENDING_EVIDENCE_VERIFICATION")


@unittest.skipIf(torch is None, "Requires the existing PyTorch/safetensors test environment")
class CandidateBundleTests(unittest.TestCase):
    def setUp(self):
        from current100k_baselines import compare
        from test_current100k_provider import EncoderFixture, TokenFixture, row, head
        from weight_runtime.artifacts import ArtifactStore
        from weight_runtime.current100k import Current100kProvider
        from weight_runtime.mechanism import run_experiment
        from weight_runtime.patches import tensor_sha256
        from weight_runtime.session import Session
        torch.set_num_threads(1)
        self.temporary = tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name);self.serial = 0;self.parent = head()
        save_file(self.parent, str(self.root / "parent.safetensors"))
        parent_ref = B.file_ref(self.root / "parent.safetensors")
        rows = [row(), row("SELL", 1)]
        for i, r in enumerate(rows):
            r["row_id"], r["input_id"] = digest({"row": i}), digest({"input": i})
        observed = B.clock_ms() - 100
        data_rows = [{**r, "net_usd": format(y, ".18f"), "reward_id": digest({"reward": i})} for i, (r, y) in enumerate(zip(rows, [-2., 4.]))]
        data_ref = self.write("development.json", {"rows": data_rows, "producer_manifest_sha256": "a" * 64, "observed_at_ms": observed})
        x = torch.zeros((2, 768));x[0, :2] = torch.tensor([3., 4.]);x[1, :2] = torch.tensor([1., -2.])
        x = torch.nn.functional.normalize(x, dim=-1);y = torch.tensor([-2., 4.])
        save_file({"features": x}, str(self.root / "features.safetensors"))
        save_file({"labels_usd": y}, str(self.root / "labels.safetensors"))
        baseline_plan = {"schema": "hepta.weight.current100k.baselines-plan.v1", "partition": "development",
                         "information_cutoff_ms": observed, "max_label_resolved_at_ms": observed, "ridge_lambda": 2.,
                         "max_head_delta_l2": .005, "sgd_budget_seconds": 1., "sgd_max_steps": 2, "sgd_learning_rate": .05}
        compare(x, y, self.parent, baseline_plan, self.root / "baseline",
                {k + "_artifact_sha256": B.file_ref(self.root / (v + ".safetensors"))["sha256"]
                 for k, v in (("head", "parent"), ("feature", "features"), ("label", "labels"))})
        store = ArtifactStore(self.root / "mechanism" / "artifacts")
        tokenizer = TokenFixture({r["feature_text"]: pair for r, pair in zip(rows, [([1, 2, 9], [1, 1, 0]), ([3, 9], [1, 0])])})
        identity = {"base_id": "b" * 64, "source_tree_sha256": "c" * 64, "base_manifest_sha256": "d" * 64,
                    "head_sha256": parent_ref["sha256"], "loader_sha256": "e" * 64}
        provider = Current100kProvider(EncoderFixture(), tokenizer, self.parent, identity, store)
        self.session = Session("bundle-fixture");self.session.provider, self.session.store = provider, store
        self.session.limits.update(max_forward_examples=14, max_patch_candidates=5)
        self.addCleanup(self.session.close, {})
        opened = {"model_id": provider.model_id, "backend_id": provider.backend_id, "model": provider.describe(), "limits": self.session.limits}
        delta = torch.zeros((1, 768));delta[0, 0] = -.01;inputs = {"rows": rows}
        plan = {"schema": "hepta.weight.mechanism-plan.v1", "experiment_id": "bundle-fixture",
                "expected_model_id": provider.model_id, "expected_backend_id": provider.backend_id,
                "data_role": "development", "input_lineage": {"scope": "synthetic fixture"},
                "target": {"tensor": "value.weight", "expected_tensor_sha256": tensor_sha256(self.parent["value.weight"]),
                           "family": "additive_delta", "delta": delta.tolist(), "max_relative_norm": 1.},
                "cases": [{"case_id": "two-rows", "inputs": inputs, "input_sha256": digest(inputs), "expected_examples": 2}],
                "doses": [0., .5, 1.], "random_controls": 2, "random_seed": 37, "random_norm_rtol": .02,
                "output_names": ["value_usd"], "probability_outputs": [],
                "budgets": {"max_forward_examples": 14, "max_patch_candidates": 5}}
        self.report = run_experiment(self.session.dispatch, opened, plan)
        self.write("mechanism/summary.json", self.report);self.write("mechanism/plan.json", plan)
        self.write("mechanism/receipts.json", [{"request": {"op": "open"}, "response": {"ok": True, "result": opened}}])
        old = {"schema": "heptatrader.current100k-weight-shadow-plan.v1", "producer_registration": {"sha256": "9" * 64}}
        old["plan_id"] = digest(old);self.old_ref = self.write("old-study/plan.json", old)
        self.request = {"schema": B.REQUEST_SCHEMA, "parent_head": parent_ref, "development_dataset": data_ref,
                        "ordered_development_row_ids": [r["row_id"] for r in rows], "prior_plans": [self.old_ref],
                        "information_cutoff_ms": B.clock_ms()}
        for key, name in (("features", "features.safetensors"), ("labels", "labels.safetensors"),
                          ("mechanism_summary", "mechanism/summary.json"), ("mechanism_plan", "mechanism/plan.json"),
                          ("mechanism_receipts", "mechanism/receipts.json"), ("baseline_report", "baseline/report.json"),
                          ("baseline_plan", "baseline/plan.json")):
            self.request[key] = B.file_ref(self.root / name)

    def write(self, name, value):
        path = self.root / name;path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(canonical(value) + b"\n");return B.file_ref(path)

    def output(self):
        self.serial += 1;return self.root / ("output-" + str(self.serial))

    def bundle(self):
        out = self.output();value = B.build_bundle(self.request, out)
        return value, B.file_ref(out / "bundle.json")

    def prepare_request(self, bundle, hip=False):
        producer = self.write("new-source.json", {"source": "synthetic"})
        period = self.write("period.json", {"period": "synthetic"})
        reward = self.write("reward.json", {"period_path": period["path"], "period_sha256": period["sha256"]})
        rows = B.read_json(self.request["development_dataset"])["rows"]
        config = {"schema": "heptatrader.current100k-weight-shadow-config.v1", "base_id": "b" * 64,
                  "behavior_model_id": "behavior-v1", "period_sha256": period["sha256"], "producer_registration": producer,
                  "heads": {}, "parent_arm": "old_parent", "training_dataset_path": self.request["development_dataset"]["path"],
                  "training_dataset_sha256": self.request["development_dataset"]["sha256"], "training_mean_usd": 1.,
                  "training_input_ids": [r["input_id"] for r in rows], "training_reward_ids": [r["reward_id"] for r in rows],
                  "training_row_ids": [r["row_id"] for r in rows], "training_cutoff_ms": self.request["information_cutoff_ms"],
                  "labels_observed_at_ms": self.request["information_cutoff_ms"], "reward_config_path": reward["path"],
                  "reward_config_sha256": reward["sha256"], "training_producer_manifest_sha256": "a" * 64,
                  "encoder_backend": "LAYA_HIP_FP32_SINGLE_ROW_MAX2048_NO_TRUNCATION_V1" if hip else "cpu_fp32",
                  "encoder_threads": 2, "encoder_batch_size": 1, "head_execution_backend": "TORCH_CPU_FP32",
                  "hip_runtime_manifest_sha256": "f" * 64 if hip else None,
                  "trade_authority": False, "automatic_selection": False, "actor_update": False}
        return {"schema": B.PREPARE_SCHEMA, "bundle": bundle, "registration_template": self.write("template.json", config),
                "producer_manifest": producer, "collector_implementation": B.file_ref(Path(B.__file__).absolute()),
                "new_study_root": str(self.root / "future-study")}

    def test_all_eleven_heads_reloaded_and_parent_and_original_sources_preserved(self):
        before = {str(p): p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        bundle, _ = self.bundle();self.assertEqual(len(bundle["candidates"]), 11)
        for c in bundle["candidates"]:
            state = load_file(c["head"]["path"]);self.assertEqual(set(state), B.HEAD_NAMES)
            self.assertTrue(all(t.dtype == torch.float32 for t in state.values()))
            if c["origin"] == "mechanism":
                self.assertTrue(torch.equal(state["value.bias"], self.parent["value.bias"]))
                if c["dose"] == 0:self.assertTrue(torch.equal(state["value.weight"], self.parent["value.weight"]))
        for path, raw in before.items():self.assertEqual(Path(path).read_bytes(), raw)
        self.assertFalse(bundle["registration_performed"]);self.assertFalse(bundle["encoder_loaded"])

    def test_decimal_string_labels_match_only_after_exact_fp32_conversion(self):
        data = B.read_json(self.request["development_dataset"])
        self.assertTrue(all(isinstance(r["net_usd"], str) for r in data["rows"]))
        data["rows"][0]["net_usd"] = "-2.000000010000000000"
        data["rows"][1]["net_usd"] = "4.000000100000000000"
        self.request["development_dataset"] = self.write("development.json", data)
        bundle, _ = self.bundle()
        self.assertEqual(bundle["development_examples"], 2)
        # The next value rounds to another FP32 label. No numeric tolerance may
        # substitute for equality with the already pinned label artifact.
        data["rows"][1]["net_usd"] = "4.000001000000000000"
        self.request["development_dataset"] = self.write("development.json", data)
        out = self.output()
        with self.assertRaises(WeightError) as error:
            B.build_bundle(self.request, out)
        self.assertEqual(error.exception.code, "INPUT_LINEAGE")
        self.assertFalse(out.exists())

    def test_finite_decimal_float_that_overflows_fp32_is_rejected(self):
        data = B.read_json(self.request["development_dataset"])
        data["rows"][0]["net_usd"] = "1e39"
        self.request["development_dataset"] = self.write("development.json", data)
        out = self.output()
        with self.assertRaises(WeightError) as error:
            B.build_bundle(self.request, out)
        self.assertEqual(error.exception.code, "NONFINITE")
        self.assertFalse(out.exists())

    def test_prepare_pins_new_family_without_creating_study_and_verifies(self):
        _, bundle = self.bundle();request = self.prepare_request(bundle);out = self.output()
        ready = B.prepare_registration(request, out)
        self.assertEqual(B.verify_ready(B.file_ref(out / "ready.json")), ready)
        self.assertFalse(Path(request["new_study_root"]).exists())
        config = B.read_json(ready["config"]);self.assertEqual(len(config["heads"]), 11)
        self.assertNotIn("input_start_ms", config)
        for h in config["heads"].values():self.assertEqual(h["workbench_lineage"]["sourceproof_sha256"], ready["sourceproof"]["sha256"])
        proof = B.read_json(ready["sourceproof"])
        self.assertFalse(proof["cross_plan_shared_encoding_verified"]);self.assertTrue(ready["resource_admission_pending"])

    def test_hip_preparation_does_not_invent_backend_qualification(self):
        _, bundle = self.bundle();request = self.prepare_request(bundle, hip=True)
        request["backend_qualification"] = self.write("qualification.json", {"scope": "HISTORICAL_REPLAY_ONLY_NOT_FUTURE_PREOPEN_PROOF"})
        ready = B.prepare_registration(request, self.output());proof = B.read_json(ready["sourceproof"])
        self.assertTrue(proof["backend_qualification_document_present"])
        self.assertFalse(proof["backend_qualification_verified"])
        self.assertTrue(ready["numerical_backend_qualification_pending"])

    def test_changed_source_and_stored_patch_bytes_rejected_before_output(self):
        changed = copy.deepcopy(self.request);changed["parent_head"]["sha256"] = "0" * 64
        out = self.output()
        with self.assertRaises(WeightError):B.build_bundle(changed, out)
        self.assertFalse(out.exists())
        path = Path(self.report["candidates"][1]["patch"]["parameters"]["path"])
        raw = path.read_bytes();path.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
        out = self.output()
        with self.assertRaises(WeightError):B.build_bundle(self.request, out)
        self.assertFalse(out.exists())

    def test_encoder_patch_is_rejected(self):
        c = self.report["candidates"][1];record = self.session.store.load_json(c["patch"]["patch"]["artifact_id"])
        replacement = self.session.store.put_tensors({"encoder.embedding.weight": torch.ones((1, 768))}, "patch-parameters")
        record["parameters"] = replacement;c["patch"]["parameters"] = replacement
        c["patch"]["patch"] = self.session.store.put_json(record, "weight-patch")
        self.request["mechanism_summary"] = self.write("mechanism/summary.json", self.report)
        with self.assertRaises(WeightError) as error:B.build_bundle(self.request, self.output())
        self.assertEqual(error.exception.code, "PATCH_SCOPE")

    def test_cutoff_and_development_order_rejected(self):
        for change in ({"information_cutoff_ms": B.clock_ms() + 100000}, {"information_cutoff_ms": 0},
                       {"ordered_development_row_ids": list(reversed(self.request["ordered_development_row_ids"]))}):
            with self.subTest(change=list(change)), self.assertRaises(WeightError):
                B.build_bundle({**self.request, **change}, self.output())

    def test_rehashed_subset_cannot_remove_candidates(self):
        bundle, _ = self.bundle();bundle["candidates"].pop()
        ref = self.write("subset-bundle.json", bundle)
        with self.assertRaises(WeightError):B.prepare_registration(self.prepare_request(ref), self.output())

    def test_effect_authority_or_frozen_window_cannot_be_imported(self):
        _, bundle = self.bundle()
        for change in ({"trade_authority": True}, {"plan_id": "a" * 64}, {"input_start_ms": 1}):
            request = self.prepare_request(bundle);config = B.read_json(request["registration_template"])
            request["registration_template"] = self.write("template.json", {**config, **change})
            with self.subTest(change=change), self.assertRaises(WeightError):B.prepare_registration(request, self.output())

    def test_existing_output_old_study_and_future_study_are_protected(self):
        with self.assertRaises(WeightError):B.build_bundle(self.request, Path(self.old_ref["path"]).parent / "bundle")
        _, bundle = self.bundle();raw = Path(bundle["path"]).read_bytes()
        with self.assertRaises(WeightError):B.build_bundle(self.request, Path(bundle["path"]).parent)
        self.assertEqual(Path(bundle["path"]).read_bytes(), raw)
        request = self.prepare_request(bundle)
        with self.assertRaises(WeightError):B.prepare_registration(request, Path(request["new_study_root"]) / "ready")
        self.assertFalse(Path(request["new_study_root"]).exists())

    def test_cpu_shared_heads_and_single_heads_agree_and_clipping_is_explicit(self):
        bundle, _ = self.bundle();states = [load_file(c["head"]["path"]) for c in bundle["candidates"]]
        x = load_file(self.request["features"]["path"])["features"]
        shared = torch.nn.functional.linear(x, torch.cat([s["value.weight"] for s in states]), torch.cat([s["value.bias"] for s in states])) * 100
        single = torch.cat([torch.nn.functional.linear(x, s["value.weight"], s["value.bias"]) * 100 for s in states], dim=1)
        torch.testing.assert_close(shared, single, rtol=1e-6, atol=1e-5)
        self.assertGreater(float(shared.abs().max()), 15.)
        audit = B.read_json(bundle["cost_fairness"])
        self.assertFalse(audit["speedup_established"]);self.assertFalse(audit["full_mechanism_within_baseline_cap"])

    def test_changed_source_rejected_by_immediate_ready_check(self):
        _, bundle = self.bundle();request = self.prepare_request(bundle);out = self.output()
        B.prepare_registration(request, out);Path(request["producer_manifest"]["path"]).write_bytes(b"changed")
        with self.assertRaises(WeightError):B.verify_ready(B.file_ref(out / "ready.json"))


if __name__ == "__main__":
    unittest.main()

"""Synthetic legacy replay regressions; no market observations or model execution."""
import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest

import paired_eval as E
import replay_laya as R


def identity(name):
    return E.digest({"synthetic_fixture": name})


def sign(value, key):
    value[key] = E.digest({k: v for k, v in value.items() if k != key})
    return value


def frozen_calibration(parent_id, adapter, role, weight):
    counts = [5, 5, 5, 5, 4, 4, 4]
    prior = [(x + 1) / 39 for x in counts]
    return sign({
        "schema": "heptatrader.laya-price-calibration.v3",
        "output_profile": "FROZEN_SAME_PRICE_TRAIN_ROWS_CENTERED_BRIER_V3",
        "parent_id": parent_id, "adapter_sha256": adapter,
        "training_row_ids_digest": identity("training rows"),
        "price_baseline_profile_id": identity("price baseline"),
        "raw_probability_receipt_digest": identity("raw receipt " + adapter),
        "training_rows": 32, "training_cutoff_ms": 50,
        "real_target_class_counts": counts,
        "train_prior_probs": prior, "mean_training_raw_probs": prior[:],
        "model_weight": weight, "model_weight_max": 1.0,
        "quadratic_numerator": weight, "quadratic_denominator": 1.0,
        "raw_logits_scope": ("ACTUAL_FROZEN_PARENT_SAME_PRICE_TRAINING_FORWARD_PASSES"
                             if role == "parent" else "ACTUAL_FINAL_CHILD_PRICE_TRAINING_FORWARD_PASSES"),
        "calibration_is_train_only": True, "future_value_proven": False,
        "additional_independent_training_rows": 0, "model_or_trading_authority": False,
        "fit_spec": {"fixture": "synthetic closed form"},
    }, "profile_id")


def calibrated(profile, raw):
    # Independently compute the stored fixture probabilities, including legacy normalization.
    raw_total = sum(raw)
    weight = profile["model_weight"]
    values = [p + weight * (r / raw_total - m) for p, m, r in
              zip(profile["train_prior_probs"], profile["mean_training_raw_probs"], raw)]
    total = sum(values)
    return [x / total for x in values]


class Bundle:
    """Create a self-contained two-row synthetic chain with independently bound roles."""
    def __init__(self, path):
        self.path = Path(path)
        parent, parent_adapter = identity("parent"), identity("parent adapter")
        edit_adapter = identity("edit adapter")
        edit_cal = frozen_calibration(parent, edit_adapter, "child", .2)
        parent_cal = frozen_calibration(parent, parent_adapter, "parent", .1)
        source_cal = frozen_calibration(parent, identity("source child adapter"), "child", .3)
        control_cal = frozen_calibration(parent, identity("control adapter"), "child", .1)
        selected = {
            "experiment_id": "synthetic experiment", "name": "synthetic edit",
            "protocol_sha256": identity("protocol"), "parent_adapter_sha256": parent_adapter,
            "adapter_sha256": edit_adapter,
            "full_effective_scorer3_weight_sha256": identity("effective scorer"),
            "family": "synthetic", "rank": 1, "strength": .5,
        }
        selected["candidate_id"] = E.digest(selected)
        selected.update(weights_sha256=identity("weights"), eligible=False,
                        calibration_profile_id=edit_cal["profile_id"])
        self.search = {
            "candidates": [selected], "selected_experimental_candidate_id": selected["candidate_id"],
            "eligible_candidates": 0, "parent_calibration_cpu": parent_cal,
        }
        self.seal = {
            "schema": "astra.sealed-experimental-weight-patch.v1",
            "candidate_id": selected["candidate_id"], "parent_candidate_id": parent,
            "created_at_ms": 100, "eligible": False,
            "experiment_id": selected["experiment_id"], "selected_edit_name": selected["name"],
            **{k: selected[k] for k in ("adapter_sha256", "parent_adapter_sha256", "protocol_sha256",
                                      "full_effective_scorer3_weight_sha256", "weights_sha256")},
            "calibration": edit_cal, "parent_calibration_cpu": parent_cal,
            "comparison_scale_calibration": control_cal,
            "comparison_scale_adapter_sha256": control_cal["adapter_sha256"],
        }
        comparator = sign({"calibration": frozen_calibration(parent, parent_adapter, "parent", .15)},
                          "comparator_id")
        self.source = {
            "schema": "heptatrader.laya-resident-future-plan.v1",
            "candidate_id": identity("original trained child"), "parent_id": parent,
            "price_calibration": source_cal, "price_calibration_profile_id": source_cal["profile_id"],
            "parent_calibration_comparator": comparator,
        }
        self.plan = {
            "schema": "astra.frozen-shadow-plan.v1",
            "candidate_id": selected["candidate_id"], "adapter_sha256": edit_adapter,
            "candidate_frozen_at_ms": 100, "all_slots": [40, 41],
            "retrospective_holdout_slots": [40, 41], "fresh_slots": [41],
            "fixed_rule": {"horizon_ms": 300000},
        }
        self.write_headers()
        self.rows = {}
        for slot in self.plan["all_slots"]:
            anchor, label = 1000 + slot * 1000, slot % 7
            state = {"synthetic_feature": slot}
            input_id = E.digest(state)
            source_common = {"slot": slot, "candidate_id": self.source["candidate_id"],
                             "plan_id": self.source["plan_id"]}
            calibration_ids = {"price_calibration_profile_id": source_cal["profile_id"],
                               "parent_calibration_comparator_id": comparator["comparator_id"]}
            original_input = dict(source_common, schema="heptatrader.laya-committed-input.v1",
                                  input_id=input_id, state=state)
            baseline = dict(source_common, **calibration_ids,
                            schema="heptatrader.resident-forward-prediction.v1",
                            parent_id=parent, input_id=input_id, anchor_ms=anchor, horizon_sec=300)
            outcome = dict(source_common, **calibration_ids, anchor_ms=anchor,
                           status="OBSERVED", target_class=label)
            raw_parent, raw_edit = [.1] * 6 + [.4], [.15] * 6 + [.1]
            probabilities = {
                "parent_cpu_raw": raw_parent, "edit_raw": raw_edit,
                "parent_cpu_refit_calibration": calibrated(parent_cal, raw_parent),
                "edit_calibrated": calibrated(edit_cal, raw_edit),
            }
            common = {"slot": slot, "candidate_id": self.seal["candidate_id"],
                      "plan_id": self.plan["plan_id"], "anchor_ms": anchor,
                      "mode": "PROSPECTIVE" if slot == 41 else "BLIND_REPLAY"}
            prediction = dict(common, schema="astra.shadow-prediction.v1", input_id=input_id,
                              target_ms=anchor + 300000, candidate_frozen_at_ms=100,
                              calibration_ready_at_ms=100, inference_finished_at_ms=anchor + 10,
                              comparison_scale_calibration_profile_id=control_cal["profile_id"],
                              probabilities=probabilities)
            result = dict(common, schema="astra.shadow-result.v1", status="OBSERVED", target_class=label,
                          scores={k: {"brier": sum((p - (i == label)) ** 2 for i, p in enumerate(probabilities[k]))}
                                  for k in ("parent_cpu_refit_calibration", "edit_calibrated")})
            self.rows[slot] = {"input": original_input, "baseline": baseline, "outcome": outcome,
                               "prediction": prediction, "result": result}
            self.write_row(slot)

    def write(self, relative, value):
        path = self.path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, sort_keys=True, ensure_ascii=False) + "\n")
        return R.sha(path)

    def write_headers(self):
        self.seal["analysis_sha256"] = self.write("analysis.json", self.search)
        self.plan["seal_sha256"] = self.write("sealed_candidate.json", self.seal)
        sign(self.source, "plan_id")
        self.plan["source_plan_sha256"] = self.write("reference/source_eval/plan.json", self.source)
        self.plan["source_plan_id"] = self.source["plan_id"]
        self.write("shadow/plan.json", sign(self.plan, "plan_id"))

    def row_path(self, slot, key):
        directory, prefix = ("shadow", key) if key in ("prediction", "result") else (
            "reference/source_eval", "prediction" if key == "baseline" else key)
        return f"{directory}/{prefix}-{slot:03}.json"

    def write_row(self, slot):
        r = self.rows[slot]
        input_sha = self.write(self.row_path(slot, "input"), r["input"])
        r["baseline"]["input_receipt_sha256"] = input_sha
        base_sha = self.write(self.row_path(slot, "baseline"), r["baseline"])
        r["outcome"]["prediction_file_sha256"] = base_sha
        outcome_sha = self.write(self.row_path(slot, "outcome"), r["outcome"])
        r["prediction"]["source_input_sha256"] = input_sha
        prediction_sha = self.write(self.row_path(slot, "prediction"), r["prediction"])
        r["result"].update(experimental_prediction_sha256=prediction_sha,
                           source_outcome_sha256=outcome_sha, source_prediction_sha256=base_sha)
        self.write(self.row_path(slot, "result"), r["result"])


class ReplayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.bundle = Bundle(Path(self.temp.name) / "bundle")
        self.output = Path(self.temp.name) / "replay"

    def rejected(self, code):
        with self.assertRaisesRegex(E.EvaluationError, code):
            R.replay(self.bundle.path, self.output)
        self.assertFalse(self.output.exists(), "invalid evidence must not publish any replay artifacts")

    def test_bound_replay_is_retrospective_and_idempotent(self):
        summary = R.replay(self.bundle.path, self.output)
        self.assertEqual(summary["verdict"], "InsufficientEvidence")
        self.assertEqual(summary["new_model_forwards"], 0)
        self.assertEqual(summary["new_prospective_observations"], 0)
        self.assertEqual(summary["original_mode_counts"], {"BLIND_REPLAY": 1, "PROSPECTIVE": 1})
        self.assertFalse(summary["activation_authorized"])
        self.assertEqual(E.read_json(self.output / "plan.json")["mode"], "retrospective")
        candidate = E.read_json(self.output / "candidate.json")
        self.assertEqual(candidate["model_digest"], self.bundle.seal["candidate_id"])
        self.assertNotEqual(candidate["model_digest"], self.bundle.source["candidate_id"])
        labels = [x["label"] for x in E.read_json(self.output / "outcomes.json")["rows"]]
        self.assertEqual(labels, [40 % 7, 41 % 7])
        before = {p.name: p.read_bytes() for p in self.output.iterdir()}
        self.assertEqual(summary, R.replay(self.bundle.path, self.output))
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.output.iterdir()})

    def test_changed_seal_cannot_relabel_existing_predictions(self):
        self.bundle.seal["candidate_id"] = identity("unrelated replacement")
        self.bundle.write("sealed_candidate.json", self.bundle.seal)
        self.rejected("LEGACY_FILE_BINDING:shadow_plan.seal_sha256")

    def test_resigned_plan_still_binds_actual_selected_candidate(self):
        self.bundle.plan["candidate_id"] = identity("different candidate")
        self.bundle.write("shadow/plan.json", sign(self.bundle.plan, "plan_id"))
        self.rejected("LEGACY_PLAN_CANDIDATE_BINDING")

    def test_changed_source_plan_requires_original_file_binding(self):
        self.bundle.source["candidate_id"] = identity("different trained child")
        self.bundle.write("reference/source_eval/plan.json", sign(self.bundle.source, "plan_id"))
        self.rejected("LEGACY_FILE_BINDING:shadow_plan.source_plan_sha256")

    def test_search_cannot_select_a_different_candidate(self):
        self.bundle.search["selected_experimental_candidate_id"] = identity("different candidate")
        self.bundle.write_headers()
        self.rejected("LEGACY_SEARCH_SELECTION_BINDING")

    def test_row_roles_and_slots_must_match_even_with_updated_file_hashes(self):
        original = copy.deepcopy(self.bundle.rows[40])
        for role in original:
            for key, value in (("candidate_id", identity("wrong candidate")),
                               ("plan_id", identity("wrong plan")), ("slot", 41)):
                with self.subTest(role=role, field=key):
                    self.bundle.rows[40] = copy.deepcopy(original)
                    self.bundle.rows[40][role][key] = value
                    self.bundle.write_row(40)
                    self.rejected("LEGACY_ROW_(IDENTITY|SLOT)_BINDING")

    def test_input_id_must_name_the_actual_committed_state(self):
        self.bundle.rows[40]["input"]["state"]["synthetic_feature"] = 999
        self.bundle.write_row(40)
        self.rejected("LEGACY_INPUT_ID_BINDING")

    def test_foreign_source_outcome_label_cannot_be_scored_as_existing_result(self):
        self.bundle.rows[40]["outcome"]["target_class"] = 0
        self.bundle.write_row(40)
        self.rejected("LEGACY_OUTCOME_LABEL_BINDING")

    def test_self_consistent_scores_cannot_hide_wrong_calibration(self):
        row = self.bundle.rows[40]
        changed = [1 / 7] * 7
        row["prediction"]["probabilities"]["edit_calibrated"] = changed
        row["result"]["scores"]["edit_calibrated"]["brier"] = E.brier(changed, row["result"]["target_class"])
        self.bundle.write_row(40)
        self.rejected("LEGACY_CALIBRATION_APPLICATION:edit_calibrated")

    def test_raw_predictions_are_bound_to_frozen_calibration_application(self):
        self.bundle.rows[40]["prediction"]["probabilities"]["parent_cpu_raw"] = [1 / 7] * 7
        self.bundle.write_row(40)
        self.rejected("LEGACY_CALIBRATION_APPLICATION:parent_cpu_refit_calibration")

    def test_calibration_adapter_and_training_population_are_bound(self):
        original = copy.deepcopy(self.bundle.seal["calibration"])
        for key, value, code in (("adapter_sha256", identity("foreign adapter"), "MODEL_BINDING"),
                                 ("training_row_ids_digest", identity("foreign training rows"), "POPULATION")):
            with self.subTest(field=key):
                profile = copy.deepcopy(original)
                profile[key] = value
                self.bundle.seal["calibration"] = sign(profile, "profile_id")
                self.bundle.search["candidates"][0]["calibration_profile_id"] = profile["profile_id"]
                self.bundle.write_headers()
                self.rejected("LEGACY_CALIBRATION_" + code)

    def test_source_calibration_and_parent_id_are_not_inferred_from_probabilities(self):
        original = copy.deepcopy(self.bundle.rows[40])
        for role, key, code in (("baseline", "parent_id", "LEGACY_PARENT_ID_BINDING"),
                                ("baseline", "price_calibration_profile_id", "LEGACY_SOURCE_CALIBRATION_BINDING"),
                                ("outcome", "parent_calibration_comparator_id", "LEGACY_SOURCE_CALIBRATION_BINDING")):
            with self.subTest(role=role, field=key):
                self.bundle.rows[40] = copy.deepcopy(original)
                self.bundle.rows[40][role][key] = identity("wrong binding")
                self.bundle.write_row(40)
                self.rejected(code)

    def test_prediction_cannot_change_seal_time_or_original_mode(self):
        original = copy.deepcopy(self.bundle.rows[40])
        for key, value, code in (("candidate_frozen_at_ms", 99, "LEGACY_PREDICTION_SEAL_BINDING"),
                                 ("calibration_ready_at_ms", 99, "LEGACY_PREDICTION_SEAL_BINDING"),
                                 ("mode", "PROSPECTIVE", "LEGACY_MODE_BINDING"),
                                 ("target_ms", 1, "LEGACY_TARGET_BINDING")):
            with self.subTest(field=key):
                self.bundle.rows[40] = copy.deepcopy(original)
                self.bundle.rows[40]["prediction"][key] = value
                self.bundle.write_row(40)
                self.rejected(code)

    def test_source_prediction_horizon_is_the_shadow_target_horizon(self):
        self.bundle.rows[40]["baseline"]["horizon_sec"] = 60
        self.bundle.write_row(40)
        self.rejected("LEGACY_SOURCE_HORIZON_BINDING")

    def test_original_prospective_tag_requires_prediction_before_target(self):
        prediction = self.bundle.rows[41]["prediction"]
        prediction["inference_finished_at_ms"] = prediction["target_ms"]
        self.bundle.write_row(41)
        self.rejected("LEGACY_PROSPECTIVE_TIME_ORDER")

    def test_source_comparator_id_commits_its_calibration(self):
        self.bundle.source["parent_calibration_comparator"]["comparator_id"] = identity("wrong comparator")
        self.bundle.write_headers()
        self.rejected("LEGACY_SELF_DIGEST:source_parent_comparator.comparator_id")

    def test_missing_fields_and_boolean_slots_are_explicitly_rejected(self):
        original = copy.deepcopy(self.bundle.rows[40])
        for role, key in (("prediction", "input_id"), ("result", "target_class"),
                          ("outcome", "status"), ("baseline", "price_calibration_profile_id")):
            with self.subTest(role=role, field=key):
                self.bundle.rows[40] = copy.deepcopy(original)
                self.bundle.rows[40][role].pop(key)
                self.bundle.write_row(40)
                self.rejected("LEGACY_REQUIRED_FIELD")
        self.bundle.rows[40] = copy.deepcopy(original)
        self.bundle.rows[40]["result"]["slot"] = True
        self.bundle.write_row(40)
        self.rejected("result.slot")

    def test_unobserved_original_outcome_cannot_become_an_observed_loss(self):
        self.bundle.rows[40]["outcome"]["status"] = "PENDING"
        self.bundle.write_row(40)
        self.rejected("LEGACY_OBSERVED_OUTCOME_REQUIRED")

    def test_cli_reports_missing_required_field_without_publishing(self):
        self.bundle.rows[40]["result"].pop("target_class")
        self.bundle.write_row(40)
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            code = R.main(["--bundle", str(self.bundle.path), "--out", str(self.output)])
        self.assertEqual(code, 2)
        response = json.loads(stream.getvalue())
        self.assertFalse(response["ok"])
        self.assertIn("LEGACY_REQUIRED_FIELD:result.target_class", response["error"])
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()

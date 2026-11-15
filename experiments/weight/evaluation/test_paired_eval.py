"""Behavioral checks for identity, time leakage, clustering and rejection."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
import paired_eval as E


def fixture(prospective=False):
    ids = [str(i) for i in range(12)]
    spec = {
        "mode": "prospective" if prospective else "retrospective",
        "base_digest": "a"*64, "candidate_digest": "b"*64,
        "execution_profile_digest": "c"*64, "dataset_digest": "d"*64,
        "parent_calibration_digest": "e"*64, "candidate_calibration_digest": "f"*64,
        "outcome_source_digest": "0"*64, "discovery_ids": ["dev-a"],
        "development_ids": ["dev-b"], "confirmation_ids": ids,
        "clusters": {key: str(int(key)//2) for key in ids},
        "information_cutoff_ms": 90, "calibration_cutoff_ms": 80,
        "classes": 2, "minimum_samples": 10, "minimum_clusters": 5,
        "bootstrap_repetitions": 399, "seed": 7, "confidence": .95,
        "minimum_brier_gain": .01, "maximum_action_tv": .05,
        "require_action_outputs": True,
    }
    plan = E.freeze(spec, now_ms=100)
    common = {"execution_profile_digest":"c"*64, "dataset_digest":"d"*64}
    parent = dict(common, model_digest="a"*64, calibration_digest="e"*64, rows=[])
    candidate = dict(common, model_digest="b"*64, calibration_digest="f"*64, rows=[])
    outcomes = {"dataset_digest":"d"*64, "source_digest":"0"*64, "rows":[]}
    for key in ids:
        row = {"unit_id":key, "input_digest":E.digest({"input":key}), "seed":7,
               "created_at_ms":120, "action_probabilities":[.5,.5]}
        parent["rows"].append(dict(row, probabilities=[.5,.5]))
        candidate["rows"].append(dict(row, probabilities=[.9,.1]))
        outcomes["rows"].append({
            "unit_id":key, "input_digest":row["input_digest"], "cluster_id":str(int(key)//2),
            "status":"observed", "label":0, "input_at_ms":110,
            "prediction_deadline_ms":130, "observed_at_ms":140,
        })
    return spec, plan, parent, candidate, outcomes


class EvaluationTests(unittest.TestCase):
    def test_paired_improvement_and_reproducibility(self):
        _, plan, p, c, out = fixture()
        result = E.evaluate(plan,p,c,out)
        self.assertEqual(result["verdict"],"ResearchGainConfirmed")
        self.assertAlmostEqual(result["paired_brier_gain"],.48)
        self.assertEqual(result,E.evaluate(plan,p,c,out))
        self.assertFalse(result["production_eligibility"])

    def test_no_change_is_not_improvement(self):
        _, plan, p, c, out = fixture()
        for row in c["rows"]:
            row["probabilities"]=[.5,.5]
        self.assertEqual(E.evaluate(plan,p,c,out)["verdict"],"NoUsefulPatch")

    def test_pending_and_censored_are_not_losses(self):
        _, plan,p,c,out = fixture()
        for i in (0,1,2,3):
            out["rows"][i].pop("label")
            out["rows"][i]["status"]="pending" if i%2 else "censored"
        result=E.evaluate(plan,p,c,out)
        self.assertEqual(result["counts"],{"observed":8,"pending":2,"censored":2})
        self.assertEqual(result["verdict"],"InsufficientEvidence")
        self.assertAlmostEqual(result["paired_brier_gain"],.48)

    def test_action_regression_rejects_price_improvement(self):
        _, plan,p,c,out = fixture()
        c["rows"][0]["action_probabilities"]=[.9,.1]
        result=E.evaluate(plan,p,c,out)
        self.assertEqual(result["reason"],"NON_TARGET_ACTION_REGRESSION")

    def test_favorable_early_rows_cannot_close_frozen_confirmation(self):
        spec, _, p, c, out = fixture()
        spec.update(minimum_samples=4, minimum_clusters=2)
        plan = E.freeze(spec, now_ms=100)
        for row in out["rows"][4:]:
            row["status"] = "pending"
            row.pop("label")
        partial = E.evaluate(plan, p, c, out)
        self.assertAlmostEqual(partial["paired_brier_gain"], .48)
        self.assertEqual(partial["verdict"], "InsufficientEvidence")
        self.assertEqual(partial["reason"], "FROZEN_CONFIRMATION_NOT_COMPLETE")
        self.assertFalse(partial["confirmation_complete"])
        for row in out["rows"][4:]:
            row.update(status="observed", label=1)
        complete = E.evaluate(plan, p, c, out)
        self.assertTrue(complete["confirmation_complete"])
        self.assertLess(complete["paired_brier_gain"], 0)
        self.assertNotEqual(complete["verdict"], "ResearchGainConfirmed")

    def test_censoring_is_not_a_shortcut_to_confirming_a_subset(self):
        spec, _, p, c, out = fixture()
        spec.update(minimum_samples=4, minimum_clusters=2)
        plan = E.freeze(spec, now_ms=100)
        for row in out["rows"][4:]:
            row["status"] = "censored"
            row.pop("label")
        result = E.evaluate(plan, p, c, out)
        self.assertEqual(result["reason"], "CENSORED_CONFIRMATION_DESCRIPTIVE_ONLY")
        self.assertEqual(result["verdict"], "InsufficientEvidence")
        self.assertFalse(result["confirmation_complete"])

    def test_plan_and_prediction_bindings(self):
        _, plan,p,c,out = fixture()
        for field in ("model_digest","calibration_digest","execution_profile_digest","dataset_digest"):
            bad=copy.deepcopy(c);bad[field]="1"*64
            with self.subTest(field=field),self.assertRaises(E.EvaluationError):
                E.evaluate(plan,p,bad,out)
        bad=copy.deepcopy(plan);bad["minimum_brier_gain"]=.2
        with self.assertRaisesRegex(E.EvaluationError,"PLAN_DIGEST"):
            E.evaluate(bad,p,c,out)

    def test_actual_input_and_seed_pairing(self):
        _, plan,p,c,out = fixture()
        for field,value in (("input_digest","1"*64),("seed",8)):
            bad=copy.deepcopy(c);bad["rows"][0][field]=value
            with self.assertRaises(E.EvaluationError):
                E.evaluate(plan,p,bad,out)

    def test_frozen_clusters_and_repeated_inputs(self):
        _,plan,p,c,out=fixture()
        out["rows"][0]["cluster_id"]="late-change"
        with self.assertRaisesRegex(E.EvaluationError,"FROZEN_CLUSTER"):
            E.evaluate(plan,p,c,out)
        out["rows"][0]["cluster_id"]="0"
        for doc in (p,c,out):
            doc["rows"][2]["input_digest"]=doc["rows"][0]["input_digest"]
        with self.assertRaisesRegex(E.EvaluationError,"REPEATED_INPUT"):
            E.evaluate(plan,p,c,out)

    def test_prospective_deadline_and_unknown_future_labels(self):
        spec,plan,p,c,out=fixture(True)
        self.assertEqual(E.evaluate(plan,p,c,out)["verdict"],"ResearchGainConfirmed")
        c["rows"][0]["created_at_ms"]=130
        with self.assertRaisesRegex(E.EvaluationError,"BEFORE_DEADLINE"):
            E.evaluate(plan,p,c,out)
        spec["outcomes_digest"]="1"*64
        with self.assertRaisesRegex(E.EvaluationError,"FUTURE_LABELS"):
            E.freeze(spec,now_ms=100)

    def test_search_overlap_and_information_cutoff(self):
        spec,*_=fixture()
        spec["discovery_ids"].append("0")
        with self.assertRaisesRegex(E.EvaluationError,"OVERLAPS"):
            E.freeze(spec,now_ms=100)
        spec["discovery_ids"].remove("0");spec["information_cutoff_ms"]=101
        with self.assertRaisesRegex(E.EvaluationError,"TIME_ORDER"):
            E.freeze(spec,now_ms=100)

    def test_nonfinite_probabilities_and_duplicates(self):
        _,plan,p,c,out=fixture()
        c["rows"][0]["probabilities"]=[float("nan"),.5]
        with self.assertRaises(E.EvaluationError):
            E.evaluate(plan,p,c,out)
        c["rows"][0]["probabilities"]=[.9,.1];c["rows"].append(c["rows"][0])
        with self.assertRaisesRegex(E.EvaluationError,"DUPLICATE_UNIT"):
            E.evaluate(plan,p,c,out)

    def test_create_once_and_strict_json(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"value.json"
            E.publish(p,{"x":1});E.publish(p,{"x":1})
            with self.assertRaisesRegex(E.EvaluationError,"CONFLICT"):
                E.publish(p,{"x":2})
            p.write_text('{"x":1,"x":2}')
            with self.assertRaisesRegex(E.EvaluationError,"DUPLICATE_JSON"):
                E.read_json(p)

    def test_cli_freeze_retry_preserves_seal(self):
        spec,*_=fixture()
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"spec.json";q=Path(d)/"plan.json"
            p.write_text(json.dumps(spec))
            self.assertEqual(E.main(["freeze","--spec",str(p),"--out",str(q)]),0)
            before=q.read_bytes()
            self.assertEqual(E.main(["freeze","--spec",str(p),"--out",str(q)]),0)
            self.assertEqual(before,q.read_bytes())


if __name__ == "__main__":
    unittest.main()


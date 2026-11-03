"""Synthetic lineage and arithmetic regressions; no market data or inference."""
import copy
import hashlib
import json
import math
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import current100k_handoff as H


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def fixture(*, final=False, incomplete=False, maximum_unresolved=0):
    day = 86400000
    start = 1_800_000_000_000
    plan = {"schema": H.SOURCE_PLAN_SCHEMA, "registered_at_ms": start-1000,
            "input_start_ms": start, "input_end_ms": start+14*day,
            "outcome_end_ms": start+15*day, "claim_scope": "PROSPECTIVE_VALUE_RESEARCH_ONLY",
            "trade_authority": False, "automatic_selection": False, "actor_update": False,
            "rule": {"window_ms": 14*day, "closure_grace_ms": day,
                     "maximum_unresolved_at_final": maximum_unresolved,
                     "target_scale_usd": 100., "max_abs_prediction_usd": 15.,
                     "sequential_test": "MIXTURE_HOEFFDING_HUBER_LOSS_DIFFERENCE"},
            "heads": {"parent": {"sha256": sha("parent")}, "edit": {"sha256": sha("edit")}},
            "parent_arm": "parent", "training_mean_usd": .5,
            "producer_registration": {"sha256": sha("original-producer")},
            "numeric_profile": "TORCH_CPU_FP32_SHARED_LINEAR_USD100_CLIP15",
            "description": "原计划，保持中文来源摘要"}
    plan["plan_id"] = H.source_digest(plan)
    registration = {"plan_id": plan["plan_id"], "plan_sha256": H.file_digest(plan),
                    "durable_at_ms": start-500, "local_receipt_only": True}
    saved = {"schema": "heptatrader.weight-shadow-review-plan-snapshot.v1",
             "source_root": "/private/source", "plan": plan, "registration": registration,
             "original_plan_sha256": H.file_digest(plan), "window_registered_by_review": False}
    saved["snapshot_id"] = H.source_digest(saved)
    provenance = {"schema": "heptatrader.weight-shadow-strict-review.v1", "plan_id": plan["plan_id"],
                  "source_root": "/private/source",
                  "original_plan_sha256": H.file_digest(plan),
                  "original_registration_sha256": H.file_digest(registration),
                  "review_implementation_sha256": {"current100k_weight_shadow_eval.py": sha("source")},
                  "original_window_modified": False, "original_reports_modified": False,
                  "request_replayed": False}
    as_of = plan["outcome_end_ms"] if final else start+10000
    rows = []
    for number, target, parent, edited in ((0, 3., 1., 2.), (1, -3., 0., -1.)):
        row = {"command_id": "command-"+str(number), "request_id": "request-"+str(number),
               "status": "OBSERVED", "reason": None, "side": "BUY", "target_usd": target,
               "fee_usd": .2, "reward_id": sha("reward-"+str(number)),
               "prediction_committed_at_ms": start+1+number, "opened_at_ms": start+10+number,
               "first_fill_ms": start+11+number, "closed_at_ms": start+100+number,
               "predictions": {"parent": parent, "edit": edited},
               "target_exceeds_training_support": False,
               "preopen_terminal_evidence": {"terminal_sha256": sha("terminal-"+str(number)),
                    "binding_sha256": sha("binding-"+str(number)),
                    "prediction_terminal": "SEALED_AWAITING_ORIGINAL_COMMAND",
                    "publication_durability_observed_at_ms": start+2+number}}
        rows.append(row)
    if incomplete:
        rows += [{"command_id": "missing", "request_id": "request-missing", "status": "CENSORED",
                  "opened_at_ms": start+20,
                  "reason": "NO_DURABLE_PREDICTION_FOR_ORIGINAL_REQUEST"},
                 {"command_id": "open", "request_id": "request-open", "status": "PENDING",
                  "reason": "AWAITING_SETTLED_EXACT_OUTCOME"}]
    refs = ("edit", "parent", "BENCHMARK_ZERO", "BENCHMARK_TRAIN_MEAN")
    predictions = {"edit": [2., -1.], "parent": [1., 0.],
                   "BENCHMARK_ZERO": [0., 0.], "BENCHMARK_TRAIN_MEAN": [.5, .5]}
    metrics = {}
    for arm, values in predictions.items():
        errors = [values[0]-3., values[1]+3.]
        metrics[arm] = {"mae_usd": sum(map(abs, errors))/2,
                        "rmse_usd": math.sqrt(sum(v*v for v in errors)/2)}
    pairs = {a+" vs "+b: {"mae_gain_usd": metrics[b]["mae_usd"]-metrics[a]["mae_usd"],
                              "rmse_gain_usd": metrics[b]["rmse_usd"]-metrics[a]["rmse_usd"],
                              "comparative_conditions_met": False}
             for a in ("edit", "parent") for b in refs if a != b}
    report = {"schema": H.SOURCE_REPORT_SCHEMA, "plan_id": plan["plan_id"], "as_of_ms": as_of,
              "state": "FINAL_RESEARCH_COMPARISON" if final else "PENDING", "reasons": [],
              "source_issues": [], "strict_preopen_terminal_required": True,
              "financial_candidate_selected": False, "canonical_agentd_accepted": False,
              "trade_authority": False, "broker_orders_sent": 0, "current_replay_complete": True,
              "original_command_count_complete": True, "original_command_count": len(rows),
              "observed_trades": 2, "status_counts": {"OBSERVED": 2},
              "prediction_coverage": 2/len(rows), "arm_metrics": metrics, "paired_comparisons": pairs,
              "review_provenance_sha256": H.file_digest(provenance),
              "outcome_set_digest": H.source_digest(rows)}
    if incomplete:
        report["status_counts"].update(CENSORED=1, PENDING=1)
        report["reasons"] = ["UNRESOLVED_OR_CENSORED_ORIGINAL_COMMANDS"]
        if final:
            report["state"] = "FINAL_INCOMPLETE"
    outcomes = {"schema": H.OUTCOME_SCHEMA, "plan_id": plan["plan_id"], "as_of_ms": as_of,
                "rows": rows, "outcome_set_digest": H.source_digest(rows)}
    return saved, provenance, report, outcomes


def refresh_rows(args):
    args[2]["outcome_set_digest"] = args[3]["outcome_set_digest"] = H.source_digest(args[3]["rows"])


def evaluate(args):
    return H.import_assessment(*args, expected_plan_id=args[0]["plan"]["plan_id"],
                               provenance_sha256=H.file_digest(args[1]) if args[1] else None)


def refresh_eligibility(args):
    value = args[2]["comparison_eligibility"]
    for proof in value["failure_proofs"]:
        proof["proof_digest"] = H.source_digest({k: v for k, v in proof.items() if k != "proof_digest"})
    value["eligibility_digest"] = H.source_digest({k: v for k, v in value.items() if k != "eligibility_digest"})


def negative_eligibility(args, *, with_proof=True):
    """Original-writer receipt shape, separately bound to the captured row set."""
    plan, report = args[0]["plan"], args[2]
    start = plan["input_start_ms"]
    terminal = {"schema": "heptatrader.preopen-request-terminal.v1", "plan_id": plan["plan_id"],
                "request_id": "request-missing", "request_sha256": sha("original-request"),
                "producer_manifest_sha256": plan["producer_registration"]["sha256"],
                "status": "NO_PREDICTION_BEFORE_ORIGINAL_COMMAND", "observed_at_ms": start+21,
                "broker_orders_sent": 0, "old_trial_modified": False}
    original = {"command_id": "missing", "request_id": terminal["request_id"],
                "request_sha256": terminal["request_sha256"]}
    proof = {"schema": H.FAILURE_PROOF_SCHEMA, "plan_id": plan["plan_id"], **original,
             "producer_manifest_sha256": terminal["producer_manifest_sha256"],
             "request_started_at_ms": start+10, "command_prepared_at_ms": start+20,
             "binding_observed_at_ms": start+22, "verified_at_ms": report["as_of_ms"],
             "terminal_record": terminal, "terminal_sha256": H.file_digest(terminal),
             "original_command_record": original, "original_command_sha256": H.file_digest(original),
             "binding_sha256": sha("private-ledger-binding"), "source_binding_digest": sha("binding-value"),
             "input_record_sha256": sha("private-input-record"), "protocol_sha256": sha("original-protocol"),
             "binding_status": "MISSING_OR_LATE_NO_CREDIT", "before_original_command": False,
             "binding_verified_by_source": True}
    maximum = plan["rule"]["maximum_unresolved_at_final"]
    blocked = with_proof and maximum == 0
    report["comparison_eligibility"] = {
        "schema": H.ELIGIBILITY_SCHEMA, "plan_id": plan["plan_id"], "as_of_ms": report["as_of_ms"],
        "outcome_set_digest": report["outcome_set_digest"],
        "status": "IRRECOVERABLY_INELIGIBLE" if blocked else "UNKNOWN",
        "formal_success_possible_under_frozen_rule": False if blocked else None,
        "permanent_unresolved_count_lower_bound": int(with_proof),
        "maximum_unresolved_at_final": maximum,
        "reason": ("IMMUTABLE_MISSED_PREOPEN_EXCEEDS_FROZEN_UNRESOLVED_LIMIT" if blocked else
                   "NO_VERIFIED_IRREVERSIBLE_BLOCKER" if report["current_replay_complete"] else
                   "CURRENT_SOURCE_UNAVAILABLE"),
        "failure_proofs": [proof] if with_proof else [], "evidence_errors": [],
        "source_state": report["state"], "original_outcome_end_ms": plan["outcome_end_ms"],
        "is_final_protocol_report": False, "original_window_modified": False,
        "diagnostic_metrics_preserved": True, "trade_authority": False}
    refresh_eligibility(args)
    return report["comparison_eligibility"]


class HandoffTests(unittest.TestCase):
    def test_known_usd_arithmetic_and_original_identity(self):
        args = fixture()
        result = evaluate(args)
        self.assertEqual(result["arm_metrics"]["parent"]["mae_usd"], 2.5)
        self.assertEqual(result["arm_metrics"]["edit"]["mae_usd"], 1.5)
        self.assertEqual(result["paired_comparisons"]["edit vs parent"]["mae_gain_usd"], 1.)
        self.assertEqual(result["source_state"], "PENDING")
        self.assertEqual(result["original_window"]["input_end_ms"], args[0]["plan"]["input_end_ms"])
        self.assertFalse(result["activation_authorized"])
        self.assertEqual(result["model_forwards_performed"], 0)
        self.assertEqual(result["comparison_eligibility"]["status"], "UNKNOWN")
        self.assertIsNone(result["formal_success_possible_under_frozen_rule"])

    def test_source_unicode_canonicalization_is_preserved(self):
        plan = fixture()[0]["plan"]
        without = {k: v for k, v in plan.items() if k != "plan_id"}
        utf8_digest = hashlib.sha256(json.dumps(without, sort_keys=True, separators=(",", ":"),
                                               ensure_ascii=False).encode()).hexdigest()
        self.assertNotEqual(utf8_digest, plan["plan_id"])
        self.assertEqual(H.source_digest(without), plan["plan_id"])

    def test_pending_and_missing_commands_remain_in_denominator(self):
        result = evaluate(fixture(incomplete=True))
        self.assertEqual(result["original_command_count"], 4)
        self.assertEqual(result["status_counts"], {"OBSERVED": 2, "PENDING": 1, "CENSORED": 1})
        self.assertIsNone(result["formal_success_possible_under_frozen_rule"])

    def test_verified_negative_receipt_blocks_family_preserving_schedule_and_diagnostics(self):
        args = fixture(incomplete=True)
        before = evaluate(args)
        negative_eligibility(args)
        after = evaluate(args)
        self.assertEqual(after["source_state"], "PENDING")
        self.assertFalse(after["formal_success_possible_under_frozen_rule"])
        self.assertEqual(after["comparison_eligibility"]["status"], "IRRECOVERABLY_INELIGIBLE")
        self.assertTrue(after["comparison_eligibility"]["negative_terminal_bytes_verified"])
        self.assertEqual(after["comparison_eligibility"]["permanent_unresolved_count_lower_bound"], 1)
        for key in ("original_window", "head_digests", "outcome_set_digest", "source_rule", "source_reasons",
                    "original_command_count", "status_counts", "arm_metrics", "paired_comparisons"):
            self.assertEqual(before[key], after[key], key)

    def test_censored_or_bounded_negative_evidence_never_implies_positive_eligibility(self):
        for with_proof, maximum in ((False, 0), (True, 1)):
            args = fixture(incomplete=True, maximum_unresolved=maximum)
            negative_eligibility(args, with_proof=with_proof)
            result = evaluate(args)
            with self.subTest(with_proof=with_proof, maximum=maximum):
                self.assertEqual(result["comparison_eligibility"]["status"], "UNKNOWN")
                self.assertIsNone(result["formal_success_possible_under_frozen_rule"])
                self.assertEqual(result["comparison_eligibility"]["negative_terminal_bytes_verified"], with_proof)

    def test_unsupported_source_eligibility_is_unknown(self):
        args = fixture(incomplete=True)
        value = negative_eligibility(args)
        value["schema"] = "future-unsupported-schema"
        result = evaluate(args)
        self.assertEqual(result["comparison_eligibility"]["status"], "UNKNOWN")
        self.assertIsNone(result["formal_success_possible_under_frozen_rule"])

    def test_negative_terminal_bytes_request_and_original_command_are_verified(self):
        for mutation in ("terminal_bytes", "request_identity", "original_command", "unsupported_terminal"):
            args = fixture(incomplete=True)
            proof = negative_eligibility(args)["failure_proofs"][0]
            if mutation == "terminal_bytes":
                proof["terminal_sha256"] = sha("different-original-bytes")
            elif mutation == "request_identity":
                proof["request_sha256"] = sha("another-request")
            elif mutation == "original_command":
                proof["original_command_record"]["command_id"] = "another-command"
                proof["original_command_sha256"] = H.file_digest(proof["original_command_record"])
            else:
                proof["terminal_record"]["status"] = "REQUEST_EXPIRED"
                proof["terminal_sha256"] = H.file_digest(proof["terminal_record"])
            refresh_eligibility(args)
            with self.subTest(mutation=mutation), self.assertRaises(H.HandoffError):
                evaluate(args)

    def test_negative_proof_requires_population_clock_and_source_binding(self):
        for mutation in ("outside_population", "observed_row", "duplicate", "clock", "binding", "producer"):
            args = fixture(incomplete=True)
            value = negative_eligibility(args)
            proof = value["failure_proofs"][0]
            if mutation == "outside_population":
                proof["command_id"] = "absent"
            elif mutation == "observed_row":
                proof["command_id"], proof["request_id"] = "command-0", "request-0"
            elif mutation == "duplicate":
                value["failure_proofs"].append(copy.deepcopy(proof))
                value["permanent_unresolved_count_lower_bound"] = 2
            elif mutation == "clock":
                proof["command_prepared_at_ms"] = proof["request_started_at_ms"]-1
            elif mutation == "binding":
                proof["binding_verified_by_source"] = False
            else:
                proof["producer_manifest_sha256"] = sha("different-producer")
            refresh_eligibility(args)
            with self.subTest(mutation=mutation), self.assertRaises(H.HandoffError):
                evaluate(args)

    def test_eligibility_cannot_change_protocol_or_claim_unsupported_conclusion(self):
        mutations = {"count": ("permanent_unresolved_count_lower_bound", True),
                     "limit": ("maximum_unresolved_at_final", False),
                     "deadline": ("original_outcome_end_ms", 1),
                     "final": ("is_final_protocol_report", True),
                     "success": ("formal_success_possible_under_frozen_rule", True),
                     "false_without_proof": ("failure_proofs", [])}
        for mutation, (key, changed) in mutations.items():
            args = fixture(incomplete=True)
            negative_eligibility(args)[key] = changed
            refresh_eligibility(args)
            with self.subTest(mutation=mutation), self.assertRaises(H.HandoffError):
                evaluate(args)

    def test_irrecoverable_failure_cannot_coexist_with_final_success(self):
        args = fixture(final=True, incomplete=True)
        args[2]["state"] = "FINAL_RESEARCH_COMPARISON"
        negative_eligibility(args)
        with self.assertRaisesRegex(H.HandoffError, "PERMANENT_FAILURE_WITH_FINAL_COMPARISON"):
            evaluate(args)

    def test_censored_diagnostic_values_do_not_score(self):
        args = fixture(incomplete=True)
        args[3]["rows"][2].update(target_usd=999., predictions={"parent": -15., "edit": 15.})
        refresh_rows(args)
        self.assertEqual(evaluate(args)["arm_metrics"]["parent"]["mae_usd"], 2.5)

    def test_source_loss_with_unenumerated_lower_bound_is_retained(self):
        args = list(fixture(final=True))
        report = args[2]
        args[3]["rows"] = [{"command_id": "retained", "request_id": None, "status": "CENSORED",
                             "reason": "CURRENT_SOURCE_UNAVAILABLE_NO_CREDIT"}]
        report.update(state="FINAL_INCOMPLETE", current_replay_complete=False,
                      original_command_count_complete=False, current_credit_withdrawn=True,
                      original_command_count=3, observed_trades=0, status_counts={"CENSORED": 3},
                      prediction_coverage=0., retained_known_command_count=1,
                      retained_unenumerated_command_count=2,
                      current_source_totals={"observed_trades": None, "original_command_count": None,
                                             "prediction_coverage": None})
        for values in report["arm_metrics"].values():
            values.update(mae_usd=None, rmse_usd=None)
        for values in report["paired_comparisons"].values():
            values.update(mae_gain_usd=None, rmse_gain_usd=None)
        refresh_rows(args)
        result = evaluate(args)
        self.assertEqual(result["retained_unenumerated_command_count"], 2)
        self.assertIsNone(result["arm_metrics"]["edit"]["mae_usd"])
        negative_eligibility(args, with_proof=False)
        result = evaluate(args)
        self.assertIsNone(result["formal_success_possible_under_frozen_rule"])
        self.assertEqual(result["comparison_eligibility"]["reason"], "CURRENT_SOURCE_UNAVAILABLE")
        report["arm_metrics"]["edit"]["mae_usd"] = 1.5
        with self.assertRaisesRegex(H.HandoffError, "SOURCE_METRIC_NOT_NULL"):
            evaluate(args)

    def test_wrong_plan_even_when_self_consistent_is_rejected(self):
        args = fixture()
        with self.assertRaisesRegex(H.HandoffError, "ORIGINAL_PLAN_IDENTITY"):
            H.import_assessment(*args, expected_plan_id=sha("other"))

    def test_original_plan_or_head_mutation_rejected(self):
        for mutation in ("window", "head"):
            args = fixture()
            if mutation == "window":
                args[0]["plan"]["input_end_ms"] += 1
            else:
                args[0]["plan"]["heads"]["edit"]["sha256"] = sha("replacement")
            with self.subTest(mutation=mutation), self.assertRaises(H.HandoffError):
                evaluate(args)

    def test_original_order_and_duplicate_commands_checked(self):
        args = fixture()
        args[3]["rows"].reverse()
        with self.assertRaisesRegex(H.HandoffError, "ORDERED_OUTCOME_DIGEST"):
            evaluate(args)
        refresh_rows(args)
        args[3]["rows"][1]["command_id"] = args[3]["rows"][0]["command_id"]
        refresh_rows(args)
        with self.assertRaisesRegex(H.HandoffError, "DUPLICATE_ORIGINAL_COMMAND"):
            evaluate(args)

    def test_no_missing_head_or_raw_clipped_confusion(self):
        for kind in ("missing", "raw"):
            args = fixture()
            if kind == "missing":
                del args[3]["rows"][0]["predictions"]["edit"]
            else:
                args[3]["rows"][0]["predictions"]["edit"] = 16.
            refresh_rows(args)
            with self.subTest(kind=kind), self.assertRaises(H.HandoffError):
                evaluate(args)

    def test_unsuccessful_or_late_original_terminal_cannot_score(self):
        for kind in ("failed", "late"):
            args = fixture()
            row = args[3]["rows"][0]
            if kind == "failed":
                row["preopen_terminal_evidence"]["prediction_terminal"] = "EXPIRED"
            else:
                row["prediction_committed_at_ms"] = row["first_fill_ms"]
            refresh_rows(args)
            with self.subTest(kind=kind), self.assertRaises(H.HandoffError):
                evaluate(args)

    def test_report_does_not_accept_before_fixed_end(self):
        args = fixture()
        args[2]["state"] = "FINAL_RESEARCH_COMPARISON"
        with self.assertRaisesRegex(H.HandoffError, "SOURCE_FINAL_BEFORE_DEADLINE"):
            evaluate(args)

    def test_incomplete_comparison_cannot_be_imported_as_accepted(self):
        args = fixture(final=True, incomplete=True)
        args[2]["paired_comparisons"]["edit vs parent"]["comparative_conditions_met"] = True
        with self.assertRaisesRegex(H.HandoffError, "INCOMPLETE_SOURCE_COMPARATIVE_CREDIT"):
            evaluate(args)

    def test_metric_and_denominator_tamper_rejected(self):
        for kind in ("metric", "denominator"):
            args = fixture()
            if kind == "metric":
                args[2]["arm_metrics"]["edit"]["mae_usd"] = 0.
            else:
                args[2]["original_command_count"] = 3
            with self.subTest(kind=kind), self.assertRaises(H.HandoffError):
                evaluate(args)

    def test_export_is_ordered_create_once_and_load_is_read_only(self):
        args = fixture()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "review"
            root.mkdir()
            pointer = H.write_outcome_snapshot(root, args[2], args[3]["rows"])
            self.assertEqual(pointer, H.write_outcome_snapshot(root, args[2], args[3]["rows"]))
            args[2]["outcome_set_snapshot"] = pointer
            for name, obj in (("assessment-strict.json", args[2]), ("review-plan-snapshot.json", args[0]),
                              ("strict-review-provenance.json", args[1])):
                H.publish_once(root/name, obj)
            before = {p: p.read_bytes() for p in root.rglob("*.json")}
            result = H.load_review(root, args[0]["plan"]["plan_id"])
            self.assertEqual(result["arm_metrics"]["edit"]["mae_usd"], 1.5)
            self.assertEqual(before, {p: p.read_bytes() for p in root.rglob("*.json")})
            with self.assertRaisesRegex(H.HandoffError, "PUBLICATION_CONFLICT"):
                H.publish_once(root/"assessment-strict.json", {"changed": True})

    def test_old_review_without_ordered_snapshot_is_explicitly_incomplete(self):
        args = fixture()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name, obj in (("assessment-strict.json", args[2]), ("review-plan-snapshot.json", args[0]),
                              ("strict-review-provenance.json", args[1])):
                H.publish_once(root/name, obj)
            with self.assertRaisesRegex(H.HandoffError, "ORDERED_OUTCOME_SNAPSHOT_REQUIRED"):
                H.load_review(root, args[0]["plan"]["plan_id"])

    def test_nonfinite_duplicate_json_and_boolean_number_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/"bad.json"
            for raw in (b'{"a":1,"a":2}', b'{"a":NaN}'):
                path.write_bytes(raw)
                with self.assertRaises(H.HandoffError):
                    H.read_json_bytes(path)
        args = fixture()
        args[3]["rows"][0]["target_usd"] = True
        refresh_rows(args)
        with self.assertRaises(H.HandoffError):
            evaluate(args)


def cost_record(identity, *, status="completed", stage="candidate_construction"):
    metrics = dict.fromkeys(H.METRICS)
    metrics.update(wall_seconds=1.25, cpu_seconds=.75, forward_examples=4, peak_rss_bytes=100)
    return {"operation_id": identity, "stage": stage, "arm_ids": ["edit"], "status": status,
            "source_sha256": sha(identity), "source_record_path": [], "metrics": metrics}


class CostTests(unittest.TestCase):
    def test_real_consumption_missing_fields_and_failed_costs(self):
        a, b = cost_record("a"), cost_record("failed", status="failed", stage="feature_extraction")
        b["arm_ids"] = ["parent", "edit"]
        b["metrics"]["peak_rss_bytes"] = 200
        result = H.summarize_costs([a, b, copy.deepcopy(a)])
        self.assertEqual(result["unique_operations"], 2)
        self.assertEqual(result["duplicate_input_records"], 1)
        self.assertEqual(result["totals"]["wall_seconds"]["value"], 2.5)
        self.assertEqual(result["totals"]["peak_rss_bytes"]["value"], 200)
        self.assertEqual(result["operations"][0]["source_sha256"], a["source_sha256"])
        self.assertIs(type(result["totals"]["forward_examples"]["value"]), int)
        self.assertIsNone(result["totals"]["gpu_seconds"]["value"])
        self.assertFalse(result["totals"]["gpu_seconds"]["complete"])
        self.assertEqual(result["totals"]["status_counts"], {"completed": 1, "failed": 1})
        self.assertIsNone(result["end_to_end_wall_seconds"])
        self.assertEqual(result["shared_operations"], ["failed"])

    def test_duplicate_operation_or_receipt_cannot_double_count(self):
        a = cost_record("a")
        b = copy.deepcopy(a)
        b["metrics"]["wall_seconds"] += 1
        with self.assertRaisesRegex(H.HandoffError, "CONFLICTING_COST_OPERATION"):
            H.summarize_costs([a, b])
        b = copy.deepcopy(a)
        b["operation_id"] = "renamed"
        with self.assertRaisesRegex(H.HandoffError, "COST_RECEIPT_COUNTED_TWICE"):
            H.summarize_costs([a, b])

    def test_no_receipts_is_unknown_not_zero(self):
        result = H.summarize_costs([])
        self.assertIsNone(result["totals"]["cpu_seconds"]["value"])
        self.assertFalse(result["totals"]["cpu_seconds"]["complete"])

    def test_cost_loader_uses_actual_hashed_fields(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            receipt = {"wall": 1.75, "cpu": 1.1, "status": "failed"}
            H.publish_once(root/"receipt.json", receipt)
            specification = {"schema": "hepta.weight.cost-inputs.v1", "records": [
                {"operation_id": "attempt-1", "stage": "candidate_construction", "arm_ids": ["edit"],
                 "source_path": str(root/"receipt.json"), "source_sha256": H.file_digest(receipt),
                 "metric_paths": {"wall_seconds": ["wall"], "cpu_seconds": ["cpu"]},
                 "status_path": ["status"]}]}
            H.publish_once(root/"costs.json", specification)
            result = H.load_costs(root/"costs.json")
            self.assertEqual(result["totals"]["wall_seconds"]["value"], 1.75)
            self.assertEqual(result["totals"]["status_counts"], {"failed": 1})
            (root/"receipt.json").write_text('{"wall":0}')
            with self.assertRaisesRegex(H.HandoffError, "COST_SOURCE_CHANGED"):
                H.load_costs(root/"costs.json")


if __name__ == "__main__":
    unittest.main()

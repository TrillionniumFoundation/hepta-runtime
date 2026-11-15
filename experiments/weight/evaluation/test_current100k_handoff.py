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
                     "family_alpha": .05,
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
              "distinct_utc_days": 1, "time_blocks": 1, "half_counts": [2, 0],
              "family_alpha": .05, "pair_alpha": .05 / len(pairs),
              "multiple_comparison_count": len(pairs),
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
                      distinct_utc_days=0, time_blocks=0, half_counts=[0, 0],
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


class ComparisonDesignTests(unittest.TestCase):
    def test_original_family_and_block_metadata_are_recomputed(self):
        result = evaluate(fixture(incomplete=True))
        design = result["comparison_design"]
        self.assertEqual(design["observed_rows"], 2)
        self.assertEqual(design["observed_block_sizes"], [2])
        self.assertEqual(design["multiple_comparison_count"], 6)
        self.assertEqual(design["mixture_threshold_records_unverified"], 6)
        self.assertAlmostEqual(design["pair_alpha"], .05 / 6)
        self.assertTrue(all(v == "verified" for v in design["source_field_checks"].values()))
        self.assertFalse(design["statistical_decision_recomputed"])
        self.assertEqual(result["original_command_count"], 4)

    def test_transitive_day_overlap_and_touching_day_stay_together(self):
        day = H.DAY_MS
        plan = {"input_start_ms": day, "input_end_ms": 20 * day,
                "rule": {"family_alpha": .05}}
        # First/third trades do not overlap directly. The middle interval joins
        # them, and a same-day close/open cannot become a new bootstrap block.
        observed = [{"command_id": str(i), "opened_at_ms": start * day + 100,
                     "closed_at_ms": end * day + 200}
                    for i, (start, end) in enumerate(((1, 2), (2, 4), (4, 5), (7, 7)))]
        report = {"paired_comparisons": {}, "time_blocks": 2, "half_counts": [4, 0],
                  "distinct_utc_days": 4, "multiple_comparison_count": 132,
                  "family_alpha": .05, "pair_alpha": .05 / 132}
        audit = H.audit_comparison_design(plan, report, observed, 132)
        self.assertEqual(audit["observed_block_sizes"], [3, 1])
        self.assertAlmostEqual(audit["pair_alpha"], .05 / 132)
        self.assertFalse(audit["independence_or_generalization_proven"])

    def test_tampered_dependence_or_smaller_selected_family_is_rejected(self):
        for key, changed in (("time_blocks", 2), ("half_counts", [1, 1]),
                             ("distinct_utc_days", 2), ("multiple_comparison_count", 1),
                             ("pair_alpha", .05), ("family_alpha", .1), ("time_blocks", True)):
            args = fixture()
            args[2][key] = changed
            with self.subTest(key=key), self.assertRaises(H.HandoffError):
                evaluate(args)

    def test_missing_legacy_metadata_is_unverified_not_invented(self):
        args = fixture()
        for key in ("time_blocks", "distinct_utc_days", "half_counts", "family_alpha",
                    "pair_alpha", "multiple_comparison_count"):
            del args[2][key]
        design = evaluate(args)["comparison_design"]
        self.assertTrue(all(v == "unavailable" for v in design["source_field_checks"].values()))
        self.assertEqual(design["time_blocks"], 1)

    def test_pair_threshold_must_keep_original_family_alpha(self):
        for wrong in (False, True):
            args = fixture()
            alpha = .05 / len(args[2]["paired_comparisons"])
            evidence = {"pair_alpha": alpha, "required_log_e": math.log(2 / alpha),
                        "method": args[0]["plan"]["rule"]["sequential_test"]}
            args[2]["paired_comparisons"]["edit vs parent"]["huber_mixture_evidence"] = evidence
            if wrong:
                evidence["required_log_e"] = math.log(2 / .05)
                with self.assertRaisesRegex(H.HandoffError, "SOURCE_METRIC_MISMATCH"):
                    evaluate(args)
            else:
                design = evaluate(args)["comparison_design"]
                self.assertFalse(design["statistical_decision_recomputed"])
                self.assertEqual(design["mixture_threshold_records_checked"], 1)

    def test_small_alpha_cannot_be_replaced_by_zero_with_absolute_tolerance(self):
        plan = {"input_start_ms": 1, "input_end_ms": 2, "rule": {"family_alpha": 1e-12}}
        with self.assertRaisesRegex(H.HandoffError, "SOURCE_ALPHA_MISMATCH"):
            H.audit_comparison_design(plan, {"paired_comparisons": {}, "pair_alpha": 0.}, [], 132)


def cost_record(identity, *, status="completed", stage="candidate_construction"):
    metrics = dict.fromkeys(H.METRICS)
    metrics.update(wall_seconds=1.25, cpu_seconds=.75, forward_examples=4, peak_rss_bytes=100)
    return {"operation_id": identity, "stage": stage, "arm_ids": ["edit"], "status": status,
            "source_sha256": sha(identity), "source_record_path": [], "metrics": metrics}


def inclusive_record(identity, *, parent=None, **kwargs):
    record = cost_record(identity, **kwargs)
    record["accounting"] = {"schema": "hepta.weight.inclusive-cost-scope.v1",
                            "operation_id": identity, "parent_operation_id": parent,
                            "metric_scope": "inclusive"}
    return record


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

    def test_stage_presence_never_claims_complete_experiment_cost(self):
        only_head = H.summarize_costs([cost_record("head")])
        self.assertIn("astra_inference", only_head["coverage"]["missing_stages"])
        self.assertIn("feature_extraction", only_head["coverage"]["missing_stages"])
        self.assertFalse(only_head["coverage"]["all_required_stages_represented"])
        records = [cost_record(name, stage=name) for name in H.REQUIRED_COST_STAGES]
        all_stages = H.summarize_costs(records)
        self.assertTrue(all_stages["coverage"]["all_required_stages_represented"])
        self.assertFalse(all_stages["coverage"]["complete_experiment_inventory_verified"])
        self.assertFalse(all_stages["coverage"]["failed_attempt_inventory_verified"])
        self.assertIsNone(all_stages["speedup_claim"])

    def test_nested_experiment_load_and_failed_attempt_are_not_added_twice(self):
        outer = inclusive_record("run", stage="other")
        outer["metrics"].update(wall_seconds=10., cpu_seconds=6., forward_examples=20,
                                 peak_rss_bytes=500)
        load = inclusive_record("load", parent="run", stage="model_load")
        failed = inclusive_record("failed", parent="run", status="failed")
        result = H.summarize_costs([outer, load, failed, copy.deepcopy(failed)], inclusive=True)
        self.assertEqual(result["totals"]["wall_seconds"]["value"], 10.)
        self.assertEqual(result["totals"]["forward_examples"]["value"], 20)
        self.assertEqual(result["totals"]["wall_seconds"]["selected_operation_ids"], ["run"])
        self.assertEqual(result["totals"]["wall_seconds"]["suppressed_operation_ids"], ["failed", "load"])
        self.assertEqual(result["totals"]["status_counts"], {"completed": 2, "failed": 1})
        self.assertEqual(result["unique_operations"], 3)
        self.assertEqual(result["duplicate_input_records"], 1)
        self.assertIsNone(result["end_to_end_wall_seconds"])

    def test_unknown_outer_metric_retains_only_known_subscope_lower_bound(self):
        outer = inclusive_record("run", stage="other")
        outer["metrics"] = dict.fromkeys(H.METRICS)
        child = inclusive_record("load", parent="run", stage="model_load")
        child["metrics"].update(cpu_seconds=None, wall_seconds=2.)
        grandchild = inclusive_record("inner", parent="load")
        result = H.summarize_costs([outer, child, grandchild], inclusive=True)
        wall, cpu = result["totals"]["wall_seconds"], result["totals"]["cpu_seconds"]
        self.assertEqual(wall["value"], 2.)
        self.assertEqual(cpu["value"], .75)
        self.assertEqual(wall["unknown_root_operation_ids"], ["run"])
        self.assertTrue(wall["known_subscope_lower_bound_only"])
        self.assertFalse(wall["complete"])
        self.assertEqual(cpu["selected_operation_ids"], ["inner"])
        self.assertFalse(wall["selected_sibling_scopes_may_overlap"])
        self.assertEqual(wall["conservative_root_scope_lower_bound"]["value"], 2.)

    def test_overlapping_siblings_are_not_an_unknown_parent_lower_bound(self):
        outer = inclusive_record("run", stage="other")
        outer["metrics"] = dict.fromkeys(H.METRICS)
        first = inclusive_record("parallel-a", parent="run")
        second = inclusive_record("parallel-b", parent="run", status="failed")
        for item in (first, second):
            item["metrics"].update(wall_seconds=8., cpu_seconds=6., forward_examples=10)
        result = H.summarize_costs([outer, first, second], inclusive=True)
        for key, summed, bound in (("wall_seconds", 16., 8.), ("cpu_seconds", 12., 6.),
                                   ("forward_examples", 20, 10)):
            with self.subTest(metric=key):
                total = result["totals"][key]
                self.assertEqual(total["value"], summed)
                self.assertFalse(total["complete"])
                self.assertFalse(total["known_subscope_lower_bound_only"])
                self.assertTrue(total["selected_sibling_scopes_may_overlap"])
                conservative = total["conservative_root_scope_lower_bound"]
                self.assertEqual(conservative["value"], bound)
                self.assertEqual(conservative["root_components"]["run"]["basis"],
                                 "largest_measured_descendant")
                self.assertEqual(conservative["root_components"]["run"]["supporting_operation_ids"],
                                 ["parallel-a", "parallel-b"])
        self.assertEqual(result["totals"]["status_counts"], {"completed": 2, "failed": 1})
        self.assertIsNone(result["end_to_end_wall_seconds"])
        # Parallel wall timers may be fully overlapping. The same valid graph
        # can later provide an inclusive 8-second root, so 16 was not its bound.
        # A known CPU root has its own counter value, independent of wall time.
        outer["metrics"].update(wall_seconds=8., cpu_seconds=12., forward_examples=20)
        complete = H.summarize_costs([outer, first, second], inclusive=True)
        for key, value in (("wall_seconds", 8.), ("cpu_seconds", 12.), ("forward_examples", 20)):
            total = complete["totals"][key]
            self.assertEqual(total["value"], value)
            self.assertTrue(total["complete"])
            self.assertFalse(total["known_subscope_lower_bound_only"])
            self.assertEqual(total["conservative_root_scope_lower_bound"]["value"], value)

    def test_root_bounds_are_metric_specific_and_preserve_unmeasured_roots(self):
        known = inclusive_record("known", stage="other")
        known["metrics"].update(wall_seconds=10., cpu_seconds=None)
        partial = inclusive_record("partial", stage="other")
        partial["metrics"] = dict.fromkeys(H.METRICS)
        partial["metrics"]["cpu_seconds"] = 20.
        first = inclusive_record("first", parent="partial")
        second = inclusive_record("second", parent="partial")
        first["metrics"].update(wall_seconds=8., cpu_seconds=6.)
        second["metrics"].update(wall_seconds=7., cpu_seconds=5.)
        result = H.summarize_costs([known, partial, first, second], inclusive=True)
        wall = result["totals"]["wall_seconds"]
        self.assertEqual(wall["value"], 25.)
        self.assertEqual(wall["conservative_root_scope_lower_bound"]["value"], 18.)
        self.assertFalse(wall["known_subscope_lower_bound_only"])
        cpu = result["totals"]["cpu_seconds"]
        self.assertEqual(cpu["value"], 20.)
        self.assertEqual(cpu["selected_operation_ids"], ["partial"])
        self.assertEqual(cpu["conservative_root_scope_lower_bound"]["value"], 20.)
        self.assertIsNone(cpu["conservative_root_scope_lower_bound"]["root_components"]["known"]["value"])
        self.assertEqual(cpu["conservative_root_scope_lower_bound"]["root_components"]["known"]["basis"],
                         "unmeasured")
        self.assertFalse(cpu["complete"])
        self.assertIsNone(result["totals"]["gpu_seconds"]["conservative_root_scope_lower_bound"]["value"])

    def test_peak_memory_bound_uses_maximum_even_for_unknown_sibling_overlap(self):
        outer = inclusive_record("run", stage="other")
        outer["metrics"] = dict.fromkeys(H.METRICS)
        first = inclusive_record("first", parent="run")
        second = inclusive_record("second", parent="run")
        first["metrics"]["peak_rss_bytes"] = 100
        second["metrics"]["peak_rss_bytes"] = 200
        peak = H.summarize_costs([outer, first, second], inclusive=True)["totals"]["peak_rss_bytes"]
        self.assertEqual(peak["value"], 200)
        self.assertTrue(peak["known_subscope_lower_bound_only"])
        self.assertTrue(peak["selected_sibling_scopes_may_overlap"])
        conservative = peak["conservative_root_scope_lower_bound"]
        self.assertEqual(conservative["value"], 200)
        self.assertEqual(conservative["aggregation"], "maximum_of_root_scope_lower_bounds")
        self.assertEqual(conservative["root_components"]["run"]["supporting_operation_ids"], ["second"])

    def test_parent_graph_cycles_unknown_parents_and_invalid_inclusive_values_fail(self):
        for kind in ("cycle", "unknown", "self", "smaller_parent", "wrong_identity"):
            outer = inclusive_record("run")
            child = inclusive_record("child", parent="run")
            if kind == "cycle":
                outer["accounting"]["parent_operation_id"] = "child"
            elif kind == "unknown":
                child["accounting"]["parent_operation_id"] = "missing"
            elif kind == "self":
                child["accounting"]["parent_operation_id"] = "child"
            elif kind == "smaller_parent":
                child["metrics"]["wall_seconds"] = 2.
            else:
                child["accounting"]["operation_id"] = "different"
            with self.subTest(kind=kind), self.assertRaises(H.HandoffError):
                H.summarize_costs([outer, child], inclusive=True)

    def test_same_receipt_ancestor_and_child_paths_require_real_scope_ancestry(self):
        outer, child = cost_record("run"), cost_record("load")
        child.update(source_sha256=outer["source_sha256"], source_record_path=["load"])
        with self.assertRaisesRegex(H.HandoffError, "COST_OVERLAPPING_RECEIPT_PATHS_REQUIRE_SCOPE"):
            H.summarize_costs([outer, child])
        outer, child = inclusive_record("run"), inclusive_record("load", parent="run")
        child.update(source_sha256=outer["source_sha256"], source_record_path=["load"])
        result = H.summarize_costs([outer, child], inclusive=True)
        self.assertEqual(result["totals"]["wall_seconds"]["value"], 1.25)
        child["accounting"]["parent_operation_id"] = None
        with self.assertRaisesRegex(H.HandoffError, "COST_OVERLAPPING_RECEIPT_PATHS_REQUIRE_SCOPE"):
            H.summarize_costs([outer, child], inclusive=True)

    def test_v2_loader_reads_scope_from_pinned_receipt_not_manifest(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            outer, inner = inclusive_record("run"), inclusive_record("load", parent="run")
            receipt = {"wall": 3., "accounting": outer["accounting"],
                       "load": {"wall": 1., "accounting": inner["accounting"]}}
            H.publish_once(root/"receipt.json", receipt)
            records = [{"operation_id": identity, "stage": stage, "arm_ids": [],
                        "source_path": str(root/"receipt.json"), "source_sha256": H.file_digest(receipt),
                        "source_record_path": path, "metric_paths": {"wall_seconds": ["wall"]},
                        "accounting_path": ["accounting"]}
                       for identity, stage, path in (("run", "other", []), ("load", "model_load", ["load"]))]
            manifest = {"schema": "hepta.weight.cost-inputs.v2", "records": records}
            H.publish_once(root/"costs.json", manifest)
            result = H.load_costs(root/"costs.json")
            self.assertEqual(result["totals"]["wall_seconds"]["value"], 3.)
            self.assertEqual(result["accounting_mode"], "RECEIPT_BOUND_INCLUSIVE_SCOPES")
            del records[0]["accounting_path"]
            records[0]["accounting"] = outer["accounting"]
            H.publish_once(root/"bad-manifest.json", manifest)
            with self.assertRaisesRegex(H.HandoffError, "COST_ACCOUNTING_RECEIPT_REQUIRED"):
                H.load_costs(root/"bad-manifest.json")


if __name__ == "__main__":
    unittest.main()


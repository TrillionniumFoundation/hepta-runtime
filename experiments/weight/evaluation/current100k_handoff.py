#!/usr/bin/env python3
"""Import an existing Current100k strict review without registering or selecting.

The source evaluator remains responsible for original request/command/outcome
replay and its frozen statistical rule. This module verifies the exported
population and independently recomputes scalar errors. It never calls a model,
changes an existing plan, or converts a USD task into multiclass Brier scoring.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
import math
import os
from pathlib import Path
import stat
import tempfile

MAX_BYTES = 64 * 1024 * 1024
MAX_ROWS = 100_000
OUTCOME_SCHEMA = "hepta.weight.current100k-ordered-outcomes.v1"
HANDOFF_SCHEMA = "hepta.weight.current100k-handoff.v1"
SOURCE_PLAN_SCHEMA = "heptatrader.current100k-weight-shadow-plan.v1"
SOURCE_REPORT_SCHEMA = "heptatrader.current100k-weight-shadow-assessment.v1"
ELIGIBILITY_SCHEMA = "heptatrader.current100k-comparison-eligibility.v1"
FAILURE_PROOF_SCHEMA = "heptatrader.current100k-permanent-preopen-failure.v1"
TIME_KEYS = ("registered_at_ms", "input_start_ms", "input_end_ms", "outcome_end_ms")
METRICS = ("wall_seconds", "cpu_seconds", "gpu_seconds", "forward_examples",
           "generated_tokens", "editor_tokens", "optimizer_steps", "peak_rss_bytes")
COUNTS = {"forward_examples", "generated_tokens", "editor_tokens", "optimizer_steps",
          "peak_rss_bytes"}
STAGES = {"model_load", "feature_extraction", "discovery", "candidate_construction",
          "confirmation", "cleanup", "astra_inference", "other"}
REQUIRED_COST_STAGES = STAGES - {"other"}
DAY_MS = 86_400_000


class HandoffError(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise HandoffError(reason)


def source_canonical(value):
    # historical_training.common uses ensure_ascii=True. Keep that convention
    # even though paired_eval.py has a different canonicalization contract.
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def source_digest(value):
    return hashlib.sha256(source_canonical(value)).hexdigest()


def file_digest(value):
    return hashlib.sha256(source_canonical(value) + b"\n").hexdigest()


def checked_hash(value, name):
    require(isinstance(value, str) and len(value) == 64
            and all(c in "0123456789abcdef" for c in value), "INVALID_DIGEST:" + name)
    return value


def integer(value, name, minimum=0):
    require(type(value) is int and minimum <= value < 2**63, "INVALID_INTEGER:" + name)
    return value


def finite(value, name, *, nonnegative=False):
    require(type(value) in (int, float) and math.isfinite(value), "INVALID_NUMBER:" + name)
    require(not nonnegative or value >= 0, "NEGATIVE_NUMBER:" + name)
    return float(value)


def _unique_pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "DUPLICATE_JSON_KEY:" + key)
        result[key] = value
    return result


def read_json_bytes(path):
    """Capture one bounded regular file; report races instead of silently mixing."""
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= MAX_BYTES,
                "ARTIFACT_SIZE_OR_TYPE")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(MAX_BYTES + 1)
        after = os.fstat(descriptor)
        signature = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        require(len(raw) <= MAX_BYTES and signature(before) == signature(after),
                "ARTIFACT_CHANGED_DURING_READ")
    finally:
        os.close(descriptor)
    def reject(value):
        raise HandoffError("NONFINITE_JSON:" + value)
    value = json.loads(raw, object_pairs_hook=_unique_pairs, parse_constant=reject)
    return value, raw


def publish_once(path, value):
    """Publish a new research artifact; an existing different artifact is retained."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = source_canonical(value) + b"\n"
    require(len(raw) <= MAX_BYTES, "ARTIFACT_SIZE_OR_TYPE")
    if path.exists() or path.is_symlink():
        _, existing = read_json_bytes(path)
        require(existing == raw, "PUBLICATION_CONFLICT")
        return
    descriptor, temporary = tempfile.mkstemp(prefix=".handoff-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            _, existing = read_json_bytes(path)
            require(existing == raw, "PUBLICATION_CONFLICT")
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        os.unlink(temporary)


def write_outcome_snapshot(review_root, assessment, rows):
    """Called by the strict evaluator with its actual, ordered results list.

    Returns a report pointer. The caller publishes that pointer in the assessment
    only after this succeeds. This function changes neither rows nor assessment.
    It is also usable when building a separate export pack from captured inputs.
    """
    require(isinstance(rows, list) and len(rows) <= MAX_ROWS, "OUTCOME_ROW_LIMIT")
    require(assessment.get("schema") == SOURCE_REPORT_SCHEMA, "SOURCE_REPORT_SCHEMA")
    checked_hash(assessment.get("plan_id"), "plan_id")
    require(source_digest(rows) == assessment.get("outcome_set_digest"),
            "ORDERED_OUTCOME_DIGEST_MISMATCH")
    document = {"schema": OUTCOME_SCHEMA, "plan_id": assessment["plan_id"],
                "as_of_ms": integer(assessment.get("as_of_ms"), "as_of_ms", 1),
                "outcome_set_digest": assessment["outcome_set_digest"], "rows": rows}
    relative = "outcome-sets/" + source_digest(document) + ".json"
    publish_once(Path(review_root) / relative, document)
    return {"schema": OUTCOME_SCHEMA, "relative_path": relative,
            "sha256": file_digest(document), "row_count": len(rows),
            "outcome_set_digest": document["outcome_set_digest"]}


def _same_number(actual, expected, name):
    if expected is None:
        require(actual is None, "SOURCE_METRIC_NOT_NULL:" + name)
    else:
        actual = finite(actual, name)
        require(math.isclose(actual, expected, rel_tol=1e-10, abs_tol=1e-9),
                "SOURCE_METRIC_MISMATCH:" + name)


def _metrics(errors):
    if not errors:
        return {"mae_usd": None, "rmse_usd": None}
    result = {"mae_usd": math.fsum(abs(v) for v in errors) / len(errors),
              "rmse_usd": math.hypot(*errors) / math.sqrt(len(errors))}
    for name, value in result.items():
        finite(value, name)
    return result


def _comparison_eligibility(plan, assessment, rows):
    """Verify negative evidence separately from the original schedule/statistics.

    The source verifies the full private input and original ledger binding.
    Here original negative-terminal and command-reference bytes, identities,
    clocks and the exact frozen unresolved limit are independently checked.
    """
    value = assessment.get("comparison_eligibility")
    if not isinstance(value, dict) or value.get("schema") != ELIGIBILITY_SCHEMA:
        return {"status": "UNKNOWN", "formal_success_possible_under_frozen_rule": None,
                "permanent_unresolved_count_lower_bound": None,
                "reason": "SOURCE_ELIGIBILITY_NOT_EXPORTED" if value is None else
                          "UNSUPPORTED_SOURCE_ELIGIBILITY_SCHEMA",
                "source_state": assessment["state"], "is_final_protocol_report": False,
                "diagnostic_metrics_preserved": True}
    require(value.get("eligibility_digest") == source_digest({
        k: v for k, v in value.items() if k != "eligibility_digest"}), "ELIGIBILITY_DIGEST")
    require(value.get("plan_id") == plan["plan_id"] and value.get("as_of_ms") == assessment["as_of_ms"]
            and value.get("outcome_set_digest") == assessment["outcome_set_digest"], "ELIGIBILITY_SOURCE_IDENTITY")
    require(value.get("source_state") == assessment["state"] and
            value.get("original_outcome_end_ms") == plan["outcome_end_ms"] and
            all(value.get(k) is False for k in ("is_final_protocol_report", "original_window_modified", "trade_authority"))
            and value.get("diagnostic_metrics_preserved") is True, "ELIGIBILITY_CHANGED_PROTOCOL")
    maximum = integer(plan["rule"].get("maximum_unresolved_at_final"), "maximum_unresolved_at_final")
    require(integer(value.get("maximum_unresolved_at_final"), "eligibility_unresolved_limit") == maximum,
            "ELIGIBILITY_RULE_CHANGED")
    proofs = value.get("failure_proofs")
    require(isinstance(proofs, list) and len(proofs) <= MAX_ROWS, "ELIGIBILITY_PROOF_LIST")
    require(assessment["current_replay_complete"] or not proofs, "FAILURE_PROOF_WITHOUT_CURRENT_SOURCE")
    by_id = {row["command_id"]: row for row in rows}
    seen = set()
    terminal_keys = {"schema", "plan_id", "request_id", "request_sha256", "producer_manifest_sha256",
                     "status", "observed_at_ms", "broker_orders_sent", "old_trial_modified"}
    for proof in proofs:
        require(isinstance(proof, dict) and proof.get("schema") == FAILURE_PROOF_SCHEMA,
                "UNSUPPORTED_PERMANENT_FAILURE_PROOF")
        require(proof.get("proof_digest") == source_digest({k: v for k, v in proof.items() if k != "proof_digest"}),
                "PERMANENT_FAILURE_PROOF_DIGEST")
        command = proof.get("command_id")
        require(isinstance(command, str) and command in by_id and command not in seen, "FAILURE_COMMAND_POPULATION")
        seen.add(command)
        row = by_id[command]
        request_id = proof.get("request_id")
        request_sha = checked_hash(proof.get("request_sha256"), "failure_request_sha256")
        require(row.get("status") == "CENSORED" and isinstance(request_id, str) and request_id
                and row.get("request_id") == request_id and proof.get("plan_id") == plan["plan_id"],
                "FAILURE_REQUEST_OR_STATUS")
        producer = checked_hash(proof.get("producer_manifest_sha256"), "failure_producer")
        require(producer == plan["producer_registration"]["sha256"], "FAILURE_PRODUCER_CHANGED")
        terminal = proof.get("terminal_record")
        require(isinstance(terminal, dict) and set(terminal) == terminal_keys and
                terminal.get("schema") == "heptatrader.preopen-request-terminal.v1" and
                terminal.get("status") == "NO_PREDICTION_BEFORE_ORIGINAL_COMMAND" and
                terminal.get("old_trial_modified") is False and
                integer(terminal.get("broker_orders_sent"), "failure_broker_orders") == 0,
                "ORIGINAL_NEGATIVE_TERMINAL_REQUIRED")
        require(all(terminal.get(k) == expected for k, expected in (
            ("plan_id", plan["plan_id"]), ("request_id", request_id), ("request_sha256", request_sha),
            ("producer_manifest_sha256", producer))), "FAILURE_TERMINAL_IDENTITY")
        require(file_digest(terminal) == checked_hash(proof.get("terminal_sha256"), "negative_terminal_sha256"),
                "ORIGINAL_NEGATIVE_TERMINAL_BYTES_CHANGED")
        original = {"command_id": command, "request_id": request_id, "request_sha256": request_sha}
        require(proof.get("original_command_record") == original and file_digest(original) ==
                checked_hash(proof.get("original_command_sha256"), "original_command_sha256"),
                "FAILURE_ORIGINAL_COMMAND_BINDING")
        for key in ("binding_sha256", "source_binding_digest", "input_record_sha256", "protocol_sha256"):
            checked_hash(proof.get(key), "failure_" + key)
        require(proof.get("binding_status") == "MISSING_OR_LATE_NO_CREDIT" and
                proof.get("before_original_command") is False and proof.get("binding_verified_by_source") is True,
                "FAILURE_BINDING_NOT_VERIFIED")
        started = integer(proof.get("request_started_at_ms"), "failure_request_clock", 1)
        prepared = integer(proof.get("command_prepared_at_ms"), "failure_prepared_clock", 1)
        terminal_at = integer(terminal.get("observed_at_ms"), "failure_terminal_clock", 1)
        bound = integer(proof.get("binding_observed_at_ms"), "failure_binding_clock", 1)
        verified = integer(proof.get("verified_at_ms"), "failure_verified_clock", 1)
        require(plan["input_start_ms"] <= started < plan["input_end_ms"] and
                started <= prepared <= terminal_at <= bound <= verified <= assessment["as_of_ms"] and
                row.get("opened_at_ms") == prepared, "FAILURE_ORIGINAL_CLOCK_ORDER")
    count = integer(value.get("permanent_unresolved_count_lower_bound"), "permanent_unresolved_count")
    require(count == len(proofs), "FAILURE_COUNT_CHANGED")
    blocked = count > maximum
    require(value.get("status") == ("IRRECOVERABLY_INELIGIBLE" if blocked else "UNKNOWN") and
            value.get("formal_success_possible_under_frozen_rule") is (False if blocked else None),
            "ELIGIBILITY_UNSUPPORTED_CONCLUSION")
    require(not blocked or assessment["state"] != "FINAL_RESEARCH_COMPARISON",
            "PERMANENT_FAILURE_WITH_FINAL_COMPARISON")
    expected_reason = ("IMMUTABLE_MISSED_PREOPEN_EXCEEDS_FROZEN_UNRESOLVED_LIMIT" if blocked else
                       "NO_VERIFIED_IRREVERSIBLE_BLOCKER" if assessment["current_replay_complete"] else
                       "CURRENT_SOURCE_UNAVAILABLE")
    require(value.get("reason") == expected_reason and isinstance(value.get("evidence_errors"), list),
            "ELIGIBILITY_REASON_OR_ERRORS")
    return dict(value, negative_terminal_bytes_verified=bool(proofs),
                original_command_reference_bytes_verified=bool(proofs),
                full_private_binding_verified_by="original_strict_source_evaluator" if proofs else None)


def audit_comparison_design(plan, assessment, observed, comparison_count):
    """Recheck source block/family metadata without issuing a statistical decision.

    The source joins whole UTC-day intervals, including transitive overlap. Exact
    trade-time clustering would split its frozen dependence blocks differently.
    Missing legacy metadata stays explicitly unverified.
    """
    intervals = sorted((r["opened_at_ms"] // DAY_MS, r["closed_at_ms"] // DAY_MS,
                        r["command_id"]) for r in observed)
    block_sizes, end = [], -1
    for first, last, _ in intervals:
        if first > end:
            block_sizes.append(0)
        block_sizes[-1] += 1
        end = max(end, last)
    midpoint = (plan["input_start_ms"] + plan["input_end_ms"]) // 2
    halves = [sum(r["opened_at_ms"] < midpoint for r in observed),
              sum(r["opened_at_ms"] >= midpoint for r in observed)]
    expected = {"time_blocks": len(block_sizes), "half_counts": halves,
                "distinct_utc_days": len({r["opened_at_ms"] // DAY_MS for r in observed}),
                "multiple_comparison_count": comparison_count}
    checks = {}
    for name, value in expected.items():
        if name in assessment:
            actual = assessment[name]
            if isinstance(value, list):
                require(isinstance(actual, list) and len(actual) == 2 and
                        all(type(v) is int for v in actual), "SOURCE_DESIGN_FIELD:" + name)
            else:
                integer(actual, name)
            require(actual == value, "SOURCE_DESIGN_MISMATCH:" + name)
            checks[name] = "verified"
        else:
            checks[name] = "unavailable"
    family_alpha = plan["rule"].get("family_alpha")
    pair_alpha, mixture_checks = None, 0
    def same_alpha(actual, expected, name):
        actual = finite(actual, name)
        require(0 < actual < 1 and math.isclose(actual, expected, rel_tol=1e-12, abs_tol=0.),
                "SOURCE_ALPHA_MISMATCH:" + name)
    if family_alpha is not None:
        family_alpha = finite(family_alpha, "family_alpha")
        require(0 < family_alpha < 1, "SOURCE_FAMILY_ALPHA")
        pair_alpha = family_alpha / comparison_count
        for name, value in (("family_alpha", family_alpha), ("pair_alpha", pair_alpha)):
            if name in assessment:
                same_alpha(assessment[name], value, name)
                checks[name] = "verified"
            else:
                checks[name] = "unavailable"
        for name, comparison in assessment["paired_comparisons"].items():
            evidence = comparison.get("huber_mixture_evidence")
            if evidence is not None:
                require(isinstance(evidence, dict), "SOURCE_MIXTURE_EVIDENCE")
                same_alpha(evidence.get("pair_alpha"), pair_alpha, name + ":pair_alpha")
                _same_number(evidence.get("required_log_e"), math.log(2 / pair_alpha),
                             name + ":required_log_e")
                require(evidence.get("method") == plan["rule"].get("sequential_test"),
                        "SOURCE_STATISTICAL_METHOD_CHANGED")
                mixture_checks += 1
    else:
        checks.update(family_alpha="unavailable", pair_alpha="unavailable")
    return {"schema": "hepta.weight.current100k-comparison-design.v1", **expected,
            "observed_rows": len(observed), "observed_block_sizes": block_sizes,
            "block_rule": "TRANSITIVELY_CONNECTED_CLOSED_UTC_DAY_INTERVALS",
            "family_alpha": family_alpha, "pair_alpha": pair_alpha,
            "mixture_threshold_records_checked": mixture_checks,
            "mixture_threshold_records_unverified": comparison_count - mixture_checks,
            "source_field_checks": checks,
            "alpha_scope": "THIS_FROZEN_RESEARCH_FAMILY_ONLY",
            "unobserved_rows_enter_error_metrics": False,
            "statistical_decision_recomputed": False,
            "independence_or_generalization_proven": False}


def import_assessment(plan_snapshot, provenance, assessment, outcomes, *,
                      expected_plan_id, provenance_sha256=None, costs=None):
    """Verify a captured source review and recompute descriptive USD comparisons.

    Self-consistent hashes do not authenticate an observer. The caller supplies
    the previously known plan ID and captures the source-owned review directory.
    No new significance test or missing-outcome estimator is introduced here.
    """
    expected_plan_id = checked_hash(expected_plan_id, "expected_plan_id")
    require(isinstance(plan_snapshot, dict) and plan_snapshot.get("schema") ==
            "heptatrader.weight-shadow-review-plan-snapshot.v1", "PLAN_SNAPSHOT_SCHEMA")
    require(plan_snapshot.get("snapshot_id") == source_digest({
        k: v for k, v in plan_snapshot.items() if k != "snapshot_id"}), "PLAN_SNAPSHOT_DIGEST")
    require(plan_snapshot.get("window_registered_by_review") is False, "REVIEW_REGISTERED_WINDOW")
    plan, registration = plan_snapshot["plan"], plan_snapshot["registration"]
    require(plan.get("schema") == SOURCE_PLAN_SCHEMA and plan.get("plan_id") == expected_plan_id,
            "ORIGINAL_PLAN_IDENTITY")
    require(source_digest({k: v for k, v in plan.items() if k != "plan_id"}) == expected_plan_id,
            "ORIGINAL_PLAN_DIGEST")
    require(plan.get("claim_scope") == "PROSPECTIVE_VALUE_RESEARCH_ONLY" and
            all(plan.get(k) is False for k in ("trade_authority", "automatic_selection", "actor_update")),
            "SOURCE_AUTHORITY_SCOPE")
    original_plan_sha = checked_hash(plan_snapshot.get("original_plan_sha256"), "original_plan_sha256")
    require(file_digest(plan) == original_plan_sha, "SOURCE_PLAN_SERIALIZATION")
    require(registration.get("plan_id") == expected_plan_id and
            registration.get("plan_sha256") == original_plan_sha, "ORIGINAL_REGISTRATION_IDENTITY")
    times = [integer(plan.get(k), k, 1) for k in TIME_KEYS]
    require(times == sorted(set(times)) and times[0] <=
            integer(registration.get("durable_at_ms"), "registration_time", 1) < times[1],
            "ORIGINAL_WINDOW_ORDER")
    rule = plan["rule"]
    require(times[2] - times[1] == rule["window_ms"] and
            times[3] - times[2] == rule["closure_grace_ms"], "ORIGINAL_WINDOW_RULE")
    require(rule.get("target_scale_usd") == 100 and rule.get("max_abs_prediction_usd") == 15,
            "UNSUPPORTED_USD_CONTRACT")
    require(plan.get("numeric_profile") in (
        "TORCH_CPU_FP32_SHARED_LINEAR_USD100_CLIP15",
        "LAYA_HIP_FP32_ENCODER_TORCH_CPU_FP32_SHARED_LINEAR_USD100_CLIP15",
        "TORCH_HIP_FP32_SHARED_LINEAR_USD100_CLIP15"), "UNSUPPORTED_NUMERIC_PROFILE")
    heads = plan["heads"]
    require(isinstance(heads, dict) and 2 <= len(heads) <= 16 and
            plan.get("parent_arm") in heads, "ORIGINAL_ARMS")
    require(not {"BENCHMARK_ZERO", "BENCHMARK_TRAIN_MEAN"} & set(heads), "RESERVED_ARM_ID")
    for name, head in heads.items():
        require(isinstance(name, str) and name, "INVALID_ARM_ID")
        checked_hash(head.get("sha256"), "head:" + name)
    require(assessment.get("schema") == SOURCE_REPORT_SCHEMA and
            assessment.get("plan_id") == expected_plan_id, "SOURCE_REPORT_IDENTITY")
    require(assessment.get("strict_preopen_terminal_required") is True,
            "ORIGINAL_STRICT_PREOPEN_REQUIRED")
    require(all(assessment.get(k) is False for k in
                ("financial_candidate_selected", "canonical_agentd_accepted", "trade_authority"))
            and assessment.get("broker_orders_sent") == 0, "SOURCE_REPORT_AUTHORITY")
    as_of = integer(assessment.get("as_of_ms"), "as_of_ms", times[0])
    state = assessment.get("state")
    require(state in ("PENDING", "FINAL_INCOMPLETE", "FINAL_RESEARCH_COMPARISON"), "SOURCE_STATE")
    require((state == "PENDING") == (as_of < times[3]), "SOURCE_FINAL_BEFORE_DEADLINE")
    complete = assessment.get("current_replay_complete")
    require(type(complete) is bool, "SOURCE_REPLAY_STATUS_REQUIRED")
    if provenance is not None:
        require(provenance.get("schema") == "heptatrader.weight-shadow-strict-review.v1"
                and provenance.get("plan_id") == expected_plan_id, "SOURCE_PROVENANCE_IDENTITY")
        require(provenance.get("original_plan_sha256") == original_plan_sha and
                provenance.get("original_registration_sha256") == file_digest(registration),
                "SOURCE_PROVENANCE_PINS")
        require(provenance.get("source_root") == plan_snapshot.get("source_root"),
                "SOURCE_PROVENANCE_ROOT")
        require(all(provenance.get(k) is False for k in
                    ("original_window_modified", "original_reports_modified", "request_replayed")),
                "SOURCE_PROVENANCE_EFFECTS")
        for value in provenance.get("review_implementation_sha256", {}).values():
            checked_hash(value, "review_implementation")
        require(bool(provenance.get("review_implementation_sha256")), "SOURCE_REVIEW_CODE_REQUIRED")
    require(not complete or provenance is not None, "COMPLETE_REVIEW_WITHOUT_PROVENANCE")
    if complete:
        require(checked_hash(provenance_sha256, "provenance_sha256") ==
                assessment.get("review_provenance_sha256"), "REPORT_PROVENANCE_CHANGED")
    require(outcomes.get("schema") == OUTCOME_SCHEMA and outcomes.get("plan_id") == expected_plan_id
            and outcomes.get("as_of_ms") == as_of, "OUTCOME_SNAPSHOT_IDENTITY")
    rows = outcomes.get("rows")
    require(isinstance(rows, list) and len(rows) <= MAX_ROWS, "OUTCOME_ROW_LIMIT")
    require(source_digest(rows) == outcomes.get("outcome_set_digest") ==
            assessment.get("outcome_set_digest"), "ORDERED_OUTCOME_DIGEST_MISMATCH")
    counts, ids, observed = Counter(), set(), []
    for row in rows:
        require(isinstance(row, dict), "OUTCOME_ROW_OBJECT")
        identity = row.get("command_id")
        require(isinstance(identity, str) and identity and len(identity) <= 512, "COMMAND_ID_REQUIRED")
        require(identity not in ids, "DUPLICATE_ORIGINAL_COMMAND")
        ids.add(identity)
        status = row.get("status")
        require(status in ("OBSERVED", "PENDING", "CENSORED"), "OUTCOME_STATUS")
        counts[status] += 1
        if status != "OBSERVED":
            # The source can retain formerly observed values after withdrawing
            # a binding. Status controls credit; retained diagnostics never score.
            require(isinstance(row.get("reason"), str) and row["reason"], "MISSING_OUTCOME_REASON")
            continue
        require(complete, "SOURCE_UNAVAILABLE_HAS_OBSERVED_CREDIT")
        require(isinstance(row.get("request_id"), str) and row["request_id"], "OBSERVED_REQUEST_MISSING")
        checked_hash(row.get("reward_id"), "reward_id")
        predicted = integer(row.get("prediction_committed_at_ms"), "prediction_committed_at_ms", 1)
        opened = integer(row.get("opened_at_ms"), "opened_at_ms", 1)
        first = integer(row.get("first_fill_ms"), "first_fill_ms", 1)
        closed = integer(row.get("closed_at_ms"), "closed_at_ms", 1)
        require(times[1] <= predicted < times[2] and predicted < opened <= first <= closed <= min(as_of, times[3]),
                "ORIGINAL_PREDICTION_EXECUTION_ORDER")
        terminal = row.get("preopen_terminal_evidence")
        require(isinstance(terminal, dict) and
                terminal.get("prediction_terminal") == "SEALED_AWAITING_ORIGINAL_COMMAND",
                "SUCCESSFUL_ORIGINAL_TERMINAL_REQUIRED")
        for name in ("terminal_sha256", "binding_sha256"):
            checked_hash(terminal.get(name), name)
        terminal_time = integer(terminal.get("publication_durability_observed_at_ms"), "terminal_publication", 1)
        require(predicted <= terminal_time < min(opened, times[2]), "TERMINAL_PUBLICATION_ORDER")
        require(set(row.get("predictions", {})) == set(heads), "UNPAIRED_HEAD_POPULATION")
        require(row.get("side") in ("BUY", "SELL"), "ACTION_SIDE")
        target = finite(row.get("target_usd"), "target_usd")
        finite(row.get("fee_usd"), "fee_usd")
        require(row.get("target_exceeds_training_support") is (abs(target) > 800), "TARGET_SUPPORT_FLAG")
        for name, value in row["predictions"].items():
            require(abs(finite(value, "prediction:" + name)) <= 15, "RAW_PREDICTION_IN_CLIPPED_CONTRACT")
        observed.append(row)
    total = integer(assessment.get("original_command_count"), "original_command_count")
    declared = assessment.get("status_counts")
    require(isinstance(declared, dict) and all(k in ("OBSERVED", "PENDING", "CENSORED") for k in declared),
            "SOURCE_STATUS_COUNTS")
    for name, count in declared.items():
        integer(count, "status_count:" + name)
    require(sum(declared.values()) == total and
            integer(assessment.get("observed_trades"), "observed_trades") == len(observed),
            "SOURCE_POPULATION_COUNTS")
    if complete:
        require(assessment.get("original_command_count_complete") is True and total == len(rows)
                and dict(counts) == declared, "ORIGINAL_COMMAND_DENOMINATOR_CHANGED")
        _same_number(assessment.get("prediction_coverage"), len(observed)/total if total else 0., "coverage")
    else:
        require(state != "FINAL_RESEARCH_COMPARISON" and assessment.get("current_credit_withdrawn") is True
                and assessment.get("original_command_count_complete") is False, "SOURCE_LOSS_NOT_WITHDRAWN")
        require(counts.get("OBSERVED", 0) == counts.get("PENDING", 0) == 0 and
                total >= len(rows) and declared == ({"CENSORED": total} if total else {}),
                "SOURCE_LOSS_DENOMINATOR")
        require(assessment.get("retained_known_command_count") == len(rows) and
                assessment.get("retained_unenumerated_command_count") == total-len(rows),
                "SOURCE_LOSS_LOWER_BOUND")
        require(assessment.get("current_source_totals") ==
                {"observed_trades": None, "original_command_count": None, "prediction_coverage": None},
                "UNKNOWN_SOURCE_TOTALS_FABRICATED")
        _same_number(assessment.get("prediction_coverage"), 0., "withdrawn_coverage")
    references = sorted(set(heads) | {"BENCHMARK_ZERO", "BENCHMARK_TRAIN_MEAN"})
    eligibility = _comparison_eligibility(plan, assessment, rows)
    training_mean = finite(plan.get("training_mean_usd"), "training_mean_usd")
    errors = {name: [] for name in references}
    for row in observed:
        values = dict(row["predictions"], BENCHMARK_ZERO=0., BENCHMARK_TRAIN_MEAN=training_mean)
        for name in references:
            errors[name].append(values[name] - row["target_usd"])
    summaries = {name: _metrics(values) for name, values in errors.items()}
    require(set(assessment.get("arm_metrics", {})) == set(references), "SOURCE_METRIC_ARMS")
    for name, values in summaries.items():
        for metric, value in values.items():
            _same_number(assessment["arm_metrics"][name].get(metric), value, name + ":" + metric)
    comparisons = {}
    source_pairs = assessment.get("paired_comparisons")
    require(isinstance(source_pairs, dict), "SOURCE_COMPARISONS_REQUIRED")
    expected_pairs = {a + " vs " + b for a in heads for b in references if a != b}
    require(set(source_pairs) == expected_pairs, "SOURCE_COMPARISON_FAMILY_CHANGED")
    for arm in sorted(heads):
        for reference in references:
            if arm == reference:
                continue
            key = arm + " vs " + reference
            gains = {"mae_gain_usd": math.fsum(abs(b)-abs(a) for a, b in
                     zip(errors[arm], errors[reference]))/len(observed) if observed else None,
                     "rmse_gain_usd": summaries[reference]["rmse_usd"] -
                     summaries[arm]["rmse_usd"] if observed else None}
            original = source_pairs[key]
            for metric, value in gains.items():
                _same_number(original.get(metric), value, key + ":" + metric)
            accepted = original.get("comparative_conditions_met")
            require(type(accepted) is bool, "SOURCE_COMPARATIVE_STATUS")
            require(not accepted or (complete and state == "FINAL_RESEARCH_COMPARISON" and
                    not assessment.get("reasons") and len(observed) == total),
                    "INCOMPLETE_SOURCE_COMPARATIVE_CREDIT")
            comparisons[key] = {**gains, "source_comparative_conditions_met": accepted,
                                "statistical_rule_recomputed": False}
    design = audit_comparison_design(plan, assessment, observed, len(expected_pairs))
    result = {"schema": HANDOFF_SCHEMA, "claim_scope": "imported_research_comparison",
              "plan_id": expected_plan_id, "source_state": state, "as_of_ms": as_of,
              "original_window": {k: plan[k] for k in TIME_KEYS},
              "parent_arm": plan["parent_arm"], "head_digests": {k: v["sha256"] for k, v in heads.items()},
              "numeric_profile": plan.get("numeric_profile"),
              "output_contract": {"task": "scalar_regression", "unit": "USD", "head_scale": 100,
                                  "absolute_prediction_bound": 15, "raw_predictions_present": False,
                                  "target_clipped": False},
              "current_replay_complete": complete, "original_command_count": total,
              "original_command_count_complete": complete, "enumerated_command_count": len(rows),
              "retained_unenumerated_command_count": total-len(rows), "status_counts": declared,
              "outcome_set_digest": outcomes["outcome_set_digest"], "arm_metrics": summaries,
              "paired_comparisons": comparisons, "source_rule": rule,
              "comparison_design": design,
              "source_reasons": assessment.get("reasons", []), "source_issues": assessment.get("source_issues", []),
              "comparison_eligibility": eligibility,
              "formal_success_possible_under_frozen_rule": eligibility["formal_success_possible_under_frozen_rule"],
              "costs": costs, "model_forwards_performed": 0, "original_window_modified": False,
              "original_records_modified": False, "production_eligibility": False,
              "activation_authorized": False, "trade_authority": False,
              "limitations": [
                  "Original strict evaluator owns request/terminal/binding and current ledger verification.",
                  "Hash consistency does not authenticate the observer or prove outcome separation.",
                  "USD error arithmetic is recomputed; the original statistical decision is preserved, not reissued.",
                  "Pending, censored or unavailable-source results do not become a new efficacy claim.",
                  "PENDING describes the original schedule; verified permanent pre-open failures can already make the frozen family ineligible.",
                  "Missing or unsupported negative evidence means unknown recoverability, never assumed eligibility.",
                  "Cost receipt sums are not end-to-end elapsed time or an equal-hardware speed comparison.",
              ]}
    result["handoff_digest"] = source_digest(result)
    return result


def _at(value, keys):
    require(isinstance(keys, list) and len(keys) <= 32, "COST_FIELD_PATH")
    for key in keys:
        require(isinstance(key, str) or (type(key) is int and key >= 0), "COST_FIELD_PATH")
        value = value[key]
    return value


def _cost_scopes(unique, inclusive):
    """Validate receipt-bound nesting; a metadata path is not a separate cost."""
    parents, ancestors = {}, {}
    for identity, record in unique.items():
        scope = record.get("accounting")
        if not inclusive:
            require(scope is None, "COST_SCOPE_REQUIRES_V2")
            continue
        require(isinstance(scope, dict) and set(scope) == {
                    "schema", "operation_id", "parent_operation_id", "metric_scope"} and
                scope["schema"] == "hepta.weight.inclusive-cost-scope.v1" and
                scope["operation_id"] == identity and scope["metric_scope"] == "inclusive",
                "COST_INCLUSIVE_SCOPE")
        parent = scope["parent_operation_id"]
        require(parent is None or (isinstance(parent, str) and parent in unique),
                "COST_UNKNOWN_PARENT")
        parents[identity] = parent
    for identity in parents:
        chain, seen, parent = [], {identity}, parents[identity]
        while parent is not None:
            require(parent not in seen, "COST_SCOPE_CYCLE")
            require(len(chain) < 64, "COST_SCOPE_DEPTH_LIMIT")
            chain.append(parent)
            seen.add(parent)
            parent = parents[parent]
        ancestors[identity] = chain
    paths = defaultdict(dict)
    for identity, record in unique.items():
        paths[record["source_sha256"]][tuple(record.get("source_record_path", []))] = identity
    for records_by_path in paths.values():
        for path, identity in records_by_path.items():
            for size in range(len(path)):
                containing = records_by_path.get(path[:size])
                if containing is not None:
                    require(inclusive and containing in ancestors[identity],
                            "COST_OVERLAPPING_RECEIPT_PATHS_REQUIRE_SCOPE")
    if inclusive:
        for identity, chain in ancestors.items():
            for parent in chain:
                for key in METRICS:
                    child_value = unique[identity]["metrics"][key]
                    parent_value = unique[parent]["metrics"][key]
                    if child_value is not None and parent_value is not None:
                        require(child_value <= parent_value or
                                (key not in COUNTS and math.isclose(
                                    child_value, parent_value, rel_tol=1e-9, abs_tol=1e-9)),
                                "COST_CHILD_EXCEEDS_INCLUSIVE_PARENT:" + key)
    return parents, ancestors


def _inclusive_cost_totals(unique, parents, ancestors):
    """Keep the outermost measured scope per metric, retaining unknown roots."""
    roots = sorted(k for k, parent in parents.items() if parent is None)
    answer = {"operation_count": len(unique),
              "status_counts": dict(Counter(x["status"] for x in unique.values()))}
    for key in METRICS:
        selected, suppressed = [], []
        for identity, record in unique.items():
            if record["metrics"][key] is None:
                continue
            if any(unique[parent]["metrics"][key] is not None for parent in ancestors[identity]):
                suppressed.append(identity)
            else:
                selected.append(identity)
        values = [unique[k]["metrics"][key] for k in selected]
        aggregate = None
        if values:
            aggregate = max(values) if key == "peak_rss_bytes" else (
                sum(values) if key in COUNTS else math.fsum(values))
        unknown_roots = [k for k in roots if unique[k]["metrics"][key] is None]
        missing = sum(record["metrics"][key] is None for record in unique.values())
        answer[key] = {
            "value": aggregate,
            "aggregation": "maximum" if key == "peak_rss_bytes" else "outermost_measured_inclusive_scopes",
            "selected_operation_ids": sorted(selected), "suppressed_operation_ids": sorted(suppressed),
            "unknown_root_operation_ids": unknown_roots,
            "known_operation_count": len(unique) - missing, "missing_operation_count": missing,
            "complete": bool(roots) and not unknown_roots,
            "scope": "DECLARED_OPERATIONS_ONLY; NOT_END_TO_END_OR_COMPLETE_EXPERIMENT",
            "known_subscope_lower_bound_only": bool(values) and bool(unknown_roots)}
    return answer


def summarize_costs(records, *, inclusive=False):
    """Summarize captured operations once, preserving unknown measurements.

    V1 keeps reported-operation sums, without asserting non-overlapping scopes.
    V2 uses explicit inclusive ancestry read from the same pinned receipts.
    Neither schema proves that the caller supplied every experiment operation.
    """
    require(isinstance(records, list) and len(records) <= MAX_ROWS, "COST_RECORD_LIMIT")
    unique, receipts = {}, {}
    for record in records:
        identity = record.get("operation_id")
        require(isinstance(identity, str) and identity and len(identity) <= 512, "COST_OPERATION_ID")
        checked_hash(record.get("source_sha256"), "cost_source_sha256")
        record_path = record.get("source_record_path", [])
        require(isinstance(record_path, list) and len(record_path) <= 32 and
                all(isinstance(x, str) or (type(x) is int and x >= 0) for x in record_path),
                "COST_RECORD_PATH")
        require(record.get("stage") in STAGES, "COST_STAGE")
        require(record.get("status") in ("completed", "failed", "interrupted", "unknown"), "COST_STATUS")
        arms = record.get("arm_ids")
        require(isinstance(arms, list) and all(isinstance(x, str) and x for x in arms)
                and len(arms) == len(set(arms)), "COST_ARMS")
        values = record.get("metrics")
        require(isinstance(values, dict) and set(values) == set(METRICS), "COST_METRIC_KEYS")
        for key, value in values.items():
            if value is not None:
                integer(value, key) if key in COUNTS else finite(value, key, nonnegative=True)
        if identity in unique:
            require(unique[identity] == record, "CONFLICTING_COST_OPERATION")
            continue
        receipt = source_digest([record["source_sha256"], record.get("source_record_path", [])])
        require(receipt not in receipts, "COST_RECEIPT_COUNTED_TWICE")
        receipts[receipt] = identity
        unique[identity] = record
    parents, ancestors = _cost_scopes(unique, inclusive)
    stages = defaultdict(list)
    for record in unique.values():
        stages[record["stage"]].append(record)
    def group_summary(items):
        answer = {"operation_count": len(items), "status_counts": dict(Counter(x["status"] for x in items))}
        for key in METRICS:
            known = [x["metrics"][key] for x in items if x["metrics"][key] is not None]
            aggregate = None
            if known:
                aggregate = max(known) if key == "peak_rss_bytes" else (
                    sum(known) if key in COUNTS else math.fsum(known))
            answer[key] = {"known_operation_count": len(known), "missing_operation_count": len(items)-len(known),
                           "aggregation": "maximum" if key == "peak_rss_bytes" else "sum_of_operations",
                           "value": aggregate,
                           "scope": "SUBMITTED_OPERATIONS_ONLY; MAY_INCLUDE_NESTED_SCOPES",
                           "complete": bool(items) and len(known) == len(items)}
        return answer
    present_stages = set(stages)
    coverage = {"required_stages": sorted(REQUIRED_COST_STAGES),
                "present_stages": sorted(present_stages),
                "missing_stages": sorted(REQUIRED_COST_STAGES - present_stages),
                "all_required_stages_represented": REQUIRED_COST_STAGES <= present_stages,
                "complete_experiment_inventory_verified": False,
                "failed_attempt_inventory_verified": False}
    result = {"schema": "hepta.weight.measured-cost-summary.v2" if inclusive else
                        "hepta.weight.measured-cost-summary.v1", "unique_operations": len(unique),
              "duplicate_input_records": len(records)-len(unique),
              "operations": [unique[k] for k in sorted(unique)],
              "stages": {k: group_summary(v) for k, v in sorted(stages.items())},
              "shared_operations": [k for k, v in unique.items() if len(v["arm_ids"]) != 1],
              "operation_arm_mapping": {k: v["arm_ids"] for k, v in unique.items()},
              "totals": (_inclusive_cost_totals(unique, parents, ancestors) if inclusive else
                         group_summary(list(unique.values()))),
              "coverage": coverage,
              "accounting_mode": "RECEIPT_BOUND_INCLUSIVE_SCOPES" if inclusive else
                                 "LEGACY_REPORTED_OPERATION_SUMS_SCOPE_UNKNOWN",
              "stage_summaries_may_overlap": True,
              "end_to_end_wall_seconds": None,
              "speedup_claim": None, "measurements_authenticated": False}
    result["cost_digest"] = source_digest(result)
    return result


def load_costs(manifest_path):
    """Metric values come from hash-checked receipt fields, never manifest numbers."""
    manifest, _ = read_json_bytes(manifest_path)
    require(manifest.get("schema") in ("hepta.weight.cost-inputs.v1", "hepta.weight.cost-inputs.v2"),
            "COST_INPUT_SCHEMA")
    inclusive = manifest["schema"] == "hepta.weight.cost-inputs.v2"
    specifications = manifest.get("records")
    require(isinstance(specifications, list) and len(specifications) <= MAX_ROWS, "COST_RECORD_LIMIT")
    records = []
    for spec in specifications:
        path = Path(spec["source_path"])
        require(path.is_absolute(), "COST_SOURCE_ABSOLUTE_PATH")
        value, raw = read_json_bytes(path)
        expected = checked_hash(spec.get("source_sha256"), "cost_source_sha256")
        require(hashlib.sha256(raw).hexdigest() == expected, "COST_SOURCE_CHANGED")
        record_path = spec.get("source_record_path", [])
        record = _at(value, record_path)
        selectors = spec.get("metric_paths", {})
        require(isinstance(selectors, dict) and set(selectors) <= set(METRICS), "COST_METRIC_KEYS")
        metrics = {key: _at(record, selectors[key]) if key in selectors else None for key in METRICS}
        status = _at(record, spec["status_path"]) if "status_path" in spec else "unknown"
        normalized = {"operation_id": spec["operation_id"], "stage": spec["stage"],
                      "arm_ids": spec["arm_ids"], "source_sha256": expected,
                      "source_record_path": record_path, "status": status, "metrics": metrics}
        if inclusive:
            require("accounting_path" in spec, "COST_ACCOUNTING_RECEIPT_REQUIRED")
            normalized["accounting"] = _at(record, spec["accounting_path"])
        else:
            require("accounting_path" not in spec and "accounting" not in spec,
                    "COST_SCOPE_REQUIRES_V2")
        records.append(normalized)
    return summarize_costs(records, inclusive=inclusive)


def load_review(review_root, expected_plan_id, *, cost_manifest=None):
    root = Path(review_root)
    require(root.is_absolute() and root.is_dir() and not root.is_symlink(), "REVIEW_ROOT")
    assessment, report_bytes = read_json_bytes(root / "assessment-strict.json")
    plan_snapshot, _ = read_json_bytes(root / "review-plan-snapshot.json")
    provenance_path = root / "strict-review-provenance.json"
    provenance, provenance_bytes = read_json_bytes(provenance_path) if provenance_path.exists() else (None, None)
    pointer = assessment.get("outcome_set_snapshot")
    require(isinstance(pointer, dict) and pointer.get("schema") == OUTCOME_SCHEMA,
            "ORDERED_OUTCOME_SNAPSHOT_REQUIRED")
    relative = pointer.get("relative_path")
    require(isinstance(relative, str) and relative.startswith("outcome-sets/") and
            len(Path(relative).parts) == 2 and Path(relative).name.endswith(".json"), "OUTCOME_SNAPSHOT_PATH")
    snapshot_path = root / relative
    require(snapshot_path.resolve().parent == (root / "outcome-sets").resolve()
            and not (root / "outcome-sets").is_symlink(), "OUTCOME_SNAPSHOT_PATH")
    outcomes, raw = read_json_bytes(snapshot_path)
    require(hashlib.sha256(raw).hexdigest() == checked_hash(pointer.get("sha256"), "snapshot_sha256"),
            "OUTCOME_SNAPSHOT_FILE_CHANGED")
    require(pointer.get("outcome_set_digest") == outcomes.get("outcome_set_digest") and
            pointer.get("row_count") == len(outcomes.get("rows", [])), "OUTCOME_SNAPSHOT_POINTER")
    costs = load_costs(cost_manifest) if cost_manifest is not None else None
    result = import_assessment(plan_snapshot, provenance, assessment, outcomes,
                               expected_plan_id=expected_plan_id,
                               provenance_sha256=hashlib.sha256(provenance_bytes).hexdigest() if provenance_bytes else None,
                               costs=costs)
    _, after = read_json_bytes(root / "assessment-strict.json")
    require(after == report_bytes, "ASSESSMENT_CHANGED_DURING_CAPTURE")
    result["source_assessment_sha256"] = hashlib.sha256(report_bytes).hexdigest()
    result["ordered_snapshot_sha256"] = hashlib.sha256(raw).hexdigest()
    result["handoff_digest"] = source_digest({k: v for k, v in result.items() if k != "handoff_digest"})
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--review-root", required=True, type=Path)
    parser.add_argument("--expected-plan-id", required=True)
    parser.add_argument("--cost-manifest", type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        require(not args.out.resolve().is_relative_to(args.review_root.resolve()), "OUTPUT_INSIDE_SOURCE_REVIEW")
        result = load_review(args.review_root, args.expected_plan_id, cost_manifest=args.cost_manifest)
        publish_once(args.out, result)
        summary = {k: result[k] for k in ("schema", "plan_id", "source_state", "original_command_count",
                                        "current_replay_complete", "handoff_digest", "formal_success_possible_under_frozen_rule")}
        summary["comparison_eligibility_status"] = result["comparison_eligibility"]["status"]
        print(json.dumps(summary, sort_keys=True))
        return 0
    except (HandoffError, OSError, KeyError, TypeError, OverflowError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

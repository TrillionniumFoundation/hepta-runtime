#!/usr/bin/env python3
"""Separate frozen-plan research evaluator; never grants production eligibility.

The host must isolate confirmation outcomes from the editing worker. Digests
verify identity, not access control or observer authenticity.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import random
import statistics
import tempfile
import time

SCHEMA = "hepta.weight.paired-plan.v1"
MAX_ROWS = 100_000
MAX_BYTES = 64 * 1024 * 1024


class EvaluationError(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise EvaluationError("DUPLICATE_JSON_KEY:" + key)
        result[key] = value
    return result


def read_json(path):
    path = Path(path)
    if not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise EvaluationError("ARTIFACT_SIZE_OR_TYPE")
    def reject(value):
        raise EvaluationError("NONFINITE_JSON:" + value)
    return json.loads(path.read_text("utf-8"), object_pairs_hook=_pairs,
                      parse_constant=reject)


def publish(path, value):
    """Create once; identical replay succeeds and conflicting replay is refused."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = canonical(value) + b"\n"
    if path.exists():
        if path.read_bytes() != data:
            raise EvaluationError("PUBLICATION_CONFLICT")
        return
    descriptor, temporary = tempfile.mkstemp(prefix=".evaluation-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            if path.read_bytes() != data:
                raise EvaluationError("PUBLICATION_CONFLICT")
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        os.unlink(temporary)


def hash_field(value, name):
    result = value.get(name)
    if (not isinstance(result, str) or len(result) != 64
            or any(c not in "0123456789abcdef" for c in result)):
        raise EvaluationError("INVALID_DIGEST:" + name)
    return result


def integer(value, name, low=0, high=2**63-1):
    if type(value) is not int or not low <= value <= high:
        raise EvaluationError("INVALID_INTEGER:" + name)
    return value


def number(value, name, low, high):
    if type(value) not in (int, float) or not math.isfinite(value) or not low <= value <= high:
        raise EvaluationError("INVALID_NUMBER:" + name)
    return float(value)


def id_set(values, name):
    if (not isinstance(values, list) or len(values) > MAX_ROWS
            or any(not isinstance(x, str) or not x or len(x) > 512 for x in values)):
        raise EvaluationError("INVALID_IDS:" + name)
    if len(set(values)) != len(values):
        raise EvaluationError("DUPLICATE_IDS:" + name)
    return set(values)


def validate_plan(plan):
    if not isinstance(plan, dict):
        raise EvaluationError("PLAN_OBJECT_REQUIRED")
    if plan.get("schema") != SCHEMA or plan.get("construction_kind") != "DirectWeightEdit":
        raise EvaluationError("PLAN_SCHEMA")
    if plan.get("claim_scope") != "research_comparison":
        raise EvaluationError("UNSUPPORTED_AUTHORITY_CLAIM")
    if plan.get("mode") not in ("retrospective", "prospective"):
        raise EvaluationError("TEMPORAL_MODE")
    for name in ("base_digest", "candidate_digest", "execution_profile_digest",
                 "parent_calibration_digest", "candidate_calibration_digest",
                 "dataset_digest", "outcome_source_digest"):
        hash_field(plan, name)
    used = id_set(plan.get("discovery_ids"), "discovery_ids") | id_set(
        plan.get("development_ids"), "development_ids")
    held = id_set(plan.get("confirmation_ids"), "confirmation_ids")
    if not held or held & used:
        raise EvaluationError("CONFIRMATION_OVERLAPS_SEARCH")
    clusters = plan.get("clusters")
    if (not isinstance(clusters, dict) or set(clusters) != held
            or any(not isinstance(x, str) or not x or len(x) > 512 for x in clusters.values())):
        raise EvaluationError("FROZEN_CLUSTERS_REQUIRED")
    sealed = integer(plan.get("sealed_at_ms"), "sealed_at_ms", 1)
    cutoff = integer(plan.get("information_cutoff_ms"), "information_cutoff_ms")
    calibration = integer(plan.get("calibration_cutoff_ms"), "calibration_cutoff_ms")
    if not calibration <= cutoff <= sealed:
        raise EvaluationError("INFORMATION_TIME_ORDER")
    integer(plan.get("classes"), "classes", 2, 65536)
    integer(plan.get("minimum_samples"), "minimum_samples", 2, MAX_ROWS)
    integer(plan.get("minimum_clusters"), "minimum_clusters", 2, MAX_ROWS)
    integer(plan.get("bootstrap_repetitions"), "bootstrap_repetitions", 199, 20000)
    if len(set(clusters.values())) * plan["bootstrap_repetitions"] > 2_000_000:
        raise EvaluationError("BOOTSTRAP_WORK_BUDGET")
    integer(plan.get("seed"), "seed", 0, 2**32-1)
    number(plan.get("confidence"), "confidence", .8, .999)
    number(plan.get("minimum_brier_gain"), "minimum_brier_gain", 0, 2)
    number(plan.get("maximum_action_tv"), "maximum_action_tv", 0, 1)
    if type(plan.get("require_action_outputs")) is not bool:
        raise EvaluationError("ACTION_REQUIREMENT_MISSING")
    if "outcomes_digest" in plan:
        hash_field(plan, "outcomes_digest")
        if plan["mode"] == "prospective":
            raise EvaluationError("FUTURE_LABELS_CANNOT_BE_PREKNOWN")


def freeze(spec, now_ms=None):
    if not isinstance(spec, dict) or "plan_digest" in spec or "sealed_at_ms" in spec:
        raise EvaluationError("CALLER_CANNOT_SET_SEAL")
    plan = dict(spec, schema=SCHEMA, construction_kind="DirectWeightEdit",
                claim_scope="research_comparison",
                sealed_at_ms=int(time.time()*1000) if now_ms is None else now_ms)
    validate_plan(plan)
    plan["plan_digest"] = digest(plan)
    return plan


def verify_plan(plan):
    validate_plan(plan)
    if hash_field(plan, "plan_digest") != digest({k:v for k,v in plan.items() if k != "plan_digest"}):
        raise EvaluationError("PLAN_DIGEST_MISMATCH")


def records(document):
    if not isinstance(document, dict):
        raise EvaluationError("ARTIFACT_OBJECT_REQUIRED")
    rows = document.get("rows")
    if not isinstance(rows, list) or len(rows) > MAX_ROWS:
        raise EvaluationError("ROW_LIMIT_OR_TYPE")
    result = {}
    for row in rows:
        if not isinstance(row, dict):
            raise EvaluationError("ROW_OBJECT_REQUIRED")
        identity = row.get("unit_id")
        if not isinstance(identity, str) or not identity or len(identity) > 512:
            raise EvaluationError("INVALID_UNIT_ID")
        if identity in result:
            raise EvaluationError("DUPLICATE_UNIT_ID")
        result[identity] = row
    return result


def probabilities(row, name, count):
    values = row.get(name)
    if not isinstance(values, list) or len(values) != count:
        raise EvaluationError("PROBABILITY_SHAPE:" + name)
    result = [number(x, name, 0, 1) for x in values]
    if abs(math.fsum(result)-1) > 1e-7:
        raise EvaluationError("PROBABILITY_SUM:" + name)
    return result


def brier(values, label):
    return math.fsum((p-int(i == label))**2 for i,p in enumerate(values))


def cluster_interval(groups, confidence, repetitions, seed):
    if len(groups) < 2:
        return None
    sums = [math.fsum(x) for x in groups.values()]
    sizes = [len(x) for x in groups.values()]
    generator = random.Random(seed)
    samples = []
    for _ in range(repetitions):
        indices = generator.choices(range(len(sums)), k=len(sums))
        samples.append(math.fsum(sums[i] for i in indices)/sum(sizes[i] for i in indices))
    samples.sort()
    def quantile(q):
        at = (len(samples)-1)*q
        left = int(at)
        right = min(left+1, len(samples)-1)
        return samples[left]+(samples[right]-samples[left])*(at-left)
    alpha = (1-confidence)/2
    return [quantile(alpha), quantile(1-alpha)]


def evaluate(plan, parent_document, candidate_document, outcomes_document):
    verify_plan(plan)
    if any(not isinstance(x, dict) for x in (parent_document, candidate_document, outcomes_document)):
        raise EvaluationError("ARTIFACT_OBJECT_REQUIRED")
    if outcomes_document.get("source_digest") != plan["outcome_source_digest"]:
        raise EvaluationError("OUTCOME_SOURCE_MISMATCH")
    if "outcomes_digest" in plan and digest(outcomes_document) != plan["outcomes_digest"]:
        raise EvaluationError("OUTCOME_COMMITMENT_MISMATCH")
    for document, model, calibration in (
            (parent_document, "base_digest", "parent_calibration_digest"),
            (candidate_document, "candidate_digest", "candidate_calibration_digest")):
        if document.get("model_digest") != plan[model]:
            raise EvaluationError("MODEL_BINDING_MISMATCH")
        if document.get("calibration_digest") != plan[calibration]:
            raise EvaluationError("CALIBRATION_BINDING_MISMATCH")
        for key in ("execution_profile_digest", "dataset_digest"):
            if document.get(key) != plan[key]:
                raise EvaluationError("PROFILE_OR_DATASET_MISMATCH")
    if outcomes_document.get("dataset_digest") != plan["dataset_digest"]:
        raise EvaluationError("OUTCOME_DATASET_MISMATCH")
    parent, candidate, outcomes = map(records, (
        parent_document, candidate_document, outcomes_document))
    expected = set(plan["confirmation_ids"])
    if any(set(x) != expected for x in (parent, candidate, outcomes)):
        raise EvaluationError("EXACT_CONFIRMATION_SET_REQUIRED")
    groups, scored, input_clusters = {}, [], {}
    counts = {"observed": 0, "pending": 0, "censored": 0}
    action_tv = 0.0
    for identity in sorted(expected):
        p, c, outcome = parent[identity], candidate[identity], outcomes[identity]
        if hash_field(p, "input_digest") != hash_field(c, "input_digest") or (
                p["input_digest"] != hash_field(outcome, "input_digest")):
            raise EvaluationError("PAIRED_INPUT_MISMATCH")
        cluster = outcome.get("cluster_id")
        if cluster != plan["clusters"][identity]:
            raise EvaluationError("FROZEN_CLUSTER_MISMATCH")
        previous = input_clusters.setdefault(p["input_digest"], cluster)
        if previous != cluster:
            raise EvaluationError("REPEATED_INPUT_SPLIT_ACROSS_CLUSTERS")
        if type(p.get("seed")) is not int or p["seed"] != c.get("seed"):
            raise EvaluationError("PAIRED_SEED_MISMATCH")
        pp = probabilities(p, "probabilities", plan["classes"])
        cp = probabilities(c, "probabilities", plan["classes"])
        for row in (p, c):
            integer(row.get("created_at_ms"), "created_at_ms", 1)
        if plan["require_action_outputs"]:
            ap = probabilities(p, "action_probabilities", 2)
            ac = probabilities(c, "action_probabilities", 2)
            action_tv = max(action_tv, .5*math.fsum(abs(x-y) for x,y in zip(ap, ac)))
        status = outcome.get("status")
        if status not in counts:
            raise EvaluationError("UNKNOWN_OUTCOME_STATUS")
        if plan["mode"] == "prospective":
            input_time = integer(outcome.get("input_at_ms"), "input_at_ms", 1)
            deadline = integer(outcome.get("prediction_deadline_ms"), "deadline", 1)
            if not plan["sealed_at_ms"] <= input_time < deadline:
                raise EvaluationError("PROSPECTIVE_INPUT_PRECEDES_SEAL")
            if plan["information_cutoff_ms"] > input_time:
                raise EvaluationError("INFORMATION_AFTER_INPUT")
            for row in (p,c):
                if not input_time <= row["created_at_ms"] < deadline:
                    raise EvaluationError("PREDICTION_NOT_BEFORE_DEADLINE")
            if status == "observed":
                observed = integer(outcome.get("observed_at_ms"), "observed_at_ms", 1)
                if observed < deadline:
                    raise EvaluationError("OUTCOME_PRECEDES_DEADLINE")
        counts[status] += 1
        if status != "observed":
            if "label" in outcome:
                raise EvaluationError("UNOBSERVED_OUTCOME_HAS_LABEL")
            continue
        label = integer(outcome.get("label"), "label", 0, plan["classes"]-1)
        pb, cb = brier(pp, label), brier(cp, label)
        gain = pb-cb
        groups.setdefault(cluster, []).append(gain)
        scored.append({"unit_id": identity, "cluster_id": cluster,
                       "parent_brier": pb, "candidate_brier": cb, "gain": gain,
                       "parent_correct": max(range(len(pp)), key=pp.__getitem__) == label,
                       "candidate_correct": max(range(len(cp)), key=cp.__getitem__) == label})
    interval = cluster_interval(groups, plan["confidence"],
                                plan["bootstrap_repetitions"], plan["seed"])
    enough = len(scored) >= plan["minimum_samples"] and len(groups) >= plan["minimum_clusters"]
    if action_tv > plan["maximum_action_tv"]:
        verdict, reason = "NoUsefulPatch", "NON_TARGET_ACTION_REGRESSION"
    elif counts["pending"]:
        verdict, reason = "InsufficientEvidence", "FROZEN_CONFIRMATION_NOT_COMPLETE"
    elif counts["censored"]:
        # V1 has no independently justified missing-outcome estimator. Excluding
        # terminal censored rows can select a favorable subset just as stopping
        # on early observed rows can. Preserve descriptive scores, not a gain claim.
        verdict, reason = "InsufficientEvidence", "CENSORED_CONFIRMATION_DESCRIPTIVE_ONLY"
    elif not enough:
        verdict, reason = "InsufficientEvidence", "SAMPLE_OR_CLUSTER_SUPPORT"
    elif interval[0] > plan["minimum_brier_gain"]:
        verdict, reason = "ResearchGainConfirmed", "FROZEN_PAIRED_BRIER_GAIN"
    elif interval[1] <= plan["minimum_brier_gain"]:
        verdict, reason = "NoUsefulPatch", "GAIN_BELOW_MINIMUM"
    else:
        verdict, reason = "InsufficientEvidence", "INTERVAL_CROSSES_REQUIRED_GAIN"
    def mean(key):
        return statistics.fmean(x[key] for x in scored) if scored else None
    result = {
        "schema": "hepta.weight.paired-evaluation.v1",
        "claim_scope": "research_comparison", "production_eligibility": False,
        "activation_authorized": False, "plan_digest": plan["plan_digest"],
        "base_digest": plan["base_digest"], "candidate_digest": plan["candidate_digest"],
        "mode": plan["mode"], "parent_predictions_digest": digest(parent_document),
        "candidate_predictions_digest": digest(candidate_document),
        "outcomes_digest": digest(outcomes_document), "counts": counts,
        "confirmation_complete": counts["pending"] == 0 and counts["censored"] == 0,
        "clusters": len(groups), "paired_brier_gain": mean("gain"),
        "cluster_bootstrap_interval": interval, "confidence": plan["confidence"],
        "bootstrap_repetitions": plan["bootstrap_repetitions"],
        "action_outputs_evaluated": plan["require_action_outputs"],
        "maximum_action_tv": action_tv if plan["require_action_outputs"] else None,
        "verdict": verdict, "reason": reason,
        "parent_brier": mean("parent_brier"), "candidate_brier": mean("candidate_brier"),
        "parent_accuracy": mean("parent_correct"), "candidate_accuracy": mean("candidate_correct"),
        "paired_rows": scored,
        "limitations": [
            "Host must enforce outcome separation and authenticate the observer independently.",
            "Timestamp consistency checks do not prove that an outcome was unknown to the editor.",
            "Cluster bootstrap assumes defensible frozen clusters and sufficient support.",
            "Observed-subset scores are descriptive while any frozen outcome is pending or censored.",
            "No financial-return, production-qualification or deployment claim is issued.",
        ],
    }
    result["evaluation_digest"] = digest(result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    freezing = sub.add_parser("freeze")
    freezing.add_argument("--spec", required=True)
    freezing.add_argument("--out", required=True)
    evaluating = sub.add_parser("evaluate")
    for name in ("plan", "parent", "candidate", "outcomes", "out"):
        evaluating.add_argument("--"+name, required=True)
    args = parser.parse_args(argv)
    try:
        if args.operation == "freeze":
            result = freeze(read_json(args.spec))
            if Path(args.out).exists():
                previous = read_json(args.out)
                verify_plan(previous)
                semantic = lambda p: {k:v for k,v in p.items() if k not in ("sealed_at_ms", "plan_digest")}
                if canonical(semantic(previous)) != canonical(semantic(result)):
                    raise EvaluationError("PUBLICATION_CONFLICT")
                result = previous
        else:
            result = evaluate(read_json(args.plan), read_json(args.parent),
                              read_json(args.candidate), read_json(args.outcomes))
        publish(args.out, result)
        print(json.dumps({k:v for k,v in result.items() if k != "paired_rows"},
                         sort_keys=True, ensure_ascii=False, allow_nan=False))
        return 0
    except (EvaluationError, OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())



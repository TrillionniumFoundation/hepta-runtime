#!/usr/bin/env python3
"""Re-evaluate a known Laya bundle; never label this replay new blind evidence."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import paired_eval as E


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def require(condition, code):
    if not condition:
        raise E.EvaluationError(code)


def field(document, key, context):
    require(isinstance(document, dict), "LEGACY_OBJECT_REQUIRED:" + context)
    require(key in document, "LEGACY_REQUIRED_FIELD:" + context + "." + key)
    return document[key]


def hash_value(document, key, context):
    field(document, key, context)
    try:
        return E.hash_field(document, key)
    except E.EvaluationError as exc:
        raise E.EvaluationError("LEGACY_INVALID_DIGEST:" + context + "." + key) from exc


def document(path, schema=None):
    try:
        value = E.read_json(path)
    except (OSError, E.EvaluationError, ValueError) as exc:
        raise E.EvaluationError("LEGACY_DOCUMENT_UNREADABLE:" + Path(path).name) from exc
    require(isinstance(value, dict), "LEGACY_OBJECT_REQUIRED:" + Path(path).name)
    if schema is not None:
        require(field(value, "schema", Path(path).name) == schema,
                "LEGACY_SCHEMA:" + Path(path).name)
    return value


def self_digest(value, key, context):
    expected = hash_value(value, key, context)
    require(expected == E.digest({k:v for k,v in value.items() if k != key}),
            "LEGACY_SELF_DIGEST:" + context + "." + key)
    return expected


def bind_file(path, owner, key, context):
    expected = hash_value(owner, key, context)
    require(sha(path) == expected, "LEGACY_FILE_BINDING:" + context + "." + key)
    return expected


def slots(value, context):
    require(isinstance(value, list) and len(value) <= E.MAX_ROWS,
            "LEGACY_SLOT_LIST:" + context)
    require(all(type(x) is int and 0 <= x <= 999999 for x in value)
            and len(set(value)) == len(value), "LEGACY_SLOT_LIST:" + context)
    return value


def calibration(profile, role, parent_id, adapter_sha256, context):
    """Validate the frozen v3 identity and the algebra needed for probability replay.

    This verifies stored metadata and its application, not a new fit or the
    authenticity of the original observer/training-population declaration.
    """
    require(field(profile, "schema", context) == "heptatrader.laya-price-calibration.v3"
            and field(profile, "output_profile", context) == "FROZEN_SAME_PRICE_TRAIN_ROWS_CENTERED_BRIER_V3",
            "LEGACY_CALIBRATION_SCHEMA:" + context)
    self_digest(profile, "profile_id", context)
    for name in ("parent_id", "adapter_sha256", "training_row_ids_digest",
                 "price_baseline_profile_id", "raw_probability_receipt_digest"):
        hash_value(profile, name, context)
    require(profile["parent_id"] == parent_id and profile["adapter_sha256"] == adapter_sha256,
            "LEGACY_CALIBRATION_MODEL_BINDING:" + context)
    scope = ("ACTUAL_FROZEN_PARENT_SAME_PRICE_TRAINING_FORWARD_PASSES" if role == "parent"
             else "ACTUAL_FINAL_CHILD_PRICE_TRAINING_FORWARD_PASSES")
    require(field(profile, "raw_logits_scope", context) == scope,
            "LEGACY_CALIBRATION_SCOPE:" + context)
    require(field(profile, "calibration_is_train_only", context) is True
            and field(profile, "future_value_proven", context) is False
            and field(profile, "model_or_trading_authority", context) is False
            and type(field(profile, "additional_independent_training_rows", context)) is int
            and profile["additional_independent_training_rows"] == 0,
            "LEGACY_CALIBRATION_AUTHORITY:" + context)
    count = E.integer(field(profile, "training_rows", context), context + ".training_rows", 1, E.MAX_ROWS)
    E.integer(field(profile, "training_cutoff_ms", context), context + ".training_cutoff_ms")
    counts = field(profile, "real_target_class_counts", context)
    require(isinstance(counts, list) and len(counts) == 7
            and all(type(x) is int and x >= 0 for x in counts) and sum(counts) == count,
            "LEGACY_CALIBRATION_COUNTS:" + context)
    prior = E.probabilities(profile, "train_prior_probs", 7)
    require(prior == [(x + 1) / (count + 7) for x in counts],
            "LEGACY_CALIBRATION_PRIOR:" + context)
    mean = E.probabilities(profile, "mean_training_raw_probs", 7)
    weight = E.number(field(profile, "model_weight", context), context + ".model_weight", 0, 1)
    maximum = E.number(field(profile, "model_weight_max", context), context + ".model_weight_max", 0, 1)
    a = E.number(field(profile, "quadratic_numerator", context), context + ".quadratic_numerator", -1e300, 1e300)
    b = E.number(field(profile, "quadratic_denominator", context), context + ".quadratic_denominator", 0, 1e300)
    expected_maximum = min([1.] + [p/m for p,m in zip(prior, mean) if m > p])
    for _ in range(8):
        if all(p - expected_maximum*m >= 0 for p,m in zip(prior, mean)):
            break
        expected_maximum = math.nextafter(expected_maximum, 0.)
    require(all(p - expected_maximum*m >= 0 for p,m in zip(prior, mean))
            and maximum == expected_maximum and weight <= maximum,
            "LEGACY_CALIBRATION_BOUND:" + context)
    expected_weight = min(maximum, max(0., a/b)) if b > 0 else 0.
    require(weight == expected_weight and (b != 0 or a == 0),
            "LEGACY_CALIBRATION_SOLUTION:" + context)
    return profile


def apply_calibration(profile, values, context):
    require(isinstance(values, list) and len(values) == 7,
            "LEGACY_RAW_PROBABILITY_SHAPE:" + context)
    raw = [E.number(x, context, 0, 1) for x in values]
    require(abs(sum(raw) - 1) <= 1e-5, "LEGACY_RAW_PROBABILITY_SUM:" + context)
    total = sum(raw)
    raw = [x/total for x in raw]
    weight = profile["model_weight"]
    if weight == 0:
        return profile["train_prior_probs"][:]
    calibrated = [p-weight*m+weight*x for p,m,x in zip(
        profile["train_prior_probs"], profile["mean_training_raw_probs"], raw)]
    total = sum(calibrated)
    require(all(math.isfinite(x) and x >= 0 for x in calibrated) and abs(total - 1) <= 1e-5,
            "LEGACY_CALIBRATION_OUTPUT:" + context)
    return [x/total for x in calibrated]


def validate_headers(bundle):
    seal_path, search_path = bundle/"sealed_candidate.json", bundle/"analysis.json"
    seal = document(seal_path, "astra.sealed-experimental-weight-patch.v1")
    search = document(search_path)
    old = document(bundle/"shadow/plan.json", "astra.frozen-shadow-plan.v1")
    source_path = bundle/"reference/source_eval/plan.json"
    source = document(source_path, "heptatrader.laya-resident-future-plan.v1")
    self_digest(old, "plan_id", "shadow_plan")
    self_digest(source, "plan_id", "source_plan")
    bind_file(seal_path, old, "seal_sha256", "shadow_plan")
    bind_file(source_path, old, "source_plan_sha256", "shadow_plan")
    bind_file(search_path, seal, "analysis_sha256", "seal")
    candidate_id = hash_value(seal, "candidate_id", "seal")
    parent_id = hash_value(seal, "parent_candidate_id", "seal")
    adapter = hash_value(seal, "adapter_sha256", "seal")
    parent_adapter = hash_value(seal, "parent_adapter_sha256", "seal")
    require(hash_value(old, "candidate_id", "shadow_plan") == candidate_id
            and hash_value(old, "adapter_sha256", "shadow_plan") == adapter,
            "LEGACY_PLAN_CANDIDATE_BINDING")
    require(hash_value(old, "source_plan_id", "shadow_plan") == source["plan_id"]
            and hash_value(source, "parent_id", "source_plan") == parent_id,
            "LEGACY_SOURCE_PLAN_BINDING")
    hash_value(source, "candidate_id", "source_plan")
    created = E.integer(field(seal, "created_at_ms", "seal"), "seal.created_at_ms", 1)
    require(E.integer(field(old, "candidate_frozen_at_ms", "shadow_plan"), "candidate_frozen_at_ms", 1) == created,
            "LEGACY_SEAL_TIME_BINDING")
    all_slots = slots(field(old, "all_slots", "shadow_plan"), "all_slots")
    held = slots(field(old, "retrospective_holdout_slots", "shadow_plan"), "retrospective_holdout_slots")
    fresh = slots(field(old, "fresh_slots", "shadow_plan"), "fresh_slots")
    require(all_slots and all_slots == sorted(set(held) | set(fresh)), "LEGACY_SLOT_POPULATION")
    E.integer(field(field(old, "fixed_rule", "shadow_plan"), "horizon_ms", "fixed_rule"), "horizon_ms", 1)
    require(hash_value(search, "selected_experimental_candidate_id", "search") == candidate_id,
            "LEGACY_SEARCH_SELECTION_BINDING")
    candidates = field(search, "candidates", "search")
    require(isinstance(candidates, list) and candidates and all(isinstance(x, dict) for x in candidates),
            "LEGACY_SEARCH_CANDIDATES")
    require(len({hash_value(x, "candidate_id", "search_candidate") for x in candidates}) == len(candidates),
            "LEGACY_DUPLICATE_CANDIDATE")
    selected = [x for x in candidates if x["candidate_id"] == candidate_id]
    require(len(selected) == 1, "LEGACY_SELECTED_CANDIDATE_MISSING")
    selected = selected[0]
    for key in ("adapter_sha256", "parent_adapter_sha256", "protocol_sha256",
                "full_effective_scorer3_weight_sha256", "weights_sha256"):
        require(hash_value(selected, key, "search_candidate") == hash_value(seal, key, "seal"),
                "LEGACY_SELECTED_CANDIDATE_BINDING:" + key)
    identity_keys = ("experiment_id", "name", "protocol_sha256", "parent_adapter_sha256",
                     "adapter_sha256", "full_effective_scorer3_weight_sha256", "family", "rank", "strength")
    identity = {k:field(selected, k, "search_candidate") for k in identity_keys}
    require(E.digest(identity) == candidate_id and field(seal, "selected_edit_name", "seal") == selected["name"]
            and field(seal, "experiment_id", "seal") == selected["experiment_id"],
            "LEGACY_CANDIDATE_IDENTITY")
    require(type(field(search, "eligible_candidates", "search")) is int
            and search["eligible_candidates"] == 0
            and all(field(x, "eligible", "search_candidate") is False for x in candidates)
            and field(seal, "eligible", "seal") is False
            and field(selected, "eligible", "search_candidate") is False,
            "NEGATIVE_CONTROL_UNEXPECTEDLY_ELIGIBLE")
    source_cal = field(source, "price_calibration", "source_plan")
    source_adapter = hash_value(source_cal, "adapter_sha256", "source_calibration")
    calibration(source_cal, "child", parent_id, source_adapter, "source_calibration")
    require(hash_value(source, "price_calibration_profile_id", "source_plan") == source_cal["profile_id"],
            "LEGACY_SOURCE_CALIBRATION_BINDING")
    comparator = field(source, "parent_calibration_comparator", "source_plan")
    self_digest(comparator, "comparator_id", "source_parent_comparator")
    calibration(field(comparator, "calibration", "source_parent_comparator"), "parent",
                parent_id, parent_adapter, "source_parent_calibration")
    profiles = {}
    for name, role, expected_adapter in (
            ("parent_calibration_cpu", "parent", parent_adapter),
            ("calibration", "child", adapter),
            ("comparison_scale_calibration", "child", hash_value(seal, "comparison_scale_adapter_sha256", "seal"))):
        profile = calibration(field(seal, name, "seal"), role, parent_id, expected_adapter, name)
        for key in ("training_row_ids_digest", "training_rows", "training_cutoff_ms",
                    "train_prior_probs", "real_target_class_counts", "price_baseline_profile_id"):
            require(profile[key] == source_cal[key], "LEGACY_CALIBRATION_POPULATION:" + name + "." + key)
        require(profile["training_cutoff_ms"] <= created, "LEGACY_CALIBRATION_AFTER_SEAL")
        profiles[name] = profile
    require(hash_value(selected, "calibration_profile_id", "search_candidate") == profiles["calibration"]["profile_id"]
            and E.digest(field(search, "parent_calibration_cpu", "search")) == E.digest(profiles["parent_calibration_cpu"]),
            "LEGACY_SEARCH_CALIBRATION_BINDING")
    return seal, search, old, source, profiles


def validate_row(bundle, slot, seal, old, source, profiles):
    pp, rp = bundle/f"shadow/prediction-{slot:03}.json", bundle/f"shadow/result-{slot:03}.json"
    ip = bundle/f"reference/source_eval/input-{slot:03}.json"
    op = bundle/f"reference/source_eval/outcome-{slot:03}.json"
    bp = bundle/f"reference/source_eval/prediction-{slot:03}.json"
    prediction = document(pp, "astra.shadow-prediction.v1")
    result = document(rp, "astra.shadow-result.v1")
    original_input = document(ip, "heptatrader.laya-committed-input.v1")
    original_outcome = document(op)
    baseline = document(bp, "heptatrader.resident-forward-prediction.v1")
    for context, item, plan_id, candidate_id in (
            ("prediction", prediction, old["plan_id"], seal["candidate_id"]),
            ("result", result, old["plan_id"], seal["candidate_id"]),
            ("source_input", original_input, source["plan_id"], source["candidate_id"]),
            ("source_prediction", baseline, source["plan_id"], source["candidate_id"]),
            ("source_outcome", original_outcome, source["plan_id"], source["candidate_id"])):
        require(E.integer(field(item, "slot", context), context + ".slot") == slot,
                "LEGACY_ROW_SLOT_BINDING:" + context)
        require(hash_value(item, "plan_id", context) == plan_id
                and hash_value(item, "candidate_id", context) == candidate_id,
                "LEGACY_ROW_IDENTITY_BINDING:" + context)
    bind_file(pp, result, "experimental_prediction_sha256", "result")
    input_sha = bind_file(ip, prediction, "source_input_sha256", "prediction")
    bind_file(op, result, "source_outcome_sha256", "result")
    bind_file(bp, result, "source_prediction_sha256", "result")
    bind_file(bp, original_outcome, "prediction_file_sha256", "source_outcome")
    require(hash_value(baseline, "input_receipt_sha256", "source_prediction") == input_sha,
            "LEGACY_INPUT_RECEIPT_BINDING")
    input_id = hash_value(original_input, "input_id", "source_input")
    require(E.digest(field(original_input, "state", "source_input")) == input_id
            and hash_value(prediction, "input_id", "prediction") == input_id
            and hash_value(baseline, "input_id", "source_prediction") == input_id,
            "LEGACY_INPUT_ID_BINDING")
    require(hash_value(baseline, "parent_id", "source_prediction") == seal["parent_candidate_id"],
            "LEGACY_PARENT_ID_BINDING")
    for context, item in (("source_prediction", baseline), ("source_outcome", original_outcome)):
        require(hash_value(item, "price_calibration_profile_id", context) == source["price_calibration_profile_id"]
                and hash_value(item, "parent_calibration_comparator_id", context) == source["parent_calibration_comparator"]["comparator_id"],
                "LEGACY_SOURCE_CALIBRATION_BINDING:" + context)
    mode = "PROSPECTIVE" if slot in old["fresh_slots"] else "BLIND_REPLAY"
    require(field(prediction, "mode", "prediction") == field(result, "mode", "result") == mode,
            "LEGACY_MODE_BINDING")
    anchor = E.integer(field(prediction, "anchor_ms", "prediction"), "anchor_ms", 1)
    require(all(E.integer(field(item, "anchor_ms", context), context + ".anchor_ms", 1) == anchor
                for context,item in (("result", result), ("source_prediction", baseline), ("source_outcome", original_outcome))),
            "LEGACY_ANCHOR_BINDING")
    require(E.integer(field(prediction, "target_ms", "prediction"), "target_ms", 1) == anchor + old["fixed_rule"]["horizon_ms"],
            "LEGACY_TARGET_BINDING")
    require(E.integer(field(baseline, "horizon_sec", "source_prediction"), "horizon_sec", 1) * 1000
            == old["fixed_rule"]["horizon_ms"], "LEGACY_SOURCE_HORIZON_BINDING")
    frozen = E.integer(field(prediction, "candidate_frozen_at_ms", "prediction"), "candidate_frozen_at_ms", 1)
    ready = E.integer(field(prediction, "calibration_ready_at_ms", "prediction"), "calibration_ready_at_ms", 1)
    finished = E.integer(field(prediction, "inference_finished_at_ms", "prediction"), "inference_finished_at_ms", 1)
    require(frozen == seal["created_at_ms"] and frozen <= ready <= finished,
            "LEGACY_PREDICTION_SEAL_BINDING")
    if mode == "PROSPECTIVE":
        require(frozen <= anchor and finished < prediction["target_ms"],
                "LEGACY_PROSPECTIVE_TIME_ORDER")
    require(hash_value(prediction, "comparison_scale_calibration_profile_id", "prediction") == profiles["comparison_scale_calibration"]["profile_id"],
            "LEGACY_CONTROL_CALIBRATION_BINDING")
    require(field(result, "status", "result") == field(original_outcome, "status", "source_outcome") == "OBSERVED",
            "LEGACY_OBSERVED_OUTCOME_REQUIRED")
    label = E.integer(field(original_outcome, "target_class", "source_outcome"), "source_outcome.target_class", 0, 6)
    require(E.integer(field(result, "target_class", "result"), "result.target_class", 0, 6) == label,
            "LEGACY_OUTCOME_LABEL_BINDING")
    probabilities = field(prediction, "probabilities", "prediction")
    verified = {}
    for key, raw_key, profile_name in (
            ("parent_cpu_refit_calibration", "parent_cpu_raw", "parent_calibration_cpu"),
            ("edit_calibrated", "edit_raw", "calibration")):
        field(probabilities, key, "prediction.probabilities")
        values = E.probabilities(probabilities, key, 7)
        expected = apply_calibration(profiles[profile_name], field(probabilities, raw_key, "prediction.probabilities"), key)
        require(max(abs(a-b) for a,b in zip(values, expected)) <= 1e-13,
                "LEGACY_CALIBRATION_APPLICATION:" + key)
        score = field(field(field(result, "scores", "result"), key, "result.scores"), "brier", "result.scores." + key)
        score = E.number(score, "result.scores." + key + ".brier", 0, 2)
        require(abs(E.brier(values, label) - score) <= 1e-13, "LEGACY_SCORE_REPLAY_MISMATCH:" + key)
        verified[key] = values
    row = {"unit_id":str(slot), "input_digest":input_sha, "created_at_ms":finished, "seed":0}
    evidence = {"slot":slot, "prediction_sha256":sha(pp), "result_sha256":sha(rp),
                "source_input_sha256":input_sha, "source_outcome_sha256":sha(op),
                "source_prediction_sha256":sha(bp), "original_mode":mode,
                "calibration_application_checked":True}
    return row, verified, label, evidence


def replay(bundle, output):
    bundle, output = Path(bundle), Path(output)
    seal, search, old, original, profiles = validate_headers(bundle)
    slots = old["all_slots"]
    dataset = E.digest({"scope":"legacy_replay","plan":old["plan_id"],"slots":slots})
    source = E.digest({"scope":"bound_original_outcomes","plan":old["source_plan_id"]})
    backend = E.digest({"device":"cpu","dtype":"float32","scope":"legacy_same_backend"})
    pc, cc = E.digest(seal["parent_calibration_cpu"]), E.digest(seal["calibration"])
    common = {"dataset_digest":dataset,"execution_profile_digest":backend}
    parent = dict(common,model_digest=seal["parent_candidate_id"],calibration_digest=pc,rows=[])
    candidate = dict(common,model_digest=seal["candidate_id"],calibration_digest=cc,rows=[])
    outcomes = {"dataset_digest":dataset,"source_digest":source,"rows":[]}
    evidence = []
    for i,slot in enumerate(slots):
        row, verified, label, row_evidence = validate_row(bundle, slot, seal, old, original, profiles)
        for document,key in ((parent,"parent_cpu_refit_calibration"),(candidate,"edit_calibrated")):
            document["rows"].append(dict(row,probabilities=verified[key]))
        outcomes["rows"].append({"unit_id":str(slot),"input_digest":row["input_digest"],
                                "cluster_id":str(i//5),"status":"observed","label":label})
        evidence.append(row_evidence)
    spec = {
        "mode":"retrospective","base_digest":seal["parent_candidate_id"],
        "candidate_digest":seal["candidate_id"],"execution_profile_digest":backend,
        "dataset_digest":dataset,"parent_calibration_digest":pc,"candidate_calibration_digest":cc,
        "outcome_source_digest":source,"outcomes_digest":E.digest(outcomes),
        "discovery_ids":[],"development_ids":[],"confirmation_ids":[str(s) for s in slots],
        "clusters":{str(s):str(i//5) for i,s in enumerate(slots)},
        "information_cutoff_ms":seal["created_at_ms"],
        "calibration_cutoff_ms":seal["calibration"]["training_cutoff_ms"],
        "classes":7,"minimum_samples":20,"minimum_clusters":8,"bootstrap_repetitions":999,
        "seed":20261103,"confidence":.95,"minimum_brier_gain":1e-6,"maximum_action_tv":.05,
        "require_action_outputs":False,
        "comparison_purpose":"known_result_replay_not_new_holdout",
        "legacy_seal_sha256":sha(bundle/"sealed_candidate.json"),
        "legacy_analysis_sha256":sha(bundle/"analysis.json"),
        "legacy_shadow_plan_sha256":sha(bundle/"shadow/plan.json"),
        "legacy_source_plan_sha256":sha(bundle/"reference/source_eval/plan.json"),
        "replay_validator_sha256":sha(__file__),
    }
    plan = E.freeze(spec)
    if (output/"plan.json").exists():
        previous = E.read_json(output/"plan.json")
        E.verify_plan(previous)
        strip = lambda x:{k:v for k,v in x.items() if k not in ("plan_digest","sealed_at_ms")}
        if E.digest(strip(previous)) != E.digest(strip(plan)):
            raise E.EvaluationError("REPLAY_PLAN_CONFLICT")
        plan = previous
    result = E.evaluate(plan,parent,candidate,outcomes)
    if result["verdict"] == "ResearchGainConfirmed" or search["eligible_candidates"]:
        raise E.EvaluationError("NEGATIVE_CONTROL_UNEXPECTEDLY_ELIGIBLE")
    summary = {
        "schema":"hepta.weight.laya-negative-replay.v1",
        "source_seal_sha256":sha(bundle/"sealed_candidate.json"),
        "source_search_sha256":sha(bundle/"analysis.json"),
        "candidate_count":len(search["candidates"]),
        "original_eligible_candidates":search["eligible_candidates"],
        "original_candidate_eligible":seal["eligible"],
        "evaluation_digest":result["evaluation_digest"],
        "parent_brier":result["parent_brier"],"candidate_brier":result["candidate_brier"],
        "paired_brier_gain":result["paired_brier_gain"],
        "verdict":result["verdict"],"reason":result["reason"],
        "new_model_forwards":0,"new_prospective_observations":0,
        "binding_verification":"plan-seal-search-source-row-calibration-v2",
        "original_mode_counts":{mode:sum(x["original_mode"] == mode for x in evidence)
                                for mode in ("BLIND_REPLAY", "PROSPECTIVE")},
        "activation_authorized":False,"evidence":evidence,
    }
    for name,value in (("plan",plan),("parent",parent),("candidate",candidate),
                       ("outcomes",outcomes),("evaluation",result),("replay_summary",summary)):
        E.publish(output/(name+".json"),value)
    return {k:v for k,v in summary.items() if k != "evidence"}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle",required=True)
    parser.add_argument("--out",required=True)
    args=parser.parse_args(argv)
    try:
        print(json.dumps(replay(args.bundle,args.out),indent=2))
        return 0
    except (E.EvaluationError, OSError, KeyError, TypeError, ValueError) as exc:
        print(json.dumps({"ok":False,"error":str(exc)}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())


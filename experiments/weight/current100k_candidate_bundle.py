#!/usr/bin/env python3
"""Seal existing Current100k heads and prepare a separate future registration.

Neither command loads an encoder, fits a head, invokes the registrar, activates a
collector, or changes an existing study. Hashes establish byte identity; the
existing HeptaTrader registrar and pre-open verifier retain source authority.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import math
from pathlib import Path
import re
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "workers" / "weight"))
from weight_runtime.artifacts import ArtifactStore, atomic_create, file_sha256
from weight_runtime.current100k import CONTRACT, HEAD_MAX_BYTES, validate_head
from weight_runtime.errors import WeightError, canonical, checksum, digest, integer, loads, need
from weight_runtime.patches import tensor_sha256


BASELINES = ("parent", "constant_mean", "constant_median", "bias_calibration",
             "ridge_delta_capped", "sgd_head_capped")
HEAD_NAMES = {"value.weight", "value.bias"}
MAX_JSON_BYTES = 32 * 1024 * 1024
REQUEST_SCHEMA = "hepta.weight.current100k.candidate-bundle-request.v1"
BUNDLE_SCHEMA = "hepta.weight.current100k.candidate-bundle.v1"
PREPARE_SCHEMA = "hepta.weight.current100k.prepare-registration.v1"
READY_SCHEMA = "hepta.weight.current100k.registration-ready.v1"
HEAD_PARITY_ABSOLUTE_USD = 0.001


def clock_ms():
    return time.time_ns() // 1000000


def _net_usd_float(value):
    """Match the source study's float(decimal-string) conversion, then FP32."""
    need(type(value) in (int, float, str), "INPUT_LINEAGE", "Expected a numeric or decimal-string USD label")
    if isinstance(value, str):
        need(re.fullmatch(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?", value) is not None,
             "INPUT_LINEAGE", "USD label is not a finite decimal representation")
    try:
        result = float(value)
    except (ValueError, OverflowError) as exc:
        raise WeightError("NONFINITE", "USD label cannot be represented as a finite float") from exc
    need(math.isfinite(result), "NONFINITE", "USD label must be finite before FP32 conversion")
    return result


def file_ref(path):
    path = Path(path).absolute()
    return {"path": str(path), "sha256": file_sha256(path)}


def read_bound(ref, limit=MAX_JSON_BYTES):
    need(isinstance(ref, dict) and {"path", "sha256"} <= set(ref),
         "INPUT_LINEAGE", "Expected a pinned path and SHA256")
    checksum(ref["sha256"])
    path = Path(ref["path"])
    need(path.is_absolute() and path.is_file() and not path.is_symlink(),
         "INVALID_PATH", "Expected an absolute existing non-symlink file", path=str(path))
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    need(len(data) <= limit, "INPUT_LIMIT", "Pinned input exceeds byte limit", path=str(path))
    need(hashlib.sha256(data).hexdigest() == ref["sha256"],
         "IDENTITY_MISMATCH", "Pinned input bytes changed", path=str(path))
    return data


def read_json(ref):
    return loads(read_bound(ref))


def _artifact(ref, root, tensors=False):
    """Read an existing worker artifact without creating or changing its store."""
    need(isinstance(ref, dict) and "artifact_id" in ref, "INPUT_LINEAGE", "Missing artifact identity")
    checksum(ref["artifact_id"])
    need(digest({k: v for k, v in ref.items() if k != "artifact_id"}) == ref["artifact_id"],
         "IDENTITY_MISMATCH", "Artifact descriptor digest differs")
    root = Path(root).resolve(strict=True)
    need(Path(ref["path"]).parent.resolve(strict=True) == root,
         "INVALID_PATH", "Artifact is outside its experiment's store")
    descriptor = root / (ref["artifact_id"] + ".ref.json")
    need(not descriptor.is_symlink() and loads(descriptor.read_bytes()) == ref,
         "IDENTITY_MISMATCH", "Retained artifact descriptor differs")
    data = read_bound(ref, HEAD_MAX_BYTES if tensors else MAX_JSON_BYTES)
    need(len(data) == ref["byte_length"], "IDENTITY_MISMATCH", "Artifact length differs")
    if tensors:
        from safetensors.torch import load
        return load(data)
    return loads(data)


def _fresh_output(root, protected):
    root = Path(root)
    need(root.is_absolute() and not root.exists() and not root.is_symlink(),
         "OUTPUT_EXISTS", "Use a new absolute output directory; incomplete output is never resumed")
    resolved = root.resolve()
    for source in protected:
        source = Path(source).resolve()
        need(resolved != source and not source.is_relative_to(resolved),
             "PATH_DENIED", "Output would contain an input or an existing study")
        if source.is_dir():
            need(not resolved.is_relative_to(source), "PATH_DENIED", "Output is inside a protected study")
    root.mkdir(parents=True, mode=0o700, exist_ok=False)
    return root


def _write(root, name, value):
    atomic_create(root / name, canonical(value) + b"\n")
    return file_ref(root / name)


def _head_metrics(state, parent):
    import torch
    delta = torch.cat([(state[k].double() - parent[k].double()).flatten() for k in sorted(parent)])
    return {"actual_head_delta_l2": float(delta.norm()),
            "changed_coordinates": sum(int((state[k] != parent[k]).sum()) for k in parent),
            "tensor_sha256": {k: tensor_sha256(v) for k, v in sorted(state.items())}}


def audit_costs(mechanism, baseline, baseline_plan, candidates, receipts):
    """Keep overlapping measurements separate; unknown costs never become zero."""
    def nonnegative(value, name):
        need(type(value) in (int, float) and math.isfinite(value) and value >= 0,
             "INVALID_COST", "Invalid nonnegative cost", field=name)
        return float(value)

    cost = mechanism["cost"]
    mechanism_wall = nonnegative(cost["wall_seconds"], "mechanism.wall_seconds")
    baseline_wall = nonnegative(baseline["total_seconds"], "baseline.total_seconds")
    unique, by_candidate = {}, {}
    for ref, receipt in receipts:
        key = ref["sha256"]
        if key in unique:
            need(unique[key] == receipt, "INVALID_COST", "Conflicting duplicate cost receipt")
            continue
        unique[key] = receipt
        name = receipt.get("candidate")
        need(receipt.get("schema") == "hepta.weight.baseline-cost.v1" and name in BASELINES
             and name not in by_candidate, "INVALID_COST", "Expected one cost receipt per baseline")
        for field in ("construction_seconds", "serialization_reload_scoring_seconds", "training_seconds"):
            nonnegative(receipt[field], name + "." + field)
        steps = integer(receipt["gradient_steps"], "gradient_steps")
        need(receipt["optimizer_calls"] == steps and receipt["encoder_forward_examples"] == 0,
             "INVALID_COST", "Baseline optimizer/encoder accounting differs")
        need(steps == next(c["gradient_steps"] for c in baseline["candidates"] if c["name"] == name),
             "INVALID_COST", "Gradient count differs from baseline result")
        by_candidate[name] = {"receipt": ref, **receipt}
    need(set(by_candidate) == set(BASELINES), "INVALID_COST", "Missing baseline cost receipt")
    cap = nonnegative(baseline_plan["max_head_delta_l2"], "max_head_delta_l2")
    norm_groups = [{"arm": c["arm"], "actual_head_delta_l2": c["actual_head_delta_l2"],
                    "declared_absolute_delta_cap": cap if c.get("norm_cap_applies") else None,
                    "scope": c["constraint_scope"]} for c in candidates]
    bounded = [c for c in candidates if c["origin"] == "mechanism" and c["role"] == "dose" and c["dose"] == 1]
    full_norm = bounded[0]["actual_head_delta_l2"] if len(bounded) == 1 else None
    return {"schema": "hepta.weight.current100k.cost-fairness.v1",
            "mechanism": {"reported_cost": copy.deepcopy(cost), "wall_seconds_after_open": mechanism_wall,
                          "load_seconds": mechanism.get("load_seconds"),
                          "gradient_steps": mechanism["gradient_steps"], "optimizer_calls": mechanism["optimizer_calls"]},
            "baselines": {"whole_comparison_seconds": baseline_wall, "examples": baseline["examples"],
                          "per_candidate_receipts": by_candidate, "unique_cost_receipts": len(unique)},
            "timings_are_not_additive": True,
            "overlap_rules": ["Model/worker time is contained in experiment wall time.",
                              "SGD training time is contained in its construction time.",
                              "Per-head times are contained in the complete baseline comparison."],
            "shared_historical_encoding_seconds": None, "astra_diagnosis_seconds": None,
            "astra_tokens": None, "end_to_end_total_seconds": None,
            "missing_costs_are_zero": False, "speedup_established": False,
            "constraints": norm_groups, "full_mechanism_delta_l2": full_norm,
            "baseline_absolute_delta_cap": cap,
            "full_mechanism_within_baseline_cap": full_norm <= cap + 1e-7 if full_norm is not None else None,
            "same_constraint_comparison_established": False,
            "development_scores_transform": "raw USD; no clipping",
            "prospective_transform": "100 * FP32 Linear, then clip each USD value to [-15,15]",
            "prospective_outcomes_observed": False,
            "future_encoding_scope": "One encoding per side shared among this new family only; cross-plan reuse is unverified.",
            "inference": "Different data scopes, constraints and missing preparation costs prevent an equal-budget or end-to-end speed claim."}


def qualify_cpu_heads(features, candidates, feature_ref):
    """Measure the collector's two-row shared-head arithmetic after dtype reload.

    These are retained CPU development features. This does not rerun or claim
    new HIP encoder forwards, and does not extrapolate a feature-error bound.
    """
    import torch
    from safetensors.torch import load
    started = time.monotonic()
    candidates = sorted(candidates, key=lambda c: c["arm"])
    states = [validate_head(load(read_bound(c["head"], HEAD_MAX_BYTES))) for c in candidates]
    weights = torch.cat([s["value.weight"] for s in states]).contiguous()
    biases = torch.cat([s["value.bias"] for s in states]).contiguous()
    maximum = {c["arm"]: 0. for c in candidates}
    clipped_maximum = dict(maximum)
    forward_calls = 0
    with torch.inference_mode():
        for start in range(0, len(features), 2):
            batch = features[start:start + 2]
            # Collector converts FP32 scaled outputs to Python floats before
            # USD100 conversion. Double here has those same scalar semantics.
            shared = torch.nn.functional.linear(batch, weights, biases).double() * 100.
            forward_calls += 1
            need(bool(torch.isfinite(shared).all()), "NONFINITE", "Shared-head USD outputs overflowed")
            for i, (candidate, state) in enumerate(zip(candidates, states)):
                single = torch.nn.functional.linear(batch, state["value.weight"], state["value.bias"]).double().flatten() * 100.
                forward_calls += 1
                need(bool(torch.isfinite(single).all()), "NONFINITE", "Single-head USD outputs overflowed")
                arm = candidate["arm"]
                maximum[arm] = max(maximum[arm], float((shared[:, i] - single).abs().max()))
                clipped_maximum[arm] = max(clipped_maximum[arm], float((shared[:, i].clamp(-15., 15.) - single.clamp(-15., 15.)).abs().max()))
    return {"schema": "hepta.weight.current100k.cpu-head-qualification.v1",
            "feature_artifact": feature_ref, "examples": len(features), "candidate_count": len(candidates),
            "heads": {c["arm"]: c["head"]["sha256"] for c in candidates},
            "ensemble_arm_order": [c["arm"] for c in candidates],
            "batch_rows": 2, "fixed_absolute_tolerance_usd": HEAD_PARITY_ABSOLUTE_USD,
            "maximum_raw_usd_difference": maximum, "maximum_clipped_usd_difference": clipped_maximum,
            "passed": all(v <= HEAD_PARITY_ABSOLUTE_USD for v in maximum.values()),
            "linear_forward_calls": forward_calls, "encoder_forward_examples": 0,
            "gradient_steps": 0, "optimizer_calls": 0, "wall_seconds": time.monotonic() - started,
            "torch_version": torch.__version__, "cpu_threads": torch.get_num_threads(),
            "scope": "New saved FP32 heads: two-row shared Linear versus separate Linear on frozen CPU development features",
            "new_family_end_to_end_hip_forward_verified": False,
            "future_inputs_or_preopen_timeliness_verified": False}


def reused_encoder_qualification(qualification, bundle, config):
    """Check the actual historical evidence, without promoting its scope."""
    if qualification is None:
        return {"verified": False, "status": "NOT_SUPPLIED"}
    try:
        need(qualification.get("schema") == "heptatrader.weight-shadow-backend-qualification.v1"
             and qualification.get("scope") == "HISTORICAL_REPLAY_ONLY_NOT_FUTURE_PREOPEN_PROOF",
             "UNQUALIFIED_BACKEND", "Expected explicit historical backend qualification")
        for key in ("backend", "encoder_threads", "encoder_batch_size", "head_execution_backend", "hip_runtime_manifest_sha256"):
            need(qualification.get(key) == config.get("encoder_backend" if key == "backend" else key),
                 "UNQUALIFIED_BACKEND", "Qualification targets another execution profile", field=key)
        ref = {"path": qualification["evidence_path"], "sha256": qualification["evidence_sha256"]}
        evidence = read_json(ref)
        need(evidence.get("schema") == "heptatrader.current100k-hip-parity-benchmark.v1"
             and evidence.get("scope") == "KNOWN_DEVELOPMENT_REQUESTS_NOT_PROSPECTIVE",
             "UNQUALIFIED_BACKEND", "Expected the actual historical parity benchmark")
        request = read_json(bundle["request"])
        need(evidence.get("feature_cache_sha256") == request["features"]["sha256"]
             and evidence.get("actual_loader_sha256") == bundle["encoder_identity"]["loader_sha256"],
             "UNQUALIFIED_BACKEND", "Historical encoder loader or frozen feature cache differs")
        for key in ("backend", "encoder_threads", "encoder_batch_size", "hip_runtime_manifest_sha256"):
            need(evidence.get(key) == qualification[key], "UNQUALIFIED_BACKEND", "Benchmark profile differs", field=key)
        need(evidence.get("heads_backend") == config.get("head_execution_backend", "TORCH_CPU_FP32")
             and qualification.get("tensor_cleanup_verified") is True
             and evidence.get("cleanup_verified") is True and evidence.get("allocation_after_close_bytes") == 0
             and evidence.get("cleanup_receipt", {}).get("all_model_allocations_released") is True,
             "UNQUALIFIED_BACKEND", "Historical head device or cleanup evidence differs")
        samples, limits = evidence["samples"], evidence["parity_limits"]
        need(isinstance(samples, list) and 1 <= len(samples) <= 64
             and len({s["row_index"] for s in samples}) == len(samples),
             "UNQUALIFIED_BACKEND", "Historical parity sample identities are incomplete")
        feature_limit, head_limit = limits["feature_max_abs"], limits["all_heads_max_abs_usd"]
        for value in (feature_limit, head_limit, qualification["max_request_seconds"], qualification["deadline_budget_seconds"]):
            need(type(value) in (int, float) and math.isfinite(value) and value > 0,
                 "UNQUALIFIED_BACKEND", "Invalid historical qualification limit")
        for sample in samples:
            integer(sample["row_index"], "row_index", 0, bundle["development_examples"] - 1)
            values = [sample["max_feature_abs_error"], sample["total_encode_and_heads_seconds"]]
            values += list(sample["head_max_abs_usd_errors"].values())
            need(values and all(type(v) in (int, float) and math.isfinite(v) and v >= 0 for v in values)
                 and bool(sample["head_max_abs_usd_errors"]) and sample.get("parity_passed") is True
                 and sample["backend"] == config["encoder_backend"]
                 and sample["max_feature_abs_error"] <= feature_limit
                 and all(v <= head_limit for v in sample["head_max_abs_usd_errors"].values()),
                 "UNQUALIFIED_BACKEND", "A historical same-input sample did not satisfy its fixed limits")
        observed_max = max(s["total_encode_and_heads_seconds"] for s in samples)
        need(math.isclose(observed_max, qualification["max_request_seconds"], rel_tol=1e-9, abs_tol=1e-9)
             and observed_max <= qualification["deadline_budget_seconds"],
             "UNQUALIFIED_BACKEND", "Historical timing receipt differs")
        return {"verified": True, "status": "VERIFIED_HISTORICAL_ENCODER_SAMPLE_ONLY", "evidence": ref,
                "sample_indices": [s["row_index"] for s in samples],
                "maximum_observed_feature_abs_error": max(s["max_feature_abs_error"] for s in samples),
                "fixed_feature_abs_limit": feature_limit, "loader_sha256": evidence["actual_loader_sha256"],
                "reference_feature_sha256": evidence["feature_cache_sha256"],
                "old_candidate_bundle_sha256": evidence["candidate_bundle_sha256"],
                "old_head_results_count_as_new_family_results": False,
                "sample_maximum_is_global_input_bound": False, "future_preopen_proof": False,
                "resource_admission_granted": False}
    except (WeightError, KeyError, TypeError, ValueError, OSError) as exc:
        return {"verified": False, "status": "PENDING_EVIDENCE_VERIFICATION",
                "reason": exc.as_dict() if isinstance(exc, WeightError) else {"message": str(exc)}}


def build_bundle(request, output_root):
    import torch
    from safetensors.torch import load
    from current100k_baselines import validate_plan as validate_baseline_plan
    from weight_runtime.mechanism import ExperimentPlan

    started = time.monotonic()
    fields = {"schema", "parent_head", "features", "labels", "development_dataset",
              "ordered_development_row_ids", "mechanism_summary", "mechanism_plan",
              "mechanism_receipts", "baseline_report", "baseline_plan", "prior_plans",
              "information_cutoff_ms"}
    need(isinstance(request, dict) and set(request) == fields and request["schema"] == REQUEST_SCHEMA,
         "INVALID_REQUEST", "Exact candidate-bundle request fields required")
    now = clock_ms()
    cutoff = integer(request["information_cutoff_ms"], "information_cutoff_ms")
    need(cutoff <= now, "CAUSALITY", "Information cutoff cannot be in the future")
    need(isinstance(request["prior_plans"], list) and 1 <= len(request["prior_plans"]) <= 16,
         "INPUT_LINEAGE", "Pin the prior plans that this new bundle must not amend")
    source_refs = {k: v for k, v in request.items() if isinstance(v, dict) and "path" in v}
    protected = [ref["path"] for ref in source_refs.values()] + [str(Path(ref["path"]).parent) for ref in request["prior_plans"]]
    prior_plans = []
    for ref in request["prior_plans"]:
        old = read_json(ref)
        need(old.get("schema") == "heptatrader.current100k-weight-shadow-plan.v1"
             and old.get("plan_id") == digest({k: v for k, v in old.items() if k != "plan_id"}),
             "INPUT_LINEAGE", "Prior plan identity is invalid")
        prior_plans.append({"source": ref, "plan_id": old["plan_id"],
                            "producer_manifest_sha256": old["producer_registration"]["sha256"]})
    parent = validate_head(load(read_bound(request["parent_head"], HEAD_MAX_BYTES)))
    parent_hashes = {k: tensor_sha256(v) for k, v in parent.items()}
    f, y = load(read_bound(request["features"])), load(read_bound(request["labels"]))
    need(set(f) == {"features"} and set(y) == {"labels_usd"}, "INPUT_LINEAGE", "Expected named frozen features/labels")
    x, labels = f["features"], y["labels_usd"]
    data, report, spec, baseline, baseline_plan = [read_json(request[k]) for k in
        ("development_dataset", "mechanism_summary", "mechanism_plan", "baseline_report", "baseline_plan")]
    validate_baseline_plan(baseline_plan)
    parsed = ExperimentPlan.parse(spec)
    rows = data["rows"]
    need(isinstance(rows, list) and 2 <= len(rows) <= 4096, "INPUT_LINEAGE", "Expected bounded development rows")
    ordered = [r["row_id"] for r in rows]
    need(request["ordered_development_row_ids"] == ordered and len(set(ordered)) == len(ordered),
         "INPUT_LINEAGE", "Declared feature order must match the complete development dataset")
    for row in rows:
        for key in ("input_id", "reward_id", "row_id"):
            checksum(row[key], key)
    need(x.dtype == labels.dtype == torch.float32 and tuple(x.shape) == (len(rows), 768)
         and tuple(labels.shape) == (len(rows),) and bool(torch.isfinite(x).all())
         and bool(torch.isfinite(labels).all()) and bool(torch.allclose(x.norm(dim=-1), torch.ones(len(rows)), atol=1e-5, rtol=1e-5)),
         "INPUT_LINEAGE", "Frozen feature/label shape, dtype, values or normalization differs")
    expected_labels = torch.tensor([_net_usd_float(r["net_usd"]) for r in rows], dtype=torch.float32)
    need(bool(torch.isfinite(expected_labels).all()), "NONFINITE", "Development USD labels overflowed FP32")
    need(torch.equal(labels, expected_labels), "INPUT_LINEAGE", "Labels do not match the declared development row order")
    need(cutoff >= max(baseline_plan["information_cutoff_ms"], data.get("observed_at_ms", 0),
                       max(r["input_started_at_ms"] for r in rows)),
         "CAUSALITY", "Frozen information cutoff precedes known development information")
    need(report.get("schema") == "hepta.weight.mechanism-experiment.v1"
         and report.get("status") == "COMPLETED_DEVELOPMENT_SCREEN"
         and report.get("plan_sha256") == digest(spec) and report.get("model_id") == parsed.model_id
         and report.get("backend_id") == parsed.backend_id and report.get("data_role") == "development"
         and report.get("production_eligible") is False and report.get("new_unseen_or_prospective_data") is False,
         "INPUT_LINEAGE", "Expected the completed pinned development mechanism screen")
    need(report.get("parent_restoration", {}).get("passed") is True,
         "PARENT_RESTORATION_FAILED", "Parent restoration was not established")
    need(len(report["candidates"]) == parsed.candidate_count
         and len({c["name"] for c in report["candidates"]}) == parsed.candidate_count,
         "INPUT_LINEAGE", "Mechanism candidate count or names differ")
    manifest = report["condition_manifest"]
    need(report["condition_manifest_sha256"] == digest(manifest)
         and len(manifest) == parsed.candidate_count
         and all(c["condition_manifest_sha256"] == digest(manifest)
                 and all(c[k] == m[k] for k in ("name", "role", "dose"))
                 for c, m in zip(report["candidates"], manifest)),
         "INPUT_LINEAGE", "Mechanism candidate inventory differs from its frozen condition manifest")
    need(baseline.get("schema") == "hepta.weight.current100k.baselines.v1"
         and baseline.get("plan_sha256") == digest(baseline_plan)
         and baseline.get("partition") == "development" and baseline.get("prospective_evidence") is False
         and baseline.get("production_eligible") is False and baseline["examples"] == len(rows)
         and baseline.get("prediction_transform") == "identity; no clipping",
         "INPUT_LINEAGE", "Expected the pinned development baseline comparison")
    need(tuple(c["name"] for c in baseline["candidates"]) == BASELINES,
         "INPUT_LINEAGE", "Retain all six declared baselines in their original order")
    need(baseline["input_lineage"] == {k + "_artifact_sha256": request[v]["sha256"]
         for k, v in (("head", "parent_head"), ("feature", "features"), ("label", "labels"))}
         and baseline["feature_tensor_sha256"] == tensor_sha256(x)
         and baseline["label_tensor_sha256"] == tensor_sha256(labels),
         "INPUT_LINEAGE", "Baseline source artifacts/tensors differ")
    receipts = read_json(request["mechanism_receipts"])
    opens = [r["response"]["result"] for r in receipts if r.get("request", {}).get("op") == "open"
             and r.get("response", {}).get("ok") is True]
    need(len(opens) == 1, "INPUT_LINEAGE", "One original successful open receipt is required")
    opened = opens[0]
    identity = opened["model"]["identity"]
    need(opened["model_id"] == report["model_id"] and opened["backend_id"] == report["backend_id"]
         and identity.get("provider") == "current100k_value" and identity.get("head_sha256") == request["parent_head"]["sha256"]
         and identity.get("task_contract") == CONTRACT and digest(identity) == opened["model_id"],
         "INPUT_LINEAGE", "Mechanism encoder/head/task identity differs")
    checksum(identity["base_id"], "base_id")
    row_by_id = {r["row_id"]: r for r in rows}
    for case in spec["cases"]:
        need(set(case["inputs"]) == {"rows"}, "INPUT_LINEAGE", "Bundle requires explicit frozen input-only mechanism rows")
        for row in case["inputs"]["rows"]:
            source = row_by_id.get(row["row_id"])
            need(source is not None and all(source.get(k) == row[k] for k in
                 ("input_id", "request_id", "action", "input_started_at_ms", "feature_text", "feature_text_sha256")),
                 "INPUT_LINEAGE", "Mechanism case is absent from the complete development exclusions")

    # Validate and materialize all candidates in memory before creating output.
    retained, cost_receipts = [], []
    baseline_root = Path(request["baseline_report"]["path"]).parent / "artifacts"
    for candidate in baseline["candidates"]:
        state = validate_head(_artifact(candidate["head"], baseline_root, tensors=True))
        if candidate["name"] == "parent":
            need({k: tensor_sha256(v) for k, v in state.items()} == parent_hashes,
                 "INPUT_LINEAGE", "Frozen baseline parent differs")
        cost_receipts.append((candidate["cost"], _artifact(candidate["cost"], baseline_root)))
        retained.append(({"arm": "baseline_" + candidate["name"], "origin": "baseline",
                          "source_name": candidate["name"], "construction_kind": candidate["construction_kind"],
                          "source_head": candidate["head"], "source_report": request["baseline_report"],
                          "norm_cap_applies": candidate["norm_cap_applies"],
                          "constraint_scope": "joint weight+bias absolute cap" if candidate["norm_cap_applies"] else "uncapped diagnostic or frozen parent",
                          "labels_used_in_construction": candidate["labels_used_in_construction"],
                          "gradient_steps": candidate["gradient_steps"]}, state))
    mechanism_root = Path(request["mechanism_summary"]["path"]).parent / "artifacts"
    for candidate in report["candidates"]:
        patch = candidate["patch"]
        record = _artifact(patch["patch"], mechanism_root)
        replacements = _artifact(patch["parameters"], mechanism_root, tensors=True)
        need(record.get("schema") == "hepta.weight.patch.v1" and record["model_id"] == report["model_id"]
             and record["backend_id"] == report["backend_id"] and record["parameters"] == patch["parameters"]
             and set(replacements) and set(replacements) <= HEAD_NAMES
             and set(record["parent_parameter_hashes"]) == set(replacements),
             "PATCH_SCOPE", "Only existing head-only patches of this exact parent can be bundled")
        need(record.get("active_weights_overwritten") is False and record.get("production_eligible") is False
             and record.get("gradient_steps") == record.get("optimizer_calls") == 0,
             "PATCH_SCOPE", "Unexpected patch construction authority")
        need(record["created_at_ms"] <= cutoff, "CAUSALITY", "Patch was constructed after the information cutoff")
        state = {k: v.clone() for k, v in parent.items()}
        measurements = {m["parameter"]: m for m in record["storage_measurements"]}
        need(set(measurements) == set(replacements), "INPUT_LINEAGE", "Patch storage measurements are incomplete")
        for key, tensor in replacements.items():
            need(record["parent_parameter_hashes"][key] == parent_hashes[key]
                 and measurements[key]["parent_parameter_sha256"] == parent_hashes[key]
                 and measurements[key]["final_parameter_sha256"] == tensor_sha256(tensor),
                 "IDENTITY_MISMATCH", "Patch parent or realized storage hash differs")
            state[key] = tensor
        validate_head(state)
        retained.append(({"arm": "mechanism_" + candidate["name"].replace(".", "p"), "origin": "mechanism",
                          "source_name": candidate["name"], "role": candidate["role"], "dose": candidate["dose"],
                          "construction_kind": "DirectWeightEdit", "source_patch": patch["patch"],
                          "source_parameters": patch["parameters"], "source_report": request["mechanism_summary"],
                          "norm_cap_applies": False, "constraint_scope": "mechanism plan target-relative bound; not baseline joint cap",
                          "control_evidence_as_recorded": copy.deepcopy(candidate.get("random_control")),
                          "newer_control_qualification_inferred": False, "gradient_steps": 0}, state))
    names = [meta["arm"] for meta, _ in retained]
    need(2 <= len(names) <= 16 and len(set(names)) == len(names)
         and all(re.fullmatch(r"[A-Za-z0-9_-]{1,160}", name) for name in names),
         "INPUT_LINEAGE", "Generated head arms are invalid, ambiguous or exceed collector capacity")
    for meta, state in retained:
        meta.update(_head_metrics(state, parent))
    fairness = audit_costs(report, baseline, baseline_plan, [m for m, _ in retained], cost_receipts)
    root = _fresh_output(output_root, protected)
    store = ArtifactStore(root / "heads")
    candidates = []
    for meta, state in retained:
        ref = store.put_tensors(state, "current100k-frozen-candidate-head", {"arm": meta["arm"]})
        reloaded = store.load_tensors(ref["artifact_id"])
        need({k: tensor_sha256(v) for k, v in reloaded.items()} == meta["tensor_sha256"],
             "RELOAD_MISMATCH", "Full FP32 head changed during bundle serialization")
        candidates.append({**meta, "head": ref, "production_eligible": False})
    # Recheck original pinned inputs after preparation; no source bytes may move.
    for ref in list(source_refs.values()) + request["prior_plans"]:
        read_bound(ref)
    request_ref = _write(root, "request.json", request)
    costs_ref = _write(root, "cost-fairness.json", fairness)
    head_qualification = _write(root, "cpu-head-qualification.json", qualify_cpu_heads(x, candidates, request["features"]))
    bundle = {"schema": BUNDLE_SCHEMA, "status": "FROZEN_UNREGISTERED_RESEARCH_FAMILY",
              "created_at_ms": clock_ms(), "information_cutoff_ms": cutoff, "request": request_ref,
              "information_cutoff_basis": "caller declaration; prospective registration conservatively uses actual bundle creation time",
              "parent_head": request["parent_head"], "parent_tensor_sha256": parent_hashes,
              "encoder_identity": identity, "task_contract": CONTRACT,
              "development_dataset": request["development_dataset"], "development_examples": len(rows),
              "development_row_order": ordered, "feature_order_basis": "caller declaration; label order and selected mechanism source rows checked",
              "source_authenticity": "byte and parent-lineage verification; authoritative market/source replay remains the registrar's responsibility",
              "prior_plans": prior_plans, "candidates": candidates, "parent_arm": "baseline_parent",
              "cost_fairness": costs_ref, "cpu_head_qualification": head_qualification,
              "preparation_wall_seconds": time.monotonic() - started,
              "preparation_cost_scope": "This build function after Python/PyTorch import; includes verification, copy/reload and head-only qualification",
              "all_source_candidates_retained": True,
              "duplicate_heads_retained": True, "automatic_selection": False, "trade_authority": False,
              "actor_update": False, "production_eligible": False, "registration_performed": False,
              "prospective_evidence": False, "encoder_loaded": False, "new_training_steps": 0,
              "source_candidate_order": "six baseline report entries, then every mechanism summary entry; no score ranking"}
    _write(root, "bundle.json", bundle)
    return bundle


def _verify_bundle(ref):
    bundle = read_json(ref)
    need(bundle.get("schema") == BUNDLE_SCHEMA and bundle.get("status") == "FROZEN_UNREGISTERED_RESEARCH_FAMILY"
         and bundle.get("all_source_candidates_retained") is True
         and all(bundle.get(k) is False for k in ("automatic_selection", "trade_authority", "actor_update", "registration_performed")),
         "INPUT_LINEAGE", "Expected an immutable unregistered research family")
    request = read_json(bundle["request"])
    for item in request.values():
        if isinstance(item, dict) and "path" in item:
            read_bound(item)
    for previous in bundle["prior_plans"]:
        need(read_json(previous["source"])["plan_id"] == previous["plan_id"],
             "IDENTITY_MISMATCH", "Prior plan changed")
    heads = bundle["candidates"]
    need(2 <= len(heads) <= 16 and len({h["arm"] for h in heads}) == len(heads),
         "INPUT_LINEAGE", "Bundle candidate inventory differs")
    baseline = read_json(request["baseline_report"])
    mechanism = read_json(request["mechanism_summary"])
    expected = [("baseline", c["name"]) for c in baseline["candidates"]]
    expected += [("mechanism", c["name"]) for c in mechanism["candidates"]]
    need([(c["origin"], c["source_name"]) for c in heads] == expected,
         "INPUT_LINEAGE", "Every original candidate must remain in the prepared family")
    for candidate in heads:
        read_bound(candidate["head"], HEAD_MAX_BYTES)
    read_json(bundle["cost_fairness"])
    qualification = read_json(bundle["cpu_head_qualification"])
    need(qualification.get("heads") == {c["arm"]: c["head"]["sha256"] for c in heads},
         "INPUT_LINEAGE", "Head-only qualification belongs to another candidate family")
    return bundle


def prepare_registration(request, output_root):
    """Generate only inputs for the existing registrar; no dates are backfilled."""
    fields = {"schema", "bundle", "registration_template", "producer_manifest",
              "collector_implementation", "new_study_root"}
    need(isinstance(request, dict) and fields <= set(request) <= fields | {"backend_qualification"}
         and request["schema"] == PREPARE_SCHEMA,
         "INVALID_REQUEST", "Exact registration preparation fields required")
    bundle = _verify_bundle(request["bundle"])
    config = read_json(request["registration_template"])
    read_bound(request["producer_manifest"])
    read_bound(request["collector_implementation"])
    need(config.get("schema") == "heptatrader.current100k-weight-shadow-config.v1"
         and all(config.get(k) is False for k in ("trade_authority", "automatic_selection", "actor_update"))
         and not ({"plan_id", "registered_at_ms", "input_start_ms", "input_end_ms", "outcome_end_ms"} & set(config)),
         "INVALID_REGISTRATION", "Use a no-effect config template, never an existing plan or backdated window")
    new_root = Path(request["new_study_root"])
    need(new_root.is_absolute() and not new_root.exists() and not new_root.is_symlink(),
         "OUTPUT_EXISTS", "New study root must not already exist")
    old_roots = [Path(p["source"]["path"]).parent.resolve() for p in bundle["prior_plans"]]
    need(all(new_root.resolve() != old and not new_root.resolve().is_relative_to(old) for old in old_roots),
         "PATH_DENIED", "New registration must be outside every previous study")
    dataset = read_json(bundle["development_dataset"])
    rows = dataset["rows"]
    need(config["base_id"] == bundle["encoder_identity"]["base_id"]
         and config["training_dataset_path"] == bundle["development_dataset"]["path"]
         and config["training_dataset_sha256"] == bundle["development_dataset"]["sha256"]
         and config["training_producer_manifest_sha256"] == dataset["producer_manifest_sha256"],
         "INPUT_LINEAGE", "Registration encoder/development source differs from the frozen bundle")
    for field, key in (("training_input_ids", "input_id"), ("training_reward_ids", "reward_id"), ("training_row_ids", "row_id")):
        need(len(config[field]) == len(set(config[field])) and set(config[field]) == {r[key] for r in rows},
             "INPUT_LINEAGE", "Registration must exclude the complete development population", field=field)
    need(config["training_mean_usd"] == sum(float(r["net_usd"]) for r in rows) / len(rows),
         "INPUT_LINEAGE", "Frozen development mean differs")
    need(config["producer_registration"]["sha256"] == request["producer_manifest"]["sha256"],
         "INPUT_LINEAGE", "Future producer registration does not bind the supplied manifest")
    reward_ref = {"path": config["reward_config_path"], "sha256": config["reward_config_sha256"]}
    reward = read_json(reward_ref)
    need(reward["period_sha256"] == config["period_sha256"], "INPUT_LINEAGE", "Reward/source period differs")
    period_ref = {"path": reward["period_path"], "sha256": config["period_sha256"]}
    read_bound(period_ref)
    backend = config["encoder_backend"].upper()
    cpu = backend == "CPU_FP32" or backend.startswith("LAYA_CPU_FP32_")
    hip = backend == "HIP_FP32" or backend.startswith("LAYA_HIP_FP32_")
    need((cpu or hip) and config["encoder_batch_size"] in (1, 2)
         and config.get("head_execution_backend", "TORCH_CPU_FP32") == "TORCH_CPU_FP32",
         "INVALID_REGISTRATION", "Expected a collector-supported FP32 encoder and CPU FP32 heads")
    integer(config["encoder_threads"], "encoder_threads", 1, 64)
    if hip:
        checksum(config.get("hip_runtime_manifest_sha256"), "hip_runtime_manifest_sha256")
    else:
        need(config.get("hip_runtime_manifest_sha256") is None,
             "INVALID_REGISTRATION", "CPU execution cannot claim a HIP runtime manifest")
    qualification = read_json(request["backend_qualification"]) if "backend_qualification" in request else None
    # Earlier label cutoffs do not backdate newly sealed baseline heads whose
    # old report has no independently verified construction wall clock.
    cutoff = bundle["created_at_ms"]
    need(max(config["training_cutoff_ms"], config["labels_observed_at_ms"], dataset.get("observed_at_ms", 0)) <= cutoff
         <= bundle["created_at_ms"] <= clock_ms(), "CAUSALITY", "Source information changed after candidate sealing")
    config = copy.deepcopy(config)
    config["training_cutoff_ms"] = config["labels_observed_at_ms"] = cutoff
    config["parent_arm"] = bundle["parent_arm"]
    protected = [request[k]["path"] for k in ("bundle", "registration_template", "producer_manifest", "collector_implementation")]
    protected += [reward_ref["path"], period_ref["path"]] + [str(p) for p in old_roots] + [str(new_root)]
    if "backend_qualification" in request:
        protected.append(request["backend_qualification"]["path"])
    need(not Path(output_root).resolve().is_relative_to(new_root.resolve()),
         "PATH_DENIED", "Preparation output cannot create any part of the future study root")
    root = _fresh_output(output_root, protected)
    reused = reused_encoder_qualification(qualification, bundle, config)
    head_qualification = read_json(bundle["cpu_head_qualification"])
    scope_is_new = config["producer_registration"]["sha256"] not in {
        p["producer_manifest_sha256"] for p in bundle["prior_plans"]}
    proof = {"schema": "hepta.weight.current100k.registration-sourceproof.v1",
             "bundle": request["bundle"], "template": request["registration_template"],
             "producer_manifest": request["producer_manifest"], "reward_config": reward_ref,
             "period": period_ref, "collector_implementation": request["collector_implementation"],
             "development_dataset": bundle["development_dataset"], "development_row_ids": bundle["development_row_order"],
             "prior_plans": bundle["prior_plans"], "new_study_root": str(new_root),
             "candidate_count": len(bundle["candidates"]), "prepared_at_ms": clock_ms(),
             "fresh_window_required": True, "prior_window_modified": False,
             "future_producer_differs_from_prior_plans": scope_is_new,
             "same_producer_scope_limits_formal_adoption": not scope_is_new,
             "local_hash_lineage_verified": True, "authoritative_source_validation_pending": True,
             "source_semantics_verifier": "existing current100k_weight_shadow.freeze and historical_training.current100k.validate_config",
             "target_numeric_profile": {k: config.get(k) for k in ("encoder_backend", "encoder_threads", "encoder_batch_size", "head_execution_backend", "hip_runtime_manifest_sha256")},
             "backend_qualification": request.get("backend_qualification"),
             "backend_qualification_document_present": qualification is not None,
             "backend_qualification_verified": reused["verified"],
             "reused_encoder_qualification": reused,
             "new_family_cpu_head_qualification": bundle["cpu_head_qualification"],
             "new_family_cpu_head_qualification_passed": head_qualification["passed"],
             "new_family_end_to_end_hip_forward_verified": False,
             "backend_qualification_status": "Historical encoder samples and current saved CPU head arithmetic are separate evidence; future timeliness and new end-to-end HIP forwards are not established.",
             "preopen_success_and_completeness_pending": True,
             "new_family_shared_encoding": True, "cross_plan_shared_encoding_verified": False,
             "existing_collector_can_accept_new_heads_in_place": False,
             "encoder_load_or_service_activation_performed": False,
             "registered_at_ms": None, "input_start_ms": None, "input_end_ms": None,
             "trade_authority": False, "automatic_selection": False, "actor_update": False}
    proof_ref = _write(root, "sourceproof.json", proof)
    config["heads"] = {c["arm"]: {"path": c["head"]["path"], "sha256": c["head"]["sha256"],
                        "construction_kind": c["construction_kind"],
                        "workbench_lineage": {"bundle_sha256": request["bundle"]["sha256"],
                                              "sourceproof_sha256": proof_ref["sha256"],
                                              "source_name": c["source_name"], "origin": c["origin"]}}
                       for c in bundle["candidates"]}
    config_ref = _write(root, "registration-config.json", config)
    ready = {"schema": READY_SCHEMA, "status": "PREPARED_NOT_REGISTERED", "config": config_ref,
             "sourceproof": proof_ref, "bundle": request["bundle"], "new_study_root": str(new_root),
             "candidate_count": len(config["heads"]), "registration_performed": False,
             "automatic_selection": False, "trade_authority": False, "actor_update": False,
             "source_authority_pending": True, "collector_activation_pending": True,
             "resource_admission_pending": True,
             "numerical_backend_qualification_pending": not (reused["verified"] and head_qualification["passed"]),
             "prospective_evidence": False,
             "register_entry_point": "python -m laya_cell.current100k_weight_shadow_eval --register CONFIG --root NEW_STUDY_ROOT"}
    _write(root, "ready.json", ready)
    return ready


def verify_ready(ref):
    """Read-only preflight immediately before the owner invokes the registrar."""
    ready = read_json(ref)
    need(ready.get("schema") == READY_SCHEMA and ready.get("status") == "PREPARED_NOT_REGISTERED"
         and ready.get("registration_performed") is False, "INVALID_REGISTRATION", "Not a prepared registration")
    bundle = _verify_bundle(ready["bundle"])
    proof, config = read_json(ready["sourceproof"]), read_json(ready["config"])
    need(config.get("schema") == "heptatrader.current100k-weight-shadow-config.v1"
         and all(config.get(k) is False for k in ("trade_authority", "automatic_selection", "actor_update"))
         and not ({"plan_id", "registered_at_ms", "input_start_ms", "input_end_ms", "outcome_end_ms"} & set(config)),
         "INVALID_REGISTRATION", "Prepared configuration acquired a plan identity or effect authority")
    for name in ("template", "producer_manifest", "reward_config", "period", "collector_implementation", "development_dataset"):
        read_bound(proof[name])
    if proof.get("backend_qualification") is not None:
        read_bound(proof["backend_qualification"])
    if proof.get("reused_encoder_qualification", {}).get("evidence") is not None:
        read_bound(proof["reused_encoder_qualification"]["evidence"])
    need(proof["bundle"] == ready["bundle"] and proof["new_study_root"] == ready["new_study_root"]
         and not Path(ready["new_study_root"]).exists(), "INVALID_REGISTRATION", "Study already exists or proof target differs")
    expected = {c["arm"]: c for c in bundle["candidates"]}
    need(set(config["heads"]) == set(expected) and config["parent_arm"] == bundle["parent_arm"],
         "INPUT_LINEAGE", "Prepared candidate family differs")
    for arm, head in config["heads"].items():
        need(head["path"] == expected[arm]["head"]["path"] and head["sha256"] == expected[arm]["head"]["sha256"]
             and head["construction_kind"] == expected[arm]["construction_kind"]
             and head["workbench_lineage"]["bundle_sha256"] == ready["bundle"]["sha256"]
             and head["workbench_lineage"]["sourceproof_sha256"] == ready["sourceproof"]["sha256"],
             "INPUT_LINEAGE", "Head or source-proof binding differs")
        read_bound(head, HEAD_MAX_BYTES)
    return ready


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("build", "prepare", "verify-ready"))
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--input-sha256", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    ref = {"path": str(args.input), "sha256": args.input_sha256}
    try:
        if args.command == "verify-ready":
            need(args.output is None, "INVALID_ARGUMENT", "Read-only verification has no output directory")
            result = verify_ready(ref)
        else:
            need(args.output is not None, "INVALID_ARGUMENT", "A new output directory is required")
            if args.command == "build":
                import torch
                torch.set_num_threads(1)
            result = (build_bundle if args.command == "build" else prepare_registration)(read_json(ref), args.output)
        print(canonical({"ok": True, "status": result["status"], "registration_performed": False,
                         "candidate_count": len(result["candidates"]) if "candidates" in result else result["candidate_count"],
                         "output": str(args.output) if args.output else None}).decode())
        return 0
    except (WeightError, OSError, ValueError, KeyError, TypeError) as exc:
        error = exc.as_dict() if isinstance(exc, WeightError) else {"code": "BUNDLE_FAILED", "message": str(exc)}
        print(canonical({"ok": False, "error": error, "registration_performed": False}).decode())
        return 1


if __name__ == "__main__":
    sys.exit(main())

"""Bounded head baselines on frozen development features, outside the worker.

This experiment may fit labels and performs real short training when enabled.
It never supplies prospective evidence or changes a live predictor. All candidates
are serialized and reloaded in FP32 before they are scored on the development set.
"""
import argparse
import hashlib
import math
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "workers" / "weight"))
from weight_runtime.artifacts import ArtifactStore, atomic_create
from weight_runtime.current100k import validate_head
from weight_runtime.errors import canonical, checksum, digest, integer, loads, need
from weight_runtime.patches import tensor_sha256


def _positive(value, name, maximum=None):
    need(type(value) in (int, float) and math.isfinite(value) and value > 0
         and (maximum is None or value <= maximum), "INVALID_PLAN", name)
    return float(value)


def validate_plan(plan):
    keys = {"schema", "partition", "information_cutoff_ms", "max_label_resolved_at_ms",
            "ridge_lambda", "max_head_delta_l2", "sgd_budget_seconds", "sgd_max_steps",
            "sgd_learning_rate"}
    need(isinstance(plan, dict) and set(plan) == keys, "INVALID_PLAN", "Exact baseline plan fields required")
    need(plan["schema"] == "hepta.weight.current100k.baselines-plan.v1"
         and plan["partition"] == "development", "INVALID_PLAN", "Baselines fit development labels only")
    cutoff = integer(plan["information_cutoff_ms"], "information_cutoff_ms")
    resolved = integer(plan["max_label_resolved_at_ms"], "max_label_resolved_at_ms")
    need(resolved <= cutoff, "INPUT_LINEAGE", "A fitted label became available after the information cutoff")
    _positive(plan["ridge_lambda"], "ridge_lambda")
    _positive(plan["max_head_delta_l2"], "max_head_delta_l2")
    _positive(plan["sgd_budget_seconds"], "sgd_budget_seconds", 2.)
    _positive(plan["sgd_learning_rate"], "sgd_learning_rate", 1.)
    integer(plan["sgd_max_steps"], "sgd_max_steps", 1, 8192)


def _project_delta(state, parent, cap):
    import torch
    delta = torch.cat([(state[k] - parent[k]).double().flatten() for k in sorted(parent)])
    scale = min(1., cap / max(float(delta.norm()), 1e-300))
    return {k: (parent[k].double() + scale * (state[k].double() - parent[k].double())).float()
            for k in parent}


def compare(features, labels_usd, parent_state, plan, output_root, lineage):
    """Return retained, honestly labelled development comparisons and cost receipts."""
    import torch
    validate_plan(plan)
    parent = {k: v.detach().cpu().clone() for k, v in validate_head(parent_state).items()}
    need(features.device.type == "cpu" and features.dtype == torch.float32
         and features.ndim == 2 and features.shape[1] == 768 and 2 <= features.shape[0] <= 4096,
         "INVALID_FEATURES", "Expected 2..4096 frozen FP32 768-dimensional CPU rows")
    need(labels_usd.device.type == "cpu" and labels_usd.dtype == torch.float32
         and labels_usd.shape == (features.shape[0],), "INVALID_LABELS", "Expected one FP32 USD label per row")
    need(bool(torch.isfinite(features).all()) and bool(torch.isfinite(labels_usd).all()),
         "NONFINITE", "Development data must be finite")
    need(bool(torch.allclose(features.norm(dim=-1), torch.ones(features.shape[0]), atol=1e-5, rtol=1e-5)),
         "INVALID_FEATURES", "Features must follow masked-mean then L2-normalize encoding")
    need(isinstance(lineage, dict) and set(lineage) == {
        "feature_artifact_sha256", "label_artifact_sha256", "head_artifact_sha256"},
        "INPUT_LINEAGE", "Bind all three source artifacts")
    for name, value in lineage.items():
        checksum(value, name)
    features, labels_usd = features.detach(), labels_usd.detach()
    root = Path(output_root)
    root.mkdir(parents=True, exist_ok=False)
    atomic_create(root / "plan.json", canonical(plan) + b"\n")
    store = ArtifactStore(root / "artifacts")
    run_started = time.monotonic()
    x, y = features.detach().double(), labels_usd.detach().double() / 100.
    pw, pb = parent["value.weight"].double(), parent["value.bias"].double()
    parent_prediction = (x @ pw.T).flatten() + pb[0]
    results, receipts = [], []

    def retain(name, state, construction, elapsed, gradient_steps=0, training_seconds=0.):
        started = time.monotonic()
        state = validate_head({k: v.detach().cpu().float().contiguous() for k, v in state.items()})
        ref = store.put_tensors(state, "current100k-baseline-head", {"name": name, "plan_sha256": digest(plan)})
        reloaded = store.load_tensors(ref["artifact_id"])
        need(all(tensor_sha256(state[k]) == tensor_sha256(reloaded[k]) for k in state),
             "RELOAD_MISMATCH", "Saved FP32 baseline head changed")
        prediction = (features @ reloaded["value.weight"].T + reloaded["value.bias"]).flatten() * 100.
        need(bool(torch.isfinite(prediction).all()), "NONFINITE", "Baseline FP32 USD outputs overflowed")
        error = prediction.double() - labels_usd.double()
        delta = torch.cat([(reloaded[k] - parent[k]).double().flatten() for k in sorted(parent)])
        scoring_seconds = time.monotonic() - started
        receipt = {"schema": "hepta.weight.baseline-cost.v1", "candidate": name,
                   "construction_seconds": elapsed, "serialization_reload_scoring_seconds": scoring_seconds,
                   "training_seconds": training_seconds, "gradient_steps": gradient_steps,
                   "optimizer_calls": gradient_steps, "encoder_forward_examples": 0,
                   "shared_encoding_seconds": None, "astra_diagnosis_seconds": None,
                   "scope": "head comparison using previously encoded development features"}
        receipt_ref = store.put_json(receipt, "baseline-cost")
        receipts.append(receipt_ref)
        results.append({"name": name, "construction_kind": construction,
                        "head": ref, "cost": receipt_ref, "mae_usd": float(error.abs().mean()),
                        "rmse_usd": float(error.square().mean().sqrt()),
                        "prediction_std_usd": float(prediction.double().std(unbiased=False)),
                        "actual_head_delta_l2": float(delta.norm()),
                        "effective_changed_coordinates": sum(int((reloaded[k] != parent[k]).sum()) for k in parent),
                        "norm_cap_applies": name in {"ridge_delta_capped", "sgd_head_capped"},
                        "labels_used_in_construction": name != "parent", "gradient_steps": gradient_steps,
                        "production_eligible": False})

    retain("parent", parent, "FrozenParent", 0.)
    for name, statistic in (("constant_mean", y.mean), ("constant_median", lambda: y.quantile(.5))):
        started = time.monotonic()
        state = {"value.weight": torch.zeros_like(pw), "value.bias": statistic().reshape(1)}
        retain(name, state, "ConstantDiagnostic", time.monotonic() - started)
    started = time.monotonic()
    calibrated = {"value.weight": pw, "value.bias": pb + (y - parent_prediction).mean()}
    retain("bias_calibration", calibrated, "LabelFittedCalibration", time.monotonic() - started)

    started = time.monotonic()
    xc = x - x.mean(0)
    residual = y - parent_prediction
    rc = residual - residual.mean()
    ridge = plan["ridge_lambda"]
    if len(x) <= x.shape[1]:
        dw = xc.T @ torch.linalg.solve(xc @ xc.T + ridge * torch.eye(len(x), dtype=x.dtype), rc)
    else:
        dw = torch.linalg.solve(xc.T @ xc + ridge * torch.eye(x.shape[1], dtype=x.dtype), xc.T @ rc)
    db = residual.mean() - x.mean(0) @ dw
    state = _project_delta({"value.weight": (pw + dw.reshape(1, -1)).float(),
                            "value.bias": (pb + db).float()}, parent, plan["max_head_delta_l2"])
    retain("ridge_delta_capped", state, "LabelFittedClosedForm", time.monotonic() - started)

    started = time.monotonic()
    # The optimizer belongs to this explicit comparator, never to the resident
    # weight worker. Initialization time counts in construction cost as well.
    with torch.enable_grad():
        weight = parent["value.weight"].clone().requires_grad_(True)
        bias = parent["value.bias"].clone().requires_grad_(True)
        optimizer = torch.optim.SGD([weight, bias], lr=plan["sgd_learning_rate"])
        training_started = time.monotonic()
        deadline, steps = training_started + plan["sgd_budget_seconds"], 0
        while steps < plan["sgd_max_steps"] and time.monotonic() < deadline:
            optimizer.zero_grad(set_to_none=True)
            prediction = (features @ weight.T + bias).flatten()
            loss = (prediction - labels_usd / 100.).square().mean()
            loss.backward()
            optimizer.step()
            with torch.no_grad():
                state = _project_delta({"value.weight": weight, "value.bias": bias}, parent,
                                       plan["max_head_delta_l2"])
                weight.copy_(state["value.weight"])
                bias.copy_(state["value.bias"])
            steps += 1
        training_seconds = time.monotonic() - training_started
        state = {"value.weight": weight.detach(), "value.bias": bias.detach()}
    retain("sgd_head_capped", state, "ShortHeadTrainingComparator", time.monotonic() - started,
           steps, training_seconds)
    report = {"schema": "hepta.weight.current100k.baselines.v1", "plan_sha256": digest(plan),
              "input_lineage": lineage, "feature_tensor_sha256": tensor_sha256(features),
              "label_tensor_sha256": tensor_sha256(labels_usd), "examples": len(x),
              "task": "Current100k USD regression", "prediction_transform": "identity; no clipping",
              "partition": "development", "prospective_evidence": False,
              "candidates": results, "cost_receipts": receipts,
              "total_seconds": time.monotonic() - run_started,
              "encoding_cost_included": False, "production_eligible": False,
              "interpretation": "Fitted development scores cannot establish future improvement or adoption."}
    atomic_create(root / "report.json", canonical(report) + b"\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for item in ("features", "labels", "head", "plan"):
        parser.add_argument("--" + item, required=True, type=Path)
        parser.add_argument("--" + item + "-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    blobs = {}
    for item in ("features", "labels", "head", "plan"):
        blob = getattr(args, item).read_bytes()
        need(hashlib.sha256(blob).hexdigest() == getattr(args, item + "_sha256"),
             "IDENTITY_MISMATCH", "Input file hash differs", source=item)
        blobs[item] = blob
    import torch
    from safetensors.torch import load
    torch.set_num_threads(1)
    features, labels = load(blobs["features"]), load(blobs["labels"])
    need(set(features) == {"features"} and set(labels) == {"labels_usd"},
         "INPUT_LINEAGE", "Expected explicit features and labels_usd tensor files")
    report = compare(features["features"], labels["labels_usd"], load(blobs["head"]),
                     loads(blobs["plan"]), args.output,
                     {key + "_artifact_sha256": getattr(args, arg + "_sha256")
                      for key, arg in (("feature", "features"), ("label", "labels"), ("head", "head"))})
    print(canonical({"report": str(args.output / "report.json"), "examples": report["examples"],
                     "prospective_evidence": False}).decode())


if __name__ == "__main__":
    main()

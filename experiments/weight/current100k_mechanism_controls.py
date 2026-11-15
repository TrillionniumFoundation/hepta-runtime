"""Label-free controls for a frozen Current100k FP32 linear head.

Recipes, seeds, input matrix and tolerances are fixed before computation. Output
matching uses development features without outcome labels. Heads are serialized
and reloaded before comparison. This is not an encoder or efficacy qualification.
"""
import argparse
import hashlib
import math
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "workers" / "weight"))
from weight_runtime.artifacts import ArtifactStore, atomic_create, file_sha256
from weight_runtime.current100k import validate_head
from weight_runtime.errors import WeightError, canonical, checksum, digest, integer, loads, need, number
from weight_runtime.patches import tensor_sha256

PLAN_SCHEMA = "hepta.weight.current100k.output-controls-plan.v1"
REPORT_SCHEMA = "hepta.weight.current100k.output-controls.v1"
HEAD_ORDER = ("value.weight", "value.bias")


def validate_plan(plan):
    fields = {"schema", "partition", "information_cutoff_ms", "doses", "random_seed",
              "random_controls", "norm_relative_tolerance", "output_relative_tolerance",
              "output_absolute_tolerance_usd", "orthogonality_max_abs_cosine",
              "max_output_rms_scale", "prediction_chunk_size"}
    need(isinstance(plan, dict) and set(plan) == fields and plan["schema"] == PLAN_SCHEMA
         and plan["partition"] == "development", "INVALID_PLAN", "Exact development control plan required")
    integer(plan["information_cutoff_ms"], "information_cutoff_ms")
    need(plan["doses"] == [0, .5, 1] and all(type(v) in (int, float) for v in plan["doses"]),
         "INVALID_PLAN", "This screen fixes zero, half and full dose")
    integer(plan["random_seed"], "random_seed", 0, 2**63 - 4)
    integer(plan["random_controls"], "random_controls", 1, 3)
    integer(plan["prediction_chunk_size"], "prediction_chunk_size", 1, 64)
    for name in ("norm_relative_tolerance", "output_relative_tolerance", "orthogonality_max_abs_cosine"):
        need(0 <= number(plan[name], name) <= .25, "INVALID_PLAN", "Tolerance must be in [0, .25]", field=name)
    need(0 <= number(plan["output_absolute_tolerance_usd"], "output_absolute_tolerance_usd") <= .001,
         "INVALID_PLAN", "Absolute output tolerance must be at most 0.001 USD")
    need(1 <= number(plan["max_output_rms_scale"], "max_output_rms_scale") <= 1e6,
         "INVALID_PLAN", "Output matching scale must be bounded in [1, 1e6]")


def _vector(state):
    import torch
    return torch.cat([state[key].detach().double().flatten() for key in HEAD_ORDER])


def _state(vector, parent, support):
    """Copy only edited coordinates, preserving all other parent FP32 bytes."""
    result, offset = {}, 0
    for key in HEAD_ORDER:
        actual = parent[key].detach().clone().contiguous()
        flat = actual.reshape(-1)
        end = offset + flat.numel()
        selected = support[offset:end]
        flat[selected] = vector[offset:end][selected].to(flat.dtype)
        result[key], offset = actual, end
    return result


def _rms(vector):
    return float(vector.square().mean().sqrt())


def _match(actual, target, relative, absolute=0., nonzero=True):
    error = abs(actual - target)
    return {"reference": target, "actual": actual, "absolute_error": error,
            "relative_error": error / abs(target) if target != 0 else None,
            "relative_tolerance": relative, "absolute_tolerance": absolute,
            "passed": (not nonzero or target != 0) and error <= absolute + relative * abs(target)}


def joint_match_bound(design, delta, plan):
    """Numerical triangle-inequality bound under support, norm and cosine limits.

    A already includes the USD transform and 1/sqrt(number of rows). Decomposing
    a direction into q=delta/||delta|| and its orthogonal complement gives
    ||delta||*(1+norm_rtol)*(||A_perp||_2 + cosine_limit*||Aq||_2).
    """
    import torch
    support = delta != 0
    selected, norm = delta[support], float(delta.norm())
    if int(support.sum()) < 2 or norm == 0:
        return {"status": "NO_ORTHOGONAL_DIRECTION", "support_elements": int(support.sum()),
                "numerical_upper_bound_usd": 0., "certified_interval_bound": False}
    q = selected / norm
    matrix = design[:, support]
    along = matrix @ q
    perpendicular = matrix - along[:, None] * q[None, :]
    singular = float(torch.linalg.svdvals(perpendicular)[0])
    permitted = norm * (1 + plan["norm_relative_tolerance"])
    return {"status": "NUMERICAL_BOUND", "support_elements": int(support.sum()),
            "strict_orthogonal_upper_bound_usd": permitted * singular,
            "numerical_upper_bound_usd": permitted * (
                singular + plan["orthogonality_max_abs_cosine"] * float(along.norm())),
            "certified_interval_bound": False,
            "basis": "FP64 SVD and triangle inequality; floating arithmetic, not interval certification"}


def compare(features, parent_state, full_state, plan, output_root, lineage):
    """Retain every planned condition and failed construction, without ranking."""
    import torch
    validate_plan(plan)
    plan = loads(canonical(plan))
    need(isinstance(lineage, dict) and set(lineage) == {
        "feature_artifact_sha256", "parent_artifact_sha256", "full_artifact_sha256"},
        "INPUT_LINEAGE", "Bind the three immutable source artifacts")
    for name, value in lineage.items():
        checksum(value, name)
    lineage = loads(canonical(lineage))
    need(isinstance(features, torch.Tensor) and features.device.type == "cpu" and features.dtype == torch.float32
         and features.ndim == 2 and features.shape[1] == 768 and 2 <= len(features) <= 4096,
         "INVALID_FEATURES", "Expected 2..4096 frozen CPU FP32 768-dimensional rows")
    need(bool(torch.isfinite(features).all()) and bool(torch.allclose(
        features.norm(dim=-1), torch.ones(len(features)), atol=1e-5, rtol=1e-5)),
        "INVALID_FEATURES", "Expected finite L2-normalized Current100k features")
    features = features.detach()
    parent = {key: value.detach().clone() for key, value in validate_head(parent_state).items()}
    full = {key: value.detach().clone() for key, value in validate_head(full_state).items()}
    input_hash = tensor_sha256(features)
    source_hashes = {key: tensor_sha256(value) for key, value in parent_state.items()}
    parent_vector, full_vector = _vector(parent), _vector(full)
    delta = full_vector - parent_vector
    support = delta != 0
    need(float(delta.norm()) > 0, "ZERO_PARAMETER_DELTA", "Full-dose stored head must differ from parent")
    root = Path(output_root)
    root.mkdir(parents=True, exist_ok=False)
    atomic_create(root / "plan.json", canonical(plan) + b"\n")
    atomic_create(root / "started.json", canonical({"plan_sha256": digest(plan), "lineage": lineage,
                  "feature_tensor_sha256": input_hash, "automatic_replay_allowed": False}) + b"\n")
    store = ArtifactStore(root / "artifacts")
    started, cpu_started = time.monotonic(), time.process_time()
    prediction_examples_attempted = prediction_examples_completed = 0

    def predict(state):
        nonlocal prediction_examples_attempted, prediction_examples_completed
        chunk = plan["prediction_chunk_size"]
        outputs = []
        for i in range(0, len(features), chunk):
            batch = features[i:i + chunk]
            prediction_examples_attempted += len(batch)
            output = torch.nn.functional.linear(batch, state["value.weight"],
                                                state["value.bias"]).flatten() * 100.
            prediction_examples_completed += len(batch)
            outputs.append(output)
        values = torch.cat(outputs)
        need(bool(torch.isfinite(values).all()), "NONFINITE", "FP32 USD outputs overflowed")
        return values

    candidates, constructions = [], []
    parent_output = None
    target_rms = target_mean = None

    def retain(name, state, role, construction_seconds, metadata=None):
        checkpoint = time.monotonic()
        state = validate_head({key: value.detach().contiguous() for key, value in state.items()})
        ref = store.put_tensors(state, "current100k-output-control-head", {"name": name, "plan_sha256": digest(plan)})
        actual = validate_head(store.load_tensors(ref["artifact_id"]))
        need(all(tensor_sha256(state[k]) == tensor_sha256(actual[k]) for k in HEAD_ORDER),
             "RELOAD_MISMATCH", "Stored control head differs after reload")
        output = predict(actual)
        output_ref = store.put_tensors({"value_usd": output}, "current100k-output-control-prediction", {"name": name})
        displacement = output.double() - parent_output.double()
        actual_delta = _vector(actual) - parent_vector
        norm = float(actual_delta.norm())
        cosine = abs(float((actual_delta / norm) @ (delta / delta.norm()))) if norm > 0 else None
        row = {"name": name, "role": role, "head": ref, "outputs": output_ref,
               "actual_dtype": "torch.float32", "save_reload_exact": True,
               "actual_head_delta_l2": norm, "actual_delta_sha256": tensor_sha256(actual_delta),
               "changed_coordinates": int((actual_delta != 0).sum()),
               "delta_mean_usd": float(displacement.mean()), "delta_rms_usd": _rms(displacement),
               "centered_delta_rms_usd": _rms(displacement - displacement.mean()),
               "mean_shift_energy_fraction": (float(displacement.mean()) ** 2 / _rms(displacement) ** 2
                                                if _rms(displacement) > 0 else None),
               "absolute_cosine_with_full_delta": cosine,
               "parameter_norm_match": _match(norm, float(delta.norm()), plan["norm_relative_tolerance"]),
               "orthogonality_passed": cosine is not None and cosine <= plan["orthogonality_max_abs_cosine"],
               "construction_seconds": construction_seconds,
               "serialization_reload_forward_seconds": time.monotonic() - checkpoint,
               "labels_used": False, "production_eligible": False, **(metadata or {})}
        if target_rms is not None:
            row["output_rms_match"] = _match(row["delta_rms_usd"], target_rms,
                plan["output_relative_tolerance"], plan["output_absolute_tolerance_usd"])
            row["mean_output_shift_match"] = _match(row["delta_mean_usd"], target_mean,
                plan["output_relative_tolerance"], plan["output_absolute_tolerance_usd"], nonzero=False)
        candidates.append(row)
        return row, actual, output

    try:
        parent_output = predict(parent)
        parent_row, _, _ = retain("parent", parent, "reference", 0.)
        for dose in plan["doses"]:
            checkpoint = time.monotonic()
            # Copy endpoints to retain signed-zero and original FP32 bytes.
            state = parent if dose == 0 else full if dose == 1 else _state(
                parent_vector + dose * delta, parent, support)
            row, _, output = retain("dose-" + format(dose, ".17g"), state, "dose",
                                    time.monotonic() - checkpoint, {"dose": dose})
            if dose == 0:
                need(row["head"]["sha256"] == parent_row["head"]["sha256"]
                     and tensor_sha256(output) == tensor_sha256(parent_output),
                     "ZERO_DOSE_NOT_NOOP", "Zero dose changed stored head or output bytes")
                row["zero_dose_exact_noop"] = True
            if dose == 1:
                target_rms, target_mean = row["delta_rms_usd"], row["delta_mean_usd"]
        checkpoint = time.monotonic()
        biased = {key: value.clone() for key, value in parent.items()}
        biased["value.bias"] = (parent["value.bias"].double() + target_mean / 100.).float()
        retain("bias-mean-match", biased, "mean_shift_control", time.monotonic() - checkpoint,
               {"construction": "One FP64 bias offset from full-dose mean displacement, then FP32 storage"})

        # The matrix constructs linear controls; match claims use FP32 forwards.
        design = torch.cat((features.double(), torch.ones((len(features), 1), dtype=torch.float64)), dim=1) * 100.
        bound = joint_match_bound(design / math.sqrt(len(features)), delta, plan)
        bound["reference_output_rms_usd"] = target_rms
        lower_required = max(0., target_rms * (1 - plan["output_relative_tolerance"])
                             - plan["output_absolute_tolerance_usd"])
        bound["required_rms_lower_edge_usd"] = lower_required
        bound["infeasible_under_numerical_bound"] = lower_required > bound["numerical_upper_bound_usd"] + 1e-10
        selected = delta[support]
        direction = selected / selected.norm()
        for index in range(plan["random_controls"]):
            checkpoint = time.monotonic()
            seed = plan["random_seed"] + index
            construction = {"index": index, "seed": seed, "attempts": 1,
                            "support": "nonzero realized full-dose head delta",
                            "support_elements": int(support.sum())}
            if int(support.sum()) < 2:
                constructions.append({**construction, "status": "FAILED", "error": "NO_ORTHOGONAL_DIRECTION"})
                continue
            generator = torch.Generator().manual_seed(seed)
            selected_random = torch.randn(selected.shape, generator=generator, dtype=torch.float64)
            selected_random -= (selected_random @ direction) * direction
            if float(selected_random.norm()) <= 1e-12:
                constructions.append({**construction, "status": "FAILED", "error": "CONTROL_DEGENERATE"})
                continue
            random = torch.zeros_like(delta)
            random[support] = selected_random / selected_random.norm() * delta.norm()
            norm_row, stored, _ = retain("random-norm-" + str(index), _state(parent_vector + random, parent, support),
                "parameter_norm_control", time.monotonic() - checkpoint, {"seed": seed})
            checkpoint = time.monotonic()
            realized_random = _vector(stored) - parent_vector
            analytic_rms = _rms(design @ realized_random)
            if target_rms == 0 or analytic_rms <= 1e-15:
                constructions.append({**construction, "status": "OUTPUT_MATCH_FAILED",
                                      "error": "ZERO_REFERENCE_OR_CONTROL_OUTPUT_RMS",
                                      "parameter_norm_candidate": norm_row["name"]})
                continue
            scale = target_rms / analytic_rms
            if scale > plan["max_output_rms_scale"]:
                constructions.append({**construction, "status": "OUTPUT_MATCH_FAILED", "error": "SCALE_LIMIT",
                                      "required_scale": scale, "parameter_norm_candidate": norm_row["name"]})
                continue
            rms_row, _, _ = retain("random-rms-" + str(index), _state(parent_vector + realized_random * scale, parent, support),
                "output_rms_control", time.monotonic() - checkpoint,
                {"seed": seed, "source_parameter_norm_control": norm_row["name"], "output_match_scale": scale,
                 "construction": "One analytic FP64 scale on stored random delta; no adaptive retry"})
            constructions.append({**construction, "status": "CONSTRUCTED",
                                  "parameter_norm_candidate": norm_row["name"], "output_rms_candidate": rms_row["name"]})

        for row in candidates:
            if "output_rms_match" not in row:
                row["output_rms_match"] = _match(row["delta_rms_usd"], target_rms,
                    plan["output_relative_tolerance"], plan["output_absolute_tolerance_usd"])
            row["joint_random_match_passed"] = row["role"] in {"parameter_norm_control", "output_rms_control"} and all(
                (row["parameter_norm_match"]["passed"], row["output_rms_match"]["passed"], row["orthogonality_passed"]))
        restored = validate_head(store.load_tensors(parent_row["head"]["artifact_id"]))
        after = predict(restored)
        preserved = all(tensor_sha256(parent_state[k]) == source_hashes[k] for k in HEAD_ORDER)
        exact_output = tensor_sha256(after) == tensor_sha256(parent_output)
        need(preserved and tensor_sha256(features) == input_hash and exact_output,
             "PARENT_RESTORATION_FAILED", "Source parameters, frozen inputs or final parent outputs changed")
        report = {"schema": REPORT_SCHEMA, "status": "COMPLETED_DEVELOPMENT_SCREEN",
                  "plan_sha256": digest(plan), "input_lineage": lineage,
                  "feature_tensor_sha256": input_hash, "examples": len(features),
                  "partition": "development", "label_inputs": 0, "recipes_fixed_before_forward": True,
                  "payloads_derived_from_frozen_outputs": True, "adaptive_retries": 0,
                  "candidates": candidates, "random_constructions": constructions,
                  "joint_match_feasibility": bound,
                  "parent_restoration": {"passed": True, "source_head_hashes": source_hashes,
                      "exact_output_bytes_equal": exact_output, "final_parent_head_recomputed": True,
                      "final_encoder_recomputed": False, "scope": "Head on frozen development features only"},
                  "cost": {"wall_seconds": time.monotonic() - started,
                      "process_cpu_seconds": time.process_time() - cpu_started,
                      "head_forward_examples": prediction_examples_completed,
                      "head_forward_examples_measurement": "COMPLETED_CHUNK_EXAMPLES",
                      "head_forward_examples_attempted": prediction_examples_attempted,
                      "head_forward_examples_completed": prediction_examples_completed,
                      "encoder_forward_examples": 0, "gradient_steps": 0, "optimizer_calls": 0,
                      "astra_seconds": None, "original_encoding_seconds": None,
                      "prior_candidate_construction_seconds": None,
                      "cost_scope": "This diagnostic after input validation; nested candidate times are included",
                      "end_to_end_cost_complete": False},
                  "production_eligible": False, "prospective_evidence": False,
                  "interpretation": "Output movement and matching controls do not demonstrate useful prediction or training savings"}
        atomic_create(root / "report.json", canonical(report) + b"\n")
        return report
    except Exception as exc:
        error = exc.as_dict() if isinstance(exc, WeightError) else {"code": "CONTROL_SCREEN_FAILED", "message": str(exc)[:2048]}
        atomic_create(root / "failure.json", canonical({"error": error, "completed": False,
            "automatic_replay_allowed": False, "completed_candidates": candidates,
            "random_constructions": constructions, "wall_seconds": time.monotonic() - started,
            "process_cpu_seconds": time.process_time() - cpu_started,
            "head_forward_examples": prediction_examples_completed,
            "head_forward_examples_measurement": "COMPLETED_CHUNK_EXAMPLES",
            "head_forward_examples_attempted": prediction_examples_attempted,
            "head_forward_examples_completed": prediction_examples_completed}) + b"\n")
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("features", "parent", "full", "plan"):
        parser.add_argument("--" + name, required=True, type=Path)
        parser.add_argument("--" + name + "-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    import torch
    from safetensors.torch import load
    torch.set_num_threads(1)
    blobs = {}
    for name in ("features", "parent", "full", "plan"):
        path = getattr(args, name)
        limit = 16 * 1024 * 1024 if name == "features" else 1048576
        need(path.stat().st_size <= limit, "INPUT_LIMIT", "Pinned input exceeds diagnostic bound", source=name)
        blobs[name] = path.read_bytes()
        need(hashlib.sha256(blobs[name]).hexdigest() == getattr(args, name + "_sha256"),
             "IDENTITY_MISMATCH", "Input SHA256 differs", source=name)
    features = load(blobs["features"])
    need(set(features) == {"features"}, "INPUT_LINEAGE", "Expected only the frozen features tensor")
    report = compare(features["features"], load(blobs["parent"]), load(blobs["full"]), loads(blobs["plan"]),
        args.output, {key + "_artifact_sha256": getattr(args, argument + "_sha256")
                      for key, argument in (("feature", "features"), ("parent", "parent"), ("full", "full"))})
    checks = {name: file_sha256(getattr(args, name)) == getattr(args, name + "_sha256")
              for name in ("features", "parent", "full", "plan")}
    atomic_create(args.output / "source-integrity.json", canonical({"passed": all(checks.values()), "checks": checks}) + b"\n")
    need(all(checks.values()), "IDENTITY_MISMATCH", "Pinned sources changed during the screen")
    print(canonical({"report": str(args.output / "report.json"), "source_integrity_passed": True,
                     "status": report["status"], "prospective_evidence": False}).decode())


if __name__ == "__main__":
    main()

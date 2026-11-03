#!/usr/bin/env python3
"""Bounded Laya DEV causal interventions and direct writer edits through the worker.

Run only against an explicitly pinned disposable session. Existing localization
inputs are development observations, never a hidden or prospective test set.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import sys
import time

for _key in ("OMP_NUM_THREADS", "MKL_NUM_THREADS", "OPENBLAS_NUM_THREADS"):
    os.environ[_key] = "2"
os.environ.update(HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1",
                  TOKENIZERS_PARALLELISM="false", USE_TF="0")
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "workers" / "weight"))


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def validate_localization(localization, rows_sha256, opened):
    if (localization.get("schema") != "hepta.weight.laya-localization.v2"
            or localization.get("rows_sha256") != rows_sha256):
        raise ValueError("LOCALIZATION_DATA_LINEAGE_MISMATCH")
    for field in ("model_id", "backend_id"):
        if localization.get(field) != opened[field]:
            raise ValueError("LOCALIZATION_MODEL_OR_BACKEND_MISMATCH:" + field)
    if (localization.get("model_identity") != opened["model"]["identity"]
            or localization.get("backend") != opened["model"]["backend"]):
        raise ValueError("LOCALIZATION_FULL_IDENTITY_MISMATCH")


def validate_probe_lineage(item, row, index, order, mode):
    from weight_runtime.errors import digest
    if (item.get("row_index") != index or item.get("order") != order
            or item.get("mode") != mode or item.get("input_sha256") != digest(row["state"])):
        raise ValueError("LOCALIZATION_PROBE_INPUT_MISMATCH")
    identifier = item.get("model_input_id")
    if not isinstance(identifier, str) or len(identifier) != 64:
        raise ValueError("LOCALIZATION_MODEL_INPUT_ID_MISSING")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("config", "rows", "rows-sha256", "localization",
                 "localization-sha256", "out"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    import numpy as np
    import torch
    from weight_runtime.artifacts import atomic_create
    from weight_runtime.errors import canonical, digest
    from weight_runtime.patches import tensor_sha256
    from weight_runtime.transport import Dispatcher

    if sha(args.rows) != args.rows_sha256 or sha(args.localization) != args.localization_sha256:
        raise ValueError("PINNED_INPUT_MISMATCH")
    config = json.loads(Path(args.config).read_text())
    rows = json.loads(Path(args.rows).read_text())
    localization = json.loads(Path(args.localization).read_text())
    root = Path(args.out).resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    identity = {"config_sha256": sha(args.config), "script_sha256": sha(__file__),
                "rows_sha256": args.rows_sha256,
                "localization_sha256": args.localization_sha256}
    summary_path = root / "summary.json"
    if summary_path.exists():
        previous = json.loads(summary_path.read_text())
        if previous["identity"] != identity:
            raise ValueError("RESUME_IDENTITY_MISMATCH")
        print(json.dumps(previous)); return
    discovery, comparison, layers = [0, 8, 16, 24], [4, 12, 20, 28], [0, 21]
    orders = [list(range(7)), list(reversed(range(7))), list(range(1, 7)) + [0]]
    protocol = {"schema": "hepta.weight.laya-mechanism-plan.v1", "identity": identity,
                "discovery_indices": discovery, "known_dev_comparison_indices": comparison,
                "layers": layers, "orders": orders, "activation_alphas": [0.5, 1.0],
                "writer_column_counts": [4, 64], "writer_alpha": 1.0,
                "random_control_seed": 20261103, "maximum_forwards": 160,
                "dev_mechanism_gate": {"permutation_rms_ratio_max": 0.75,
                    "state_variation_ratio_min": 0.8, "canonical_correlation_min": 0.9,
                    "amplitude_ratio_min": 0.5, "action_tv_max": 0.05},
                "production_eligibility": False, "new_unseen_or_prospective_data": False}
    atomic_create(root / "protocol.json", canonical(protocol) + b"\n")
    dispatcher = Dispatcher("laya-mechanism-v1")
    receipts = []
    started, cpu_started = time.monotonic(), time.process_time()

    def call(operation, params):
        request = {"id": "request-%04d" % len(receipts), "op": operation, "params": params}
        response = dispatcher.handle(request)
        receipts.append({"request": request, "response": response})
        if not response["ok"]:
            atomic_create(root / "failure.json", canonical({"identity": identity,
                          "receipts": receipts}) + b"\n")
            raise RuntimeError(json.dumps(response["error"]))
        return response["result"]

    opened = call("open", config)
    validate_localization(localization, args.rows_sha256, opened)
    provider, store = dispatcher.session.provider, dispatcher.session.store
    pinned = {f"model.encoder.layers.{layer}.mlp.Wo.weight":
              tensor_sha256(provider.get_tensor(f"model.encoder.layers.{layer}.mlp.Wo.weight"))
              for layer in layers}
    directions, direction_evidence = {}, {}
    for layer in layers:
        differences = []
        for index in discovery:
            values = []
            for order_index in range(3):
                key = f"sequential-{index:02}-{order_index}"
                item = next(x for x in localization["probes"] if x["key"] == key)
                validate_probe_lineage(item, rows[index], index, orders[order_index], "sequential")
                path = Path(args.localization).parent / (key + ".npz")
                if sha(path) != item["artifact_sha256"]:
                    raise ValueError("ACTIVATION_IDENTITY_MISMATCH")
                with np.load(path, allow_pickle=False) as archive:
                    values.append(torch.from_numpy(archive[f"encoder.layers.{layer}"].copy()).double())
            differences.extend(value - values[0] for value in values[1:])
        matrix = torch.cat(differences, dim=0)
        ref = store.put_tensors({"difference": matrix}, "discovery-contrasts")
        decomposition = call("analyze", {"operation": "svd", "rank": 1,
            "value": {"artifact_id": ref["artifact_id"], "tensor": "difference"}})
        svd_arrays = store.load_tensors(decomposition["arrays"]["artifact_id"])
        direction, singular = svd_arrays["basis"][0], svd_arrays["singular_values"]
        directions[layer] = direction
        direction_evidence[str(layer)] = {"artifact": ref,
            "leading_variance_share": float(singular[0].square() / singular.square().sum()),
            "analysis": decomposition}

    def probe(index, order, parallel=False, interventions=None, captures=None, patch_id=None):
        spec = {"inputs": {"state": rows[index]["state"], "order": order,
                           "parallel_layout": parallel}}
        if interventions: spec["interventions"] = interventions
        if captures: spec["captures"] = captures
        if patch_id: spec["patch_id"] = patch_id
        result = call("intervene" if interventions else "probe", spec)
        mode = "parallel" if parallel else "sequential"
        matches = [item for item in localization["probes"] if item["row_index"] == index
                   and item["order"] == order and item["mode"] == mode]
        if len(matches) != 1:
            raise ValueError("LOCALIZATION_PROBE_INVENTORY_MISMATCH")
        validate_probe_lineage(matches[0], rows[index], index, order, mode)
        if result["input"]["model_input_id"] != matches[0]["model_input_id"]:
            raise ValueError("LOCALIZATION_PREPROCESSOR_OUTPUT_MISMATCH")
        outputs = store.load_tensors(result["outputs"]["artifact_id"])
        captured = store.load_tensors(result["activations"]["artifact_id"]) if result["activations"] else {}
        return outputs, captured

    def measure(name, **options):
        logits, probabilities, actions = [], [], []
        for index in comparison:
            state_logits, state_probabilities, state_actions = [], [], []
            for order in orders:
                outputs, _ = probe(index, order, **options)
                state_logits.append(outputs["price_logits"][0].double().numpy())
                state_probabilities.append(outputs["price_probabilities"][0].double().numpy())
                state_actions.append(outputs["action_probabilities"][0].double().numpy())
            logits.append(state_logits); probabilities.append(state_probabilities); actions.append(state_actions)
        raw = np.asarray(logits)
        centered = raw - raw.mean(-1, keepdims=True)
        probs, acts = np.asarray(probabilities), np.asarray(actions)
        tv = .5 * np.abs(probs[:, 1:] - probs[:, :1]).sum(-1)
        metrics = {"name": name, "permutation_rms": float(np.sqrt(np.mean((centered[:, 1:] - centered[:, :1]) ** 2))),
            "canonical_rms": float(np.sqrt(np.mean(centered[:, 0] ** 2))),
            "state_variation_rms": float(np.sqrt(np.mean((centered[:, 0] - centered[:, 0].mean(0)) ** 2))),
            "mean_order_tv": float(tv.mean()), "max_order_tv": float(tv.max()),
            "top1_disagreement": float((probs[:, 1:].argmax(-1) != probs[:, :1].argmax(-1)).mean())}
        print(json.dumps({"event": "condition_complete", **metrics}), flush=True)
        return {"metrics": metrics, "centered_logits": centered, "probabilities": probs,
                "action_probabilities": acts}

    parent = measure("parent_sequential")

    def compare(result):
        baseline, metric = parent["metrics"], result["metrics"]
        metric["permutation_rms_ratio"] = metric["permutation_rms"] / max(baseline["permutation_rms"], 1e-30)
        metric["state_variation_ratio"] = metric["state_variation_rms"] / max(baseline["state_variation_rms"], 1e-30)
        metric["amplitude_ratio"] = metric["canonical_rms"] / max(baseline["canonical_rms"], 1e-30)
        a, b = parent["centered_logits"][:, 0].ravel(), result["centered_logits"][:, 0].ravel()
        metric["canonical_correlation"] = float(np.corrcoef(a, b)[0, 1]) if np.std(a) * np.std(b) else 0.0
        metric["action_tv_max"] = float((.5 * np.abs(result["action_probabilities"] - parent["action_probabilities"]).sum(-1)).max())
        metric["dev_mechanism_gate_passed"] = bool(metric["permutation_rms_ratio"] <= .75
            and metric["state_variation_ratio"] >= .8 and metric["canonical_correlation"] >= .9
            and metric["amplitude_ratio"] >= .5 and metric["action_tv_max"] <= .05)
        return metric

    observations = [parent["metrics"], compare(measure("parallel_layout_control", parallel=True))]
    for layer in layers:
        for alpha in (.5, 1.0):
            observations.append(compare(measure(f"activation_l{layer}_alpha{alpha}", interventions=[{
                "module": f"model.encoder.layers.{layer}", "select": "markers",
                "operation": "subtract_direction", "direction": directions[layer].tolist(), "alpha": alpha}])))

    # Writer contributions are chosen exclusively from the four discovery states.
    activation_sets = {layer: [] for layer in layers}
    captures = [{"name": f"l{layer}", "module": f"model.encoder.layers.{layer}.mlp.Wo",
                 "where": "input", "select": "markers", "semantic_order": True} for layer in layers]
    for index in discovery:
        for order in orders:
            _, captured = probe(index, order, captures=captures)
            for layer in layers:
                activation_sets[layer].append(captured[f"l{layer}.0"][0].double())
    patch_results, selections = [], {}
    for layer in layers:
        name = f"model.encoder.layers.{layer}.mlp.Wo.weight"
        parameter = call("inspect", {"export_tensor": True, "tensor": name})
        direction = directions[layer]
        values = torch.stack(activation_sets[layer]).reshape(4, 3, 7, -1)
        difference = (values[:, 1:] - values[:, :1]).reshape(-1, values.shape[-1])
        contrast_ref = store.put_tensors({"difference": difference}, "discovery-mlp-contrast")
        ranked = call("analyze", {"operation": "writer_ranking", "top_k": 64,
            "value": {"artifact_id": contrast_ref["artifact_id"], "tensor": "difference"},
            "weight": {"artifact_id": parameter["array"]["artifact_id"], "tensor": "value"},
            "direction": direction.tolist()})
        positive = ranked["result"]["columns"]
        selections[layer] = positive
        score_ref = ranked["arrays"]
        for count in (4, 64):
            columns = positive[:count]
            if not columns:
                patch_results.append({"name": f"writer_l{layer}_k{count}", "status": "NO_POSITIVE_WRITERS"}); continue
            patch = call("patch", {"expected_model_id": opened["model_id"], "operations": [{
                "tensor": name, "expected_tensor_sha256": pinned[name], "operation": "writer_projection",
                "columns": columns, "direction": direction.tolist(), "alpha": 1.0, "compute_dtype": "float64"}]})
            metrics = compare(measure(f"writer_l{layer}_k{count}", patch_id=patch["patch"]["artifact_id"]))
            patch_results.append({"patch": patch, "metrics": metrics, "columns": columns,
                                  "ranking": score_ref, "discovery_only_selection": True})

    layer = 21
    name = f"model.encoder.layers.{layer}.mlp.Wo.weight"
    weight, direction = provider.get_tensor(name).double(), directions[layer]
    columns = selections[layer]
    if columns:
        generator = torch.Generator().manual_seed(20261103)
        random = torch.randn(direction.shape, generator=generator, dtype=torch.float64)
        random -= (random @ direction) * direction
        random /= random.norm()
        selected = weight[:, columns]
        alpha = float((direction @ selected).norm() / (random @ selected).norm())
        if 0 < alpha <= 8:
            patch = call("patch", {"expected_model_id": opened["model_id"], "operations": [{
                "tensor": name, "expected_tensor_sha256": pinned[name], "operation": "writer_projection",
                "columns": columns, "direction": random.tolist(), "alpha": alpha, "compute_dtype": "float64"}]})
            metrics = compare(measure("norm_matched_random_l21_k64", patch_id=patch["patch"]["artifact_id"]))
            patch_results.append({"patch": patch, "metrics": metrics, "alpha": alpha,
                                  "is_random_control": True, "columns": columns,
                                  "matching_basis": "pre-cast Frobenius norm; realized norms are retained"})
        else:
            patch_results.append({"name": "norm_matched_random_l21_k64", "status": "MATCH_EXCEEDS_ALPHA_LIMIT", "alpha": alpha})

    provider.module.assert_frozen()
    restored = all(tensor_sha256(provider.get_tensor(name)) == value for name, value in pinned.items())
    if not restored: raise ValueError("PARENT_RESTORATION_FAILED")
    forwards, candidates = dispatcher.session.forward_examples, dispatcher.session.patch_candidates
    closed = call("close", {})
    atomic_create(root / "receipts.json", canonical(receipts) + b"\n")
    summary = {"schema": "hepta.weight.laya-session-experiment.v1", "identity": identity,
        "model_id": opened["model_id"], "backend_id": opened["backend_id"],
        "protocol_sha256": sha(root / "protocol.json"), "directions": direction_evidence,
        "observations": observations, "patch_results": patch_results,
        "forward_calls": forwards, "patch_candidates": candidates, "wall_seconds": time.monotonic() - started,
        "cpu_seconds": time.process_time() - cpu_started,
        "peak_rss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
        "gradient_steps": 0, "optimizer_calls": 0, "parent_restored": restored,
        "close": closed, "new_unseen_or_prospective_data": False, "production_eligible": False,
        "limitations": ["All inputs were already known DEV data", "Four comparison states are not independent efficacy evidence",
            "State sensitivity and correlation do not prove useful predictive information", "No outcomes or trading returns evaluated",
            "Input-layout control is not a weight edit", "No active model files were replaced"]}
    atomic_create(summary_path, canonical(summary) + b"\n")
    print(json.dumps({"event": "complete", "forward_calls": forwards, "patch_candidates": candidates,
                      "parent_restored": restored, "summary_sha256": sha(summary_path)}), flush=True)


if __name__ == "__main__":
    main()

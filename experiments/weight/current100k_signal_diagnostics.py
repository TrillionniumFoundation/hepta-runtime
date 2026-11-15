"""Chronological development diagnostics for frozen Current100k representations.

The four representation contracts are fixed before scoring. Labels were already
seen, so even later development rows are not prospective evidence. No live model,
registered family, source evaluator or trading service is changed by this tool.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "workers" / "weight"))
from weight_runtime.artifacts import ArtifactStore, atomic_create
from weight_runtime.current100k import validate_head
from weight_runtime.errors import WeightError, canonical, checksum, digest, integer, loads, need
from weight_runtime.patches import tensor_sha256

REPRESENTATIONS = ("masked_mean", "action", "grouped", "structured")
STRUCTURED_COLUMNS = ("action_sign", "spread_bps", "signed_return_all_bps",
                      "signed_return_last5_bps", "signed_return_last_bps",
                      "rms_step_bps", "range_bps", "quote_age_seconds")
LABEL_AVAILABILITY_BASIS = "VERIFIED_ORIGINAL_ACCOUNTING_ASOF_UPPER_BOUND"


def structured_features(text, action, input_started_at_ms):
    """Eight input-only scalars from the exact original prompt's quote history."""
    import torch
    need(action in ("BUY", "SELL"), "INVALID_INPUT", "Expected BUY or SELL")
    integer(input_started_at_ms, "input_started_at_ms", 1)
    prefix = "Recent authoritative quotes="
    need(isinstance(text, str) and text.count(prefix) == 1,
         "INVALID_INPUT", "Expected one original quote-history marker")
    quotes, _ = json.JSONDecoder().raw_decode(text.split(prefix, 1)[1])
    need(isinstance(quotes, list) and 2 <= len(quotes) <= 4096,
         "INVALID_INPUT", "Expected 2..4096 original quotes")
    bids, asks, stamps = [], [], []
    for quote in quotes:
        need(isinstance(quote, dict), "INVALID_INPUT", "Expected original quote objects")
        stamp = integer(quote.get("t"), "quote.t", 1)
        known = integer(quote.get("known_at_ms", stamp), "quote.known_at_ms", 1)
        need(stamp <= known <= input_started_at_ms and (not stamps or stamps[-1] <= stamp),
             "INPUT_LINEAGE", "Quote history is unordered or unavailable at request time")
        need(type(quote.get("bid")) is not bool and type(quote.get("ask")) is not bool,
             "INVALID_INPUT", "Boolean quotes are not prices")
        try:
            bid, ask = float(quote["bid"]), float(quote["ask"])
        except (ValueError, TypeError, KeyError) as exc:
            raise ValueError("Invalid original quote price") from exc
        need(math.isfinite(bid) and math.isfinite(ask) and 0 < bid <= ask,
             "INVALID_INPUT", "Quotes must be finite, positive and uncrossed")
        bids.append(bid)
        asks.append(ask)
        stamps.append(stamp)
    mid = [(a + b) / 2 for a, b in zip(asks, bids)]
    sign = 1. if action == "BUY" else -1.
    steps = [(b / a - 1.) * 10000 for a, b in zip(mid, mid[1:])]
    values = [sign, (asks[-1] - bids[-1]) / mid[-1] * 10000,
              sign * (mid[-1] / mid[0] - 1.) * 10000,
              sign * (mid[-1] / mid[max(0, len(mid) - 6)] - 1.) * 10000,
              sign * steps[-1], math.sqrt(sum(v * v for v in steps) / len(steps)),
              (max(mid) - min(mid)) / mid[-1] * 10000,
              (input_started_at_ms - stamps[-1]) / 1000.]
    result = torch.tensor(values, dtype=torch.float32)
    need(bool(torch.isfinite(result).all()), "NONFINITE", "Structured features overflowed")
    return result


def validate_plan(plan):
    keys = {"schema", "partition", "information_cutoff_ms", "folds", "ridge_lambda",
            "absolute_parameter_l2", "relative_parent_delta_l2", "sgd_budget_seconds",
            "sgd_max_steps", "sgd_learning_rate", "standardization_floor"}
    need(isinstance(plan, dict) and set(plan) == keys,
         "INVALID_PLAN", "Exact signal-diagnostic plan fields required")
    need(plan["schema"] == "hepta.weight.current100k.signal-plan.v1"
         and plan["partition"] == "previously_viewed_development",
         "INVALID_PLAN", "This diagnostic is not an independent test")
    cutoff = integer(plan["information_cutoff_ms"], "information_cutoff_ms", 1)
    for name in ("ridge_lambda", "absolute_parameter_l2", "relative_parent_delta_l2",
                 "sgd_budget_seconds", "sgd_learning_rate", "standardization_floor"):
        value = plan[name]
        need(type(value) in (int, float) and math.isfinite(value) and value > 0,
             "INVALID_PLAN", "Expected a finite positive parameter", field=name)
    need(plan["sgd_budget_seconds"] <= 2 and plan["sgd_learning_rate"] <= 1,
         "INVALID_PLAN", "Short SGD is bounded to two seconds and learning rate <= 1")
    integer(plan["sgd_max_steps"], "sgd_max_steps", 1, 8192)
    folds = plan["folds"]
    need(isinstance(folds, list) and 1 <= len(folds) <= 4,
         "INVALID_PLAN", "Expected one to four fixed chronological folds")
    previous_end = 0
    for fold in folds:
        need(isinstance(fold, dict) and set(fold) == {
            "fit_before_ms", "score_start_ms", "score_end_ms", "embargo_ms"},
            "INVALID_PLAN", "Exact fold fields required")
        for key in fold:
            integer(fold[key], key, 0 if key == "embargo_ms" else 1)
        need(fold["fit_before_ms"] + fold["embargo_ms"] <= fold["score_start_ms"]
             < fold["score_end_ms"] <= cutoff and fold["score_start_ms"] >= previous_end,
             "INVALID_PLAN", "Scoring intervals must be ordered and disjoint, after fit and embargo")
        previous_end = fold["score_end_ms"]


def split_rows(rows, fold, cutoff):
    """Purge against exact resolution times or conservative availability bounds.

    An accounting replay can prove availability by a time without identifying
    the actual completion time. Such a bound is never converted into an exact
    resolution timestamp. The caller binds and verifies the replay provenance.
    """
    need(isinstance(rows, list) and 4 <= len(rows) <= 4096,
         "INPUT_LIMIT", "Expected 4..4096 aligned metadata rows")
    ids, request_ids, available_by = set(), {}, []
    common = {"row_id", "request_id", "input_started_at_ms"}
    exact_fields = common | {"label_resolved_at_ms"}
    bounded_fields = common | {"label_available_by_ms", "label_time_basis"}
    for row in rows:
        need(isinstance(row, dict) and (set(row) == exact_fields or set(row) == bounded_fields),
             "INPUT_LINEAGE", "Expected exact-resolution metadata or explicit accounting availability-bound metadata")
        bounded = set(row) == bounded_fields
        need(not bounded or row["label_time_basis"] == LABEL_AVAILABILITY_BASIS,
             "INPUT_LINEAGE", "Unrecognized label availability-bound provenance")
        for key in ("row_id", "request_id"):
            need(isinstance(row[key], str) and bool(row[key]), "INPUT_LINEAGE", "Missing row identity")
        need(row["row_id"] not in ids, "INPUT_LINEAGE", "Duplicate row identity")
        ids.add(row["row_id"])
        start = integer(row["input_started_at_ms"], "input_started_at_ms", 1)
        time_field = "label_available_by_ms" if bounded else "label_resolved_at_ms"
        end = integer(row[time_field], time_field, 1)
        need(start <= end <= cutoff, "INPUT_LINEAGE", "Label availability evidence must be within the development cutoff")
        available_by.append(end)
        need(row["request_id"] not in request_ids or request_ids[row["request_id"]] == start,
             "INPUT_LINEAGE", "One request cannot acquire different input times")
        request_ids[row["request_id"]] = start
    train = [i for i, row in enumerate(rows) if row["input_started_at_ms"] < fold["fit_before_ms"]
             and available_by[i] < fold["fit_before_ms"]]
    score = [i for i, row in enumerate(rows)
             if fold["score_start_ms"] <= row["input_started_at_ms"] < fold["score_end_ms"]]
    need(len(train) >= 3 and len(score) >= 2, "INSUFFICIENT_DEVELOPMENT", "Need three fit and two scoring rows")
    need(not ({rows[i]["request_id"] for i in train} & {rows[i]["request_id"] for i in score}),
         "INPUT_LINEAGE", "A request cannot occur in both fit and scoring sets")
    purged = [i for i, row in enumerate(rows) if row["input_started_at_ms"] < fold["fit_before_ms"]
              and available_by[i] >= fold["fit_before_ms"]]
    return train, score, purged


def standardize(features, fit_indices, floor):
    """All moments use the fit subset, including when scoring inputs are extreme."""
    import torch
    fit = features[fit_indices].double()
    mean = fit.mean(0)
    std = fit.std(0, unbiased=False)
    scale = torch.where(std >= floor, std, torch.ones_like(std))
    transformed = ((features.double() - mean) / scale).float()
    need(bool(torch.isfinite(transformed).all()), "NONFINITE", "Standardized FP32 features overflowed")
    return transformed, mean, scale


def constrained_ridge(x, y, center, radius, ridge, penalty_center=None):
    """Solve joint weight/intercept ridge in a ball, not radial clipping of OLS.

    Minimize mean scaled-USD error + ridge*||theta-penalty_center||² subject to
    ||theta-center|| <= radius. A missing penalty center retains the original
    primitive behavior. Thin SVD includes the penalty's nullspace component;
    dropping it would solve a different problem for underdetermined features.
    """
    import torch
    design = torch.cat((x.double(), torch.ones((len(x), 1), dtype=torch.float64)), 1)
    residual = y.double() / 100. - design @ center.double()
    penalty = (center if penalty_center is None else penalty_center).detach()
    offset = penalty.double() - center.double()
    u, singular, vh = torch.linalg.svd(design, full_matrices=False)
    projected_offset = vh @ offset
    null_offset = offset - vh.T @ projected_offset
    numerator = singular * (u.T @ residual) + len(x) * ridge * projected_offset
    def delta(multiplier):
        return (vh.T @ (numerator / (singular.square() + len(x) * (ridge + multiplier)))
                + ridge / (ridge + multiplier) * null_offset)
    answer, multiplier = delta(0.), 0.
    if radius is not None and float(answer.norm()) > radius:
        high = 1.
        while float(delta(high).norm()) > radius:
            high *= 2.
            need(math.isfinite(high), "NUMERICAL_FAILURE", "Could not bracket constrained solution")
        low = 0.
        for _ in range(80):
            middle = (low + high) / 2.
            if float(delta(middle).norm()) > radius:
                low = middle
            else:
                high = middle
        multiplier, answer = high, delta(high)
    return (center.double() + answer).float(), multiplier


def short_sgd(x, y, center, radius, plan, penalty_center=None, meter=None):
    """Same objective and ball as ridge; retain interrupted optimizer accounting."""
    import torch
    started, cpu_started = time.monotonic(), time.process_time()
    deadline = started + plan["sgd_budget_seconds"]
    meter = {} if meter is None else meter
    meter.update(status="INITIALIZING", backward_calls_started=0, backward_calls_completed=0,
                 optimizer_calls_started=0, optimizer_calls_completed=0, completed_steps=0,
                 step_in_progress=False, budget_seconds=plan["sgd_budget_seconds"],
                 completed_counts_are_lower_bounds=False, incomplete_step_effects_unknown=False)
    try:
        penalty = (center if penalty_center is None else penalty_center).detach()
        center, x, y = center.detach(), x.detach(), y.detach()
        with torch.enable_grad():
            theta = center.detach().float().clone().requires_grad_(True)
            design = torch.cat((x.float(), torch.ones((len(x), 1))), 1)
            # This input-only bound and per-candidate optimizer creation count
            # in the budget. One-time runtime startup is measured by compare().
            lipschitz = float(torch.linalg.matrix_norm(design.double(), ord=2)) ** 2 / len(x) + plan["ridge_lambda"]
            learning_rate = min(plan["sgd_learning_rate"], .9 / (2. * lipschitz))
            optimizer = torch.optim.SGD([theta], lr=learning_rate)
            meter["status"] = "UPDATING"
            steps = 0
            while steps < plan["sgd_max_steps"] and time.monotonic() < deadline:
                optimizer.zero_grad(set_to_none=True)
                delta = theta - penalty.float()
                loss = (design @ theta - y.float() / 100.).square().mean() + plan["ridge_lambda"] * delta.square().sum()
                meter["step_in_progress"] = True
                meter["backward_calls_started"] += 1
                loss.backward()
                meter["backward_calls_completed"] += 1
                meter["optimizer_calls_started"] += 1
                optimizer.step()
                meter["optimizer_calls_completed"] += 1
                with torch.no_grad():
                    if radius is not None:
                        delta = theta.double() - center.double()
                        theta.copy_((center.double() + delta * min(1., radius / max(float(delta.norm()), 1e-300))).float())
                steps += 1
                meter["completed_steps"] = steps
                meter["step_in_progress"] = False
            result = theta.detach().clone()
        meter["status"] = "COMPLETED"
        return result, steps, time.monotonic() - started, learning_rate
    except BaseException as exc:
        # A call may have changed parameters before an interrupt reaches Python
        # and before its completed counter is recorded. Never guess that effect.
        meter.update(status="FAILED" if isinstance(exc, Exception) else "INTERRUPTED",
                     completed_counts_are_lower_bounds=True,
                     incomplete_step_effects_unknown=meter["step_in_progress"])
        raise
    finally:
        meter.update(wall_seconds=time.monotonic() - started,
                     process_cpu_seconds=time.process_time() - cpu_started)


def _initialize_optimizer_runtime(meter):
    """One shared data-free startup; no loss, backward call or optimizer step."""
    import torch
    started, cpu_started = time.monotonic(), time.process_time()
    meter.update(status="STARTED", labels_read=0, input_rows_read=0, gradient_steps=0, optimizer_calls=0)
    try:
        torch.optim.SGD([torch.zeros(1, dtype=torch.float32, requires_grad=True)], lr=1.)
        meter["status"] = "COMPLETED"
    except BaseException as exc:
        meter["status"] = "FAILED" if isinstance(exc, Exception) else "INTERRUPTED"
        raise
    finally:
        meter.update(wall_seconds=time.monotonic() - started,
                     process_cpu_seconds=time.process_time() - cpu_started)


def compare(representations, labels_usd, parent_state, rows, plan, output_root, lineage):
    import torch
    validate_plan(plan)
    plan, rows, lineage = loads(canonical(plan)), loads(canonical(rows)), loads(canonical(lineage))
    need(isinstance(representations, dict) and set(representations) == set(REPRESENTATIONS),
         "INVALID_FEATURES", "All four frozen representations are required")
    n = len(rows)
    for name, value in representations.items():
        need(isinstance(value, torch.Tensor) and value.device.type == "cpu" and value.dtype == torch.float32
             and value.ndim == 2 and value.shape[0] == n and 1 <= value.shape[1] <= 4096
             and bool(torch.isfinite(value).all()), "INVALID_FEATURES", "Expected aligned finite CPU FP32 matrices", representation=name)
    need(representations["masked_mean"].shape[1] == 768 and representations["action"].shape[1] == 768
         and representations["grouped"].shape[1] == 768 and representations["structured"].shape[1] == 8,
         "INVALID_FEATURES", "Widths bind original, action, quotes/template/action and structured contracts")
    for name in ("masked_mean", "action", "grouped"):
        need(torch.allclose(representations[name].norm(dim=1), torch.ones(n), atol=1e-5, rtol=1e-5),
             "INVALID_FEATURES", "Expected L2-normalized original/action features")
    need(labels_usd.device.type == "cpu" and labels_usd.dtype == torch.float32 and labels_usd.shape == (n,)
         and bool(torch.isfinite(labels_usd).all()), "INVALID_LABELS", "One finite USD target per row")
    representations = {key: value.detach() for key, value in representations.items()}
    labels_usd = labels_usd.detach()
    parent = {k: v.detach().clone() for k, v in validate_head(parent_state).items()}
    parent_theta = torch.cat((parent["value.weight"].flatten(), parent["value.bias"]))
    need(isinstance(lineage, dict) and set(lineage) == {"features_sha256", "labels_sha256", "head_sha256", "rows_sha256"},
         "INPUT_LINEAGE", "Bind all input artifacts")
    for name, value in lineage.items():
        checksum(value, name)
    splits = [split_rows(rows, fold, plan["information_cutoff_ms"]) for fold in plan["folds"]]
    root = Path(output_root)
    start, cpu_start = time.monotonic(), time.process_time()
    root.mkdir(parents=True, exist_ok=False)
    progress = {"completed_candidates": [], "sgd_attempts": [],
                "shared_optimizer_initialization": {"status": "NOT_STARTED"}}

    def execute():
        _initialize_optimizer_runtime(progress["shared_optimizer_initialization"])
        parent_before = (representations["masked_mean"] @ parent_theta[:-1] + parent_theta[-1]) * 100.
        reports = []
        for fold_number, (train, score, purged) in enumerate(splits):
            entries, transforms = [], {}
            def retain(name, x, theta, center, radius, coordinates, construction_seconds, steps=0,
                       multiplier=None, transform=None, learning_rate=None, penalty_center=None, sgd_meter=None):
                scoring_started = time.monotonic()
                need(bool(torch.isfinite(theta).all()), "NONFINITE", "Candidate parameters overflowed", candidate=name)
                state = {"readout.weight": theta[:-1].reshape(1, -1).contiguous(), "readout.bias": theta[-1:].contiguous()}
                ref = store.put_tensors(state, "current100k-diagnostic-readout", {"name": name, "fold": fold_number, "plan_sha256": digest(plan)})
                reloaded = store.load_tensors(ref["artifact_id"])
                need(all(tensor_sha256(state[k]) == tensor_sha256(reloaded[k]) for k in state), "RELOAD_MISMATCH", "FP32 save/reload changed")
                actual = torch.cat((reloaded["readout.weight"].flatten(), reloaded["readout.bias"]))
                distance = float((actual.double() - center.double()).norm())
                tolerance = max(1e-8, (radius or 0.) * 1e-5)
                need(radius is None or distance <= radius + tolerance, "NORM_CAP", "Stored candidate exceeds its declared norm ball")
                pred = (x @ actual[:-1] + actual[-1]) * 100.
                need(bool(torch.isfinite(pred).all()), "NONFINITE", "FP32 predictions overflowed")
                def metrics(indices):
                    error = pred[indices].double() - labels_usd[indices].double()
                    return {"rows": len(indices), "mae_usd": float(error.abs().mean()), "rmse_usd": float(error.square().mean().sqrt()),
                            "prediction_std_usd": float(pred[indices].double().std(unbiased=False))}
                raw_theta = actual.double()
                if transform is not None:
                    mean, scale = transform
                    raw_weight = actual[:-1].double() / scale
                    raw_theta = torch.cat((raw_weight, (actual[-1].double() - mean @ raw_weight).reshape(1)))
                fit_metrics, score_metrics = metrics(train), metrics(score)
                entry = {"name": name, "head": ref, "coordinates": coordinates, "parameter_count": actual.numel(),
                                "constraint_center_sha256": tensor_sha256(center), "joint_norm_radius": radius,
                                "ridge_penalty_center_sha256": tensor_sha256(penalty_center) if penalty_center is not None else None,
                                "ridge_lambda": plan["ridge_lambda"] if penalty_center is not None else None,
                                "fit_objective": ("mean((prediction_usd/100-label_usd/100)^2) + ridge_lambda*||theta-penalty_center||^2"
                                                  if penalty_center is not None else None),
                                "actual_distance_to_center": distance, "stored_parameter_l2": float(actual.double().norm()),
                                "equivalent_raw_parameter_l2": float(raw_theta.norm()), "norm_rounding_tolerance": tolerance,
                                "construction_seconds": construction_seconds, "serialization_reload_scoring_seconds": time.monotonic() - scoring_started,
                                "gradient_steps": steps, "lagrange_multiplier": multiplier, "actual_sgd_learning_rate": learning_rate,
                                "construction_budget_seconds": plan["sgd_budget_seconds"],
                                "construction_budget_exceeded": construction_seconds > plan["sgd_budget_seconds"],
                                "sgd_cost": sgd_meter,
                                "fit": fit_metrics, "chronological_development_score": score_metrics, "production_eligible": False}
                entries.append(entry)
                progress["completed_candidates"].append({"fold": fold_number, "candidate": entry})

            def run_sgd(name, inputs, center, radius, penalty_center):
                meter = {"fold": fold_number, "candidate": name}
                progress["sgd_attempts"].append(meter)
                values = short_sgd(inputs, labels_usd[train], center, radius, plan,
                                   penalty_center=penalty_center, meter=meter)
                return (*values, meter)
            x = representations["masked_mean"]
            zero = torch.zeros(769)
            retain("parent", x, parent_theta, zero, None, "raw_original_features", 0.)
            for name, statistic in (("constant_mean", lambda y: y.mean()), ("constant_median", lambda y: y.quantile(.5))):
                began = time.monotonic()
                theta = zero.clone()
                theta[-1] = statistic(labels_usd[train].double() / 100.).float()
                retain(name, x, theta, zero, None, "raw_original_features", time.monotonic() - began)
            began = time.monotonic()
            theta = parent_theta.clone()
            theta[-1] += ((labels_usd[train].double() - parent_before[train].double()).mean() / 100.).float()
            retain("bias_calibration", x, theta, parent_theta, None, "raw_original_features", time.monotonic() - began)
            # Signal/pooling comparisons share identical folds, methods and encoder
            # head width. The eight-scalar baseline has its own reported capacity.
            # Standardization changes the ridge
            # geometry and is not an equivalent fixed raw-coordinate norm constraint.
            for representation in REPRESENTATIONS:
                z, mean, scale = standardize(representations[representation], train, plan["standardization_floor"])
                transforms[representation] = store.put_tensors({"mean": mean, "scale": scale}, "fit-only-standardization", {"fold": fold_number, "representation": representation})
                center = torch.zeros(z.shape[1] + 1)
                began = time.monotonic()
                theta, multiplier = constrained_ridge(z[train], labels_usd[train], center, None, plan["ridge_lambda"])
                retain(representation + ":standardized:ridge", z, theta, center, None, "fit_only_zscore", time.monotonic() - began,
                       multiplier=multiplier, transform=(mean, scale), penalty_center=center)
                theta, steps, seconds, learning_rate, meter = run_sgd(representation + ":standardized:sgd", z[train], center, None, center)
                retain(representation + ":standardized:sgd", z, theta, center, None, "fit_only_zscore", seconds, steps,
                       transform=(mean, scale), learning_rate=learning_rate, penalty_center=center, sgd_meter=meter)
            # Constraint diagnostics retain the ORIGINAL raw feature coordinates and
            # include bias in the norm. Both keep the same zero-centered ridge
            # penalty; only their permitted parameter balls differ.
            for constraint, center, radius in (("absolute", zero, plan["absolute_parameter_l2"]),
                                               ("parent_delta", parent_theta, plan["relative_parent_delta_l2"])):
                began = time.monotonic()
                theta, multiplier = constrained_ridge(x[train], labels_usd[train], center, radius,
                                                       plan["ridge_lambda"], penalty_center=zero)
                retain("masked_mean:" + constraint + ":ridge", x, theta, center, radius, "raw_original_features", time.monotonic() - began,
                       multiplier=multiplier, penalty_center=zero)
                theta, steps, seconds, learning_rate, meter = run_sgd("masked_mean:" + constraint + ":sgd", x[train], center, radius, zero)
                retain("masked_mean:" + constraint + ":sgd", x, theta, center, radius, "raw_original_features", seconds, steps,
                       learning_rate=learning_rate, penalty_center=zero, sgd_meter=meter)
            reports.append({"fold": fold_number, "fit_rows": train, "score_rows": score, "purged_label_unavailable_rows": purged,
                            "standardization": transforms, "candidates": entries})
        parent_after = (representations["masked_mean"] @ parent_theta[:-1] + parent_theta[-1]) * 100.
        need(tensor_sha256(parent_before) == tensor_sha256(parent_after)
             and all(tensor_sha256(parent[k]) == tensor_sha256(parent_state[k]) for k in parent),
             "RESTORE_MISMATCH", "Parent recomputation or source parameters changed")
        report = {"schema": "hepta.weight.current100k.signal-diagnostics.v1", "plan_sha256": digest(plan), "input_lineage": lineage,
                  "label_time_metadata": [{"row_id": row["row_id"],
                      "label_time_is_exact": "label_resolved_at_ms" in row,
                      **{key: row[key] for key in ("label_resolved_at_ms", "label_available_by_ms", "label_time_basis")
                         if key in row}} for row in rows],
                  "label_timing_scope": "Pinned caller metadata; availability bounds retain their accounting-replay basis and are not actual resolution timestamps",
                  "representations": {k: {"shape": list(v.shape), "tensor_sha256": tensor_sha256(v)} for k, v in representations.items()},
                  "group_order": ["quotes", "template", "action"],
                  "grouped_pooling": "L2_NORMALIZE((L2_quotes + L2_template + L2_action) / 3); template includes action",
                  "structured_columns": list(STRUCTURED_COLUMNS),
                  "folds": reports, "parent_recomputation_exact": True, "parent_head_only_recomputation": True,
                  "encoder_forward_examples": 0, "shared_encoding_seconds": None, "astra_seconds": None,
                  "shared_optimizer_initialization": progress["shared_optimizer_initialization"],
                  "shared_optimizer_initialization_seconds": progress["shared_optimizer_initialization"]["wall_seconds"],
                  "sgd_attempts": progress["sgd_attempts"],
                  "total_gradient_steps": sum(item["completed_steps"] for item in progress["sgd_attempts"]),
                  "total_seconds": time.monotonic() - start, "process_cpu_seconds": time.process_time() - cpu_start,
                  "cost_scope": "Full diagnostic after validation; shared startup and candidate times are nested, not additive",
                  "partition": "previously_viewed_development",
                  "primary_diagnostic_metric": "RMSE_USD_RAW_UNCLIPPED", "selection_rule": "RETAIN_ALL_NO_WINNER_SELECTION",
                  "prospective_evidence": False, "production_eligible": False,
                  "limitations": ["Previously seen labels do not become independent evidence after chronological splitting.",
                                  "Accounting availability upper bounds are used conservatively for purging; this runner does not replay their source accounting.",
                                  "All three encoder readouts have 769 parameters; the structured baseline has nine.",
                                  "Z-score ridge and raw-coordinate constrained ridge use different regularization geometries.",
                                  "Raw absolute and parent-delta comparisons use the same zero-centered ridge penalty.",
                                  "A same numerical norm cap after feature scaling generally defines a different function class.",
                                  "Head-only timers exclude prior extraction, model loading, Astra work and failed earlier attempts."]}
        atomic_create(root / "report.json", canonical(report) + b"\n")
        return report

    try:
        atomic_create(root / "plan.json", canonical(plan) + b"\n")
        atomic_create(root / "started.json", canonical({
            "schema": "hepta.weight.current100k.signal-attempt.v1",
            "plan_sha256": digest(plan), "input_lineage": lineage,
            "started_at_ms": time.time_ns() // 1000000,
            "automatic_replay_allowed": False}) + b"\n")
        store = ArtifactStore(root / "artifacts")
        return execute()
    except BaseException as exc:
        error = exc.as_dict() if isinstance(exc, WeightError) else {
            "code": "SIGNAL_DIAGNOSTIC_FAILED", "message": str(exc)[:2048],
            "exception_type": type(exc).__name__}
        failure = {"schema": "hepta.weight.current100k.signal-failure.v1",
                   "plan_sha256": digest(plan), "input_lineage": lineage,
                   "error": error, "completed": False, "automatic_replay_allowed": False,
                   "status": "failed" if isinstance(exc, Exception) else "interrupted",
                   "retained_progress_is_lower_bound": True,
                   "incomplete_sgd_step_effects_unknown": any(
                       item.get("step_in_progress", False) for item in progress["sgd_attempts"]),
                   **progress, "wall_seconds": time.monotonic() - start,
                   "process_cpu_seconds": time.process_time() - cpu_start,
                   "cost_scope": "Complete diagnostic after validation, including startup and failed attempt; nested times are included"}
        try:
            atomic_create(root / "failure.json", canonical(failure) + b"\n")
        except BaseException as retention_error:
            # Full disks and other retention failures must not hide the actual
            # numerical or optimizer failure that ended the experiment.
            if hasattr(exc, "add_note"):
                exc.add_note("Failure receipt could not be retained: " + str(retention_error)[:512])
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("features", "labels", "head", "rows", "plan"):
        parser.add_argument("--" + key, required=True, type=Path)
        parser.add_argument("--" + key + "-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    blobs = {}
    for key in ("features", "labels", "head", "rows", "plan"):
        data = getattr(args, key).read_bytes()
        need(hashlib.sha256(data).hexdigest() == getattr(args, key + "_sha256"), "IDENTITY_MISMATCH", "Input hash differs", source=key)
        blobs[key] = data
    import torch
    from safetensors.torch import load
    torch.set_num_threads(1)
    labels = load(blobs["labels"])
    need(set(labels) == {"labels_usd"}, "INVALID_LABELS", "Expected labels_usd tensor")
    report = compare(load(blobs["features"]), labels["labels_usd"], load(blobs["head"]), loads(blobs["rows"]),
                     loads(blobs["plan"]), args.output, {key + "_sha256": getattr(args, key + "_sha256") for key in ("features", "labels", "head", "rows")})
    checks = []
    for key in ("features", "labels", "head", "rows", "plan"):
        try:
            actual = hashlib.sha256(getattr(args, key).read_bytes()).hexdigest()
            checks.append({"source": key, "expected_sha256": getattr(args, key + "_sha256"),
                           "actual_sha256": actual, "passed": actual == getattr(args, key + "_sha256")})
        except OSError as exc:
            checks.append({"source": key, "passed": False, "error": str(exc)[:512]})
    integrity = {"schema": "hepta.weight.current100k.signal-source-integrity.v1",
                 "checks": checks, "passed": all(check["passed"] for check in checks)}
    atomic_create(args.output / "source-integrity.json", canonical(integrity) + b"\n")
    need(integrity["passed"], "INPUT_CHANGED", "A source changed during the diagnostic; report is not source-qualified")
    print(canonical({"report": str(args.output / "report.json"), "folds": len(report["folds"]), "prospective_evidence": False}).decode())


if __name__ == "__main__":
    main()


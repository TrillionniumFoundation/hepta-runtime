"""Fixed-budget, same-input mechanism experiments over the existing worker protocol.

This module orchestrates public operations; it never accesses a provider, applies
live weights itself, fits to outcomes, or promotes a candidate. Controls and doses
are fixed before the first forward. Norm matching is checked again after the
worker has compiled, stored and reloaded each candidate in its actual dtype.
"""
from dataclasses import dataclass
import math
import time
from typing import Callable

from .errors import WeightError, canonical, checksum, digest, identifier, integer, loads, need, number


PLAN_SCHEMA = "hepta.weight.mechanism-plan.v1"
RESULT_SCHEMA = "hepta.weight.mechanism-experiment.v1"


@dataclass(frozen=True)
class Budget:
    max_forward_examples: int
    max_patch_candidates: int
    max_operations: int = 256
    max_queried_elements: int = 131072
    max_selected_elements: int = 8192
    max_output_elements: int = 8192
    max_wall_seconds: float = 600.0
    max_request_ms: int = 120000

    @classmethod
    def parse(cls, value):
        need(isinstance(value, dict) and set(value) <= set(cls.__dataclass_fields__),
             "INVALID_PLAN", "Unknown mechanism budget")
        need({"max_forward_examples", "max_patch_candidates"} <= set(value),
             "INVALID_PLAN", "Forward and candidate limits must be explicit")
        result = cls(**value)
        for name, ceiling in (("max_forward_examples", 160), ("max_patch_candidates", 16),
                              ("max_operations", 2048), ("max_queried_elements", 1048576),
                              ("max_selected_elements", 8192), ("max_output_elements", 65536),
                              ("max_request_ms", 600000)):
            integer(getattr(result, name), name, 1, ceiling)
        need(0 < number(result.max_wall_seconds, "max_wall_seconds") <= 7200,
             "INVALID_PLAN", "Invalid wall-time budget")
        return result


@dataclass(frozen=True)
class InputCase:
    case_id: str
    inputs_json: bytes
    input_sha256: str
    expected_examples: int


@dataclass(frozen=True)
class ExperimentPlan:
    document: bytes
    experiment_id: str
    model_id: str
    backend_id: str
    cases: tuple[InputCase, ...]
    doses: tuple[float, ...]
    random_controls: int
    random_seed: int
    random_norm_rtol: float
    output_names: tuple[str, ...]
    probability_outputs: tuple[str, ...]
    budget: Budget

    @property
    def candidate_count(self):
        return len(self.doses) + self.random_controls

    @property
    def forward_examples(self):
        return (self.candidate_count + 2) * sum(c.expected_examples for c in self.cases)

    @classmethod
    def parse(cls, value):
        try:
            encoded = canonical(value)
        except (TypeError, ValueError) as exc:
            raise WeightError("INVALID_PLAN", "Plan must be finite JSON data") from exc
        need(len(encoded) <= 1048576, "INVALID_PLAN", "Mechanism plan exceeds 1 MiB")
        value = loads(encoded)
        fields = {"schema", "experiment_id", "expected_model_id", "expected_backend_id",
                  "data_role", "input_lineage", "target", "cases", "doses", "random_controls",
                  "random_seed", "random_norm_rtol", "output_names", "probability_outputs", "budgets", "hypothesis"}
        need(isinstance(value, dict) and set(value) <= fields and value.get("schema") == PLAN_SCHEMA,
             "INVALID_PLAN", "Expected a typed mechanism plan")
        need(value.get("data_role") == "development", "INVALID_PLAN", "Mechanism screens use development data only")
        experiment_id = identifier(value.get("experiment_id"), "experiment_id")
        model_id = checksum(value.get("expected_model_id"), "expected_model_id")
        backend_id = checksum(value.get("expected_backend_id"), "expected_backend_id")
        if "hypothesis" in value:
            hypothesis = value["hypothesis"]
            need(isinstance(hypothesis, dict) and set(hypothesis) == {
                "statement", "expected_observation", "falsifying_observation", "diagnostic_evidence", "author_model"},
                "INVALID_HYPOTHESIS", "Exact structured hypothesis fields are required")
            for field in ("statement", "expected_observation", "falsifying_observation", "author_model"):
                need(isinstance(hypothesis[field], str) and hypothesis[field].strip()
                     and len(hypothesis[field].encode("utf-8")) <= (128 if field == "author_model" else 4096),
                     "INVALID_HYPOTHESIS", "Hypothesis text must be nonempty and bounded", field=field)
            references = hypothesis["diagnostic_evidence"]
            need(isinstance(references, list) and 1 <= len(references) <= 16,
                 "INVALID_HYPOTHESIS", "Bind 1..16 diagnostic evidence references")
            for reference in references:
                need(isinstance(reference, dict) and set(reference) == {"ref", "sha256"}
                     and isinstance(reference["ref"], str) and reference["ref"].strip()
                     and len(reference["ref"].encode("utf-8")) <= 2048,
                     "INVALID_HYPOTHESIS", "Diagnostic references require ref and sha256")
                checksum(reference["sha256"], "diagnostic_evidence.sha256")
        target = value.get("target")
        need(isinstance(target, dict) and set(target) <= {
            "tensor", "expected_tensor_sha256", "rows", "columns", "family", "delta",
            "direction", "max_relative_norm"}, "INVALID_PLAN", "Unknown mechanism target fields")
        need(isinstance(target.get("tensor"), str) and target["tensor"], "INVALID_PLAN", "Target tensor is required")
        checksum(target.get("expected_tensor_sha256"), "expected_tensor_sha256")
        family = target.get("family")
        need(family in ("additive_delta", "writer_projection"), "INVALID_PLAN", "Unsupported mechanism family")
        need(("delta" in target and "direction" not in target) if family == "additive_delta"
             else ("direction" in target and "delta" not in target), "INVALID_PLAN", "Mechanism payload differs from family")
        norm_limit = number(target.get("max_relative_norm", 1.0), "max_relative_norm")
        need(0 <= norm_limit <= 16, "INVALID_PLAN", "Invalid target norm limit")
        raw_cases = value.get("cases")
        need(isinstance(raw_cases, list) and 1 <= len(raw_cases) <= 32, "INVALID_PLAN", "Expected 1..32 fixed inputs")
        cases = []
        for item in raw_cases:
            need(isinstance(item, dict) and set(item) == {"case_id", "inputs", "input_sha256", "expected_examples"},
                 "INVALID_PLAN", "Invalid input case")
            case_id = identifier(item["case_id"], "case_id")
            need(isinstance(item["inputs"], dict), "INVALID_PLAN", "Inputs must be an object")
            pinned = checksum(item["input_sha256"], "input_sha256")
            need(digest(item["inputs"]) == pinned, "IDENTITY_MISMATCH", "Frozen input differs", case_id=case_id)
            cases.append(InputCase(case_id, canonical(item["inputs"]), pinned,
                                   integer(item["expected_examples"], "expected_examples", 1, 160)))
        need(len({c.case_id for c in cases}) == len(cases), "INVALID_PLAN", "Duplicate case ids")
        raw_doses = value.get("doses")
        need(isinstance(raw_doses, list) and 3 <= len(raw_doses) <= 8, "INVALID_PLAN", "Predeclare 3..8 doses")
        doses = tuple(number(d, "dose") for d in raw_doses)
        need(tuple(sorted(set(doses))) == doses and doses[0] == 0 and 1 in doses and doses[-1] <= 2
             and any(0 < d < 1 for d in doses), "INVALID_PLAN", "Doses need zero, one and an intermediate value")
        controls = integer(value.get("random_controls"), "random_controls", 1, 3)
        seed = integer(value.get("random_seed"), "random_seed", 0, 2**63 - 4)
        rtol = number(value.get("random_norm_rtol", .02), "random_norm_rtol")
        need(0 <= rtol <= .25, "INVALID_PLAN", "Random norm tolerance must be at most 25 percent")
        output_names = value.get("output_names")
        need(isinstance(output_names, list) and 1 <= len(output_names) <= 8
             and all(isinstance(n, str) and n for n in output_names)
             and len(set(output_names)) == len(output_names), "INVALID_PLAN", "Expected unique output names")
        probabilities = value.get("probability_outputs", [])
        need(isinstance(probabilities, list) and all(isinstance(n, str) for n in probabilities)
             and len(set(probabilities)) == len(probabilities)
             and set(probabilities) <= set(output_names), "INVALID_PLAN", "Probability outputs must be selected outputs")
        budget = Budget.parse(value.get("budgets"))
        result = cls(canonical(value), experiment_id, model_id, backend_id, tuple(cases), doses,
                     controls, seed, rtol, tuple(output_names), tuple(probabilities), budget)
        need(result.candidate_count <= budget.max_patch_candidates
             and result.forward_examples <= budget.max_forward_examples, "EXPERIMENT_BUDGET",
             "All doses, controls and both parent passes must fit the predeclared budget",
             required_candidates=result.candidate_count, required_forward_examples=result.forward_examples)
        return result


def required_limits(plan):
    """Use before opening the disposable worker, so its hard counters bind this plan."""
    plan = plan if isinstance(plan, ExperimentPlan) else ExperimentPlan.parse(plan)
    return {"max_forward_examples": plan.forward_examples,
            "max_patch_candidates": plan.candidate_count}


class _Meter:
    def __init__(self, call, plan):
        self.worker_call, self.plan = call, plan
        self.started, self.cpu_started = time.monotonic(), time.process_time()
        self.operations = self.queried_elements = self.forwards = self.candidates = 0
        self.model_seconds = self.worker_seconds = self.worker_cpu_seconds = 0.0
        self.artifact_payloads = {}
        self.observed_forward_total = self.observed_patch_total = 0
        self.probe_receipts = self.encoder_receipts = 0
        self.computation_totals = {k: 0 for k in ("encoder_forward_examples", "feature_cache_hits",
                                  "feature_cache_misses", "feature_cache_bypassed_examples")}

    def _retain_refs(self, value):
        if isinstance(value, dict):
            if {"artifact_id", "sha256", "byte_length", "path"} <= set(value):
                self.artifact_payloads[value["sha256"]] = value["byte_length"]
            else:
                for item in value.values():
                    self._retain_refs(item)
        elif isinstance(value, list):
            for item in value:
                self._retain_refs(item)

    def call(self, operation, params):
        remaining = self.plan.budget.max_wall_seconds - (time.monotonic() - self.started)
        need(remaining > 0 and self.operations < self.plan.budget.max_operations,
             "EXPERIMENT_BUDGET", "Operation or wall-time budget exhausted")
        params = loads(canonical(params))
        params["timeout_ms"] = max(1, min(self.plan.budget.max_request_ms, int(remaining * 1000)))
        self.operations += 1
        result = self.worker_call(operation, params)
        self._retain_refs(result)
        cost = result.get("cost", {})
        self.worker_seconds += float(cost.get("worker_wall_seconds", 0))
        self.worker_cpu_seconds += float(cost.get("worker_cpu_seconds", 0))
        self.observed_forward_total = result.get("total_forward_examples", cost.get("forward_examples_total", self.observed_forward_total))
        self.observed_patch_total = result.get("patch_candidates", cost.get("patch_candidates_total", self.observed_patch_total))
        if operation == "probe":
            self.probe_receipts += 1
            self.model_seconds += float(result["model_forward_seconds"])
            computation = result.get("computation", {})
            self.encoder_receipts += int("encoder_forward_examples" in computation)
            for key in self.computation_totals:
                if key in computation:
                    self.computation_totals[key] += integer(computation[key], key, 0, 160)
        need(time.monotonic() - self.started <= self.plan.budget.max_wall_seconds,
             "EXPERIMENT_BUDGET", "Worker operation returned after the experiment wall-time budget",
             completed_operation=operation, partial_cost=self.cost(),
             last_result_artifacts={key: result[key] for key in ("evidence", "outputs", "patch", "parameters") if key in result})
        return result

    def tensor(self, artifact, name, maximum):
        import torch
        values, offset, shape, dtype, total = [], 0, None, None, None
        while True:
            page = self.call("query", {"artifact_id": artifact["artifact_id"], "tensor": name,
                                       "offset": offset, "limit": min(1024, maximum)})
            count = integer(page["total_elements"], "total_elements", 1, maximum)
            need(self.queried_elements + count - offset <= self.plan.budget.max_queried_elements,
                 "EXPERIMENT_BUDGET", "Tensor queries exceed their declared element budget")
            if shape is None:
                shape, dtype, total = page["shape"], page["dtype"], count
            need(page["artifact"]["sha256"] == artifact["sha256"] and page["shape"] == shape
                 and page["dtype"] == dtype and count == total and page["offset"] == offset,
                 "IDENTITY_MISMATCH", "Retained tensor pagination changed")
            part = page["values"]
            need(isinstance(part, list) and 0 < len(part) <= 1024 and offset + len(part) <= total,
                 "PROTOCOL_ERROR", "Invalid tensor page")
            values.extend(part)
            offset += len(part)
            self.queried_elements += len(part)
            if offset == total:
                need(page["next_offset"] is None, "PROTOCOL_ERROR", "Unexpected tensor continuation")
                break
            need(page["next_offset"] == offset, "PROTOCOL_ERROR", "Invalid tensor continuation")
        types = {"torch.float16": torch.float16, "torch.bfloat16": torch.bfloat16,
                 "torch.float32": torch.float32, "torch.float64": torch.float64}
        need(dtype in types and math.prod(shape) == total, "UNSUPPORTED_DTYPE", "Expected a floating tensor")
        result = torch.tensor(values, dtype=types[dtype]).reshape(shape)
        need(bool(torch.isfinite(result).all()), "NONFINITE", "Non-finite retained tensor")
        return result

    def cost(self):
        complete_encoder_accounting = self.probe_receipts > 0 and self.encoder_receipts == self.probe_receipts
        return {"forward_examples": self.observed_forward_total, "patch_candidates": self.observed_patch_total,
                "worker_operations": self.operations, "queried_elements": self.queried_elements,
                "wall_seconds": time.monotonic() - self.started,
                "process_cpu_seconds": time.process_time() - self.cpu_started,
                "cpu_seconds_scope": "Orchestrating process; includes embedded worker time, do not add worker_cpu_seconds",
                "model_forward_seconds": self.model_seconds,
                "worker_wall_seconds": self.worker_seconds, "worker_cpu_seconds": self.worker_cpu_seconds,
                "retained_artifact_payload_bytes": sum(self.artifact_payloads.values()),
                "unique_artifact_payloads": len(self.artifact_payloads),
                "artifact_byte_scope": "Unique content payloads in public receipts; excludes descriptors and request ledger",
                "encoder_accounting_complete": complete_encoder_accounting,
                **{key: value if complete_encoder_accounting else None for key, value in self.computation_totals.items()},
                "feature_cache_scope": "Initial parent uses the provider default; final parent explicitly bypasses feature cache",
                "cost_scope": "Experiment after open; worker load and close are reported separately by the caller",
                "worker_cost_receipts_available": self.worker_seconds > 0,
                "backward_steps": 0, "optimizer_calls": 0}


def _selection(value, width, field):
    if value is None:
        return list(range(width))
    need(isinstance(value, list) and value and all(type(i) is int and 0 <= i < width for i in value)
         and len(set(value)) == len(value), "INVALID_PLAN", "Invalid matrix selection", field=field)
    return value


def _deltas(parent, target, count, seed):
    import torch
    def as_double(value):
        try:
            return torch.as_tensor(value, dtype=torch.float64)
        except (TypeError, ValueError, RuntimeError) as exc:
            raise WeightError("SHAPE_MISMATCH", "Expected a rectangular finite numeric mechanism payload") from exc
    if target["family"] == "additive_delta":
        delta = as_double(target["delta"])
        need(delta.shape == parent.shape, "SHAPE_MISMATCH", "Delta must match the selected block")
        need(bool(torch.isfinite(delta).all()) and float(delta.norm()) > 0,
             "INVALID_PLAN", "Mechanism delta must be finite and nonzero")
        need(delta.numel() >= 2, "INVALID_PLAN", "An orthogonal control needs at least two selected coordinates")
        direction = delta.reshape(-1) / delta.norm()
        random_deltas = []
        for i in range(count):
            generator = torch.Generator().manual_seed(seed + i)
            random = torch.randn(direction.shape, generator=generator, dtype=torch.float64)
            random -= (random @ direction) * direction
            need(float(random.norm()) > 1e-12, "CONTROL_DEGENERATE", "Random control is degenerate")
            random_deltas.append((random / random.norm() * delta.norm()).reshape(delta.shape))
        return delta, random_deltas, "same-support isotropic delta orthogonal to the proposed delta; rank is not matched"
    direction = as_double(target["direction"]).reshape(-1)
    need(direction.numel() == parent.shape[0] and bool(torch.isfinite(direction).all())
         and float(direction.norm()) > 0 and direction.numel() >= 2,
         "SHAPE_MISMATCH", "Writer direction needs the selected output width and at least two dimensions")
    direction /= direction.norm()
    delta = -direction[:, None] @ (direction[None, :] @ parent)
    need(float(delta.norm()) > 0, "CONTROL_DEGENERATE", "Selected writer has zero proposed change")
    random_deltas = []
    for i in range(count):
        generator = torch.Generator().manual_seed(seed + i)
        random = torch.randn(direction.shape, generator=generator, dtype=torch.float64)
        random -= (random @ direction) * direction
        need(float(random.norm()) > 1e-12, "CONTROL_DEGENERATE", "Random writer direction is degenerate")
        random /= random.norm()
        change = -random[:, None] @ (random[None, :] @ parent)
        need(float(change.norm()) > 1e-12, "CONTROL_DEGENERATE", "Random writer has zero change")
        random_deltas.append(change * (delta.norm() / change.norm()))
    return delta, random_deltas, "same-support rank-one writer projection with an orthogonal random output direction"


def _norms(patch):
    return (math.sqrt(sum(m["delta_l2"] ** 2 for m in patch["measurements"])),
            math.sqrt(sum(m["storage_delta_l2"] ** 2 for m in patch["storage_measurements"])))


def norm_match(reference, control, tolerance):
    reference_norms, control_norms = _norms(reference), _norms(control)
    results = {}
    for index, name in enumerate(("effective", "storage")):
        target, actual = reference_norms[index], control_norms[index]
        relative = abs(actual - target) / target if target > 0 else None
        results[name] = {"reference_delta_l2": target, "control_delta_l2": actual,
                         "relative_error": relative,
                         "matched": relative is not None and relative <= tolerance}
    return {"basis": "worker-compiled, serialized and reloaded parameters; actual storage precision",
            "relative_tolerance": tolerance, "effective": results["effective"], "storage": results["storage"],
            "passed": all(v["matched"] for v in results.values()),
            "zero_realized_reference_is_a_valid_control": False}


def _comparison(parent, child, plan):
    import torch
    results = {}
    for name in plan.output_names:
        before, after = [x[name].double() for x in parent], [x[name].double() for x in child]
        need(all(a.shape == b.shape for a, b in zip(before, after)), "SHAPE_MISMATCH", "Compared output shapes differ")
        difference = torch.cat([(b - a).reshape(-1) for a, b in zip(before, after)])
        metric = {"delta_rms": float(difference.square().mean().sqrt()),
                  "delta_max_abs": float(difference.abs().max()), "numeric_equal": bool((difference == 0).all())}
        if all(v.shape == after[0].shape for v in after):
            stacked = torch.stack(after)
            metric["case_variation_rms"] = float((stacked - stacked.mean(dim=0)).square().mean().sqrt())
        if name in plan.probability_outputs:
            for tensor in before + after:
                need(tensor.ndim >= 1 and bool((tensor >= 0).all()) and bool((tensor <= 1).all())
                     and bool(torch.allclose(tensor.sum(-1), torch.ones_like(tensor.sum(-1)), atol=1e-4, rtol=1e-4)),
                     "INVALID_PROBABILITIES", "Declared probability output is not a simplex", output=name)
            metric["total_variation_max"] = max(float(.5 * (b - a).abs().sum(-1).max()) for a, b in zip(before, after))
        results[name] = metric
    return results


def run_experiment(call: Callable[[str, dict], dict], opened: dict, plan: dict | ExperimentPlan):
    """Run a precommitted finite screen. ``call`` returns public worker result objects.

    The caller owns transport, durable request ids and failure receipts. The worker
    must be freshly opened with ``required_limits(plan)`` or stricter hard limits.
    A failed run must not be relabelled as completed or silently restarted.
    """
    import torch
    plan = plan if isinstance(plan, ExperimentPlan) else ExperimentPlan.parse(plan)
    need(opened.get("model_id") == plan.model_id and opened.get("backend_id") == plan.backend_id,
         "IDENTITY_MISMATCH", "Experiment belongs to another model or backend")
    need(opened.get("model", {}).get("task_kind") != "regression" or not plan.probability_outputs,
         "TASK_SEMANTICS", "Regression outputs cannot be relabelled as probabilities")
    need(plan.forward_examples <= opened["limits"]["max_forward_examples"] <= plan.budget.max_forward_examples
         and plan.candidate_count <= opened["limits"]["max_patch_candidates"] <= plan.budget.max_patch_candidates,
         "EXPERIMENT_BUDGET", "Worker hard budgets must bind all planned comparisons")
    meter = _Meter(call, plan)
    specification = loads(plan.document)
    target = specification["target"]
    inspected = meter.call("inspect", {"names": [target["tensor"]], "hash": True})
    need(inspected["model_id"] == plan.model_id and inspected["backend_id"] == plan.backend_id
         and len(inspected["rows"]) == 1, "IDENTITY_MISMATCH", "Target inventory differs")
    entry = inspected["rows"][0]
    need(entry["name"] == target["tensor"] and entry.get("patch_allowed") is True
         and entry["tensor_sha256"] == target["expected_tensor_sha256"] and len(entry["shape"]) == 2,
         "IDENTITY_MISMATCH", "Target is not the admitted pinned matrix")
    rows = _selection(target.get("rows"), entry["shape"][0], "rows")
    columns = _selection(target.get("columns"), entry["shape"][1], "columns")
    need(len(rows) * len(columns) <= plan.budget.max_selected_elements,
         "EXPERIMENT_BUDGET", "Select a smaller target block")
    exported = meter.call("inspect", {"export_tensor": True, "tensor": target["tensor"], "rows": rows, "columns": columns})
    need(exported["parent_tensor_sha256"] == target["expected_tensor_sha256"], "IDENTITY_MISMATCH", "Parent changed during export")
    parent_block = meter.tensor(exported["array"], "value", plan.budget.max_selected_elements).double()
    need(tuple(parent_block.shape) == (len(rows), len(columns)), "SHAPE_MISMATCH", "Exported block shape differs")
    delta, random_deltas, random_basis = _deltas(parent_block, target, plan.random_controls, plan.random_seed)
    flat_indices = [r * entry["shape"][1] + c for r in rows for c in columns]
    # All candidate payloads are determined before a single model output is seen.
    conditions = [("dose-" + format(d, ".12g"), "dose", d, delta * d) for d in plan.doses]
    conditions.extend(("random-" + str(i), "random_control", 1.0, d) for i, d in enumerate(random_deltas))
    need(all(bool(torch.isfinite(d).all()) for _, _, _, d in conditions), "NONFINITE", "Non-finite candidate delta")
    condition_manifest = [{"name": n, "role": role, "dose": d,
                           "delta_sha256": digest(change.tolist()), "pre_cast_delta_l2": float(change.norm())}
                          for n, role, d, change in conditions]
    condition_hash = digest(condition_manifest)
    parent_input_ids, physical_hashes = {}, {}

    def observe(patch=None, force_uncached=False):
        retained, arrays = [], []
        for case in plan.cases:
            need(meter.forwards + case.expected_examples <= plan.budget.max_forward_examples,
                 "EXPERIMENT_BUDGET", "Forward budget exhausted")
            params = {"inputs": loads(case.inputs_json)}
            if force_uncached:
                params["bypass_feature_cache"] = True
            if patch is not None:
                params["patch_id"] = patch["patch"]["artifact_id"]
            result = meter.call("probe", params)
            actual = integer(result["input"]["examples"], "examples", 1, 160)
            previous = meter.forwards
            meter.forwards = integer(result["total_forward_examples"], "total_forward_examples", 1, 160)
            need(actual == case.expected_examples and meter.forwards == previous + actual,
                 "FORWARD_COUNT_MISMATCH", "Worker is not fresh or actual batch size differs from the plan")
            encoded = checksum(result["input"]["model_input_id"], "model_input_id")
            if case.case_id in parent_input_ids:
                need(parent_input_ids[case.case_id] == encoded, "INPUT_ENCODING_MISMATCH",
                     "Parent and candidate consumed different encoded inputs", case_id=case.case_id)
            else:
                parent_input_ids[case.case_id] = encoded
            computation = result.get("computation", {})
            if force_uncached and ("feature_cache" in opened.get("model", {}) or "encoder_forward_examples" in computation):
                need(computation.get("encoder_forward_examples") == actual
                     and computation.get("feature_cache_hits") == 0
                     and computation.get("feature_cache_enabled") is False,
                     "PARENT_RECOMPUTE_FAILED", "Final parent did not recompute the encoder without cached features")
            values = {name: meter.tensor(result["outputs"], name, plan.budget.max_output_elements)
                      for name in plan.output_names}
            arrays.append(values)
            retained.append({"case_id": case.case_id, "input_sha256": case.input_sha256,
                             "model_input_id": encoded, "input": result["input"],
                             "outputs": result["outputs"], "evidence": result["evidence"],
                             "model_forward_seconds": result["model_forward_seconds"],
                             "computation": computation, "bypass_feature_cache": force_uncached})
        return retained, arrays

    parent_records, parent_outputs = observe()
    candidates, full_dose = [], None
    for name, role, dose, change in conditions:
        operation = {"tensor": target["tensor"], "expected_tensor_sha256": target["expected_tensor_sha256"],
                     "indices": flat_indices, "compute_dtype": "float64"}
        if role == "dose" and dose == 0:
            # Multiplication preserves signed zero; adding +0 need not do so.
            operation.update(operation="scale", factor=1.0)
        else:
            operation.update(operation="add", value=change.reshape(-1).tolist())
        patch = meter.call("patch", {"expected_model_id": plan.model_id,
                                     "max_relative_norm": target.get("max_relative_norm", 1.0),
                                     "operations": [operation]})
        meter.candidates += 1
        need(patch["patch_candidates"] == meter.candidates <= plan.budget.max_patch_candidates,
             "CANDIDATE_COUNT_MISMATCH", "Worker candidate counter differs from the fixed plan")
        for storage in patch["storage_measurements"]:
            key, value = storage["parameter"], storage["parent_parameter_sha256"]
            need(physical_hashes.setdefault(key, value) == value, "PARENT_RESTORATION_FAILED", "Stored parent changed between candidates")
        records, outputs = observe(patch)
        evidence = {"schema": "hepta.weight.mechanism-candidate.v1", "name": name, "role": role, "dose": dose,
                    "condition_manifest_sha256": condition_hash, "patch": patch, "observations": records,
                    "comparison_to_parent": _comparison(parent_outputs, outputs, plan),
                    "production_eligible": False, "is_efficacy_evidence": False}
        if role == "dose" and dose == 0:
            exact = patch["storage_bytes_unchanged"] and all(a["outputs"]["sha256"] == b["outputs"]["sha256"]
                                                             for a, b in zip(parent_records, records))
            need(exact, "ZERO_DOSE_NOT_NOOP", "Zero dose changed stored bytes or model outputs")
            evidence["zero_dose_exact_noop"] = True
        if role == "dose" and dose == 1:
            full_dose = patch
        if role == "random_control":
            need(full_dose is not None, "INVALID_PLAN", "Full-dose reference missing")
            evidence["random_control"] = {"seed": plan.random_seed + int(name.split("-")[-1]),
                                           "construction": random_basis,
                                           "post_storage_norm_match": norm_match(full_dose, patch, plan.random_norm_rtol)}
        candidates.append(evidence)
    restored_records, restored_outputs = observe(force_uncached=True)
    output_restore = all(a["outputs"]["sha256"] == b["outputs"]["sha256"]
                         for a, b in zip(parent_records, restored_records))
    expected_hashes = {**physical_hashes, target["tensor"]: target["expected_tensor_sha256"]}
    final = meter.call("inspect", {"names": sorted(expected_hashes), "hash": True, "limit": 128})
    actual_hashes = {r["name"]: r["tensor_sha256"] for r in final["rows"]}
    need(actual_hashes == expected_hashes and output_restore, "PARENT_RESTORATION_FAILED",
         "Parent physical parameters, effective target or repeated outputs changed")
    need(meter.forwards == plan.forward_examples and meter.candidates == plan.candidate_count,
         "EXPERIMENT_INCOMPLETE", "Executed comparisons differ from the bound plan")
    return {"schema": RESULT_SCHEMA, "status": "COMPLETED_DEVELOPMENT_SCREEN",
            "experiment_id": plan.experiment_id, "plan_sha256": digest(specification),
            "model_id": plan.model_id, "backend_id": plan.backend_id,
            "data_role": "development", "input_lineage": specification.get("input_lineage", {}),
            "input_lineage_basis": "caller declaration, independently verify before efficacy assessment",
            "diagnosis_present": "hypothesis" in specification, "hypothesis": specification.get("hypothesis"),
            "hypothesis_status": "declared_for_testing" if "hypothesis" in specification else "not_provided",
            "hypothesis_evidence_verified_by_runner": False,
            "condition_manifest": condition_manifest, "condition_manifest_sha256": condition_hash,
            "planned_forward_examples": plan.forward_examples, "planned_patch_candidates": plan.candidate_count,
            "worker_artifact_limits": {name: opened["limits"][name] for name in ("max_artifact_bytes", "max_artifacts_bytes")},
            "parent_before": parent_records, "candidates": candidates, "parent_after": restored_records,
            "parent_restoration": {"exact_stored_parameter_hashes": actual_hashes, "effective_target_hash_verified": True,
                                   "exact_output_bytes_equal": output_restore, "uncached_parent_probe_requested": True,
                                   "final_encoder_recomputed": True if "feature_cache" in opened.get("model", {}) else None,
                                   "passed": True},
            "restored_output_comparison": _comparison(parent_outputs, restored_outputs, plan),
            "cost": meter.cost(), "gradient_steps": 0, "optimizer_calls": 0,
            "production_eligible": False, "new_unseen_or_prospective_data": False,
            "limitations": ["A mechanism screen is not an independent efficacy evaluation",
                            "Output variation and a successful edit do not establish predictive information",
                            "Post-storage norm mismatch invalidates that control; no adaptive retries were made",
                            "Parent restoration covers touched stored parameters, selected effective target and these fixed outputs"]}

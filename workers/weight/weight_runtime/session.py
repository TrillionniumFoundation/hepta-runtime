"""Stateful no-gradient experiments, retained evidence and bounded typed operations."""
from contextlib import ExitStack
import math
import time

from .artifacts import ArtifactStore, PathPolicy, atomic_create
from .errors import canonical, checksum, digest, identifier, integer, need


DEFAULT_LIMITS = {"max_forward_examples": 160, "max_patch_candidates": 16,
                  "max_artifact_bytes": 268435456, "max_artifacts_bytes": 1073741824,
                  "max_capture_elements": 4194304, "max_patch_elements": 16777216}


class Session:
    def __init__(self, session_id):
        self.session_id = identifier(session_id, "session_id")
        self.provider = self.store = self.policy = None
        self.closed = False
        self.forward_examples = self.patch_candidates = 0
        self.limits = dict(DEFAULT_LIMITS)

    def open(self, params):
        need(self.provider is None and not self.closed, "SESSION_STATE", "Session already opened/closed")
        need(not ({"artifact_root", "run_dir"} & set(params)), "INVALID_ARGUMENT", "Use owner-injected output_root")
        self.policy = PathPolicy(params["input_roots"], params["output_root"])
        limits = params.get("limits", {})
        need(isinstance(limits, dict) and set(limits) <= set(DEFAULT_LIMITS), "INVALID_ARGUMENT", "Unknown session limits")
        for key, default in DEFAULT_LIMITS.items():
            self.limits[key] = integer(limits.get(key, default), key, 1, default)
        self.store = ArtifactStore(self.policy.output, self.limits["max_artifact_bytes"], self.limits["max_artifacts_bytes"])
        import torch
        torch.set_num_threads(integer(params.get("cpu_threads", 2), "cpu_threads", 1, 8))
        try:
            torch.set_num_interop_threads(1)
        except RuntimeError:
            need(torch.get_num_interop_threads() == 1, "THREAD_POLICY", "Interop pool has a different initialized limit")
        torch.set_grad_enabled(False)
        from .providers import load_provider
        started = time.monotonic()
        self.provider = load_provider(params.get("provider", "torch_sequential"), params["model"], self.policy, self.store)
        need(math.isfinite(self.provider.global_squared_norm), "NONFINITE", "Non-finite base norm")
        if params.get("expected_model_id") is not None:
            need(params["expected_model_id"] == self.provider.model_id, "IDENTITY_MISMATCH", "Model identity differs")
        self.open_spec_id = digest(params)
        state = {"schema": "hepta.weight.session.v1", "session_id": self.session_id,
                 "open_spec_id": self.open_spec_id, "model_id": self.provider.model_id,
                 "backend_id": self.provider.backend_id, "limits": self.limits,
                 "construction_kind": "DirectWeightEdit", "training_allowed": False,
                 "production_activation_allowed": False}
        atomic_create(self.policy.output / "session.json", canonical(state) + b"\n")
        return {**state, "model": self.provider.describe(), "load_seconds": time.monotonic() - started,
                "output_root": str(self.policy.output),
                "supported_ops": ["inspect", "probe", "intervene", "analyze", "patch", "seal", "query", "close"]}

    def _active(self):
        need(self.provider is not None and not self.closed, "SESSION_STATE", "Open a live model session first")

    def _evidence(self, kind, data):
        body = {"schema": "hepta.weight.evidence.v1", "kind": kind, "session_id": self.session_id,
                "model_id": self.provider.model_id if self.provider else None,
                "backend_id": self.provider.backend_id if self.provider else None,
                "created_at_ms": int(time.time() * 1000), **data}
        return self.store.put_json(body, kind)

    def inspect(self, params):
        self._active()
        from .patches import tensor_sha256, squared_norm
        if params.get("export_tensor"):
            name = params["tensor"]
            tensor = self.provider.get_tensor(name)
            parent_hash = tensor_sha256(tensor)
            from .patches import indices
            selection = {}
            for field, axis in (("rows", 0), ("columns", 1)):
                if field in params:
                    need(tensor.ndim == 2, "SHAPE_MISMATCH", "Row/column selection needs a matrix")
                    selected = indices(params[field], tensor.shape[axis], field)
                    tensor = tensor.index_select(axis, selected)
                    selection[field] = params[field]
            need(tensor.numel() <= self.limits["max_capture_elements"],
                 "CAPTURE_LIMIT", "Tensor export exceeds budget; select a smaller matrix block")
            ref = self.store.put_tensors({"value": tensor}, "inspected-parameter", {
                "model_id": self.provider.model_id, "tensor": name,
                "parent_tensor_sha256": parent_hash, "selection": selection})
            return {"model_id": self.provider.model_id, "backend_id": self.provider.backend_id,
                    "tensor": name, "parent_tensor_sha256": parent_hash, "selection": selection,
                    "shape": list(tensor.shape), "dtype": str(tensor.dtype), "array": ref}
        offset, limit = integer(params.get("offset", 0), "offset"), integer(params.get("limit", 32), "limit", 1, 128)
        if params.get("collection") == "modules":
            rows = [{"index": i, "name": n, "type": type(m).__module__ + "." + type(m).__name__}
                    for i, (n, m) in enumerate(self.provider.module.named_modules())]
        else:
            names = self.provider.tensor_names()
            if "names" in params:
                need(isinstance(params["names"], list) and all(n in names for n in params["names"]), "UNKNOWN_TENSOR", "Unknown selected tensor")
                names = [n for n in names if n in params["names"]]
            rows = []
            for i, name in enumerate(names):
                if not offset <= i < offset + limit:
                    rows.append(None)
                    continue
                tensor = self.provider.get_tensor(name)
                row = {"index": i, "name": name, "shape": list(tensor.shape), "dtype": str(tensor.dtype),
                       "elements": tensor.numel(), "patch_allowed": name in self.provider.allowed_targets}
                if params.get("hash", False):
                    row["tensor_sha256"] = tensor_sha256(tensor)
                if params.get("statistics", False):
                    row.update(l2=math.sqrt(squared_norm(tensor)), minimum=float(tensor.min()), maximum=float(tensor.max()))
                rows.append(row)
        return {"model_id": self.provider.model_id, "backend_id": self.provider.backend_id,
                "total": len(rows), "offset": offset, "rows": rows[offset:offset + limit],
                "next_offset": offset + limit if offset + limit < len(rows) else None}

    def _load_patch(self, artifact_id):
        record = self.store.load_json(artifact_id)
        need(record.get("schema") == "hepta.weight.patch.v1" and record.get("model_id") == self.provider.model_id
             and record.get("backend_id") == self.provider.backend_id,
             "IDENTITY_MISMATCH", "Patch belongs to another base model")
        from .patches import tensor_sha256
        replacements = self.store.load_tensors(record["parameters"]["artifact_id"])
        need(set(replacements) == set(record["parent_parameter_hashes"]), "IDENTITY_MISMATCH", "Patch parameter inventory changed")
        for name in replacements:
            need(name in self.provider.parameters and tensor_sha256(self.provider.parameters[name]) == record["parent_parameter_hashes"][name],
                 "IDENTITY_MISMATCH", "Live parent parameter differs", tensor=name)
        return record, replacements

    def probe(self, params, intervention=False):
        self._active()
        import torch
        from .hooks import install_hooks
        need(not (self.provider.task_kind == "regression" and "softmax_output" in params),
             "TASK_SEMANTICS", "Regression values cannot be converted to class probabilities")
        need(type(params.get("bypass_feature_cache", False)) is bool,
             "INVALID_ARGUMENT", "bypass_feature_cache must be boolean")
        prepare_started = time.monotonic()
        inputs = params["inputs"]
        args, kwargs, meta = self.provider.prepare_inputs(inputs)
        prepare_seconds = time.monotonic() - prepare_started
        examples = integer(meta["examples"], "examples", 1, self.limits["max_forward_examples"])
        need(self.forward_examples + examples <= self.limits["max_forward_examples"], "FORWARD_BUDGET", "Forward example budget exhausted")
        interventions = params.get("interventions", [])
        need(intervention or not interventions, "INVALID_ARGUMENT", "Use intervene for activation changes")
        replacements = {}
        if params.get("patch_id"):
            _, replacements = self._load_patch(params["patch_id"])
        captured = {}
        self.forward_examples += examples
        started = time.monotonic()
        with ExitStack() as stack:
            stack.enter_context(torch.inference_mode())
            stack.enter_context(self.provider.temporary_patch(replacements))
            stack.enter_context(self.provider.probe_context(replacements, params.get("captures", []), interventions,
                                                           params.get("bypass_feature_cache", False)))
            install_hooks(self.provider, self.store, params.get("captures", []), interventions,
                          captured, stack, self.limits["max_capture_elements"])
            model_started = time.monotonic()
            outputs = self.provider.forward(args, kwargs)
            model_seconds = time.monotonic() - model_started
            for name, value in outputs.items():
                need(isinstance(value, torch.Tensor) and bool(torch.isfinite(value).all()), "NONFINITE", "Invalid model output", output=name)
            if "softmax_output" in params:
                key = params["softmax_output"]
                need(key in outputs and outputs[key].is_floating_point(), "INVALID_ARGUMENT", "Unknown softmax output")
                outputs["probabilities"] = outputs[key].float().softmax(-1)
            output_ref = self.store.put_tensors(outputs, "model-outputs")
            capture_ref = self.store.put_tensors(captured, "activations", {
                "captures": params.get("captures", []), "capture_before_intervention_at_same_hook": True,
                "input": meta}) if captured else None
        need(all(p.grad is None for p in self.provider.module.parameters()), "GRADIENT_STATE", "Unexpected gradient storage")
        record = {"input": meta, "input_spec": inputs, "patch_id": params.get("patch_id"), "outputs": output_ref,
                  "task_kind": self.provider.task_kind,
                  "computation": dict(self.provider.last_probe_metrics),
                  "input_prepare_seconds": prepare_seconds,
                  "bypass_feature_cache": params.get("bypass_feature_cache", False),
                  "activations": capture_ref, "captures": params.get("captures", []), "interventions": interventions,
                  "forward_seconds": time.monotonic() - started, "forward_examples": examples,
                  "model_forward_seconds": model_seconds,
                  "forward_seconds_scope": "probe including temporary patch, hooks and artifact persistence",
                  "total_forward_examples": self.forward_examples, "gradient_steps": 0, "optimizer_calls": 0,
                  "mode": "DEVELOPMENT_OBSERVATION", "is_prospective_evaluation": False}
        evidence = self._evidence("intervention" if intervention else "probe", record)
        return {"evidence": evidence, "input": meta, "outputs": output_ref, "activations": capture_ref,
                "task_kind": self.provider.task_kind, "computation": record["computation"],
                "input_prepare_seconds": prepare_seconds,
                "forward_seconds": record["forward_seconds"], "model_forward_seconds": model_seconds,
                "total_forward_examples": self.forward_examples}

    def analyze(self, params):
        self._active()
        from .analysis import analyze
        result = analyze(params, self.store, self.limits["max_capture_elements"])
        return {**result, "evidence": self._evidence("analysis", {"inputs": params, **result})}

    def patch(self, params):
        self._active()
        from .patches import edit_tensor, patch_metrics, tensor_sha256
        need(params.get("expected_model_id") == self.provider.model_id, "IDENTITY_MISMATCH", "Explicit expected_model_id is required")
        need(self.patch_candidates < self.limits["max_patch_candidates"], "PATCH_BUDGET", "Candidate budget exhausted")
        specs = params.get("operations")
        need(isinstance(specs, list) and 1 <= len(specs) <= 16, "INVALID_ARGUMENT", "Expected 1..16 typed operations")
        need(len({s.get("tensor") for s in specs}) == len(specs), "INVALID_ARGUMENT", "One operation per target per patch")
        self.patch_candidates += 1
        replacements, parent_hashes, measurements = {}, {}, []
        delta_squared = 0.0
        for spec in specs:
            name = spec["tensor"]
            before = self.provider.get_tensor(name)
            requested, rounding = edit_tensor(before, spec, self.store, self.limits["max_patch_elements"])
            storage, realized = self.provider.compile_tensor(name, requested)
            need(not (set(storage) & set(replacements)), "PATCH_SCOPE", "Overlapping aliased/effective patch targets")
            metrics = patch_metrics(before, realized, self.provider.global_squared_norm)
            if "max_relative_norm" in params:
                from .errors import number
                limit = number(params["max_relative_norm"], "max_relative_norm")
                need(0 <= limit <= 16 and metrics["tensor_relative_norm"] is not None
                     and metrics["tensor_relative_norm"] <= limit, "PATCH_NORM_LIMIT", "Realized tensor norm exceeds requested limit")
            delta_squared += metrics["delta_l2"] ** 2
            measurements.append({"tensor": name, "parent_tensor_sha256": tensor_sha256(before), **rounding, **metrics,
                                 "compiled_parameter_names": sorted(storage),
                                 "realization_max_abs_error": float((realized.double() - requested.double()).abs().max())})
            for key, value in storage.items():
                parent_hashes[key] = tensor_sha256(self.provider.parameters[key])
                replacements[key] = value
        parameter_ref = self.store.put_tensors(replacements, "patch-parameters")
        reloaded = self.store.load_tensors(parameter_ref["artifact_id"])
        need(all(tensor_sha256(reloaded[k]) == tensor_sha256(v) for k, v in replacements.items()),
             "IDENTITY_MISMATCH", "Serialized candidate changed dtype/bytes")
        storage_measurements = []
        for name, value in sorted(reloaded.items()):
            physical = patch_metrics(self.provider.parameters[name].detach().cpu(), value,
                                     self.provider.global_squared_norm)
            final_hash = physical["final_tensor_sha256"]
            storage_measurements.append({"parameter": name, "parent_parameter_sha256": parent_hashes[name],
                                         "final_parameter_sha256": final_hash,
                                         "storage_changed_coordinates": physical["effective_changed_coordinates"],
                                         "storage_delta_l2": physical["delta_l2"],
                                         "storage_delta_max_abs": physical["delta_max_abs"],
                                         "bytes_unchanged": parent_hashes[name] == final_hash})
        storage_changed = sum(m["storage_changed_coordinates"] for m in storage_measurements)
        storage_parameters_changed = sum(not m["bytes_unchanged"] for m in storage_measurements)
        storage_bytes_unchanged = storage_parameters_changed == 0
        global_relative = math.sqrt(delta_squared / self.provider.global_squared_norm) if self.provider.global_squared_norm else None
        changed = sum(m["effective_changed_coordinates"] for m in measurements)
        record = {"schema": "hepta.weight.patch.v1", "model_id": self.provider.model_id,
                  "backend_id": self.provider.backend_id, "construction_kind": "DirectWeightEdit",
                  "parameters": parameter_ref, "parent_parameter_hashes": parent_hashes,
                  "encoded_patch_bytes": parameter_ref["byte_length"],
                  "stored_parameter_elements": sum(t.numel() for t in replacements.values()),
                  "operations": specs, "measurements": measurements,
                  "storage_measurements": storage_measurements,
                  "storage_changed_coordinates": storage_changed,
                  "storage_changed_parameters": storage_parameters_changed,
                  "storage_bytes_unchanged": storage_bytes_unchanged,
                  "no_op_basis": "Exact stored-parameter byte equality; zero effective-matrix coordinate changes alone do not establish an execution no-op",
                  "effective_changed_coordinates": changed, "global_relative_norm": global_relative,
                  "reference_numeric_screen": {"per_tensor_reference_limit": 0.005, "global_reference_limit": 0.0025,
                      "coordinate_reference_limit": 4096,
                      "norm_basis": "unique effective weights across the whole loaded model; per-target tensor norms; not the legacy adapter-only production profile",
                      "research_only": True, "production_policy_evaluated": False,
                      "within_numeric_limits": global_relative is not None and global_relative <= 0.0025 and changed <= 4096
                          and all(m["tensor_relative_norm"] is not None and m["tensor_relative_norm"] <= 0.005 for m in measurements),
                      "is_production_approval": False},
                  "gradient_steps": 0, "optimizer_calls": 0, "production_eligible": False,
                  "active_weights_overwritten": False, "created_at_ms": int(time.time() * 1000)}
        patch = self.store.put_json(record, "weight-patch")
        return {"patch": patch, "parameters": parameter_ref, "measurements": measurements,
                "storage_measurements": storage_measurements,
                "storage_changed_coordinates": storage_changed,
                "storage_changed_parameters": storage_parameters_changed,
                "storage_bytes_unchanged": storage_bytes_unchanged,
                "effective_changed_coordinates": changed, "global_relative_norm": global_relative,
                "production_eligible": False, "patch_candidates": self.patch_candidates}

    def seal(self, params):
        self._active()
        self._load_patch(params["patch_id"])
        cutoff = integer(params["information_cutoff_ms"], "information_cutoff_ms")
        need(cutoff <= int(time.time() * 1000), "CAUSALITY", "Information cutoff cannot be in the future")
        checksum(params["evaluation_protocol_sha256"], "evaluation_protocol_sha256")
        calibration = self.store.ref(params["calibration_artifact_id"]) if params.get("calibration_artifact_id") else None
        value = {"schema": "hepta.weight.sealed-candidate.v1", "construction_kind": "DirectWeightEdit",
                 "model_id": self.provider.model_id, "backend_id": self.provider.backend_id,
                 "patch": self.store.ref(params["patch_id"]), "calibration": calibration,
                 "evaluation_protocol_sha256": params["evaluation_protocol_sha256"],
                 "information_cutoff_ms": cutoff, "information_cutoff_basis": "caller declaration; independent evaluator must verify lineage",
                 "sealed_at_ms": int(time.time() * 1000), "gradient_steps": 0, "optimizer_calls": 0,
                 "status": "SEALED_RESEARCH_CANDIDATE", "production_eligible": False,
                 "requires_independent_evaluation": True, "active_weights_overwritten": False}
        value["candidate_id"] = digest(value)
        return {"candidate_id": value["candidate_id"], "candidate": self.store.put_json(value, "sealed-candidate"),
                "status": value["status"], "production_eligible": False}

    def query(self, params):
        need(self.store is not None, "SESSION_STATE", "No retained artifact store")
        artifact_id = params["artifact_id"]
        reference = self.store.ref(artifact_id)
        if "tensor" in params:
            tensors = self.store.load_tensors(artifact_id)
            name = params["tensor"]
            need(name in tensors, "UNKNOWN_TENSOR", "Unknown retained tensor")
            tensor = tensors[name]
            offset, limit = integer(params.get("offset", 0), "offset"), integer(params.get("limit", 64), "limit", 1, 1024)
            values = tensor.reshape(-1)[offset:offset + limit].tolist()
            return {"artifact": reference, "tensor": name, "shape": list(tensor.shape), "dtype": str(tensor.dtype),
                    "offset": offset, "values": values, "total_elements": tensor.numel(),
                    "next_offset": offset + len(values) if offset + len(values) < tensor.numel() else None}
        if params.get("view", "summary") == "json":
            value = self.store.load_json(artifact_id)
            if "fields" in params:
                need(isinstance(params["fields"], list), "INVALID_ARGUMENT", "fields must be a list")
                value = {k: value[k] for k in params["fields"] if k in value}
            need(len(canonical(value)) <= 262144, "VIEW_LIMIT", "Select fields for a bounded JSON view")
            return {"artifact": reference, "value": value, "historical_evidence": True}
        return {"artifact": reference, "historical_evidence": True, "source_file_reopened": False}

    def close(self, params):
        if self.provider is not None:
            self.provider.close()
            self.provider = None
        self.closed = True
        return {"session_id": self.session_id, "closed": True, "forward_examples": self.forward_examples,
                "patch_candidates": self.patch_candidates, "artifacts_retained": self.store is not None}

    def dispatch(self, op, params):
        handlers = {"open": self.open, "inspect": self.inspect, "probe": self.probe,
                    "intervene": lambda p: self.probe(p, intervention=True), "analyze": self.analyze,
                    "patch": self.patch, "seal": self.seal, "query": self.query, "close": self.close}
        need(op in handlers, "UNSUPPORTED_OPERATION", "Unknown worker operation", operation=op)
        return handlers[op](params)

"""Explicit model adapters. Loading declarations alone never claims inference support."""
from contextlib import contextmanager
import importlib
from pathlib import Path
import sys

from .artifacts import file_sha256
from .errors import digest, integer, loads, need, WeightError
from .patches import checked_tensor, squared_norm, tensor_sha256


def source_tree_identity(root):
    root = Path(root)
    files = sorted(root.rglob("*.py"))
    need(files, "INVALID_MODEL", "No Python source in pinned source directory")
    return digest({p.relative_to(root).as_posix(): file_sha256(p) for p in files})


class TorchProvider:
    name = "torch_sequential"
    task_kind = "tensor"

    def __init__(self, module, identity, store, allowed_targets=None, freeze_parameters=True):
        import torch
        self.module, self.identity, self.store = module, identity, store
        self.module.eval()
        if freeze_parameters:
            self.module.requires_grad_(False)
        self.parameters = dict(module.named_parameters(remove_duplicate=False))
        need(self.parameters, "INVALID_MODEL", "Model has no parameters")
        need(all(p.device.type == "cpu" for p in self.parameters.values()), "UNSUPPORTED_DEVICE", "This provider supports CPU only")
        self.aliases = {}
        self.canonical_names = {}
        for name, parameter in self.parameters.items():
            key = (parameter.data_ptr(), tuple(parameter.shape), tuple(parameter.stride()))
            canonical = self.canonical_names.setdefault(key, name)
            self.aliases[name] = canonical
        self.allowed_targets = set(allowed_targets if allowed_targets is not None else self.parameters)
        self.model_id = digest(identity)
        package_root = Path(__file__).resolve().parent
        code_files = [package_root.parent / "worker.py"] + sorted(package_root.glob("*.py"))
        code_identity = digest({p.relative_to(package_root.parent).as_posix(): file_sha256(p) for p in code_files})
        self.backend = {"provider": self.name, "torch_version": torch.__version__, "device": "cpu",
                        "threads": torch.get_num_threads(), "interop_threads": torch.get_num_interop_threads(),
                        "worker_package_sha256": code_identity, "inference_mode": True, "training": False}
        self.backend_id = digest(self.backend)
        self.global_squared_norm = self._global_squared_norm()

    def _global_squared_norm(self):
        total = 0.0
        for parameter in self.module.parameters():
            if parameter.is_floating_point():
                import torch
                need(bool(torch.isfinite(parameter).all()), "NONFINITE", "Base contains non-finite parameters")
                total += squared_norm(parameter)
        return total

    def tensor_names(self):
        return sorted(self.parameters)

    def get_tensor(self, name):
        need(name in self.parameters, "UNKNOWN_TENSOR", "Unknown model parameter", tensor=name)
        return self.parameters[name].detach().cpu().clone()

    def compile_tensor(self, name, value):
        need(name in self.allowed_targets, "PATCH_SCOPE", "Target is not admitted for this session", tensor=name)
        before = self.get_tensor(name)
        need(before.shape == value.shape and before.dtype == value.dtype, "SHAPE_MISMATCH", "Compiled tensor shape/dtype differs")
        return {self.aliases[name]: value}, value

    @contextmanager
    def temporary_patch(self, replacements):
        import torch
        originals = {}
        try:
            with torch.inference_mode():
                for name, value in replacements.items():
                    need(name in self.parameters, "UNKNOWN_TENSOR", "Unknown stored patch parameter", tensor=name)
                    parameter = self.parameters[name]
                    need(parameter.shape == value.shape and parameter.dtype == value.dtype,
                         "SHAPE_MISMATCH", "Stored patch shape/dtype differs", tensor=name)
                    need(bool(torch.isfinite(value).all()), "NONFINITE", "Stored patch contains non-finite values")
                    originals[name] = parameter.detach().clone()
                    parameter.copy_(value)
            yield
        finally:
            with torch.inference_mode():
                for name, value in originals.items():
                    self.parameters[name].copy_(value)

    def prepare_inputs(self, inputs):
        import torch
        need(isinstance(inputs, dict) and set(inputs) == {"x"}, "INVALID_INPUT", "Sequential inputs must contain only x")
        dtype = next(iter(self.parameters.values())).dtype
        x = checked_tensor(inputs["x"], self.store, dtype, "x")
        need(x.ndim >= 1 and x.numel() <= 1048576, "INPUT_LIMIT", "Input shape/size exceeds budget")
        return (x,), {}, {"examples": x.shape[0] if x.ndim > 1 else 1, "input_id": digest(inputs),
                         "model_input_id": tensor_sha256(x)}

    def forward(self, args, kwargs):
        import torch
        value = self.module(*args, **kwargs)
        if isinstance(value, torch.Tensor):
            return {"output": value}
        if isinstance(value, dict) and all(isinstance(v, torch.Tensor) for v in value.values()):
            return value
        raise WeightError("UNSUPPORTED_OUTPUT", "Provider must expose named tensor outputs")

    @contextmanager
    def probe_context(self, replacements, captures, interventions, force_uncached=False):
        """Providers may account for work or bypass caches for instrumented probes."""
        self.last_probe_metrics = {"feature_cache_enabled": False}
        yield

    def describe(self):
        return {"provider": self.name, "model_id": self.model_id, "identity": self.identity,
                "task_kind": self.task_kind,
                "backend_id": self.backend_id, "backend": self.backend,
                "capabilities": ["inspect", "probe", "intervene", "analyze", "patch", "seal", "query"],
                "allowed_patch_targets": sorted(self.allowed_targets),
                "global_effective_squared_norm": self.global_squared_norm,
                "limitations": ["CPU only", "No training or production activation", "No arbitrary pickle/module deserialization"]}

    def close(self):
        self.parameters.clear()
        self.module = None


def load_sequential(config, policy, store):
    import torch
    from torch import nn
    from safetensors import safe_open
    from safetensors.torch import load_file
    architecture = config.get("architecture")
    need(isinstance(architecture, dict) and set(architecture) == {"layers"}, "INVALID_MODEL", "Expected declarative sequential architecture")
    layers = architecture["layers"]
    need(isinstance(layers, list) and 1 <= len(layers) <= 64, "INVALID_MODEL", "Expected 1..64 layers")
    constructors = {
        "Linear": (nn.Linear, {"in_features", "out_features", "bias"}),
        "ReLU": (nn.ReLU, set()), "Tanh": (nn.Tanh, set()),
        "GELU": (nn.GELU, {"approximate"}), "Sigmoid": (nn.Sigmoid, set()),
        "LayerNorm": (nn.LayerNorm, {"normalized_shape", "eps", "elementwise_affine", "bias"}),
        "Flatten": (nn.Flatten, {"start_dim", "end_dim"}),
        "Identity": (nn.Identity, set()), "Softmax": (nn.Softmax, {"dim"}),
    }
    modules = []
    with torch.device("meta"):
        for spec in layers:
            need(isinstance(spec, dict) and spec.get("type") in constructors, "UNSUPPORTED_MODEL", "Unsupported declarative layer")
            constructor, allowed = constructors[spec["type"]]
            need(set(spec) <= allowed | {"type"}, "INVALID_MODEL", "Unknown layer arguments")
            modules.append(constructor(**{k: v for k, v in spec.items() if k != "type"}))
        module = nn.Sequential(*modules)
    model_file = policy.bound(config["weights_path"], config["weights_sha256"])
    maximum = integer(config.get("max_parameters", 100000000), "max_parameters", 1, 100000000)
    with safe_open(str(model_file), framework="pt", device="cpu") as weights:
        count = sum(__import__("math").prod(weights.get_slice(k).get_shape()) for k in weights.keys())
        need(count <= maximum, "MODEL_LIMIT", "Model parameter count exceeds declaration budget")
    state = load_file(str(model_file), device="cpu")
    expected = module.state_dict()
    need(set(state) == set(expected), "SHAPE_MISMATCH", "Weights do not match the declared graph")
    for name, value in state.items():
        need(value.shape == expected[name].shape and value.is_floating_point()
             and bool(torch.isfinite(value).all()), "SHAPE_MISMATCH", "Invalid weight shape/dtype/value", tensor=name)
    module.load_state_dict(state, strict=True, assign=True)
    identity = {"provider": "torch_sequential", "architecture": architecture,
                "architecture_sha256": digest(architecture), "weights_sha256": config["weights_sha256"]}
    if "architecture_sha256" in config:
        need(config["architecture_sha256"] == identity["architecture_sha256"], "IDENTITY_MISMATCH", "Architecture hash differs")
    return TorchProvider(module, identity, store, config.get("allowed_patch_targets"))


class LayaProvider(TorchProvider):
    name = "laya"
    task_kind = "classification"

    def __init__(self, cell, tokenizer, identity, store, encode, allowed_targets=None):
        self.tokenizer, self.encode = tokenizer, encode
        super().__init__(cell, identity, store,
                         allowed_targets if allowed_targets is not None else ["effective.scorer.3.weight"], freeze_parameters=False)
        need(self.allowed_targets <= set(self.tensor_names()), "PATCH_SCOPE", "Laya research allowlist names a missing tensor")

    def _global_squared_norm(self):
        total = 0.0
        adapter_prefixes = ["model." + name for name in self.module.adapters]
        for name, parameter in self.module.named_parameters():
            if any(name in (prefix + ".A", prefix + ".B", prefix + ".base.weight") for prefix in adapter_prefixes):
                continue
            total += squared_norm(parameter)
        for adapter in self.module.adapters.values():
            total += squared_norm(adapter.full_effective_weight())
        return total

    def tensor_names(self):
        return super().tensor_names() + ["effective.scorer.3.weight"]

    def get_tensor(self, name):
        if name == "effective.scorer.3.weight":
            return self.module.adapters["scorer.3"].full_effective_weight().detach().cpu().clone()
        return super().get_tensor(name)

    def compile_tensor(self, name, value):
        import torch
        need(name in self.allowed_targets, "PATCH_SCOPE", "Target not in the explicit research allowlist")
        if name != "effective.scorer.3.weight":
            return super().compile_tensor(name, value)
        adapter = self.module.adapters["scorer.3"]
        base = adapter.base.weight.detach().cpu()
        need(value.shape == base.shape and value.dtype == base.dtype and base.shape[0] == 1,
             "SHAPE_MISMATCH", "Expected the pinned single-row Laya final scorer")
        rows = adapter.row_index.detach().cpu()
        need(rows.tolist() == [0] and tuple(adapter.A.shape) == (1, base.shape[1])
             and tuple(adapter.B.shape) == (1, 1), "UNSUPPORTED_MODEL", "Laya final adapter layout differs")
        before = self.get_tensor(name)
        if tensor_sha256(value) == tensor_sha256(before):
            # A merged matrix can lose sub-ULP LoRA contributions that the nested
            # forward still computes. An unchanged target must preserve its factors.
            return {"model.scorer.3.A": adapter.A.detach().cpu().clone(),
                    "model.scorer.3.B": adapter.B.detach().cpu().clone()}, before
        a, b = (value - base).to(base.dtype), torch.ones_like(adapter.B.detach().cpu())
        realized = base.index_add(0, rows, b @ a)
        return {"model.scorer.3.A": a, "model.scorer.3.B": b}, realized

    def prepare_inputs(self, inputs):
        import torch
        need(isinstance(inputs, dict) and set(inputs) <= {"state", "order", "parallel_layout"} and "state" in inputs,
             "INVALID_INPUT", "Laya inputs require a causal state and optional option order")
        state, order = inputs["state"], inputs.get("order", list(range(7)))
        need(isinstance(order, list) and all(type(i) is int for i in order) and sorted(order) == list(range(7)),
             "INVALID_INPUT", "Expected a permutation of seven options")
        need(type(inputs.get("parallel_layout", False)) is bool, "INVALID_INPUT", "parallel_layout must be boolean")
        batch, meta = self.encode(self.tokenizer, state, order, inputs.get("parallel_layout", False))
        self._order = order
        self.marker_positions = batch["marker_pos"].detach().cpu()
        meta.update(examples=1, input_id=digest(state), semantic_option_order=order,
                    model_input_id=digest({k: v.tolist() for k, v in batch.items()}))
        return (), batch, meta

    def forward(self, args, kwargs):
        import torch
        price, action = self.module(**kwargs)
        inverse = torch.argsort(torch.tensor(self._order))
        price = price.index_select(-1, inverse)
        return {"price_logits": price, "price_probabilities": price.float().softmax(-1),
                "action_logits": action, "action_probabilities": action.float().softmax(-1)}

    def close(self):
        self.tokenizer = self.encode = None
        super().close()


def normalize_laya_state(state, causal_fields):
    need(isinstance(state, dict) and set(causal_fields) <= set(state), "INVALID_INPUT", "Missing causal state fields")
    need(not (set(state) - set(causal_fields)), "INVALID_INPUT", "Unexpected state fields; outcome labels are not inputs")
    # Match the pinned dataset.encode_rows contract. Upstream JSON tokenization
    # preserves insertion order, whereas retained canonical JSON sorts its keys.
    return {name: state[name] for name in causal_fields}


def make_laya_encoder(dataset, common):
    """Build the production-compatible tokenizer path without loading model weights."""
    causal_fields = tuple(dataset.CAUSAL_STATE_FIELDS)
    def encode(tokenizer, state, order, parallel):
        state = normalize_laya_state(state, causal_fields)
        result = common.build_sequence(tokenizer, state, dataset.question(300), max_len=1024, head_max_len=256,
                                       option_order=order, return_stats=True, return_truncation_stats=True, return_layout=parallel)
        ids, markers, stats, truncation = result[:4]
        need(len(markers) == 7 and stats["options_distinct"] == 7 and not truncation["truncated"],
             "INVALID_INPUT", "Laya option identities or truncation changed")
        item = {"ids": ids, "markers": markers, "qtype": 0}
        if parallel:
            item["layout"] = result[4]
        batch = common.collate_items([[item]], tokenizer.pad_token_id)
        keys = ["input_ids", "attention_mask", "marker_pos", "marker_mask", "qtype"]
        if parallel:
            keys += ["position_ids", "option_ids"]
        return {k: batch[k] for k in keys}, {"tokens": len(ids), "markers": markers, "truncation": truncation,
                                         "parallel_layout": parallel, "state_field_order": list(causal_fields),
                                         "state_encoding": "pinned_dataset_causal_state_order"}
    return encode


def load_laya(config, policy, store):
    import torch
    from safetensors.torch import load_file
    source = policy.read(config["source_dir"], directory=True)
    for path in source.rglob("*.py"):
        policy.read(path)
    source_hash = source_tree_identity(source)
    need(source_hash == config["source_tree_sha256"], "IDENTITY_MISMATCH", "Pinned Laya source tree differs")
    base = policy.read(config["base_dir"], directory=True)
    for path in base.rglob("*"):
        if path.is_file() or path.is_symlink():
            policy.read(path, directory=path.is_dir())
    manifest_path = policy.bound(str(base / "base-manifest.json"), config["base_manifest_sha256"])
    parent = policy.bound(config["parent_adapter_path"], config["parent_adapter_sha256"])
    sys.path.insert(0, str(source))
    model_module = importlib.import_module("laya_cell.model")
    resident_module = importlib.import_module("laya_cell.resident_model")
    dataset = importlib.import_module("laya_cell.dataset")
    common = importlib.import_module("laya.common")
    for imported in (model_module, resident_module, dataset):
        need(Path(imported.__file__).resolve().is_relative_to(source), "IDENTITY_MISMATCH", "Laya module was imported from another release")
    pretrained, tokenizer, base_id = model_module.load_verified_laya(base, loads(manifest_path.read_bytes()), enforce_gpu=False)
    cell = resident_module.ResidentDecisionCell(pretrained, base_id)
    cell.restore_parent(load_file(str(parent), device="cpu"), allow_scorer_only=True)
    cell.eval()

    identity = {"provider": "laya", "base_id": base_id,
                "base_manifest_sha256": config["base_manifest_sha256"],
                "parent_adapter_sha256": config["parent_adapter_sha256"],
                "source_tree_sha256": source_hash, "common_code_sha256": file_sha256(common.__file__)}
    allowed = config.get("allowed_patch_targets", ["effective.scorer.3.weight"])
    import re
    need(isinstance(allowed, list) and all(n == "effective.scorer.3.weight" or
         re.fullmatch(r"model\.(encoder\.layers\.[0-9]+\.mlp\.Wo|head\.layers\.[0-9]+\.linear2)\.weight", n)
         for n in allowed), "PATCH_SCOPE", "Laya allowlist includes an unsupported research target")
    return LayaProvider(cell, tokenizer, identity, store, make_laya_encoder(dataset, common), allowed)


def load_provider(name, config, policy, store):
    if name in ("torch_sequential", "torch_fixture"):
        return load_sequential(config, policy, store)
    if name == "laya":
        return load_laya(config, policy, store)
    if name == "current100k_value":
        from .current100k import load_current100k
        return load_current100k(config, policy, store)
    if name == "mit_qwen_reference":
        from .qwen import load_qwen
        return load_qwen(config, policy, store)
    raise WeightError("UNSUPPORTED_PROVIDER", "Provider is not implemented", {"provider": name})

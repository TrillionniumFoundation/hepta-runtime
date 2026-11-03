"""Current100k USD regression over the pinned Laya encoder and a separate head.

This is a CPU research adapter. It preserves the serial tokenizer/encoder and
masked-mean/L2 computation used by Current100k; it does not implement the Laya
seven-option decision task, authenticate market records, or activate a model.
"""
from collections import OrderedDict
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import importlib
from pathlib import Path
import sys

from .artifacts import file_sha256
from .errors import checksum, digest, integer, loads, need
from .patches import tensor_sha256
from .providers import TorchProvider, source_tree_identity


FEATURE_WIDTH = 768
MAX_TOKENS = 2048
MAX_ROWS = 64
SCALE_USD = 100.0
HEAD_MAX_BYTES = 128 * 1024
CACHE_MAX_ENTRIES = 128
CONTRACT = {
    "schema": "hepta.weight.current100k-contract.v1",
    "task": "eventual_roundtrip_net_usd_after_reported_execution_commissions",
    "instrument": "EUR.USD", "currency": "USD", "reference_notional_usd": 100000,
    "feature_width": FEATURE_WIDTH, "pooling": "MASKED_MEAN_L2_NORMALIZED",
    "normalization_eps": 1e-12, "encoder_batch_size": 1,
    "head_batch": "all_ordered_rows_after_serial_feature_extraction",
    "tokenization": "padding=True,truncation=False,return_tensors=pt",
    "max_tokens": MAX_TOKENS, "dtype": "float32", "output_scale_usd": SCALE_USD,
    "outputs": {"features": "normalized_encoder_features",
                "value_scaled": "raw_linear_readout",
                "value_usd": "100_times_raw_linear_readout"},
    "clipping": None, "classification": False,
}


def feature_text(request, action):
    """The Current100k input-only template; caller must verify original provenance."""
    need(isinstance(request, dict) and action in ("BUY", "SELL"),
         "INVALID_INPUT", "Expected a request and BUY/SELL action")
    need(request.get("instrument") == "EUR.USD" and request.get("position_at_request") == 0
         and type(request.get("position_at_request")) is not bool,
         "INVALID_INPUT", "Current100k requires EUR.USD and a flat original request")
    need(isinstance(request.get("prompt"), str) and bool(request["prompt"])
         and isinstance(request.get("model_id"), str) and bool(request["model_id"]),
         "INVALID_INPUT", "Original prompt and behavior model are required")
    return (request["prompt"] +
            "\nFinancial value context: EUR.USD; requested reference notional budget=100000 USD; " +
            "selected action=" + action + "; behavior model=" + request["model_id"] +
            ". Predict eventual roundtrip net USD after reported execution commissions.")


def validate_rows(value):
    """Accept frozen input-only rows, never label-bearing dataset records."""
    required = {"row_id", "input_id", "request_id", "action", "input_started_at_ms",
                "feature_text", "feature_text_sha256"}
    optional = {"source_request_sha256", "source_record_sha256"}
    need(isinstance(value, list) and 1 <= len(value) <= MAX_ROWS,
         "INPUT_LIMIT", "Expected 1..64 frozen Current100k input rows")
    rows, identities, request_actions = [], set(), set()
    for row in value:
        need(isinstance(row, dict) and required <= set(row) and set(row) <= required | optional,
             "INVALID_INPUT", "Current100k rows require the exact input-only schema")
        for name in ("row_id", "input_id", "request_id"):
            need(isinstance(row[name], str) and 1 <= len(row[name]) <= 256,
                 "INVALID_INPUT", "Invalid frozen row identifier", field=name)
        integer(row["input_started_at_ms"], "input_started_at_ms", 1)
        need(row["action"] in ("BUY", "SELL"), "INVALID_INPUT", "Expected BUY or SELL")
        text = row["feature_text"]
        need(isinstance(text, str) and 1 <= len(text.encode("utf-8")) <= 128 * 1024,
             "INPUT_LIMIT", "Feature text must be nonempty bounded UTF-8")
        checksum(row["feature_text_sha256"], "feature_text_sha256")
        need(hashlib.sha256(text.encode("utf-8")).hexdigest() == row["feature_text_sha256"],
             "IDENTITY_MISMATCH", "Frozen feature text SHA256 differs")
        # Check the task/action suffix as well as bytes: a 25k row cannot silently
        # become a Current100k row merely by changing its surrounding metadata.
        marker = ("\nFinancial value context: EUR.USD; requested reference notional budget=100000 USD; "
                  "selected action=" + row["action"] + "; behavior model=")
        ending = ". Predict eventual roundtrip net USD after reported execution commissions."
        prefix, found, behavior = text.rpartition(marker)
        need(found and prefix and behavior.endswith(ending) and len(behavior) > len(ending),
             "INPUT_SCOPE", "Feature text is not the Current100k action-conditioned template")
        for name in optional & set(row):
            checksum(row[name], name)
        pair = (row["request_id"], row["action"])
        need(row["row_id"] not in identities and pair not in request_actions,
             "INVALID_INPUT", "Duplicate row or request/action identity")
        identities.add(row["row_id"])
        request_actions.add(pair)
        rows.append(dict(row))
    return rows


def validate_head(state):
    import torch
    need(isinstance(state, dict) and set(state) == {"value.weight", "value.bias"},
         "SHAPE_MISMATCH", "Expected the separate Current100k value head")
    for name, shape in (("value.weight", (1, FEATURE_WIDTH)), ("value.bias", (1,))):
        value = state[name]
        need(isinstance(value, torch.Tensor) and tuple(value.shape) == shape
             and value.dtype == torch.float32 and value.device.type == "cpu"
             and bool(torch.isfinite(value).all()),
             "SHAPE_MISMATCH", "Current100k head must have finite CPU FP32 tensors", tensor=name)
    return state


def read_head(policy, path, expected_sha256):
    """Hash the same bounded immutable bytes that safetensors decodes."""
    from safetensors.torch import load
    checksum(expected_sha256, "head_sha256")
    source = policy.read(path)
    with source.open("rb") as stream:
        content = stream.read(HEAD_MAX_BYTES + 1)
    need(len(content) <= HEAD_MAX_BYTES, "MODEL_LIMIT", "Value head exceeds byte limit")
    need(hashlib.sha256(content).hexdigest() == expected_sha256,
         "IDENTITY_MISMATCH", "Current100k head SHA256 differs")
    return validate_head(load(content))


def value_module(encoder, head_state):
    """Build only the encoder/value graph; classification heads are not executed."""
    import torch
    from torch import nn
    from torch.nn import functional as F

    class Current100kValue(nn.Module):
        def __init__(self):
            super().__init__()
            self.encoder = encoder
            self.value = nn.Linear(FEATURE_WIDTH, 1, device="cpu", dtype=torch.float32)
            state = validate_head(head_state)
            self.value.load_state_dict({"weight": state["value.weight"], "bias": state["value.bias"]})
            self.feature_cache = OrderedDict()
            self.encoder_cache_identity = None
            self.cache_enabled = False
            self.probe_metrics = None

        def forward(self, batches, input_ids):
            vectors = []
            need(len(batches) == len(input_ids), "IDENTITY_MISMATCH", "Encoded row/cache identities differ")
            for batch, input_id in zip(batches, input_ids):
                if self.probe_metrics is not None:
                    self.probe_metrics["logical_forward_examples"] += 1
                key = (self.encoder_cache_identity, input_id)
                if self.cache_enabled and key in self.feature_cache:
                    features = self.feature_cache[key].clone()
                    self.feature_cache.move_to_end(key)
                    self.probe_metrics["feature_cache_hits"] += 1
                else:
                    if self.probe_metrics is not None:
                        self.probe_metrics["encoder_forward_examples"] += 1
                        if self.cache_enabled:
                            self.probe_metrics["feature_cache_misses"] += 1
                        else:
                            self.probe_metrics["feature_cache_bypassed_examples"] += 1
                    hidden = self.encoder(**batch).last_hidden_state
                    need(hidden.ndim == 3 and hidden.shape[:2] == batch["attention_mask"].shape
                         and hidden.shape[2] == FEATURE_WIDTH and hidden.dtype == torch.float32
                         and bool(torch.isfinite(hidden).all()),
                         "SHAPE_MISMATCH", "Current100k encoder output changed shape, precision or values")
                    mask = batch["attention_mask"].unsqueeze(-1).to(hidden.dtype)
                    mean = (hidden * mask).sum(1) / mask.sum(1).clamp_min(1)
                    features = F.normalize(mean.float(), p=2, dim=1).detach()
                    if self.cache_enabled:
                        self.feature_cache[key] = features.clone()
                        self.feature_cache.move_to_end(key)
                        while len(self.feature_cache) > CACHE_MAX_ENTRIES:
                            self.feature_cache.popitem(last=False)
                vectors.append(features)
            features = torch.cat(vectors)
            # Production concatenates separately encoded rows before its head.
            # Keep that matmul shape instead of silently switching to per-row GEMV.
            result = self.value(features).squeeze(-1)
            return {"features": features, "value_scaled": result,
                    "value_usd": result * SCALE_USD}

    return Current100kValue()


class Current100kProvider(TorchProvider):
    name = "current100k_value"
    task_kind = "regression"

    def __init__(self, encoder, tokenizer, head_state, identity, store, allowed_targets=None):
        import torch
        self.tokenizer = tokenizer
        contract = deepcopy(CONTRACT)
        identity = {**identity, "provider": self.name, "task_contract": contract,
                    "task_contract_sha256": digest(contract)}
        super().__init__(value_module(encoder, head_state), identity, store,
                         ["value.weight", "value.bias"] if allowed_targets is None else allowed_targets)
        need(self.allowed_targets <= set(self.tensor_names()),
             "PATCH_SCOPE", "Current100k allowlist names a missing parameter")
        need(all(name in ("value.weight", "value.bias") or name.startswith("encoder.")
                 for name in self.allowed_targets),
             "PATCH_SCOPE", "Current100k target is outside the encoder/value graph")
        need(all(parameter.dtype == torch.float32
                 for parameter in self.parameters.values()),
             "UNSUPPORTED_DTYPE", "Current100k research graph requires FP32 parameters")
        self.module.encoder_cache_identity = digest({
            "base_id": identity.get("base_id"), "source_tree_sha256": identity.get("source_tree_sha256"),
            "base_manifest_sha256": identity.get("base_manifest_sha256"),
            "loader_sha256": identity.get("loader_sha256"),
            "task_contract_sha256": identity["task_contract_sha256"], "backend_id": self.backend_id})
        self.last_probe_metrics = {}

    @contextmanager
    def probe_context(self, replacements, captures, interventions, force_uncached=False):
        """Reuse only unchanged encoder results; observation/intervention always runs it."""
        need(type(force_uncached) is bool, "INVALID_ARGUMENT", "force_uncached must be boolean")
        reason = ("explicit_recomputation" if force_uncached else
                  "captures" if captures else "interventions" if interventions else
                  "encoder_or_other_parameter_patch" if not set(replacements) <= {"value.weight", "value.bias"}
                  else None)
        self.last_probe_metrics = {"logical_forward_examples": 0, "encoder_forward_examples": 0,
                                   "feature_cache_enabled": reason is None,
                                   "feature_cache_hits": 0, "feature_cache_misses": 0,
                                   "feature_cache_bypassed_examples": 0, "feature_cache_bypass_reason": reason,
                                   "feature_cache_max_entries": CACHE_MAX_ENTRIES,
                                   "feature_cache_max_bytes": CACHE_MAX_ENTRIES * FEATURE_WIDTH * 4,
                                   "encoder_cache_identity": self.module.encoder_cache_identity}
        self.module.cache_enabled = reason is None
        self.module.probe_metrics = self.last_probe_metrics
        try:
            yield
        finally:
            self.last_probe_metrics["feature_cache_retained_entries"] = len(self.module.feature_cache)
            self.last_probe_metrics["feature_cache_retained_bytes"] = sum(
                value.numel() * value.element_size() for value in self.module.feature_cache.values())
            self.module.cache_enabled = False
            self.module.probe_metrics = None

    def prepare_inputs(self, inputs):
        import torch
        need(isinstance(inputs, dict) and set(inputs) in ({"rows"}, {"rows_artifact_id"}),
             "INVALID_INPUT", "Provide rows or one retained input-row artifact")
        value = inputs.get("rows") if "rows" in inputs else self.store.load_json(inputs["rows_artifact_id"])
        rows = validate_rows(value)
        batches, receipts = [], []
        for row in rows:
            encoded = self.tokenizer([row["feature_text"]], padding=True,
                                     truncation=False, return_tensors="pt")
            need(isinstance(encoded, dict) or hasattr(encoded, "items"),
                 "INVALID_INPUT", "Tokenizer must return named tensors")
            need("input_ids" in encoded and "attention_mask" in encoded,
                 "INVALID_INPUT", "Tokenizer omitted IDs or attention mask")
            batch = {name: value.detach().cpu().clone() for name, value in encoded.items()
                     if name in ("input_ids", "attention_mask", "token_type_ids")
                     and isinstance(value, torch.Tensor)}
            need("input_ids" in batch and "attention_mask" in batch,
                 "INVALID_INPUT", "Tokenizer IDs/mask must be tensors")
            shape = batch["input_ids"].shape
            need(len(shape) == 2 and shape[0] == 1 and 1 <= shape[1] <= MAX_TOKENS,
                 "INPUT_LIMIT", "Expected one untruncated sequence of at most 2048 tokens")
            for name, value in batch.items():
                need(value.shape == shape and value.dtype in (torch.int32, torch.int64),
                     "INVALID_INPUT", "Tokenizer tensors must be aligned integer matrices", tensor=name)
            mask = batch["attention_mask"]
            need(bool(((mask == 0) | (mask == 1)).all()) and int(mask.sum()) > 0,
                 "INVALID_INPUT", "Attention mask must contain real tokens and binary padding")
            need(bool((batch["input_ids"] >= 0).all()), "INVALID_INPUT", "Token IDs must be nonnegative")
            hashes = {name: tensor_sha256(value) for name, value in sorted(batch.items())}
            receipts.append({**{key: val for key, val in row.items() if key != "feature_text"},
                             "row_sha256": digest(row), "encoded_tensors_sha256": hashes,
                             "model_input_id": digest(hashes), "tokens": int(mask.sum()),
                             "padded_tokens": shape[1]})
            batches.append(batch)
        return (batches, [row["model_input_id"] for row in receipts]), {}, {
            "examples": len(rows), "input_id": digest(rows), "rows": receipts,
            "model_input_id": digest([row["model_input_id"] for row in receipts]),
            "task_contract_sha256": self.identity["task_contract_sha256"],
            "encoder_batch_size": 1, "labels_accepted": False,
            "source_authenticity": "caller_provenance_not_established_by_hashes",
        }

    def describe(self):
        return {**super().describe(), "task_kind": "regression", "task_contract": self.identity["task_contract"],
                "output_units": {"value_scaled": "USD/100", "value_usd": "USD"},
                "output_clipping": None,
                "feature_cache": {"scope": "resident_session", "max_entries": CACHE_MAX_ENTRIES,
                                  "max_bytes": CACHE_MAX_ENTRIES * FEATURE_WIDTH * 4,
                                  "key": "pinned_encoder_backend_contract_and_exact_token_tensors",
                                  "bypass": "captures_interventions_or_encoder_parameter_edits"},
                "limitations": ["CPU FP32 research backend; GPU bitwise parity is not claimed",
                                "Raw USD outputs; the existing collector owns its separate 15 USD bound",
                                "No outcome labels, trading, production activation or classification",
                                "Input hashes bind bytes and order, not external source authenticity"]}

    def close(self):
        self.tokenizer = None
        if self.module is not None:
            self.module.feature_cache.clear()
        super().close()


def load_current100k(config, policy, store):
    """Load an existing verified Laya install without modifying its files."""
    required = {"source_dir", "source_tree_sha256", "base_dir", "base_manifest_sha256",
                "head_path", "head_sha256"}
    optional = {"expected_base_id", "allowed_patch_targets", "task_contract_sha256"}
    need(isinstance(config, dict) and required <= set(config) and set(config) <= required | optional,
         "INVALID_MODEL", "Unknown or missing Current100k model binding")
    if "task_contract_sha256" in config:
        need(config["task_contract_sha256"] == digest(CONTRACT),
             "IDENTITY_MISMATCH", "Current100k task contract differs")
    source = policy.read(config["source_dir"], directory=True)
    for path in source.rglob("*.py"):
        policy.read(path)
    source_hash = source_tree_identity(source)
    need(source_hash == config["source_tree_sha256"], "IDENTITY_MISMATCH", "Laya source tree differs")
    base = policy.read(config["base_dir"], directory=True)
    for path in base.rglob("*"):
        if path.is_file() or path.is_symlink():
            policy.read(path, directory=path.is_dir())
    manifest_path = policy.bound(str(base / "base-manifest.json"), config["base_manifest_sha256"])
    manifest_bytes = manifest_path.read_bytes()
    need(hashlib.sha256(manifest_bytes).hexdigest() == config["base_manifest_sha256"],
         "IDENTITY_MISMATCH", "Base manifest changed during admission")
    head = read_head(policy, config["head_path"], config["head_sha256"])
    sys.path.insert(0, str(source))
    model_module = importlib.import_module("laya_cell.model")
    module_path = Path(model_module.__file__).resolve()
    need(module_path.is_relative_to(source), "IDENTITY_MISMATCH", "Laya loader belongs to another release")
    raw, tokenizer, base_id = model_module.load_verified_laya(base, loads(manifest_bytes), enforce_gpu=False)
    need(source_tree_identity(source) == source_hash, "IDENTITY_MISMATCH", "Laya source changed while loading")
    need(file_sha256(manifest_path) == config["base_manifest_sha256"],
         "IDENTITY_MISMATCH", "Base manifest changed while loading")
    if "expected_base_id" in config:
        need(base_id == config["expected_base_id"], "IDENTITY_MISMATCH", "Laya base identity differs")
    identity = {"base_id": base_id, "source_tree_sha256": source_hash,
                "base_manifest_sha256": config["base_manifest_sha256"],
                "head_sha256": config["head_sha256"], "loader_sha256": file_sha256(module_path)}
    return Current100kProvider(raw.encoder, tokenizer, head, identity, store,
                              config.get("allowed_patch_targets"))

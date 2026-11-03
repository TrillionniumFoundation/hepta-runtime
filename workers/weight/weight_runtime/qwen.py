"""Optional, explicitly pinned bridge to the independently verified Qwen reference."""
import importlib
from pathlib import Path
import sys

from .errors import digest, need
from .providers import TorchProvider, source_tree_identity


class QwenProvider(TorchProvider):
    name = "mit_qwen_reference"

    def __init__(self, reference, identity, store, allowed_targets):
        self.reference = reference
        super().__init__(reference.module, identity, store, allowed_targets)
        need(self.allowed_targets <= set(self.tensor_names()), "PATCH_SCOPE", "Missing Qwen allowlisted tensor")

    def prepare_inputs(self, inputs):
        encoded = self.reference.normalize_inputs(inputs)
        ids = encoded["input_ids"]
        return (), encoded, {"input_id": digest(inputs), "examples": ids.shape[0],
                             "model_input_id": digest({k: v.tolist() for k, v in encoded.items()}),
                             "tokens": int(encoded["attention_mask"].sum()),
                             "output_scope": "last_nonpadding_token_logits"}

    def forward(self, args, kwargs):
        import torch
        output = self.module(**kwargs, use_cache=False, return_dict=True)
        mask = kwargs["attention_mask"].bool()
        need(bool(mask.any(dim=1).all()), "INVALID_INPUT", "Empty Qwen input sequence")
        positions = torch.arange(mask.shape[1], device=mask.device)[None, :].expand_as(mask)
        last = positions.masked_fill(~mask, -1).max(dim=1).values
        logits = output.logits[torch.arange(mask.shape[0], device=mask.device), last, :]
        return {"next_token_logits": logits, "input_ids": kwargs["input_ids"], "attention_mask": kwargs["attention_mask"]}

    def describe(self):
        result = super().describe()
        result["reference"] = self.reference.describe()
        result["limitations"] += ["Worker probes return last nonpadding token logits; text generation and full benchmark evaluation are not implemented",
                                  "The independent reference runner performs public-text teacher-forced mechanism diagnostics only",
                                  "The BF16 reference edit is a verified sparse replacement; a recomputed projection is a different candidate"]
        return result

    def close(self):
        self.reference.close()
        super().close()


def load_qwen(config, policy, store):
    import torch
    need(config.get("device", "cpu") == "cpu", "UNSUPPORTED_DEVICE", "Core weight worker currently admits CPU Qwen only")
    root = policy.read(config["reference_root"], directory=True)
    for path in root.rglob("*"):
        if path.is_file() or path.is_symlink():
            policy.read(path, directory=path.is_dir())
    repository = Path(__file__).resolve().parents[3]
    source = repository / "experiments" / "weight" / "mit_replay"
    need(source.is_dir(), "DEPENDENCY_MISSING", "The Qwen reference adapter is not installed with this worker")
    source_hash = source_tree_identity(source)
    need(source_hash == config["adapter_source_sha256"], "IDENTITY_MISMATCH", "Qwen reference adapter source differs")
    sys.path.insert(0, str(repository))
    module = importlib.import_module("experiments.weight.mit_replay.qwen_adapter")
    need(Path(module.__file__).resolve().is_relative_to(source), "IDENTITY_MISMATCH", "Qwen adapter imported from another package")
    owner_threads = torch.get_num_threads()
    threads = config.get("threads", owner_threads)
    need(type(threads) is int and 1 <= threads <= owner_threads, "THREAD_POLICY", "Qwen threads exceed the owner budget")
    reference = module.load({**config, "reference_root": str(root), "threads": threads})
    identity = {"provider": "mit_qwen_reference", "reference": reference.verification,
                "variant": reference.variant, "adapter_source_sha256": source_hash}
    allowed = config.get("allowed_patch_targets", sorted(reference.reference_arrays))
    need(isinstance(allowed, list) and set(allowed) <= set(reference.reference_arrays),
         "PATCH_SCOPE", "Initial Qwen bridge restricts edits to verified reference target matrices")
    return QwenProvider(reference, identity, store, allowed)

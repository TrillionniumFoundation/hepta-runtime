"""Lazy Qwen3.5 provider factory for the weight worker and independent replay.

Importing this module never loads a model, starts a process, or accesses the network.
Only the caller-owned resident model is patched; checkpoint files stay read-only.
"""

import gc
import importlib.metadata
from pathlib import Path


def _json_loading_info(value):
    """Transformers 5 uses sets for some empty checkpoint-key collections."""
    if isinstance(value, dict):
        return {key: _json_loading_info(item) for key, item in value.items()}
    if isinstance(value, set):
        return [_json_loading_info(item) for item in sorted(value, key=repr)]
    if isinstance(value, (list, tuple)):
        return [_json_loading_info(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError(f"unsupported checkpoint metadata type: {type(value).__name__}")


class QwenReferenceProvider:
    """Expose a standard module/normalize_inputs/forward/describe/close contract."""

    def __init__(self, config):
        import torch
        from transformers import AutoModelForImageTextToText, AutoTokenizer

        try:
            from .verify import raw_sha256, verify_reference
        except ImportError:
            from verify import raw_sha256, verify_reference

        self.torch, self.raw_sha256 = torch, raw_sha256
        self.root = Path(config["reference_root"]).expanduser().resolve()
        self.device = str(config.get("device", "cpu"))
        if self.device != "cpu" and self.device not in {"cuda", "cuda:0"}:
            raise ValueError("reference adapter supports cpu or the explicitly reserved cuda:0 device")
        threads = int(config.get("threads", 4))
        self.max_batch = int(config.get("max_batch", 2))
        self.max_sequence = int(config.get("max_sequence", 512))
        if not 1 <= threads <= 8 or not 1 <= self.max_batch <= 4 or not 8 <= self.max_sequence <= 4096:
            raise ValueError("requested resources exceed the bounded reference adapter")
        torch.set_num_threads(threads)
        self.verification, self.reference_arrays = verify_reference(self.root)
        self.tokenizer = AutoTokenizer.from_pretrained(
            str(self.root / "base"), local_files_only=True, trust_remote_code=False)
        if self.tokenizer.pad_token_id is None:
            self.tokenizer.pad_token_id = self.tokenizer.eos_token_id
        loaded = AutoModelForImageTextToText.from_pretrained(
            str(self.root / "base"), local_files_only=True, trust_remote_code=False,
            dtype=torch.bfloat16, attn_implementation="eager", output_loading_info=True)
        self.module, self.loading_info = loaded
        self.loading_info = _json_loading_info(self.loading_info)
        if self.loading_info.get("mismatched_keys") or self.loading_info.get("error_msgs"):
            raise ValueError("checkpoint loader reported a mismatch")
        unexpected = self.loading_info.get("unexpected_keys", [])
        missing = self.loading_info.get("missing_keys", [])
        if unexpected or missing:
            raise ValueError(f"checkpoint loader did not consume the exact architecture: missing={missing}, unexpected={unexpected}")
        self.module.requires_grad_(False)
        self.module.eval()
        self.module.to(self.device)
        parameters = dict(self.module.named_parameters())
        for name, arrays in self.reference_arrays.items():
            tensor = parameters[name]
            bits = tensor.detach().cpu().contiguous().view(torch.uint16).numpy()
            if tensor.dtype != torch.bfloat16 or raw_sha256(bits) != raw_sha256(arrays["base"]):
                raise ValueError(f"loaded parameter does not match the BF16 source: {name}")
        self.variant = "base"
        if config.get("variant", "base") != "base":
            self.set_reference_variant(config["variant"])

    def normalize_inputs(self, inputs):
        torch = self.torch
        if set(inputs) & {"labels", "answers", "outcomes", "rewards", "expected"}:
            raise ValueError("outcome metadata does not belong in the inference provider")
        if "texts" in inputs:
            texts = inputs["texts"]
            if not isinstance(texts, list) or not 1 <= len(texts) <= self.max_batch:
                raise ValueError("text batch exceeds the declared budget")
            if any(not isinstance(x, str) or len(x) > 65536 for x in texts):
                raise ValueError("invalid raw text input")
            encoded = self.tokenizer(texts, add_special_tokens=False, padding=True, return_tensors="pt")
        elif "input_ids" in inputs:
            ids = torch.as_tensor(inputs["input_ids"], dtype=torch.long)
            encoded = {"input_ids": ids, "attention_mask": torch.as_tensor(
                inputs.get("attention_mask", torch.ones_like(ids)), dtype=torch.long)}
        else:
            raise ValueError("provide raw texts or explicit input_ids")
        ids = encoded["input_ids"]
        if ids.ndim != 2 or not 1 <= ids.shape[0] <= self.max_batch or not 2 <= ids.shape[1] <= self.max_sequence:
            raise ValueError("tokenized input exceeds the declared shape budget")
        if bool((ids < 0).any()) or bool((ids >= len(self.tokenizer)).any()):
            raise ValueError("input token is outside the vocabulary")
        mask = encoded["attention_mask"]
        if mask.shape != ids.shape or bool(((mask != 0) & (mask != 1)).any()):
            raise ValueError("attention_mask must be binary and match input_ids")
        if bool((mask.sum(dim=1) == 0).any()):
            raise ValueError("empty masked sequences are not valid forward inputs")
        return {key: value.to(self.device) for key, value in encoded.items()
                if key in {"input_ids", "attention_mask"}}

    def forward(self, inputs):
        if self.module is None:
            raise RuntimeError("provider is closed")
        encoded = self.normalize_inputs(inputs)
        with self.torch.inference_mode():
            output = self.module(**encoded, use_cache=False, return_dict=True)
        return {"logits": output.logits, "input_ids": encoded["input_ids"],
                "attention_mask": encoded["attention_mask"]}

    def set_reference_variant(self, variant):
        if variant not in {"base", "edited"}:
            raise ValueError("unknown immutable reference variant")
        parameters = dict(self.module.named_parameters())
        with self.torch.no_grad():
            for name, arrays in self.reference_arrays.items():
                source = self.torch.from_numpy(arrays[variant].copy()).view(self.torch.bfloat16)
                parameters[name].copy_(source.to(parameters[name].device))
                actual = parameters[name].detach().cpu().contiguous().view(self.torch.uint16).numpy()
                if self.raw_sha256(actual) != self.raw_sha256(arrays[variant]):
                    raise ValueError("resident patch hash check failed")
        self.variant = variant

    def describe(self):
        return {"provider": "mit_qwen_reference", "variant": self.variant,
                "reference_root": str(self.root), "device": self.device, "dtype": "bfloat16",
                "model_class": type(self.module).__name__, "max_batch": self.max_batch,
                "max_sequence": self.max_sequence, "threads": self.torch.get_num_threads(),
                "torch": self.torch.__version__, "transformers": importlib.metadata.version("transformers"),
                "dependencies": {name: importlib.metadata.version(name)
                                 for name in ("numpy", "safetensors", "tokenizers", "huggingface-hub")},
                "parameter_count": sum(x.numel() for x in self.module.parameters()),
                "probe_modules": ["model.language_model.layers.15", "model.language_model.layers.19",
                                  "model.language_model.layers.15.mlp.down_proj",
                                  "model.language_model.layers.19.mlp.down_proj"],
                "loading_info": self.loading_info}

    def close(self):
        self.module = None
        self.reference_arrays = {}
        gc.collect()
        if self.device.startswith("cuda"):
            self.torch.cuda.empty_cache()


def load(config):
    """Factory imported by the core registry; loading is always an explicit operation."""
    return QwenReferenceProvider(config)

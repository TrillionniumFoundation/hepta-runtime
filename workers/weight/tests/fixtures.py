"""Deterministic small CPU network fixture, not a mocked model provider."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import torch
from safetensors.torch import save_file
from weight_runtime.artifacts import file_sha256


def fixture(root):
    path = root / "fixture.safetensors"
    save_file({"0.weight": torch.tensor([[1., 0.], [0., 1.], [1., -1.]]),
               "2.weight": torch.tensor([[1., 0., .5], [0., 1., -.5]])}, str(path))
    return {"provider": "torch_sequential", "input_roots": [str(root)], "output_root": str(root / "artifacts"),
            "model": {"architecture": {"layers": [
                {"type": "Linear", "in_features": 2, "out_features": 3, "bias": False},
                {"type": "ReLU"}, {"type": "Linear", "in_features": 3, "out_features": 2, "bias": False}]},
                "weights_path": str(path), "weights_sha256": file_sha256(path)}}

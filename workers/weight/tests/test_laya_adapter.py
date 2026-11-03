"""Test the real RowLoRA algebra/parameter names without loading the market model."""
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import torch
from torch import nn
from weight_runtime.artifacts import ArtifactStore
from weight_runtime.patches import tensor_sha256
from weight_runtime.providers import LayaProvider
from weight_runtime.session import Session


class RowAdapter(nn.Module):
    def __init__(self):
        super().__init__()
        self.base = nn.Linear(4, 1, bias=False)
        self.A = nn.Parameter(torch.tensor([[.1, .2, .3, .4]]))
        self.B = nn.Parameter(torch.tensor([[.5]]))
        self.register_buffer("row_index", torch.tensor([0]), persistent=False)

    def full_effective_weight(self):
        return self.base.weight.index_add(0, self.row_index, self.B @ self.A)

    def forward(self, x):
        base = self.base(x)
        delta = torch.nn.functional.linear(torch.nn.functional.linear(x, self.A), self.B)
        return base.index_add(-1, self.row_index, delta)


class Cell(nn.Module):
    def __init__(self):
        super().__init__()
        self.model = nn.Module()
        self.model.scorer = nn.Sequential(nn.Identity(), nn.Linear(4, 4), nn.GELU(), RowAdapter())
        self.adapters = {"scorer.3": self.model.scorer[3]}


class LayaAdapterTests(unittest.TestCase):
    def cancellation_session(self, directory):
        cell = Cell()
        adapter = cell.model.scorer[3]
        with torch.no_grad():
            adapter.base.weight.copy_(torch.tensor([[2. ** 24, 2. ** 24, 0., 0.]]))
            adapter.A.copy_(torch.tensor([[1., 0., 0., 0.]]))
            adapter.B.fill_(1.)
        store = ArtifactStore(Path(directory))
        provider = LayaProvider(cell, None, {"fixture": "row-lora-cancellation"}, store, None)
        session = Session("row-lora-cancellation")
        session.provider, session.store = provider, store
        self.addCleanup(session.close, {})
        return session, adapter

    def test_effective_noop_preserves_factors_and_actual_nested_forward(self):
        with tempfile.TemporaryDirectory() as directory:
            session, adapter = self.cancellation_session(directory)
            provider = session.provider
            x = torch.tensor([[1., -1., 0., 0.]])
            before = provider.get_tensor("effective.scorer.3.weight")
            self.assertEqual(float(adapter(x)), 1.)
            self.assertEqual(float(torch.nn.functional.linear(x, before)), 0.)
            candidate = session.patch({"expected_model_id": provider.model_id, "operations": [{
                "tensor": "effective.scorer.3.weight", "operation": "scale", "indices": [0],
                "factor": 1., "expected_tensor_sha256": tensor_sha256(before)}]})
            self.assertEqual(candidate["effective_changed_coordinates"], 0)
            self.assertEqual(candidate["storage_changed_coordinates"], 0)
            self.assertEqual(candidate["storage_changed_parameters"], 0)
            self.assertTrue(candidate["storage_bytes_unchanged"])
            record = session.store.load_json(candidate["patch"]["artifact_id"])
            self.assertTrue(record["storage_bytes_unchanged"])
            replacements = session.store.load_tensors(candidate["parameters"]["artifact_id"])
            self.assertEqual(tensor_sha256(replacements["model.scorer.3.A"]), tensor_sha256(adapter.A))
            self.assertEqual(tensor_sha256(replacements["model.scorer.3.B"]), tensor_sha256(adapter.B))
            with provider.temporary_patch(replacements):
                self.assertEqual(float(adapter(x)), 1.)
                self.assertTrue(torch.equal(provider.get_tensor("effective.scorer.3.weight"), before))
            self.assertEqual(float(adapter(x)), 1.)

    def test_effective_and_stored_changes_are_reported_separately(self):
        with tempfile.TemporaryDirectory() as directory:
            session, adapter = self.cancellation_session(directory)
            provider = session.provider
            before = provider.get_tensor("effective.scorer.3.weight")
            candidate = session.patch({"expected_model_id": provider.model_id, "operations": [{
                "tensor": "effective.scorer.3.weight", "operation": "add", "indices": [1],
                "value": 2., "expected_tensor_sha256": tensor_sha256(before)}]})
            self.assertEqual(candidate["effective_changed_coordinates"], 1)
            self.assertEqual(candidate["storage_changed_coordinates"], 2)
            self.assertEqual(candidate["storage_changed_parameters"], 1)
            self.assertFalse(candidate["storage_bytes_unchanged"])
            measurements = {m["parameter"]: m for m in candidate["storage_measurements"]}
            self.assertEqual(measurements["model.scorer.3.A"]["storage_changed_coordinates"], 2)
            self.assertTrue(measurements["model.scorer.3.B"]["bytes_unchanged"])
            replacements = session.store.load_tensors(candidate["parameters"]["artifact_id"])
            x = torch.tensor([[1., -1., 0., 0.]])
            with provider.temporary_patch(replacements):
                self.assertEqual(float(adapter(x)), -2.)
            self.assertEqual(float(adapter(x)), 1.)

    def test_row_only_adapter_realizes_effective_weight_and_restores(self):
        with tempfile.TemporaryDirectory() as directory:
            cell = Cell()
            store = ArtifactStore(Path(directory))
            provider = LayaProvider(cell, None, {"fixture": "row-lora"}, store, None)
            before = provider.get_tensor("effective.scorer.3.weight")
            base = cell.model.scorer[3].base.weight.detach().clone()
            replacements, realized = provider.compile_tensor("effective.scorer.3.weight", before * 1.1)
            self.assertEqual(set(replacements), {"model.scorer.3.A", "model.scorer.3.B"})
            with provider.temporary_patch(replacements):
                self.assertTrue(torch.equal(provider.get_tensor("effective.scorer.3.weight"), realized))
                self.assertTrue(torch.equal(cell.model.scorer[3].base.weight, base))
            self.assertTrue(torch.equal(provider.get_tensor("effective.scorer.3.weight"), before))

    def test_explicit_empty_allowlist_is_not_default_permission(self):
        with tempfile.TemporaryDirectory() as directory:
            provider = LayaProvider(Cell(), None, {"fixture": "none"}, ArtifactStore(Path(directory)), None, [])
            self.assertEqual(provider.allowed_targets, set())


if __name__ == "__main__":
    unittest.main()

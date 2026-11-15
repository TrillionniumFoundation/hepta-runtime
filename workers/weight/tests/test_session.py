"""Real CPU inference, intervention, patch replay, restoration and sealing."""
from contextlib import ExitStack
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch as mock_patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import torch
from fixtures import fixture
from weight_runtime.artifacts import ArtifactStore
from weight_runtime.errors import WeightError
from weight_runtime.hooks import install_hooks
from weight_runtime.patches import tensor_sha256
from weight_runtime.providers import TorchProvider, load_provider
from weight_runtime.session import Session


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.session = Session("real-tests")
        self.opened = self.session.open(fixture(self.root))

    def tearDown(self):
        self.session.close({})
        self.temporary.cleanup()

    def output(self, result):
        return self.session.store.load_tensors(result["outputs"]["artifact_id"])["output"]

    def assert_failed_admission_closes_provider(self, reason):
        root = self.root / reason
        root.mkdir()
        params = fixture(root)
        failed = Session("failed-" + reason)
        captured = []
        def load(*args):
            provider = load_provider(*args)
            captured.append(provider)
            return provider
        with ExitStack() as stack:
            stack.enter_context(mock_patch("weight_runtime.providers.load_provider", side_effect=load))
            if reason == "identity":
                params["expected_model_id"] = "0" * 64
            else:
                stack.enter_context(mock_patch("weight_runtime.session.atomic_create", side_effect=OSError("receipt write failed")))
            with self.assertRaises((WeightError, OSError)):
                failed.open(params)
        self.assertIsNone(failed.provider)
        self.assertTrue(failed.closed)
        self.assertEqual(len(captured), 1)
        self.assertIsNone(captured[0].module)
        self.assertEqual(captured[0].parameters, {})
        with self.assertRaises(WeightError) as error:
            failed.probe({"inputs": {"x": [[1., 2.]]}})
        self.assertEqual(error.exception.code, "SESSION_STATE")
        with self.assertRaises(WeightError):
            failed.open(params)

    def test_failed_expected_model_identity_never_admits_live_provider(self):
        self.assert_failed_admission_closes_provider("identity")

    def test_failed_admission_receipt_never_admits_live_provider(self):
        self.assert_failed_admission_closes_provider("receipt")

    def test_forward_capture_patch_replay_restore_seal(self):
        inputs = {"x": [[2., 1.], [-1., 3.]]}
        baseline = self.session.probe({"inputs": inputs, "captures": [{"module": "1", "name": "hidden"}]})
        self.assertTrue(torch.equal(self.output(baseline), torch.tensor([[2.5, .5], [0., 3.]])))
        hidden = self.session.store.load_tensors(baseline["activations"]["artifact_id"])["hidden.0"]
        self.assertTrue(torch.equal(hidden, torch.tensor([[2., 1., 1.], [0., 3., 0.]])))
        target = self.session.provider.get_tensor("2.weight")
        patch = self.session.patch({"expected_model_id": self.opened["model_id"], "operations": [{
            "tensor": "2.weight", "operation": "writer_projection", "direction": [1., 0.],
            "columns": [0, 2], "alpha": 1., "expected_tensor_sha256": tensor_sha256(target)}]})
        self.assertEqual(patch["effective_changed_coordinates"], 2)
        self.assertEqual(patch["storage_changed_coordinates"], 2)
        self.assertFalse(patch["storage_bytes_unchanged"])
        edited = self.session.probe({"inputs": inputs, "patch_id": patch["patch"]["artifact_id"]})
        self.assertTrue(torch.equal(self.output(edited), torch.tensor([[0., .5], [0., 3.]])))
        self.assertTrue(torch.equal(self.output(self.session.probe({"inputs": inputs})), self.output(baseline)))
        self.assertTrue(torch.equal(self.session.provider.get_tensor("2.weight"), target))
        self.assertTrue(all(p.grad is None for p in self.session.provider.module.parameters()))
        sealed = self.session.seal({"patch_id": patch["patch"]["artifact_id"], "information_cutoff_ms": 0,
                                    "evaluation_protocol_sha256": "a" * 64})
        record = self.session.store.load_json(sealed["candidate"]["artifact_id"])
        self.assertEqual(record["construction_kind"], "DirectWeightEdit")
        self.assertNotIn("trained_until_ms", record)
        self.assertFalse(record["production_eligible"])

    def test_zero_numeric_changes_do_not_imply_parameter_byte_identity(self):
        target = self.session.provider.get_tensor("0.weight")
        candidate = self.session.patch({"expected_model_id": self.opened["model_id"], "operations": [{
            "tensor": "0.weight", "operation": "replace_sparse", "indices": [1], "values": [-0.0],
            "expected_tensor_sha256": tensor_sha256(target)}]})
        self.assertEqual(candidate["effective_changed_coordinates"], 0)
        self.assertEqual(candidate["storage_changed_coordinates"], 0)
        self.assertEqual(candidate["storage_changed_parameters"], 1)
        self.assertFalse(candidate["storage_bytes_unchanged"])
        stored = self.session.store.load_tensors(candidate["parameters"]["artifact_id"])["0.weight"]
        self.assertTrue(bool(torch.signbit(stored.flatten()[1])))
        self.assertFalse(bool(torch.signbit(target.flatten()[1])))

    def test_failed_intervention_cleans_hooks(self):
        inputs = {"x": [[2., 1.]]}
        baseline = self.session.probe({"inputs": inputs})
        with self.assertRaises(WeightError):
            self.session.probe({"inputs": inputs, "interventions": [{"module": "1", "operation": "replace", "value": [[1., 2.]]}]}, intervention=True)
        self.assertTrue(torch.equal(self.output(self.session.probe({"inputs": inputs})), self.output(baseline)))
        self.assertEqual(len(self.session.provider.module[1]._forward_hooks), 0)

    def test_intervention_effect_is_not_persistent(self):
        result = self.session.probe({"inputs": {"x": [[2., 1.]]}, "interventions": [
            {"module": "1", "operation": "scale", "factor": 0}]}, intervention=True)
        self.assertTrue(torch.equal(self.output(result), torch.zeros(1, 2)))
        self.assertTrue(torch.equal(self.output(self.session.probe({"inputs": {"x": [[2., 1.]]}})), torch.tensor([[2.5, .5]])))

    def test_wrong_base_and_budget_fail(self):
        with self.assertRaises(WeightError):
            self.session.patch({"expected_model_id": "0" * 64, "operations": []})
        self.session.forward_examples = self.session.limits["max_forward_examples"]
        with self.assertRaises(WeightError):
            self.session.probe({"inputs": {"x": [[1., 2.]]}})

    def test_svd_and_paged_arrays(self):
        result = self.session.analyze({"operation": "svd", "value": [[3., 0.], [0., 1.]], "rank": 1})
        query = self.session.query({"artifact_id": result["arrays"]["artifact_id"], "tensor": "singular_values", "limit": 1})
        self.assertEqual(query["values"], [3.])
        self.assertEqual(query["next_offset"], 1)


class MarkerTests(unittest.TestCase):
    def test_marker_capture_and_intervention_preserve_other_tokens(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ArtifactStore(Path(directory))
            module = torch.nn.Sequential(torch.nn.Linear(4, 4, bias=False))
            with torch.no_grad():
                module[0].weight.copy_(torch.eye(4))
            provider = TorchProvider(module, {"fixture": "markers"}, store)
            provider.marker_positions = torch.tensor([[1, 3, 5]])
            provider._order = [2, 0, 1]
            captured, x = {}, torch.arange(28.).reshape(1, 7, 4)
            with ExitStack() as stack:
                install_hooks(provider, store, [{"module": "0", "name": "markers", "select": "markers"}],
                              [{"module": "0", "select": "markers", "operation": "scale", "factor": 0}], captured, stack, 100)
                actual = module(x)
            self.assertTrue(torch.equal(captured["markers.0"], x[:, [3, 5, 1]]))
            self.assertTrue(torch.equal(actual[:, [0, 2, 4, 6]], x[:, [0, 2, 4, 6]]))
            self.assertTrue(torch.equal(actual[:, [1, 3, 5]], torch.zeros(1, 3, 4)))


if __name__ == "__main__":
    unittest.main()

"""Actual tensor edits: dtype, rounding, sparse support and parent binding."""
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import torch
from weight_runtime.artifacts import ArtifactStore
from weight_runtime.errors import WeightError
from weight_runtime.patches import edit_tensor, patch_metrics, tensor_sha256


class PatchMathTests(unittest.TestCase):
    def setUp(self):
        torch.set_num_threads(2)
        self.temporary = tempfile.TemporaryDirectory()
        self.store = ArtifactStore(Path(self.temporary.name))

    def tearDown(self):
        self.temporary.cleanup()

    def edit(self, tensor, **spec):
        return edit_tensor(tensor, {"expected_tensor_sha256": tensor_sha256(tensor), **spec}, self.store)[0]

    def test_writer_alpha_six_reverses_only_selected_columns(self):
        base = torch.tensor([[1., 2., 3.], [4., 5., 6.]], dtype=torch.bfloat16)
        result = self.edit(base, operation="writer_projection", columns=[0, 2], direction=[1., 0.], alpha=6)
        expected = torch.tensor([[-5., 2., -15.], [4., 5., 6.]], dtype=torch.bfloat16)
        self.assertTrue(torch.equal(result, expected))
        self.assertEqual(result.dtype, base.dtype)
        self.assertEqual(patch_metrics(base, result, float(base.double().square().sum()))["effective_changed_coordinates"], 2)
        self.assertEqual(base[0, 0].item(), 1.)

    def test_rounding_counts_real_coordinates(self):
        base = torch.ones(2, 2, dtype=torch.bfloat16)
        result = self.edit(base, operation="add", value=1e-9)
        self.assertEqual(patch_metrics(base, result, 4.)["effective_changed_coordinates"], 0)

    def test_lower_compute_precision_preserves_unselected_parent_bytes(self):
        base = torch.tensor([[1., 1. + 2.**-40], [-0., 2. + 2.**-40]], dtype=torch.float64)
        for operation in ("add", "zero", "scale", "replace_sparse"):
            payload = {"add": {"value": .5}, "zero": {}, "scale": {"factor": 2.},
                       "replace_sparse": {"values": [3.]}}[operation]
            result = self.edit(base, operation=operation, indices=[0], compute_dtype="float32", **payload)
            self.assertEqual(tensor_sha256(result.reshape(-1)[1:]), tensor_sha256(base.reshape(-1)[1:]))
            self.assertNotEqual(float(result[0, 0]), float(base[0, 0]))
        projected = self.edit(base, operation="writer_projection", columns=[0], direction=[1., 0.],
                              alpha=1., compute_dtype="float32")
        self.assertEqual(tensor_sha256(projected[:, 1]), tensor_sha256(base[:, 1]))
        self.assertEqual(float(projected[0, 0]), 0.)

    def test_noncontiguous_target_applies_selected_edit_in_logical_order(self):
        base = torch.arange(6., dtype=torch.float32).reshape(2, 3).T
        self.assertFalse(base.is_contiguous())
        result = self.edit(base, operation="add", indices=[1, 4], value=[.5, -2.])
        expected = base.contiguous().clone()
        expected.reshape(-1)[[1, 4]] += torch.tensor([.5, -2.])
        self.assertTrue(torch.equal(result, expected))
        self.assertTrue(torch.equal(base, torch.arange(6.).reshape(2, 3).T))

    def test_unselected_values_outside_compute_range_remain_unchanged(self):
        base = torch.tensor([1., 1e40], dtype=torch.float64)
        result = self.edit(base, operation="add", indices=[0], value=1., compute_dtype="float32")
        self.assertEqual(float(result[0]), 2.)
        self.assertEqual(tensor_sha256(result[1:]), tensor_sha256(base[1:]))
        matrix = torch.tensor([[1., 1e40], [2., 3.]], dtype=torch.float64)
        projected = self.edit(matrix, operation="writer_projection", columns=[0],
                              direction=[1., 0.], alpha=1., compute_dtype="float32")
        self.assertTrue(torch.equal(projected[:, 0], torch.tensor([0., 2.], dtype=torch.float64)))
        self.assertEqual(tensor_sha256(projected[:, 1]), tensor_sha256(matrix[:, 1]))

    def test_final_dtype_overflow_rejected(self):
        with self.assertRaises(WeightError):
            self.edit(torch.full((1, 2), 60000., dtype=torch.float16), operation="scale", factor=8)

    def test_wrong_shape_nonfinite_parent_hash_rejected(self):
        base = torch.eye(2)
        with self.assertRaises(WeightError):
            self.edit(base, operation="low_rank", left=[[1., 2., 3.]], right=[[1., 2.]])
        with self.assertRaises(WeightError):
            self.edit(base, operation="add", value=float("nan"))
        with self.assertRaises(WeightError):
            edit_tensor(base, {"operation": "scale", "factor": 1, "expected_tensor_sha256": "0" * 64}, self.store)

    def test_low_rank_and_projection_values(self):
        base = torch.eye(2)
        result = self.edit(base, operation="low_rank", left=[[1.], [2.]], right=[[3., 4.]], alpha=.5)
        self.assertTrue(torch.equal(result, torch.tensor([[2.5, 2.], [3., 5.]])))
        projected = self.edit(base, operation="input_projection", basis=[[1., 0.]], alpha=1)
        self.assertTrue(torch.equal(projected, torch.tensor([[0., 0.], [0., 1.]])))


if __name__ == "__main__":
    unittest.main()

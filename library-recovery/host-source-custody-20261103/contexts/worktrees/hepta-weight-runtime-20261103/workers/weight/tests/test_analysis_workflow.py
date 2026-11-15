"""Numerical analysis can complete a writer-selection workflow through public ops."""
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import torch
from fixtures import fixture
from weight_runtime.errors import WeightError
from weight_runtime.session import Session


class AnalysisWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.session = Session("analysis-workflow")
        self.session.open(fixture(Path(self.temporary.name)))

    def tearDown(self):
        self.session.close({})
        self.temporary.cleanup()

    def ref(self, result, tensor):
        return {"artifact_id": result["arrays"]["artifact_id"], "tensor": tensor}

    def test_export_concat_differences_svd_writer_ranking(self):
        parameter = self.session.inspect({"export_tensor": True, "tensor": "2.weight"})
        joined = self.session.analyze({"operation": "concatenate", "values": [
            [[0., 0., 0.]], [[2., 0., 1.]], [[1., 1., 1.]], [[3., 1., 2.]]]})
        reshaped = self.session.analyze({"operation": "reshape", "value": self.ref(joined, "value"), "shape": [2, 2, 3]})
        contrast = self.session.analyze({"operation": "pair_differences", "value": self.ref(reshaped, "value")})
        svd = self.session.analyze({"operation": "svd", "value": self.ref(contrast, "difference"), "rank": 1})
        self.assertAlmostEqual(svd["result"]["singular_values_preview"][0], 10 ** .5, places=10)
        ranked = self.session.analyze({"operation": "writer_ranking", "value": self.ref(contrast, "difference"),
            "weight": {"artifact_id": parameter["array"]["artifact_id"], "tensor": "value"},
            "direction": [1., 0.], "top_k": 2})
        self.assertEqual(ranked["result"]["columns"], [0, 2])
        self.assertEqual(ranked["result"]["scores"], [5., 1.25])
        # Reversing a direction must not change the covariance-based ranking.
        reversed_direction = self.session.analyze({"operation": "writer_ranking", "value": self.ref(contrast, "difference"),
            "weight": {"artifact_id": parameter["array"]["artifact_id"], "tensor": "value"},
            "direction": [-1., 0.], "top_k": 2})
        self.assertEqual(ranked["result"], reversed_direction["result"])

    def test_parameter_block_and_budget(self):
        result = self.session.inspect({"export_tensor": True, "tensor": "2.weight", "rows": [1], "columns": [2, 0]})
        query = self.session.query({"artifact_id": result["array"]["artifact_id"], "tensor": "value"})
        self.assertEqual(query["values"], [-.5, 0.])
        self.assertEqual(query["shape"], [1, 2])
        self.session.limits["max_capture_elements"] = 2
        with self.assertRaises(WeightError):
            self.session.inspect({"export_tensor": True, "tensor": "2.weight"})

    def test_shape_and_allocation_limits(self):
        self.session.limits["max_capture_elements"] = 4
        with self.assertRaises(WeightError):
            self.session.analyze({"operation": "concatenate", "values": [[[1., 2., 3.]], [[1., 2., 3.]]]})
        with self.assertRaises(WeightError):
            self.session.analyze({"operation": "reshape", "value": [1., 2.], "shape": [3, -1]})
        with self.assertRaises(WeightError):
            self.session.analyze({"operation": "pair_differences", "value": [[1., 2.], [3., 4.]]})
        with self.assertRaises(WeightError):
            self.session.analyze({"operation": "concatenate", "values": [[[1., 2.]], [[1.]]]})

    def test_nonzero_reference_permutation(self):
        result = self.session.analyze({"operation": "pair_differences", "value": [[[1., 2.], [4., 6.], [7., 9.]]],
                                      "reference_permutation": 1, "flatten_to_rows": False})
        value = self.session.store.load_tensors(result["arrays"]["artifact_id"])["difference"]
        self.assertTrue(torch.equal(value, torch.tensor([[[-3., -4.], [3., 3.]]], dtype=torch.float64)))


if __name__ == "__main__":
    unittest.main()

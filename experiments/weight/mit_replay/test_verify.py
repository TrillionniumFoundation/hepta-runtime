"""Reject malformed/tampered edits before any model can be loaded."""

import unittest
import numpy as np

try:
    from .verify import raw_sha256, rebuild_sparse
except ImportError:
    from verify import raw_sha256, rebuild_sparse


class SparseVerificationTests(unittest.TestCase):
    def setUp(self):
        self.base = np.array([[0x3F80, 0x4000, 0x4040], [0x4080, 0x40A0, 0x40C0]], dtype=np.uint16)
        self.indices = np.array([1, 4], dtype=np.int32)
        self.values = np.array([0x3F00, 0x3F80], dtype=np.uint16)
        result = self.base.copy()
        result.reshape(-1)[self.indices] = self.values
        self.expected = {"shape": [2, 3], "base_sha256": raw_sha256(self.base),
                         "edited_sha256": raw_sha256(result), "changed_entries": 2,
                         "changed_columns": 1}

    def test_exact_rebuild_and_source_immutability(self):
        before = self.base.copy()
        edited = rebuild_sparse(self.base, self.indices, self.values, self.expected)
        self.assertTrue(np.array_equal(before, self.base))
        self.assertEqual(raw_sha256(edited), self.expected["edited_sha256"])

    def test_tampered_base_rejected(self):
        self.base[0, 0] ^= np.uint16(1)
        with self.assertRaisesRegex(ValueError, "source tensor hash"):
            rebuild_sparse(self.base, self.indices, self.values, self.expected)

    def test_duplicate_and_outside_indices_rejected(self):
        for indices in (np.array([1, 1], dtype=np.int32), np.array([1, 6], dtype=np.int32)):
            with self.assertRaises(ValueError):
                rebuild_sparse(self.base, indices, self.values, self.expected)

    def test_tampered_patch_rejected(self):
        self.values[0] ^= np.uint16(1)
        with self.assertRaisesRegex(ValueError, "reconstructed tensor hash"):
            rebuild_sparse(self.base, self.indices, self.values, self.expected)

    def test_float_values_cannot_masquerade_as_bf16_bits(self):
        with self.assertRaises(ValueError):
            rebuild_sparse(self.base, self.indices, self.values.astype(np.float32), self.expected)


if __name__ == "__main__":
    unittest.main()

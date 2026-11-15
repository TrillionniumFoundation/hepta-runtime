"""Reject cross-model and cross-input activation handoffs without model loading."""
import copy
import unittest
from laya_session_experiment import validate_localization, validate_probe_lineage
from weight_runtime.errors import digest


class LineageTests(unittest.TestCase):
    def fixture(self):
        opened = {"model_id": "a" * 64, "backend_id": "b" * 64,
                  "model": {"identity": {"parent_adapter_sha256": "c" * 64},
                            "backend": {"device": "cpu", "threads": 2}}}
        summary = {"schema": "hepta.weight.laya-localization.v2", "rows_sha256": "d" * 64,
                   "model_id": opened["model_id"], "backend_id": opened["backend_id"],
                   "model_identity": opened["model"]["identity"], "backend": opened["model"]["backend"]}
        return opened, summary

    def test_exact_shared_model_and_backend_pass(self):
        opened, summary = self.fixture()
        validate_localization(summary, "d" * 64, opened)

    def test_individually_valid_but_different_inputs_or_parent_fail(self):
        opened, summary = self.fixture()
        for field, value in (("rows_sha256", "e" * 64), ("model_id", "e" * 64),
                             ("backend_id", "e" * 64), ("model_identity", {"parent_adapter_sha256": "e" * 64}),
                             ("backend", {"device": "cpu", "threads": 4})):
            invalid = copy.deepcopy(summary)
            invalid[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_localization(invalid, "d" * 64, opened)

    def test_probe_semantic_alignment_and_state_identity(self):
        row, order = {"state": {"instrument": "SYNTHETIC", "quotes": [1, 2]}}, list(range(7))
        item = {"row_index": 3, "order": order, "mode": "sequential",
                "input_sha256": digest(row["state"]), "model_input_id": "a" * 64}
        validate_probe_lineage(item, row, 3, order, "sequential")
        for field, value in (("row_index", 4), ("order", list(reversed(order))),
                             ("mode", "parallel"), ("input_sha256", "b" * 64), ("model_input_id", None)):
            invalid = dict(item)
            invalid[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_probe_lineage(invalid, row, 3, order, "sequential")

    def test_old_unbound_summary_cannot_claim_new_lineage(self):
        opened, summary = self.fixture()
        summary["schema"] = "hepta.weight.laya-localization.v1"
        with self.assertRaisesRegex(ValueError, "DATA_LINEAGE"):
            validate_localization(summary, "d" * 64, opened)


if __name__ == "__main__":
    unittest.main()

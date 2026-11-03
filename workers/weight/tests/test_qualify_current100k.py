"""Qualification receipts over actual Current100k CPU tensor fixtures.

Only full-checkpoint loading is replaced with the already-constructed small
fixture graph. Token preparation, forward, cache, patch, restoration and artifact
storage are the real implementations; this is not full Laya/GPU qualification.
"""
import copy
import hashlib
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import torch
from safetensors.torch import save_file

from weight_runtime.artifacts import ArtifactStore, file_sha256
from weight_runtime.current100k import Current100kProvider
from weight_runtime.errors import WeightError, canonical, digest, loads
from weight_runtime.session import Session
from test_current100k_provider import EncoderFixture, TokenFixture, head, row


def script_module():
    path = Path(__file__).resolve().parents[3] / "experiments" / "weight" / "qualify_current100k.py"
    spec = importlib.util.spec_from_file_location("qualify_current100k", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class QualificationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.module = script_module()
        self.rows = [row(), row("SELL", 1)]
        self.head_path = self.root / "value-head.safetensors"
        save_file(head(), str(self.head_path))
        self.rows_path = self.root / "rows.json"
        self.rows_path.write_bytes(canonical(self.rows))
        self.config_path = self.root / "model.json"
        self.config = {"source_dir": str(self.root), "base_dir": str(self.root),
                       "head_path": str(self.head_path), "head_sha256": file_sha256(self.head_path)}
        self.config_path.write_bytes(canonical(self.config))
        self.reference = torch.zeros((4, 768), dtype=torch.float32)
        self.reference[1, :2] = torch.tensor([.6, .8])
        self.reference[3, :2] = torch.tensor([1., -2.]) / torch.sqrt(torch.tensor(5.))
        self.reference_path = self.root / "reference.safetensors"
        save_file({"features": self.reference}, str(self.reference_path))
        self.open_calls = 0
        self.sessions = []
        self.change_head_on_close = False

    def session_factory(self, identity):
        owner = self

        class FixtureSession(Session):
            def open(self, params):
                owner.open_calls += 1
                self.store = ArtifactStore(Path(params["output_root"]))
                tokenizer = TokenFixture({r["feature_text"]: pair for r, pair in zip(
                    owner.rows, [([1, 2, 9], [1, 1, 0]), ([3, 9], [1, 0])])})
                self.provider = Current100kProvider(EncoderFixture(), tokenizer, head(),
                    {"fixture": "qualification-real-cpu", "head_sha256": owner.config["head_sha256"]}, self.store)
                self.limits.update(params["limits"])
                return {"model": self.provider.describe(), "model_id": self.provider.model_id,
                        "backend_id": self.provider.backend_id, "limits": dict(self.limits),
                        "load_seconds": 0.0, "fixture_only_no_full_model_load": True}

            def close(self, params):
                result = super().close(params)
                if owner.change_head_on_close:
                    owner.head_path.write_bytes(b"simulated external source change")
                return result

        session = FixtureSession(identity)
        self.sessions.append(session)
        return session

    def run_qualification(self, directory="run", **kwargs):
        return self.module.run(str(self.config_path), file_sha256(self.config_path),
            str(self.rows_path), kwargs.pop("rows_sha", file_sha256(self.rows_path)),
            str(self.reference_path), file_sha256(self.reference_path), kwargs.pop("indices", [1, 3]),
            str(self.root / directory), 1, session_factory=self.session_factory, **kwargs)

    def test_one_session_measures_real_parity_patch_cache_and_uncached_restoration(self):
        original_head = file_sha256(self.head_path)
        result = self.run_qualification()
        self.assertTrue(result["passed"])
        self.assertEqual(result["status"], "PASS_ENGINEERING_PARITY")
        self.assertEqual(self.open_calls, 1)
        self.assertEqual(result["session_open_calls"], 1)
        self.assertEqual(result["checks"]["counts"]["logical_forward_examples"], 6)
        self.assertEqual(result["checks"]["counts"]["encoder_forward_examples"], 4)
        self.assertEqual(result["checks"]["counts"]["feature_cache_hits"], 2)
        self.assertEqual(result["checks"]["head_patch"]["computation"]["encoder_forward_examples"], 0)
        self.assertEqual(result["checks"]["restoration"]["computation"]["feature_cache_bypass_reason"], "explicit_recomputation")
        self.assertTrue(result["checks"]["encoded_input_identity_preserved"])
        self.assertTrue(result["source_files_unchanged"])
        self.assertEqual(file_sha256(self.head_path), original_head)
        self.assertTrue(result["close"]["closed"])
        self.assertFalse(result["quality_improvement_claim"])
        self.assertFalse(result["production_eligible"])
        self.assertFalse(result["labels_read"])
        self.assertEqual(set(result["timings"]), {"load", "parent", "head_patch", "patched", "restored_uncached", "close"})
        saved = loads((self.root / "run" / "qualification.json").read_bytes())
        self.assertEqual(saved, result)
        self.assertEqual(saved["receipt_sha256"], digest({k: v for k, v in saved.items() if k != "receipt_sha256"}))

    def test_predeclared_feature_tolerance_is_fixed_and_outside_value_fails(self):
        self.assertEqual((self.module.FEATURE_ATOL, self.module.FEATURE_RTOL), (2e-6, 2e-5))
        # At a zero reference coordinate the allowed absolute discrepancy is
        # 2e-6; this 3e-6 mismatch must fail instead of widening the threshold.
        self.reference[1, 10] = 3e-6
        save_file({"features": self.reference}, str(self.reference_path))
        result = self.run_qualification()
        self.assertFalse(result["passed"])
        self.assertEqual(result["status"], "FAIL_ENGINEERING_PARITY")
        self.assertEqual(result["checks"]["reference_feature_parity"]["elements_outside_tolerance"], 1)
        self.assertTrue(result["checks"]["restoration"]["same_parameters"])
        self.assertTrue(result["close"]["closed"])
        started = loads((self.root / "run" / "started.json").read_bytes())
        self.assertEqual((started["feature_atol"], started["feature_rtol"]), (2e-6, 2e-5))

    def test_wrong_input_pin_or_label_bearing_rows_fail_before_loading(self):
        with self.assertRaises(WeightError):
            self.run_qualification(rows_sha="0" * 64)
        self.assertEqual(self.open_calls, 0)
        self.assertFalse((self.root / "run").exists())
        contaminated = copy.deepcopy(self.rows)
        contaminated[0]["net_usd"] = 12.0
        self.rows_path.write_bytes(canonical(contaminated))
        with self.assertRaises(WeightError):
            self.run_qualification()
        self.assertEqual(self.open_calls, 0)

    def test_reference_labels_or_invalid_indices_are_rejected_before_loading(self):
        with self.assertRaises(WeightError):
            self.run_qualification(indices=[1, 1])
        save_file({"features": self.reference, "labels": torch.ones(4)}, str(self.reference_path))
        with self.assertRaises(WeightError) as error:
            self.run_qualification()
        self.assertEqual(error.exception.code, "INVALID_REFERENCE")
        self.assertEqual(self.open_calls, 0)

    def test_existing_receipt_is_immutable_and_never_reloads(self):
        result = self.run_qualification()
        path = self.root / "run" / "qualification.json"
        before = path.read_bytes()
        with self.assertRaises(WeightError) as error:
            self.run_qualification()
        self.assertEqual(error.exception.code, "OUTPUT_EXISTS")
        self.assertEqual(self.open_calls, 1)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(result["receipt_sha256"], loads(before)["receipt_sha256"])

    def test_source_head_change_is_reported_even_when_in_memory_checks_pass(self):
        self.change_head_on_close = True
        result = self.run_qualification()
        self.assertTrue(result["checks"]["passed"])
        self.assertFalse(result["source_files_unchanged"])
        self.assertFalse(result["passed"])
        self.assertEqual(result["status"], "FAIL_ENGINEERING_PARITY")
        self.assertNotEqual(result["source_hashes_after"][str(self.head_path)], self.config["head_sha256"])


if __name__ == "__main__":
    unittest.main()

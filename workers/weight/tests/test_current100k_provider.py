"""Real CPU tensor/forward tests for Current100k's separate USD regression task.

The encoder and tokenizer below are small deterministic fixtures. These tests
establish the computation/input contract, not parity on the full private Laya
checkpoint or GPU backend.
"""
import hashlib
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import torch
from torch import nn
from safetensors.torch import save_file

from weight_runtime.artifacts import ArtifactStore, PathPolicy, file_sha256
from weight_runtime.current100k import (
    CACHE_MAX_ENTRIES, CONTRACT, FEATURE_WIDTH, Current100kProvider, feature_text, load_current100k,
    read_head, validate_head, validate_rows,
)
from weight_runtime.errors import WeightError, digest
from weight_runtime.patches import tensor_sha256
from weight_runtime.session import Session


class EncoderFixture(nn.Module):
    def __init__(self):
        super().__init__()
        self.embedding = nn.Embedding(10, FEATURE_WIDTH)
        with torch.no_grad():
            self.embedding.weight.zero_()
            self.embedding.weight[1, :2] = torch.tensor([3., 0.])
            self.embedding.weight[2, :2] = torch.tensor([0., 4.])
            self.embedding.weight[3, :2] = torch.tensor([1., -2.])
            self.embedding.weight[9].fill_(10000.)
        self.calls = []

    def forward(self, input_ids, attention_mask, token_type_ids=None):
        self.calls.append(tuple(input_ids.shape))
        return SimpleNamespace(last_hidden_state=self.embedding(input_ids))


class TokenFixture:
    def __init__(self, by_text):
        self.by_text, self.calls = by_text, []

    def __call__(self, texts, **kwargs):
        self.calls.append((list(texts), dict(kwargs)))
        if len(texts) != 1:
            raise AssertionError("Current100k must encode each row separately")
        ids, mask = self.by_text[texts[0]]
        return {"input_ids": torch.tensor([ids], dtype=torch.int64),
                "attention_mask": torch.tensor([mask], dtype=torch.int64),
                "token_type_ids": torch.zeros((1, len(ids)), dtype=torch.int64)}


def row(action="BUY", index=0):
    text = feature_text({"prompt": "Frozen market observation " + str(index),
                         "model_id": "behavior-v1", "instrument": "EUR.USD",
                         "position_at_request": 0}, action)
    return {"row_id": "row-" + str(index), "input_id": "input-" + str(index),
            "request_id": "request-" + str(index), "action": action,
            "input_started_at_ms": 1700000000000 + index,
            "feature_text": text, "feature_text_sha256": hashlib.sha256(text.encode()).hexdigest(),
            "source_request_sha256": digest({"request": index})}


def head():
    weight = torch.zeros((1, FEATURE_WIDTH), dtype=torch.float32)
    weight[0, :2] = torch.tensor([.03, -.04])
    return {"value.weight": weight, "value.bias": torch.tensor([.25], dtype=torch.float32)}


class Current100kProviderTests(unittest.TestCase):
    def make_session(self, directory, rows=None, allowed_targets=None):
        rows = rows or [row(), row("SELL", 1)]
        store = ArtifactStore(Path(directory))
        tokenizer = TokenFixture({r["feature_text"]: pair for r, pair in zip(
            rows, [([1, 2, 9], [1, 1, 0]), ([3, 9], [1, 0])])})
        encoder = EncoderFixture()
        provider = Current100kProvider(encoder, tokenizer, head(),
                                      {"fixture": "current100k-real-cpu"}, store, allowed_targets)
        session = Session("current100k-fixture")
        session.provider, session.store = provider, store
        self.addCleanup(session.close, {})
        return session, rows, encoder, tokenizer

    def test_serial_pooling_scaling_and_frozen_input_receipts(self):
        with tempfile.TemporaryDirectory() as directory:
            session, rows, encoder, tokenizer = self.make_session(directory)
            result = session.probe({"inputs": {"rows": rows}})
            output = session.store.load_tensors(result["outputs"]["artifact_id"])
            expected_features = torch.zeros((2, FEATURE_WIDTH))
            expected_features[0, :2] = torch.tensor([.6, .8])
            expected_features[1, :2] = torch.tensor([1., -2.]) / torch.sqrt(torch.tensor(5.))
            expected = nn.functional.linear(expected_features, head()["value.weight"], head()["value.bias"]).flatten()
            torch.testing.assert_close(output["features"], expected_features, rtol=0, atol=0)
            torch.testing.assert_close(output["value_scaled"], expected, rtol=0, atol=3e-8)
            torch.testing.assert_close(output["value_usd"], expected * 100., rtol=0, atol=4e-6)
            self.assertTrue(bool((output["value_usd"] > 15.).all()))
            self.assertEqual(encoder.calls, [(1, 3), (1, 2)])
            self.assertEqual(len(tokenizer.calls), 2)
            self.assertTrue(all(kw == {"padding": True, "truncation": False, "return_tensors": "pt"}
                                for _, kw in tokenizer.calls))
            self.assertEqual(set(output), {"features", "value_scaled", "value_usd"})
            meta = result["input"]
            self.assertEqual(meta["input_id"], digest(rows))
            self.assertEqual(meta["task_contract_sha256"], digest(CONTRACT))
            self.assertEqual(meta["rows"][0]["row_sha256"], digest(rows[0]))
            self.assertEqual(meta["rows"][0]["source_request_sha256"], rows[0]["source_request_sha256"])
            self.assertEqual(meta["rows"][0]["tokens"], 2)
            self.assertEqual(meta["rows"][0]["padded_tokens"], 3)
            self.assertNotIn("feature_text", meta["rows"][0])
            self.assertFalse(meta["labels_accepted"])
            self.assertEqual(result["computation"]["logical_forward_examples"], 2)
            self.assertEqual(result["computation"]["encoder_forward_examples"], 2)
            self.assertEqual(result["computation"]["feature_cache_misses"], 2)

    def test_retained_rows_and_row_order_have_explicit_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            session, rows, _, _ = self.make_session(directory)
            ref = session.store.put_json(rows, "current100k-input-rows")
            a = session.provider.prepare_inputs({"rows": rows})[2]
            b = session.provider.prepare_inputs({"rows_artifact_id": ref["artifact_id"]})[2]
            c = session.provider.prepare_inputs({"rows": list(reversed(rows))})[2]
            self.assertEqual(a, b)
            self.assertNotEqual(a["input_id"], c["input_id"])
            self.assertNotEqual(a["model_input_id"], c["model_input_id"])

    def test_temporary_head_edit_changes_actual_forward_and_restores_source(self):
        with tempfile.TemporaryDirectory() as directory:
            session, rows, encoder, _ = self.make_session(directory)
            inputs = {"rows": rows}
            baseline = session.probe({"inputs": inputs})
            parent = session.provider.get_tensor("value.bias")
            candidate = session.patch({"expected_model_id": session.provider.model_id, "operations": [{
                "tensor": "value.bias", "operation": "add", "indices": [0], "value": .01,
                "expected_tensor_sha256": tensor_sha256(parent)}]})
            edited = session.probe({"inputs": inputs, "patch_id": candidate["patch"]["artifact_id"]})
            restored = session.probe({"inputs": inputs})
            original = session.store.load_tensors(baseline["outputs"]["artifact_id"])
            changed = session.store.load_tensors(edited["outputs"]["artifact_id"])
            again = session.store.load_tensors(restored["outputs"]["artifact_id"])
            torch.testing.assert_close(changed["value_usd"] - original["value_usd"], torch.ones(2), rtol=0, atol=3e-6)
            self.assertTrue(torch.equal(again["value_usd"], original["value_usd"]))
            self.assertTrue(torch.equal(changed["features"], original["features"]))
            self.assertTrue(torch.equal(session.provider.get_tensor("value.bias"), parent))
            self.assertTrue(all(p.grad is None and not p.requires_grad for p in session.provider.parameters.values()))
            self.assertEqual(edited["computation"]["encoder_forward_examples"], 0)
            self.assertEqual(edited["computation"]["feature_cache_hits"], 2)
            self.assertEqual(restored["computation"]["feature_cache_hits"], 2)
            self.assertEqual(session.forward_examples, 6)
            self.assertEqual(len(encoder.calls), 2)

    def test_capture_intervention_and_encoder_patch_bypass_without_polluting_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            session, rows, encoder, _ = self.make_session(
                directory, allowed_targets=["value.weight", "value.bias", "encoder.embedding.weight"])
            inputs = {"rows": rows}
            first = session.probe({"inputs": inputs})
            baseline = session.store.load_tensors(first["outputs"]["artifact_id"])
            captured = session.probe({"inputs": inputs, "captures": [{
                "module": "encoder.embedding", "where": "output", "name": "tokens"}]})
            self.assertEqual(captured["computation"]["feature_cache_bypass_reason"], "captures")
            self.assertEqual(captured["computation"]["encoder_forward_examples"], 2)
            intervened = session.probe({"inputs": inputs, "interventions": [{
                "module": "encoder.embedding", "where": "output", "operation": "scale", "factor": 0.}]},
                intervention=True)
            intervention_output = session.store.load_tensors(intervened["outputs"]["artifact_id"])
            self.assertEqual(intervened["computation"]["feature_cache_bypass_reason"], "interventions")
            self.assertEqual(int(torch.count_nonzero(intervention_output["features"])), 0)
            name = "encoder.embedding.weight"
            before = session.provider.get_tensor(name)
            candidate = session.patch({"expected_model_id": session.provider.model_id, "operations": [{
                "tensor": name, "operation": "add", "indices": [FEATURE_WIDTH + 1], "value": 2.,
                "expected_tensor_sha256": tensor_sha256(before)}]})
            edited = session.probe({"inputs": inputs, "patch_id": candidate["patch"]["artifact_id"]})
            changed = session.store.load_tensors(edited["outputs"]["artifact_id"])
            self.assertEqual(edited["computation"]["feature_cache_bypass_reason"], "encoder_or_other_parameter_patch")
            self.assertFalse(torch.equal(changed["features"], baseline["features"]))
            again = session.probe({"inputs": inputs})
            restored = session.store.load_tensors(again["outputs"]["artifact_id"])
            self.assertEqual(again["computation"]["feature_cache_hits"], 2)
            self.assertEqual(again["computation"]["encoder_forward_examples"], 0)
            self.assertTrue(torch.equal(restored["features"], baseline["features"]))
            self.assertTrue(torch.equal(session.provider.get_tensor(name), before))
            self.assertEqual(len(encoder.calls), 8)

    def test_cache_is_bounded_and_does_not_reuse_changed_token_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            session, rows, encoder, tokenizer = self.make_session(directory)
            provider = session.provider
            for size in range(1, CACHE_MAX_ENTRIES + 2):
                tokenizer.by_text[rows[0]["feature_text"]] = ([1] * size, [1] * size)
                args, kwargs, _ = provider.prepare_inputs({"rows": rows[:1]})
                with torch.inference_mode(), provider.probe_context({}, [], []):
                    provider.forward(args, kwargs)
                self.assertEqual(provider.last_probe_metrics["feature_cache_hits"], 0)
            self.assertEqual(len(provider.module.feature_cache), CACHE_MAX_ENTRIES)
            self.assertEqual(provider.last_probe_metrics["feature_cache_retained_bytes"], CACHE_MAX_ENTRIES * FEATURE_WIDTH * 4)
            tokenizer.by_text[rows[0]["feature_text"]] = ([1], [1])
            args, kwargs, _ = provider.prepare_inputs({"rows": rows[:1]})
            with torch.inference_mode(), provider.probe_context({}, [], []):
                provider.forward(args, kwargs)
            self.assertEqual(provider.last_probe_metrics["feature_cache_hits"], 0)
            self.assertEqual(len(encoder.calls), CACHE_MAX_ENTRIES + 2)

    def test_explicit_recomputation_executes_encoder_and_preserves_base_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            session, rows, encoder, _ = self.make_session(directory)
            first = session.probe({"inputs": {"rows": rows}})
            cached = dict(session.provider.module.feature_cache)
            repeated = session.probe({"inputs": {"rows": rows}, "bypass_feature_cache": True})
            self.assertEqual(repeated["computation"]["feature_cache_bypass_reason"], "explicit_recomputation")
            self.assertEqual(repeated["computation"]["encoder_forward_examples"], 2)
            self.assertEqual(repeated["computation"]["feature_cache_hits"], 0)
            self.assertEqual(len(encoder.calls), 4)
            self.assertEqual(first["outputs"]["sha256"], repeated["outputs"]["sha256"])
            self.assertEqual(set(cached), set(session.provider.module.feature_cache))
            self.assertTrue(all(value is session.provider.module.feature_cache[key] for key, value in cached.items()))
            reused = session.probe({"inputs": {"rows": rows}})
            self.assertEqual(reused["computation"]["feature_cache_hits"], 2)
            self.assertEqual(len(encoder.calls), 4)

    def test_regression_softmax_is_rejected_before_forward_or_budget_consumption(self):
        with tempfile.TemporaryDirectory() as directory:
            session, rows, encoder, tokenizer = self.make_session(directory)
            with self.assertRaises(WeightError):
                session.probe({"inputs": {"rows": rows}, "softmax_output": "value_usd"})
            self.assertEqual(encoder.calls, [])
            self.assertEqual(tokenizer.calls, [])
            self.assertEqual(session.forward_examples, 0)

    def test_label_fields_wrong_task_action_and_text_identity_are_refused(self):
        source = row()
        bad_rows = [
            {**source, "net_usd": "3.14"},
            {**source, "label": 1},
            {**source, "feature_text": source["feature_text"] + " changed"},
            {**source, "action": "SELL"},
            {**source, "input_started_at_ms": True},
        ]
        old = source["feature_text"].replace("requested reference notional budget=100000 USD", "fixed requested quantity=25000 EUR")
        bad_rows.append({**source, "feature_text": old, "feature_text_sha256": hashlib.sha256(old.encode()).hexdigest()})
        for bad in bad_rows:
            with self.subTest(keys=list(bad)):
                with self.assertRaises(WeightError):
                    validate_rows([bad])
        with self.assertRaises(WeightError):
            validate_rows([source, dict(source)])

    def test_maximum_context_and_invalid_masks_fail_without_encoder_forward(self):
        with tempfile.TemporaryDirectory() as directory:
            session, rows, encoder, tokenizer = self.make_session(directory)
            for ids, mask in (([1] * 2049, [1] * 2049), ([1, 2], [0, 0]), ([1, 2], [1, 2])):
                tokenizer.by_text[rows[0]["feature_text"]] = (ids, mask)
                with self.assertRaises(WeightError):
                    session.probe({"inputs": {"rows": rows[:1]}})
            self.assertEqual(encoder.calls, [])
            self.assertEqual(session.forward_examples, 0)

    def test_head_file_exact_identity_schema_and_precision(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "value-head.safetensors"
            save_file(head(), str(path))
            policy = PathPolicy([str(root)], str(root / "out"))
            pin = file_sha256(path)
            loaded = read_head(policy, str(path), pin)
            self.assertTrue(torch.equal(loaded["value.weight"], head()["value.weight"]))
            with self.assertRaises(WeightError):
                read_head(policy, str(path), "0" * 64)
            for state in ({"scorer.3.weight": head()["value.weight"]},
                          {**head(), "value.bias": torch.zeros(1, dtype=torch.float16)},
                          {**head(), "value.weight": torch.zeros(1, 767)},
                          {**head(), "value.bias": torch.tensor([float("nan")])}):
                with self.subTest(keys=list(state)):
                    with self.assertRaises(WeightError):
                        validate_head(state)
            with self.assertRaises(WeightError):
                load_current100k({"source_dir": str(root)}, policy, ArtifactStore(root / "artifacts"))

    def test_default_targets_and_output_contract_do_not_claim_classification_or_clip(self):
        with tempfile.TemporaryDirectory() as directory:
            session, _, _, _ = self.make_session(directory)
            description = session.provider.describe()
            self.assertEqual(description["task_kind"], "regression")
            self.assertIsNone(description["output_clipping"])
            self.assertFalse(description["task_contract"]["classification"])
            self.assertEqual(session.provider.allowed_targets, {"value.weight", "value.bias"})
            self.assertEqual(description["output_units"]["value_usd"], "USD")
            with self.assertRaises(WeightError):
                session.provider.compile_tensor("encoder.embedding.weight", session.provider.get_tensor("encoder.embedding.weight"))


if __name__ == "__main__":
    unittest.main()

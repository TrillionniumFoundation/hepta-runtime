"""Synthetic provenance, economic cutoff and cached representation regressions."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import torch
from safetensors.torch import load_file, save
import prepare_current100k_signal_inputs as P


ACCOUNTING_FIXTURE = '''
def validate_period(period):
    if period['schema'] != 'fixture-original-period':
        raise ValueError('period')
def replay(events, period, instrument, now_ms):
    if instrument != 'EUR.USD':
        raise ValueError('instrument')
    for event in events:
        if type(event.get('ts_ms')) is not int or event['ts_ms'] > now_ms:
            raise ValueError('future or malformed event retained')
        if event.get('block_until_ms', 0) > now_ms:
            raise ValueError('original replay not yet complete')
    fees = {e['execution_id']: e['commission'] for e in events if e['event'] == 'fee'}
    terminal = {e['command_id'] for e in events if e['event'] == 'terminal'}
    executions = [dict(e['execution']) for e in events if e['event'] == 'execution']
    for execution in executions:
        execution['commission'] = fees.get(execution['execution_id'])
    return {'executions': executions,
        'settlement_pending_command_ids': sorted({e['command_id'] for e in executions} - terminal),
        'fee_missing_execution_ids': [e['execution_id'] for e in executions if e['commission'] is None],
        'fee_conflicting_execution_ids': []}
'''


class PreparationTests(unittest.TestCase):
    def setUp(self):
        torch.set_num_threads(1)
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.inputs = self.root / "inputs"
        self.inputs.mkdir()
        self.serial = 0
        self.period = {"schema": "fixture-original-period", "instruments": {"EUR.USD": {"opening_quantity": "0"}}}
        period_pin = self.write("period.json", self.period)
        producer = "a" * 64
        self.rows, self.events = [], []
        for i in range(6):
            start = (i + 1) * 100
            quotes = [{"t": start - 2, "bid": "1", "ask": "1.01"},
                      {"t": start - 1, "bid": "1.01", "ask": "1.02"}]
            prompt = "Recent authoritative quotes=" + json.dumps(quotes)
            original = {"request_id": "request-" + str(i), "started_at_ms": start,
                        "instrument": "EUR.USD", "model_id": "fixture-model", "prompt": prompt,
                        "position_at_request": 0}
            text = P.current100k_feature_text(original, "BUY")
            input_id = P.source_digest(original)
            executions = []
            for j, side, price in ((0, "BUY", "10"), (1, "SELL", "12")):
                execution = {"execution_id": f"execution-{i}-{j}", "command_id": f"command-{i}-{j}",
                             "order_id": 2 * i + j, "side": side, "quantity": "1", "price": price,
                             "cumulative_quantity": "1", "commission": ".5", "commission_currency": "USD"}
                executions.append(execution)
                at = start + 10 + j * 10
                self.events.extend([{"event": "execution", "ts_ms": at, "execution": execution},
                    {"event": "fee", "ts_ms": at + 1, "execution_id": execution["execution_id"], "commission": ".5"},
                    {"event": "terminal", "ts_ms": 350 if (i, j) == (1, 1) else at + 2,
                     "command_id": execution["command_id"]}])
            reward = {"instrument": "EUR.USD", "currency": "USD", "behavior_model_id": "fixture-model",
                      "input_id": input_id, "input_attribution": {"request_id": original["request_id"],
                          "producer_manifest_sha256": producer}, "open_command_id": executions[0]["command_id"],
                      "executions": executions, "execution_ids": [e["execution_id"] for e in executions],
                      "command_ids": [e["command_id"] for e in executions], "learning_eligible": True,
                      "exact_input_bound": True, "fees_complete": True, "settlement_complete": True,
                      "unsettled_commands": [], "learning_exclusion_reasons": [],
                      "realized_gross_usd": "2", "actual_commissions_usd": "1", "realized_net_usd": "1"}
            reward["reward_id"] = P.source_digest(reward)
            row = {"schema": "heptatrader.current100k-value-row.v1", "period_sha256": period_pin["sha256"],
                   "input_id": input_id, "input_started_at_ms": start, "request_id": original["request_id"],
                   "feature_text": text, "feature_text_sha256": hashlib.sha256(text.encode()).hexdigest(),
                   "action": "BUY", "net_usd": "1", "actual_commissions_usd": "1", "reward": reward,
                   "reward_id": reward["reward_id"], "open_command_id": reward["open_command_id"],
                   "source_request": {"request": original, "request_sha256": input_id, "producer_manifest_sha256": producer},
                   "source_binding": {"request_id": original["request_id"], "request_started_at_ms": start,
                       "request_sha256": input_id, "producer_manifest_sha256": producer,
                       "command": {"command_id": reward["open_command_id"], "side": "BUY"}}}
            row["row_id"] = P.source_digest(row)
            self.rows.append(row)
        dataset = {"schema": "heptatrader.current100k-value-dataset.v1", "rows": self.rows,
                   "period_sha256": period_pin["sha256"], "producer_manifest_sha256": producer}
        mean = torch.zeros((6, 768), dtype=torch.float32)
        mean[:, 0] = 1.
        self.request = {"schema": P.SCHEMA, "expected_rows": 6, "split_indices": [2, 4],
                        "information_cutoff_ms": 900, "oms_captured_at_ms": 1000, "period": period_pin,
                        "dataset": self.write("dataset.json", dataset),
                        "features": self.write("features.safetensors", save({"features": mean})),
                        "labels": self.write("labels.safetensors", save({"labels_usd": torch.ones(6)})),
                        "head": self.write("head.safetensors", save({"value.weight": torch.zeros((1, 768)), "value.bias": torch.zeros(1)})),
                        "oms_capture": self.write_events(),
                        "accounting_module": self.write("hepta_pnl_accounting.py", ACCOUNTING_FIXTURE.encode()),
                        "signal_module": self.write("signal.py", Path(P.__file__).with_name("current100k_signal_diagnostics.py").read_bytes())}
        binding = {"schema": "heptatrader.layer-diagnosis-binding.v1", "scope": "KNOWN_DEVELOPMENT_INPUTS",
                   "dataset_sha256": self.request["dataset"]["sha256"], "feature_cache_sha256": self.request["features"]["sha256"],
                   "selected_indices": list(range(6)), "probes": [{"index": i, "variant": "original", "text_sha256": row["feature_text_sha256"]}
                                                               for i, row in enumerate(self.rows)],
                   "dtype": "float32", "device": "cpu", "weights_modified": False, "fit_performed": False}
        self.request["layer_binding"] = self.write("binding.json", binding)
        self.request["layer_report"] = self.write("report.json", {"schema": "heptatrader.current100k-layer-diagnosis.v1",
            "binding_sha256": self.request["layer_binding"]["sha256"], "original_rows": 6, "requested_probes": 6, "completed_probes": 6,
            "skipped_probes": [], "weights_modified": False, "historical_labels_already_viewed": True,
            "layer_geometry": [{"index": 23, "stage": "final_norm"}]})
        self.request["layer_rows"] = []
        for i, row in enumerate(self.rows):
            tensors = {}
            for j, name in enumerate(("all", "action", "quotes", "template")):
                vector = torch.zeros(768)
                vector[j] = 1.
                tensors["normalized." + name + ".23"] = vector
            receipt = {"index": i, "variant": "original", "supported": True, "row_id": row["row_id"],
                       "text_sha256": row["feature_text_sha256"], "hidden_state_count": 24,
                       "layers": [{"index": 23, "stage": "final_norm"}]}
            self.request["layer_rows"].append({"index": i, "receipt": self.write(f"row-{i}.json", receipt),
                "tensors": self.write(f"row-{i}.safetensors", save(tensors))})

    def tearDown(self):
        self.temp.cleanup()

    def write(self, name, value):
        raw = value if isinstance(value, bytes) else P.canonical(value) + b"\n"
        path = self.inputs / name
        path.write_bytes(raw)
        return {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest()}

    def write_events(self):
        raw = b"".join(P.canonical(e) + b"\n" for e in sorted(self.events, key=lambda e: e["ts_ms"]))
        return self.write("oms.jsonl", raw)

    def run_prepare(self):
        out = self.root / f"prepared-{self.serial}"
        self.serial += 1
        return P.prepare(self.request, out), out

    def test_cached_representations_and_original_order_have_no_encoder_work(self):
        result, out = self.run_prepare()
        features = load_file(result["artifacts"]["features"]["path"])
        self.assertEqual({k: tuple(v.shape) for k, v in features.items()},
                         {"masked_mean": (6, 768), "action": (6, 768), "grouped": (6, 768), "structured": (6, 8)})
        expected = torch.zeros(768)
        expected[1:4] = 1 / 3**.5
        self.assertTrue(torch.allclose(features["grouped"], expected.expand(6, -1)))
        self.assertEqual(result["cost"]["encoder_forward_examples"], 0)
        self.assertEqual(result["available_before_fit_counts"], [1, 4])
        metadata = json.loads((out / "rows.json").read_text())
        self.assertEqual([r["row_id"] for r in metadata], [r["row_id"] for r in self.rows])
        self.assertEqual([r["label_available_by_ms"] for r in metadata], [299, 499, 499, 499, 900, 900])
        self.assertTrue(all(r["label_time_basis"] == P.TIME_BASIS and "label_resolved_at_ms" not in r for r in metadata))
        self.assertFalse(result["exact_settlement_times_claimed"])
        self.assertTrue(result["source_integrity_passed"])

    def test_execution_and_fee_without_original_terminal_do_not_prove_early_label(self):
        _, out = self.run_prepare()
        first = json.loads((out / "label-availability.json").read_text())["checkpoints"][0]
        self.assertEqual(first["row_reasons"][1], "ORIGINAL_COMMAND_SETTLEMENT_PENDING")

    def test_final_economic_change_rejects_even_previously_matching_early_reward(self):
        self.events.append({"event": "fee", "ts_ms": 800, "execution_id": "execution-0-1", "commission": ".75"})
        self.request["oms_capture"] = self.write_events()
        with self.assertRaises(P.WeightError) as raised:
            self.run_prepare()
        self.assertEqual(raised.exception.code, "LABEL_AVAILABILITY_UNPROVEN")
        out = self.root / "prepared-0"
        proof = json.loads((out / "label-availability.json").read_text())["checkpoints"]
        self.assertIsNone(proof[0]["row_reasons"][0])
        self.assertIn("ECONOMICS", proof[-1]["row_reasons"][0])
        self.assertTrue((out / "failure.json").exists())
        self.assertFalse((out / "ready.json").exists())
        before = (out / "failure.json").read_bytes()
        with self.assertRaises(FileExistsError):
            P.prepare(self.request, out)
        self.assertEqual(before, (out / "failure.json").read_bytes())

    def test_failed_early_replay_cannot_manufacture_availability(self):
        self.events.append({"event": "observer", "ts_ms": 1, "block_until_ms": 400})
        self.request["oms_capture"] = self.write_events()
        result, out = self.run_prepare()
        self.assertEqual(result["available_before_fit_counts"], [0, 4])
        proof = json.loads((out / "label-availability.json").read_text())["checkpoints"][0]
        self.assertEqual(proof["status"], "REPLAY_FAILED")

    def test_labels_and_layer_identity_are_checked_even_with_fresh_file_pins(self):
        for kind in ("labels", "row", "text", "mean"):
            with self.subTest(kind=kind):
                original = copy.deepcopy(self.request)
                if kind == "labels":
                    self.request["labels"] = self.write("bad-labels.safetensors", save({"labels_usd": torch.zeros(6)}))
                elif kind in ("row", "text"):
                    receipt = json.loads(Path(self.request["layer_rows"][0]["receipt"]["path"]).read_text())
                    receipt["row_id" if kind == "row" else "text_sha256"] = "b" * 64
                    self.request["layer_rows"][0]["receipt"] = self.write("bad-" + kind + ".json", receipt)
                else:
                    tensors = load_file(self.request["layer_rows"][0]["tensors"]["path"])
                    tensors["normalized.all.23"] = tensors["normalized.action.23"].clone()
                    self.request["layer_rows"][0]["tensors"] = self.write("bad-mean.safetensors", save(tensors))
                with self.assertRaises(P.WeightError):
                    self.run_prepare()
                self.request = original

    def test_feature_text_is_rederived_from_original_request_not_just_self_hashed(self):
        dataset = json.loads(Path(self.request["dataset"]["path"]).read_text())
        row = dataset["rows"][0]
        # Preserve all original request, reward and command identities while
        # making the feature text internally self-consistent but unrelated.
        row["feature_text"] = "Unrelated context\n" + row["feature_text"]
        row["feature_text_sha256"] = hashlib.sha256(row["feature_text"].encode()).hexdigest()
        row["row_id"] = P.source_digest({key: value for key, value in row.items() if key != "row_id"})
        with self.assertRaises(P.WeightError) as raised:
            P.validate_rows(dataset, self.request["period"]["sha256"])
        self.assertEqual(raised.exception.code, "INPUT_LINEAGE")
        self.assertIn("Feature text does not match the original flat request", str(raised.exception))

    def test_end_audit_withdraws_ready_when_pinned_input_changes(self):
        original = P.read_pin
        reads = 0
        def changed(pin, maximum=64 * 1024 * 1024):
            nonlocal reads
            if pin == self.request["period"]:
                reads += 1
                if reads == 2:
                    Path(pin["path"]).write_bytes(b"{}\n")
            return original(pin, maximum)
        with patch.object(P, "read_pin", changed), self.assertRaises(P.WeightError):
            self.run_prepare()
        out = self.root / "prepared-0"
        self.assertFalse(json.loads((out / "source-integrity.json").read_text())["passed"])
        self.assertFalse((out / "ready.json").exists())
        self.assertTrue((out / "failure.json").exists())

    def test_future_clock_and_partial_oms_tail_fail_without_early_credit(self):
        self.events.append({"event": "observer", "ts_ms": 1001})
        self.request["oms_capture"] = self.write_events()
        with self.assertRaises(P.WeightError):
            self.run_prepare()
        self.request["oms_capture"] = self.write("partial.jsonl", b'{"event":"incomplete"}')
        with self.assertRaises(P.WeightError) as raised:
            self.run_prepare()
        self.assertEqual(raised.exception.code, "OMS_CAPTURE")


if __name__ == "__main__":
    unittest.main()

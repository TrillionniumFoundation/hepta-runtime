"""State-order contract tests; real tokenizer parity is checked by check_laya_encoding.py."""
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from weight_runtime.errors import WeightError
from weight_runtime.providers import normalize_laya_state


FIELDS = ("instrument", "anchor_ms", "reference_mid", "horizon_sec", "columns", "quotes", "quantity")


class LayaEncodingContractTests(unittest.TestCase):
    def state(self):
        return {"instrument": "EUR.USD", "anchor_ms": 1700000000000,
                "reference_mid": "1.10005", "horizon_sec": 300,
                "columns": ["offset_ms", "bid", "ask"],
                "quotes": [[-1000, "1.1000", "1.1001"], [0, "1.1000", "1.1001"]],
                "quantity": "underlying MID return; not execution profit"}

    def test_stored_json_and_reverse_order_render_identically_without_input_mutation(self):
        source = self.state()
        expected = json.dumps(source, ensure_ascii=False)
        variants = [source, json.loads(json.dumps(source, sort_keys=True)), dict(reversed(list(source.items())))]
        self.assertNotEqual(json.dumps(variants[1], ensure_ascii=False), expected)
        for state in variants:
            with self.subTest(keys=list(state)):
                original = json.dumps(state, ensure_ascii=False)
                normalized = normalize_laya_state(state, FIELDS)
                self.assertEqual(json.dumps(normalized, ensure_ascii=False), expected)
                self.assertEqual(json.dumps(state, ensure_ascii=False), original)
                self.assertIsNot(normalized, state)
                self.assertEqual(normalized["quotes"], source["quotes"])

    def test_missing_extra_and_nonobject_states_are_rejected(self):
        source = self.state()
        for state in ([source], {k: v for k, v in source.items() if k != "anchor_ms"},
                      {**source, "outcome": 1}):
            with self.subTest(state_type=type(state).__name__):
                with self.assertRaises(WeightError) as caught:
                    normalize_laya_state(state, FIELDS)
                self.assertEqual(caught.exception.code, "INVALID_INPUT")


if __name__ == "__main__":
    unittest.main()

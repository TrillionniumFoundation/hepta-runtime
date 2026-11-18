# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Native parse results for every actual SDK raw transport observation.

This suite's splitting driver is test-only. Actual fixed-adapter framing is
separately executed by the real ELF and control suites.
"""
from pathlib import Path
import json
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from connection_test_context import Suite, U, message_frame, projection_parts

ERROR = '{"jsonrpc":"2.0","error":{"code":-32600,"message":"Invalid request"}}\n'


def main():
    with Suite("transport") as suite:
        context = suite.context
        calls = cases_total = errors_total = messages_total = 0
        exports = {}
        with context.module("message") as module:
            with module.session(output_capacity=1 << 20, workspace_capacity=2 << 20) as decoder:
                for domain in ["transport-core", "message-boundaries"]:
                    cases = context.rows(domain, "requests.jsonl")
                    originals = context.rows(domain, "transport.stdout")
                    outputs = []
                    for case, original in zip(cases, originals, strict=True):
                        assert case["label"] == original["label"]
                        actual = []
                        replies = []
                        projections = []
                        for line in bytes.fromhex(case["hex"]).split(b"\n"):
                            if line.endswith(b"\r"):
                                line = line[:-1]
                            if not line:
                                continue
                            raw = decoder(message_frame(line))
                            calls += 1
                            disposition = U(raw, 8)
                            projections.append(raw.hex())
                            if disposition == 0:
                                continue
                            if disposition == 5:
                                replies.append(ERROR)
                                continue
                            kind = {1: "request", 2: "notification", 3: "response", 4: "error"}[disposition]
                            actual.append((kind, raw, line))
                        assert "".join(replies) == original["response_raw"], case["label"]
                        assert len(actual) == len(original["messages"]), case["label"]
                        for (kind, raw, line), expected in zip(actual, original["messages"], strict=True):
                            assert kind == expected["kind"]
                            parts = projection_parts(raw)
                            if kind in ("request", "notification"):
                                assert parts[0].decode() == expected["message"]["method"]
                                if "params" in expected["message"]:
                                    assert json.loads(parts[7]) == expected["message"]["params"]
                            if "id" in expected["message"]:
                                assert json.loads(parts[1]) == expected["message"]["id"]
                            if kind in ("response", "error"):
                                assert parts[9] == line
                        cases_total += 1
                        errors_total += len(replies)
                        messages_total += len(actual)
                        outputs.append({"label": case["label"], "projections_hex": projections,
                                        "response_raw": "".join(replies)})
                    exports[domain] = suite.rows(domain + ".jsonl", outputs)
        assert cases_total == 4804
        suite.summary.update(counts={"cases": cases_total, "native_message_calls": calls,
                                     "parsed_messages": messages_total, "transport_error_responses": errors_total},
                             exports=exports, framing_driver="explicit test-only split; actual adapter covered separately")


if __name__ == "__main__":
    main()

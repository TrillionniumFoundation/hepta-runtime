# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Execute every retained direct typed-message case on the native HIA owner."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from connection_test_context import Suite, compare_projection, message_frame


def main():
    with Suite("message") as suite:
        context = suite.context
        calls = 0
        exports = {}
        with context.module("message") as module:
            with module.session(output_capacity=1 << 20, workspace_capacity=2 << 20) as decoder:
                for domain in ["message-core", "message-boundaries"]:
                    cases = context.rows(domain, "requests.jsonl")
                    originals = context.rows(domain, "direct.stdout")
                    transports = {row["label"]: row for row in context.rows(domain, "transport.stdout")}
                    assert len(cases) == len(originals)
                    outputs = []
                    for case, original in zip(cases, originals, strict=True):
                        assert case["label"] == original["label"]
                        raw = bytes.fromhex(case["hex"])
                        output = decoder(message_frame(raw))
                        calls += 1
                        compare_projection(raw, output, original, transports[case["label"]])
                        outputs.append({"label": case["label"], "projection_hex": output.hex()})
                    exports[domain] = suite.rows(domain + ".jsonl", outputs)
        assert calls == 4782
        suite.summary.update(counts={"native_message_calls": calls, "domains": 2}, exports=exports)


if __name__ == "__main__":
    main()

# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Execute persistent HIA admission and original request-context snapshots."""
from pathlib import Path
import json
import struct
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from connection_test_context import Suite, U, pair, connection_frame, message_frame


def main():
    with Suite("connection") as suite:
        context = suite.context
        counts = {"sessions": 0, "message_calls": 0, "connection_calls": 0, "fixture_calls": 0,
                  "context_joins": 0, "response_lines": 0, "eof_calls": 0}
        exports = {}
        with context.module("message") as message, context.module("connection") as connection, context.module("fixture") as fixture:
            with message.session(output_capacity=1 << 20, workspace_capacity=2 << 20) as decoder, fixture.session(output_capacity=1 << 20, workspace_capacity=65536) as handler:
                for domain in ["lifecycle-core", "lifecycle-matrix"]:
                    cases = context.rows(domain, "requests.jsonl")
                    originals = context.rows(domain, "lifecycle.stdout")
                    observed = []
                    for case, reference in zip(cases, originals, strict=True):
                        assert case["label"] == reference["label"]
                        actual, events = [], []
                        closed = False
                        with connection.session(output_capacity=2 << 20, workspace_capacity=1 << 20) as state:
                            for event in case["events"]:
                                if closed:
                                    break
                                raw = bytes.fromhex(event["wire_hex"]) if "wire_hex" in event else event["wire"].encode()
                                projection = decoder(message_frame(raw))
                                counts["message_calls"] += 1
                                action = state(connection_frame(projection))
                                counts["connection_calls"] += 1
                                assert action[:8] == b"HRCNS001"
                                kind = U(action, 8)
                                reply = pair(action, 64) if kind == 1 else b""
                                if 2 <= kind <= 5:
                                    reply = handler(action)
                                    counts["fixture_calls"] += 1
                                    if kind == 2:
                                        identifier = json.loads(pair(projection, 80))
                                        method = pair(projection, 64).decode()
                                        matches = [row["before"] for row in reference["trace"] if "before" in row
                                                   and row["before"]["request_id"] == identifier
                                                   and row["before"]["request"]["method"] == method]
                                        assert matches, (case["label"], "actual original Service request missing")
                                        before = matches[-1]
                                        version = pair(action, 144)
                                        assert (version.decode() if version is not None else None) == before["protocol_version"]
                                        assert json.loads(pair(projection, 96)) == before["metadata"]
                                        peer = before["peer_info"]
                                        assert U(action, 48) == int(peer is not None)
                                        if peer is not None:
                                            assert pair(action, 112).decode() == peer["protocolVersion"]
                                            assert json.loads(pair(action, 96)) == peer["capabilities"]
                                            assert json.loads(pair(action, 128)) == peer["clientInfo"]
                                        counts["context_joins"] += 1
                                if reply:
                                    actual.append(reply + b"\n")
                                events.append({"projection_hex": projection.hex(), "admission_hex": action.hex(), "reply_hex": reply.hex()})
                                closed = bool(U(action, 16))
                            expected = [row["response_raw"].encode() for row in reference["events"] if "response_raw" in row]
                            assert actual == expected, case["label"]
                            assert closed == (reference["terminal"]["phase"] == "startup")
                            end = state(b"HRCNQ001" + struct.pack("<QQ", 2, 0))
                            counts["connection_calls"] += 1
                            counts["eof_calls"] += 1
                            assert U(end, 8) == 6 and U(end, 16) == 1
                        counts["sessions"] += 1
                        counts["response_lines"] += len(actual)
                        observed.append({"label": case["label"], "events": events, "closed_before_eof": closed,
                                         "eof_hex": end.hex(), "response_hex": [row.hex() for row in actual]})
                    exports[domain] = suite.rows(domain + ".jsonl", observed)
        assert counts["sessions"] == 2203 and counts["response_lines"] == 6126
        suite.summary.update(counts=counts, exports=exports, fixture_handler_is_test_only=True)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# Licensed under the Apache License, Version 2.0.
"""Negative controls for native final-frame qualification evidence."""

import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import rea_frame_mcp_qualification as runner


class FrameQualificationBoundaries(unittest.TestCase):
    def test_maximum_inputs_preserve_escaped_and_plain_ids(self):
        for modern in (False, True):
            params = runner.params("bundle", modern=modern, omit=True)
            for motif in ("i", '\x00"\\雪😀'):
                request_id = runner.maximal_id(params, motif, 4096)
                raw = runner.call_bytes(params, request_id)
                self.assertEqual(len(raw), 4096)
                self.assertEqual(json.loads(raw)["id"], request_id)
                smallest = {"jsonrpc": "2.0", "id": request_id,
                            "error": {"code": -32603, "message": ""}}
                encoded = (json.dumps(smallest, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
                self.assertLess(len(encoded), len(raw))

    def test_mismatched_id_and_unterminated_or_oversized_frame_are_failures(self):
        response = {"jsonrpc": "2.0", "id": "original", "error": {"code": -32603, "message": ""}}
        raw = (json.dumps(response) + "\n").encode()
        runner.validate_envelope(response, "original", raw, cap=len(raw))
        for request_id, wire, cap in (("other", raw, len(raw)), ("original", raw[:-1], len(raw)),
                                      ("original", raw, len(raw) - 1)):
            with self.assertRaises(ValueError):
                runner.validate_envelope(response, request_id, wire, cap)

    def test_stale_context_and_false_lower_bound_cannot_pass(self):
        body = {"error": {"details": {"operation": "inspect_elf_notes", "reported_limits": {
            "boundary": "native-mcp-frame", "max_frame_bytes": runner.FRAME_BYTES,
            "frame_bytes_at_least": runner.FRAME_BYTES + 1,
            "includes_request_id": True, "includes_newline": True}}}}
        response = {"result": {"isError": True, "content": [{"type": "text", "text": json.dumps(body)}],
                               "_meta": runner.q.TARGET_META}}
        runner.frame_refusal(response, "inspect_elf_notes", runner.q.TARGET_META)
        with self.assertRaisesRegex(ValueError, "stale operation"):
            runner.frame_refusal(response, "get_evidence_bundle", runner.q.TARGET_META)
        changed = copy.deepcopy(body)
        changed["error"]["details"]["reported_limits"]["frame_bytes_at_least"] = runner.FRAME_BYTES
        response["result"]["content"][0]["text"] = json.dumps(changed)
        with self.assertRaisesRegex(ValueError, "boundary facts"):
            runner.frame_refusal(response, "inspect_elf_notes", runner.q.TARGET_META)

    def test_gzip_log_is_lossless_and_tampering_is_detected(self):
        with tempfile.TemporaryDirectory() as temporary:
            client = runner.CompressedMcp.__new__(runner.CompressedMcp)
            client.output = Path(temporary)
            client.entries = []
            client.lock = threading.Lock()
            raw = runner.call_bytes(runner.params("bundle"), '\x00"\\雪😀' * 100)
            with (client.output / "wire.jsonl").open("xb") as client.wire:
                client._log("sent", raw)
            entry = client.entries[0]
            self.assertEqual(client.original(entry), raw)
            self.assertEqual(entry["raw_sha256"], hashlib.sha256(raw).hexdigest())
            path = client.output / entry["path"]
            path.write_bytes(path.read_bytes() + b"changed")
            with self.assertRaisesRegex(ValueError, "compressed wire changed"):
                client.original(entry)


if __name__ == "__main__":
    unittest.main()

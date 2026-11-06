#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Independent refusal controls for the ELF family runner, not execution receipts."""

import copy
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import rea_elf_evidence_family_qualification as h
import rea_operation_qualification as q


def original_row():
    response = {"jsonrpc": "2.0", "id": 3, "result": {
        "content": [{"type": "text", "text": '{"b":2,"a":1}'}],
        "structuredContent": {"b": 2, "a": 1}, "_meta": q.TARGET_META}}
    return {"id": "case", "operation": "inspect_elf_notes", "arguments": {"max_entries": 1},
            "response": response, "response_bytes": 200, "response_sha256": "1" * 64}


def successful_page(raw, offset=0, length=7):
    end = min(offset + length, len(raw))
    chunk = raw[offset:end]
    digest = hashlib.sha256(raw).hexdigest()
    page = {"profile": h.READBACK_PROFILE, "snapshot_id": "ebs1_" + digest,
            "sha256": digest, "total_bytes": len(raw), "records": 3, "unknowns": 0,
            "encoding": "hex", "offset": offset, "length": len(chunk), "bytes_hex": chunk.hex(),
            "chunk_sha256": hashlib.sha256(chunk).hexdigest(), "next_offset": end if end < len(raw) else None,
            "eof": end == len(raw), "persistence": "session-only"}
    body = {"result": page}
    return {"result": {"content": [{"type": "text", "text": json.dumps(body)}],
                       "structuredContent": body, "_meta": q.TARGET_META}}


class ElfFamilyRefusalTests(unittest.TestCase):
    def test_oversized_fixture_has_one_complete_physical_note_and_outside_padding(self):
        raw = h.oversized_elf()
        self.assertEqual(len(raw), 6291592)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), h.OVERSIZED_SHA256)
        self.assertEqual(raw[:6], b"\x7fELF\x02\x01")
        phoff = struct.unpack_from("<Q", raw, 32)[0]
        self.assertEqual(struct.unpack_from("<HH", raw, 54), (56, 1))
        kind, flags, offset, virtual, physical, file_bytes, memory_bytes, alignment = struct.unpack_from("<IIQQQQQQ", raw, phoff)
        self.assertEqual((kind, offset, file_bytes, memory_bytes, alignment), (4, 120, h.DESCRIPTOR_BYTES + 16, h.DESCRIPTOR_BYTES + 16, 4))
        self.assertEqual(struct.unpack_from("<III", raw, offset), (4, h.DESCRIPTOR_BYTES, 3))
        self.assertEqual(raw[offset + 12:offset + 16], b"GNU\0")
        descriptor = raw[136:136 + h.DESCRIPTOR_BYTES]
        self.assertEqual(hashlib.sha256(descriptor).hexdigest(), h.DESCRIPTOR_SHA256)
        self.assertEqual(raw[offset + file_bytes:], bytes(h.DESCRIPTOR_BYTES))
        self.assertLess(2 * len(descriptor) + 11, len(raw))
        self.assertGreater(2 * len(descriptor.hex()), 10 * 1024 * 1024)
        self.assertLess(len(descriptor.hex()), h.MAX_EXPORT_BYTES)

    def test_embedded_text_reordering_is_a_complete_result_failure(self):
        original = original_row()
        changed = copy.deepcopy(original)
        changed["response"]["result"]["content"][0]["text"] = '{ "a": 1, "b": 2 }'
        self.assertTrue(q.json_equal(q.tool_value(original["response"]), q.tool_value(changed["response"])))
        compared = h.compare_row(original, changed)
        self.assertEqual(compared["status"], "FAIL")
        self.assertFalse(compared["opaque_text_equal"])

    def test_outer_object_order_is_distinct_from_raw_wire_byte_equality(self):
        original = original_row()
        changed = copy.deepcopy(original)
        changed["response"] = dict(reversed(list(changed["response"].items())))
        changed["response_sha256"] = "2" * 64
        result = h.compare_row(original, changed)
        self.assertEqual(result["status"], "PASS")
        self.assertTrue(result["jsonrpc_object_equal"])
        self.assertFalse(result["raw_jsonrpc_frame_equal"])

    def test_boolean_arguments_do_not_bind_numeric_requests(self):
        changed = original_row()
        changed["arguments"]["max_entries"] = True
        with self.assertRaises(q.QualificationError):
            h.compare_row(original_row(), changed)

    def test_missing_provenance_or_invented_calltoolresult_fails(self):
        changed = original_row()
        del changed["response"]["result"]["_meta"]
        self.assertEqual(h.compare_row(original_row(), changed)["status"], "FAIL")
        changed["response"] = {"error": {"code": -1}}
        with self.assertRaises(q.QualificationError):
            h.compare_row(original_row(), changed)

    def test_reused_case_count_cannot_hide_a_missing_or_duplicated_case(self):
        close = {"returncode": 0, "forced_cleanup": [], "reader_stopped": True,
                 "owner_pidfd_exited": True, "process_group_gone": True}
        sessions = {(label, scenario): SimpleNamespace(
            rows=[{"id": case} for case in cases], state={"close": copy.deepcopy(close)})
            for label in ("reference", "native") for scenario, cases in h.EXPECTED_CASES.items()}
        self.assertTrue(h.complete_sequences(sessions))
        sessions[("native", "restore")].rows[-1] = sessions[("native", "restore")].rows[-2]
        self.assertFalse(h.complete_sequences(sessions))
        sessions[("native", "restore")].rows[-1] = {"id": h.EXPECTED_CASES["restore"][-1]}
        sessions[("native", "cold")].state["close"]["forced_cleanup"] = ["SIGTERM"]
        self.assertFalse(h.complete_sequences(sessions))

    def test_snapshot_chunk_hash_or_continuation_mutation_is_not_accepted(self):
        raw = '{"path":"中文🙂"}'.encode()
        offset = raw.index("中".encode()) + 1
        original = successful_page(raw, offset, 1)
        self.assertEqual(h.readback_page(original, raw, 3, offset, 1)["bytes_hex"], raw[offset:offset + 1].hex())
        for key, changed_value in (("chunk_sha256", "0" * 64), ("next_offset", offset + 2),
                                   ("eof", True), ("records", True), ("bytes_hex", "00")):
            changed = copy.deepcopy(original)
            changed["result"]["structuredContent"]["result"][key] = changed_value
            changed["result"]["content"][0]["text"] = json.dumps(changed["result"]["structuredContent"])
            with self.subTest(key=key), self.assertRaises(q.QualificationError):
                h.readback_page(changed, raw, 3, offset, 1)

    def test_snapshot_from_different_complete_bytes_is_refused(self):
        raw = b'{"records":[]}'
        with self.assertRaises(q.QualificationError):
            h.readback_page(successful_page(raw), raw, 3, 0, 7, "ebs1_" + "0" * 64)

    def test_stable_file_reader_refuses_symlinks_hardlinks_and_fifos(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = root / "source"
            original.write_bytes(b"fixed")
            raw, identity = h.read_stable(original, 5)
            self.assertEqual(raw, b"fixed")
            self.assertEqual(identity["sha256"], hashlib.sha256(b"fixed").hexdigest())
            with self.assertRaises(q.QualificationError):
                h.read_stable(original, 4)
            alias = root / "symlink"
            alias.symlink_to(original)
            with self.assertRaises(q.QualificationError):
                h.read_stable(alias, 5)
            os.link(original, root / "hardlink")
            with self.assertRaises(q.QualificationError):
                h.read_stable(original, 5)
            fifo = root / "fifo"
            os.mkfifo(fifo)
            with self.assertRaises(q.QualificationError):
                h.read_stable(fifo, 5)


if __name__ == "__main__":
    unittest.main()

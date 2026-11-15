#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Native private-state controls, distinct from executed ELF semantic traces.

Snapshots are injected test state. Forged child receipts are rejection controls:
no child runs, and they never count as completed original or native operations.
"""
from __future__ import annotations
import ctypes
import gzip
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from hia_native_loader import NativeModule

INVALID, CAPACITY, STATE, CALL = 0xffffffff, 0xfffffffe, 0xfffffffd, 0xffffffe0
MAXIMUM = (1 << 64) - 1
ARENA = (16 << 20) + 8192
WORK = ARENA + 512
REPLY = (8 << 20) + 4096
RECORDS = []


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def request(magic, operation, generation=1, sequence=1, a=0, b=0, payload=b""):
    return magic + struct.pack("<7Q", operation, generation, sequence, a, b, len(payload), 0) + payload


def put(session, offset, value):
    ctypes.memmove(ctypes.addressof(session._workspace) + offset, struct.pack("<Q", value), 8)


def scope_state(session, *, phase=1, generation=1, sequence=1):
    raw = b"HRSCST01" + struct.pack("<8Q", 1, generation, phase, sequence, 3, 5,
                                     1 if phase in (1, 2) else 0, 2 if phase in (1, 2) else 0)
    ctypes.memmove(session._workspace, raw, len(raw))


def lease_state(session, *, count=1, last=None, epoch=1, phase=1):
    raw = b"HRCLST01" + struct.pack("<6Q", 1, epoch, phase, count, count if last is None else last, 6)
    ctypes.memmove(session._workspace, raw, len(raw))
    for index in range(count):
        put(session, ARENA + 8 * index, index + 1)


class BoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        manifest = Path(os.environ["HIA_REQUEST_SCOPE_MANIFEST"])
        metadata = json.loads(manifest.read_bytes())
        cls.modules = {}
        for label, index, source in (("scope", 1, "native/request_scope_lifecycle.hepta"),
                                     ("lease", 5, "native/request_cache_lease.hepta")):
            path = manifest.parent / metadata["members"][index]["manifest"]
            raw = path.read_bytes()
            child = json.loads(raw)
            if sha(raw) != metadata["members"][index]["manifest_sha256"] or child["source_sha256"] != sha((ROOT / source).read_bytes()):
                raise ValueError("boundary owner source or image identity differs")
            cls.modules[label] = NativeModule(path, manifest_sha256=sha(raw))
        destination = os.environ.get("HIA_REQUEST_SCOPE_BOUNDARY_DIR")
        cls.corpus = Path(destination) if destination else None
        if cls.corpus:
            cls.corpus.mkdir(parents=True, exist_ok=False)

    @classmethod
    def tearDownClass(cls):
        for module in cls.modules.values():
            module.close()

    def session(self, kind, *, output=128, workspace=WORK):
        session = self.modules[kind].session(output_capacity=output, workspace_capacity=workspace)
        self.addCleanup(session.close)
        return session

    def refuses(self, label, session, wire, expected, *, extended_input=False):
        ctypes.memset(session._output, 0xa5, session.output_capacity)
        before = session._workspace.raw[:session.workspace_capacity]
        if extended_input:
            # Deliberately probe the borrowed entry beyond the standard transport
            # profile; each actual allocation still covers its complete buffer.
            source = ctypes.create_string_buffer(wire, len(wire))
            ctypes.memset(ctypes.addressof(session._output) + session.output_capacity, 0xa5, 16)
            ctypes.memset(ctypes.addressof(session._workspace) + session.workspace_capacity, 0x5a, 16)
            code = session.module._entry(source, len(wire), session._output, session.output_capacity,
                                         session._workspace, session.workspace_capacity)
            self.assertEqual(source.raw, wire)
            self.assertEqual(ctypes.string_at(ctypes.addressof(session._output) + session.output_capacity, 16), b"\xa5" * 16)
            self.assertEqual(ctypes.string_at(ctypes.addressof(session._workspace) + session.workspace_capacity, 16), b"\x5a" * 16)
            output = session._output.raw[:session.output_capacity]
            after = session._workspace.raw[:session.workspace_capacity]
        else:
            code, output, after = session.invoke_raw(wire)
        streams = {"input": wire, "workspace-before": before, "workspace-after": after,
                   "output-before": b"\xa5" * session.output_capacity, "output-after": output}
        record = {"label": label, "classification": "injected-private-state-native-refusal",
                  "actual_code": code, "expected_code": expected, "native_calls": 1,
                  "input_beyond_standard_transport_profile": extended_input,
                  "executed_native_children": 0, "original_operations": 0,
                  "streams": {name: {"bytes": len(raw), "sha256": sha(raw)} for name, raw in streams.items()}}
        if self.corpus:
            for name, raw in streams.items():
                relative = f"{len(RECORDS):03d}.{label}.{name}.gz"
                compressed = gzip.compress(raw, mtime=0)
                with (self.corpus / relative).open("xb") as handle:
                    handle.write(compressed)
                record["streams"][name].update({"path": relative, "gzip_bytes": len(compressed), "gzip_sha256": sha(compressed)})
        RECORDS.append(record)
        self.assertEqual(code, expected, label)
        self.assertEqual(output, b"\xa5" * session.output_capacity, label)
        self.assertEqual(after, before, label)

    def test_01_actual_supplied_lease_arena_capacity(self):
        s = self.session("lease")
        lease_state(s, count=32)
        self.refuses("full-actual-arena", s, request(b"HRCLQ001", 2), CAPACITY)
        put(s, 32, 33)
        self.refuses("count-beyond-actual-arena", s, request(b"HRCLQ001", 2), STATE)
        put(s, 32, 32)
        put(s, 40, MAXIMUM)
        self.refuses("lease-counter-does-not-wrap", s, request(b"HRCLQ001", 2), CAPACITY)
        put(s, 40, 32)
        put(s, ARENA + 8, 1)
        self.refuses("duplicate-private-record", s, request(b"HRCLQ001", 2), STATE)

    def test_02_generation_sequence_and_closed_state(self):
        for label, field, value in (("bad-magic", 0, 7), ("bad-version", 8, 2), ("zero-generation", 16, 0),
                                    ("opening-not-accessible", 24, 4), ("zero-continuation", 32, 0),
                                    ("absent-cache-epoch", 56, 0), ("absent-live-lease", 64, 0)):
            s = self.session("scope")
            scope_state(s)
            put(s, field, value)
            self.refuses(label, s, request(b"HRSCQ001", 2), STATE)
        s = self.session("scope")
        scope_state(s, phase=0, generation=MAXIMUM)
        self.refuses("scope-generation-does-not-wrap", s,
                     request(b"HRSCQ001", 1, 0, 0, 3, 5, struct.pack("<2Q", 1, 1)), STATE)
        s = self.session("scope")
        scope_state(s, sequence=MAXIMUM)
        self.refuses("continuation-does-not-wrap", s, request(b"HRSCQ001", 5, sequence=MAXIMUM), STATE)
        s = self.session("scope")
        scope_state(s)
        put(s, 256, MAXIMUM)
        self.refuses("bridge-sequence-does-not-wrap", s, request(b"HRSCQ001", 2), STATE)
        s = self.session("lease")
        lease_state(s, count=0, epoch=MAXIMUM, phase=0)
        self.refuses("cache-epoch-does-not-wrap", s, request(b"HRCLQ001", 1, 0, 0, 6), STATE)

    def test_03_forged_child_receipts_cannot_complete_access(self):
        s = self.session("scope")
        scope_state(s)
        wire = request(b"HRSCQ001", 2)
        code, output, state = s.invoke_raw(wire)
        self.assertEqual(code, CALL)
        self.assertEqual(struct.unpack_from("<Q", state, 264)[0], 4)
        # Only a child request was issued. No child is invoked in this group.
        footer = WORK - 256
        original_sequence = struct.unpack_from("<Q", state, footer + 8)[0]
        for label, offset, value in (("ack-magic", 0, 0), ("ack-sequence", 8, original_sequence + 1),
                                     ("ack-target", 16, 4), ("ack-input-region", 24, 1),
                                     ("ack-input-offset", 32, 4097), ("ack-input-length", 40, 31),
                                     ("ack-output-region", 48, 1), ("ack-output-offset", 56, REPLY + 1),
                                     ("ack-output-capacity", 64, 39), ("ack-reserved", 72, 1),
                                     ("ack-completed-sequence", 88, original_sequence + 1),
                                     ("ack-completed-flag", 96, 0), ("ack-status", 104, 5),
                                     ("ack-status-with-success", 104, 1), ("ack-dirty-upper-result", 80, 1 << 32)):
            ctypes.memmove(s._workspace, state, len(state))
            put(s, footer + 80, 40)
            put(s, footer + 88, original_sequence)
            put(s, footer + 96, 1)
            put(s, footer + 104, 0)
            put(s, footer + offset, value)
            self.refuses(label, s, wire, STATE)
        ctypes.memmove(s._workspace, state, len(state))
        put(s, footer + 80, 40)
        put(s, footer + 88, original_sequence)
        put(s, footer + 96, 1)
        put(s, footer + 104, 0)
        fake_reply = b"HRCXR001" + struct.pack("<4Q", 3, 1, 8, 99)
        ctypes.memmove(ctypes.addressof(s._workspace) + REPLY, fake_reply, len(fake_reply))
        self.refuses("ack-wrong-private-cache-association", s, wire, STATE)

    def test_04_fixed_header_and_minimum_buffer_boundaries(self):
        for kind, magic, op in (("scope", b"HRSCQ001", 2), ("lease", b"HRCLQ001", 5)):
            s = self.session(kind, workspace=WORK - 1)
            self.refuses(kind + "-workspace-short", s, request(magic, op), CAPACITY)
            s = self.session(kind, output=63)
            self.refuses(kind + "-output-short", s, request(magic, op), CAPACITY)
            s = self.session(kind)
            self.refuses(kind + "-truncated-header", s, request(magic, op)[:63], INVALID)
            self.refuses(kind + "-trailing-byte", s, request(magic, op) + b"x", INVALID)
        for size in ((8 << 20) - 31, 16 << 20):
            s = self.session("scope")
            scope_state(s)
            wire = request(b"HRSCQ001", 3, payload=b"a" * size)
            self.refuses("push-window-overflow-" + str(size), s, wire, CAPACITY, extended_input=True)


if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(BoundaryTests))
    summary = {"schema": "hepta.runtime.request-scope-boundary-corpus.v1", "groups": result.testsRun,
               "status": "PASS" if result.wasSuccessful() else "FAIL", "native_refusal_calls": len(RECORDS),
               "native_child_requests_issued_without_execution": 1, "executed_native_children": 0,
               "original_operations": 0, "records": RECORDS}
    raw = (json.dumps(summary, sort_keys=True) + "\n").encode()
    if getattr(BoundaryTests, "corpus", None):
        with (BoundaryTests.corpus / "native-boundary-corpus.json").open("xb") as handle:
            handle.write(raw)
    sys.stdout.buffer.write(raw)
    raise SystemExit(0 if result.wasSuccessful() else 1)

#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Differential tests of actual HIA machine code, with original Rust oracle export.

Set HIA_BYTES_MANIFEST to the compiled module manifest. Optional
HIA_BYTES_CORPUS_DIR retains gzip-compressed input/native-output streams for
tests/hia_native/oracle_runtime_bytes.rs. No production semantic fallback runs.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import os
from pathlib import Path
import random
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from hia_native_loader import NativeCapacityError, NativeModule, NativeRejected

MASK = (1 << 64) - 1
INVALID = 0xFFFFFFFF
CAPACITY = 0xFFFFFFFE
ZERO_INDEX = 0xFFFFFFFD
POSITIVE_RANGE = 0xFFFFFFFC
NEGATIVE_RANGE = 0xFFFFFFFB
CURSOR_RANGE = 0xFFFFFFFA
MAGIC = b"HRTKERN1"
NATIVE_INPUT = bytearray()
NATIVE_OUTPUT = bytearray()
COUNTS = {"native_calls": 0, "rust_oracle_cases": 0, "byte_extension_cases": 0}


def frame(op: int, a: int = 0, b: int = 0, c: int = 0, payload: bytes = b"") -> bytes:
    return MAGIC + struct.pack("<QQQQ", op, a & MASK, b, c) + payload


def fnv_reference(raw: bytes) -> bytes:
    # Independent fold: XOR the four little-endian bytes of the FNV32 result.
    value = 2166136261
    for byte in raw:
        value = ((value ^ byte) * 16777619) % (1 << 32)
    folded = 0
    for byte in value.to_bytes(4, "little"):
        folded ^= byte
    return bytes(f"{folded:02x}", "ascii")


def reference(raw: bytes, capacity: int) -> tuple[int, bytes]:
    if len(raw) < 40 or raw[:8] != MAGIC:
        return INVALID, b""
    op, a, b, c = struct.unpack_from("<QQQQ", raw, 8)
    if (not 1 <= op <= 8 or (3 <= op <= 5 and len(raw) != 40)
            or (op != 5 and c != 0) or ((op == 1 or op >= 6) and a != 0)
            or ((op <= 2 or op >= 6) and b != 0)):
        return INVALID, b""
    payload = raw[40:]
    if op == 1:
        output = fnv_reference(payload)
    elif op == 2:
        output = str(a).encode() + b":" + fnv_reference(payload)
    elif op in (3, 4):
        if a == 0:
            return ZERO_INDEX, b""
        index = a if a < 1 << 63 else a - (1 << 64)
        if index > 0:
            if index > b:
                if op == 3:
                    return POSITIVE_RANGE, b""
                line, clamped = b, True
            else:
                line, clamped = index, False
        else:
            # Preserve Rust checked_neg().unwrap_or(usize::MAX), not abs(MIN).
            magnitude = MASK if index == -(1 << 63) else -index
            if magnitude > b:
                if op == 3:
                    return NEGATIVE_RANGE, b""
                line, clamped = 1, True
            else:
                line, clamped = b - magnitude + 1, False
        output = struct.pack("<QQ", line, int(clamped))
    elif op == 5:
        if a > b:
            return CURSOR_RANGE, b""
        limit = max(1, min(c, 16384))
        count = min(limit, b - a)
        next_offset = a + count
        output = struct.pack("<QQQQ", count, next_offset, int(next_offset >= b), limit)
    elif op == 6:
        allowed = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-@"
        output = bytes([bool(payload) and len(payload) <= 128
                        and all(byte in allowed for byte in payload)])
    elif op == 7:
        output = bytes([len(payload) == 64 and payload != b"0" * 64
                        and all(byte in b"0123456789abcdef" for byte in payload)])
    else:
        output = bytes([bool(payload) and len(payload) <= 256
                        and all(33 <= byte <= 126 for byte in payload)])
    return (len(output), output) if len(output) <= capacity else (CAPACITY, b"")


def original_text_domain(raw: bytes) -> bool:
    if len(raw) < 40 or raw[:8] != MAGIC:
        return True
    op = struct.unpack_from("<Q", raw, 8)[0]
    if op not in (1, 2, 6, 7, 8):
        return True
    try:
        raw[40:].decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def selected_manifest() -> Path:
    selected = os.environ.get("HIA_BYTES_MANIFEST")
    if selected:
        return Path(selected).resolve(strict=True)
    dependency = os.environ.get("HIA_HEPTA_DIR")
    build_root = os.environ.get("HIA_BUILD_ROOT")
    if not dependency or not build_root:
        raise RuntimeError("set HIA_BYTES_MANIFEST, or HIA_HEPTA_DIR and HIA_BUILD_ROOT")
    from hia_native_build import NativeBuild
    cached = Path(build_root) / "modules" / "runtime-bytes" / "manifest.json"
    if cached.exists():
        return cached
    return NativeBuild(dependency, build_root).compile(
        "runtime-bytes", ROOT / "native" / "runtime_bytes.hepta", standalone=None)


class RuntimeBytesNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = selected_manifest()
        cls.manifest_bytes = cls.manifest.read_bytes()
        cls.module = NativeModule(cls.manifest,
                                  manifest_sha256=hashlib.sha256(cls.manifest_bytes).hexdigest())
        expected = hashlib.sha256((ROOT / "native" / "runtime_bytes.hepta").read_bytes()).hexdigest()
        if cls.module.metadata["source_sha256"] != expected:
            raise RuntimeError("selected module is not built from this runtime_bytes.hepta")

    @classmethod
    def tearDownClass(cls):
        cls.module.close()
        corpus_dir = os.environ.get("HIA_BYTES_CORPUS_DIR")
        if corpus_dir:
            folder = Path(corpus_dir)
            folder.mkdir(parents=True, exist_ok=True)
            values = {"input.bin.gz": bytes(NATIVE_INPUT),
                      "native-output.bin.gz": bytes(NATIVE_OUTPUT)}
            entries = {}
            for name, raw in values.items():
                encoded = gzip.compress(raw, mtime=0)
                (folder / name).write_bytes(encoded)
                entries[name] = {"compressed_bytes": len(encoded),
                                 "sha256": hashlib.sha256(encoded).hexdigest(),
                                 "raw_bytes": len(raw),
                                 "raw_sha256": hashlib.sha256(raw).hexdigest()}
            report = {"schema": "hepta.runtime.bytes-native-tests.v1",
                      "baseline_commit": "a0dcdda1991ec536d5e2d252c006a778993fa566",
                      "module": cls.module.metadata,
                      "counts": COUNTS, "corpus": entries,
                      "native_buffer_guards_checked": True,
                      "rust_oracle_executed_by_this_suite": False}
            (folder / "native-corpus.json").write_text(json.dumps(report, indent=2) + "\n")

    def check(self, raw: bytes, capacity: int = 64, expected=None, workspace_capacity: int = 37):
        want_code, want_output = reference(raw, capacity) if expected is None else expected
        code, output, workspace = self.module.invoke_raw(
            raw, output_capacity=capacity, workspace_capacity=workspace_capacity,
            output_fill=0xA7, workspace_fill=0x5C)
        self.assertEqual(code, want_code, (raw[:40].hex(), capacity))
        self.assertEqual(workspace, b"\x5c" * workspace_capacity, "unused workspace changed")
        if code >= 0xFFFF0000:
            self.assertEqual(output, b"\xa7" * capacity, "failure changed the output")
            body = b""
        else:
            self.assertEqual(output[:code], want_output, raw[:40].hex())
            self.assertEqual(output[code:], b"\xa7" * (capacity - code), "output tail changed")
            body = output[:code]
        COUNTS["native_calls"] += 1
        if original_text_domain(raw):
            NATIVE_INPUT.extend(struct.pack("<QQ", len(raw), capacity) + raw)
            NATIVE_OUTPUT.extend(struct.pack("<QQ", code, len(body)) + body)
            COUNTS["rust_oracle_cases"] += 1
        else:
            COUNTS["byte_extension_cases"] += 1

    def test_fixed_hash_vectors_and_line_ids(self):
        vectors = [(b"", b"c5"), (b"a", b"ed"), (b"hello", b"57"),
                   (b"hello world", b"c6")]
        for payload, digest in vectors:
            self.check(frame(1, payload=payload), expected=(2, digest))
            for line in (0, 1, 9, 10, 99, 100, 1000, (1 << 63) - 1, 1 << 63, MASK):
                output = str(line).encode() + b":" + digest
                self.check(frame(2, line, payload=payload), expected=(len(output), output))

    def test_hash_utf8_and_binary_extension(self):
        samples = ["\x00", "\r\n", "one\ntwo", "汉字", "é", "e\u0301", "😀",
                   "\uffff\U0010ffff", " \t ", "line ", "line"]
        for sample in samples:
            self.check(frame(1, payload=sample.encode()))
        rng = random.Random(0x484941)
        for _ in range(300):
            values = [rng.randrange(0x110000) for _ in range(rng.randrange(80))]
            text = "".join(chr(v) for v in values if not 0xD800 <= v <= 0xDFFF)
            self.check(frame(1, payload=text.encode()))
        for size in (1, 2, 15, 16, 255, 256, 4095, 4096, 65536, 262144):
            self.check(frame(1, payload=(bytes(range(256)) * (size // 256 + 1))[:size]))
        self.check(frame(1, payload=b"bounded line " * 16384))

    def test_line_index_exhaustive_small_domain(self):
        for total in range(64):
            for index in range(-70, 71):
                for op in (3, 4):
                    self.check(frame(op, index, total))

    def test_line_index_integer_boundaries(self):
        totals = (0, 1, 2, (1 << 31) - 1, 1 << 32, (1 << 63) - 1, 1 << 63, MASK - 1, MASK)
        indices = (-(1 << 63), -(1 << 63) + 1, -(1 << 32), -1, 0, 1,
                   (1 << 31) - 1, 1 << 32, (1 << 63) - 1)
        for total in totals:
            for index in indices:
                for op in (3, 4):
                    self.check(frame(op, index, total))
        rng = random.Random(0x4C494E45)
        for _ in range(1000):
            self.check(frame(rng.choice((3, 4)), rng.randrange(1 << 64), rng.randrange(1 << 64)))
        # These corner cases intentionally retain the original Rust function.
        self.check(frame(4, 1, 0), expected=(16, struct.pack("<QQ", 0, 1)))
        self.check(frame(4, -1, 0), expected=(16, struct.pack("<QQ", 1, 1)))
        for op in (3, 4):
            self.check(frame(op, -(1 << 63), MASK), expected=(16, struct.pack("<QQ", 1, 0)))

    def test_log_page_boundary_and_overflow_domain(self):
        sizes = (0, 1, 2, 16383, 16384, 16385, (1 << 32) - 1, 1 << 63, MASK - 1, MASK)
        limits = (0, 1, 2, 16383, 16384, 16385, 65536, 1 << 63, MASK)
        for size in sizes:
            offsets = {0, size, max(0, size - 1), max(0, size - 16384), min(MASK, size + 1)}
            for offset in sorted(offsets):
                for limit in limits:
                    self.check(frame(5, offset, size, limit))
        rng = random.Random(0x50414745)
        for _ in range(1000):
            self.check(frame(5, rng.randrange(1 << 64), rng.randrange(1 << 64),
                             rng.randrange(1 << 64)))

    def test_name_and_text_ascii_domains(self):
        for byte in range(256):
            for op in (6, 8):
                self.check(frame(op, payload=bytes([byte])))
        for op, bound in ((6, 128), (8, 256)):
            for count in (0, 1, bound - 1, bound, bound + 1, bound * 2):
                self.check(frame(op, payload=b"a" * count))
        for text in ("host@a._-1", "..", ".", "/", "a/b", "汉字", "é", "Ｈost",
                     "with space", " leading", "trailing ", "\x00", "\n", "\t"):
            for op in (6, 8):
                self.check(frame(op, payload=text.encode()))

    def test_nonzero_lowercase_sha256_grammar(self):
        for length in (0, 1, 63, 64, 65, 128):
            for byte in (b"0", b"a", b"f", b"F"):
                self.check(frame(7, payload=byte * length))
        for position in (0, 31, 63):
            for byte in range(256):
                raw = bytearray(b"0" * 64)
                raw[position] = byte
                self.check(frame(7, payload=bytes(raw)))
        self.check(frame(7, payload=b"0123456789abcdef" * 4), expected=(1, b"\x01"))

    def test_capacity_and_untouched_buffers(self):
        requests = [frame(1, payload=b"hello"), frame(2, MASK, payload=b"hello"),
                    frame(3, -1, 5), frame(4, -99, 5), frame(5, 2, 19, 7),
                    frame(6, payload=b"host"), frame(7, payload=b"a" * 64),
                    frame(8, payload=b"caller")]
        for raw in requests:
            needed = reference(raw, 64)[0]
            for capacity in sorted({0, 1, max(0, needed - 1), needed, needed + 1, 64}):
                for workspace_size in (0, 1, 37):
                    self.check(raw, capacity, workspace_capacity=workspace_size)

    def test_malformed_frames_and_error_precedence(self):
        original = frame(1, payload=b"hello")
        for length in range(40):
            self.check(original[:length], capacity=0)
        for position in range(8):
            raw = bytearray(original)
            raw[position] ^= 0xFF
            self.check(bytes(raw))
        for op in (0, 9, 255, (1 << 32) - 1, MASK):
            self.check(frame(op))
        for op in range(1, 9):
            for field in (0, 1, 2):
                words = [0, 0, 0]
                words[field] = 1
                self.check(frame(op, *words), capacity=0)
        for op in (3, 4, 5):
            self.check(frame(op, 1, 5, payload=b"extra"))
        for capacity in (0, 1, 64):
            self.check(frame(3, 0, 0), capacity, expected=(ZERO_INDEX, b""))
            self.check(frame(3, 1, 0), capacity, expected=(POSITIVE_RANGE, b""))
            self.check(frame(3, -1, 0), capacity, expected=(NEGATIVE_RANGE, b""))
            self.check(frame(5, MASK, 0), capacity, expected=(CURSOR_RANGE, b""))

    def test_public_loader_preserves_domain_rejections(self):
        for raw, code in ((b"bad", INVALID), (frame(3, 0, 5), ZERO_INDEX),
                          (frame(3, 6, 5), POSITIVE_RANGE), (frame(3, -6, 5), NEGATIVE_RANGE),
                          (frame(5, 9, 8), CURSOR_RANGE)):
            with self.assertRaises(NativeRejected) as caught:
                self.module.invoke(raw, output_capacity=64, workspace_capacity=0)
            self.assertEqual(caught.exception.code, code)
        with self.assertRaises(NativeCapacityError):
            self.module.invoke(frame(1), output_capacity=1, workspace_capacity=0)
        self.assertEqual(self.module.invoke(frame(1, payload=b"hello"),
                                           output_capacity=2, workspace_capacity=0), b"57")


if __name__ == "__main__":
    unittest.main(verbosity=2)

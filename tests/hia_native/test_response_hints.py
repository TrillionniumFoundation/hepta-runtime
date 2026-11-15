#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Execute real HIA response formatting and retain complete original-domain bytes."""
from __future__ import annotations

import gzip
import hashlib
import json
import os
from pathlib import Path
import random
import struct
import subprocess
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from hia_native_loader import NativeModule

INVALID = 0xFFFFFFFF
CAPACITY = 0xFFFFFFFE
INPUT_BYTES = 8 << 20
PREFIX = b"\xe2\x9a\xa0\xef\xb8\x8f "
NATIVE_INPUT = bytearray()
NATIVE_OUTPUT = bytearray()
COUNTS = {"native_calls": 0, "original_semantic_cases": 0,
          "invalid_frame_controls": 0, "invalid_utf8_controls": 0,
          "capacity_controls": 0, "actual_static_elf_processes": 0,
          "reused_workspace_requests": 0, "unicode_scalars": 0}
ELF_RECORDS = []


def drain_frame(hints: list[bytes]) -> bytes:
    payload = b"".join(struct.pack("<Q", len(hint)) + hint for hint in hints)
    return b"HRCXR001" + struct.pack("<QQQ", 1, len(hints), len(payload)) + payload


def frame(base: bytes, hints: list[bytes]) -> bytes:
    drain = drain_frame(hints)
    return b"HRHAQ001" + struct.pack("<QQQ", len(base), len(drain), 0) + base + drain


def word_changed(raw: bytes, at: int, value: int) -> bytes:
    return raw[:at] + struct.pack("<Q", value) + raw[at + 8:]


def selected_manifest() -> Path:
    selected = os.environ.get("HIA_RESPONSE_HINTS_MANIFEST")
    if selected:
        return Path(selected).resolve(strict=True)
    dependency = os.environ.get("HIA_HEPTA_DIR")
    build_root = os.environ.get("HIA_BUILD_ROOT")
    if not dependency or not build_root:
        raise RuntimeError("set HIA_RESPONSE_HINTS_MANIFEST or HIA_HEPTA_DIR/HIA_BUILD_ROOT")
    cached = Path(build_root) / "modules/response-hints/manifest.json"
    if cached.exists():
        return cached
    from hia_native_build import NativeBuild
    return NativeBuild(dependency, build_root).compile(
        "response-hints", ROOT / "native/response_hints.hepta", standalone="filter")


def examples():
    return [
        (b"", [], b""),
        (b"result", [], b"result"),
        (b"\x00\r\n\t ", [], b"\x00\r\n\t "),
        (b"", [b""], b"\n\n" + PREFIX + b"\n"),
        (b"result", [b"hint"], b"result\n\n" + PREFIX + b"hint\n"),
        (b"\n", [b"\n"], b"\n\n\n" + PREFIX + b"\n\n"),
        (b"\r\n", [b"\r\n"], b"\r\n\n\n" + PREFIX + b"\r\n\n"),
        (b"x", [b" a ", b""], b"x\n\n" + PREFIX + b" a \n" + PREFIX + b"\n"),
        (b"x", [b"same", b"same"], b"x\n\n" + PREFIX + b"same\n" + PREFIX + b"same\n"),
        (b"\x00", [b"\x00"], b"\x00\n\n" + PREFIX + b"\x00\n"),
        ("中文🙂".encode(), ["⚠️ e\u0301".encode(), "é".encode()],
         "中文🙂\n\n⚠️ ⚠️ e\u0301\n⚠️ é\n".encode()),
        (b"\\n\"", [b"\\r\"\\n"], b"\\n\"\n\n" + PREFIX + b"\\r\"\\n\n"),
    ]


class ResponseHintsNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = selected_manifest()
        cls.manifest_bytes = cls.manifest.read_bytes()
        cls.module = NativeModule(cls.manifest,
            manifest_sha256=hashlib.sha256(cls.manifest_bytes).hexdigest())
        actual = hashlib.sha256((ROOT / "native/response_hints.hepta").read_bytes()).hexdigest()
        if cls.module.metadata["source_sha256"] != actual:
            raise RuntimeError("selected image was not built from this response_hints.hepta")
        executable = cls.module.metadata.get("standalone")
        if not executable or executable.get("transport") != "filter":
            raise RuntimeError("response-hints suite requires its actual static filter ELF")
        cls.executable = cls.manifest.parent / executable["path"]
        if hashlib.sha256(cls.executable.read_bytes()).hexdigest() != executable["sha256"]:
            raise RuntimeError("response-hints ELF identity differs")

    @classmethod
    def tearDownClass(cls):
        cls.module.close()

    def check(self, wire: bytes, expected: bytes | None, *, capacity: int | None = None,
              code: int | None = None, kind: str = "semantic", workspace_capacity: int = 37):
        if capacity is None:
            capacity = len(expected) + 17 if expected is not None else 97
        actual, output, workspace = self.module.invoke_raw(wire, output_capacity=capacity,
            workspace_capacity=workspace_capacity, output_fill=0xA3, workspace_fill=0xBC)
        COUNTS["native_calls"] += 1
        self.assertEqual(workspace, b"\xbc" * workspace_capacity, "unused workspace changed")
        wanted = len(expected) if code is None else code
        self.assertEqual(actual, wanted, (wire[:64].hex(), capacity))
        if actual >= 0xFFFF0000:
            self.assertEqual(output, b"\xa3" * capacity, "refusal wrote output")
            COUNTS[kind + "_controls"] += 1
            return
        self.assertEqual(output[:actual], expected)
        self.assertEqual(output[actual:], b"\xa3" * (capacity - actual), "output tail changed")
        if kind == "semantic":
            NATIVE_INPUT.extend(struct.pack("<QQ", len(wire), capacity) + wire)
            NATIVE_OUTPUT.extend(struct.pack("<QQ", actual, actual) + output[:actual])
            COUNTS["original_semantic_cases"] += 1

    def test_exact_original_layout_and_duplicates(self):
        for base, hints, expected in examples():
            self.check(frame(base, hints), expected)
        rng = random.Random(0x524553504F4E5345)
        alphabet = ["\x00", "\n", "\r", " ", "\t", "a", "Z", "\"", "\\", "é", "中", "🙂", "\u0301", "\ufe0f"]
        for _ in range(256):
            base = "".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 50))).encode()
            hints = ["".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 30))).encode()
                     for _ in range(rng.randrange(0, 12))]
            # Test-only expected formatting; fresh original Rust replay remains mandatory.
            expected = base if not hints else base + b"\n\n" + b"".join(PREFIX + h + b"\n" for h in hints)
            self.check(frame(base, hints), expected)

    def test_complete_unicode_scalar_domain(self):
        scalars = "".join(chr(value) for value in range(0x110000) if not 0xD800 <= value <= 0xDFFF)
        raw = scalars.encode()
        COUNTS["unicode_scalars"] = len(scalars)
        self.assertEqual(len(scalars), 1112064)
        self.check(frame(raw, []), raw, capacity=len(raw), workspace_capacity=0)
        expected = b"\n\n" + PREFIX + raw + b"\n"
        self.check(frame(b"", [raw]), expected, capacity=len(expected), workspace_capacity=0)

    def test_single_bytes_and_invalid_utf8(self):
        for value in range(256):
            raw = bytes([value])
            if value < 128:
                self.check(frame(raw, []), raw)
                self.check(frame(b"", [raw]), b"\n\n" + PREFIX + raw + b"\n")
            else:
                self.check(frame(raw, []), None, code=INVALID, kind="invalid_utf8")
                self.check(frame(b"", [raw]), None, code=INVALID, kind="invalid_utf8")
        invalid = [b"\xc0\x80", b"\xc1\xbf", b"\xc2", b"\xdf", b"\xc2\x7f", b"\xdf\xc0",
                   b"\xe0\x9f\xbf", b"\xed\xa0\x80", b"\xed\xbf\xbf", b"\xef\xbf",
                   b"\xe1\x80\x7f", b"\xe1\x80\xc0", b"\xe0", b"\xe0\xa0",
                   b"\xf0\x8f\xbf\xbf", b"\xf4\x90\x80\x80", b"\xf4\xbf\xbf\xbf",
                   b"\xf5\x80\x80\x80", b"\xf8\x88\x80\x80\x80", b"\xfc\x84\x80\x80\x80\x80",
                   b"\xf0\x90\x80", b"\xf0\x90", b"\xf0", b"\xf1\x80\x80\x7f",
                   b"\xf1\x80\x80\xc0", b"\xf1\x80\x7f\x80", b"\xf1\x80\xc0\x80"]
        for bad in invalid:
            for prefix, suffix in [(b"", b""), (b"valid\x00", b"valid"), (b"x" * 127, b"")]:
                self.check(frame(prefix + bad + suffix, []), None, code=INVALID, kind="invalid_utf8")
                self.check(frame(b"base", [b"valid", prefix + bad + suffix]), None,
                           code=INVALID, kind="invalid_utf8")
        self.check(frame(b"\xc2", [b"\xa0"]), None, code=INVALID, kind="invalid_utf8")
        self.check(frame(b"base", [b"\xc2", b"\xa0"]), None, code=INVALID, kind="invalid_utf8")

    def test_full_frame_validation_precedes_effects(self):
        wire = frame(b"base", [b"first", b"second"])
        for size in range(len(wire)):
            self.check(wire[:size], None, code=INVALID, kind="invalid_frame")
        for at in range(8):
            raw = bytearray(wire); raw[at] ^= 1
            self.check(bytes(raw), None, code=INVALID, kind="invalid_frame")
        drain = 36
        for at in range(drain, drain + 8):
            raw = bytearray(wire); raw[at] ^= 1
            self.check(bytes(raw), None, code=INVALID, kind="invalid_frame")
        for at, values in [(8, [0, 3, 5, (1 << 64) - 1]),
                           (16, [0, 31, len(wire), (1 << 64) - 1]),
                           (24, [1, (1 << 64) - 1]),
                           (drain + 8, [0, 2, (1 << 64) - 1]),
                           (drain + 16, [0, 1, 3, (1 << 64) - 1]),
                           (drain + 24, [0, 1, (1 << 64) - 1]),
                           (drain + 32, [0, 4, 6, (1 << 64) - 1])]:
            for value in values:
                self.check(word_changed(wire, at, value), None, code=INVALID, kind="invalid_frame")
        for tail in [b"\x00", bytes(8), b"extra"]:
            self.check(wire + tail, None, code=INVALID, kind="invalid_frame")
        late = word_changed(wire, drain + 32 + 8 + 5, (1 << 64) - 1)
        self.check(late, None, code=INVALID, kind="invalid_frame", capacity=0)

    def test_output_capacity_and_write_extent(self):
        for base, hints, expected in examples():
            wire = frame(base, hints)
            self.check(wire, expected, capacity=len(expected), workspace_capacity=0)
            self.check(wire, expected, capacity=len(expected) + 1, workspace_capacity=1)
            if expected:
                self.check(wire, None, capacity=len(expected) - 1, code=CAPACITY, kind="capacity")
        self.check(frame(b"longer than output", [b"hint"]), None,
                   capacity=0, code=CAPACITY, kind="capacity")

    def test_complete_standard_capacity(self):
        base = b"x" * (INPUT_BYTES - 64)
        wire = frame(base, [])
        self.assertEqual(len(wire), INPUT_BYTES)
        self.check(wire, base, capacity=INPUT_BYTES, workspace_capacity=0)
        hint = b"y" * (INPUT_BYTES - 72)
        wire = frame(b"", [hint])
        self.assertEqual(len(wire), INPUT_BYTES)
        expected = b"\n\n" + PREFIX + hint + b"\n"
        self.check(wire, expected, capacity=len(expected), workspace_capacity=0)
        self.check(wire, None, capacity=len(expected) - 1, code=CAPACITY, kind="capacity", workspace_capacity=0)
        count = (INPUT_BYTES - 64) // 8
        wire = frame(b"", [b""] * count)
        self.assertEqual(len(wire), INPUT_BYTES)
        expected = b"\n\n" + (PREFIX + b"\n") * count
        self.check(wire, expected, capacity=len(expected), workspace_capacity=0)

    def test_reused_workspace_has_no_retained_response(self):
        with self.module.session(output_capacity=256, workspace_capacity=128) as session:
            for _ in range(3):
                for base, hints, expected in examples():
                    self.assertEqual(session.invoke(frame(base, hints)), expected)
                    COUNTS["native_calls"] += 1
                    COUNTS["reused_workspace_requests"] += 1

    def test_actual_static_elf(self):
        for base, hints, expected in examples()[::2]:
            wire = frame(base, hints)
            start = time.monotonic()
            result = subprocess.run([str(self.executable)], input=wire,
                                    capture_output=True, timeout=30)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, expected, b""))
            self.record_elf(wire, result, time.monotonic() - start)
        for wire, expected_exit in [(b"", 2), (frame(b"\xff", []), 2),
                                    (frame(b"x" * (INPUT_BYTES - 63), []), 3)]:
            start = time.monotonic()
            result = subprocess.run([str(self.executable)], input=wire,
                                    capture_output=True, timeout=30)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (expected_exit, b"", b""))
            self.record_elf(wire, result, time.monotonic() - start)

    def record_elf(self, wire, result, elapsed):
        COUNTS["actual_static_elf_processes"] += 1
        ELF_RECORDS.append({"input_bytes": len(wire), "input_sha256": hashlib.sha256(wire).hexdigest(),
            "stdout_bytes": len(result.stdout), "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
            "stderr_bytes": len(result.stderr), "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
            "exit_code": result.returncode, "elapsed_seconds": elapsed})


def retain(result, elapsed):
    report = {"schema": "hepta.runtime.response-hints-native-tests.v1",
        "status": "PASS" if result.wasSuccessful() and not result.skipped else "FAIL",
        "test_groups": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
        "skips": len(result.skipped), "counts": COUNTS, "elapsed_seconds": elapsed,
        "manifest_sha256": hashlib.sha256(ResponseHintsNativeTests.manifest_bytes).hexdigest()
            if hasattr(ResponseHintsNativeTests, "manifest_bytes") else None,
        "source_sha256": hashlib.sha256((ROOT / "native/response_hints.hepta").read_bytes()).hexdigest(),
        "real_elf_processes": ELF_RECORDS, "rust_oracle_executed_by_this_suite": False,
        "production_activated": False, "whole_runtime_replaced": False}
    corpus_dir = os.environ.get("HIA_RESPONSE_HINTS_CORPUS_DIR")
    if corpus_dir:
        folder = Path(corpus_dir)
        folder.mkdir(parents=True, exist_ok=False)
        corpus = {}
        for name, raw in [("input.bin.gz", bytes(NATIVE_INPUT)),
                          ("native-output.bin.gz", bytes(NATIVE_OUTPUT))]:
            compressed = gzip.compress(raw, mtime=0)
            (folder / name).write_bytes(compressed)
            corpus[name] = {"bytes": len(compressed), "sha256": hashlib.sha256(compressed).hexdigest(),
                "raw_bytes": len(raw), "raw_sha256": hashlib.sha256(raw).hexdigest()}
        report["corpus"] = corpus
        (folder / "native-corpus.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    start = time.monotonic()
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(ResponseHintsNativeTests))
    retain(result, time.monotonic() - start)
    raise SystemExit(0 if result.wasSuccessful() and not result.skipped else 1)

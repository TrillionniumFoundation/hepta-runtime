#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Native parse_endpoint differential and byte-boundary qualification.

Select HIA_ENDPOINT_MANIFEST or HIA_HEPTA_DIR/HIA_BUILD_ROOT. Optional
HIA_ENDPOINT_CORPUS_DIR exports actual native calls for the original Rust owner.
Python is an independent test reference, never an execution fallback.
"""
from __future__ import annotations
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import random
import re
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from hia_native_loader import NativeModule

MASK = (1 << 64) - 1
INVALID, CAPACITY = 0xFFFFFFFF, 0xFFFFFFFE
ORIGINAL_SHA = "904bc9a70e1ade3802213cd067ab7b75bce4dd075e4ab4965f32e9964293ba57"
WHITE_SPACE = "\t\n\v\f\r \u0085\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000"
COUNTS = {"native_calls": 0, "rust_oracle_cases": 0, "python_differential_cases": 0}
CORPUS = []

def frame(kind, payload=b"", scalar=0):
    return b"HIAEP001" + struct.pack("<3Q", kind, len(payload), scalar & MASK) + payload

def string_frame(value):
    return frame(2, value.encode("utf-8"))

def result(tag, value, auxiliary=0, payload=b""):
    return b"HIAEPR01" + struct.pack("<3Q", tag, value & MASK, auxiliary) + payload

def error(reason, message):
    raw = message.encode("utf-8")
    return result(0, reason, len(raw), raw)

def reference(packet):
    """Independent high-level Rust behavior; valid typed packets only."""
    kind, _, scalar = struct.unpack_from("<3Q", packet, 8)
    if kind == 0:
        return result(1, scalar)
    if kind == 1:
        return error(1, "line number must be an integer")
    text = packet[32:].decode("utf-8")
    if kind == 3:
        return error(7, 'line value must be a line id like "12:a3" or an integer line number, got ' + text)
    text = text.strip(WHITE_SPACE)
    if not text:
        return error(2, "line value is empty")
    if re.fullmatch(r"[+-]?[0-9]+", text):
        sign = -1 if text.startswith("-") else 1
        digits = text.lstrip("+-").lstrip("0") or "0"
        if len(digits) <= 19:
            value = sign * int(digits)
            if -(1 << 63) <= value < 1 << 63:
                return result(1, value)
    if ":" in text:
        number, hash_part = text.split(":", 1)
        valid = bool(re.fullmatch(r"\+?[0-9]+", number))
        digits = number.lstrip("+").lstrip("0") or "0"
        if valid and len(digits) <= 20:
            line = int(digits)
            valid = line <= MASK
        else:
            valid = False
        if not valid:
            return error(3, f'invalid line id \'{text}\': expected "N:hh" as shown in view output (e.g. "12:a3")')
        if line == 0:
            return error(4, f"invalid line id '{text}': lines are 1-indexed")
        if not re.fullmatch(r"[0-9a-fA-F]{2}", hash_part):
            return error(5, f'invalid line id \'{text}\': the hash part must be 2 hex chars (e.g. "12:a3")')
        return result(2, line, int.from_bytes(hash_part.lower().encode("ascii"), "little"))
    return error(6, f'invalid line value \'{text}\': pass a line id like "12:a3" (from view output) or an integer line number')

def decoded(raw):
    if len(raw) < 32 or raw[:8] != b"HIAEPR01":
        raise AssertionError("invalid endpoint result header")
    tag, value, auxiliary = struct.unpack_from("<3Q", raw, 8)
    if tag == 0:
        assert 1 <= value <= 7 and len(raw) == 32 + auxiliary
        return {"kind": "error", "message": raw[32:].decode("utf-8")}
    assert len(raw) == 32
    if tag == 1:
        assert auxiliary == 0
        return {"kind": "number", "number": value if value < 1 << 63 else value - (1 << 64)}
    if tag == 2:
        raw_hash = auxiliary.to_bytes(8, "little")
        assert value and raw_hash[2:] == bytes(6) and re.fullmatch(rb"[0-9a-f]{2}", raw_hash[:2])
        return {"kind": "id", "line": value, "hash": raw_hash[:2].decode("ascii")}
    raise AssertionError("unknown endpoint result tag")

def record(packet, actual, source=None):
    if not os.environ.get("HIA_ENDPOINT_CORPUS_DIR"):
        return
    if source is None:
        kind, _, scalar = struct.unpack_from("<3Q", packet, 8)
        if kind == 0:
            source = str(scalar if scalar < 1 << 63 else scalar - (1 << 64))
        elif kind == 1:
            source = "1.0"
        elif kind == 2:
            source = json.dumps(packet[32:].decode("utf-8"), ensure_ascii=True)
        else:
            source = packet[32:].decode("utf-8")
    CORPUS.append(json.dumps({"json": source, "input_hex": packet.hex(), "native_output_hex": actual.hex()}, ensure_ascii=True))

def manifest():
    selected = os.environ.get("HIA_ENDPOINT_MANIFEST")
    if selected:
        return Path(selected).resolve(strict=True)
    dependency, build_root = os.environ.get("HIA_HEPTA_DIR"), os.environ.get("HIA_BUILD_ROOT")
    if not dependency or not build_root:
        raise RuntimeError("set HIA_ENDPOINT_MANIFEST, or HIA_HEPTA_DIR and HIA_BUILD_ROOT")
    source = ROOT / "native/line_endpoint.hepta"
    cached = Path(build_root) / "modules/line-endpoint/manifest.json"
    if cached.exists():
        if json.loads(cached.read_text()).get("source_sha256") != hashlib.sha256(source.read_bytes()).hexdigest():
            raise RuntimeError("cached endpoint source differs; select a fresh build root")
        return cached
    from hia_native_build import NativeBuild
    return NativeBuild(Path(dependency), Path(build_root)).compile("line-endpoint", source, standalone=None)

class LineEndpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        selected = manifest()
        cls.module = NativeModule(selected, manifest_sha256=hashlib.sha256(selected.read_bytes()).hexdigest())
        cls.session = cls.module.session(output_capacity=4096, workspace_capacity=8)

    @classmethod
    def tearDownClass(cls):
        cls.session.close()
        cls.module.close()
        target = os.environ.get("HIA_ENDPOINT_CORPUS_DIR")
        if target:
            directory = Path(target)
            directory.mkdir(parents=True, exist_ok=True)
            raw = ("\n".join(CORPUS) + "\n").encode()
            compressed = gzip.compress(raw, mtime=0)
            name = "endpoint_cases.jsonl.gz"
            (directory / name).write_bytes(compressed)
            metadata = {"schema": "hepta.runtime.native-corpus.v1", "rust_oracle_cases": len(CORPUS),
                        "source_sha256": cls.module.metadata["source_sha256"],
                        "corpus": {"file": name, "gzip_sha256": hashlib.sha256(compressed).hexdigest(),
                                   "gzip_bytes": len(compressed), "raw_sha256": hashlib.sha256(raw).hexdigest(), "raw_bytes": len(raw)}}
            (directory / "native-corpus.json").write_text(json.dumps(metadata, sort_keys=True, indent=2) + "\n")

    def invoke(self, packet):
        COUNTS["native_calls"] += 1
        return self.session.invoke(packet)

    def differential(self, packet):
        actual = self.invoke(packet)
        self.assertEqual(actual, reference(packet), repr(packet))
        record(packet, actual)
        COUNTS["python_differential_cases"] += 1

    def raw(self, packet, capacity, workspace=8):
        COUNTS["native_calls"] += 1
        return self.module.invoke_raw(packet, output_capacity=capacity, workspace_capacity=workspace,
                                      output_fill=0xA7, workspace_fill=0x6B)

    def test_original_rust_vectors(self):
        corpus = json.loads(Path(__file__).with_name("line_endpoint_rust_vectors.json").read_text())
        self.assertEqual(corpus["schema"], "hepta.runtime.line-endpoint-rust-vectors.v1")
        self.assertEqual(corpus["reference"]["line_hash_sha256"], ORIGINAL_SHA)
        self.assertEqual(corpus["reference"]["serde_json"], "1.0.151")
        self.assertEqual(corpus["reference"]["serde"], "1.0.229")
        self.assertEqual(corpus["case_count"], len(corpus["cases"]))
        self.assertGreaterEqual(corpus["case_count"], 900)
        retained = ROOT / "src/utils/line_hash.rs"
        if retained.exists():
            self.assertEqual(hashlib.sha256(retained.read_bytes()).hexdigest(), ORIGINAL_SHA)
        for row in corpus["cases"]:
            packet = bytes.fromhex(row["input_hex"])
            actual = self.invoke(packet)
            self.assertEqual(decoded(actual), row["result"], row["json"])
            self.assertEqual(actual, reference(packet), row["json"])
            record(packet, actual, row["json"])
            COUNTS["rust_oracle_cases"] += 1

    def test_numeric_value_domain_and_i64_bounds(self):
        rng = random.Random(0x45504E554D)
        for value in [-(1 << 63), -(1 << 63) + 1, -1, 0, 1, (1 << 63) - 1] + [rng.randrange(-(1 << 63), 1 << 63) for _ in range(512)]:
            self.differential(frame(0, scalar=value))
            self.differential(string_frame(str(value)))
        self.differential(frame(1))
        for value in [-(1 << 63) - 1, 1 << 63, (1 << 64) - 1, 1 << 64]:
            self.differential(string_frame(str(value)))
            self.differential(string_frame(str(value) + ":Ff"))

    def test_generated_string_differential(self):
        rng = random.Random(0x48494145504F494E54)
        alphabet = "0123456789abcdefABCDEF:+- \t\r\n_gGé０١\x00\u00a0\u3000\ufeff"
        for _ in range(4000):
            if rng.randrange(3):
                text = "".join(rng.choice(alphabet) for _ in range(rng.randrange(60)))
            else:
                text = rng.choice(["", "+", "-", "0" * rng.randrange(24)]) + str(rng.randrange(1 << 66))
                text += rng.choice(["", ":" + "".join(rng.choice(alphabet) for _ in range(rng.randrange(6)))])
                text = rng.choice(["", rng.choice(WHITE_SPACE)]) + text + rng.choice(["", rng.choice(WHITE_SPACE)])
            self.differential(string_frame(text))

    def test_rust_unicode_whitespace_and_ascii_digits(self):
        for scalar in WHITE_SPACE:
            for body in ["", "-1", "+0001", "12:Af", "0:gg", "1 :ab"]:
                self.differential(string_frame(scalar + body + scalar))
        for scalar in ["\x1c", "\x1d", "\x1e", "\x1f", "\u180e", "\u200b", "\u2060", "\ufeff", "\ufffe", "\uffff", "\U0010ffff"]:
            self.differential(string_frame(scalar + "1" + scalar))
        for value in ["１", "١", "१२", "1:é", "1:İ", "+00000000000000000001:FF", "000:é", "-0:00"]:
            self.differential(string_frame(value))

    def test_output_capacity_is_atomic(self):
        packets = [frame(0, scalar=MASK), frame(1), string_frame("1:FF"), string_frame(""),
                   string_frame("1 :ab"), string_frame("0:zz"), string_frame("1:aZ"), string_frame("a'\nß"), frame(3, b"[true,null]")]
        for packet in packets:
            expected = reference(packet)
            for capacity in sorted({0, 1, 31, len(expected) - 1, len(expected), len(expected) + 7}):
                code, output, _ = self.raw(packet, capacity)
                if capacity < len(expected):
                    self.assertEqual(code, CAPACITY)
                    self.assertEqual(output, b"\xa7" * capacity)
                else:
                    self.assertEqual(code, len(expected))
                    self.assertEqual(output[:code], expected)
                    self.assertEqual(output[code:], b"\xa7" * (capacity - code))

    def test_invalid_packet_and_workspace_are_atomic(self):
        good = string_frame("12:ab")
        packets = [b"", b"HIAEP001", bytes(31), b"BADMAGIC" + good[8:], frame(4), frame(MASK),
                   frame(0, b"0"), frame(1, b"0"), frame(1, scalar=1), frame(2, b"x", scalar=1), frame(3, b"null", scalar=1), good[:-1], good + b"x"]
        for packet in packets:
            code, output, workspace = self.raw(packet, 256)
            self.assertEqual(code, INVALID)
            self.assertEqual(output, b"\xa7" * 256)
            self.assertEqual(workspace, b"\x6b" * 8)
        for workspace_size in range(8):
            code, output, workspace = self.raw(good, 256, workspace_size)
            self.assertEqual(code, INVALID)
            self.assertEqual(output, b"\xa7" * 256)
            self.assertEqual(workspace, b"\x6b" * workspace_size)

    def test_utf8_validation_precedes_parsing(self):
        invalid = [b"\x80", b"\xbf", b"\xc0\x80", b"\xc1\xbf", b"\xc2", b"\xc2A", b"\xe0\x80\x80", b"\xe2\x82", b"\xe2A\xa1", b"\xed\xa0\x80", b"\xef\xbf", b"\xf0\x80\x80\x80", b"\xf0\x90\x80", b"\xf4\x90\x80\x80", b"\xf5\x80\x80\x80", b"\xff", b"\xfe"]
        for kind in [2, 3]:
            for raw in invalid:
                for payload in [raw, b"1" + raw, b"1:ff" + raw, raw + b"1"]:
                    code, output, workspace = self.raw(frame(kind, payload), 256)
                    self.assertEqual(code, INVALID, payload)
                    self.assertEqual(output, b"\xa7" * 256)
                    self.assertEqual(workspace, b"\x6b" * 8)
        for value in ["\x00", "\x7f", "\u0080", "\u07ff", "\u0800", "\ud7ff", "\ue000", "\uffff", "\U00010000", "\U0010ffff"]:
            self.differential(string_frame(value))

    def test_large_errors_leading_zeros_and_input_limit(self):
        packet = string_frame("\u3000" + "0" * 100000 + ":Qz" + "\u00a0")
        expected = reference(packet)
        code, output, _ = self.raw(packet, len(expected) - 1)
        self.assertEqual(code, CAPACITY)
        self.assertEqual(output, b"\xa7" * len(output))
        code, output, _ = self.raw(packet, len(expected))
        self.assertEqual((code, output), (len(expected), expected))
        record(packet, output)
        packet = frame(2, b"0" * ((8 << 20) - 32))
        code, output, _ = self.raw(packet, 32)
        self.assertEqual((code, output), (32, result(1, 0)))
        with self.assertRaises(ValueError):
            self.module.invoke(packet + b"0", output_capacity=32, workspace_capacity=8)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--hepta")
    parser.add_argument("--build-root")
    parser.add_argument("--manifest")
    args, remaining = parser.parse_known_args()
    for value, env in [(args.hepta, "HIA_HEPTA_DIR"), (args.build_root, "HIA_BUILD_ROOT"), (args.manifest, "HIA_ENDPOINT_MANIFEST")]:
        if value:
            os.environ[env] = value
    program = unittest.main(argv=[sys.argv[0], *remaining], exit=False, verbosity=2)
    print(json.dumps({"line_endpoint": COUNTS}, sort_keys=True))
    raise SystemExit(0 if program.result.wasSuccessful() else 1)

#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Byte-encoding and refusal controls; not native provider qualification."""

import copy
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import rea_elf_format_fixtures as fixtures
import rea_operation_profile_v2 as composition


class FormatFixtureTests(unittest.TestCase):
    def test_independent_elf_header_section_ranges_and_gnu_descriptor(self):
        for bits in (32, 64):
            for order in ("little", "big"):
                with self.subTest(bits=bits, order=order):
                    raw = fixtures.named_elf(fixtures.NAMES, bits, order)
                    endian = "<" if order == "little" else ">"
                    header = struct.unpack_from(endian + ("HHIQQQIHHHHHH" if bits == 64 else "HHIIIIIHHHHHH"), raw, 16)
                    self.assertEqual(raw[:7], b"\x7fELF" + bytes([bits // 32, 1 if order == "little" else 2, 1]))
                    self.assertEqual((header[9], header[11], header[12]), (0, 3, 1))
                    section = endian + ("IIQQQQIIQQ" if bits == 64 else "IIIIIIIIII")
                    names = struct.unpack_from(section, raw, header[5] + header[10])
                    note = struct.unpack_from(section, raw, header[5] + 2 * header[10])
                    self.assertEqual(raw[names[4]:names[4] + names[5]], b"\0.note.good\0")
                    self.assertEqual((note[0], note[1], note[8]), (1, 7, 4))
                    self.assertEqual(struct.unpack_from(endian + "III", raw, note[4]), (4, 20, 3))
                    self.assertEqual(raw[note[4] + 12:note[4] + 16], b"GNU\0")
                    self.assertEqual(raw[note[4] + 16:note[4] + 36], bytes(range(20)))

    def test_stored_compression_has_independent_size_and_checksum(self):
        encoded = fixtures.stored_zlib(fixtures.NAMES)
        self.assertEqual(zlib.decompress(encoded), fixtures.NAMES)
        changed = bytearray(encoded)
        changed[-1] ^= 1
        with self.assertRaises(zlib.error):
            zlib.decompress(changed)
        frame = fixtures.stored_zstd(fixtures.NAMES)
        self.assertEqual(frame[:5], bytes.fromhex("28b52ffd20"))
        self.assertEqual(frame[5], len(fixtures.NAMES))
        self.assertEqual(int.from_bytes(frame[6:9], "little"), len(fixtures.NAMES) * 8 + 1)
        self.assertEqual(frame[9:], fixtures.NAMES)

    def test_corpus_stays_fixed_and_writes_actual_regenerable_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = fixtures.corpus(root, write=True)
            self.assertEqual(manifest, fixtures.corpus(root))
            self.assertEqual(len(manifest["cases"]), 99)
            self.assertEqual(len({row["id"] for row in manifest["cases"]}), 99)
            self.assertEqual({(row["bits"], row["byte_order"]) for row in manifest["cases"]},
                             {(32, "little"), (32, "big"), (64, "little"), (64, "big")})
            for item in manifest["fixtures"].values():
                raw = Path(item["path"]).read_bytes()
                self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), (item["bytes"], item["sha256"]))
            with self.assertRaises(FileExistsError):
                fixtures.corpus(root, write=True)


def independently_assessed_fixture():
    """Synthetic consumer facts test composition only; never a stored receipt."""
    op = {"case_comparisons": {"case": {"passed": True, "opaque_response_equal": True, "parsed_result_equal": True}},
          "schema_equal": True, "retention_equal": True, "cold_session_empty": True}
    fam = {"comparisons": [{"status": "PASS"} for _ in range(50)], "normal_owner_closes": 8,
           "native_readback": {"pages": 2, "reconstructed_bytes": 65537}}
    life = {"gates": {name: "PASS" for name in (
        "active-cancellation-owner-drain", "unknown-cancellation-boundary", "native-worker-deadline-owner-drain",
        "parallel-independent-request-completion", "active-eof-owner-drain")}}
    life["gates"]["deadline-owner-drain"] = "OPEN"
    fmt = {"cases": {"error": {"passed": True, "opaque_response_equal": True, "expected_outcome": "error"}},
           "retention": {"opaque_response_equal": True}}
    cache = {"normal_owner_closes": 3, "results": {
        "extension-count": {"distinct_live_snapshots": 4, "count_refusals": 1, "restored_zero": True},
        "extension-total-bytes": {"retained_before_refusal": 2, "aggregate_refusals": 1, "restored_zero": True},
        "extension-single-bytes": {"per_snapshot_refusals": 1, "restored_zero": True}}}
    return op, fam, life, fmt, cache


class CompositionRefusalTests(unittest.TestCase):
    def test_gate_names_and_explicit_legacy_deadline_boundary(self):
        observed = independently_assessed_fixture()
        result = composition.derive_gates(*observed, True)
        self.assertEqual(tuple(result), composition.GATES)
        self.assertEqual(set(result.values()), {"PASS"})
        self.assertEqual(observed[2]["gates"]["deadline-owner-drain"], "OPEN")
        self.assertIn("reference worker-deadline injection", " ".join(composition.EXCLUDED))

    def test_each_missing_observation_retains_an_open_gate(self):
        mutations = (
            lambda a: a[0].update(schema_equal=False),
            lambda a: a[0]["case_comparisons"]["case"].update(opaque_response_equal=False),
            lambda a: a[0].update(retention_equal=False),
            lambda a: a[0].update(cold_session_empty=False),
            lambda a: a[1]["comparisons"].pop(),
            lambda a: a[1]["comparisons"][0].update(status="FAIL"),
            lambda a: a[1]["native_readback"].update(pages=1),
            lambda a: a[1].update(normal_owner_closes=7),
            lambda a: a[2]["gates"].update({"parallel-independent-request-completion": "OPEN"}),
            lambda a: a[2]["gates"].update({"native-worker-deadline-owner-drain": "FAILED"}),
            lambda a: a[2]["gates"].update({"active-cancellation-owner-drain": "OPEN"}),
            lambda a: a[2]["gates"].update({"active-eof-owner-drain": "OPEN"}),
            lambda a: a[3]["cases"]["error"].update(passed=False),
            lambda a: a[4].update(normal_owner_closes=2),
            lambda a: a[4]["results"]["extension-total-bytes"].update(restored_zero=False),
            lambda a: a[4]["results"].pop("extension-single-bytes"),
        )
        for number, mutate in enumerate(mutations):
            with self.subTest(number=number):
                observed = independently_assessed_fixture()
                mutate(observed)
                self.assertIn("OPEN", composition.derive_gates(*observed, True).values())
        self.assertEqual(composition.derive_gates(*independently_assessed_fixture(), False)["source_package_boundary"], "OPEN")

    def test_index_rejects_handwritten_pass_duplicate_roles_and_unpinned_receipts(self):
        valid = {"schema": composition.SCHEMA, "profile": composition.PROFILE,
                 "operation": "inspect_elf_notes", "scope": composition.SCOPE,
                 "receipts": [{"role": role, "report": role + ".json", "sha256": "0" * 64}
                              for role in composition.ROLES]}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "index.json"
            for change in (lambda x: x.update(status="PASS"),
                           lambda x: x["receipts"].pop(),
                           lambda x: x["receipts"][1].update(role="operation"),
                           lambda x: x["receipts"][0].update(report="../escape.json"),
                           lambda x: x["scope"].update(build="producer claimed PASS")):
                value = copy.deepcopy(valid)
                change(value)
                raw = json.dumps(value).encode()
                path.write_bytes(raw)
                with self.assertRaises((ValueError, OSError)):
                    composition.validate_index(ROOT, path, hashlib.sha256(raw).hexdigest())


if __name__ == "__main__":
    unittest.main()

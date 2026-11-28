#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Native language custody and original-oracle refusal controls; no native run."""
from __future__ import annotations

from hashlib import sha256
import importlib.util
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    "hia_native_language_coverage", Path(__file__).with_name("hia_native_language_coverage.py"))
language_run = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(language_run)
custody = language_run.custody


class NativeLanguageCustodyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.base = self.root / "qualification/base"
        self.base.mkdir(parents=True)
        images = {"B0": b"fixture seed", "B1": b"fixture original", "B2": b"fixture original",
                  "B3": b"fixture original", "M1": b"fixture first change",
                  "M2": b"fixture modified fixed point", "M3": b"fixture modified fixed point"}
        for name, raw in images.items():
            (self.base / (name + ".flat")).write_bytes(raw)
        self.observer = b"O" * 1107
        (self.base / "native-observer.elf").write_bytes(self.observer)
        self.cold = {"generation_sha256": [sha256(images[name]).hexdigest() for name in ("B1", "B2", "B3")],
                     "modified_generation_sha256": [sha256(images[name]).hexdigest() for name in ("M1", "M2", "M3")],
                     "seed_sha256": sha256(images["B0"]).hexdigest(), "native_flat_observer_hex": self.observer.hex()}
        self.path = self.root / "final-cold.json"
        self.save()

    def save(self):
        custody.write_json(self.path, self.cold)
        self.binding = {"cold_report_sha256": custody.digest(self.path),
                        "compiler_sha256": self.cold["generation_sha256"][-1]}

    def test_both_successors_and_seven_original_generation_bytes_are_bound(self):
        compilers, observer, captured = language_run.cold_successors(self.path, self.binding)
        self.assertEqual(compilers, {name: self.base / (name + ".flat") for name in ("B3", "M3")})
        self.assertEqual(observer, self.observer)
        self.assertEqual(set(captured), {"B0", "B1", "B2", "B3", "M1", "M2", "M3", "observer"})

    def test_foreign_modified_successor_cannot_use_a_valid_original_B3(self):
        (self.base / "M3.flat").write_bytes(b"foreign successor")
        with self.assertRaisesRegex(RuntimeError, "generation differs.*M3"):
            language_run.cold_successors(self.path, self.binding)

    def test_modified_chain_cannot_relabel_the_original_or_omit_its_first_change(self):
        for values in ([self.binding["compiler_sha256"]] * 3,
                       [self.cold["modified_generation_sha256"][-1]] * 3,
                       ["a" * 64, "b" * 64], [False, "b" * 64, "b" * 64]):
            with self.subTest(values=values):
                self.cold["modified_generation_sha256"] = values
                self.save()
                with self.assertRaisesRegex(RuntimeError, "both exact original and modified cold fixed points"):
                    language_run.cold_successors(self.path, self.binding)

    def test_changed_report_and_independent_observer_are_refused(self):
        raw = self.path.read_bytes()
        self.path.write_bytes(raw + b"\n")
        with self.assertRaisesRegex(RuntimeError, "changed after post-cold admission"):
            language_run.cold_successors(self.path, self.binding)
        self.path.write_bytes(raw)
        (self.base / "native-observer.elf").write_bytes(b"X" + self.observer[1:])
        with self.assertRaisesRegex(RuntimeError, "observer differs from the admitted"):
            language_run.cold_successors(self.path, self.binding)

    def test_actual_journals_and_archives_must_match_the_original_phase_pins(self):
        self.cold["phases"] = []
        for number in range(60):
            name = "fixture-phase-" + str(number)
            archive = self.root / "qualification" / (name + ".hiaqar")
            journal = self.root / "qualification" / name / "evidence.hiaqj"
            journal.parent.mkdir()
            archive.write_bytes(b"non-executable archive fixture " + name.encode())
            journal.write_bytes(b"non-executable journal fixture " + name.encode())
            self.cold["phases"].append({"id": name, "archive_sha256": custody.digest(archive),
                                        "journal_sha256": custody.digest(journal)})
        self.save()
        self.assertEqual(len(language_run.phase_evidence(self.path)), 120)
        journal.write_bytes(b"substituted original journal")
        with self.assertRaisesRegex(RuntimeError, "native cold journal differs from the original phase report"):
            language_run.phase_evidence(self.path)


class OriginalLanguageOracleTests(unittest.TestCase):
    """Small mocked responses ensure refusals and all original case domains survive."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.observer = b"non-executable native observer fixture"
        positive = {"id": "positive-fixture", "source": b"source", "input": b"input",
                    "capacity": 8, "workspace_size": 3, "expected_result": 7,
                    "expected_output": b"positive", "case_ids": ["fixture-case"]}
        negative = {"id": "refusal-fixture", "source": b"invalid source"}
        trap = {"id": "trap-fixture", "source": b"trapping source", "expected_output": b"\xa5" * 8,
                "kind": "shift", "operand_type": "u64"}
        self.fixture_api = types.SimpleNamespace(positive_fixtures=lambda: [positive],
            rejected_fixtures=lambda: [negative], shift_trap_cases=lambda: [trap],
            checked_arithmetic_trap_cases=lambda: [], checked_cast_trap_cases=lambda: [],
            word_trap_fixtures=lambda *_: [], Assembly=object(), HEADER="fixture")
        self.compilers = {"B3": self.root / "actual-B3", "M3": self.root / "actual-M3"}
        self.compiler_api = types.SimpleNamespace(INVALID=0xffffffff,
            compile_stage=mock.Mock(side_effect=self.compile_response), invoke=mock.Mock(side_effect=self.invoke_response))
        self.report = {"checks": {}, "positive": [], "negative": [], "traps": []}
        module = types.ModuleType("tools.hia_evidence_archive")
        module.OWNER = "fixture-owner"
        module.archive_completed_stage = lambda path, token: {"fixture_only": True, "path": str(path)}
        patcher = mock.patch.dict(sys.modules, {"tools.hia_evidence_archive": module})
        patcher.start()
        self.addCleanup(patcher.stop)

    def compile_response(self, directory, label, compiler, source, **kwargs):
        self.assertIn(compiler, self.compilers.values())
        self.assertEqual(kwargs, {"flat_observer": self.observer})
        return directory / (label + ".fixture-image"), {"fixture_only": True}

    def invoke_response(self, directory, label, image, source, **kwargs):
        self.assertEqual(kwargs["flat_observer"], self.observer)
        if "reject-" in label:
            return {"status": "returned", "abi_status": 0, "core_u32": 0xffffffff,
                    "source_unchanged": True, "output_unchanged": True,
                    "forbidden_compiler_modules_loaded": []}, bytes([165]) * 512
        if "trap-" in label:
            self.assertTrue(kwargs["observe_trap_writes"])
            return {"status": "child_failed", "returncode": -4,
                    "shared_output_observation": {"available": True, "unchanged": True}}, bytes([165]) * 8
        return {"status": "returned", "abi_status": 0, "core_u32": 7, "source_unchanged": True,
                "forbidden_compiler_modules_loaded": []}, b"positive"

    def run_fixtures(self):
        return language_run.run_fixtures(self.fixture_api, self.compiler_api, self.compilers,
                                         self.observer, self.root, self.report)

    def test_original_positive_refusal_and_trap_witnesses_run_under_both_successors(self):
        counts = self.run_fixtures()
        self.assertEqual(counts["compilers"], 2)
        self.assertEqual(self.compiler_api.compile_stage.call_count, 4)
        self.assertEqual(self.compiler_api.invoke.call_count, 6)
        self.assertTrue(all(self.report["checks"].values()))
        for kind in ("positive", "negative", "traps"):
            self.assertEqual({row["compiler"] for row in self.report[kind]}, {"B3", "M3"})

    def test_transactional_rejection_cannot_ignore_output_corruption(self):
        def corrupt(*args, **kwargs):
            result, observed = self.invoke_response(*args, **kwargs)
            return result, b"changed" if "reject-" in args[1] else observed
        self.compiler_api.invoke.side_effect = corrupt
        self.run_fixtures()
        self.assertFalse(self.report["checks"]["B3-reject-refusal-fixture"])
        self.assertFalse(self.report["checks"]["M3-reject-refusal-fixture"])
        self.assertTrue(all(row["transactional_rejection"] is False for row in self.report["negative"]))

    def test_traps_require_the_original_SIGILL_and_observed_prior_writes(self):
        def wrong_signal(*args, **kwargs):
            result, observed = self.invoke_response(*args, **kwargs)
            if "trap-" in args[1]:
                result["returncode"] = -9
            return result, observed
        self.compiler_api.invoke.side_effect = wrong_signal
        self.run_fixtures()
        self.assertFalse(self.report["checks"]["B3-trap-fixture"])
        self.assertFalse(self.report["checks"]["M3-trap-fixture"])

    def test_missing_modified_successor_cannot_shrink_the_case_inventory(self):
        self.compilers.pop("M3")
        with self.assertRaisesRegex(RuntimeError, "omitted or duplicated an original positive witness"):
            self.run_fixtures()


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Bounded local checks of actual evidence and publication refusal boundaries."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
path = Path(__file__).with_name("build_prepared_path_publication.py")
spec = importlib.util.spec_from_file_location("prepared_publisher", path)
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)


class Publication(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module, _ = publisher.load_dependencies()
        cls.values = {label: cls.module.decode((publisher.ROOT / relative).read_bytes())
                      for label, (relative, _, _) in publisher.INPUTS.items()}
        cls.archive = (publisher.ROOT / publisher.ARCHIVE).read_bytes()

    def test_actual_complete_rows_sources_identity_and_schema_keys(self):
        result, members = publisher.verify_actual(self.module, self.values, self.archive)
        public, inventory, detail = publisher.transform(self.module, self.values)
        self.assertEqual(len(members), 237)
        self.assertEqual(len(result["actual_formatted_source_tree_files"]), 22)
        self.assertEqual(result["unchanged_r01_r02_Rust_source_pairs"], 44)
        self.assertEqual(detail["owner_counts"]["rows"], 2176)
        self.assertEqual(detail["owner_counts"]["row_failed_or_not_passed"], 0)
        self.assertEqual(len(inventory["explicit_adaptations"]), 2138)
        self.assertEqual(sum(row["identity_metadata_fields_inside"]
                             for row in inventory["already_inside_opaque_parents"]), 12)
        self.assertEqual(len(inventory["transfer_and_native_identity_adaptations"]), 12)
        self.assertEqual(len(detail["dependency_key_collision_receipts"]), 14)
        self.assertEqual(len(detail["relative_archive_file_key_adaptations"]), 24)
        self.assertTrue(detail["all_fixed_schema_key_names_preserved"])
        self.assertEqual(detail["schema_key_overrides"], [])
        for label in ("prepared-path/analysis-r02", "prepared-path/root-recomputation"):
            self.assertEqual(public[label], self.values[label])

    def test_changed_timing_cannot_pass_original_stdout_binding(self):
        changed = deepcopy(self.values)
        changed["prepared-path/run-r02"]["cells"][0]["record"]["rows"][0]["process_cpu_ns"] += 1
        with self.assertRaisesRegex(ValueError, "original child ledger differs"):
            publisher.verify_actual(self.module, changed, self.archive)

    def test_first_failed_prepare_cannot_be_rewritten_as_unprepared(self):
        changed = deepcopy(self.values)
        changed["prepared-path/failed-prepare-r01"]["prepared"] = False
        with self.assertRaisesRegex(ValueError, "first format-check failure differs"):
            publisher.verify_actual(self.module, changed, self.archive)

    def test_crate_heuristic_may_not_rename_fixed_receipt_or_errno_keys(self):
        changed = deepcopy(self.values)
        changed["prepared-path/failed-prepare-r01"]["error"]["reason"] += " bytes@1.0.0 errno@1.0.0"
        with self.assertRaisesRegex(ValueError, "fixed metric/receipt schema key would be redacted"):
            publisher.transform(self.module, changed)


if __name__ == "__main__":
    unittest.main()

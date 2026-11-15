"""A newer production tree must not disappear behind historical native parity."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from check_hia_native_target import actual_sources, inspect_target, source_tree


class MigrationTargetTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="hia-migration-target-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "historical"
        self.target = Path(self.tmp.name) / "target"
        old = '#[tool(description = "view")]\nasync fn view() {}\n'
        new = old + '#[tool(description = "new")]\nasync fn weight_bellman_plan() {}\n'
        for base, body in ((self.root, old), (self.target, new)):
            (base / "src/mcp").mkdir(parents=True)
            (base / "src/mcp/server.rs").write_text(body)
            (base / "Cargo.toml").write_text('[package]\nname = "fixture"\n')
            (base / "Cargo.lock").write_text("version = 4\n")
        (self.target / "src/mcp/weight_bellman.rs").write_text("pub fn solve() {}\n")
        files = actual_sources(self.target)
        self.snapshot = {
            "schema": "hepta.runtime.hia-migration-target.v1",
            "repository": "TrillionniumFoundation/hepta-runtime",
            "target_commit": "1" * 40, "target_tree": "2" * 40,
            "target_src_tree": source_tree(files),
            "historical_comparison_base": "3" * 40,
            "tools": ["view", "weight_bellman_plan"],
            "source_files": list(files.values()),
        }
        self.inventory = {
            "runtime_base_commit": "3" * 40,
            "legacy_tool_handlers": [{"name": "view", "family": "filesystem_and_control",
                                       "status": "not_ported", "native_owner": None}],
        }
        (self.root / "native").mkdir()
        self.write_snapshot()

    def write_snapshot(self, raw=None):
        if raw is None:
            raw = (json.dumps(self.snapshot, indent=2) + "\n").encode()
        (self.root / "native/migration_target.json").write_bytes(raw)
        self.inventory["migration_target"] = {
            "path": "native/migration_target.json", "sha256": hashlib.sha256(raw).hexdigest()}
        (self.root / "native/migration.json").write_text(json.dumps(self.inventory))

    def check(self):
        return inspect_target(self.root, target_root=self.target)

    def test_new_tool_and_changed_source_are_visible_without_advancing_qualification(self):
        value = self.check()
        self.assertTrue(value["target_checkout_verified"])
        self.assertEqual((value["historical_handler_count"], value["target_handler_count"]), (1, 2))
        self.assertEqual(value["target_handlers_missing_from_historical_inventory"], ["weight_bellman_plan"])
        self.assertEqual(value["source_drift"]["target_only"], ["src/mcp/weight_bellman.rs"])
        self.assertEqual(value["source_drift"]["changed"], ["src/mcp/server.rs"])
        self.assertEqual(value["native_production_handler_count"], 0)
        for key in ("target_behavior_qualified", "production_activated",
                    "whole_runtime_replaced", "old_stack_removal_qualified"):
            self.assertIs(value[key], False)

    def test_snapshot_alone_does_not_claim_live_target_readback(self):
        self.assertFalse(inspect_target(self.root)["target_checkout_verified"])

    def test_resealed_omitted_tool_is_rejected_against_actual_target_server(self):
        self.snapshot["tools"].pop()
        self.write_snapshot()
        with self.assertRaisesRegex(ValueError, "target handler list"):
            self.check()

    def test_resealed_omitted_source_cannot_reconstruct_the_target_git_tree(self):
        self.snapshot["source_files"] = [row for row in self.snapshot["source_files"]
                                          if row["path"] != "src/mcp/weight_bellman.rs"]
        self.write_snapshot()
        with self.assertRaisesRegex(ValueError, "reconstruct"):
            self.check()

    def test_complete_source_closure_rejects_an_added_unregistered_owner(self):
        (self.target / "src/extra.rs").write_text("pub fn hidden() {}\n")
        with self.assertRaisesRegex(ValueError, "extra.rs"):
            self.check()

    def test_complete_source_closure_rejects_nonregular_entries(self):
        os.mkfifo(self.target / "src/unregistered-owner")
        with self.assertRaisesRegex(ValueError, "nonregular production source entry"):
            self.check()

    def test_current_target_changes_do_not_inherit_old_parity(self):
        path = self.target / "src/mcp/weight_bellman.rs"
        path.write_text("pub fn solve() { panic!(); }\n")
        with self.assertRaisesRegex(ValueError, "weight_bellman.rs"):
            self.check()

    def test_dependency_declarations_are_part_of_target_identity(self):
        (self.target / "Cargo.lock").write_text("version = 3\n")
        with self.assertRaisesRegex(ValueError, "Cargo.lock"):
            self.check()

    def test_executable_mode_drift_is_rejected(self):
        (self.target / "src/mcp/server.rs").chmod(0o755)
        with self.assertRaisesRegex(ValueError, "server.rs"):
            self.check()

    def test_identical_symlink_bytes_do_not_count_as_source_custody(self):
        path = self.target / "src/mcp/server.rs"
        path.rename(self.target / "server-retained.rs")
        path.symlink_to(self.target / "server-retained.rs")
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.check()

    def test_snapshot_digest_is_checked_before_reading_claims(self):
        path = self.root / "native/migration_target.json"
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaisesRegex(ValueError, "inventory binding"):
            self.check()

    def test_duplicate_json_fields_are_rejected_even_with_updated_digest(self):
        raw = json.dumps(self.snapshot).encode()
        self.write_snapshot(b'{"tools":[], ' + raw[1:])
        with self.assertRaisesRegex(ValueError, "duplicate JSON field"):
            self.check()

    def test_flags_cannot_substitute_for_actual_migrated_call_sites(self):
        self.inventory["legacy_tool_handlers"][0]["status"] = "ported"
        self.write_snapshot()
        with self.assertRaisesRegex(ValueError, "unqualified"):
            self.check()

    def test_invalid_paths_duplicates_and_non_integer_sizes_are_rejected(self):
        original = copy.deepcopy(self.snapshot)
        for replacement in ("../escape", "/src/escape", "src/../escape", "src/./escape", "src//escape"):
            with self.subTest(path=replacement):
                self.snapshot = copy.deepcopy(original)
                self.snapshot["source_files"][0]["path"] = replacement
                self.write_snapshot()
                with self.assertRaises(ValueError):
                    self.check()
        self.snapshot = copy.deepcopy(original)
        self.snapshot["source_files"].append(self.snapshot["source_files"][0])
        self.write_snapshot()
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.check()
        self.snapshot = copy.deepcopy(original)
        self.snapshot["source_files"][0]["bytes"] = True
        self.write_snapshot()
        with self.assertRaisesRegex(ValueError, "source identity"):
            self.check()

    def test_require_complete_returns_two_even_with_verified_current_source(self):
        run = subprocess.run([sys.executable, "-B", str(ROOT / "scripts/check_hia_native_target.py"),
                              "--root", str(self.root), "--target-root", str(self.target),
                              "--require-complete"], capture_output=True, text=True, timeout=10)
        self.assertEqual(run.returncode, 2, run.stderr)
        value = json.loads(run.stdout)
        self.assertEqual(value["completion_check"], "INCOMPLETE")
        self.assertTrue(value["target_checkout_verified"])


if __name__ == "__main__":
    unittest.main()

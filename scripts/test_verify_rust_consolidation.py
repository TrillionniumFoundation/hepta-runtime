"""Exercise archival custody against real disposable Git histories."""

import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

import verify_rust_consolidation as verification


class ArchiveCustodyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "repository"
        self.root.mkdir()
        self.command("init", "-q")
        self.command("config", "user.name", "Archive test")
        self.command("config", "user.email", "archive-test@example.invalid")
        self.original = b"original source\n"
        self.failure = b'{"status":"failed","accepted":false}\n'
        self.documentation_path = "docs/evidence.md"
        self.original_documentation = b"[Evidence](../historical/run/failure.json)\n"
        self.write("src/legacy.rs", self.original)
        self.write(self.documentation_path, self.original_documentation)
        self.write("historical/run/failure.json", self.failure)
        self.commit()
        self.source = self.command("rev-parse", "HEAD").decode().strip()
        self.source_tree = self.command("rev-parse", "HEAD^{tree}").decode().strip()
        original_tree = verification.read_tree(self.root, self.source)
        self.blob = original_tree["src/legacy.rs"][2]
        self.failure_blob = original_tree["historical/run/failure.json"][2]
        self.documentation_blob = original_tree[self.documentation_path][2]
        self.archive_path = "archives/rust-branches/" + self.source[:12] + "/manifest.json"
        self.previous = "archives/rust-branches/" + self.source[:12] + "/files/src/legacy.rs"
        self.archive = {
            "schema": "hepta.rust-branch-consolidation.v2",
            "source_commit": self.source, "source_tree": self.source_tree,
            "production_adopted_by_this_merge": False,
            "paths": [{"path": "src/legacy.rs", "source_blob": self.blob,
                       "source_mode": "100644", "retained_path": None,
                       "previous_retained_path": self.previous,
                       "disposition": "retained_in_reachable_git_history"}],
        }
        self.history_path = "archives/repository-history/test.json"
        self.history = {
            "schema": "hepta.repository-history-retention.v1",
            "source_commit": self.source, "source_tree": self.source_tree,
            "retired_roots": ["historical/"], "file_count": 1,
            "byte_count": len(self.failure),
            "paths": [{"path": "historical/run/failure.json", "source_mode": "100644",
                       "source_blob": self.failure_blob, "bytes": len(self.failure)}],
        }
        self.write("src/legacy.rs", b"current implementation\n")
        (self.root / "historical/run/failure.json").unlink()
        self.save()

    def command(self, *args, input_bytes=None):
        return subprocess.run(["git", *args], cwd=self.root, input=input_bytes,
                              capture_output=True, check=True).stdout

    def write(self, path, data):
        destination = self.root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)

    def commit(self):
        self.command("add", "--all")
        self.command("commit", "--quiet", "--allow-empty", "-m", "Fixture revision")

    def save(self):
        self.write(self.archive_path, json.dumps(self.archive).encode())
        self.write(self.history_path, json.dumps(self.history).encode())
        self.commit()

    def verify_archive(self):
        return verification.verify_archive_manifests(
            self.root, "HEAD", verification.read_tree(self.root, "HEAD"))

    def verify_history(self):
        return verification.verify_repository_history(
            self.root, "HEAD", verification.read_tree(self.root, "HEAD"))

    def update_documentation(self):
        updated = b"[Evidence](https://example.invalid/original/failure.json)\n"
        self.write(self.documentation_path, updated)
        current_blob = self.command("hash-object", "--stdin", input_bytes=updated).decode().strip()
        self.archive["paths"] = [{
            "path": self.documentation_path, "source_blob": self.documentation_blob,
            "source_mode": "100644", "current_blob": None,
            "disposition": "original_in_history_with_updated_documentation",
            "retained_path": None, "previous_disposition": "import_new_historical_evidence",
            "previous_retained_path": self.documentation_path,
            "current_documentation_path": self.documentation_path,
            "current_documentation_blob": current_blob, "current_documentation_mode": "100644",
        }]
        self.save()

    def retire_documentation_as_file(self):
        self.history["schema"] = "hepta.repository-history-retention.v2"
        self.history["retired_files"] = [self.documentation_path]
        self.history["paths"].append({
            "path": self.documentation_path, "source_blob": self.documentation_blob,
            "source_mode": "100644", "bytes": len(self.original_documentation)})
        self.history["file_count"] += 1
        self.history["byte_count"] += len(self.original_documentation)
        (self.root / self.documentation_path).unlink()
        self.save()

    def test_history_recovers_exact_original_source_and_failure_bytes(self):
        report = self.verify_archive()
        self.assertEqual(report["history_retained_blob_paths"], 1)
        self.assertEqual(report["exact_retained_blob_paths"], 0)
        history = self.verify_history()
        self.assertEqual(history["repository_history_files"], 1)
        self.assertEqual(history["repository_history_bytes"], len(self.failure))
        self.assertEqual(self.command("show", self.source + ":src/legacy.rs"), self.original)
        self.assertEqual(self.command("show", self.source + ":historical/run/failure.json"), self.failure)

    def test_v1_materialized_archive_remains_supported(self):
        self.archive["schema"] = "hepta.rust-branch-consolidation.v1"
        row = self.archive["paths"][0]
        row["disposition"] = "retain_exact_variant_outside_active_build"
        row["retained_path"] = row.pop("previous_retained_path")
        self.write(self.previous, self.original)
        self.save()
        self.assertEqual(self.verify_archive()["exact_retained_blob_paths"], 1)
        self.write(self.previous, b"altered copy\n")
        self.commit()
        with self.assertRaisesRegex(RuntimeError, "Retained original bytes or mode differ"):
            self.verify_archive()

    def test_changed_original_blob_mode_and_path_are_refused(self):
        original = copy.deepcopy(self.archive)
        for field, value in (("source_blob", "0" * 40), ("source_mode", "100755"),
                             ("path", "src/missing.rs")):
            with self.subTest(field=field):
                self.archive = copy.deepcopy(original)
                self.archive["paths"][0][field] = value
                self.save()
                with self.assertRaisesRegex(RuntimeError, "Original source blob or mode differs"):
                    self.verify_archive()

    def test_unknown_commit_and_changed_source_tree_are_refused(self):
        for field, pattern in (("source_commit", "unavailable"), ("source_tree", "tree differs")):
            original = self.archive[field]
            self.archive[field] = "f" * 40
            self.save()
            with self.subTest(field=field), self.assertRaisesRegex(RuntimeError, pattern):
                self.verify_archive()
            self.archive[field] = original

    def test_existing_unrelated_commit_is_not_history_custody(self):
        unrelated = self.command("commit-tree", self.source_tree,
                                 input_bytes=b"Unrelated history\n").decode().strip()
        self.archive["source_commit"] = unrelated
        self.history["source_commit"] = unrelated
        self.save()
        with self.assertRaisesRegex(RuntimeError, "unreachable"):
            self.verify_archive()
        with self.assertRaisesRegex(RuntimeError, "unreachable"):
            self.verify_history()

    def test_unsafe_source_and_previous_paths_are_refused(self):
        original = copy.deepcopy(self.archive)
        for field in ("path", "previous_retained_path"):
            for name in ("../outside", "/absolute", "a//b", "./file", "a\\b", "a\0b"):
                with self.subTest(field=field, path=name):
                    self.archive = copy.deepcopy(original)
                    self.archive["paths"][0][field] = name
                    self.save()
                    with self.assertRaisesRegex(RuntimeError, "Invalid repository path"):
                        self.verify_archive()

    def test_missing_retention_path_cannot_silently_pass(self):
        self.archive["paths"][0]["disposition"] = "import_new_historical_evidence"
        self.save()
        with self.assertRaisesRegex(RuntimeError, "retention path is missing"):
            self.verify_archive()

    def test_claimed_history_only_path_must_be_absent(self):
        self.write(self.previous, self.original)
        self.commit()
        with self.assertRaisesRegex(RuntimeError, "still materialized"):
            self.verify_archive()

    def test_updated_documentation_preserves_original_and_pins_current_bytes(self):
        self.update_documentation()
        report = self.verify_archive()
        self.assertEqual(report["history_retained_blob_paths"], 1)
        self.assertEqual(report["updated_documentation_paths"], 1)
        self.assertEqual(report["exact_retained_blob_paths"], 0)
        self.assertEqual(self.command("show", self.source + ":" + self.documentation_path),
                         self.original_documentation)
        self.assertIsNone(self.archive["paths"][0]["current_blob"])

    def test_updated_documentation_rejects_changed_pins_non_markdown_and_missing_path(self):
        self.update_documentation()
        original = copy.deepcopy(self.archive)
        for field, value in (("current_documentation_blob", self.documentation_blob),
                             ("current_documentation_mode", "100755")):
            with self.subTest(field=field):
                self.archive = copy.deepcopy(original)
                self.archive["paths"][0][field] = value
                self.save()
                with self.assertRaisesRegex(RuntimeError, "Current documentation bytes or mode differ"):
                    self.verify_archive()
        self.archive = copy.deepcopy(original)
        self.archive["paths"][0].update(path="src/legacy.rs", source_blob=self.blob)
        self.save()
        with self.assertRaisesRegex(RuntimeError, "Invalid updated documentation record"):
            self.verify_archive()
        self.archive = copy.deepcopy(original)
        (self.root / self.documentation_path).unlink()
        self.save()
        with self.assertRaisesRegex(RuntimeError, "Current documentation bytes or mode differ"):
            self.verify_archive()

    def test_repository_inventory_cannot_omit_duplicate_or_add_paths(self):
        original = copy.deepcopy(self.history)
        variants = [[], original["paths"] * 2,
                    original["paths"] + [{"path": "src/legacy.rs", "source_blob": self.blob,
                                           "source_mode": "100644", "bytes": len(self.original)}]]
        for rows in variants:
            with self.subTest(rows=len(rows)):
                self.history = copy.deepcopy(original)
                self.history["paths"] = rows
                self.history["file_count"] = len(rows)
                self.history["byte_count"] = sum(row["bytes"] for row in rows)
                self.save()
                with self.assertRaises(RuntimeError):
                    self.verify_history()

    def test_repository_object_size_mode_and_blob_are_bound(self):
        original = copy.deepcopy(self.history)
        for field, value in (("bytes", len(self.failure) + 1), ("source_mode", "100755"),
                             ("source_blob", self.blob)):
            with self.subTest(field=field):
                self.history = copy.deepcopy(original)
                self.history["paths"][0][field] = value
                self.history["byte_count"] = self.history["paths"][0]["bytes"]
                self.save()
                with self.assertRaises(RuntimeError):
                    self.verify_history()

    def test_repository_retention_rejects_unsafe_or_overlapping_roots(self):
        for roots in (["../outside/"], ["historical"], ["historical/", "historical/run/"],
                      ["missing/"], ["historical/", "historical/"]):
            with self.subTest(roots=roots):
                self.history["retired_roots"] = roots
                self.save()
                with self.assertRaises(RuntimeError):
                    self.verify_history()

    def test_repository_v2_recovers_root_and_individual_file_originals(self):
        self.retire_documentation_as_file()
        report = self.verify_history()
        self.assertEqual(report["repository_history_files"], 2)
        self.assertEqual(report["repository_history_bytes"],
                         len(self.failure) + len(self.original_documentation))
        self.assertEqual(self.command("show", self.source + ":" + self.documentation_path),
                         self.original_documentation)
        baseline = self.command("rev-parse", "HEAD").decode().strip()
        self.assertEqual(self.verify_continuity(baseline)["retention_inventory_source_rows"], 3)

    def test_repository_v2_supports_only_individual_files(self):
        self.retire_documentation_as_file()
        self.history["retired_roots"] = []
        self.history["paths"] = self.history["paths"][1:]
        self.history["file_count"] = 1
        self.history["byte_count"] = len(self.original_documentation)
        self.save()
        self.assertEqual(self.verify_history()["repository_history_files"], 1)

    def test_repository_v2_requires_explicit_file_list_and_nonempty_selection(self):
        self.retire_documentation_as_file()
        original = copy.deepcopy(self.history)
        for files in (None, "docs/evidence.md", {}):
            with self.subTest(files=files):
                self.history = copy.deepcopy(original)
                self.history["retired_files"] = files
                self.save()
                with self.assertRaisesRegex(RuntimeError, "retired files must be a list"):
                    self.verify_history()
        self.history = copy.deepcopy(original)
        self.history.pop("retired_files")
        self.save()
        with self.assertRaisesRegex(RuntimeError, "retired files must be a list"):
            self.verify_history()
        self.history = copy.deepcopy(original)
        self.history.update(retired_roots=[], retired_files=[])
        self.save()
        with self.assertRaisesRegex(RuntimeError, "retirement selection is empty"):
            self.verify_history()

    def test_repository_v1_cannot_silently_ignore_individual_files(self):
        self.retire_documentation_as_file()
        self.history["schema"] = "hepta.repository-history-retention.v1"
        self.save()
        with self.assertRaisesRegex(RuntimeError, "Retired files require repository history schema v2"):
            self.verify_history()

    def test_repository_v2_rejects_unsafe_or_nonexistent_individual_files(self):
        self.retire_documentation_as_file()
        for name in ("", "../outside", "/absolute", "a//b", "./file", "a\\b", "a\0b",
                     "docs/evidence.md/"):
            with self.subTest(path=name):
                self.history["retired_files"] = [name]
                self.save()
                with self.assertRaisesRegex(RuntimeError, "Invalid repository path"):
                    self.verify_history()
        for name in ("docs/missing.md", "docs"):
            with self.subTest(path=name):
                self.history["retired_files"] = [name]
                self.save()
                with self.assertRaisesRegex(RuntimeError, "retired file is absent from the source"):
                    self.verify_history()

    def test_repository_v2_rejects_duplicate_files_or_overlapping_roots(self):
        self.retire_documentation_as_file()
        original = copy.deepcopy(self.history)
        for roots, files in ((["historical/"], [self.documentation_path] * 2),
                             (["historical/", "docs/"], [self.documentation_path]),
                             (["historical/"], [self.documentation_path,
                                                "historical/run/failure.json"]),
                             (["historical/"], ["historical"])):
            with self.subTest(roots=roots, files=files):
                self.history = copy.deepcopy(original)
                self.history.update(retired_roots=roots, retired_files=files)
                self.save()
                with self.assertRaisesRegex(RuntimeError, "Duplicate or overlapping.*retired files"):
                    self.verify_history()

    def test_repository_v2_individual_file_rows_cannot_be_omitted_or_duplicated(self):
        self.retire_documentation_as_file()
        original = copy.deepcopy(self.history)
        for rows in (original["paths"][:1], original["paths"] + original["paths"][1:]):
            with self.subTest(rows=len(rows)):
                self.history = copy.deepcopy(original)
                self.history["paths"] = rows
                self.history["file_count"] = len(rows)
                self.history["byte_count"] = sum(row["bytes"] for row in rows)
                self.save()
                with self.assertRaisesRegex(RuntimeError, "inventory is incomplete|Duplicate repository history path"):
                    self.verify_history()

    def test_repository_v2_individual_file_blob_mode_and_size_are_bound(self):
        self.retire_documentation_as_file()
        original = copy.deepcopy(self.history)
        for field, value in (("bytes", len(self.original_documentation) + 1),
                             ("bytes", True), ("source_mode", "100755"),
                             ("source_blob", self.blob)):
            with self.subTest(field=field, value=value):
                self.history = copy.deepcopy(original)
                self.history["paths"][1][field] = value
                self.history["byte_count"] = sum(row["bytes"] for row in self.history["paths"])
                self.save()
                with self.assertRaises(RuntimeError):
                    self.verify_history()

    def test_repository_v2_individual_files_cannot_stay_materialized(self):
        self.retire_documentation_as_file()
        for raw in (self.original_documentation, b"modified replacement\n"):
            with self.subTest(raw=raw):
                self.write(self.documentation_path, raw)
                self.commit()
                with self.assertRaisesRegex(RuntimeError, "Retired repository path is still materialized"):
                    self.verify_history()

    def test_inventory_continuity_rejects_consistent_individual_file_removal(self):
        self.retire_documentation_as_file()
        baseline = self.command("rev-parse", "HEAD").decode().strip()
        self.history["retired_files"] = []
        self.history["paths"] = self.history["paths"][:1]
        self.history["file_count"] = 1
        self.history["byte_count"] = len(self.failure)
        self.save()
        # The smaller selection is internally consistent, but erases a complete
        # previously required original from custody without continuity checking.
        self.assertEqual(self.verify_history()["repository_history_files"], 1)
        with self.assertRaisesRegex(RuntimeError, "Custody inventory retired files changed"):
            self.verify_continuity(baseline)

    def test_inventory_continuity_rejects_missing_or_substituted_individual_files(self):
        self.retire_documentation_as_file()
        baseline = self.command("rev-parse", "HEAD").decode().strip()
        original = copy.deepcopy(self.history)
        self.history.pop("retired_files")
        self.save()
        with self.assertRaisesRegex(RuntimeError, "Custody inventory retired files changed"):
            self.verify_continuity(baseline)
        self.history = copy.deepcopy(original)
        self.history["retired_files"] = ["src/legacy.rs"]
        self.history["paths"][1] = {
            "path": "src/legacy.rs", "source_blob": self.blob,
            "source_mode": "100644", "bytes": len(self.original)}
        self.history["byte_count"] = len(self.failure) + len(self.original)
        (self.root / "src/legacy.rs").unlink()
        self.save()
        self.assertEqual(self.verify_history()["repository_history_files"], 2)
        with self.assertRaisesRegex(RuntimeError, "Custody inventory retired files changed"):
            self.verify_continuity(baseline)

    def test_missing_blob_objects_cannot_be_reported_as_recoverable(self):
        with self.assertRaisesRegex(RuntimeError, "blob is unavailable"):
            verification.blob_sizes(self.root, ["f" * 40])

    def test_already_identical_original_must_remain_available_after_source_changes(self):
        row = self.archive["paths"][0]
        row["disposition"] = "already_identical"
        row.pop("previous_retained_path")
        self.save()
        current_blob = verification.read_tree(self.root, "HEAD")["src/legacy.rs"][2]
        self.assertNotEqual(current_blob, self.blob)
        self.assertEqual(self.verify_archive()["original_source_paths_checked"], 1)

        # The original tree entry and ancestor remain intact, but the original
        # bytes have been lost. The later active implementation cannot stand in
        # for a historical row that never needed its own materialized copy.
        (self.root / ".git/objects" / self.blob[:2] / self.blob[2:]).unlink()
        self.assertEqual(verification.read_tree(self.root, self.source)["src/legacy.rs"][2], self.blob)
        with self.assertRaisesRegex(RuntimeError, "Archived blob is unavailable"):
            self.verify_archive()

    def verify_continuity(self, baseline, revision="HEAD"):
        return verification.verify_inventory_continuity(
            self.root, revision, verification.read_tree(self.root, revision), baseline)

    def test_inventory_continuity_accepts_original_and_pre_cleanup_revisions(self):
        baseline = self.command("rev-parse", "HEAD").decode().strip()
        report = self.verify_continuity(baseline)
        self.assertEqual(report["retention_inventory_status"], "PASS")
        self.assertEqual(report["retention_inventory_manifests"], 2)
        self.assertEqual(report["retention_inventory_source_rows"], 2)
        prior = self.verify_continuity(baseline, self.source)
        self.assertEqual(prior["retention_inventory_status"], "not_applicable_before_cleanup")

    def test_inventory_continuity_cannot_drop_row_to_hide_lost_original(self):
        baseline = self.command("rev-parse", "HEAD").decode().strip()
        self.archive["paths"] = []
        self.save()
        (self.root / ".git/objects" / self.blob[:2] / self.blob[2:]).unlink()
        with self.assertRaisesRegex(RuntimeError, "Custody inventory source rows changed"):
            self.verify_continuity(baseline)

    def test_inventory_continuity_requires_both_kinds_of_manifest(self):
        baseline = self.command("rev-parse", "HEAD").decode().strip()
        for path in (self.archive_path, self.history_path):
            with self.subTest(path=path):
                (self.root / path).unlink()
                self.commit()
                with self.assertRaisesRegex(RuntimeError, "Required custody manifests are missing"):
                    self.verify_continuity(baseline)
                self.save()

    def test_inventory_continuity_rejects_consistent_retired_root_removal(self):
        # Both directory inventories are initially exact. Removing a complete
        # root and adjusting totals would satisfy the per-manifest check, but
        # must not erase its original failure bytes from the required scope.
        self.history["retired_roots"].append("docs/")
        self.history["paths"].append({
            "path": self.documentation_path, "source_blob": self.documentation_blob,
            "source_mode": "100644", "bytes": len(self.original_documentation)})
        self.history["file_count"] = 2
        self.history["byte_count"] += len(self.original_documentation)
        (self.root / self.documentation_path).unlink()
        self.save()
        baseline = self.command("rev-parse", "HEAD").decode().strip()
        self.history["retired_roots"] = ["docs/"]
        self.history["paths"] = self.history["paths"][1:]
        self.history["file_count"] = 1
        self.history["byte_count"] = len(self.original_documentation)
        self.save()
        (self.root / ".git/objects" / self.failure_blob[:2] / self.failure_blob[2:]).unlink()
        self.assertEqual(self.verify_history()["repository_history_files"], 1)
        with self.assertRaisesRegex(RuntimeError, "Custody inventory retired roots changed"):
            self.verify_continuity(baseline)

    def test_inventory_continuity_cannot_substitute_another_valid_ancestor(self):
        baseline = self.command("rev-parse", "HEAD").decode().strip()
        self.archive["source_commit"] = baseline
        self.archive["source_tree"] = self.command("rev-parse", "HEAD^{tree}").decode().strip()
        self.archive["paths"][0]["source_blob"] = verification.read_tree(
            self.root, baseline)["src/legacy.rs"][2]
        self.save()
        self.assertEqual(self.verify_archive()["original_source_paths_checked"], 1)
        with self.assertRaisesRegex(RuntimeError, "Custody inventory source identity changed"):
            self.verify_continuity(baseline)

    def test_inventory_continuity_allows_additional_manifests(self):
        baseline = self.command("rev-parse", "HEAD").decode().strip()
        self.write("archives/rust-branches/additional/manifest.json", json.dumps(self.archive).encode())
        self.commit()
        self.assertEqual(self.verify_continuity(baseline)["retention_inventory_status"], "PASS")
        self.assertEqual(self.verify_archive()["archive_manifests"], 2)

    def test_inventory_continuity_rejects_unrelated_history(self):
        baseline = self.command("rev-parse", "HEAD").decode().strip()
        unrelated = self.command("commit-tree", self.source_tree,
                                 input_bytes=b"Unrelated revision\n").decode().strip()
        with self.assertRaisesRegex(RuntimeError, "unrelated to the retention inventory baseline"):
            self.verify_continuity(baseline, unrelated)

    def test_shallow_history_requires_explicit_fetch(self):
        shallow = Path(self.temporary.name) / "shallow"
        self.command("clone", "--quiet", "--depth", "1", self.root.as_uri(), str(shallow))
        with self.assertRaisesRegex(RuntimeError, "shallow checkout"):
            verification.require_history(shallow)


if __name__ == "__main__":
    unittest.main()

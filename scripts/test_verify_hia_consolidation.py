"""Refuse fabricated HIA integration evidence using real disposable Git objects."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

import verify_hia_consolidation as verification


class HiaIntegrationCustodyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "repository"
        self.root.mkdir()
        self.command("init", "-q")
        self.command("config", "user.name", "HIA custody fixture")
        self.command("config", "user.email", "fixture@example.invalid")
        self.original = b"fn original_owner() { 0 }\n"
        self.write("native/owner.hepta", self.original)
        self.write("native/other.hepta", b"fn other_owner() { 1 }\n")
        self.command("add", "--all")
        self.command("commit", "-q", "-m", "Original sources")
        self.base = self.command("rev-parse", "HEAD").decode().strip()
        self.tree = self.command("rev-parse", "HEAD^{tree}").decode().strip()
        self.initial = self.commit_tree(self.tree, [self.base], "Initial integration")
        self.incoming = self.commit_tree(self.tree, [self.base], "Independent native branch")
        self.merged = self.commit_tree(self.tree, [self.initial, self.incoming], "Normal source merge")
        self.pending = self.commit_tree(self.tree, [self.base], "Unmerged source with independent work")
        self.integration = {
            "schema": "hepta.runtime.normal-frontier-integration.v1",
            "initial_candidate": self.initial, "merged_head": self.merged,
            "native_source_base": self.base, "normal_merges": 1,
            "unresolved_frontiers": 1, "independent_frontiers": 3,
            "physical_sources_qualified_here": False, "history_rewritten": False,
        }
        self.ledger = {
            "initial_head": self.initial, "head": self.merged, "qualification_transferred": False,
            "merges": [
                {"before": self.initial, "incoming": self.base, "refs": ["refs/heads/base"],
                 "status": "already-ancestor"},
                {"before": self.initial, "incoming": self.incoming, "head": self.merged,
                 "tree": self.tree, "refs": ["refs/heads/native"], "status": "normal-two-parent-merge"},
            ],
            "remaining": [
                {"before": self.initial, "incoming": self.pending, "refs": ["refs/heads/pending"],
                 "status": "conflict-needs-source-review", "paths": ["native/owner.hepta"]},
            ],
        }
        self.manifest = {
            "schema": "hepta.runtime.public-source-closure.v2",
            "sources": {name: {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
                        for name, raw in (("native/owner.hepta", self.original),
                                          ("native/other.hepta", b"fn other_owner() { 1 }\n"))},
        }

    def command(self, *args, input_bytes=None):
        return subprocess.run(["git", *args], cwd=self.root, input=input_bytes,
                              capture_output=True, check=True).stdout

    def write(self, name, raw):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)

    def commit_tree(self, tree, parents, message):
        args = ["commit-tree", tree]
        for parent in parents:
            args.extend(["-p", parent])
        return self.command(*args, input_bytes=(message + "\n").encode()).decode().strip()

    def verify_frontiers(self, revision=None):
        return verification.verify_frontier_history(
            self.root, revision or self.merged, self.integration, self.ledger)

    def replace_merge(self, parents, tree=None):
        self.merged = self.commit_tree(tree or self.tree, parents, "Alternative merge object")
        self.integration["merged_head"] = self.merged
        self.ledger["head"] = self.merged
        self.ledger["merges"][1]["head"] = self.merged

    def test_actual_normal_merge_and_remaining_work_are_distinct(self):
        report = self.verify_frontiers()
        self.assertEqual(report["normal_two_parent_merges"], 1)
        self.assertEqual(report["already_ancestor_frontiers"], 1)
        self.assertEqual(report["retained_unresolved_frontier_commits"], 1)
        self.assertEqual(report["formerly_unresolved_now_ancestors"], 0)
        self.assertEqual(report["unresolved_frontiers_still_outside_revision"], 1)
        sources = verification.verify_native_sources(self.root, self.base, self.merged, self.manifest, 2)
        self.assertEqual(sources["original_native_binding_paths"], 2)
        later = self.commit_tree(self.tree, [self.merged, self.pending], "Later exact integration")
        self.assertEqual(self.verify_frontiers(later)["formerly_unresolved_now_ancestors"], 1)

    def test_one_parent_reversed_and_extra_parent_claims_are_refused(self):
        for parents in ([self.initial], [self.incoming, self.initial],
                        [self.initial, self.incoming, self.pending]):
            with self.subTest(parents=parents):
                self.replace_merge(parents)
                with self.assertRaisesRegex(RuntimeError, "exact two ordered parents"):
                    self.verify_frontiers()

    def test_merge_tree_is_checked_against_commit_bytes(self):
        self.ledger["merges"][1]["tree"] = self.command("mktree", input_bytes=b"").decode().strip()
        with self.assertRaisesRegex(RuntimeError, "merge tree differs"):
            self.verify_frontiers()

    def test_skipped_chain_step_and_unreachable_merge_are_refused(self):
        self.ledger["merges"][1]["before"] = self.base
        with self.assertRaisesRegex(RuntimeError, "chain is discontinuous"):
            self.verify_frontiers()
        self.ledger["merges"][1]["before"] = self.initial
        with self.assertRaisesRegex(RuntimeError, "not an ancestor"):
            self.verify_frontiers(self.initial)

    def test_false_already_ancestor_cannot_substitute_a_merge(self):
        self.ledger["merges"][0]["incoming"] = self.pending
        with self.assertRaisesRegex(RuntimeError, "declared already-ancestor"):
            self.verify_frontiers()

    def test_omitted_duplicate_and_relabelled_frontiers_are_refused(self):
        original = copy.deepcopy(self.ledger)
        self.ledger["merges"].pop()
        with self.assertRaisesRegex(RuntimeError, "inventory count"):
            self.verify_frontiers()
        self.ledger = copy.deepcopy(original)
        self.ledger["remaining"][0]["incoming"] = self.incoming
        with self.assertRaisesRegex(RuntimeError, "Duplicate frontier"):
            self.verify_frontiers()
        self.ledger = copy.deepcopy(original)
        self.ledger["qualification_transferred"] = True
        with self.assertRaisesRegex(RuntimeError, "cannot transfer execution"):
            self.verify_frontiers()

    def test_missing_unmerged_commit_and_unsafe_conflict_paths_are_refused(self):
        self.ledger["remaining"][0]["incoming"] = "f" * 40
        with self.assertRaisesRegex(RuntimeError, "commit is unavailable"):
            self.verify_frontiers()
        self.ledger["remaining"][0]["incoming"] = self.pending
        for path in ("../outside", "/outside", "native//owner", "native\\owner"):
            with self.subTest(path=path):
                self.ledger["remaining"][0]["paths"] = [path]
                with self.assertRaisesRegex(RuntimeError, "Invalid repository path"):
                    self.verify_frontiers()

    def test_bound_source_inventory_size_and_digest_are_required(self):
        for field, value in (("bytes", True), ("bytes", len(self.original) + 1), ("sha256", "0" * 64)):
            manifest = copy.deepcopy(self.manifest)
            manifest["sources"]["native/owner.hepta"][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(RuntimeError):
                verification.verify_native_sources(self.root, self.base, self.merged, manifest, 2)
        with self.assertRaisesRegex(RuntimeError, "inventory is incomplete"):
            verification.verify_native_sources(self.root, self.base, self.merged, self.manifest, 3)

    def test_changed_source_content_and_mode_are_not_object_preservation(self):
        self.write("native/owner.hepta", b"changed native source\n")
        self.command("add", "native/owner.hepta")
        altered_tree = self.command("write-tree").decode().strip()
        altered = self.commit_tree(altered_tree, [self.initial, self.incoming], "Changed source")
        with self.assertRaisesRegex(RuntimeError, "object or mode differs"):
            verification.verify_native_sources(self.root, self.base, altered, self.manifest, 2)
        self.write("native/owner.hepta", self.original)
        self.command("add", "native/owner.hepta")
        self.command("update-index", "--chmod=+x", "native/owner.hepta")
        altered_tree = self.command("write-tree").decode().strip()
        altered = self.commit_tree(altered_tree, [self.initial, self.incoming], "Changed mode")
        with self.assertRaisesRegex(RuntimeError, "object or mode differs"):
            verification.verify_native_sources(self.root, self.base, altered, self.manifest, 2)

    def test_original_blob_must_remain_readable(self):
        blob = verification.legacy.read_tree(self.root, self.base)["native/owner.hepta"][2]
        (self.root / ".git/objects" / blob[:2] / blob[2:]).unlink()
        with self.assertRaisesRegex(RuntimeError, "blob is unavailable"):
            verification.verify_native_sources(self.root, self.base, self.merged, self.manifest, 2)

    def test_fixed_authority_rejects_new_json_mode_and_missing_file(self):
        path, raw = "docs/authority.json", b'{"source":"original"}\n'
        self.write(path, raw)
        self.command("add", path)
        self.command("commit", "-q", "-m", "Fixed independent authority")
        revision = self.command("rev-parse", "HEAD").decode().strip()
        tree = verification.legacy.read_tree(self.root, revision)
        expected = (len(raw), hashlib.sha256(raw).hexdigest(), tree[path][2])
        self.assertEqual(verification.pinned_json(self.root, revision, tree, path, expected),
                         {"source": "original"})
        for value, executable in ((b'{"source":"replacement"}\n', False), (raw, True), (None, False)):
            with self.subTest(value=value, executable=executable):
                if value is None:
                    (self.root / path).unlink()
                    self.command("add", path)
                else:
                    self.write(path, value)
                    self.command("add", path)
                    self.command("update-index", "--chmod=" + ("+x" if executable else "-x"), path)
                current_tree = self.command("write-tree").decode().strip()
                current = self.commit_tree(current_tree, [revision], "Altered authority")
                with self.assertRaisesRegex(RuntimeError, "authority blob or mode differs"):
                    verification.pinned_json(self.root, current,
                        verification.legacy.read_tree(self.root, current), path, expected)

    def test_native_and_frozen_original_ancestry_cannot_be_omitted(self):
        branches = [{"name": "rust", "sha": self.initial}, {"name": "native", "sha": self.incoming},
                    {"name": "frozen", "sha": self.base}]
        preserved = [{"name": "native", "sha": self.incoming, "kind": "native_hia_rewrite"},
                     {"name": "frozen", "sha": self.base, "kind": "frozen_hia_pr_base"}]
        report = verification.verify_branch_ancestry(self.root, self.merged, branches, preserved)
        self.assertEqual(report["integrated_rust_refs"], 1)
        self.assertEqual(report["integrated_native_hia_refs"], 1)
        with self.assertRaisesRegex(RuntimeError, "not an ancestor"):
            verification.verify_branch_ancestry(self.root, self.initial, branches, preserved)
        preserved[0]["sha"] = self.base
        with self.assertRaisesRegex(RuntimeError, "branch identity changed"):
            verification.verify_branch_ancestry(self.root, self.merged, branches, preserved)


if __name__ == "__main__":
    unittest.main()

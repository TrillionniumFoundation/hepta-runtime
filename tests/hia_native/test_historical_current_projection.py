"""Reject wrong current sources and lossy historical profile composition."""
from pathlib import Path
from unittest import mock
import ast
import copy
import importlib.util
import json
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "tests/hia_native/historical_public58/current_projection.py"
SPEC = importlib.util.spec_from_file_location("historical_current_projection", PATH)
projection = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(projection)


class CurrentHistoricalProjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="hia-current-historical-controls-")
        cls.base = Path(cls.temporary.name)
        cls.source = cls.base / "current"
        cls.source.mkdir()
        cls.authority = projection.manifest(ROOT)
        binding = json.loads((ROOT / cls.authority["current_binding"]["path"]).read_bytes())
        names = set(binding["sources"]) | set(cls.authority["current_native_sources"])
        names.update(cls.authority["restore"])
        names.update(str(projection.FIXTURE / name) for name in cls.authority["restore"])
        names.add(str(projection.FIXTURE / cls.authority["original_reader"]["path"]))
        names.add(str(projection.PROFILE))
        for field in ("profile", "reference_profile", "current_binding"):
            names.add(cls.authority[field]["path"])
        for name in sorted(names):
            path = cls.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, path)
            path.chmod((ROOT / name).stat().st_mode & 0o777)
        projection.admit_current(cls.source)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_every_restore_and_exclusion_refuses_a_different_current_preimage(self):
        names = set(self.authority["restore"]) | set(self.authority["exclude_new_native_sources"])
        for name in sorted(names):
            path = self.source / name
            before = path.read_bytes()
            try:
                with self.subTest(path=name):
                    path.write_bytes(before + b"\x00")
                    with self.assertRaisesRegex(ValueError, "preimage changed"):
                        projection.admit_current(self.source)
            finally:
                path.write_bytes(before)

    def test_current_authority_and_restore_fixtures_cannot_redefine_the_old_inputs(self):
        path = self.source / projection.PROFILE
        original = path.read_bytes()
        changed = json.loads(original)
        changed["current_registered_components"] = 195
        try:
            path.write_text(json.dumps(changed))
            with self.assertRaisesRegex(ValueError, "authority changed"):
                projection.admit_current(self.source)
        finally:
            path.write_bytes(original)
        for name in self.authority["restore"]:
            path = self.source / projection.FIXTURE / name
            original = path.read_bytes()
            try:
                with self.subTest(fixture=name):
                    path.write_bytes(original + b"\x00")
                    with self.assertRaisesRegex(ValueError, "preimage changed"):
                        projection.admit_current(self.source)
            finally:
                path.write_bytes(original)

    def test_complete_current_binding_and_native_inventory_reject_uncovered_changes(self):
        binding = json.loads((self.source / self.authority["current_binding"]["path"]).read_bytes())
        name = next(name for name in binding["sources"]
                    if name.startswith("tests/") and name not in self.authority["restore"])
        path = self.source / name
        original = path.read_bytes()
        try:
            path.write_bytes(original + b"\x00")
            with self.assertRaisesRegex(ValueError, "preimage changed"):
                projection.admit_current(self.source)
        finally:
            path.write_bytes(original)
        extra = self.source / "native/unregistered_projection_input.hepta"
        try:
            extra.write_bytes(b"not an admitted native source\n")
            with self.assertRaisesRegex(ValueError, "native source inventory changed"):
                projection.admit_current(self.source)
        finally:
            extra.unlink()

    def test_original_196_to_195_inventory_change_is_exactly_the_bootstrap_entry(self):
        current = json.loads((self.source / "native/migration.json").read_bytes())
        historical = json.loads((self.source / projection.FIXTURE / "native/migration.json").read_bytes())
        entries = current["native_components"]
        self.assertEqual(len(entries), 196)
        added = [row for row in entries if row["source"] == "native/native_read_bootstrap.hepta"]
        self.assertEqual(len(added), 1)
        inverse = copy.deepcopy(current)
        inverse["native_components"] = [row for row in entries if row not in added]
        self.assertEqual(inverse, historical)
        self.assertEqual(len(historical["native_components"]), 195)

    def test_workflow_changes_add_only_complete_sparse_checkout_inputs(self):
        required = {"native", "scripts", "src", "tests", ".github", "authoring",
                    "vendor", "runtime_support", "qualification"}

        def split_checkout(raw):
            outside, blocks, block, indent = [], [], None, None
            for line in raw.decode().splitlines(keepends=True):
                depth = len(line) - len(line.lstrip())
                if block is not None and line.strip() and depth <= indent:
                    blocks.append(block)
                    block = None
                if block is not None:
                    block.append(line.strip())
                else:
                    outside.append(line)
                    if line.strip() == "sparse-checkout: |":
                        block, indent = [], depth
            if block is not None:
                blocks.append(block)
            return outside, blocks

        rows = self.authority["workflow_projection"]
        self.assertEqual(len(rows), 4)
        for name, identity in rows.items():
            with self.subTest(workflow=name):
                current = (ROOT / name).read_bytes()
                original = (ROOT / projection.FIXTURE / name).read_bytes()
                self.assertEqual(projection.pin(current), identity["current"])
                self.assertEqual(projection.pin(original), identity["original"])
                old_outside, old_blocks = split_checkout(original)
                new_outside, new_blocks = split_checkout(current)
                self.assertEqual(new_outside, old_outside)
                self.assertEqual(len(new_blocks), len(old_blocks))
                expanded = 0
                for before, after in zip(old_blocks, new_blocks):
                    if {"native", "scripts"} <= set(before):
                        self.assertEqual([line for line in after if line in before], before)
                        self.assertEqual(set(after) - set(before), required - set(before))
                        self.assertTrue(required <= set(after))
                        expanded += before != after
                    else:
                        self.assertEqual(after, before)
                self.assertGreater(expanded, 0)

    def test_projected_files_receipt_and_current_sources_are_independently_verified(self):
        output = self.base / "projected"
        before = projection.snapshot(self.source)
        receipt = projection.project(self.source, output)
        self.assertEqual(projection.snapshot(self.source), before)
        self.assertEqual(projection.verify(self.source, output)["status"], "CURRENT_SOURCE_PROJECTION_VERIFIED")
        self.assertEqual(receipt["restored_paths"], sorted(self.authority["restore"]))
        self.assertEqual(receipt["excluded_current_native_paths"], sorted(self.authority["exclude_new_native_sources"]))
        self.assertFalse((output / "native/native_read_bootstrap.hepta").exists())
        self.assertTrue((self.source / "native/native_read_bootstrap.hepta").is_file())
        target = output / "native/migration.json"
        original = target.read_bytes()
        try:
            target.write_bytes(original + b"\x00")
            with self.assertRaisesRegex(ValueError, "projected source receipt or files changed"):
                projection.verify(self.source, output)
        finally:
            target.write_bytes(original)
        path = output / projection.RECEIPT
        original = path.read_bytes()
        forged = json.loads(original)
        forged["projected_files"].pop("native/migration.json")
        try:
            path.write_text(json.dumps(forged))
            with self.assertRaisesRegex(ValueError, "projected source receipt or files changed"):
                projection.verify(self.source, output)
        finally:
            path.write_bytes(original)
        extra = output / "scripts/unowned-added-source.py"
        try:
            extra.write_text("raise RuntimeError('unowned source')\n")
            with self.assertRaisesRegex(ValueError, "projected source receipt or files changed"):
                projection.verify(self.source, output)
        finally:
            extra.unlink()
        self.assertEqual(projection.snapshot(self.source), before)

    def test_symbolic_links_and_in_tree_or_existing_outputs_are_refused(self):
        link = self.base / "linked-current"
        link.symlink_to(self.source, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symbolic links"):
            projection.read(link, projection.PROFILE)
        name = next(iter(self.authority["restore"]))
        path = self.source / projection.FIXTURE / name
        original = path.read_bytes()
        saved = self.base / "original-projection-source"
        saved.write_bytes(original)
        try:
            path.unlink()
            path.symlink_to(saved)
            with self.assertRaisesRegex(ValueError, "symbolic links"):
                projection.admit_current(self.source)
        finally:
            path.unlink()
            path.write_bytes(original)
        for output in (self.source / "inside", self.base):
            with self.subTest(output=output), self.assertRaisesRegex(ValueError, "fresh independent output"):
                projection.project(self.source, output)

    def test_current_sources_are_reread_after_admission(self):
        target = self.source / "native/migration.json"
        original = target.read_bytes()
        old_read = projection.read
        calls = 0

        def drift(root, name):
            nonlocal calls
            if root / name == target:
                calls += 1
                if calls == 2:
                    target.write_bytes(original + b"\x00")
            return old_read(root, name)

        try:
            with mock.patch.object(projection, "read", side_effect=drift):
                with self.assertRaisesRegex(ValueError, "terminal readback"):
                    projection.admit_current(self.source)
            self.assertEqual(calls, 2)
        finally:
            target.write_bytes(original)

    def test_every_original_materializer_function_and_fixed_profile_remains_exact(self):
        original = (ROOT / projection.FIXTURE / "materialize_original.py").read_bytes()
        current = (ROOT / projection.PREFIX / "materialize.py").read_bytes()
        before = {node.name: node for node in ast.parse(original).body if isinstance(node, ast.FunctionDef)}
        after = {node.name: node for node in ast.parse(current).body if isinstance(node, ast.FunctionDef)}
        after["main"] = copy.deepcopy(after["historical_main"])
        after["main"].name = "main"
        for name, node in before.items():
            with self.subTest(function=name):
                self.assertEqual(ast.dump(after[name], include_attributes=False),
                                 ast.dump(node, include_attributes=False))
        for field in ("profile", "reference_profile"):
            row = self.authority[field]
            self.assertEqual(projection.pin((ROOT / row["path"]).read_bytes()),
                             {key: row[key] for key in ("bytes", "sha256", "git_blob")})


if __name__ == "__main__":
    unittest.main()

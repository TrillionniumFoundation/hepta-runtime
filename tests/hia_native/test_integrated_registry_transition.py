"""Controls for the separately fixed current/historical module registry."""
from pathlib import Path
from unittest import mock
import ast
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tests/hia_native/historical_public58/materialize.py"
spec = importlib.util.spec_from_file_location("registry_transition_materializer", MODULE_PATH)
materialize = importlib.util.module_from_spec(spec)
spec.loader.exec_module(materialize)


class RegistrySourceTransitionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.transition = materialize.current_source_transition(ROOT)
        cls.registry = cls.transition["profile"]["registry_transition"]
        cls.name = cls.registry["path"]

    def current_root(self):
        temporary = tempfile.TemporaryDirectory(prefix="hia-registry-source-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / "source"
        root.mkdir()
        for name, row in self.transition["captured"].items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(row["raw"])
            path.chmod(row["identity"][2] & 0o777)
        return root

    def reject(self, root):
        with self.assertRaises((ValueError, AssertionError, FileNotFoundError)):
            materialize.current_source_transition(root)

    def test_complete_registry_inverse_preserves_all_other_module_and_test_entries(self):
        current = self.transition["captured"][self.name]["raw"]
        original = self.transition["registry_predecessor"]
        self.assertEqual(materialize.pin(current), self.registry["current"])
        self.assertEqual(materialize.pin(original), self.registry["predecessor"])
        self.assertEqual(len(self.registry["inverse"]), 2)
        self.assertEqual(len(current) - len(original), 270)

        def modules(raw):
            assignments = [node for node in ast.parse(raw).body if isinstance(node, ast.Assign)
                           and any(isinstance(target, ast.Name) and target.id == "MODULES"
                                   for target in node.targets)]
            self.assertEqual(len(assignments), 1)
            return [ast.literal_eval(node) for node in assignments[0].value.elts
                    if isinstance(node, ast.Dict)]

        before, after = modules(original), modules(current)
        self.assertEqual([row["key"] for row in before],
                         [row["key"] for row in after if row["key"] != "native_read_bootstrap"])
        expected = [dict(row) for row in after if row["key"] != "native_read_bootstrap"]
        owner = next(row for row in expected if row["key"] == "local_service")
        self.assertIn("test_file_info_ready_reap.py", owner["additional_tests"])
        owner["additional_tests"] = tuple(name for name in owner["additional_tests"]
                                           if name != "test_file_info_ready_reap.py")
        self.assertEqual(before, expected)
        self.assertEqual((ROOT / self.name).read_bytes(), current)

    def test_missing_modified_or_historical_physical_registry_is_rejected(self):
        root = self.current_root()
        path, raw = root / self.name, (root / self.name).read_bytes()
        for candidate in (None, raw + b"\x00", self.transition["registry_predecessor"]):
            try:
                with self.subTest(candidate="missing" if candidate is None else materialize.SHA(candidate)):
                    path.unlink() if candidate is None else path.write_bytes(candidate)
                    self.reject(root)
            finally:
                path.write_bytes(raw)

    def test_registry_bytes_and_identity_are_repeated_at_terminal_admission(self):
        original_read = materialize.read
        for same_bytes in (False, True):
            root = self.current_root()
            path, raw, count = root / self.name, (root / self.name).read_bytes(), 0

            def drift(base, relative):
                nonlocal count
                if base / relative == path:
                    count += 1
                    if count == 2:
                        if same_bytes:
                            replacement = path.with_name("replacement.py")
                            replacement.write_bytes(raw)
                            replacement.chmod(path.stat().st_mode & 0o777)
                            os.replace(replacement, path)
                        else:
                            path.write_bytes(raw + b"\x00")
                return original_read(base, relative)

            with self.subTest(same_bytes=same_bytes), mock.patch.object(materialize, "read", side_effect=drift):
                with self.assertRaisesRegex(ValueError, "terminal readback"):
                    materialize.current_source_transition(root)
            self.assertEqual(count, 2)

    def test_both_fixed_transition_authorities_and_control_loader_relation_are_required(self):
        root = self.current_root()
        for name in (materialize.CURRENT_SOURCE_TRANSITION, materialize.PREVIOUS_SOURCE_TRANSITION):
            path, raw = root / name, (root / name).read_bytes()
            for missing in (False, True):
                try:
                    with self.subTest(path=str(name), missing=missing):
                        path.unlink() if missing else path.write_bytes(raw + b"\x00")
                        self.reject(root)
                finally:
                    path.write_bytes(raw)
        path = root / "tests/hia_native/test_integrated_source_transition.py"
        current = path.read_bytes()
        value = json.loads((root / materialize.CURRENT_SOURCE_TRANSITION).read_bytes())
        predecessor = materialize._transition_inverse(current, value["control_loader_transition"], str(path))
        path.write_bytes(predecessor)
        self.reject(root)

    def test_new_registry_controls_are_fixed_complete_source_inputs(self):
        root = self.current_root()
        name = "tests/hia_native/test_integrated_registry_transition.py"
        self.assertIn(name, self.transition["profile"]["current_auxiliary_files"])
        path, raw = root / name, (root / name).read_bytes()
        path.write_bytes(raw + b"\x00")
        self.reject(root)
        path.unlink()
        self.reject(root)

    def test_historical_output_registry_is_fixed_even_if_the_output_receipt_is_rewritten(self):
        temporary = tempfile.TemporaryDirectory(prefix="hia-registry-output-")
        self.addCleanup(temporary.cleanup)
        output = Path(temporary.name) / "historical"
        process = subprocess.run(
            [sys.executable, "-I", "-B", str(MODULE_PATH), "--source", str(ROOT), "--output", str(output)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
        self.assertEqual(process.returncode, 0, process.stderr.decode(errors="replace"))
        materialize.verify_materialized(output)
        path = output / self.name
        self.assertEqual(path.read_bytes(), self.transition["registry_predecessor"])
        self.assertEqual((ROOT / self.name).read_bytes(), self.transition["captured"][self.name]["raw"])
        path.write_bytes(path.read_bytes() + b"\x00")
        receipt_path = output / "HISTORICAL_PUBLIC_SOURCE.json"
        receipt = json.loads(receipt_path.read_bytes())
        receipt["files"][self.name] = materialize.pin(path.read_bytes())
        receipt_path.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
        with self.assertRaisesRegex(ValueError, "registry predecessor differs"):
            materialize.verify_materialized(output)


if __name__ == "__main__":
    unittest.main()

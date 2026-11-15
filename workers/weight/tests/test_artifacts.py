"""Storage/identity tests that do not require a model runtime."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from weight_runtime.artifacts import ArtifactStore, PathPolicy, file_sha256
from weight_runtime.errors import WeightError, loads


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.inputs = self.root / "inputs"
        self.inputs.mkdir()
        self.policy = PathPolicy([str(self.inputs)], str(self.root / "outputs"))
        self.store = ArtifactStore(self.policy.output)

    def tearDown(self):
        self.temporary.cleanup()

    def test_content_identity_and_repeated_retention(self):
        first = self.store.put_json({"value": 1})
        self.assertEqual(first, self.store.put_json({"value": 1}))
        self.assertEqual(self.store.load_json(first["artifact_id"]), {"value": 1})
        other = self.store.put_json({"value": 1}, "another-kind")
        self.assertEqual(first["sha256"], other["sha256"])
        self.assertNotEqual(first["artifact_id"], other["artifact_id"])

    def test_tampered_payload_is_rejected(self):
        ref = self.store.put_json({"value": 2})
        Path(ref["path"]).write_bytes(b"changed")
        with self.assertRaisesRegex(WeightError, "bytes changed"):
            self.store.ref(ref["artifact_id"])

    def test_path_authority_and_symlink_escape(self):
        outside = self.root / "outside.json"
        outside.write_text("{}")
        with self.assertRaises(WeightError):
            self.policy.read(outside)
        (self.inputs / "link.json").symlink_to(outside)
        with self.assertRaises(WeightError):
            self.policy.read(self.inputs / "link.json")

    def test_input_hash_binding(self):
        path = self.inputs / "model.json"
        path.write_text("{}")
        self.assertEqual(self.policy.bound(path, file_sha256(path)), path)
        with self.assertRaises(WeightError):
            self.policy.bound(path, "0" * 64)

    def test_object_quota(self):
        store = ArtifactStore(self.root / "small", max_artifact_bytes=8)
        with self.assertRaises(WeightError):
            store.put_json({"too_large": "value"})

    def test_strict_json(self):
        for payload in ('{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}', '{"x":1e999}'):
            with self.assertRaises(WeightError):
                loads(payload)


if __name__ == "__main__":
    unittest.main()

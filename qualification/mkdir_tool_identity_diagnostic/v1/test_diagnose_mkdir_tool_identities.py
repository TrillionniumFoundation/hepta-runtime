from pathlib import Path
import hashlib
import json
import tempfile
import unittest

import diagnose_mkdir_tool_identities as probe


class DiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.receipt = self.base / "result.json"
        self.tools = self.base / "tools"
        self.tools.mkdir()
        self.paths = tuple(self.tools / role for role in probe.ROLES)
        for role, path in zip(probe.ROLES, self.paths, strict=True):
            path.write_bytes(role.encode())
            path.chmod(0o700)
        self.ref = probe.load_reference(Path(__file__).resolve().parents[3])
        self.expected = {role: self.ref.tool_identity(path)
                         for role, path in zip(probe.ROLES, self.paths, strict=True)}

    def prepare_receipt(self):
        raw = json.dumps({"schema": probe.SCHEMA, "status": "PASS", "error": None,
                          "tools": self.expected}).encode()
        self.receipt.write_bytes(raw)
        return hashlib.sha256(raw).hexdigest()

    def test_exact_identity(self):
        digest = self.prepare_receipt()
        prior = probe.expected_identities(self.ref, self.receipt, digest)
        self.assertEqual(probe.compare(self.ref, prior, self.paths), {
            "status": "MATCH", "differences": {}, "unavailable": {}, "qualification_performed": False})

    def test_symlink_launch_path_only(self):
        alias = self.tools / "rustc_alias"
        alias.symlink_to(self.paths[0])
        result = probe.compare(self.ref, self.expected, (alias, *self.paths[1:]))
        self.assertEqual(result["status"], "MISMATCH")
        self.assertEqual(set(result["differences"]["rustc"]), {"launch_path"})

    def test_same_size_sha_only(self):
        self.paths[2].write_bytes(b"XX")
        result = probe.compare(self.ref, self.expected, self.paths)
        self.assertEqual(result["status"], "MISMATCH")
        self.assertEqual(set(result["differences"]["ld"]), {"sha256"})

    def test_unavailable_tool_does_not_mask_a_second_mismatch(self):
        self.paths[3].unlink()
        self.paths[2].write_bytes(b"changed")
        result = probe.compare(self.ref, self.expected, self.paths)
        self.assertEqual(result["status"], "MISMATCH")
        self.assertEqual(result["unavailable"]["interpreter"]["error_type"], "FileNotFoundError")
        self.assertEqual(set(result["differences"]["ld"]), {"bytes", "sha256"})

    def test_invalid_record_or_digest(self):
        checksum = self.prepare_receipt()
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            probe.expected_identities(self.ref, self.receipt, checksum[::-1])
        del self.expected["interpreter"]["sha256"]
        checksum = self.prepare_receipt()
        with self.assertRaisesRegex(ValueError, "interpreter"):
            probe.expected_identities(self.ref, self.receipt, checksum)

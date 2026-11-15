"""Offline regressions for source-safe executable PATH qualification."""

from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from qualification_path_fence import UnsafeCommandPath, check_command_search_path


class QualificationPathFenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "repo"
        self.root.mkdir()

    def test_accept_absolute_external_path(self):
        check_command_search_path("/usr/bin:/bin", self.root)

    def test_refuse_missing_empty_and_relative_entries(self):
        for path in (None, "", ":/usr/bin", "/usr/bin:", ".:/usr/bin", "bin:/usr/bin", "../bin"):
            with self.subTest(path=path), self.assertRaises(UnsafeCommandPath):
                check_command_search_path(path, self.root)

    def test_refuse_source_root_and_nested_directory(self):
        nested = self.root / "tools"
        nested.mkdir()
        for path in (str(self.root), str(nested), f"/usr/bin:{nested}"):
            with self.subTest(path=path), self.assertRaisesRegex(UnsafeCommandPath, "source"):
                check_command_search_path(path, self.root)

    @unittest.skipUnless(os.name == "posix", "directory symlinks require POSIX")
    def test_refuse_alias_to_source_directory(self):
        tools = self.root / "tools"
        tools.mkdir()
        alias = Path(self.tmp.name) / "alias"
        alias.symlink_to(tools, target_is_directory=True)
        with self.assertRaisesRegex(UnsafeCommandPath, "source"):
            check_command_search_path(str(alias), self.root)

    def test_allow_diagnostics_without_source_context(self):
        check_command_search_path("/usr/bin:/bin")

    def test_do_not_leak_path_details_in_denial(self):
        secret = self.root / "secret-canary"
        secret.mkdir()
        with self.assertRaises(UnsafeCommandPath) as raised:
            check_command_search_path(str(secret), self.root)
        self.assertNotIn("secret-canary", str(raised.exception))


if __name__ == "__main__":
    unittest.main()

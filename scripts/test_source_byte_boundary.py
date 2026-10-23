from __future__ import annotations

import os
from pathlib import Path
import stat
import tempfile
import unittest

from source_byte_boundary import MAX_SOURCE_BYTES, UnsafeSourcePath, read_indexed_file


@unittest.skipUnless(os.name == "posix", "POSIX no-follow source intake required")
class SourceBytesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_regular_nested_file_reads_expected_bytes_and_mode(self):
        inner = self.root / "dir" / "child"
        inner.mkdir(parents=True)
        f = inner / "source.rs"
        f.write_bytes(b"fn main() {}\\n")
        actual, mode = read_indexed_file(self.root, b"dir/child/source.rs")
        self.assertEqual(actual, b"fn main() {}\\n")
        self.assertTrue(stat.S_ISREG(mode))

    def test_refuses_final_and_intermediate_symlinks(self):
        with tempfile.TemporaryDirectory() as outside:
            target = Path(outside) / "tracked.py"
            target.write_text("trusted data\\n")
            (self.root / "linked_file").symlink_to(target)
            (self.root / "nested").symlink_to(outside, target_is_directory=True)
            for raw in (b"linked_file", b"nested/tracked.py"):
                with self.subTest(raw=raw):
                    with self.assertRaises(UnsafeSourcePath):
                        read_indexed_file(self.root, raw)

    def test_denies_external_hard_link_to_mutable_source(self):
        with tempfile.TemporaryDirectory() as outside:
            external = Path(outside) / "artifact"
            external.write_bytes(b"original")
            os.link(external, self.root / "tracked")
            with self.assertRaisesRegex(UnsafeSourcePath, "hard links"):
                read_indexed_file(self.root, b"tracked")

    def test_refuses_fifo_without_blocking(self):
        os.mkfifo(self.root / "pipe")
        with self.assertRaisesRegex(UnsafeSourcePath, "regular file"):
            read_indexed_file(self.root, b"pipe")

    def test_deny_noncanonical_path(self):
        for raw in (b"../secret", b"dir/../secret", b"/absolute", b"dir//file", b"./file", b""):
            with self.subTest(raw=raw):
                with self.assertRaisesRegex(UnsafeSourcePath, "noncanonical"):
                    read_indexed_file(self.root, raw)

    def test_refuses_oversized_file_before_materializing_it(self):
        f = self.root / "large"
        with f.open("wb") as handle:
            handle.truncate(MAX_SOURCE_BYTES + 1)
        with self.assertRaisesRegex(UnsafeSourcePath, "byte cap"):
            read_indexed_file(self.root, b"large")


if __name__ == "__main__":
    unittest.main()

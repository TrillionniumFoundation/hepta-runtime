"""Mechanical snapshot regression controls; no native requests are counted."""
import errno
import hashlib
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from evidence_snapshot import copy_evidence_files, unrelated_fixture_guard


class EvidenceSnapshotTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='snapshot-regression-')
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)
        self.source = self.folder / 'evidence'
        (self.source / 'build').mkdir(parents=True)
        self.original = self.source / 'build/owned.bin'
        self.original.write_bytes(b'complete admitted bytes\0\xff\n')
        self.original.chmod(0o640)
        self.expected = {'build/owned.bin': hashlib.sha256(self.original.read_bytes()).hexdigest()}

    def test_exact_closure_ignores_loops_dangling_links_fifos_and_raw_names(self):
        before = self.original.stat()
        destination = self.folder / 'snapshot'
        with unrelated_fixture_guard(self.source) as fixtures:
            self.assertTrue(stat.S_ISFIFO((fixtures / 'fifo').lstat().st_mode))
            self.assertEqual(os.readlink(fixtures / 'loop-a'), 'loop-b')
            with self.assertRaises(OSError) as failure:
                (fixtures / 'loop-a').stat()
            self.assertEqual(failure.exception.errno, errno.ELOOP)
            result = copy_evidence_files(self.source, destination, self.expected)
            self.assertEqual(set(result), set(self.expected))
        self.assertEqual(sorted(p.relative_to(destination).as_posix()
                                for p in destination.rglob('*') if p.is_file()), list(self.expected))
        copied = destination / 'build/owned.bin'
        self.assertEqual(copied.read_bytes(), self.original.read_bytes())
        self.assertEqual(stat.S_IMODE(copied.stat().st_mode), 0o640)
        self.assertNotEqual((copied.stat().st_dev, copied.stat().st_ino), (before.st_dev, before.st_ino))
        copied.write_bytes(b'private refusal mutation')
        self.assertEqual(hashlib.sha256(self.original.read_bytes()).hexdigest(), self.expected['build/owned.bin'])
        after = self.original.stat()
        for field in ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'):
            self.assertEqual(getattr(before, field), getattr(after, field))

    def test_declared_symlink_cannot_alias_admitted_bytes(self):
        (self.source / 'alias').symlink_to('build/owned.bin')
        with self.assertRaisesRegex(ValueError, 'symbolic link'):
            copy_evidence_files(self.source, self.folder / 'snapshot',
                                {'alias': self.expected['build/owned.bin']})

    def test_declared_fifo_is_rejected_before_any_read(self):
        os.mkfifo(self.source / 'pipe')
        with self.assertRaisesRegex(ValueError, 'ordinary regular file'):
            copy_evidence_files(self.source, self.folder / 'snapshot', {'pipe': '0' * 64})
        self.assertTrue(stat.S_ISFIFO((self.source / 'pipe').lstat().st_mode))

    def test_changed_admitted_bytes_do_not_reach_a_snapshot(self):
        self.original.write_bytes(b'changed evidence')
        destination = self.folder / 'snapshot'
        with self.assertRaisesRegex(ValueError, 'admitted SHA256'):
            copy_evidence_files(self.source, destination, self.expected)
        self.assertFalse((destination / 'build/owned.bin').exists())

    def test_fixture_guard_detects_mutation_without_following_its_links(self):
        with self.assertRaisesRegex(AssertionError, 'changed unrelated filesystem fixtures'):
            with unrelated_fixture_guard(self.source) as fixtures:
                (fixtures / 'fifo').unlink()


if __name__ == '__main__':
    unittest.main()

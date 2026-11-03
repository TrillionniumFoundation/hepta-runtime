"""Disposable Git reference: source SHA cannot attest mutable symlink targets.
Only reference checks; NOT checked-out hepta-runtime source or host tests.
"""
from pathlib import Path
import hashlib
import os
import runpy
import subprocess
import tempfile
import unittest


def git(repo, *args):
    return subprocess.run(("git", *args), cwd=repo, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=True).stdout


def init_repo(root):
    git(root, "init", "-q")
    git(root, "config", "user.email", "test@example.invalid")
    git(root, "config", "user.name", "Fixture")
    (root / "tracked.txt").write_text("first\n")
    git(root, "add", "tracked.txt")
    git(root, "commit", "-qm", "baseline")


def old_git_mode_check(repo):
    seen = 0
    for entry in git(repo, "ls-files", "--stage", "-z").split(b"\0"):
        if not entry:
            continue
        mode_sha, path_bytes = entry.split(b"\t", 1)
        mode, sha, stage = mode_sha.decode().split()
        path = repo / os.fsdecode(path_bytes)
        if mode == "120000":
            if not path.is_symlink():
                raise AssertionError("missing link")
            data = os.fsencode(os.readlink(path))
        else:
            data = path.read_bytes()
        digest = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        if digest != sha:
            raise AssertionError("blob changed")
        seen += 1
    return seen


def new_git_mode_check(repo):
    seen = 0
    for entry in git(repo, "ls-files", "--stage", "-z").split(b"\0"):
        if not entry:
            continue
        mode_sha, _path = entry.split(b"\t", 1)
        mode, _sha, _stage = mode_sha.decode().split()
        if mode == "120000":
            raise ValueError("tracked symlink has no immutable target-byte proof")
        seen += 1
    return seen


class SymlinkReferenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "repo"
        self.root.mkdir()
        init_repo(self.root)

    def test_regular_source_allowed(self):
        self.assertEqual(old_git_mode_check(self.root), 1)
        self.assertEqual(new_git_mode_check(self.root), 1)

    def test_external_link_can_change_executable_bytes_without_git_change(self):
        external = Path(self.temp.name) / "external.py"
        external.write_text('VALUE="first"\n')
        (self.root / "linked.py").symlink_to(external)
        git(self.root, "add", "linked.py")
        git(self.root, "commit", "-qm", "external link")
        head = git(self.root, "rev-parse", "HEAD").decode().strip()
        self.assertEqual(old_git_mode_check(self.root), 2)
        self.assertEqual(runpy.run_path(str(self.root / "linked.py"))["VALUE"], "first")
        external.write_text('VALUE="second"\n')
        self.assertEqual(old_git_mode_check(self.root), 2)
        self.assertEqual(runpy.run_path(str(self.root / "linked.py"))["VALUE"], "second")
        self.assertEqual(git(self.root, "rev-parse", "HEAD").decode().strip(), head)
        with self.assertRaisesRegex(ValueError, "tracked symlink"):
            new_git_mode_check(self.root)

    def test_relative_symlink_is_refused(self):
        (self.root / "linked.txt").symlink_to("tracked.txt")
        git(self.root, "add", "linked.txt")
        git(self.root, "commit", "-qm", "in checkout link")
        self.assertEqual(old_git_mode_check(self.root), 2)
        with self.assertRaisesRegex(ValueError, "tracked symlink"):
            new_git_mode_check(self.root)

if __name__ == "__main__":
    unittest.main(verbosity=2)

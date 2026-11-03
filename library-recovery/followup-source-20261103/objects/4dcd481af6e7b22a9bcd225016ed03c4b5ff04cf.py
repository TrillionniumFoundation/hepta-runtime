"""Isolated executable Git configuration preflight and adversarial regression reference.

This is NOT the hepta-runtime repository checkout.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class QualificationError(Exception):
    pass


def git(repo: Path, *args: str) -> bytes:
    proc = subprocess.run(("git", "-c", "core.hooksPath=/dev/null", *args),
                          cwd=repo, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          env={**os.environ, "GIT_NO_REPLACE_OBJECTS": "1"})
    if proc.returncode:
        raise QualificationError("git operation failed")
    return proc.stdout


def assert_no_executable_checkout_config(repo: Path) -> None:
    """Prevent Git checkout smudge/process, fsmonitor and conditional includes."""
    settings = git(repo, "config", "--list", "-z")
    for entry in settings.split(b"\0"):
        if not entry:
            continue
        raw_key, separator, value = entry.partition(b"\n")
        if not separator:
            raise QualificationError("malformed Git config entry")
        try:
            key = raw_key.decode("ascii").lower()
        except UnicodeDecodeError as exc:
            raise QualificationError("noncanonical Git config key") from exc
        if key == "core.hookspath":
            if value != b"/dev/null":
                raise QualificationError("unreviewed Git hooksPath config")
        elif key == "core.fsmonitor":
            if value.strip().lower() not in (b"false", b"0", b""):
                raise QualificationError("unreviewed Git fsmonitor command")
        elif (key.startswith("filter.") and
              (key.endswith(".smudge") or key.endswith(".process")) and value.strip()):
            raise QualificationError("unreviewed Git checkout filter command")
        elif key == "include.path" or (key.startswith("includeif.") and key.endswith(".path")):
            raise QualificationError("unreviewed Git conditional/included config")


class Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.repo = self.base / "repo"
        self.repo.mkdir()
        git(self.repo, "init", "-q")
        git(self.repo, "config", "user.name", "Fixture")
        git(self.repo, "config", "user.email", "fixture@example.invalid")

    def test_clean_default(self):
        assert_no_executable_checkout_config(self.repo)

    def test_smudge_exec_reproduced_then_preflight_denies(self):
        (self.repo / ".gitattributes").write_text("payload.txt filter=bad\n")
        (self.repo / "payload.txt").write_text("content\n")
        git(self.repo, "add", ".gitattributes", "payload.txt")
        git(self.repo, "commit", "-qm", "fixture")
        marker = self.base / "MARKER"
        git(self.repo, "config", "filter.bad.smudge", f"sh -c 'touch {marker}; cat'")
        with self.assertRaisesRegex(QualificationError, "checkout filter"):
            assert_no_executable_checkout_config(self.repo)
        self.assertFalse(marker.exists())
        # Demonstrates the original bypass after disabling Git hooks.
        git(self.repo, "worktree", "add", "--detach", str(self.base / "unsafe"), "HEAD")
        self.assertTrue(marker.exists(), "reproduced external command execution at checkout")

    def test_process_filter_denied(self):
        git(self.repo, "config", "filter.other.process", "unsafe-command")
        with self.assertRaisesRegex(QualificationError, "checkout filter"):
            assert_no_executable_checkout_config(self.repo)

    def test_conditional_include_denied(self):
        git(self.repo, "config", "includeIf.gitdir:/tmp/ignored/.path", "/tmp/untrusted.conf")
        with self.assertRaisesRegex(QualificationError, "included config"):
            assert_no_executable_checkout_config(self.repo)

    def test_fsmonitor_exec_denied(self):
        git(self.repo, "config", "core.fsmonitor", "sh -c 'exit 0'")
        with self.assertRaisesRegex(QualificationError, "fsmonitor"):
            assert_no_executable_checkout_config(self.repo)

    def test_hookspath_override_denied(self):
        git(self.repo, "config", "core.hooksPath", "/tmp/myhooks")
        with self.assertRaisesRegex(QualificationError, "hooksPath"):
            assert_no_executable_checkout_config(self.repo)

    def test_disabled_fsmonitor_permitted(self):
        git(self.repo, "config", "core.fsmonitor", "false")
        assert_no_executable_checkout_config(self.repo)

if __name__ == '__main__':
    unittest.main(verbosity=2)

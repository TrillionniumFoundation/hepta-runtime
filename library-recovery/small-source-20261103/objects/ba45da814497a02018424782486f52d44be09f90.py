import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import hepta_local_blocker_runner as module


class HeptaLocalRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.repo = self.base / "source"
        self.repo.mkdir()
        self.git("init", "-q")
        self.git("config", "user.email", "tester@example.invalid")
        self.git("config", "user.name", "Test")
        (self.repo / "hello.txt").write_text("original\n")
        self.git("add", "hello.txt")
        self.git("commit", "-qm", "fixture")

    def git(self, *args):
        subprocess.run(["git", *args], cwd=self.repo, check=True, capture_output=True)

    def test_git_clean_identity_and_source_drift(self):
        original = module.git_info(self.repo)
        self.assertEqual(original["status"], "PASS")
        self.assertTrue(original["clean"])
        self.assertEqual(len(original["head_sha"]), 40)
        self.assertEqual(module.git_info(self.repo, "0" * 40)["reason"], "unexpected_head_sha")
        (self.repo / "hello.txt").write_text("changed\n")
        self.assertEqual(module.git_info(self.repo)["reason"], "dirty_worktree")

    def test_missing_repository_fail_closed(self):
        r = module.git_info(self.base / "absent")
        self.assertEqual(r["reason"], "repository_directory_missing")
        self.assertEqual(r["status"], "BLOCKED")

    def test_executable_search_path_does_not_trust_repository(self):
        trusted, _ = module.trustworthy_path([self.repo])
        self.assertTrue(trusted)
        with patch.dict(os.environ, PATH="/bin::/usr/bin"):
            valid, reason = module.trustworthy_path([self.repo])
        self.assertFalse(valid)
        self.assertEqual(reason, "relative_or_empty_PATH_component")
        with patch.dict(os.environ, PATH=str(self.repo) + ":/usr/bin"):
            valid, reason = module.trustworthy_path([self.repo])
        self.assertFalse(valid)
        self.assertEqual(reason, "untrusted_or_missing_PATH_directory")

    def test_symlink_path_alias_to_source_is_rejected(self):
        alias = self.base / "alias"
        alias.symlink_to(self.repo, target_is_directory=True)
        with patch.dict(os.environ, PATH=str(alias) + ":/usr/bin"):
            valid, reason = module.trustworthy_path([self.repo])
        self.assertFalse(valid)
        self.assertEqual(reason, "untrusted_or_missing_PATH_directory")

    def test_git_fallback_has_no_shell_expansion(self):
        log = self.base / "receipt.log"
        run = module.run_limited(["/bin/sh", "-c", "printf foo"], self.base, 5, log)
        self.assertEqual(run["status"], "PASS")
        self.assertEqual(run["log_bytes"], 3)
        self.assertEqual(run["log_sha256"], module.sha256_file(log))
        fail = module.run_limited(["/does-not-exist/command"], self.base, 5, self.base / "missing.log")
        self.assertEqual(fail["status"], "BLOCKED")

    def test_qual_steps_have_same_runtime_ci_gates(self):
        c = module.commands_for("runtime", True, False)
        self.assertEqual(len(c), 5)
        self.assertEqual([x[0] for x in c],
                         ["rust-format", "rust-check", "rust-clippy", "rust-tests", "rust-release"])
        self.assertEqual(c[2][1][-2:], ["-D", "warnings"])
        self.assertEqual(len(module.commands_for("hepta", False, False)), 4)
        self.assertEqual(len(module.commands_for("hepta", True, True)), 6)

    def test_preflight_report_does_not_mark_missing_tools_passed(self):
        (self.repo / "codex-rs").mkdir()
        report_dir = self.base / "logs"
        report_dir.mkdir()
        with patch.object(module, "tool_versions", return_value={
            "rustc": {"present": False, "version": None},
            "cargo": {"present": False, "version": None},
        }):
            result = module.qualify_project("hepta", self.repo, report_dir, full=False,
                                            include_bazel=False, check_only=True,
                                            expected_sha=None)
        self.assertEqual(result["qualification"], "BLOCKED")
        self.assertEqual(result["reason"], "requires_rustc_1_95_0")

    def test_global_preflight_report_is_explicitly_non_authorizing(self):
        out = self.base / "report"
        status = module.main(["--runtime", str(self.base / "missing"),
                              "--check-only", "--output", str(out)])
        self.assertEqual(status, 2)
        report = json.loads((out / "qualification.json").read_text())
        self.assertEqual(report["summary"], "BLOCKED_OR_UNVERIFIED")
        self.assertIn("NO_PRODUCTION_GO", report["authority"])
        self.assertEqual(report["projects"][0]["reason"], "repository_directory_missing")


if __name__ == "__main__":
    unittest.main()

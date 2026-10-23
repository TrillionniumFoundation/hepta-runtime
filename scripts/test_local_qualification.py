"""Offline regressions for local dual-SHA qualification and log custody."""
from __future__ import annotations

import hashlib
import os
import signal
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from local_qualification import (SHA_RE, blob_hash, check_source_bytes,
                                 assert_no_executable_checkout_config,
                                 execute_bounded, git, qualify, safe_env,
                                 QualificationError)


class LocalQualificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def command(self, *args):
        return subprocess.run(args, cwd=self.root, check=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def make_repo(self) -> str:
        self.command("git", "init", "-q")
        self.command("git", "config", "user.email", "local-test@example.invalid")
        self.command("git", "config", "user.name", "Local Test")
        (self.root / "hello.txt").write_text("stable\n")
        self.command("git", "add", "hello.txt")
        self.command("git", "commit", "-qm", "fixture")
        return self.command("git", "rev-parse", "HEAD").stdout.decode().strip()

    def test_git_blob_digest_matches_exact_byte_payload(self):
        self.assertEqual(blob_hash(b"hello\n", "sha1"),
                         hashlib.sha1(b"blob 6\0hello\n").hexdigest())
        self.assertFalse(SHA_RE.fullmatch("main"))
        self.assertTrue(SHA_RE.fullmatch("a" * 40))

    def test_tracked_bytes_detect_modification(self):
        self.make_repo()
        fmt, count = check_source_bytes(self.root)
        self.assertEqual(fmt, "sha1")
        self.assertEqual(count, 1)
        (self.root / "hello.txt").write_text("edited\n")
        with self.assertRaisesRegex(QualificationError, "source bytes differ"):
            check_source_bytes(self.root)

    def test_hidden_index_modification_is_denied(self):
        self.make_repo()
        self.command("git", "update-index", "--assume-unchanged", "hello.txt")
        with self.assertRaisesRegex(QualificationError, "index contains"):
            check_source_bytes(self.root)

    def test_untracked_source_is_denied(self):
        self.make_repo()
        (self.root / "surprise.rs").write_text("fn main() {}")
        with self.assertRaisesRegex(QualificationError, "untracked"):
            check_source_bytes(self.root)


    def test_checkout_smudge_command_rejected_before_worktree_creation(self):
        self.make_repo()
        (self.root / ".gitattributes").write_text("payload.txt filter=untrusted\n")
        (self.root / "payload.txt").write_text("original\n")
        self.command("git", "add", ".gitattributes", "payload.txt")
        self.command("git", "commit", "-qm", "attributes fixture")
        marker = self.root.parent / (self.root.name + "-smudge-marker")
        self.command("git", "config", "filter.untrusted.smudge",
                     f"sh -c 'touch {marker}; cat'")
        with self.assertRaisesRegex(QualificationError, "checkout filter"):
            assert_no_executable_checkout_config(self.root)
        self.assertFalse(marker.exists(), "Git filter must not execute on preflight")

    def test_qualification_denies_process_filter_before_any_worktree(self):
        source, merge, _ = self.make_diverged_merge_pair()
        self.command("git", "config", "filter.untrusted.process", "sh -c 'exit 0'")
        with tempfile.TemporaryDirectory() as evidence:
            result = qualify(self.root, source, merge, Path(evidence))
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["lanes"], [])
        self.assertIn("checkout filter", result["error"])
        self.assertFalse(result["production_authority"])

    def test_conditional_include_fsmonitor_and_hooks_override_are_denied(self):
        self.make_repo()
        configurations = (
            ("includeIf.gitdir:/tmp/future-linked-worktree/.path", "/tmp/unreviewed.conf", "included/conditional"),
            ("core.fsmonitor", "sh -c 'exit 0'", "fsmonitor"),
            ("core.hooksPath", "/tmp/unreviewed-hooks", "hooksPath"),
        )
        for key, value, message in configurations:
            with self.subTest(key=key):
                self.command("git", "config", key, value)
                with self.assertRaisesRegex(QualificationError, message):
                    assert_no_executable_checkout_config(self.root)
                self.command("git", "config", "--unset", key)

    def test_global_execution_config_is_isolated(self):
        self.make_repo()
        with tempfile.TemporaryDirectory() as temporary:
            (Path(temporary) / ".gitconfig").write_text(
                '[filter "foreign"]\n smudge = sh -c "exit 0"\n'
            )
            with mock.patch.dict(os.environ, {"HOME": temporary}):
                environment = safe_env()
                self.assertEqual(environment["GIT_CONFIG_GLOBAL"], os.devnull)
                self.assertEqual(environment["GIT_CONFIG_NOSYSTEM"], "1")
                assert_no_executable_checkout_config(self.root)

    def test_bounded_capture_and_nonzero_are_distinct(self):
        pass_log = self.root / "pass.log"
        r = execute_bounded((sys.executable, "-c", "print('pass')"),
                            self.root, safe_env(), pass_log, 3, 2048)
        self.assertEqual(r["outcome"], "pass")
        self.assertEqual(r["log_sha256"], hashlib.sha256(pass_log.read_bytes()).hexdigest())
        err = execute_bounded((sys.executable, "-c", "raise SystemExit(7)"),
                              self.root, safe_env(), self.root / "err.log", 3, 2048)
        self.assertEqual(err["outcome"], "nonzero")
        self.assertEqual(err["exit_code"], 7)

    @unittest.skipUnless(os.name == "posix", "POSIX process-group termination required")
    def test_output_budget_and_timeout_fail_closed(self):
        oversize = execute_bounded((sys.executable, "-c", "print('x'*100000)"),
                                   self.root, safe_env(), self.root / "bounded.log", 3, 1024)
        self.assertEqual(oversize["outcome"], "log_limit")
        self.assertLessEqual((self.root / "bounded.log").stat().st_size, 1024)
        timed = execute_bounded((sys.executable, "-c", "import time; time.sleep(30)"),
                                self.root, safe_env(), self.root / "timeout.log", 1, 1024)
        self.assertEqual(timed["outcome"], "timeout")
        self.assertLess(timed["duration_seconds"], 4)

    def make_diverged_merge_pair(self) -> tuple[str, str, str]:
        base = self.make_repo()
        self.command("git", "switch", "-qc", "source")
        (self.root / "source.txt").write_text("new source\n")
        self.command("git", "add", "source.txt")
        self.command("git", "commit", "-qm", "source")
        source = self.command("git", "rev-parse", "HEAD").stdout.decode().strip()
        self.command("git", "switch", "-qc", "base", base)
        (self.root / "base.txt").write_text("new base\n")
        self.command("git", "add", "base.txt")
        self.command("git", "commit", "-qm", "base")
        first_parent = self.command("git", "rev-parse", "HEAD").stdout.decode().strip()
        self.command("git", "merge", "--no-ff", "--no-edit", source)
        merge = self.command("git", "rev-parse", "HEAD").stdout.decode().strip()
        return source, merge, first_parent

    def test_github_merge_requires_exact_second_parent(self):
        from local_qualification import assert_github_merge_parentage
        source, merge, first_parent = self.make_diverged_merge_pair()
        assert_github_merge_parentage(self.root, source, merge)
        for wrong in (first_parent,):
            with self.assertRaisesRegex(QualificationError, "second parent"):
                assert_github_merge_parentage(self.root, wrong, merge)

    def test_linear_commit_cannot_masquerade_as_github_merge(self):
        from local_qualification import assert_github_merge_parentage
        source, _merge, linear = self.make_diverged_merge_pair()
        with self.assertRaisesRegex(QualificationError, "exactly two parents"):
            assert_github_merge_parentage(self.root, source, linear)

    def test_graft_metadata_cannot_forge_second_parent(self):
        from local_qualification import assert_github_merge_parentage
        source, merge, first_parent = self.make_diverged_merge_pair()
        (self.root / ".git" / "info" / "grafts").write_text(
            merge + " " + first_parent + " " + first_parent + "\n"
        )
        # The SHA-addressed commit object still binds its actual source HEAD.
        assert_github_merge_parentage(self.root, source, merge)


    @unittest.skipUnless(os.name == "posix", "POSIX process-group termination required")
    def test_orphan_descendant_retaining_output_pipe_is_killed(self):
        # The immediate command exits zero; its child inherits stdout and
        # holds the capture reader open. Never leave it alive after an error.
        launcher = (
            "import sys, subprocess, pathlib\n"
            "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'], "
            "stdout=sys.stdout, stderr=sys.stderr)\n"
            "pathlib.Path('descendant.pid').write_text(str(child.pid))\n"
        )
        with mock.patch("local_qualification.os.killpg", wraps=os.killpg) as killpg:
            result = execute_bounded(
                (sys.executable, "-c", launcher), self.root, safe_env(),
                self.root / "descendant.log", 5, 1024,
            )
        self.assertEqual(result["outcome"], "io_error", result)
        self.assertTrue(killpg.called, "abandoned process group was not killed")
        self.assertLess(result["duration_seconds"], 9)


    @unittest.skipUnless(os.name == "posix", "POSIX process-group termination required")
    def test_parent_success_with_closed_pipes_cannot_hide_live_descendant(self):
        # The child redirects its streams; stdout reaches EOF and parent exits
        # zero, but the original session group still contains a live child.
        launcher = (
            "import sys, subprocess, pathlib\n"
            "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'], "
            "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
            "pathlib.Path('live-descendant.pid').write_text(str(child.pid))\n"
        )
        with mock.patch("local_qualification.os.killpg", wraps=os.killpg) as killpg:
            result = execute_bounded(
                (sys.executable, "-c", launcher), self.root, safe_env(),
                self.root / "closed-pipes.log", 5, 1024,
            )
        try:
            self.assertEqual(result["outcome"], "io_error", result)
            self.assertEqual(result["exit_code"], 0)
            self.assertTrue(any(
                call.args[1] == signal.SIGKILL for call in killpg.call_args_list
            ), "must terminate an orphaned session group")
        finally:
            # The deliberately vulnerable baseline must not leak a process
            # when this regression demonstrates its previous false-positive.
            pid_file = self.root / "live-descendant.pid"
            if pid_file.exists():
                try:
                    os.kill(int(pid_file.read_text()), signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_distinct_source_and_merge_lanes_run_in_isolated_worktrees(self):
        # Mock binaries validate the verifier's orchestration only; they are
        # NOT evidence that real Rust compilation or tests have passed.
        source, merge, _base = self.make_diverged_merge_pair()
        fakebin = self.root / "fakebin"
        fakebin.mkdir()
        for binary in ("rustc", "cargo"):
            file = fakebin / binary
            file.write_text('#!/bin/sh\necho "' + binary + ' 1.95.0 (mock)"\n')
            file.chmod(0o755)
        with tempfile.TemporaryDirectory() as evidence, \
                mock.patch.dict(os.environ, {"PATH": str(fakebin) + os.pathsep + os.environ["PATH"]}), \
                mock.patch("local_qualification.CHECKS", (("mock", (sys.executable, "-c", "print('mock')")),)):
            result = qualify(self.root, source, merge, Path(evidence))
            self.assertEqual(result["status"], "LOCAL_CHECKS_PASS_NOT_PRODUCTION", result)
            self.assertEqual([entry["sha"] for entry in result["lanes"]], [source, merge])
            self.assertEqual([entry["status"] for entry in result["lanes"]],
                             ["LOCAL_CHECKS_PASS", "LOCAL_CHECKS_PASS"])
            self.assertFalse(result["production_authority"])
            self.assertTrue((Path(evidence) / "qualification.json").exists())

    def test_missing_merge_object_emits_blocked_receipt(self):
        original = self.make_repo()
        result = qualify(self.root, original, "f" * 40, self.root.parent / (self.root.name + "-evidence"))
        self.assertEqual(result["status"], "BLOCKED")
        self.assertFalse(result["production_authority"])
        self.assertIn("git rev-parse failed", result["error"])


    def test_inherited_pythonpath_denied_before_running_git(self):
        self.make_repo()
        with mock.patch.dict(os.environ, {"PYTHONPATH": "untrusted-reference", "PATH": os.environ.get("PATH", "")}, clear=True), \
                mock.patch("local_qualification.subprocess.run") as spawn:
            with self.assertRaisesRegex(QualificationError, "PYTHONPATH") as caught:
                git(self.root, "rev-parse", "HEAD")
            spawn.assert_not_called()
            self.assertNotIn("untrusted-reference", str(caught.exception))

    def test_cargo_loader_compiler_git_and_python_environment_fails_closed(self):
        overrides = (
            "PYTHONPATH", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES",
            "RUSTFLAGS", "RUSTC", "RUSTUP_TOOLCHAIN",
            "CARGO_HOME", "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER",
            "GIT_CONFIG_COUNT", "GIT_OBJECT_DIRECTORY", "BASH_ENV",
            "ENV", "CC", "OPENSSL_DIR", "PKG_CONFIG_PATH", "NODE_OPTIONS",
        )
        for key in overrides:
            with self.subTest(key=key), mock.patch.dict(os.environ, {key: "private-test-marker"}, clear=True):
                with self.assertRaisesRegex(QualificationError, key) as caught:
                    safe_env()
                self.assertNotIn("private-test-marker", str(caught.exception))

    def test_allow_benign_diagnostics_but_pin_execution_identity(self):
        with mock.patch.dict(os.environ, {"PATH": os.environ.get("PATH", ""),
                                          "RUST_BACKTRACE": "1", "RUST_LOG": "info",
                                          "CARGO_TERM_COLOR": "never"}, clear=True):
            env = safe_env()
            self.assertEqual(env["RUST_BACKTRACE"], "1")
            self.assertEqual(env["RUST_LOG"], "info")
            self.assertEqual(env["CARGO_TERM_COLOR"], "never")
            self.assertEqual(env["RUSTUP_TOOLCHAIN"], "1.95.0")
            self.assertEqual(env["GIT_NO_REPLACE_OBJECTS"], "1")

    def test_qualification_emits_blocked_report_without_git_launch(self):
        with tempfile.TemporaryDirectory() as evidence, \
                mock.patch.dict(os.environ, {"PYTHONPATH": "injected-path"}, clear=True), \
                mock.patch("local_qualification.subprocess.run") as spawn:
            result = qualify(self.root, "a" * 40, "b" * 40, Path(evidence))
            spawn.assert_not_called()
            self.assertEqual(result["status"], "BLOCKED")
            self.assertFalse(result["production_authority"])
            self.assertIn("PYTHONPATH", result["error"])
            self.assertNotIn("injected-path", result["error"])
            self.assertTrue((Path(evidence) / "qualification.json").is_file())


if __name__ == "__main__":
    unittest.main()

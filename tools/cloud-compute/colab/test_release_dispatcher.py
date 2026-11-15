"""Offline routing tests. Fixtures contain no credentials and prohibit networking."""
from contextlib import redirect_stdout
from dataclasses import asdict
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hepta_colab as adapter
import release_dispatcher as dispatch


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class ReleaseDispatcherTests(unittest.TestCase):
    def setUp(self):
        self.old_umask = os.umask(0o077)
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-dispatch-test-", dir=Path.home())
        self.root = Path(self.temp.name)
        # A copied test interpreter avoids the untrusted ownership of some
        # container-mounted runtime directories; production checks stay strict.
        self.python = self.root / "fixture-python"
        shutil.copyfile(Path("/usr/bin/python3").resolve(), self.python)
        self.python.chmod(0o700)
        self.config = self.root / ".config" / "hepta-colab"
        self.config.mkdir(parents=True, mode=0o700)
        self.state = self.root / "account-state"
        self.state.mkdir(mode=0o700)
        self.profile_path = self.state / "profile.json"
        self.profile = adapter.Profile(name="fixture", session_name="owned-session",
            state_file=str(self.state / "sessions.json"), endpoint="owned-endpoint",
            kernel_id="owned-kernel", session_id="owned-client",
            expected_account_email="owner@example.invalid")
        self.profile_path.write_text(json.dumps(asdict(self.profile)))
        self.code = self.root / "fixture.py"
        self.code.write_text('print("offline fixture")\n')
        self.marker = self.root / "unexpected-provider-or-network-call"
        self.ledger = adapter.Ledger(self.state / "jobs")
        self.accounts = {"accounts": {"account-a": {
            "email": "owner@example.invalid", "state_dir": str(self.state),
            "profile": str(self.profile_path), "keyring_service": "fixture-keyring",
            "chrome_profile": "fixture-browser"}}}
        self.write_json("accounts.json", self.accounts)
        self.mapping = {"schema": 1, "current": "v5", "releases": {}}
        source = Path(__file__).resolve().parent
        for label in ("v4", "v5"):
            release = self.root / label
            release.mkdir(mode=0o700)
            for name in dispatch.REQUIRED_MODULES:
                shutil.copyfile(source / name, release / name)
            if label == "v4":
                runner = release / "remote_runner.py"
                runner.write_bytes(b"# retained runner fixture\n" + runner.read_bytes())
            sdk = release / "colab_cli"
            sdk.mkdir(mode=0o700)
            (sdk / "__init__.py").write_text("from . import auth\n")
            (sdk / "auth.py").write_text(
                "import socket\nfrom pathlib import Path\n"
                + "MARKER = Path(" + repr(str(self.marker)) + ")\n"
                + "def denied(*args, **kwargs):\n"
                + "    MARKER.write_text('unexpected call')\n"
                + "    raise AssertionError('offline fixture forbids provider/network calls')\n"
                + "socket.socket.connect = denied\nsocket.create_connection = denied\n"
                + "def __getattr__(name):\n    return denied\n")
            python = self.python
            self.mapping["releases"][label] = {
                "directory": str(release), "python": str(python),
                "python_sha256": sha(python), "runner_sha256": sha(release / "remote_runner.py"),
                "files": {p.relative_to(release).as_posix(): sha(p) for p in release.rglob("*.py")}}
        self.write_map()

    def tearDown(self):
        try:
            self.assertFalse(self.marker.exists(), "a fixture attempted provider/network access")
        finally:
            self.temp.cleanup()
            os.umask(self.old_umask)

    def write_json(self, name, value):
        path = self.config / name
        path.write_text(json.dumps(value))
        path.chmod(0o600)

    def write_map(self):
        self.write_json("release-map.json", self.mapping)

    def submit(self, label="v4", key="original-key"):
        with mock.patch.object(adapter, "RUNNER", self.root / label / "remote_runner.py"):
            return self.ledger.submit(self.profile, key, self.code.read_text())

    def args_submit(self, key="original-key"):
        return ["account-a", "run", "submit", "--key", key,
                "--code-file", str(self.code)]

    def plan(self, argv):
        return dispatch.make_plan(argv, home=self.root)

    def run_child(self, plan):
        result = subprocess.run(plan.command, env=plan.environment(), stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, timeout=10, check=False)
        self.assertFalse(self.marker.exists())
        self.assertEqual(result.stderr, "")
        return result.returncode, json.loads(result.stdout)

    def snapshot(self):
        with sqlite3.connect(self.ledger.path.as_uri() + "?mode=ro", uri=True) as db:
            return db.execute("SELECT * FROM jobs").fetchall(), db.execute("SELECT * FROM events").fetchall()

    def refused(self, argv, code):
        with self.assertRaisesRegex(dispatch.DispatchError, "^" + code + "$"):
            self.plan(argv)

    def test_new_key_requires_existing_ledger_and_chooses_current_without_write(self):
        before = sha(self.ledger.path), self.snapshot()
        plan = self.plan(self.args_submit("new-key"))
        self.assertEqual((plan.release, plan.reason), ("v5", "verified_key_absent"))
        self.assertEqual(plan.command[6:], tuple(self.args_submit("new-key")))
        self.assertEqual((sha(self.ledger.path), self.snapshot()), before)

    def test_all_job_verbs_select_original_runner_and_preserve_argv(self):
        job = self.submit()
        before = self.snapshot()
        for verb, extra in (("run", []), ("status", ["--local"]), ("cancel", []),
                            ("read", ["--offset", "4", "--limit", "7"]),
                            ("fetch", ["--artifact", "result.json", "--destination", str(self.root / "out")])):
            with self.subTest(verb=verb):
                argv = ["account-a", "run", verb, "--job-id", job["job_id"], *extra]
                plan = self.plan(argv)
                self.assertEqual((plan.release, plan.reason), ("v4", "original_runner"))
                self.assertEqual(plan.command[6:], tuple(argv))
        self.assertEqual(self.snapshot(), before)

    def test_old_same_key_submit_runs_original_launcher_and_reuses_original_job(self):
        job = self.submit()
        before = self.snapshot()
        plan = self.plan(self.args_submit())
        self.assertEqual(plan.release, "v4")
        for _ in range(2):
            rc, result = self.run_child(plan)
            self.assertEqual(rc, 0)
            self.assertEqual(result["job_id"], job["job_id"])
            self.assertEqual(result["submit_attempts"], 0)
            self.assertEqual(self.snapshot(), before)

    def test_old_key_inspection_keeps_runner_guard_in_fresh_process(self):
        job = self.submit()
        before = self.snapshot()
        plan = self.plan(["account-a", "run", "inspect-key", "--key=original-key"])
        self.assertEqual(plan.release, "v4")
        rc, result = self.run_child(plan)
        self.assertEqual(rc, 0)
        self.assertTrue(result["found"])
        self.assertTrue(result["request"]["runner_matches_current"])
        self.assertEqual(result["request"]["runner_sha256"], job["runner_sha256"])
        self.assertEqual(self.snapshot(), before)

    def test_unknown_ack_same_key_keeps_original_attempt_and_release(self):
        job = self.submit()
        with self.ledger.connection() as db:
            db.execute("UPDATE jobs SET state='unknown',submit_attempts=1")
        before = self.snapshot()
        plan = self.plan(self.args_submit())
        self.assertEqual(plan.release, "v4")
        rc, result = self.run_child(plan)
        self.assertEqual((rc, result["job_id"], result["state"], result["submit_attempts"]),
                         (0, job["job_id"], "unknown", 1))
        self.assertEqual(self.snapshot(), before)

    def test_current_job_uses_current_release(self):
        job = self.submit("v5")
        plan = self.plan(["account-a", "run", "status", "--job-id", job["job_id"], "--local"])
        self.assertEqual(plan.release, "v5")
        rc, result = self.run_child(plan)
        self.assertEqual((rc, result["job_id"], result["state"]), (0, job["job_id"], "queued"))

    def test_new_submission_creates_one_local_current_job_only(self):
        argv = self.args_submit("new-key")
        rc, first = self.run_child(self.plan(argv))
        self.assertEqual(rc, 0)
        stored = self.ledger.get(first["job_id"])
        self.assertEqual(stored["runner_sha256"], self.mapping["releases"]["v5"]["runner_sha256"])
        self.assertEqual(first["submit_attempts"], 0)
        before = self.snapshot()
        rc, second = self.run_child(self.plan(argv))
        self.assertEqual((rc, second["job_id"]), (0, first["job_id"]))
        self.assertEqual(self.snapshot(), before)

    def test_unknown_runner_never_falls_back_to_current(self):
        job = self.submit()
        with self.ledger.connection() as db:
            db.execute("UPDATE jobs SET runner_sha256=?", ("0" * 64,))
        before = self.snapshot()
        for argv in (self.args_submit(), ["account-a", "run", "status", "--job-id", job["job_id"]]):
            self.refused(argv, "DISPATCH_RUNNER_UNKNOWN")
        self.assertEqual(self.snapshot(), before)

    def test_missing_ledger_or_directory_is_not_proof_of_absence(self):
        self.ledger.path.unlink()
        for remove_dir in (False, True):
            if remove_dir:
                shutil.rmtree(self.state / "jobs")
            self.refused(self.args_submit(), "DISPATCH_LEDGER_MISSING")
            self.assertFalse(self.ledger.path.exists())

    def test_corrupt_ledger_is_refused_without_repair(self):
        self.ledger.path.write_bytes(b"not a sqlite ledger")
        before = self.ledger.path.read_bytes()
        self.refused(self.args_submit(), "DISPATCH_LEDGER_INVALID")
        self.assertEqual(self.ledger.path.read_bytes(), before)

    def test_missing_events_table_is_not_a_valid_empty_ledger(self):
        with self.ledger.connection() as db:
            db.execute("DROP TABLE events")
        self.refused(self.args_submit(), "DISPATCH_LEDGER_INVALID")

    def test_malformed_historical_key_cannot_be_mistaken_for_absence(self):
        self.submit()
        with self.ledger.connection() as db:
            db.execute("UPDATE jobs SET idempotency_key=?", (b"original-key",))
        before = self.snapshot()
        self.refused(self.args_submit(), "DISPATCH_LEDGER_INVALID")
        self.assertEqual(self.snapshot(), before)

    def test_ambiguous_ledger_identity_is_refused(self):
        self.submit()
        with self.ledger.connection() as db:
            db.execute("CREATE TABLE unindexed AS SELECT * FROM jobs")
            db.execute("INSERT INTO unindexed SELECT * FROM jobs")
            db.execute("DROP TABLE jobs")
            db.execute("ALTER TABLE unindexed RENAME TO jobs")
        self.refused(self.args_submit(), "DISPATCH_LEDGER_AMBIGUOUS")

    def test_unknown_job_id_refuses_but_verified_absent_key_can_be_inspected(self):
        self.refused(["account-a", "run", "status", "--job-id", "missing"], "DISPATCH_JOB_NOT_FOUND")
        plan = self.plan(["account-a", "run", "inspect-key", "--key", "missing"])
        rc, result = self.run_child(plan)
        self.assertEqual((rc, result["found"], result["absence_verified"]), (0, False, True))

    def test_original_launcher_still_rejects_different_profile_before_provider(self):
        job = self.submit()
        before = self.snapshot()
        self.profile_path.write_text(json.dumps(asdict(self.profile) | {"kernel_id": "foreign-kernel"}))
        for argv in (["account-a", "run", "run", "--job-id", job["job_id"]],
                     ["account-a", "run", "status", "--job-id", job["job_id"], "--local"],
                     ["account-a", "run", "inspect-key", "--key", "original-key"]):
            plan = self.plan(argv)
            self.assertEqual(plan.release, "v4")
            rc, result = self.run_child(plan)
            self.assertEqual((rc, result["code"]), (2, "profile_identity_changed"))
            self.assertEqual(self.snapshot(), before)

    def test_fixed_account_state_and_profile_cannot_be_overridden(self):
        for flag in ("--profile", "--prof", "--state-dir", "--state", "--jobs-state-dir",
                     "--expected-email", "--expected", "--quota-project", "--name"):
            with self.subTest(flag=flag):
                self.refused(["account-a", "run", "status", flag, str(self.root)],
                             "ACCOUNT_IDENTITY_OVERRIDE_DENIED")

    def test_duplicate_or_mixed_cli_identities_are_refused(self):
        for argv in (self.args_submit() + ["--key=another"],
                     ["account-a", "run", "status", "--job-id", "a", "--job-id=b"],
                     ["account-a", "--provision-key=a", "--provision-key=b", "run", "--help"]):
            self.refused(argv, "DISPATCH_IDENTITY_AMBIGUOUS")
        for argv in (self.args_submit() + ["--job-id", "another"],
                     ["account-a", "run", "status", "--release", "v4"]):
            self.refused(argv, "DISPATCH_ARGUMENTS_INVALID")
        self.refused(["account-a", "run", "status", "--job", "a"],
                     "ACCOUNT_IDENTITY_OVERRIDE_DENIED")

    def test_duplicate_json_keys_are_refused(self):
        (self.config / "accounts.json").write_text('{"accounts":{},"accounts":{}}')
        self.refused(self.args_submit(), "DISPATCH_CONFIG_AMBIGUOUS")

    def test_two_aliases_cannot_share_a_jobs_root(self):
        self.accounts["accounts"]["account-b"] = dict(self.accounts["accounts"]["account-a"])
        self.write_json("accounts.json", self.accounts)
        self.refused(self.args_submit(), "DISPATCH_ACCOUNT_STATE_AMBIGUOUS")

    def test_selected_release_checks_every_required_module(self):
        self.submit()
        for name in dispatch.REQUIRED_MODULES:
            with self.subTest(module=name):
                path = self.root / "v4" / name
                original = path.read_bytes()
                path.write_bytes(original + b"\n# altered\n")
                self.refused(self.args_submit(), "DISPATCH_RELEASE_HASH_MISMATCH")
                path.write_bytes(original)

    def test_unselected_current_corruption_does_not_replace_a_known_old_runner(self):
        self.submit()
        (self.root / "v5" / "remote_runner.py").write_text("invalid new release")
        self.assertEqual(self.plan(self.args_submit()).release, "v4")

    def test_unmanifested_source_or_sourceless_code_is_refused(self):
        for name in ("extra.py", "authorize_colab.pyc", "shadow.so"):
            path = self.root / "v5" / name
            path.write_bytes(b"untrusted")
            self.refused(self.args_submit(), "DISPATCH_RELEASE_UNMANIFESTED_CODE")
            path.unlink()

    def test_release_map_requires_complete_unambiguous_runner_mapping(self):
        original = json.loads(json.dumps(self.mapping))
        del self.mapping["releases"]["v4"]["files"]["authorize_colab.py"]
        self.write_map()
        self.refused(self.args_submit(), "DISPATCH_RELEASE_MAP_INVALID")
        self.mapping = original
        self.mapping["releases"]["v4"]["runner_sha256"] = self.mapping["releases"]["v5"]["runner_sha256"]
        self.mapping["releases"]["v4"]["files"]["remote_runner.py"] = self.mapping["releases"]["v5"]["runner_sha256"]
        self.write_map()
        self.refused(self.args_submit(), "DISPATCH_RELEASE_MAP_AMBIGUOUS")

    def test_unsafe_config_and_ledger_permissions_are_refused(self):
        config = self.config / "accounts.json"
        config.chmod(0o644)
        self.refused(self.args_submit(), "DISPATCH_FILE_UNSAFE")
        config.chmod(0o600)
        self.ledger.path.chmod(0o644)
        self.refused(self.args_submit(), "DISPATCH_FILE_UNSAFE")

    def test_ledger_auxiliary_symlink_is_refused(self):
        target = self.root / "foreign"
        target.write_text("fixture")
        auxiliary = Path(str(self.ledger.path) + "-wal")
        auxiliary.symlink_to(target)
        self.refused(self.args_submit(), "DISPATCH_FILE_UNSAFE")
        self.assertEqual(target.read_text(), "fixture")

    def test_symlinked_release_or_module_is_refused(self):
        release = self.mapping["releases"]["v5"]
        alias = self.root / "release-link"
        alias.symlink_to(self.root / "v5", target_is_directory=True)
        release["directory"] = str(alias)
        self.write_map()
        with self.assertRaises(OSError):
            self.plan(self.args_submit())
        release["directory"] = str(self.root / "v5")
        self.write_map()
        path = self.root / "v5" / "remote_runner.py"
        original = path.read_bytes()
        target = self.root / "runner-copy"
        target.write_bytes(original)
        path.unlink()
        path.symlink_to(target)
        with self.assertRaises(OSError):
            self.plan(self.args_submit())

    def test_interpreter_symlink_chain_keeps_venv_argv(self):
        target = self.mapping["releases"]["v5"]["python"]
        (self.root / "python-real-link").symlink_to(target)
        link = self.root / "venv-python"
        link.symlink_to("python-real-link")
        self.mapping["releases"]["v5"]["python"] = str(link)
        self.write_map()
        self.assertEqual(self.plan(self.args_submit()).command[0], str(link))

    def test_interpreter_intermediate_untrusted_directory_is_refused(self):
        unsafe = self.root / "unsafe"
        unsafe.mkdir(mode=0o777)
        unsafe.chmod(0o777)
        (unsafe / "python").symlink_to(self.mapping["releases"]["v5"]["python"])
        link = self.root / "venv-python"
        link.symlink_to(unsafe / "python")
        self.mapping["releases"]["v5"]["python"] = str(link)
        self.write_map()
        self.refused(self.args_submit(), "DISPATCH_PATH_UNSAFE")

    def test_manage_authorize_and_help_use_current_without_a_ledger(self):
        shutil.rmtree(self.state / "jobs")
        for argv in (["account-a", "manage", "readiness"], ["account-a", "authorize"],
                     ["account-a", "run", "--help"], ["account-a", "run", "submit", "--help"]):
            plan = self.plan(argv)
            self.assertEqual((plan.release, plan.reason), ("v5", "current_non_job_command"))
            self.assertFalse(self.ledger.path.exists())

    def test_global_help_needs_no_private_configuration(self):
        shutil.rmtree(self.config)
        with redirect_stdout(io.StringIO()) as output, self.assertRaises(SystemExit) as caught:
            self.plan(["--help"])
        self.assertEqual(caught.exception.code, 0)
        self.assertIn("account", output.getvalue())

    def test_environment_cannot_redirect_home_or_python_imports(self):
        with mock.patch.object(dispatch.pwd, "getpwuid", return_value=SimpleNamespace(pw_dir=str(self.root))), \
             mock.patch.dict(os.environ, {"HOME": "/untrusted", "PYTHONPATH": "/untrusted", "LD_PRELOAD": "/untrusted"}):
            plan = dispatch.make_plan(self.args_submit())
            self.assertEqual(plan.home, str(self.root))
            self.assertEqual(plan.environment()["HOME"], str(self.root))
            self.assertNotIn("PYTHONPATH", plan.environment())
            self.assertNotIn("LD_PRELOAD", plan.environment())
            self.assertIn("-I", plan.command)

    def test_existing_bytecode_cannot_bypass_pinned_module_source(self):
        job = self.submit()
        module = self.root / "v4" / "hepta_colab.py"
        original = module.read_bytes()
        poison = b"raise RuntimeError('stale bytecode executed')\n"
        module.write_bytes(poison + b"#" * (len(original) - len(poison)))
        timestamp = module.stat().st_mtime_ns
        subprocess.run([str(self.python), "-I", "-c",
                        "import py_compile,sys; py_compile.compile(sys.argv[1],doraise=True)", str(module)],
                       capture_output=True, check=True, timeout=10)
        module.write_bytes(original)
        os.utime(module, ns=(timestamp, timestamp))
        # Establish that this cache really would override the verified source.
        control = subprocess.run([str(self.python), "-I", "-B", "-c",
                                  "import sys; sys.path.insert(0,sys.argv[1]); import hepta_colab",
                                  str(module.parent)], capture_output=True, text=True, timeout=10)
        self.assertNotEqual(control.returncode, 0)
        self.assertIn("stale bytecode executed", control.stderr)
        plan = self.plan(["account-a", "run", "status", "--job-id", job["job_id"], "--local"])
        rc, result = self.run_child(plan)
        self.assertEqual((rc, result["job_id"]), (0, job["job_id"]))

    def test_committed_wal_row_cannot_be_mistaken_for_an_absent_key(self):
        db = sqlite3.connect(self.ledger.path)
        try:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA wal_autocheckpoint=0")
            self.submit()
            self.assertTrue(Path(str(self.ledger.path) + "-wal").exists())
            with sqlite3.connect(self.ledger.path.as_uri() + "?immutable=1", uri=True) as stale:
                self.assertEqual(stale.execute("SELECT count(*) FROM jobs").fetchone()[0], 0)
            self.assertEqual(self.plan(self.args_submit()).release, "v4")
        finally:
            db.close()

    def test_old_submission_arriving_after_absence_lookup_is_not_replayed(self):
        plan = self.plan(self.args_submit())
        self.assertEqual(plan.release, "v5")
        old_job = self.submit()
        before = self.snapshot()
        rc, result = self.run_child(plan)
        self.assertEqual((rc, result["code"]), (2, "idempotency_payload_mismatch"))
        self.assertEqual(self.snapshot(), before)
        rc, result = self.run_child(self.plan(self.args_submit()))
        self.assertEqual((rc, result["job_id"]), (0, old_job["job_id"]))

    def test_scoped_provision_key_is_forwarded_unchanged(self):
        self.submit()
        argv = ["account-a", "--provision-key", "original-provision", *self.args_submit()[1:]]
        plan = self.plan(argv)
        self.assertEqual(plan.release, "v4")
        self.assertEqual(plan.command[6:], tuple(argv))


if __name__ == "__main__":
    unittest.main()

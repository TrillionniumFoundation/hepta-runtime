import contextlib
from dataclasses import asdict
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import account_launcher as launcher
import manage_colab as manage
from hepta_colab import Profile


class ScopedProfileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-colab-scope-test-", dir=Path.home())
        self.root = Path(self.temp.name)
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
        self.entry = {"state_dir": str(self.state), "email": "owner@example.invalid",
                      "profile": str(self.root / "legacy.json"), "keyring_service": "fixture"}
        self.journal = manage.Journal(self.state / "bootstrap")
        self.key = "job-20261109-01"
        self.record = {"schema": 1, "key": self.key, "account_email": self.entry["email"],
                       "phase": "runtime_ready", "runtime_submit_attempts": 1,
                       "kernel_submit_attempts": 0, "endpoint": "owned-endpoint",
                       "client_session_id": "owned-client", "session_name": "owned-session",
                       "requested_spec": {"variant": "GPU", "accelerator": "T4", "shape": "STANDARD"}}
        self.journal.save(dict(self.record))

    def tearDown(self):
        self.temp.cleanup()

    def bind_path(self, key=None, extra=None):
        key = key or self.key
        return launcher.scoped_profile(self.entry, "account-a", key, "manage",
                                       extra or ["bind", "--key", key])

    def make_bound(self):
        path, name = self.bind_path()
        record = self.journal.load(self.key)
        profile = Profile(name=name, session_name=record["session_name"],
                          state_file=str(self.journal.state_file), endpoint=record["endpoint"],
                          kernel_id="owned-kernel", session_id=record["client_session_id"],
                          expected_account_email=self.entry["email"])
        manage.private_write(Path(path), asdict(profile), no_clobber=True)
        record.update(phase="bound", profile_path=path, profile_hash=profile.fingerprint,
                      kernel_id=profile.kernel_id, kernel_submit_attempts=1)
        self.journal.save(record)
        return path, profile

    def test_profile_is_deterministic_private_and_account_scoped(self):
        path, name = self.bind_path()
        self.assertEqual(path, str(self.state / "profiles" / (hashlib.sha256(self.key.encode()).hexdigest() + ".json")))
        self.assertEqual((Path(path).parent.stat().st_mode & 0o777), 0o700)
        self.assertEqual((path, name), self.bind_path())
        self.assertFalse(Path(path).exists())
        self.assertFalse(Path(self.entry["profile"]).exists())

    def test_all_execution_verbs_keep_bound_identity(self):
        path, _ = self.make_bound()
        for command in ("submit", "run", "status", "cancel", "read", "fetch"):
            self.assertEqual(launcher.scoped_profile(self.entry, "account-a", self.key, "run",
                                                    [command, "--job-id", "fixture"])[0], path)

    def test_released_runtime_keeps_original_profile_for_retained_artifacts(self):
        path, _ = self.make_bound()
        record = self.journal.load(self.key)
        record["phase"] = "released"
        self.journal.save(record)
        for command in ("status", "read", "fetch"):
            self.assertEqual(launcher.scoped_profile(self.entry, "account-a", self.key, "run",
                                                    [command, "--job-id", "fixture"])[0], path)

    def test_missing_mismatched_and_duplicate_key_rejected(self):
        for extra in (["bind"], ["bind", "--key", "other"],
                      ["bind", "--key", self.key, "--key", self.key]):
            with self.assertRaisesRegex(launcher.ScopedProfileError, "PROVISION_KEY_MISMATCH"):
                self.bind_path(extra=extra)
        for key in ("../foreign", "", "a"*65, "/tmp/profile", "space key"):
            with self.assertRaises(launcher.ScopedProfileError):
                launcher.scoped_profile(self.entry, "account-a", key, "manage", ["bind", "--key", key])
        with self.assertRaisesRegex(launcher.ScopedProfileError, "PROVISIONING_REQUEST_NOT_FOUND"):
            self.bind_path(key="new-key-no-record")

    def test_cross_account_and_legacy_path_cannot_be_adopted(self):
        foreign = dict(self.entry, email="foreign@example.invalid")
        with self.assertRaisesRegex(launcher.ScopedProfileError, "AUTH_ACCOUNT_MISMATCH"):
            launcher.scoped_profile(foreign, "account-b", self.key, "manage", ["bind", "--key", self.key])
        record = self.journal.load(self.key)
        record["profile_path"] = self.entry["profile"]
        self.journal.save(record)
        with self.assertRaisesRegex(launcher.ScopedProfileError, "PROFILE_PATH_CONFLICT"):
            self.bind_path()

    def test_profile_content_change_and_unbound_execution_rejected(self):
        with self.assertRaisesRegex(launcher.ScopedProfileError, "PROVISION_PROFILE_NOT_BOUND"):
            launcher.scoped_profile(self.entry, "account-a", self.key, "run", ["submit"])
        path, profile = self.make_bound()
        tampered = asdict(profile) | {"kernel_id": "different-kernel"}
        manage.private_write(Path(path), tampered)
        with self.assertRaisesRegex(launcher.ScopedProfileError, "PROVISION_PROFILE_IDENTITY_MISMATCH"):
            launcher.scoped_profile(self.entry, "account-a", self.key, "run", ["submit"])

    def test_profile_directory_symlink_rejected(self):
        other = self.root / "other"
        other.mkdir(mode=0o700)
        (self.state / "profiles").symlink_to(other, target_is_directory=True)
        with self.assertRaises(Exception):
            self.bind_path()

    def test_flag_does_not_adopt_session_or_authorize(self):
        for action, extra in (("run", ["bind"]), ("authorize", []),
                              ("manage", ["create", "--key", self.key])):
            with self.assertRaisesRegex(launcher.ScopedProfileError, "PROVISION_KEY_REQUIRES_BIND_OR_RUN"):
                launcher.scoped_profile(self.entry, "account-a", self.key, action, extra)

    def run_wrapper(self, argv):
        config = self.root / "accounts.json"
        config.write_text(json.dumps({"accounts": {"account-a": self.entry}}))
        forwarded = []
        with mock.patch.object(launcher, "CONFIG", config), \
             mock.patch.object(launcher, "configure", return_value=self.entry), \
             mock.patch.object(launcher.runpy, "run_path", side_effect=lambda *a, **kw: forwarded.append(list(sys.argv))), \
             mock.patch.object(sys, "argv", ["hepta-colab-account", *argv]), \
             contextlib.redirect_stdout(io.StringIO()) as out:
            code = launcher.main()
        return code, forwarded, out.getvalue()

    def test_legacy_calls_preserve_fixed_profile_and_scoped_calls_forward(self):
        code, args, out = self.run_wrapper(["account-a", "run", "status", "--job-id", "old-job", "--local"])
        self.assertEqual(code, 0)
        self.assertEqual(args[0][1:5], ["--state-dir", str(self.state/"jobs"),
                                      "--profile", self.entry["profile"]])
        path, _ = self.make_bound()
        code, args, out = self.run_wrapper(["account-a", "--provision-key", self.key,
                                           "run", "status", "--job-id", "new-job"])
        self.assertEqual(code, 0)
        self.assertEqual(args[0][4], path)
        self.assertNotIn("--provision-key", args[0])

    def test_identity_override_full_and_abbreviated_options_blocked(self):
        for flag in ("--profile", "--prof", "--state-dir", "--state", "--expected-email",
                     "--expected", "--jobs-state-dir", "--jobs", "--quota-project", "--quota", "--name"):
            code, forwarded, out = self.run_wrapper(["account-a", "run", "status", flag, "/unsafe"])
            self.assertEqual(code, 2, flag)
            self.assertEqual(forwarded, [], flag)
            self.assertEqual(json.loads(out)["error_code"], "ACCOUNT_IDENTITY_OVERRIDE_DENIED")

    def test_readiness_reports_unknown_without_rewriting_or_cloud_mutation(self):
        class Backend:
            account = {"account_email": "owner@example.invalid"}
            def __getattr__(self, name):
                raise AssertionError("Unexpected cloud call: " + name)
        manager = manage.Manager(self.journal, Backend())
        self.assertTrue(manager.readiness()["can_create"])
        for phase in ("admitted", "allocation_unknown", "release_unknown"):
            record = self.journal.load(self.key)
            record.update(phase=phase, error_code="ORIGINAL_UNCERTAINTY")
            self.journal.save(record)
            before = self.journal.path(self.key).read_bytes()
            result = manager.readiness()
            self.assertFalse(result["can_create"])
            self.assertTrue(result["authorized"])
            self.assertTrue(result["job_profile_supported"])
            self.assertEqual(result["allocation_blockers"], [{"key": self.key, "phase": phase,
                                                               "error_code": "ORIGINAL_UNCERTAINTY"}])
            self.assertEqual(before, self.journal.path(self.key).read_bytes())

    def test_readiness_rejects_foreign_history(self):
        class Backend:
            account = {"account_email": "different@example.invalid"}
        with self.assertRaises(manage.BootstrapError):
            manage.Manager(self.journal, Backend()).readiness()

    def test_explicit_refusal_is_terminal_but_transport_uncertainty_is_not(self):
        class Backend:
            account = {"account_email": "owner@example.invalid"}
            calls = 0
            failure = manage.AllocationRefused("ALLOCATION_REFUSED_PRECONDITION")
            def inventory(self):
                return {"assignments": {"status": "available", "runtimes": []},
                        "eligibility": {"status": "available", "runtime_specs": [
                            {"variant": "GPU", "accelerator": "T4", "shape": "STANDARD", "eligible": True}]}}
            def assign(self, notebook_hash, spec):
                self.calls += 1
                raise self.failure
            def reconcile_assignment(self, notebook_hash, spec):
                return None
        backend = Backend()
        manager = manage.Manager(self.journal, backend)
        refused = manager.create("definite-refusal", "gpu", "T4", "standard")
        self.assertEqual(refused["phase"], "allocation_refused")
        self.assertEqual(refused["refusal_http_status"], 412)
        self.assertFalse(refused["owned_runtime"])
        self.assertTrue(manager.readiness()["can_create"])
        self.assertEqual(manager.create("definite-refusal", "gpu", "T4", "standard"), refused)
        self.assertEqual(backend.calls, 1)
        backend.failure = TimeoutError("transport uncertainty")
        uncertain = manager.create("transport-uncertain", "gpu", "T4", "standard")
        self.assertEqual(uncertain["phase"], "allocation_unknown")
        self.assertNotIn("refusal_http_status", uncertain)
        self.assertFalse(manager.readiness()["can_create"])
        self.assertEqual(manager.reconcile("transport-uncertain")["phase"], "allocation_unknown")
        self.assertEqual(backend.calls, 2)


if __name__ == "__main__":
    unittest.main()


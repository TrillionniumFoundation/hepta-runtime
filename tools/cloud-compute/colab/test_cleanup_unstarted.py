import hashlib
import sqlite3
from types import SimpleNamespace
import unittest

import account_launcher as launcher
import manage_colab as manage
from hepta_colab import Engine, Ledger, Profile, Conflict, inspect_submission_key
import test_scoped_profiles as scoped_tests


class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.f = scoped_tests.ScopedProfileTests(methodName="runTest")
        self.f.setUp()
        record = self.f.journal.load(self.f.key)
        record.update(owned_runtime=True, owned_kernel=False)
        self.f.journal.save(record)
        self.jobs = self.f.state / "jobs"
        outer = self

        class Backend:
            account = {"account_email": "owner@example.invalid"}
            present = True
            releases = 0
            kernels = []
            fail_release = False
            lock_held_during_release = False

            def assignments(self):
                return [SimpleNamespace(endpoint="owned-endpoint", variant="GPU",
                                        accelerator="T4", machine_shape="STANDARD")] if self.present else []

            def jupyter(self, assignment, method, route):
                assert method == "GET" and route == "/api/kernels"
                return self.kernels

            def unassign(self, endpoint):
                assert endpoint == "owned-endpoint"
                probe = sqlite3.connect(outer.jobs / "jobs.sqlite3", timeout=0, isolation_level=None)
                try:
                    try:
                        probe.execute("BEGIN IMMEDIATE")
                    except sqlite3.OperationalError as exc:
                        self.lock_held_during_release = "locked" in str(exc)
                    else:
                        probe.rollback()
                finally:
                    probe.close()
                self.releases += 1
                if self.fail_release:
                    raise TimeoutError("uncertain response")
                self.present = False

        self.backend = Backend()
        self.manager = manage.Manager(self.f.journal, self.backend)

    def tearDown(self):
        self.f.tearDown()

    def bind(self, make_ledger=True):
        path, profile = self.f.make_bound()
        record = self.f.journal.load(self.f.key)
        record.update(owned_runtime=True, owned_kernel=True, jobs_state_dir=str(self.jobs))
        self.f.journal.save(record)
        self.backend.kernels = [{"id": profile.kernel_id, "execution_state": "idle"}]
        ledger = Ledger(self.jobs) if make_ledger else None
        return profile, ledger

    def test_inspect_key_distinguishes_missing_ledger_and_missing_job(self):
        profile, _ = self.bind(make_ledger=False)
        result = inspect_submission_key(profile, self.jobs, "never-submitted")
        self.assertFalse(result["found"])
        self.assertFalse(result["ledger_present"])
        self.assertFalse(result["absence_verified"])
        self.assertFalse(self.jobs.exists())
        Ledger(self.jobs)
        result = inspect_submission_key(profile, self.jobs, "never-submitted")
        self.assertFalse(result["found"])
        self.assertTrue(result["ledger_present"])
        self.assertTrue(result["absence_verified"])
        self.assertEqual(result["idempotency_key"], "never-submitted")

    def test_inspect_key_returns_original_intent_without_mutating_job(self):
        profile, ledger = self.bind()
        source = "print('small fixture')\n"
        job = ledger.submit(profile, "submit-one", source, ["b.json", "a.json"], 120)
        before = ledger.get(job["job_id"])
        result = inspect_submission_key(profile, self.jobs, "submit-one")
        self.assertTrue(result["found"])
        self.assertEqual(result["idempotency_key"], "submit-one")
        self.assertEqual(result["job"]["job_id"], job["job_id"])
        self.assertEqual(result["job"]["submit_attempts"], 0)
        self.assertEqual(result["request"], {"code_sha256": hashlib.sha256(source.encode()).hexdigest(),
            "wall_seconds": 120, "artifacts": ["a.json", "b.json"],
            "runner_sha256": job["runner_sha256"], "runner_matches_current": True})
        self.assertEqual(before, ledger.get(job["job_id"]))

    def test_inspect_key_rejects_same_key_under_different_profile(self):
        profile, ledger = self.bind()
        ledger.submit(profile, "submit-one", "pass", [], 120)
        other = Profile(**(profile.__dict__ | {"kernel_id": "another-kernel"}))
        with self.assertRaises(Conflict):
            inspect_submission_key(other, self.jobs, "submit-one")

    def test_inspect_missing_schema_is_error_not_absence(self):
        profile, _ = self.bind()
        db = sqlite3.connect(self.jobs / "jobs.sqlite3")
        db.execute("DROP TABLE jobs")
        db.close()
        with self.assertRaises(sqlite3.OperationalError):
            inspect_submission_key(profile, self.jobs, "submit-one")

    def test_close_never_bound_owned_runtime_with_empty_kernel_inventory(self):
        result = self.manager.close_unstarted(self.f.key)
        self.assertEqual(result["phase"], "released")
        self.assertTrue(result["never_dispatched"])
        self.assertEqual(result["cleanup_reason"], "unstarted_compute")
        self.assertTrue(result["cleanup_evidence"]["never_bound"])
        self.assertEqual(result["cleanup_evidence"]["matching_jobs"], 0)
        self.assertTrue(self.backend.lock_held_during_release)
        self.assertEqual(self.backend.releases, 1)
        again = self.manager.close_unstarted(self.f.key)
        self.assertEqual(again["phase"], "released")
        self.assertTrue(again["never_dispatched"])
        self.assertEqual(self.backend.releases, 1)

    def test_bound_runtime_requires_original_ledger(self):
        self.bind(make_ledger=False)
        with self.assertRaises(manage.BootstrapError) as caught:
            self.manager.close_unstarted(self.f.key)
        self.assertEqual(caught.exception.code, "CLOSE_UNSTARTED_LEDGER_EVIDENCE_MISSING")
        self.assertEqual(self.backend.releases, 0)

    def test_bound_without_job_can_close_and_record_evidence(self):
        self.bind()
        result = self.manager.close_unstarted(self.f.key)
        self.assertEqual(result["phase"], "released")
        self.assertFalse(result["cleanup_evidence"]["never_bound"])
        self.assertTrue(result["never_dispatched"])

    def test_queued_job_blocks_until_original_local_cancellation(self):
        profile, ledger = self.bind()
        job = ledger.submit(profile, "submit-one", "pass", [], 120)
        with self.assertRaises(manage.BootstrapError) as caught:
            self.manager.close_unstarted(self.f.key)
        self.assertEqual(caught.exception.code, "RELEASE_BLOCKED_BY_ACTIVE_OR_UNKNOWN_JOB")
        self.assertEqual(self.backend.releases, 0)
        cancelled = Engine(profile, ledger).cancel(job["job_id"])
        self.assertTrue(cancelled["local_only_cancel"])
        proof = inspect_submission_key(profile, self.jobs, "submit-one")
        self.assertTrue(proof["job"]["local_only_cancel"])
        result = self.manager.close_unstarted(self.f.key)
        self.assertEqual(result["phase"], "released")
        self.assertEqual(result["cleanup_evidence"]["locally_cancelled_jobs"], 1)
        self.assertTrue(self.backend.lock_held_during_release)

    def test_dispatched_terminal_job_is_not_unstarted(self):
        profile, ledger = self.bind()
        job = ledger.submit(profile, "submit-one", "pass", [], 120)
        self.assertTrue(ledger.claim(job["job_id"]))
        with ledger.connection() as db:
            db.execute("UPDATE jobs SET state='succeeded' WHERE job_id=?", (job["job_id"],))
        with self.assertRaises(manage.BootstrapError) as caught:
            self.manager.close_unstarted(self.f.key)
        self.assertEqual(caught.exception.code, "CLOSE_UNSTARTED_JOB_MAY_HAVE_DISPATCHED")
        self.assertEqual(self.backend.releases, 0)

    def test_foreign_busy_and_unknown_kernels_still_block(self):
        profile, _ = self.bind()
        for kernels in ([{"id": "foreign-kernel", "execution_state": "idle"}],
                        [{"id": profile.kernel_id, "execution_state": "busy"}]):
            self.backend.kernels = kernels
            with self.assertRaises(manage.BootstrapError) as caught:
                self.manager.close_unstarted(self.f.key)
            self.assertEqual(caught.exception.code, "RELEASE_BLOCKED_BY_FOREIGN_OR_BUSY_KERNEL")
        record = self.f.journal.load(self.f.key)
        record["phase"] = "kernel_unknown"
        self.f.journal.save(record)
        with self.assertRaises(manage.BootstrapError) as caught:
            self.manager.close_unstarted(self.f.key)
        self.assertEqual(caught.exception.code, "CLOSE_UNSTARTED_REQUIRES_CONFIRMED_RUNTIME_AND_KERNEL")
        self.assertEqual(self.backend.releases, 0)

    def test_foreign_runtime_or_wrong_jobs_scope_still_block(self):
        record = self.f.journal.load(self.f.key)
        record["owned_runtime"] = False
        self.f.journal.save(record)
        with self.assertRaises(manage.BootstrapError) as caught:
            self.manager.close_unstarted(self.f.key)
        self.assertEqual(caught.exception.code, "RELEASE_REQUIRES_TASK_OWNED_RUNTIME")
        record["owned_runtime"] = True
        record["jobs_state_dir"] = str(self.f.root / "other-jobs")
        self.f.journal.save(record)
        with self.assertRaises(manage.BootstrapError) as caught:
            self.manager.close_unstarted(self.f.key)
        self.assertEqual(caught.exception.code, "RELEASE_REQUIRES_FIXED_JOBS_STATE_DIRECTORY")
        self.assertEqual(self.backend.releases, 0)

    def test_uncertain_release_reconciles_without_resubmit_and_preserves_proof(self):
        self.bind()
        self.backend.fail_release = True
        result = self.manager.close_unstarted(self.f.key)
        self.assertEqual(result["phase"], "release_unknown")
        self.assertTrue(result["never_dispatched"])
        second = self.manager.close_unstarted(self.f.key)
        self.assertEqual(second["phase"], "release_unknown")
        self.assertEqual(self.backend.releases, 1)
        self.backend.present = False
        third = self.manager.reconcile(self.f.key)
        self.assertEqual(third["phase"], "released")
        self.assertTrue(third["never_dispatched"])
        self.assertEqual(third["cleanup_reason"], "unstarted_compute")
        self.assertEqual(self.backend.releases, 1)

    def test_released_profile_blocks_new_submit_and_run_but_retains_reads(self):
        self.bind()
        self.manager.close_unstarted(self.f.key)
        for action in ("submit", "run"):
            with self.assertRaisesRegex(launcher.ScopedProfileError, "PROVISION_RUNTIME_NOT_BOUND"):
                launcher.scoped_profile(self.f.entry, "account-a", self.f.key, "run", [action])
        for action in ("status", "read", "fetch", "inspect-key"):
            launcher.scoped_profile(self.f.entry, "account-a", self.f.key, "run", [action])

    def test_normal_release_still_requires_original_bound_jobs_scope(self):
        with self.assertRaises(manage.BootstrapError) as caught:
            self.manager.release(self.f.key, self.jobs)
        self.assertEqual(caught.exception.code, "RELEASE_REQUIRES_FIXED_JOBS_STATE_DIRECTORY")
        self.assertEqual(self.backend.releases, 0)

    def test_inspect_key_rejects_changed_runner(self):
        profile, ledger = self.bind()
        job = ledger.submit(profile, "submit-one", "pass", [], 120)
        with ledger.connection() as db:
            db.execute("UPDATE jobs SET runner_sha256=? WHERE job_id=?", ("0"*64, job["job_id"]))
        with self.assertRaisesRegex(Conflict, "runner_changed_after_submission"):
            inspect_submission_key(profile, self.jobs, "submit-one")


if __name__ == "__main__":
    unittest.main()



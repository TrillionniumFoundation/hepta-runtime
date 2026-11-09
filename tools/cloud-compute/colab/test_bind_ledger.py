import sqlite3
import unittest
from unittest import mock

import manage_colab as manage
import test_cleanup_unstarted as cleanup_tests


class BindLedgerTests(unittest.TestCase):
    def setUp(self):
        self.c = cleanup_tests.CleanupTests(methodName="runTest")
        self.c.setUp()
        record = self.c.f.journal.load(self.c.f.key)
        record["kernel_path"] = "hepta_fixture.ipynb"
        self.c.f.journal.save(record)
        self.sessions = []
        self.posts = 0

        def jupyter(assignment, method, route, body=None):
            if method == "GET" and route == "/api/kernels":
                return self.c.backend.kernels
            if method == "GET" and route == "/api/sessions":
                return self.sessions
            if method == "POST" and route == "/api/sessions":
                self.assertTrue((self.c.jobs / "jobs.sqlite3").is_file())
                with sqlite3.connect(self.c.jobs / "jobs.sqlite3") as db:
                    self.assertEqual(db.execute("SELECT count(*) FROM jobs").fetchone()[0], 0)
                current = self.c.f.journal.load(self.c.f.key)
                self.assertTrue(current["jobs_ledger_initialized_before_kernel"])
                self.assertEqual(current["kernel_submit_attempts"], 1)
                self.posts += 1
                self.sessions.append({"path": body["path"], "id": "owned-server-session",
                                      "kernel": {"id": "owned-kernel"}})
                self.c.backend.kernels = [{"id": "owned-kernel", "execution_state": "idle"}]
                return self.sessions[0]
            raise AssertionError((method, route))

        self.c.backend.jupyter = jupyter
        self.c.f.journal.save_session = lambda record, assignment: None
        self.profile_path, self.profile_name = self.c.f.bind_path()

    def tearDown(self):
        self.c.tearDown()

    def bind(self):
        return self.c.manager.bind(self.c.f.key, self.profile_path,
                                   self.profile_name, self.c.jobs)

    def test_bind_initializes_ledger_before_kernel_then_can_close_without_submit(self):
        result = self.bind()
        self.assertEqual(result["phase"], "bound")
        self.assertTrue(result["jobs_ledger_initialized_before_kernel"])
        self.assertEqual(self.posts, 1)
        self.assertTrue((self.c.jobs / "jobs.sqlite3").is_file())
        closed = self.c.manager.close_unstarted(self.c.f.key)
        self.assertEqual(closed["phase"], "released")
        self.assertTrue(closed["never_dispatched"])
        self.assertEqual(closed["cleanup_evidence"]["matching_jobs"], 0)

    def test_ledger_initialization_failure_cannot_create_kernel_or_publish_profile(self):
        with mock.patch.object(manage, "Ledger", side_effect=OSError("fixture storage failure")):
            with self.assertRaises(OSError):
                self.bind()
        record = self.c.f.journal.load(self.c.f.key)
        self.assertEqual(record["kernel_submit_attempts"], 0)
        self.assertFalse(record.get("profile_hash"))
        self.assertEqual(self.posts, 0)

    def test_rebind_cannot_recreate_a_missing_ledger_after_kernel_attempt(self):
        self.bind()
        (self.c.jobs / "jobs.sqlite3").unlink()
        with self.assertRaises(manage.BootstrapError) as caught:
            self.bind()
        self.assertEqual(caught.exception.code, "BIND_JOBS_LEDGER_EVIDENCE_MISSING")
        self.assertFalse((self.c.jobs / "jobs.sqlite3").exists())
        self.assertEqual(self.posts, 1)


if __name__ == "__main__":
    unittest.main()

"""Exercise output contracts with actual short-lived child processes, offline."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import remote_runner


class RemoteRunnerOutputTest(unittest.TestCase):
    def run_finished_child(self, stream, size):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "owned-run"
            code = f"import sys; sys.{stream}.write('x' * {size}); sys.{stream}.flush()"
            payload = {
                "job_id": "output-contract", "payload_sha256": "a" * 64,
                "endpoint": "fixture", "kernel_id": "fixture-kernel",
                "session_id": "fixture-session", "remote_dir": str(root),
                "code": code, "code_sha256": hashlib.sha256(code.encode()).hexdigest(),
                "artifacts": [], "wall_seconds": 10,
                "max_output_bytes": 100, "max_artifact_bytes": 10000,
            }
            real_popen = subprocess.Popen

            def completed_before_first_poll(*args, **kwargs):
                child = real_popen(*args, **kwargs)
                child.wait(timeout=5)
                return child

            # Use a real child and deterministic completion before the polling
            # loop, so the test specifically covers the missed-final-poll race.
            with mock.patch("subprocess.Popen", side_effect=completed_before_first_poll), \
                    contextlib.redirect_stdout(io.StringIO()):
                remote_runner._hepta_main(payload)
            status = json.loads((root / "status.json").read_text())
            manifest = json.loads((root / "artifacts.json").read_text())
            self.assertEqual(status["exit_code"], 0)
            self.assertTrue(status["cloud_execution_stopped"])
            self.assertFalse(status["cloud_process_group_alive"])
            self.assertEqual(manifest["entries"][stream]["size"], size)
            return status

    def test_fast_stdout_over_limit_cannot_report_success(self):
        status = self.run_finished_child("stdout", 1001)
        self.assertEqual(status["state"], "failed")
        self.assertEqual(status["reason"], "output_size_limit")

    def test_fast_stderr_over_limit_cannot_report_success(self):
        status = self.run_finished_child("stderr", 1001)
        self.assertEqual(status["state"], "failed")
        self.assertEqual(status["reason"], "output_size_limit")

    def test_exact_output_limit_is_accepted(self):
        for stream in ("stdout", "stderr"):
            with self.subTest(stream=stream):
                status = self.run_finished_child(stream, 100)
                self.assertEqual(status["state"], "succeeded")
                self.assertIsNone(status["reason"])


if __name__ == "__main__":
    unittest.main()

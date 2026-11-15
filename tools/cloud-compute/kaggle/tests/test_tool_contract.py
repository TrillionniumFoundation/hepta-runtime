import json
from pathlib import Path
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tool_contract import call_argv
from kaggle_transport import AdapterError


class ToolContractTest(unittest.TestCase):
    def test_call_cannot_inject_global_config_or_credentials(self):
        for args in ({"credentials_file": "/tmp/no"}, {"token": "secret"}, {"state_dir": "/tmp/no"}, {"expected_username": "other"}):
            with self.assertRaises(AdapterError): call_argv({"tool": "kaggle_account", "arguments": args})

    def test_submit_types_and_unknown_tool_are_rejected(self):
        with self.assertRaises(AdapterError): call_argv({"tool": "kaggle_call", "arguments": {}})
        with self.assertRaises(AdapterError): call_argv({"tool": "kaggle_submit", "arguments": {"request_id": "x", "source": "a.py", "timeout": True}})
        with self.assertRaises(AdapterError): call_argv({"tool": "kaggle_cancel", "arguments": {"request_id": "x", "wait_seconds": 61}})

    def test_stdin_capabilities_has_one_json_stdout_record(self):
        folder = Path(__file__).resolve().parents[1]
        result = subprocess.run([sys.executable, "hepta_kaggle.py", "call"],
                                input=json.dumps({"tool": "kaggle_capabilities", "arguments": {}}),
                                cwd=folder, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        body = json.loads(result.stdout)
        self.assertTrue(body["ok"])
        self.assertFalse(body["result"]["automatic_submission_replay"])

    def test_stdin_call_preserves_host_expected_username(self):
        folder = Path(__file__).resolve().parents[1]
        result = subprocess.run([sys.executable, "hepta_kaggle.py", "--expected-username", "expected", "call"],
                                input=json.dumps({"tool": "kaggle_capabilities", "arguments": {}}),
                                cwd=folder, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["result"]["expected_username"], "expected")


if __name__ == "__main__": unittest.main()

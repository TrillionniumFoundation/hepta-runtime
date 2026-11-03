"""Fake driver contract checks; no SSH, runtime execution, or production authority."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
FAKE = r'''
import json, os, sys, time
from pathlib import Path
root = Path(sys.argv[1]).parent
action = sys.argv[2]
request = json.loads(Path(sys.argv[3]).read_text())
fence = {key: os.environ.get(key) for key in ('HEPTA_EFFECT_OWNER_FENCE_DIR',
         'HEPTA_EFFECT_OWNER_SELF', 'HEPTA_EFFECT_OWNER_FENCE_REQUIRED')}
with (root / 'calls.jsonl').open('a') as stream:
    stream.write(json.dumps({'action': action, 'request': request, 'fence': fence}) + '\n')
assert action in ('observe', 'read'), action
assert fence == {'HEPTA_EFFECT_OWNER_FENCE_DIR': str(root / 'authority'),
                 'HEPTA_EFFECT_OWNER_SELF': 'v4', 'HEPTA_EFFECT_OWNER_FENCE_REQUIRED': '1'}
mode = (root / 'mode').read_text()
if mode == 'timeout': time.sleep(10)
values = json.loads((root / 'responses.json').read_text())
if action == 'observe':
    kind = 'resume' if request['args'][-1] == 'resume' else 'cancel'
    value = values[kind]['observe']
    if mode == 'wrong_job': value['job']['id'] = 'substitute-job'
    if mode == 'pending': value['status']['state'] = 'effect_unknown'
    if mode == 'missing_witness': value['status']['output_complete'] = False
    calls = [json.loads(line) for line in (root / 'calls.jsonl').read_text().splitlines()]
    if mode == 'publication_changed' and len(calls) == 3: value['status']['at_unix_ms'] += 1
    if mode == 'cancel_timed_out' and kind == 'cancel':
        value['status']['state'] = 'timed_out'
        value['status']['timed_out'] = True
else:
    kind = next(kind for kind in values if values[kind]['read']['job_id'] == request['job_id'])
    value = values[kind]['read']
    if mode == 'short_page': value['stdout']['bytes_hex'] = value['stdout']['bytes_hex'][:-2]
print(json.dumps(value))
'''


def write_json(path, value):
    path.write_text(json.dumps(value))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class CanaryResume(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="native-canary-resume-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        for name in ("authority", "state", "target", "requests", "work"):
            (self.root / name).mkdir()
        write_json(self.root / "config.json", {
            "state_dir": str(self.root / "state"), "controller_workspace_roots": [str(self.root / "work")],
            "hosts": {"native-local-test": {"ssh_target": "localhost", "platform": "linux",
                "execution_mode": "operator", "remote_state_dir": str(self.root / "target"),
                "allow_execute": True, "allow_pty": False, "allow_write": False,
                "allow_job_network": True, "allow_detached_fallback": False}}})
        write_json(self.root / "authority/.owner.json", {
            "schema": "hepta-effect-owner-fence-v1", "owner": "v4", "epoch": 1, "phase": "admitting",
            "state_root": str(self.root / "state"), "predecessor_state_root": None})
        (self.root / "authority/.owner.lock").write_text("")
        self.binary = self.root / "driver"
        self.binary.write_text("#!" + sys.executable + "\n" + FAKE)
        self.binary.chmod(0o700)
        self.report_path = self.root / "report.json"
        params, jobs = {}, {}
        for index, kind in enumerate(("resume", "cancel"), 1):
            (self.root / "work" / (kind + ".marker")).write_text("one execution\n")
            (self.root / "work" / (kind + ".attempts")).write_text(str(122 + index) + "\n")
            params[kind] = {"host": "native-local-test", "executable": "/usr/bin/python3",
                "args": [str(self.root / "work/worker.py"), str(self.root / "work"), kind],
                "cwd": str(self.root / "work"), "stdin": "native exact stdin\n", "timeout_seconds": 45,
                "idempotency_key": "native-library-" + self.root.name + "-" + kind, "nice": 10}
            jobs[kind] = {"id": "original-" + kind, "host": "native-local-test",
                "idempotency_key": params[kind]["idempotency_key"], "request_digest": str(index) * 64,
                "request_fingerprint": index, "ssh_target": "localhost", "execution_mode": "operator",
                "executable": params[kind]["executable"], "args": params[kind]["args"],
                "cwd": params[kind]["cwd"], "env_keys": [], "system_jobctl": False,
                "unit": "hepta-runtime-job-original-" + kind,
                "remote_job_dir": str(self.root / "target/jobs" / ("original-" + kind))}
        finished = {"job_id": jobs["resume"]["id"], "state": "succeeded", "exit_code": 0,
            "timed_out": False, "cancelled": False, "launch_nonce": "ab" * 16, "at_unix_ms": 123456,
            "terminal_publication_protocol": 1, "terminal_publication_confirmed": True,
            "output_complete": True, "output_durable": True,
            "log_bytes": {"stdout": {"stored": 24, "seen": 24}, "stderr": {"stored": 14, "seen": 14}},
            "log_truncated": {"stdout": False, "stderr": False},
            "log_errors": {"stdout": None, "stderr": None}, "log_synced": {"stdout": True, "stderr": True}}
        running = {"job_id": jobs["resume"]["id"], "state": "running", "backend": "systemd"}
        reuse = {"job": jobs["resume"], "reused": True, "retried_launch": False, "launch": None, "status": running}

        def row(action, value, entries=0):
            return {"action": action, "driver_action": "start-checked" if action == "start" else action,
                    "exit": 0, "entry_calls": entries, "stdout": json.dumps(value),
                    "stderr": "HEPTA_NATIVE_CHECKED_FIXTURE_ENTRY\n" if entries else ""}

        started = {kind: {"job": jobs[kind], "reused": False, "launch": {"backend": "systemd"}}
                   for kind in ("resume", "cancel")}
        events = [{"action": "start-hold", "response": started["resume"], "controller_pid": 122},
            row("status", running), row("start", reuse),
            {"action": "start", "driver_action": "start-checked", "exit": 1, "entry_calls": 0,
             "stdout": "", "stderr": "Error: idempotency key is already bound to a different request"},
            row("status", finished), row("read", {"job_id": jobs["resume"]["id"]}),
            row("start", started["cancel"], 1),
            {"action": "status", "driver_action": "status", "exit": 1, "entry_calls": 0,
             "stdout": "", "stderr": "Error: remote helper failed with 255; Connection closed"},
            row("cancel", {"job_id": jobs["resume"]["id"], "result": "already_exited",
                           "automatic_retry": False, "termination_confirmed": False}),
            row("cancel", {"job_id": jobs["cancel"]["id"], "result": "stop_requested",
                           "automatic_retry": False, "termination_confirmed": False})]
        self.report = {"schema": "hepta-native-process-library-canary/v1", "root": str(self.root),
            "binary_sha256": digest(self.binary), "passed": False, "checked_native_entry": True,
            "owner_fence_required": True, "entry_fixture_only": True, "systemd_scope": "user",
            "events": events, "original_job_id": jobs["resume"]["id"],
            "owned_controller_sigkill": {"exit": -9, "stderr": "HEPTA_NATIVE_CHECKED_FIXTURE_ENTRY\n"},
            "running_after_controller_death": running, "same_key_reuse": reuse, "completed_original": finished,
            "execution_count": 1, "worker_attempt_pids": ["123"], "error": "status failed with 255",
            "output_sha256": {"stdout": hashlib.sha256(b"BEGIN resume\nEND resume\n").hexdigest(),
                              "stderr": hashlib.sha256(b"stderr resume\n").hexdigest()}}
        refs = {kind: {"host": "native-local-test", "job_id": jobs[kind]["id"]} for kind in jobs}
        requests = [params["resume"], refs["resume"], params["resume"],
            dict(params["resume"], args=params["resume"]["args"] + ["different-payload"]),
            refs["resume"], dict(refs["resume"], stdout_offset=0, stderr_offset=0, limit=16384),
            params["cancel"], refs["cancel"], dict(refs["resume"], grace_seconds=2),
            dict(refs["cancel"], grace_seconds=2)]
        for index, value in enumerate(requests, 1):
            write_json(self.root / "requests" / f"{index:03d}.json", value)
        write_json(self.report_path, self.report)
        self.frozen_report = self.report_path.read_bytes()
        responses = {}
        for kind in ("resume", "cancel"):
            started = next(event.get("response") or json.loads(event["stdout"])
                           for event in self.report["events"]
                           if event.get("action") in ("start-hold", "start")
                           and ("response" in event or event.get("exit") == 0)
                           and ((event.get("response") or json.loads(event["stdout"]))
                                .get("job", {}).get("args", [None])[-1] == kind))
            job = started["job"]
            terminal = dict(self.report["completed_original"])
            stdout = ("BEGIN resume\nEND resume\n" if kind == "resume" else "BEGIN cancel\n").encode()
            stderr = ("stderr " + kind + "\n").encode()
            if kind == "cancel":
                terminal.update(job_id=job["id"], state="cancelled", cancelled=True,
                                exit_code=-15, launch_nonce="ab" * 16)
                terminal["log_bytes"] = {name: {"seen": len(body), "stored": len(body)}
                                         for name, body in (("stdout", stdout), ("stderr", stderr))}
            output = {"job_id": job["id"]}
            for name, body in (("stdout", stdout), ("stderr", stderr)):
                output[name] = {"offset": 0, "next_offset": len(body), "size": len(body),
                                "eof": True, "bytes_hex": body.hex(), "text": body.decode()}
            responses[kind] = {"observe": {"job": job, "status": terminal, "observation_only": True,
                                              "reused": True, "retried_launch": False, "launch": None},
                               "read": output}
        write_json(self.root / "responses.json", responses)
        self.receipt = self.root / "continuation.json"
        self.environment = dict(os.environ, HEPTA_EFFECT_OWNER_FENCE_DIR="/unrelated-production-owner",
                                HEPTA_EFFECT_OWNER_SELF="wrong", HEPTA_EFFECT_OWNER_FENCE_REQUIRED="0")

    def run_helper(self, mode="pass", sha=None, timeout="2"):
        (self.root / "mode").write_text(mode)
        return subprocess.run([sys.executable, "-B", str(HERE / "native_canary_resume.py"),
            "--resume-report", str(self.report_path), "--expected-report-sha256", sha or digest(self.report_path),
            "--driver", str(self.binary), "--receipt", str(self.receipt),
            "--call-timeout-seconds", timeout], env=self.environment, capture_output=True, text=True, timeout=10)

    def calls(self):
        path = self.root / "calls.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def test_only_original_reads_and_private_fence_keep_failed_first_report_unchanged(self):
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertEqual([call["action"] for call in self.calls()], ["observe", "read", "observe"] * 2)
        self.assertEqual(self.report_path.read_bytes(), self.frozen_report)
        record = json.loads(self.receipt.read_text())
        self.assertTrue(record["complete"])
        self.assertFalse(record["original_report_passed"])
        self.assertFalse(record["original_cancel_running_observation"])
        self.assertIsNone(record["cancellation_end_to_end_seconds"])
        self.assertEqual(record["jobs"]["cancel"]["terminal_proof"]["state"], "cancelled")
        self.assertEqual(record["original_cancel_ack"]["result"], "stop_requested")
        self.assertTrue(record["original_report_unchanged"])
        self.assertFalse(record["new_execution_submitted"])
        self.assertFalse(record["new_cancellation_submitted"])

    def test_bad_original_hash_refuses_before_any_driver_call(self):
        self.assertNotEqual(self.run_helper(sha="0" * 64).returncode, 0)
        self.assertEqual(self.calls(), [])
        self.assertFalse(self.receipt.exists())

    def test_pending_unknown_stops_without_an_effect_or_automatic_poll(self):
        self.assertNotEqual(self.run_helper("pending").returncode, 0)
        self.assertEqual(len(self.calls()), 1)
        self.assertFalse(json.loads(self.receipt.read_text())["complete"])

    def test_substituted_job_or_missing_publication_is_held(self):
        self.assertNotEqual(self.run_helper("wrong_job").returncode, 0)
        self.assertEqual(len(self.calls()), 1)

    def test_incomplete_publication_is_held(self):
        self.assertNotEqual(self.run_helper("missing_witness").returncode, 0)
        self.assertEqual(len(self.calls()), 1)

    def test_short_output_page_does_not_become_terminal_success(self):
        self.assertNotEqual(self.run_helper("short_page").returncode, 0)
        self.assertEqual(len(self.calls()), 2)

    def test_publication_change_between_reads_stops_continuation(self):
        self.assertNotEqual(self.run_helper("publication_changed").returncode, 0)
        self.assertEqual(len(self.calls()), 3)

    def test_original_cancel_timed_out_is_not_relabeled_cancelled(self):
        self.assertNotEqual(self.run_helper("cancel_timed_out").returncode, 0)
        self.assertEqual(len(self.calls()), 4)
        record = json.loads(self.receipt.read_text())
        self.assertIn("resume", record["jobs"])
        self.assertNotIn("cancel", record["jobs"])

    def test_existing_receipt_never_gets_replaced_or_repeated(self):
        self.assertEqual(self.run_helper().returncode, 0)
        receipt = self.receipt.read_bytes()
        self.assertNotEqual(self.run_helper().returncode, 0)
        self.assertEqual(len(self.calls()), 6)
        self.assertEqual(self.receipt.read_bytes(), receipt)

    def test_observation_timeout_preserves_unknown_and_original_report(self):
        self.assertNotEqual(self.run_helper("timeout", timeout="0.1").returncode, 0)
        self.assertEqual(len(self.calls()), 1)
        record = json.loads(self.receipt.read_text())
        self.assertFalse(record["complete"])
        self.assertEqual(record["events"][0]["result"], "observation_timeout")
        self.assertEqual(self.report_path.read_bytes(), self.frozen_report)


if __name__ == "__main__":
    unittest.main()

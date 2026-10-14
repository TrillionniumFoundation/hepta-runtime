#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Offline contract tests for the bounded configured-host inventory collector."""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("collector", ROOT / "deploy/dc_readonly_inventory.py")
assert SPEC and SPEC.loader
import sys
sys.path.insert(0, str(ROOT / "deploy"))
I = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(I)


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="hepta-r5-inventory-fixture-")
        self.base = Path(self.tmp.name)
        self.bin = self.base / "bin"
        self.bin.mkdir(mode=0o700)
        self.old_path = os.environ.get("PATH", "")
        os.environ["PATH"] = str(self.bin) + ":" + self.old_path

    def tearDown(self):
        os.environ["PATH"] = self.old_path
        self.tmp.cleanup()

    def test_streaming_exact_reply(self):
        output = I.bounded_capture(
            ["/usr/bin/python3", "-c", "import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())"],
            b"abcd\n", timeout=4,
            max_stdout=5,
        )
        self.assertEqual(output, b"abcd\n")

    def test_stdout_oversize_refusal(self):
        with self.assertRaisesRegex(I.InventoryError, "stdout_bound_exceeded"):
            I.bounded_capture(
                ["/usr/bin/python3", "-c", "import sys;sys.stdout.write('x'*8192)"],
                b"", timeout=4, max_stdout=1024
            )

    def test_stderr_oversize_refusal_without_leak(self):
        with self.assertRaisesRegex(I.InventoryError, "stderr_bound_exceeded"):
            I.bounded_capture(
                ["/usr/bin/python3", "-c", "import sys;sys.stderr.write('PRIVATE'*1024)"],
                b"", timeout=4, max_stderr=512
            )

    def test_explicit_nonzero_failure(self):
        with self.assertRaisesRegex(I.InventoryError, "remote_helper_nonzero"):
            I.bounded_capture(["/usr/bin/python3", "-c", "raise SystemExit(17)"], b"", timeout=4)

    def test_timeout_kills_owned_child(self):
        with self.assertRaisesRegex(I.InventoryError, "transport_timeout"):
            I.bounded_capture(
                ["/usr/bin/python3", "-c", "import time;time.sleep(10)"], b"", timeout=1
            )

    def test_invalid_config_fails_without_io(self):
        for config in [
            {}, {"hosts": {}}, {"hosts": {"main": {}}, "state_dir": "relative"},
            {"hosts": {"main": {"platform": "win", "ssh_target": "a",
                                 "remote_state_dir": "/x"}}, "state_dir": "/tmp"},
        ]:
            with self.assertRaises(I.InventoryError):
                I.check_config(config, None)

    def test_configuration_symlink_is_refused(self):
        p = self.base / "configuration.json"
        p.write_text('{"hosts":{},"state_dir":"/tmp"}')
        target = self.base / "configuration-link.json"
        target.symlink_to(p)
        with self.assertRaises(OSError):
            I.read_private_config(target)

    def test_configuration_group_writable_is_refused(self):
        p = self.base / "configuration.json"
        p.write_text('{"hosts":{},"state_dir":"/tmp"}')
        p.chmod(0o660)
        with self.assertRaisesRegex(I.InventoryError, "config_identity_or_mode"):
            I.read_private_config(p)

    def test_configuration_duplicate_key_refused(self):
        p = self.base / "configuration.json"
        p.write_text('{"hosts":{},"hosts":{},"state_dir":"/tmp"}')
        p.chmod(0o600)
        with self.assertRaises(I.core.Refusal):
            I.read_private_config(p)

    def test_ssh_destination_option_injection_refused(self):
        config = {"state_dir":"/tmp","hosts":{"main":{
            "platform":"linux","ssh_target":"-oProxyCommand=cat",
            "remote_state_dir":"/tmp/state"}}}
        with self.assertRaisesRegex(I.InventoryError, "invalid_ssh_target"):
            I.check_config(config, None)

    def test_expected_host_set_rejects_unlisted(self):
        config = {"state_dir": "/tmp", "hosts": {
            "main": {"platform": "linux", "ssh_target": "fixture", "remote_state_dir": "/tmp/other"}
        }}
        with self.assertRaisesRegex(I.InventoryError, "host_set_mismatch"):
            I.check_config(config, ["main", "pocket4"])

    def test_invalid_record_refusal_not_success(self):
        state = self.base / "controller"
        (state / "jobs").mkdir(parents=True,mode=0o700)
        (state / "terminals").mkdir(mode=0o700)
        a = state / "jobs" / "invalid.json"
        a.write_text("{bad-json")
        a.chmod(0o600)
        host = {"main": {"ssh_target": "fixture", "remote_state_dir": "/private"}}
        rows, unresolved, _, manifests = I.scan_controller(state, host)
        self.assertFalse(rows["main"])
        self.assertEqual(len(unresolved), 1)
        self.assertEqual(manifests, {})

    def test_dc_start_time_reused_pid_not_accepted(self):
        pid = os.getpid()
        observed = I.inspect_known_dc_processes([str(pid)+":1"])
        self.assertEqual(len(observed), 1)
        self.assertFalse(observed[0]["start_identity_match"])

    def test_invalid_dc_identity_refused(self):
        for value in ["-1:123", "abc", "1:0", "0:1", "99999999999999:11"]:
            with self.assertRaises(I.InventoryError):
                I.inspect_known_dc_processes([value])

    def fixture(self, *, remove_exit=False):
        state = self.base / "controller"
        state.mkdir(mode=0o700)
        (state / "jobs").mkdir(mode=0o700)
        (state / "terminals").mkdir(mode=0o700)
        remote = self.base / "remote"
        remote.mkdir(mode=0o700)
        (remote / "jobs").mkdir(mode=0o700)
        (remote / "terminals").mkdir(mode=0o700)
        jobid = "a-b-c"
        jobdir = remote / "jobs" / jobid
        jobdir.mkdir(mode=0o700)
        session = "dpty-fixture-001"
        ptydir = remote / "terminals" / session
        ptydir.mkdir(mode=0o700)
        def save(path, record):
            path.write_text(json.dumps(record))
            path.chmod(0o600)
        def data(path, raw):
            path.write_bytes(raw)
            path.chmod(0o600)
        fingerprint = "a"*64
        save(state / "jobs" / (jobid+".json"), {
            "id": jobid, "host": "main", "ssh_target": "fixture",
            "remote_job_dir": str(jobdir), "request_fingerprint": 2,
            "request_digest": fingerprint, "execution_mode": "operator",
            "system_jobctl": False,
        })
        save(state / "terminals" / (session+".json"), {
            "session_id": session, "host": "main", "ssh_target": "fixture",
            "remote_state_dir": str(remote), "job_dir": str(ptydir),
            "request": {"session_id": session},
        })
        save(jobdir / "request.json", {"job_id": jobid, "request_fingerprint": fingerprint})
        if not remove_exit:
            save(jobdir / "exit.json", {
                "exit_code": 0, "timed_out": False, "cancelled": False,
                "output_complete": True,
                "log_bytes": {
                    "stdout": {"seen": 2, "stored": 2},
                    "stderr": {"seen": 0, "stored": 0}
                },
                "log_errors": {"stdout": None, "stderr": None},
                "log_truncated": {"stdout": False, "stderr": False}
            })
        data(jobdir / "stdout.log", b"OK")
        data(jobdir / "stderr.log", b"")
        save(ptydir / "request.json", {"session_id": session})
        save(ptydir / "exit.json", {
            "state": "exited", "exit_code": 0, "bytes_seen": 2,
            "bytes_stored": 2, "capture_error": None, "output_complete": True
        })
        data(ptydir / "output.log", b"OK")
        config = self.base / "runtime.json"
        save(config, {"state_dir": str(state), "hosts": {
            "main": {"platform": "linux", "ssh_target": "fixture", "remote_state_dir": str(remote)}
        }})
        # The binary name is 'ssh' but only executes the bundled Python helper
        # in the owned fixture. No actual SSH, network, or production host.
        wrapper = self.bin / "ssh"
        wrapper.write_text(
            "#!/usr/bin/python3\nimport sys,shlex,os\n"
            "args=shlex.split(sys.argv[-1])\n"
            "assert args[:2]==['python3','-c'] and len(args)==3\n"
            "os.execv('/usr/bin/python3',['/usr/bin/python3','-c',args[2]])\n"
        )
        wrapper.chmod(0o700)
        return config

    def test_native_fixture_reports_two_records_no_cutover(self):
        config = self.fixture()
        out = self.base / "out"
        result_dir, report = I.run(argparse.Namespace(
            config=str(config), output=str(out), hosts=["main"], dc_identity=[]
        ))
        self.assertEqual(result_dir, out)
        self.assertEqual(report["controller_records_selected"], 2)
        self.assertTrue(report["controller_cohort_stable"])
        self.assertTrue(report["every_host_response_complete"])
        self.assertTrue(report["count_matched"])
        self.assertFalse(report["can_retire_desktop_commander"])
        self.assertFalse(report["full_replacement_qualified"])
        self.assertEqual(report["observations"]["main"]["state_counts"]["jobs"]["succeeded"],1)
        self.assertEqual(report["observations"]["main"]["state_counts"]["terminals"]["exited"],1)
        self.assertEqual(report["observations"]["main"]["output_size_and_receipt_verified"],2)
        for name in ("main.json", "summary.json","membership.json","controller-manifest.json"):
            path = out / name
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(out.stat().st_mode & 0o777,0o700)
        self.assertNotIn("PRIVATE", (out/"summary.json").read_text())

    def test_native_fixture_missing_exit_never_claims_complete(self):
        config = self.fixture(remove_exit=True)
        result_dir, report = I.run(argparse.Namespace(
            config=str(config), output=str(self.base/"out"), hosts=["main"], dc_identity=[]
        ))
        assert report["every_host_response_complete"]
        self.assertFalse(report["observations"]["main"]["all_records_resolved"])
        self.assertEqual(report["observations"]["main"]["state_counts"]["jobs"]["nonterminal_or_missing_receipt"],1)
        self.assertFalse(report["can_retire_desktop_commander"])

    def test_second_run_refuses_to_overwrite_original_evidence(self):
        config = self.fixture()
        out = self.base/"out"
        I.run(argparse.Namespace(config=str(config),output=str(out),hosts=["main"],dc_identity=[]))
        with self.assertRaisesRegex(I.InventoryError, "output_exists"):
            I.run(argparse.Namespace(config=str(config),output=str(out),hosts=["main"],dc_identity=[]))


if __name__ == "__main__":
    unittest.main()

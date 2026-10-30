#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Local lease-only fixtures: no SSH, real host access, or native benchmark."""
import hashlib
import json
import os
from pathlib import Path
import signal
import select
import socket
import subprocess
import sys
import tempfile
import time
import unittest

import forwarded_validation_lease as lease


class HeartbeatTests(unittest.TestCase):
    def test_partial_stream_and_strict_sequence(self):
        reader = lease.Heartbeats("nonce")
        self.assertEqual(reader.consume(b'{"nonce":"nonce",', 1.0), [])
        self.assertEqual(reader.consume(b'"sequence":0}\n', 2.0), [{"sequence": 0, "received_monotonic": 2.0}])
        self.assertEqual(reader.consume(b'{"nonce":"nonce","sequence":1}\n', 3.0)[0]["sequence"], 1)
        self.assertEqual(reader.last_received, 3.0)

    def test_replay_gap_wrong_nonce_and_eof_are_refused(self):
        for raw in [b'', b'{"nonce":"wrong","sequence":0}\n', b'{"nonce":"nonce","sequence":1}\n']:
            with self.assertRaises((RuntimeError, ValueError)):
                lease.Heartbeats("nonce").consume(raw, 0.0)
        reader = lease.Heartbeats("nonce")
        raw = b'{"nonce":"nonce","sequence":0}\n'
        reader.consume(raw, 0.0)
        with self.assertRaises(RuntimeError):
            reader.consume(raw, 1.0)


@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "pidfd_open"), "Linux pidfd required")
class OwnedChildTests(unittest.TestCase):
    def test_parent_death_signal_and_forced_owned_reap(self):
        row = {}
        script = "import ctypes,signal,time\nv=ctypes.c_int();assert ctypes.CDLL(None).prctl(2,ctypes.byref(v),0,0,0)==0\nsignal.signal(signal.SIGTERM,signal.SIG_IGN)\nprint(v.value,flush=True)\ntime.sleep(300)\n"
        child = lease.OwnedChild([sys.executable, "-I", "-c", script], row,
                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            self.assertTrue(select.select([child.process.stdout], [], [], 5)[0])
            self.assertEqual(child.process.stdout.readline().strip(), str(signal.SIGTERM.value).encode())
            child.terminate(0.05)
            self.assertEqual(row["returncode"], -signal.SIGKILL)
            self.assertEqual([item["signal"] for item in row["signals"]], ["SIGTERM", "SIGKILL"])
            self.assertEqual(row["pid"], row["actual_waitpid"])
        finally:
            if not child.reap():
                child.terminate(0.05)
            child.process.stdout.close()
            child.close()
        self.assertTrue(row["custody_retained_until_reap"])


@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "pidfd_open"), "Linux pidfd required")
class RemoteLeaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.agent = socket.socket(socket.AF_UNIX)
        self.agent.bind(str(self.root / "agent"))
        self.wrapper = Path(lease.__file__).resolve()
        self.runner = self.root / "fixture.py"
        self.output = self.root / "native"
        self.out = self.root / "remote-lease"
        self.nonce = "a" * 32
        self.env = {**os.environ, "SSH_AUTH_SOCK": str(self.root / "agent")}
        self.child = None

    def tearDown(self):
        if self.child is not None and self.child.poll() is None:
            self.child.terminate()
            self.child.wait(timeout=10)
        if self.child is not None:
            for stream in (self.child.stdin, self.child.stdout, self.child.stderr):
                if stream is not None and not stream.closed:
                    stream.close()
        self.agent.close()
        self.temp.cleanup()

    def launch(self, script, report_kind=None):
        self.runner.write_text(script)
        self.runner.chmod(0o600)
        argv = [sys.executable, "-B", str(self.wrapper), "remote",
                "--self-sha256", hashlib.sha256(self.wrapper.read_bytes()).hexdigest(),
                "--nonce", self.nonce, "--runner", str(self.runner),
                "--runner-sha256", hashlib.sha256(self.runner.read_bytes()).hexdigest(),
                "--out", str(self.out), *([] if report_kind is None else ["--report-kind", report_kind]),
                "--", "--qualification", str(self.root / "qualification.json"),
                "--qualification-sha256", "b" * 64, "--test-audit", str(self.root / "audit.json"),
                "--test-audit-sha256", "c" * 64, "--out", str(self.output), "--socket-parent", str(self.root / "sockets")]
        self.child = subprocess.Popen(argv, env=self.env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return self.child

    def launch_report(self, schema, report_kind=None, **overrides):
        value = {"schema": schema, "passed": True, "complete": True, **overrides}
        script = "import pathlib,sys\np=pathlib.Path(sys.argv[sys.argv.index('--out')+1]);p.mkdir()\n"
        return self.launch(script + "(p/'report.json').write_text(" + repr(json.dumps(value)) + ")\n", report_kind)

    def heartbeat(self):
        self.child.stdin.write((json.dumps({"nonce": self.nonce, "sequence": 0}) + "\n").encode())
        self.child.stdin.flush()

    def report(self):
        return json.loads((self.out / "report.json").read_text())

    def wait_for_marker(self):
        until = time.monotonic() + 5
        while not (self.root / "running").exists():
            if time.monotonic() >= until:
                self.fail("lease fixture did not start")
            time.sleep(0.01)

    def test_eof_before_admission_never_launches(self):
        child = self.launch("raise AssertionError('must not execute')\n")
        child.stdin.close()
        self.assertNotEqual(child.wait(timeout=5), 0)
        value = self.report()
        self.assertFalse(value["passed"])
        self.assertEqual(value["launch_attempts"], 0)
        self.assertFalse((self.out / "admission.json").exists())

    def test_success_requires_real_original_completion_report_and_reap(self):
        child = self.launch_report("hepta-x230-composed-native-validation/v1")
        self.heartbeat()
        self.assertEqual(child.wait(timeout=5), 0)
        value = self.report()
        self.assertTrue(value["passed"])
        self.assertEqual(value["launch_attempts"], 1)
        self.assertTrue(value["child"]["original_child_reaped"])
        self.assertEqual(value["child"]["pid"], value["child"]["actual_waitpid"])
        self.assertTrue((self.out / "admission.json").exists())
        self.assertEqual(value["report_kind"], "native")
        self.assertEqual([json.loads(line)["report_kind"] for line in child.stdout], ["native", "native"])

    def test_explicit_extended_soak_requires_its_report_and_original_reap(self):
        child = self.launch_report("hepta-x230-extended-file-soak/v1", "extended-soak")
        self.heartbeat()
        self.assertEqual(child.wait(timeout=5), 0)
        value = self.report()
        self.assertTrue(value["passed"])
        self.assertEqual(value["report_kind"], "extended-soak")
        self.assertEqual(value["launch_attempts"], 1)
        self.assertTrue(value["child"]["original_child_reaped"])
        self.assertEqual(value["child"]["pid"], value["child"]["actual_waitpid"])
        self.assertEqual([json.loads(line)["report_kind"] for line in child.stdout], ["extended-soak", "extended-soak"])

    def test_default_native_refuses_extended_schema_after_zero_exit(self):
        child = self.launch_report("hepta-x230-extended-file-soak/v1")
        self.heartbeat()
        self.assertNotEqual(child.wait(timeout=5), 0)
        value = self.report()
        self.assertFalse(value["passed"])
        self.assertEqual(value["report_kind"], "native")
        self.assertEqual(value["child"]["returncode"], 0)
        self.assertTrue(value["child"]["original_child_reaped"])

    def test_extended_refuses_native_schema_after_zero_exit(self):
        child = self.launch_report("hepta-x230-composed-native-validation/v1", "extended-soak")
        self.heartbeat()
        self.assertNotEqual(child.wait(timeout=5), 0)
        value = self.report()
        self.assertFalse(value["passed"])
        self.assertEqual(value["report_kind"], "extended-soak")
        self.assertEqual(value["child"]["returncode"], 0)
        self.assertTrue(value["child"]["original_child_reaped"])

    def test_extended_refuses_incomplete_report(self):
        child = self.launch_report("hepta-x230-extended-file-soak/v1", "extended-soak", complete=False)
        self.heartbeat()
        self.assertNotEqual(child.wait(timeout=5), 0)
        self.assertFalse(self.report()["passed"])

    def test_report_kind_cannot_be_an_arbitrary_schema(self):
        child = self.launch("raise AssertionError('must not execute')\n", "hepta-x230-composed-native-validation/v1")
        self.assertNotEqual(child.wait(timeout=5), 0)
        self.assertFalse(self.out.exists())

    def test_zero_exit_without_native_report_is_not_a_pass(self):
        child = self.launch("pass\n")
        self.heartbeat()
        self.assertNotEqual(child.wait(timeout=5), 0)
        self.assertFalse(self.report()["passed"])
        self.assertEqual(self.report()["child"]["returncode"], 0)

    def test_eof_reaps_the_owned_running_child(self):
        child = self.launch("import pathlib,time\npathlib.Path(__file__).with_name('running').write_text('ready')\ntime.sleep(300)\n")
        self.heartbeat()
        self.wait_for_marker()
        child.stdin.close()
        self.assertNotEqual(child.wait(timeout=5), 0)
        value = self.report()
        self.assertFalse(value["passed"])
        self.assertTrue(value["child"]["custody_retained_until_reap"])
        self.assertEqual(value["child"]["signals"][0]["target"], "original_child_pidfd")
        self.assertEqual(value["child"]["signals"][0]["signal"], "SIGTERM")

    def test_hup_uses_the_same_revoke_and_reap_path(self):
        child = self.launch("import pathlib,time\npathlib.Path(__file__).with_name('running').write_text('ready')\ntime.sleep(300)\n")
        self.heartbeat()
        self.wait_for_marker()
        child.send_signal(signal.SIGHUP)
        self.assertNotEqual(child.wait(timeout=5), 0)
        value = self.report()
        self.assertFalse(value["passed"])
        self.assertTrue(value["child"]["custody_retained_until_reap"])
        self.assertEqual(value["stop_signals"][0]["signal"], "SIGHUP")


if __name__ == "__main__":
    unittest.main()

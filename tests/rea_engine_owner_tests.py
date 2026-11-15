#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Actual embedded owner lifecycle on owned fixtures; not Java engine qualification."""
import json
import os
from pathlib import Path
import re
import select
import signal
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

SOURCE = (Path(__file__).resolve().parents[1] / "src/mcp/runtime/jobs.rs").read_text()


def constant(name):
    return re.search(r"const " + name + r': &str = r#"(.*?)"#;', SOURCE, re.S).group(1)


PRIVATE = constant("PRIVATE_DIRECTORY_CODE")
PREFIX = "REMOTE_DIRECTORY_SOURCE = " + repr(PRIVATE) + "\nexec(REMOTE_DIRECTORY_SOURCE)\n"
CODE = {name: PREFIX + (constant("BOUND_OBSERVATION_CODE") if name != "START_CODE" else "") + constant(name)
        for name in ("START_CODE", "STATUS_CODE", "READ_CODE", "CANCEL_CODE")}

WORKER = r'''#!/usr/bin/python3
import json, os, pathlib, signal, subprocess, sys, time
request = json.load(sys.stdin)
owner = json.loads(os.environ["HEPTA_RUNTIME_ENGINE_SCRATCH"])
root = pathlib.Path(owner["path"])
claim = {"schema":"hepta.rea.engine-scratch-claim.v1", "owner":owner,
         "worker_pid":os.getpid(), "engine":"ghidra"}
with (root / "claim.json").open("x") as stream:
    json.dump(claim, stream); stream.flush(); os.fsync(stream.fileno())
(root / "cache").mkdir()
(root / "cache/data").write_bytes(b"owned engine cache")
if request["fixture"] == "replace":
    root.rename(root.with_name("retained-original"))
    root.mkdir(mode=0o700)
    (root / "preserve").write_bytes(b"replacement data")
    print("READY", flush=True)
elif request["fixture"] in ("normal", "unprivate-claim"):
    if request["fixture"] == "unprivate-claim": (root / "claim.json").chmod(0o644)
    print("READY", flush=True)
else:
    writer = subprocess.Popen([sys.executable, "-c",
        "import os,signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);"
        "f=open(os.environ['OWNED_FILE'],'ab',buffering=0);"
        "\nwhile True:f.write(b'.');time.sleep(.01)"],
        env=dict(os.environ, OWNED_FILE=str(root / "cache/data")),
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    (root.parent / "writer.json").write_text(json.dumps({"pid":writer.pid, "identity":{"kind":"proc_start_ticks", "value":pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip() + ":" + pathlib.Path(f"/proc/{writer.pid}/stat").read_text().rsplit(") ", 1)[1].split()[19]}}))
    print("READY", flush=True)
    time.sleep(60)
'''


@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "pidfd_open"), "Linux atomic custody required")
class EngineOwnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-engine-owner-")
        self.root = Path(self.temp.name)
        self.worker = self.root / "owned-worker"
        self.worker.write_text(WORKER)
        self.worker.chmod(0o700)
        self.job = self.root / "state/jobs" / uuid.uuid4().hex
        self.q = {"job_id":self.job.name, "job_dir":str(self.job), "unit":"test-" + self.job.name,
                  "request_fingerprint":"a" * 64, "request_digest":"a" * 64,
                  "platform":"macos", "execution_mode":"operator", "executable":str(self.worker),
                  "args":["rea-static-worker"], "cwd":str(self.root), "env":{},
                  "timeout_seconds":20, "allow_job_network":True, "allow_detached_fallback":True}
        self.owned_fds = []

    def call(self, name, q=None):
        result = subprocess.run([sys.executable, "-c", CODE[name]], input=json.dumps(q or self.q),
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, (name, result.stdout, result.stderr))
        return json.loads(result.stdout)

    def wait_for(self, callback, timeout=15):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = callback()
            if result:
                return result
            time.sleep(.03)
        self.fail("owned fixture did not reach expected state")

    def start(self, mode="live", timeout=20):
        self.q.update(timeout_seconds=timeout, stdin=json.dumps({
            "schema":"hepta.rea.static-request.v1", "profile":{"provider":"ghidra"}, "fixture":mode}))
        self.assertEqual(self.call("START_CODE")["backend"], "detached")
        self.wait_for(lambda: "READY" in (self.job / "stdout.log").read_text() if (self.job / "stdout.log").exists() else False)
        for name, field in (("started.json", "supervisor_pid"), ("child.json", "pid"), ("writer.json", "pid")):
            path = self.job / name
            if path.exists():
                record = json.loads(path.read_text())
                pid = record[field]
                expected = record["supervisor_identity" if name == "started.json" else "identity"]
                try:
                    fd = os.pidfd_open(pid, 0)
                except ProcessLookupError:
                    continue
                try:
                    ticks = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()[19]
                    actual = {"kind":"proc_start_ticks", "value":Path("/proc/sys/kernel/random/boot_id").read_text().strip() + ":" + ticks}
                    if actual == expected:
                        self.owned_fds.append((name, fd))
                        fd = None
                except FileNotFoundError:
                    pass
                finally:
                    if fd is not None:
                        os.close(fd)

    def terminal(self):
        def observed():
            status = self.call("STATUS_CODE")
            return status if status.get("terminal_publication_confirmed") is True else None
        return self.wait_for(observed)

    def assert_removed(self, status):
        receipt = status["scratch_cleanup"]
        self.assertEqual(receipt["state"], "removed", receipt)
        for flag in ("removed", "durable", "worker_adopted", "original_process_group_stopped", "original_child_reaped"):
            self.assertIs(receipt[flag], True, receipt)
        self.assertEqual(receipt["job_id"], self.q["job_id"])
        self.assertEqual(receipt["launch_nonce"], status["launch_nonce"])
        self.assertFalse((self.job / "engine-scratch").exists())
        self.assertEqual(self.call("STATUS_CODE"), status)
        self.assertTrue(self.call("START_CODE")["reused_remote"])
        for name, fd in self.owned_fds:
            if name != "started.json":
                self.assertTrue(select.select([fd], [], [], 1)[0], name)

    def test_normal_completion_removes_only_original_private_namespace(self):
        self.start("normal")
        status = self.terminal()
        self.assertEqual(status["state"], "succeeded")
        self.assert_removed(status)

    def test_unprivate_claim_does_not_become_positive_worker_adoption(self):
        self.start("unprivate-claim")
        status = self.terminal()
        self.assertEqual(status["scratch_cleanup"]["state"], "removed")
        self.assertFalse(status["scratch_cleanup"]["worker_adopted"])
        self.assertFalse((self.job / "engine-scratch").exists())

    def test_cancel_stops_term_ignoring_descendant_before_cleanup(self):
        self.start()
        self.call("CANCEL_CODE", dict(self.q, grace_seconds=3))
        status = self.terminal()
        self.assertEqual(status["state"], "cancelled")
        self.assert_removed(status)

    def test_timeout_and_worker_crash_are_readable_without_harness_cleanup(self):
        self.start(timeout=1)
        status = self.terminal()
        self.assertEqual(status["state"], "timed_out")
        self.assert_removed(status)

    def test_worker_sigkill_cannot_leave_a_live_writer_in_removed_scratch(self):
        self.start()
        fd = next(fd for name, fd in self.owned_fds if name == "child.json")
        signal.pidfd_send_signal(fd, signal.SIGKILL)
        status = self.terminal()
        self.assertEqual(status["state"], "failed")
        self.assertEqual(status["exit_code"], -9)
        self.assert_removed(status)

    def test_owner_loss_stays_unknown_and_never_deletes_scratch_on_status(self):
        self.start()
        fd = next(fd for name, fd in self.owned_fds if name == "started.json")
        signal.pidfd_send_signal(fd, signal.SIGKILL)
        self.assertTrue(select.select([fd], [], [], 2)[0])
        status = self.call("STATUS_CODE")
        self.assertFalse(status.get("terminal_publication_confirmed", False))
        self.assertFalse(status["status_authoritative"])
        self.assertTrue((self.job / "engine-scratch/cache/data").is_file())
        self.assertTrue(self.call("START_CODE")["reused_remote"])
        self.assertTrue((self.job / "engine-scratch/cache/data").is_file())

    def test_replaced_directory_is_retained_without_deleting_original_or_replacement(self):
        self.start("replace")
        status = self.terminal()
        self.assertEqual(status["scratch_cleanup"]["state"], "retained")
        self.assertFalse(status["scratch_cleanup"]["removed"])
        self.assertEqual((self.job / "engine-scratch/preserve").read_bytes(), b"replacement data")
        self.assertTrue((self.job / "retained-original/cache/data").is_file())

    def tearDown(self):
        # A failed-owner fixture intentionally retains scratch. Its disposable
        # test resources are reclaimed only after atomic original-process exit;
        # this teardown never contributes to a positive cleanup assertion.
        for _, fd in self.owned_fds:
            try:
                signal.pidfd_send_signal(fd, signal.SIGKILL)
            except ProcessLookupError:
                pass
            select.select([fd], [], [], 2)
            os.close(fd)
        self.temp.cleanup()


if __name__ == "__main__":
    unittest.main(verbosity=2)

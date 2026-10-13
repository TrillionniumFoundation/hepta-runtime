#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Adversarial real native worker checks using private disposable file trees."""
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKER = ROOT / "src/mcp/runtime/search_worker.py"
if not WORKER.exists():
    WORKER = pathlib.Path(__file__).with_name("search_worker.py")
spec = importlib.util.spec_from_file_location("search_worker", WORKER)
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)


class SearchWorkerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-search-worker-")
        self.base = pathlib.Path(self.temp.name).resolve()
        self.root = self.base / "root"
        self.root.mkdir()
        self.state = self.base / "state"
        self.identity = "1" * 64
        self.owner = "2" * 64

    def tearDown(self):
        self.temp.cleanup()

    def request(self, action, **extra):
        value = {"action": action, "search_id": self.identity, "owner": self.owner,
                 "state_dir": str(self.state)}
        value.update(extra)
        return value

    def rpc(self, action, expect=True, **extra):
        output = subprocess.run([sys.executable, str(WORKER)], input=json.dumps(self.request(action, **extra)),
                                text=True, capture_output=True, timeout=8)
        if expect:
            self.assertEqual(output.returncode, 0, output.stderr)
            return json.loads(output.stdout)
        self.assertNotEqual(output.returncode, 0)
        self.assertEqual(json.loads(output.stderr), {"error": "native search request refused"})
        self.assertNotIn(str(self.root), output.stderr)
        return output

    def start(self, **extra):
        value = {"root": str(self.root), "allowed_roots": [str(self.root)], "query": "needle",
                 "kind": "content", "include_hidden": False,
                 "limits": {"results": 1000, "entries": 10000, "bytes": 64 * 1024 * 1024, "seconds": 10}}
        value.update(extra)
        return self.rpc("start", **value)

    def terminal(self):
        for _ in range(200):
            value = self.rpc("results", cursor=0, limit=32)
            if value["state"] in worker.TERMINAL:
                return value
            time.sleep(0.01)
        self.fail("search did not terminate")

    def test_native_content_path_utf8_binary_and_no_symlink_or_hardlink_escape(self):
        (self.root / "alpha.txt").write_text("needle 中文\nother\nneedle two\n")
        (self.root / ".hidden").write_text("needle hidden")
        (self.root / "binary").write_bytes(b"needle\0binary")
        outside = self.base / "outside"
        outside.write_text("needle secret")
        (self.root / "link").symlink_to(outside)
        os.link(outside, self.root / "hardlink")
        os.mkfifo(self.root / "fifo")
        self.start()
        value = self.terminal()
        self.assertEqual(value["state"], "completed")
        self.assertEqual([row["line"] for row in value["results"]], [1, 3])
        self.assertEqual(value["statistics"]["skipped_symlinks"], 1)
        self.assertEqual(value["statistics"]["skipped_hardlinks"], 1)
        self.assertEqual(value["statistics"]["skipped_binary_or_non_utf8"], 1)
        self.assertEqual(value["statistics"]["skipped_special"], 1)
        (self.root / "alpha.txt").write_text("different")
        self.assertEqual(self.rpc("results", cursor=0, limit=32), value)
        self.identity = "3" * 64
        self.start(kind="files", query="alpha")
        self.assertEqual(self.terminal()["results"], [{"path": "alpha.txt"}])

    def test_cursors_independent_terminal_snapshot_repeat_and_resource_limit(self):
        (self.root / "match.txt").write_text("needle\n" * 40)
        self.start(limits={"results": 40, "entries": 100, "bytes": 10000, "seconds": 10})
        value = self.terminal()
        self.assertEqual(value["state"], "limited")
        self.assertEqual(value["reason"], "result_limit")
        one = self.rpc("results", cursor=0, limit=7)
        two = self.rpc("results", cursor=7, limit=7)
        self.assertEqual(one["next_cursor"], 7)
        self.assertEqual(two["results"][0]["line"], 8)
        self.assertEqual(self.rpc("results", cursor=0, limit=7), one)
        self.rpc("results", expect=False, cursor=41, limit=7)

    def test_owner_denial_and_stop_cannot_cancel_someone_elses_job(self):
        (self.root / "input").write_text("needle")
        self.start()
        original = self.owner
        self.owner = "9" * 64
        self.rpc("results", expect=False)
        self.rpc("stop", expect=False)
        self.assertFalse((self.state / "search" / self.identity / "cancel").exists())
        self.owner = original
        self.assertEqual(self.terminal()["state"], "completed")

    def test_cooperative_cancellation_retains_stable_partial_snapshot(self):
        # Cancellation is deterministically exercised before scanning, without introducing a fake sleep option.
        request = self.request("start", root=str(self.root), allowed_roots=[str(self.root)], query="needle",
                               kind="content", include_hidden=False,
                               limits={"results": 1000, "entries": 10000, "bytes": 64*1024*1024, "seconds": 10})
        directory = self.base / "direct"
        directory.mkdir(mode=0o700)
        fd = worker.open_dir(str(directory))
        try:
            (directory / "cancel").write_text("")
            record = {"owner": self.owner, "state": "running", "deadline": time.time()+10}
            worker.search(fd, request, record)
            value = worker.read_json(fd, "record.json")
            self.assertEqual(value["state"], "cancelled")
            self.assertTrue(value["snapshot_ready"])
            self.assertEqual(worker.snapshot(fd, value, 0, 32)["results"], [])
        finally:
            os.close(fd)

    def test_root_authorization_symlink_state_and_interrupted_deadline(self):
        self.rpc("start", expect=False, root=str(self.base), allowed_roots=[str(self.root)], query="x",
                 kind="files", limits={"results": 10, "entries": 100, "bytes": 1000, "seconds": 1})
        link = self.base / "root-link"
        link.symlink_to(self.root)
        self.start(root=str(link), allowed_roots=[str(self.base)])
        self.assertEqual(self.terminal()["state"], "failed")
        directory = self.state / "search" / self.identity
        fd = worker.open_dir(str(directory))
        try:
            record = {"owner": self.owner, "state": "running", "deadline": time.time()-30}
            worker.write_json(fd, "record.json", record)
            interrupted = worker.reconcile(fd, record)
            self.assertEqual(interrupted["state"], "interrupted")
            self.assertFalse(interrupted["snapshot_ready"])
        finally:
            os.close(fd)

    def test_size_caps_and_entry_byte_limits(self):
        for i in range(4):
            (self.root / f"{i}.txt").write_text("needle" * 100)
        self.start(limits={"results": 100, "entries": 1, "bytes": 10000, "seconds": 10})
        value = self.terminal()
        self.assertEqual(value["reason"], "entry_limit")
        self.assertEqual(value["statistics"]["entries"], 1)
        self.identity = "3" * 64
        self.start(limits={"results": 100, "entries": 10, "bytes": 4, "seconds": 10})
        value = self.terminal()
        self.assertEqual(value["reason"], "read_bytes_limit")
        self.assertEqual(value["statistics"]["bytes"], 4)
        self.assertLess(len(json.dumps(value).encode()), 96*1024)

    def test_mac_case_and_unicode_normalization_protected_aliases_fail_closed(self):
        with mock.patch.object(worker.sys,"platform","darwin"):
            self.assertTrue(worker.protected_path("/private/tmp/Root/Secret/file", ["/private/tmp/root/secret"]))
            self.assertTrue(worker.protected_path("/private/tmp/root/Cafe\u0301/file", ["/private/tmp/root/CAFÉ"]))
            self.assertFalse(worker.protected_path("/private/tmp/root/secret-suffix/file", ["/private/tmp/root/secret"]))
        if sys.platform=="darwin":
            (self.root / "Secret").mkdir()
            (self.root / "Secret" / "private").write_text("needle forbidden")
            self.start(protected_roots=[str(self.root / "secret")])
            value=self.terminal()
            self.assertEqual(value["results"],[])
            self.assertEqual(value["statistics"]["skipped_protected"],1)


if __name__ == "__main__":
    unittest.main()

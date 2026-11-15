#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Private JSON pipe peers exercise the adapter; no REA engine is launched."""

import gzip
import hashlib
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rea_ghidra_mcp_client as adapter


PEER = r'''
import json, os, sys, time
mode = MODE
for raw in sys.stdin.buffer:
    request = json.loads(raw)
    if "id" not in request:
        continue
    response = {"jsonrpc": "2.0", "id": request["id"]}
    if request["method"] == "initialize":
        if mode == "bad-initialize":
            response["error"] = {"code": -32603, "message": "private pipe handshake refusal"}
        else:
            response["result"] = {"protocolVersion": "2026-07-28", "capabilities": {},
                                  "serverInfo": {"name": "private-pipe-peer", "version": "0"}}
    else:
        name = request["params"]["name"]
        if name == "opaque":
            text = '{ "z": 2, "a": 1 }'
        elif name == "error":
            text = '{"error":{"code":"private-pipe-refusal"}}'
        elif name == "environment":
            text = json.dumps(dict(os.environ))
        elif name == "rea_static_read":
            text = json.dumps({"complete": mode != "incomplete", "origin": "private-pipe-peer"})
        else:
            raise AssertionError("unexpected private pipe request")
        response["result"] = {"content": [{"type": "text", "text": text}]}
        if name == "error":
            response["result"]["isError"] = True
    print(json.dumps(response, separators=(",", ":")), flush=True)
if mode == "stubborn-eof":
    time.sleep(30)
'''


@unittest.skipUnless(sys.platform.startswith("linux") and hasattr(os, "pidfd_open"),
                     "controller ownership checks require Linux pidfds")
class GhidraMcpClientTests(unittest.TestCase):
    def peer(self, root, mode="normal"):
        path = root / "private-pipe-peer"
        path.write_text("#!" + sys.executable + "\n" + PEER.replace("MODE", repr(mode), 1))
        path.chmod(0o500)
        (root / "authority").mkdir()
        (root / "config.json").write_text("{}\n")
        return path

    def emergency_close(self, client):
        transport = getattr(client, "_client", None)
        process = getattr(transport, "process", None)
        if process is not None:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=3)
            for stream in (process.stdin, process.stdout):
                if stream is not None and not stream.closed:
                    stream.close()
        reader = getattr(transport, "reader", None)
        if reader is not None and reader.ident is not None:
            reader.join(timeout=3)
        for name in ("stderr", "wire"):
            stream = getattr(transport, name, None)
            if stream is not None and not stream.closed:
                stream.close()

    def assert_capture(self, client, record):
        self.assertFalse(record["qualified"])
        self.assertEqual(record["session_id"], client.session_id)
        self.assertEqual(Path(record["capture_root"]), client.capture_root)
        self.assertEqual(json.loads((client.capture_root / "session.json").read_bytes()), record)
        for field in ("launch", "close", "wire_index", "stderr"):
            pin = record["artifacts"][field]
            raw = (client.root / pin["path"]).read_bytes()
            self.assertEqual(len(raw), pin["bytes"])
            self.assertEqual(hashlib.sha256(raw).hexdigest(), pin["sha256"])
        self.assertIs(client.close(), record)

    def test_interfaces_original_wire_minimal_environment_and_separate_restart_owners(self):
        before_fds = set(os.listdir("/proc/self/fd"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = self.peer(root)
            with mock.patch.dict(os.environ, {"HEPTA_TEST_DO_NOT_CAPTURE": "unrelated-test-credential"}):
                client = adapter.Mcp(runtime, root)
            try:
                result = client.raw("opaque", {})
                self.assertEqual(result["content"][0]["text"], '{ "z": 2, "a": 1 }')
                self.assertEqual(client.call("opaque", {}), {"z": 2, "a": 1})
                self.assertNotIn("HEPTA_TEST_DO_NOT_CAPTURE", client.call("environment", {}))
                self.assertEqual(client.complete({"idempotency_key": "private-test-only"}),
                                 {"complete": True, "origin": "private-pipe-peer"})
                self.assertTrue(client.raw("error", {})["isError"])
                with self.assertRaises(adapter.q.QualificationError):
                    client.call("error", {})
                record = client.close()
                self.assertTrue(record["normal_close"])
                self.assertTrue(record["construction_succeeded"])
                self.assert_capture(client, record)
                launch = json.loads((client.capture_root / "launch.json").read_bytes())
                self.assertEqual(launch["environment"], adapter.native_environment(root))
                self.assertEqual(set(launch["environment"]), {"PATH", "LANG", "HEPTA_EFFECT_OWNER_FENCE_DIR",
                                                           "HEPTA_EFFECT_OWNER_SELF", "HEPTA_EFFECT_OWNER_FENCE_REQUIRED"})
                self.assertEqual(launch["argv"], [str(runtime), "mcp", "--runtime-config", str(root / "config.json")])
                self.assertEqual(launch["cwd"], str(root))
                self.assertNotIn("unrelated-test-credential", (client.capture_root / "launch.json").read_text())
                replies = []
                for raw in (client.capture_root / "wire.jsonl").read_bytes().splitlines():
                    entry = json.loads(raw)
                    frame = gzip.decompress((client.capture_root / entry["path"]).read_bytes())
                    self.assertEqual(hashlib.sha256(frame).hexdigest(), entry["raw_sha256"])
                    if entry["direction"] == "received":
                        replies.append(json.loads(frame))
                self.assertIn('{ "z": 2, "a": 1 }', [row.get("result", {}).get("content", [{}])[0].get("text") for row in replies])
                original_wire = (client.capture_root / "wire.jsonl").read_bytes()
                restarted = adapter.Mcp(runtime, root)
                try:
                    newer = restarted.close()
                    self.assertTrue(newer["normal_close"])
                    self.assertNotEqual(newer["session_id"], record["session_id"])
                    self.assertNotEqual(newer["owner_close"]["owner"], record["owner_close"]["owner"])
                    self.assert_capture(restarted, newer)
                finally:
                    self.emergency_close(restarted)
                self.assertEqual((client.capture_root / "wire.jsonl").read_bytes(), original_wire)
            finally:
                self.emergency_close(client)
        self.assertEqual(set(os.listdir("/proc/self/fd")), before_fds)

    def test_eof_timeout_records_actual_owned_group_signal_and_refuses_normal_close(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            client = adapter.Mcp(self.peer(root, "stubborn-eof"), root)
            real_killpg = os.killpg
            try:
                with mock.patch.object(adapter.q, "EOF_SECONDS", 0.05), \
                        mock.patch.object(adapter.q.os, "killpg", wraps=real_killpg) as signals:
                    record = client.close()
                self.assertFalse(record["normal_close"])
                close = record["owner_close"]
                self.assertEqual(close["forced_cleanup"], ["SIGTERM"])
                self.assertEqual(close["returncode"], -signal.SIGTERM)
                self.assertTrue(close["owner_pidfd_exited"] and close["process_group_gone"] and close["reader_stopped"])
                self.assertEqual([row.args for row in signals.call_args_list if row.args[1] != 0],
                                 [(close["owner"]["pid"], signal.SIGTERM)])
                self.assertFalse(adapter.normal_owner_close(close))
                self.assert_capture(client, record)
            finally:
                self.emergency_close(client)

    def test_failed_handshake_is_closed_and_retains_a_failed_session_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = self.peer(root, "bad-initialize")
            client = adapter.Mcp.__new__(adapter.Mcp)
            try:
                with self.assertRaisesRegex(adapter.q.QualificationError, "MCP initialize failed"):
                    adapter.Mcp.__init__(client, runtime, root)
                record = client.close_record
                self.assertFalse(record["construction_succeeded"])
                self.assertFalse(record["normal_close"])
                self.assertIsNotNone(record["construction_error"])
                self.assertEqual(record["owner_close"]["returncode"], 0)
                self.assertTrue(record["owner_close"]["owner_pidfd_exited"])
                self.assert_capture(client, record)
            finally:
                self.emergency_close(client)

    def test_approved_partial_constructor_cleanup_is_retained_and_not_reclassified(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = self.peer(root)
            client = adapter.Mcp.__new__(adapter.Mcp)
            original = OSError("private pidfd fault")
            try:
                with mock.patch.object(adapter.q.os, "pidfd_open", side_effect=original), \
                        self.assertRaises(OSError) as raised:
                    adapter.Mcp.__init__(client, runtime, root)
                self.assertIs(raised.exception, original)
                record = client.close_record
                self.assertFalse(record["normal_close"])
                self.assertFalse(record["construction_succeeded"])
                self.assertFalse(record["owner_close"]["construction_succeeded"])
                self.assertNotIn("returncode", record["owner_close"])
                self.assertTrue(record["owner_close"]["cleanup_complete"])
                self.assertIsNotNone(record["artifacts"]["initialization_failure"])
                self.assertIsNone(record["artifacts"]["close"])
                self.assertEqual(json.loads((client.capture_root / "session.json").read_bytes()), record)
                self.assertIs(client.close(), record)
                self.assertFalse(hasattr(client._client, "pidfd"))
            finally:
                self.emergency_close(client)

    def test_complete_polls_only_within_its_total_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            client = adapter.Mcp(self.peer(root, "incomplete"), root)
            try:
                with mock.patch.object(adapter, "COMPLETE_SECONDS", 0.05), \
                        mock.patch.object(client._client, "receive", wraps=client._client.receive) as received, \
                        self.assertRaises(TimeoutError):
                    client.complete({"idempotency_key": "private-incomplete"})
                self.assertTrue(received.call_args_list)
                self.assertTrue(all(0 < call.kwargs["seconds"] <= 0.05 for call in received.call_args_list))
                self.assertTrue(client.close()["normal_close"])
            finally:
                self.emergency_close(client)


if __name__ == "__main__":
    unittest.main()

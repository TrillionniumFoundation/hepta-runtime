#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
import http.server
import json
import os
import pathlib
import queue
import socket
import subprocess
import sys
import tempfile
import threading
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class Fake(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        method, ident = request.get("method"), request.get("id")
        with self.server.condition:
            self.server.seen.append({
                "method": method, "id": ident,
                "session": self.headers.get("Mcp-Session-Id"),
                "protocol": self.headers.get("MCP-Protocol-Version"),
                "token": self.headers.get("X-Hepta-Runtime-Token"),
            })
            if method == "initialize":
                self.server.initializations += 1
                session = "session-fixture" if self.server.initializations == 1 else "session-second"
            self.server.condition.notify_all()
        if method in ("notifications/initialized", "notifications/cancelled"):
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if method == "initialize":
            self.server.initialize_gate.wait(10)
            self._reply({"jsonrpc": "2.0", "id": ident, "result": {
                "protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                "serverInfo": {"name": "private", "version": "1"},
            }}, session=session, sse=True)
            return
        if method == "tools/list":
            self._reply({"jsonrpc": "2.0", "id": ident, "result": {"tools": [
                {"name": "host_list", "inputSchema": {"type": "object"}},
                {"name": "shell_start", "inputSchema": {"type": "object"}},
            ]}})
            return
        if method == "tools/call" and request.get("params", {}).get("name") == "host_list":
            self.server.call_gate.wait(10)
            if self.server.wrong_id:
                ident = "unrelated-response"
            self._reply({"jsonrpc": "2.0", "id": ident, "result": {"content": [
                {"type": "text", "text": json.dumps({"hosts": [{"name": "main"}]})},
            ]}}, session=self.server.call_session)
            return
        self._reply({"jsonrpc": "2.0", "id": ident, "error": {"code": -32601, "message": "unknown"}})

    def _reply(self, value, session=None, sse=False):
        encoded = json.dumps(value, separators=(",", ":"))
        body = ("data: " + encoded + "\n\n").encode() if sse else encoded.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream" if sse else "application/json")
        self.send_header("Content-Length", str(len(body)))
        if session:
            self.send_header("Mcp-Session-Id", session)
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass


class FakeServer(http.server.ThreadingHTTPServer):
    request_queue_size = socket.SOMAXCONN

    def __init__(self):
        super().__init__(("127.0.0.1", 0), Fake)
        self.condition = threading.Condition()
        self.seen = []
        self.initializations = 0
        self.initialize_gate = threading.Event()
        self.initialize_gate.set()
        self.call_gate = threading.Event()
        self.call_gate.set()
        self.wrong_id = False
        self.call_session = None

    def records(self, method):
        with self.condition:
            return [item for item in self.seen if item["method"] == method]

    def wait_seen(self, method, count, timeout=5):
        with self.condition:
            return self.condition.wait_for(
                lambda: sum(item["method"] == method for item in self.seen) >= count,
                timeout=timeout,
            )


class Stdio(unittest.TestCase):
    bridge = ROOT / "deploy/chatgpt_mcp_bridge.py"

    def setUp(self):
        self.server = FakeServer()
        self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.server_thread.start()
        self.temp = tempfile.TemporaryDirectory()
        token = pathlib.Path(self.temp.name) / "token"
        token.write_text("fixture-secret")
        os.chmod(token, 0o600)
        self.proc = subprocess.Popen(
            [sys.executable, str(self.bridge), "--stdio", "--upstream",
             f"http://127.0.0.1:{self.server.server_port}/mcp", "--token-file", str(token)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1,
        )
        self.replies = queue.Queue()

        def read_replies():
            for line in self.proc.stdout:
                self.replies.put(json.loads(line))

        self.reader = threading.Thread(target=read_replies, daemon=True)
        self.reader.start()

    def tearDown(self):
        self.server.initialize_gate.set()
        self.server.call_gate.set()
        if self.proc.poll() is None:
            self.proc.terminate()
            self.proc.wait(timeout=5)
        self.reader.join(timeout=2)
        for stream in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
            stream.close()
        self.server.shutdown()
        self.server.server_close()
        self.server_thread.join(timeout=2)
        self.temp.cleanup()

    def send(self, value):
        self.proc.stdin.write(json.dumps(value, separators=(",", ":")) + "\n")
        self.proc.stdin.flush()

    def receive(self):
        try:
            return self.replies.get(timeout=5)
        except queue.Empty:
            self.fail(f"bridge produced no response; exit={self.proc.poll()}")

    def initialize(self, ident=1):
        self.send({"jsonrpc": "2.0", "id": ident, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "fixture", "version": "1"},
        }})

    def read_hosts(self, ident):
        self.send({"jsonrpc": "2.0", "id": ident, "method": "tools/call",
                   "params": {"name": "host_list", "arguments": {}}})

    def test_stdio_bridge_retains_session_and_filters_tools(self):
        self.initialize()
        self.assertEqual(self.receive()["result"]["serverInfo"]["name"], "hepta-chatgpt-readonly")
        self.send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        tools = self.receive()["result"]["tools"]
        self.assertEqual([item["name"] for item in tools], ["host_list"])
        self.assertTrue(tools[0]["annotations"]["readOnlyHint"])
        self.assertFalse(tools[0]["annotations"]["destructiveHint"])
        self.send({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                   "params": {"name": "shell_start", "arguments": {}}})
        self.assertEqual(self.receive()["error"]["code"], -32601)
        self.read_hosts(4)
        self.assertIn("hosts", self.receive()["result"]["content"][0]["text"])
        upstream = self.server.records("tools/list") + self.server.records("tools/call")
        self.assertTrue(all(item["session"] == "session-fixture" for item in upstream))
        self.assertTrue(all(item["protocol"] == "2025-06-18" for item in upstream))
        self.assertTrue(all(item["token"] == "fixture-secret" for item in upstream))
        self.assertEqual(len(self.server.records("tools/call")), 1)

    def test_thirty_two_reads_overlap_after_one_pipelined_initialize(self):
        self.server.initialize_gate.clear()
        self.server.call_gate.clear()
        self.initialize()
        self.assertTrue(self.server.wait_seen("initialize", 1))
        for ident in range(2, 34):
            self.read_hosts(ident)
        self.assertFalse(self.server.wait_seen("tools/call", 1, timeout=0.1))
        self.server.initialize_gate.set()
        self.assertEqual(self.receive()["id"], 1)
        self.assertTrue(self.server.wait_seen("tools/call", 32))
        self.assertTrue(all(item["session"] == "session-fixture" for item in self.server.records("tools/call")))
        self.server.call_gate.set()
        replies = [self.receive() for _ in range(32)]
        self.assertEqual({item["id"] for item in replies}, set(range(2, 34)))
        self.assertTrue(all("result" in item for item in replies))

    def test_reinitialize_waits_for_original_reads_and_binds_only_later_reads(self):
        self.initialize()
        self.receive()
        self.server.call_gate.clear()
        self.read_hosts(2)
        self.assertTrue(self.server.wait_seen("tools/call", 1))
        self.initialize(3)
        self.read_hosts(4)
        self.assertFalse(self.server.wait_seen("initialize", 2, timeout=0.1))
        self.server.call_gate.set()
        self.assertEqual({self.receive()["id"] for _ in range(3)}, {2, 3, 4})
        reads = {item["id"]: item["session"] for item in self.server.records("tools/call")}
        self.assertEqual(reads, {2: "session-fixture", 4: "session-second"})

    def test_eof_joins_original_connections_and_preserves_every_response(self):
        self.initialize()
        self.receive()
        self.server.call_gate.clear()
        for ident in range(2, 34):
            self.read_hosts(ident)
        self.assertTrue(self.server.wait_seen("tools/call", 32))
        self.proc.stdin.close()
        self.assertIsNone(self.proc.poll())
        self.server.call_gate.set()
        replies = [self.receive() for _ in range(32)]
        self.assertEqual({item["id"] for item in replies}, set(range(2, 34)))
        self.assertEqual(self.proc.wait(timeout=5), 0)
        self.reader.join(timeout=2)
        self.assertTrue(self.replies.empty())
        self.assertEqual(len(self.server.records("tools/call")), 32)
        self.assertEqual(self.proc.stderr.read(), "")

    def test_active_id_is_not_rebound_and_completed_id_is_reusable(self):
        self.initialize()
        self.receive()
        self.server.call_gate.clear()
        self.read_hosts(2)
        self.assertTrue(self.server.wait_seen("tools/call", 1))
        self.read_hosts(2)
        self.assertEqual(self.receive()["error"]["code"], -32600)
        self.assertEqual(len(self.server.records("tools/call")), 1)
        self.server.call_gate.set()
        self.assertIn("result", self.receive())
        for _ in range(32):
            self.read_hosts(2)
            self.assertIn("result", self.receive())
        self.assertEqual(len(self.server.records("tools/call")), 33)

    def test_wrong_response_id_fails_original_without_replay_or_lost_ownership(self):
        self.initialize()
        self.receive()
        self.server.wrong_id = True
        self.read_hosts(2)
        response = self.receive()
        self.assertEqual(response["id"], 2)
        self.assertEqual(response["error"]["code"], -32000)
        self.assertEqual(len(self.server.records("tools/call")), 1)
        self.server.wrong_id = False
        self.read_hosts(2)
        self.assertIn("result", self.receive())

    def test_ordinary_response_cannot_replace_the_initialize_owned_session(self):
        self.initialize()
        self.receive()
        self.server.call_session = "unowned-session"
        self.read_hosts(2)
        self.receive()
        self.read_hosts(3)
        self.receive()
        self.assertTrue(all(item["session"] == "session-fixture" for item in self.server.records("tools/call")))

    def test_cancellation_notification_does_not_wait_behind_the_original_read(self):
        self.initialize()
        self.receive()
        self.server.call_gate.clear()
        self.read_hosts(2)
        self.assertTrue(self.server.wait_seen("tools/call", 1))
        self.send({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 2}})
        self.assertTrue(self.server.wait_seen("notifications/cancelled", 1))
        self.server.call_gate.set()
        self.assertEqual(self.receive()["id"], 2)


class PackagedStdio(Stdio):
    bridge = ROOT / "deploy/readonly-bridge/bridge.py"


if __name__ == "__main__":
    unittest.main(verbosity=2)

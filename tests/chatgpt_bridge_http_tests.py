#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""The seven-tool Unix HTTP deployment keeps its contract during real fan-out."""
import concurrent.futures
import http.client
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from chatgpt_bridge_stdio_tests import FakeServer

ROOT = Path(__file__).resolve().parents[1]


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=8)
        self.path = str(path)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


class ReadonlyHTTP(unittest.TestCase):
    bridge = ROOT / "deploy/chatgpt_mcp_bridge.py"

    def setUp(self):
        self.backend = FakeServer()
        self.backend_thread = threading.Thread(target=self.backend.serve_forever, daemon=True)
        self.backend_thread.start()
        self.temporary = tempfile.TemporaryDirectory(prefix="hepta-http-")
        self.root = Path(self.temporary.name)
        self.token = self.root / "token"
        self.token.write_text("fixture-secret")
        self.token.chmod(0o600)
        self.path = self.root / "bridge.sock"
        self.log = (self.root / "bridge.log").open("wb")
        self.process = subprocess.Popen(
            [sys.executable, str(self.bridge), "--socket", str(self.path),
             "--upstream", f"http://127.0.0.1:{self.backend.server_port}/mcp",
             "--token-file", str(self.token)],
            stdin=subprocess.DEVNULL, stdout=self.log, stderr=self.log,
        )
        self.addCleanup(self.cleanup)
        deadline = time.monotonic() + 5
        while not self.path.exists() and time.monotonic() < deadline:
            if self.process.poll() is not None:
                self.fail((self.root / "bridge.log").read_text())
            time.sleep(.01)
        self.assertTrue(self.path.exists(), "private Unix HTTP socket was not created")
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.root.stat().st_mode & 0o777, 0o700)

    def cleanup(self):
        self.backend.initialize_gate.set()
        self.backend.call_gate.set()
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)
        self.log.close()
        self.backend.shutdown()
        self.backend.server_close()
        self.backend_thread.join(timeout=2)
        self.temporary.cleanup()

    def request(self, method="POST", path="/mcp", value=None, headers=None):
        client = UnixHTTPConnection(self.path)
        try:
            body = None if value is None else json.dumps(value)
            client.request(method, path, body=body,
                           headers={"Content-Type": "application/json", "Connection": "close", **(headers or {})})
            response = client.getresponse()
            raw = response.read()
            result = None
            if raw:
                if "text/event-stream" in (response.getheader("Content-Type") or ""):
                    result = [json.loads(line[5:].strip()) for line in raw.decode().splitlines()
                              if line.startswith("data:") and line[5:].strip()][-1]
                else:
                    result = json.loads(raw)
            return response.status, dict(response.getheaders()), result
        finally:
            client.close()

    def test_thirty_two_original_reads_overlap_without_expanding_the_catalog(self):
        status, headers, initialized = self.request(value={
            "jsonrpc": "2.0", "id": "init", "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {}},
        })
        self.assertEqual(status, 200)
        self.assertEqual(initialized["result"]["serverInfo"]["name"], "hepta-chatgpt-readonly")
        common = {"Mcp-Session-Id": headers["Mcp-Session-Id"], "MCP-Protocol-Version": "2025-06-18",
                  "X-Hepta-Runtime-Token": "caller-token-must-not-be-forwarded",
                  "Authorization": "Bearer caller-credential-must-not-be-forwarded"}
        _, _, catalog = self.request(value={"jsonrpc": "2.0", "id": "catalog", "method": "tools/list"}, headers=common)
        self.assertEqual([tool["name"] for tool in catalog["result"]["tools"]], ["host_list"])
        self.assertTrue(catalog["result"]["tools"][0]["annotations"]["readOnlyHint"])
        self.backend.call_gate.clear()
        with concurrent.futures.ThreadPoolExecutor(max_workers=32) as workers:
            original = [workers.submit(self.request, value={
                "jsonrpc": "2.0", "id": ident, "method": "tools/call",
                "params": {"name": "host_list", "arguments": {}},
            }, headers=common) for ident in range(32)]
            try:
                self.assertTrue(self.backend.wait_seen("tools/call", 32), "all 32 reads must enter before any is released")
                self.assertTrue(all(not future.done() for future in original))
            finally:
                self.backend.call_gate.set()
            replies = [future.result(timeout=8) for future in original]
        self.assertEqual([value[2]["id"] for value in replies], list(range(32)))
        self.assertTrue(all(status == 200 and "result" in value for status, _, value in replies))
        receipts = self.backend.records("tools/call")
        self.assertEqual(len(receipts), 32)
        self.assertEqual({item["id"] for item in receipts}, set(range(32)))
        self.assertTrue(all(item["session"] == "session-fixture" and item["token"] == "fixture-secret"
                            for item in receipts))
        _, _, denied = self.request(value={"jsonrpc": "2.0", "id": "denied", "method": "tools/call",
                                          "params": {"name": "process_start", "arguments": {}}}, headers=common)
        self.assertEqual(denied["error"]["code"], -32601)
        self.assertEqual(len(self.backend.records("tools/call")), 32)

    def test_http_discovery_reports_oauth_absence_without_exposing_more_tools(self):
        self.assertEqual(self.request(method="GET", path="/healthz")[2],
                         {"ok": True, "mode": "read_only", "tools": 7})
        self.assertEqual(self.request(method="GET")[0], 405)
        for path in ("/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-protected-resource"):
            self.assertEqual(self.request(method="GET", path=path)[0], 404)
        self.assertEqual(self.backend.seen, [])


class PackagedReadonlyHTTP(ReadonlyHTTP):
    bridge = ROOT / "deploy/readonly-bridge/bridge.py"


if __name__ == "__main__":
    unittest.main()

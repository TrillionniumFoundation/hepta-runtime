#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""The readiness probe must finish before a persistent SSE connection closes."""
import importlib.util
import io
from pathlib import Path
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import urllib.request

spec = importlib.util.spec_from_file_location(
    "runtime_http_probe", Path(__file__).resolve().parents[1] / "deploy/runtime_http_probe.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class Response(io.BytesIO):
    def __init__(self, data, content_type="text/event-stream", status=200):
        super().__init__(data)
        self.headers = {"Content-Type": content_type}
        self.status = status


class ProbeTests(unittest.TestCase):
    def test_persistent_stream_returns_original_reply_without_waiting_for_eof(self):
        release = threading.Event()

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args):
                pass

            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                self.wfile.write(b': keepalive\n\ndata: {"method":"ping"}\n\n'
                                 b'data: {"jsonrpc":"2.0","id":7,"result":{}}\n\n')
                self.wfile.flush()
                release.wait(5)
                self.close_connection = True

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with urllib.request.urlopen("http://127.0.0.1:%s/" % server.server_port,
                                        timeout=1) as response:
                self.assertEqual(probe.read_rpc(response, 7)["id"], 7)
            self.assertFalse(release.is_set())
        finally:
            release.set()
            server.shutdown()
            server.server_close()
            thread.join()

    def test_multiline_sse_ignores_unrelated_response(self):
        response = Response(b'data:\n\ndata: {"id":8}\n\ndata: {"id":7,\ndata: "result":{}}\n\n')
        self.assertEqual(probe.read_rpc(response, 7), {"id": 7, "result": {}})

    def test_json_response_and_mismatched_identity(self):
        self.assertEqual(probe.read_rpc(Response(b'{"id":7}', "application/json"), 7),
                         {"id": 7})
        with self.assertRaises(RuntimeError):
            probe.read_rpc(Response(b'{"id":8}', "application/json"), 7)

    def test_acknowledgment_is_not_a_request_result(self):
        self.assertIsNone(probe.read_rpc(Response(b"", status=202), None))
        with self.assertRaises(RuntimeError):
            probe.read_rpc(Response(b"", status=202), 7)

    def test_missing_original_response_fails(self):
        with self.assertRaises(RuntimeError):
            probe.read_rpc(Response(b'data: {"method":"ping"}\n\n'), 7)


if __name__ == "__main__":
    unittest.main()

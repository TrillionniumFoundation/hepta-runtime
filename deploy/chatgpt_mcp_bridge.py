#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Read-only ChatGPT MCP facade for the private hepta-runtime.

Listens only on an account-owned Unix socket. It never accepts caller credentials
for the backend: the existing private runtime token is read locally and injected
only into the loopback upstream request. Tool discovery is allowlisted and every
tools/call is checked independently before forwarding.
"""
import argparse
import http.client
import http.server
import json
import os
import pathlib
import socketserver
import stat
import sys
import threading
import urllib.parse

MAX_BODY = 1024 * 1024
ALLOWED_TOOLS = {
    "host_list",
    "process_status",
    "file_info",
    "stream_handoff_list",
    "stream_handoff_status",
    "stream_handoff_read",
    "document_read",
}
ALLOWED_METHODS = {
    "initialize",
    "notifications/initialized",
    "notifications/cancelled",
    "ping",
    "tools/list",
    "tools/call",
}


def private_file(path: pathlib.Path) -> bytes:
    path = path.expanduser().resolve(strict=True)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise PermissionError(f"private account-owned regular file required: {path}")
    return path.read_bytes()


def jsonrpc_error(item, code, message):
    return {"jsonrpc": "2.0", "id": item.get("id"), "error": {"code": code, "message": message}}


def inspect_request(item):
    if not isinstance(item, dict):
        return jsonrpc_error({}, -32600, "Invalid Request")
    method = item.get("method")
    if method not in ALLOWED_METHODS:
        return jsonrpc_error(item, -32601, "Method not exposed by read-only facade")
    if method == "tools/call":
        params = item.get("params")
        if not isinstance(params, dict) or params.get("name") not in ALLOWED_TOOLS:
            return jsonrpc_error(item, -32601, "Tool not exposed by read-only facade")
    return None


def filter_tool(tool):
    tool = dict(tool)
    annotations = dict(tool.get("annotations") or {})
    annotations.update({
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    })
    tool["annotations"] = annotations
    return tool


def filter_response(request, response):
    if isinstance(request, list):
        req_by_id = {json.dumps(v.get("id"), sort_keys=True): v for v in request if isinstance(v, dict) and "id" in v}
        values = response if isinstance(response, list) else [response]
        return [filter_response(req_by_id.get(json.dumps(v.get("id"), sort_keys=True), {}), v) if isinstance(v, dict) else v for v in values]
    if not isinstance(request, dict) or not isinstance(response, dict):
        return response
    method = request.get("method")
    result = response.get("result")
    if method == "tools/list" and isinstance(result, dict) and isinstance(result.get("tools"), list):
        response = dict(response)
        result = dict(result)
        result["tools"] = [filter_tool(t) for t in result["tools"] if isinstance(t, dict) and t.get("name") in ALLOWED_TOOLS]
        response["result"] = result
    elif method == "initialize" and isinstance(result, dict):
        response = dict(response)
        result = dict(result)
        info = dict(result.get("serverInfo") or {})
        info["name"] = "hepta-chatgpt-readonly"
        result["serverInfo"] = info
        response["result"] = result
    return response


class UnixThreadingHTTPServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = False


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "hepta-chatgpt-readonly/1"

    def log_message(self, fmt, *args):
        # Never log tool arguments, headers, tokens, or response bodies.
        print(f"bridge {self.client_address!r} {fmt % args}", flush=True)

    def _send_json(self, status, value, extra=None):
        data = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        if extra:
            for key, val in extra.items():
                if key.lower() in ("mcp-session-id",):
                    self.send_header(key, val)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/healthz":
            self._send_json(200, {"ok": True, "mode": "read_only", "tools": len(ALLOWED_TOOLS)})
        else:
            self._send_json(405, {"error": "POST /mcp only"})

    def do_POST(self):
        if self.path != "/mcp":
            self._send_json(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send_json(400, {"error": "invalid content length"})
            return
        if length <= 0 or length > MAX_BODY:
            self._send_json(413, {"error": "bounded JSON-RPC body required"})
            return
        raw = self.rfile.read(length)
        try:
            request = json.loads(raw)
        except json.JSONDecodeError:
            self._send_json(400, {"error": "invalid JSON"})
            return
        items = request if isinstance(request, list) else [request]
        blocked = [inspect_request(v) for v in items]
        if any(v is not None for v in blocked):
            replies = [err for err in blocked if err is not None]
            self._send_json(200, replies if isinstance(request, list) else replies[0])
            return

        token = self.server.token
        upstream = urllib.parse.urlsplit(self.server.upstream)
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "X-Hepta-Runtime-Token": token,
        }
        session = self.headers.get("Mcp-Session-Id")
        if session:
            headers["Mcp-Session-Id"] = session
        protocol = self.headers.get("MCP-Protocol-Version")
        if protocol:
            headers["MCP-Protocol-Version"] = protocol
        # Intentionally do not forward caller Authorization/Cookie/Forwarded headers.
        connection = http.client.HTTPConnection(upstream.hostname, upstream.port, timeout=30)
        try:
            connection.request("POST", upstream.path or "/mcp", body=raw, headers=headers)
            resp = connection.getresponse()
            body = resp.read(MAX_BODY + 1)
            if len(body) > MAX_BODY:
                self._send_json(502, {"error": "upstream response exceeds bridge limit"})
                return
            if resp.status == 202 or not body:
                self.send_response(resp.status)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            content_type = (resp.getheader("Content-Type") or "").lower()
            out_headers = {}
            mcp_session = resp.getheader("Mcp-Session-Id")
            if mcp_session:
                out_headers["Mcp-Session-Id"] = mcp_session
            if "text/event-stream" in content_type:
                lines = []
                for line in body.decode("utf-8").splitlines():
                    if line.startswith("data:") and line[5:].strip():
                        value = json.loads(line[5:].strip())
                        value = filter_response(request, value)
                        line = "data: " + json.dumps(value, separators=(",", ":"))
                    lines.append(line)
                data = ("\n".join(lines) + "\n").encode()
                self.send_response(resp.status)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Content-Length", str(len(data)))
                for key, val in out_headers.items():
                    self.send_header(key, val)
                self.end_headers()
                self.wfile.write(data)
                return
            if "application/json" not in content_type:
                self._send_json(502, {"error": "unexpected upstream response type"})
                return
            value = json.loads(body)
            value = filter_response(request, value)
            self._send_json(resp.status, value, out_headers)
        except Exception as exc:
            self._send_json(502, {"jsonrpc": "2.0", "id": request.get("id") if isinstance(request, dict) else None,
                                  "error": {"code": -32000, "message": "private MCP upstream unavailable"}})
        finally:
            connection.close()


def _stdio_emit(value):
    data = json.dumps(value, separators=(",", ":")).encode()
    if len(data) > MAX_BODY:
        raise ValueError("stdio response exceeds bridge limit")
    sys.stdout.buffer.write(data + b"\n")
    sys.stdout.buffer.flush()


def _request_has_id(request):
    if isinstance(request, dict):
        return "id" in request
    if isinstance(request, list):
        return any(isinstance(item, dict) and "id" in item for item in request)
    return True


def serve_stdio(upstream_url, token):
    """Serve newline-delimited MCP JSON-RPC on stdio for tunnel-client.

    The facade remains the policy owner: every request is inspected before the
    loopback backend is contacted. MCP session and protocol headers are retained
    inside this one bridge process and never supplied by the tunnel caller.
    """
    upstream = urllib.parse.urlsplit(upstream_url)
    if upstream.scheme != "http" or upstream.hostname not in ("127.0.0.1", "localhost"):
        raise ValueError("stdio bridge upstream must remain loopback HTTP")
    session = None
    protocol = None
    while True:
        raw = sys.stdin.buffer.readline(MAX_BODY + 2)
        if not raw:
            return
        if len(raw) > MAX_BODY + 1 or not raw.endswith(b"\n"):
            while raw and not raw.endswith(b"\n"):
                raw = sys.stdin.buffer.readline(MAX_BODY + 2)
            _stdio_emit({"jsonrpc":"2.0","id":None,"error":{"code":-32600,"message":"bounded JSON-RPC line required"}})
            continue
        raw = raw.rstrip(b"\r\n")
        if not raw:
            _stdio_emit({"jsonrpc":"2.0","id":None,"error":{"code":-32600,"message":"Invalid Request"}})
            continue
        try:
            request = json.loads(raw)
        except json.JSONDecodeError:
            _stdio_emit({"jsonrpc":"2.0","id":None,"error":{"code":-32700,"message":"Parse error"}})
            continue
        items = request if isinstance(request, list) else [request]
        blocked = [inspect_request(value) for value in items]
        if any(value is not None for value in blocked):
            replies = []
            for original, error in zip(items, blocked):
                if error is not None and isinstance(original, dict) and "id" in original:
                    replies.append(error)
            if replies:
                _stdio_emit(replies if isinstance(request, list) else replies[0])
            continue
        headers = {
            "Content-Type":"application/json",
            "Accept":"application/json, text/event-stream",
            "X-Hepta-Runtime-Token":token,
        }
        if session:
            headers["Mcp-Session-Id"] = session
        if protocol:
            headers["MCP-Protocol-Version"] = protocol
        connection = http.client.HTTPConnection(upstream.hostname, upstream.port, timeout=30)
        try:
            connection.request("POST", upstream.path or "/mcp", body=raw, headers=headers)
            response = connection.getresponse()
            body = response.read(MAX_BODY + 1)
            if len(body) > MAX_BODY:
                raise ValueError("upstream response exceeds bridge limit")
            returned_session = response.getheader("Mcp-Session-Id")
            if returned_session:
                session = returned_session
            if response.status == 202 or not body:
                continue
            content_type = (response.getheader("Content-Type") or "").lower()
            values = []
            if "text/event-stream" in content_type:
                for line in body.decode("utf-8").splitlines():
                    if line.startswith("data:") and line[5:].strip():
                        values.append(json.loads(line[5:].strip()))
            elif "application/json" in content_type:
                values.append(json.loads(body))
            else:
                raise ValueError("unexpected upstream response type")
            for value in values:
                filtered = filter_response(request, value)
                if isinstance(request, dict) and request.get("method") == "initialize":
                    result = filtered.get("result") if isinstance(filtered, dict) else None
                    if isinstance(result, dict) and isinstance(result.get("protocolVersion"), str):
                        protocol = result["protocolVersion"]
                if _request_has_id(request) or (isinstance(filtered, dict) and "method" in filtered):
                    _stdio_emit(filtered)
        except Exception:
            if _request_has_id(request):
                if isinstance(request, dict):
                    ident = request.get("id")
                    _stdio_emit({"jsonrpc":"2.0","id":ident,"error":{"code":-32000,"message":"private MCP upstream unavailable"}})
                else:
                    replies=[jsonrpc_error(item,-32000,"private MCP upstream unavailable")
                             for item in request if isinstance(item,dict) and "id" in item]
                    if replies:
                        _stdio_emit(replies)
        finally:
            connection.close()


def main():
    ap = argparse.ArgumentParser()
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--socket")
    mode.add_argument("--stdio", action="store_true")
    ap.add_argument("--upstream", default="http://127.0.0.1:8790/mcp")
    ap.add_argument("--token-file", required=True)
    args = ap.parse_args()
    token = private_file(pathlib.Path(args.token_file)).decode().strip()
    if not token or any(c.isspace() for c in token):
        raise ValueError("runtime token file must contain one non-whitespace token")
    if args.stdio:
        serve_stdio(args.upstream, token)
        return
    socket_path = pathlib.Path(args.socket)
    parent = socket_path.parent
    parent.mkdir(parents=True, exist_ok=True)
    pinfo = parent.stat()
    if pinfo.st_uid != os.getuid() or pinfo.st_mode & 0o077:
        raise PermissionError("private account-owned socket directory required")
    if socket_path.exists() or socket_path.is_symlink():
        socket_path.unlink()
    server = UnixThreadingHTTPServer(str(socket_path), Handler)
    server.upstream = args.upstream
    server.token = token
    os.chmod(socket_path, 0o600)
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        server.server_close()
        socket_path.unlink(missing_ok=True)


if __name__ == "__main__":
    main()

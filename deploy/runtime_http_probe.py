#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Read-only native HTTP readiness probe, including persistent MCP SSE replies.

Never print the token, request headers, tool payloads or response bodies. Return
as soon as the original JSON-RPC response arrives; SSE may remain open forever.
"""

import argparse
import json
from pathlib import Path
import time
import urllib.request

MAX_RESPONSE_BYTES = 8 * 1024 * 1024


def read_rpc(response, request_id, timeout=10):
    if response.status in (202, 204):
        if request_id is not None:
            raise RuntimeError("MCP request acknowledged without its result")
        return None
    if request_id is None:
        return None
    deadline = time.monotonic() + timeout
    if "text/event-stream" not in response.headers.get("Content-Type", ""):
        raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise RuntimeError("MCP probe response exceeds byte budget")
        value = json.loads(raw)
        if value.get("id") == request_id:
            return value
        raise RuntimeError("MCP response does not match original request")
    data = []
    consumed = 0
    while time.monotonic() < deadline:
        line = response.readline(MAX_RESPONSE_BYTES - consumed + 1)
        consumed += len(line)
        if consumed > MAX_RESPONSE_BYTES:
            raise RuntimeError("MCP probe response exceeds byte budget")
        if not line:
            break
        line = line.rstrip(b"\r\n")
        if line.startswith(b"data:"):
            data.append(line[5:].lstrip(b" "))
        elif not line and data:
            raw = b"\n".join(data)
            data.clear()
            if not raw.strip():
                continue
            value = json.loads(raw)
            if value.get("id") == request_id:
                return value
    raise RuntimeError("MCP stream ended or timed out before original response")


def probe(endpoint, token_file, expected_policy="unbounded_by_runtime", timeout=10):
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "X-Hepta-Runtime-Token": Path(token_file).read_text().strip(),
    }
    session = None

    def rpc(payload):
        nonlocal session
        request = urllib.request.Request(endpoint, json.dumps(payload).encode(), headers=headers)
        with urllib.request.urlopen(request, timeout=timeout) as response:
            sid = response.headers.get("Mcp-Session-Id")
            if sid:
                session = sid
                headers["Mcp-Session-Id"] = sid
            return read_rpc(response, payload.get("id"), timeout)

    try:
        initialized = rpc({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                       "clientInfo": {"name": "hepta-readiness-probe", "version": "1"}},
        })
        headers["MCP-Protocol-Version"] = initialized["result"]["protocolVersion"]
        rpc({"jsonrpc": "2.0", "method": "notifications/initialized"})
        reply = rpc({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                     "params": {"name": "effective_config", "arguments": {}}})
        result = reply["result"]
        if result.get("isError"):
            raise RuntimeError("effective_config failed")
        value = json.loads(next(item["text"] for item in result["content"]
                                if item.get("type") == "text"))
        policy = value["limits"].get("concurrent_execution")
        if expected_policy is not None and policy != expected_policy:
            raise RuntimeError("runtime concurrency policy differs from expected release")
        return {"concurrent_execution": policy, "host_count": len(value["hosts"]),
                "schema": value["schema"]}
    finally:
        if session:
            try:
                request = urllib.request.Request(endpoint, headers=headers, method="DELETE")
                with urllib.request.urlopen(request, timeout=timeout):
                    pass
            except OSError:
                pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", default="http://127.0.0.1:8790/mcp")
    parser.add_argument("--token-file", type=Path, required=True)
    args = parser.parse_args()
    # Authentication must never be sent to an arbitrary remote endpoint.
    from urllib.parse import urlsplit
    url = urlsplit(args.endpoint)
    if url.scheme != "http" or url.hostname not in ("127.0.0.1", "::1", "localhost"):
        parser.error("probe endpoint must be loopback HTTP")
    print(json.dumps(probe(args.endpoint, args.token_file), sort_keys=True))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Public stdio MCP fixture client, extracted from the pinned native helper.

Source: hepta-private-ci@2d0120e208ed81515837a7530c9f6943af03e87f
tools/hcsn/wsp_20261104/native/run_current100k_native.py
Only generic transport/identity helpers are reused; no private-data entrypoint.
"""
import hashlib
import json
import os
import queue
import shutil
import struct
import subprocess
import threading
import time
import numpy as np

def sha(data):
    return hashlib.sha256(data).hexdigest()

def encode_weight(weight):
    data = np.asarray(weight, dtype="<f4").tobytes()
    header = json.dumps({"weight": {"dtype": "F32", "shape": list(weight.shape),
                                   "data_offsets": [0, len(data)]}}, separators=(",", ":")).encode()
    header += b" " * (-len(header) % 8)
    return struct.pack("<Q", len(header)) + header + data

def pin_binary(binary, work):
    """Execute an isolated immutable-by-this-driver copy, not a changing build path."""
    pinned = work / "hepta-runtime-executed"
    with binary.open("rb") as src, pinned.open("xb") as dst:
        shutil.copyfileobj(src, dst)
    os.chmod(pinned, 0o500)
    return pinned, sha(pinned.read_bytes()), pinned.stat()

def verify_binary(pinned, identity, before):
    after = pinned.stat()
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    assert tuple(getattr(before, f) for f in fields) == tuple(getattr(after, f) for f in fields)
    assert sha(pinned.read_bytes()) == identity, "executed binary changed during qualification"

class Mcp:
    def __init__(self, binary, config, log):
        self.log = log.open("w")
        try:
            self.p = subprocess.Popen([str(binary), "mcp", "--runtime-config", str(config)],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=self.log, text=True, bufsize=1)
        except BaseException:
            self.log.close()
            raise
        self.sequence = 0
        self.lines = queue.Queue()

        def read():
            for line in self.p.stdout:
                self.lines.put(line)
            self.lines.put(None)
        threading.Thread(target=read, daemon=True).start()
        try:
            self.request("initialize", {"protocolVersion": "2026-07-28", "capabilities": {},
                                        "clientInfo": {"name": "wsp-private-replay", "version": "1"}})
            self.send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
        except BaseException:
            self.close()
            raise

    def send(self, value):
        self.p.stdin.write(json.dumps(value, separators=(",", ":"), allow_nan=False) + "\n")
        self.p.stdin.flush()

    def request(self, method, params):
        self.sequence += 1
        seq = self.sequence
        self.send({"jsonrpc": "2.0", "id": seq, "method": method, "params": params})
        deadline = time.monotonic() + 120
        for _ in range(64):
            line = self.lines.get(timeout=max(0.001, deadline-time.monotonic()))
            if line is None:
                raise RuntimeError("native MCP process ended before replying")
            reply = json.loads(line)
            if reply.get("id") == seq:
                if "error" in reply:
                    raise RuntimeError(str(reply["error"]))
                return reply["result"]
        raise RuntimeError("too many unrelated MCP notifications")

    def call(self, tool, arguments):
        result = self.request("tools/call", {"name": tool, "arguments": arguments})
        if result.get("isError"):
            raise RuntimeError(str(result))
        return json.loads(result["content"][0]["text"])

    def close(self):
        self.p.terminate()
        try:
            self.p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.p.kill()
            self.p.wait(timeout=10)
        self.log.close()

#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Ghidra qualification's bounded stdio client and explicit controller close proof.

The transport and owner lifetime come from the operation qualification client.
Every controller restart has a separate original wire/archive directory. This
adapter does not qualify an operation or imply that remote jobs have stopped.
"""

import json
import os
from pathlib import Path
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import rea_operation_qualification as q
from rea_frame_mcp_qualification import CompressedMcp


REQUEST_SECONDS = 60.0
COMPLETE_SECONDS = 125.0


def native_environment(root):
    """The explicit five-key native environment observed in the R3 capture."""
    return {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
            "HEPTA_EFFECT_OWNER_FENCE_DIR": str(root / "authority"),
            "HEPTA_EFFECT_OWNER_SELF": "v4", "HEPTA_EFFECT_OWNER_FENCE_REQUIRED": "1"}


def normal_owner_close(observation):
    return (isinstance(observation, dict) and type(observation.get("returncode")) is int
            and observation["returncode"] == 0 and observation.get("forced_cleanup") == []
            and all(observation.get(name) is True
                    for name in ("reader_stopped", "owner_pidfd_exited", "process_group_gone")))


class Mcp:
    def __init__(self, runtime, root):
        self.root, runtime = Path(root), Path(runtime)
        q.require(self.root.is_absolute() and runtime.is_absolute(), "Ghidra MCP paths must be absolute")
        self.session_id = "controller-" + uuid.uuid4().hex
        self.capture_root = self.root / self.session_id
        self.close_record = None
        self.construction_succeeded = False
        self.construction_error = None
        self._client = CompressedMcp.__new__(CompressedMcp)
        try:
            CompressedMcp.__init__(self._client,
                [str(runtime), "mcp", "--runtime-config", str(self.root / "config.json")],
                self.root, native_environment(self.root), self.capture_root)
            self._client.initialize()
            self.construction_succeeded = True
        except BaseException as original:
            self.construction_error = {"type": type(original).__name__, "message": str(original)}
            try:
                self.close()
            except BaseException as secondary:
                original.add_note("Ghidra controller constructor cleanup: " + repr(secondary))
            original.add_note("Ghidra controller capture: " + str(self.capture_root))
            raise

    def _request(self, method, params, seconds=REQUEST_SECONDS):
        request_id = self._client.begin(method, params)
        response = self._client.receive(request_id, seconds=seconds)
        q.require("error" not in response and isinstance(response.get("result"), dict),
                  "Ghidra MCP request returned an RPC error or invalid result: " + str(response))
        return response["result"]

    def raw(self, name, arguments):
        # Preserve the complete original CallToolResult and opaque text. Only
        # call()/complete() decode a value for the existing harness assertions.
        return self._request("tools/call", {"name": name, "arguments": arguments})

    @staticmethod
    def _value(name, result):
        q.require(result.get("isError") is not True, "Ghidra MCP tool failure: " + name + ": " + str(result))
        content = result.get("content")
        q.require(isinstance(content, list) and len(content) == 1 and content[0].get("type") == "text"
                  and isinstance(content[0].get("text"), str), "Ghidra MCP tool did not return one text value")
        return q.parse_json(content[0]["text"].encode("utf-8"))

    def call(self, name, arguments):
        return self._value(name, self.raw(name, arguments))

    def complete(self, request):
        deadline = time.monotonic() + COMPLETE_SECONDS
        while (left := deadline - time.monotonic()) > 0:
            result = self._value("rea_static_read", self._request("tools/call",
                {"name": "rea_static_read", "arguments": request}, min(REQUEST_SECONDS, left)))
            if result.get("complete") is True:
                return result
            time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))
        raise TimeoutError("original job did not produce a complete retained outcome")

    def close(self):
        if self.close_record is not None:
            return self.close_record
        error = None
        try:
            observation = self._client.close()
        except BaseException as original:
            error = original
            observation = getattr(self._client, "close_observation", None)
        record = {"schema": "hepta.rea.ghidra-controller-session.v1", "qualified": False,
                  "session_id": self.session_id, "capture_root": str(self.capture_root),
                  "construction_succeeded": self.construction_succeeded,
                  "construction_error": self.construction_error,
                  "owner_close": observation, "normal_close": False,
                  "close_error": None if error is None else {"type": type(error).__name__, "message": str(error)},
                  "capture_errors": [], "artifacts": {}}
        self.close_record = record
        for field, name in (("launch", "launch.json"), ("close", "close.json"),
                            ("wire_index", "wire.jsonl"), ("stderr", "stderr.log"),
                            ("initialization_failure", "initialization-failure.json")):
            path = self.capture_root / name
            record["artifacts"][field] = None
            try:
                if path.exists():
                    record["artifacts"][field] = q.artifact_reference(path, self.root)
                elif field != "initialization_failure":
                    record["capture_errors"].append({"artifact": field, "error": "missing original artifact"})
            except BaseException as secondary:
                record["capture_errors"].append({"artifact": field, "error": repr(secondary)})
                if error is None:
                    error = secondary
        record["normal_close"] = (self.construction_succeeded and error is None
                                  and not record["capture_errors"] and normal_owner_close(observation))
        try:
            with (self.capture_root / "session.json").open("xb") as stream:
                stream.write(q.json_bytes(record))
        except BaseException as secondary:
            record["normal_close"] = False
            record["capture_errors"].append({"artifact": "session", "error": repr(secondary)})
            # Keep a durable, bounded diagnostic even when artifact publication
            # fails. It never marks an incomplete close as normal.
            diagnostic = {"schema": record["schema"], "session_id": self.session_id,
                          "normal_close": False, "qualified": False,
                          "session_receipt_error": repr(secondary)[:256]}
            try:
                os.write(2, (json.dumps(diagnostic, sort_keys=True) + "\n").encode())
            except BaseException:
                pass
            if error is None:
                error = secondary
            else:
                error.add_note("Ghidra controller close receipt: " + repr(secondary))
        if error is not None:
            raise error
        return record

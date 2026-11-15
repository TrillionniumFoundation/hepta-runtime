#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Pure fixture checks only; never launch a runtime or read the remote roots."""
import ast
import base64
import copy
import hashlib
import io
import json
from pathlib import Path
import threading
import time
import types

HERE = Path(__file__).resolve().parent


def main():
    module = types.ModuleType("r36_async_pure_test")
    module.__file__ = str(HERE / "run_async_read_abba.py")
    exec(compile(Path(module.__file__).read_bytes(), module.__file__, "exec"), module.__dict__)
    checks = []
    def reject(label, function):
        try:
            function()
        except (RuntimeError, ValueError, KeyError):
            checks.append(label)
        else:
            raise AssertionError("accepted invalid fixture: " + label)
    scope = {"ownership_scope": "native_mcp_session_only", "session_scope": "native_mcp_session_only",
             "cross_session_resume": False, "credential_metadata_resume": False}
    operation_id = "a" * 64
    status = dict(scope, operation_id=operation_id, tool_name="process_read", automatic_retry=False,
        async_state="completed", owned_future_active=False, payload_available=True, result_state="stored_observed")
    assert module.completed(status, operation_id, "process_read")
    assert not module.completed(dict(status, async_state="settling"), operation_id, "process_read")
    reject("unknown durable operation is not success", lambda: module.completed(dict(status, async_state="unknown"), operation_id, "process_read"))
    reject("wrong operation id is rejected", lambda: module.completed(status, "b" * 64, "process_read"))
    reject("cross-session success is rejected", lambda: module.completed(dict(status, cross_session_resume=True), operation_id, "process_read"))
    expected = "marker-测试\n".encode()
    job = {"id": "old-job", "expected": expected}
    dto = {"job_id": "old-job", "audit_recorded": True,
           "stdout": {"bytes_hex": expected.hex(), "offset": 0, "next_offset": len(expected), "size": len(expected), "eof": True},
           "stderr": {"bytes_hex": "", "offset": 0, "next_offset": 0, "size": 0, "eof": True}}
    original = json.dumps({"content": [{"type": "text", "text": json.dumps(dto, ensure_ascii=False)}]}, ensure_ascii=False).encode()
    module.validate_original(original, job, "process_read")
    checks.append("SDK payload without V8 metadata validates exact frozen output")
    reject("wrong frozen output is rejected", lambda: module.validate_original(original, dict(job, expected=b"wrong"), "process_read"))
    digest = hashlib.sha256(original).hexdigest()
    pages = []
    for offset in range(0, len(original), 17):
        chunk = original[offset:offset + 17]
        pages.append(dict(scope, operation_id=operation_id, offset=offset, next_offset=offset + len(chunk),
            total_bytes=len(original), eof=offset + len(chunk) == len(original), data_base64=base64.b64encode(chunk).decode(),
            result_sha256=digest, payload_kind="native_result", format=module.RESULT_FORMAT, immutable_snapshot=True, automatic_retry=False))
    client = object.__new__(module.Client)
    client.protocol = {"result_page_bytes": 17, "maximum_result_bytes": 1048576}
    client.bench = types.SimpleNamespace(digest=lambda raw: hashlib.sha256(raw).hexdigest())
    iterator = iter(pages)
    client.rpc = lambda *args, **kwargs: ({}, next(iterator))
    raw, identity, raw_pages = client.original(operation_id, "synthetic")
    assert raw == original and identity["result_sha256"] == digest and len(raw_pages) == len(pages)
    checks.append("17-byte pages preserve complete original bytes and full SHA")
    reject("wrong page cursor is rejected", lambda: module.result_page(dict(pages[0], next_offset=999), operation_id, 0, None, 1048576))
    reject("native error payload is rejected", lambda: module.result_page(dict(pages[0], payload_kind="native_error"), operation_id, 0, None, 1048576))
    changed_pages = copy.deepcopy(pages)
    changed_pages[-1]["data_base64"] = base64.b64encode(b"X" * (changed_pages[-1]["next_offset"] - changed_pages[-1]["offset"])).decode()
    iterator = iter(changed_pages)
    reject("changed bytes with unchanged claimed SHA are rejected", lambda: client.original(operation_id, "synthetic"))
    receipt = dict(scope, operation_id=operation_id, tool_name="process_read", reused=True,
                   idempotency_binding_retained=True, async_state="unknown", automatic_retry=False)
    responses = iter([receipt, status])
    client.rpc = lambda *args, **kwargs: ({}, next(responses))
    client.original = lambda *args, **kwargs: (original, identity, raw_pages)
    assert client.idempotency({"arguments": {}, "label": "synthetic", "operation_id": operation_id,
        "tool": "process_read", "original_bytes": original, "original_identity": identity})["reused"]
    checks.append("completed same-key unknown live receipt uses durable status and unchanged result")
    # Ordinary errors cannot masquerade as successful owner isolation.
    client = object.__new__(module.Client)
    client.deadline = time.monotonic() + 30
    client.lock, client.journal = threading.Lock(), io.BytesIO()
    client.bench = types.SimpleNamespace(digest=lambda raw: hashlib.sha256(raw).hexdigest(), canonical=lambda v: json.dumps(v).encode())
    client.controller = types.SimpleNamespace(rpc=lambda *args, **kwargs: {"error": {"message": "transport failed"}})
    reject("RPC failure is not owner refusal", lambda: client.rpc("operation_status", {}, "synthetic", refuse=True))
    client.controller = types.SimpleNamespace(rpc=lambda *args, **kwargs: {"result": {"isError": True,
        "content": [{"type": "text", "text": "request audit unavailable; dispatch refused"}]}})
    reject("unrelated audit refusal is not owner isolation", lambda: client.rpc("operation_status", {}, "synthetic", refuse=True))
    for path in HERE.glob("*.py"):
        compile(path.read_bytes(), str(path), "exec")
    tree = ast.parse((HERE / "seal_protocol.py").read_text())
    wrapper_assignment = next(node for node in ast.walk(tree) if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "wrapper" for target in node.targets))
    template = ast.literal_eval(wrapper_assignment.value.left)
    ast.parse(template % ("/synthetic/root", {"path": "/synthetic/runner", "bytes": 1, "sha256": "0" * 64}, "1" * 64, "2" * 64))
    checks.append("late-bound original-holder wrapper parses without executing")
    result = {"schema": "hepta-r36-async-pure-review/v1", "passed": True, "checks": checks,
        "synthetic_only": True, "runtime_or_remote_commands_executed": 0}
    (HERE / "pure-review.json").write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()

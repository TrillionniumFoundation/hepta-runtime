"""CI-only first execution of the new exact Batch/Text SDK reference carrier."""
from pathlib import Path
import argparse
import json
import os
from receipt_support import PIN, process, put, require


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def run(binary, output):
    require(os.environ.get("GITHUB_ACTIONS") == "true", "reference execution is CI-only")
    binary = Path(binary).resolve(strict=True)
    output = Path(output).absolute()
    output.mkdir(parents=True, exist_ok=False)
    work = output / "work"
    work.mkdir()
    initial = b"alpha\nbeta\n"
    (work / "file").write_bytes(initial)
    rows = []
    def wire(session, value, response=True):
        rows.append({"id": len(rows), "kind": "wire", "session": session,
            "response": response, "wire_hex": encoded(value).hex()})
    for session in (0, 1):
        wire(session, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "batch-current-reference", "version": "1"}}})
        wire(session, {"jsonrpc": "2.0", "method": "notifications/initialized"}, False)
    for session, name, args in (
        (0, "batch_edit", {"path": "file", "operations": [{"operation": "insert", "start": 0, "content": "hello"}]}),
        (0, "batch_edit", {"path": "file", "operations": [{"operation": "delete", "start": 0}]}),
        (1, "text_editor", {"command": "undo_edit", "path": "file"}),
    ):
        wire(session, {"jsonrpc": "2.0", "id": len(rows) + 1, "method": "tools/call",
            "params": {"name": name, "arguments": args}})
    data = b"".join(encoded(row) for row in rows)
    row, stdout, stderr = process(output / "processes", "sdk-smoke", [binary], cwd=work, stdin=data, timeout=180)
    replies = [json.loads(line) for line in stdout.splitlines()]
    require(len(replies) == len(rows), "complete reference observations")
    for expected, actual in zip(rows, replies):
        require((actual["id"], actual["session"], actual["kind"]) ==
            (expected["id"], expected["session"], "wire"), "fixture reply identity")
        raw = bytes.fromhex(actual["output_hex"])
        require(actual["scope_unbound_after_exchange"] is True, "request scope leaked")
        if not expected["response"]:
            require(raw == b"", "notification emitted a response")
        else:
            reply = json.loads(raw)
            request = json.loads(bytes.fromhex(expected["wire_hex"]))
            require(reply["id"] == request["id"], "SDK request/response ID")
            if expected["id"] == 5:
                require(reply["error"]["code"] == -32602, "actual typed rejection")
            else:
                require("result" in reply and not reply["result"].get("isError", False), "actual original method result")
    final = (work / "file").read_bytes()
    require(final == initial and stderr == b"", "shared real history restore/complete stderr")
    report = {"status": "PASS", "rows": len(rows), "actual_original_roots": 1,
        "actual_sdk_sessions": 2, "actual_original_tool_calls": 2,
        "actual_typed_rejections": 1, "process": row,
        "before_hex": initial.hex(), "after_hex": final.hex(),
        "full_stdout": PIN(stdout), "full_stderr": PIN(stderr),
        "native_compared": False, "public_batch_qualified": False,
        "full_async_cancellation_qualified": False, "whole_runtime_replaced": False}
    put(output / "result.json", report)
    return report


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    print(json.dumps(run(a.binary, a.output), sort_keys=True))

"""Read actual public exchanges without starting a process or opening a fixture.

The two complete file-search producers share the source-owned MCP transport.
This reader checks its cwd-based capture format, complete streams, and every
60-second request receipt. It does not compute a view response.
"""
from __future__ import annotations

from hia_native_runtime_mcp_evidence import decode, exact, finite, require, sha


def session_streams(evidence, folder, record, *, session, executable, cwd):
    fields = ("session", "command", "cwd", "environment", "timeout_seconds",
              "elapsed_seconds", "exit_code", "timed_out", "failure_cleanup_requested",
              "unconsumed_stdout_bytes", "exchanges", "stdin", "stdout", "stderr")
    exact(sorted(record), sorted(fields), "public session receipt fields differ")
    exact(record["session"], session, "public session identity differs")
    exact(record["command"], [str(executable)], "public session executable differs")
    exact(record["cwd"], str(cwd), "public session initial directory differs")
    exact(record["environment"], {"PATH": "", "LC_ALL": "C"}, "public session environment differs")
    require(type(record["exit_code"]) is int and record["exit_code"] == 0
            and type(record["timeout_seconds"]) is int and record["timeout_seconds"] == 60
            and finite(record["elapsed_seconds"], 180) and record["timed_out"] is False
            and record["failure_cleanup_requested"] is False
            and type(record["unconsumed_stdout_bytes"]) is int and record["unconsumed_stdout_bytes"] == 0
            and type(record["exchanges"]) is int and record["exchanges"] > 0,
            "public session failed or its deadline/cleanup differs")
    stem = folder + "/sessions/" + session + "/"
    exact(evidence.object(stem + "process.json"), record, "public process receipt copy differs")
    capture = {key: value for key, value in record.items() if key != "session"}
    for key in ("stdin", "stdout", "stderr"):
        capture[key] = {name: value for name, value in record[key].items() if name != "path"}
    exact(evidence.object(stem + "capture-process.json"), capture,
          "public transport process receipt differs")
    streams = {key: evidence.stream(folder, record[key], "sessions/" + session + "/" + key + ".bin.gz")
               for key in ("stdin", "stdout", "stderr")}
    exact(streams["stderr"], b"", "production emitted private fixture receipts or diagnostics")
    require(streams["stdin"].endswith(b"\n") and streams["stdout"].endswith(b"\n"),
            "actual public streams are incomplete")
    requests = streams["stdin"][:-1].split(b"\n")
    replies = streams["stdout"][:-1].split(b"\n")
    exchanges = decode(evidence.read(stem + "exchanges.json"))
    require(type(exchanges) is list and len(exchanges) == record["exchanges"] == len(requests),
            "actual public exchange count differs")
    reply_index = 0
    for index, (exchange, raw) in enumerate(zip(exchanges, requests)):
        exact(sorted(exchange), ["elapsed_seconds", "error", "number", "request_sha256",
                                 "requested_bytes", "responses", "timeout_seconds", "written_bytes"],
              "actual public exchange fields differ")
        expected = dict(number=index, timeout_seconds=60, requested_bytes=len(raw) + 1,
                        written_bytes=len(raw) + 1, request_sha256=sha(raw + b"\n"), error=None)
        exact({key: exchange[key] for key in expected}, expected,
              "actual public write/deadline differs")
        require(finite(exchange["elapsed_seconds"], 60), "actual public request exceeded 60 seconds")
        request = decode(raw)
        require(type(request) is dict, "actual public request is not an object")
        count = int("id" in request)
        response = replies[reply_index:reply_index + count]
        require(len(response) == count, "actual public response is missing")
        exact(exchange["responses"], [dict(bytes=len(value), sha256=sha(value)) for value in response],
              "actual public response bytes differ from the exchange receipt")
        if count:
            reply = decode(response[0])
            require(type(reply) is dict, "actual public reply is not an object")
            exact(reply.get("jsonrpc"), "2.0", "actual public response version differs")
            exact(reply.get("id"), request["id"], "actual public response correlation differs")
            require(("result" in reply) != ("error" in reply), "ambiguous actual public response")
        reply_index += count
    exact(reply_index, len(replies), "extra actual public response bytes")
    return streams

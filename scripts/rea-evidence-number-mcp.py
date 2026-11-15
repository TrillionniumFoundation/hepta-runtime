#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Exercise a fingerprinted runtime's public Evidence verifier with npm records."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import queue
import subprocess
import threading


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--binary-sha256", required=True)
    parser.add_argument("--corpus", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--expected-rejections", default="")
    args = parser.parse_args()
    binary = Path(args.binary).resolve(strict=True)
    if digest(binary) != args.binary_sha256:
        raise RuntimeError("selected runtime SHA-256 changed")
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    workspace = output / "inputs"
    workspace.mkdir()
    corpus = Path(args.corpus).resolve(strict=True)
    cases = json.loads(corpus.read_text())["cases"]
    if len(cases) < 400:
        raise RuntimeError("expected an actual npm Evidence corpus with at least 400 records")
    rejected = {int(value) for value in args.expected_rejections.split(",") if value}
    if not rejected.issubset(range(len(cases))):
        raise RuntimeError("rejection index outside the reference corpus")
    policy = {
        "controller_workspace_roots": [str(workspace)],
        "state_dir": str(output / "state"),
        "hosts": {
            "never-connect": {
                "ssh_target": "never-connect-invalid",
                "remote_state_dir": str(output / "never-used-remote-state"),
                "allow_execute": False,
                "allow_pty": False,
                "allow_write": False,
                "allow_job_network": False,
            }
        },
    }
    config = output / "runtime-config.json"
    config.write_text(json.dumps(policy, sort_keys=True) + "\n")
    replies = queue.Queue()
    requests_file = (output / "mcp.requests.jsonl").open("w")
    stdout_file = (output / "mcp.stdout.jsonl").open("wb")
    stderr_file = (output / "mcp.stderr.log").open("wb")
    child = subprocess.Popen(
        [str(binary), "mcp", "--runtime-config", str(config)],
        cwd="/", env={}, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=stderr_file, start_new_session=True,
    )

    def receive():
        try:
            while True:
                line = child.stdout.readline(1024 * 1024 + 1)
                if not line:
                    replies.put(EOFError("runtime stdout closed"))
                    return
                if len(line) > 1024 * 1024:
                    replies.put(RuntimeError("runtime reply exceeded 1 MiB"))
                    return
                stdout_file.write(line)
                stdout_file.flush()
                replies.put(json.loads(line))
        except BaseException as error:
            replies.put(error)

    reader = threading.Thread(target=receive, daemon=True)
    reader.start()

    def send(message):
        encoded = json.dumps(message, separators=(",", ":")) + "\n"
        requests_file.write(encoded)
        requests_file.flush()
        child.stdin.write(encoded.encode())
        child.stdin.flush()

    def request(identifier, method, params):
        send({"jsonrpc": "2.0", "id": identifier, "method": method, "params": params})
        for _ in range(64):
            message = replies.get(timeout=30)
            if isinstance(message, BaseException):
                raise message
            if message.get("id") == identifier:
                if "error" in message:
                    raise RuntimeError("unexpected JSON-RPC error: " + json.dumps(message["error"]))
                return message["result"]
        raise RuntimeError("too many unrelated runtime messages")

    successes = 0
    observed_rejections = []
    mismatches = []
    result = None
    try:
        initialize = request(1, "initialize", {
            "protocolVersion": "2026-07-28",
            "capabilities": {},
            "clientInfo": {"name": "rea-numeric-independent-mcp", "version": "1"},
        })
        send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
        for index, record in enumerate(cases):
            path = workspace / ("record-%04d.json" % index)
            path.write_text(json.dumps(record, ensure_ascii=True, separators=(",", ":")) + "\n")
            reply = request(index + 2, "tools/call", {
                "name": "rea_verify_evidence", "arguments": {"path": str(path)}
            })
            is_error = reply.get("isError") is True
            text = "\n".join(
                part.get("text", "") for part in reply.get("content", [])
                if part.get("type") == "text"
            )
            if is_error:
                observed_rejections.append({"index": index, "evidence_id": record["evidence_id"], "error": text})
                if index not in rejected or "digest mismatch" not in text:
                    mismatches.append({"index": index, "unexpected_rejection": text})
            elif index in rejected:
                mismatches.append({"index": index, "unexpected_acceptance": True})
            else:
                verified = json.loads(reply["content"][0]["text"])
                if verified.get("status") != "subset_digest_verified" or verified.get("evidence_id") != record["evidence_id"]:
                    mismatches.append({"index": index, "wrong_success": verified})
                elif verified.get("rea_full_schema_qualified") is not False:
                    mismatches.append({"index": index, "overclaimed_schema": verified})
                else:
                    successes += 1
        result = {
            "schema": "hepta.rea.numeric-mcp-differential.v1",
            "runtime_sha256": args.binary_sha256,
            "corpus_sha256": digest(corpus),
            "runtime_server_info": initialize.get("serverInfo"),
            "cases": len(cases),
            "successes": successes,
            "expected_rejection_indices": sorted(rejected),
            "observed_rejections": observed_rejections,
            "mismatches": mismatches,
            "matches_expected_behavior": not mismatches and len(observed_rejections) == len(rejected),
            "full_upstream_parity_qualified": False,
        }
    finally:
        child.stdin.close()
        try:
            child.wait(timeout=15)
        except subprocess.TimeoutExpired:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
        reader.join(timeout=5)
        requests_file.close()
        stdout_file.close()
        stderr_file.close()
    if result is None:
        raise RuntimeError("numeric MCP differential did not complete")
    result["runtime_exit_code"] = child.returncode
    result["runtime_sha256_after"] = digest(binary)
    result["runtime_unchanged"] = result["runtime_sha256_after"] == args.binary_sha256
    result["harness_sha256"] = digest(__file__)
    (output / "qualification.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, sort_keys=True))
    if not result["matches_expected_behavior"] or not result["runtime_unchanged"] or child.returncode != 0:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

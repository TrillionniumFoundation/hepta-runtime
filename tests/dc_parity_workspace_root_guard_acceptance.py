#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Prove a directory move cannot uproot configured workspace capabilities.

Real private HTTP MCP fixture with an independently built binary. Does NOT
modify running hepta-runtime, Desktop Commander, or ChatGPT's tunnel. A failed
old implementation is expected to move only disposable temporary directories.
"""
import argparse
import json
import pathlib
import secrets
import socket
import subprocess
import sys
import tempfile
import time

from runtime_http_acceptance import Client

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument('--successor-contract')
    args = parser.parse_args()
    binary = pathlib.Path(args.binary).resolve(strict=True)
    tests = []
    def passed(name):
        tests.append(name)
        print("PASS", name, flush=True)
    with tempfile.TemporaryDirectory(prefix="hepta-parity-root-guard-") as t:
        base = pathlib.Path(t)
        first = base/"workspace-a"
        second = base/"workspace-b"
        first.mkdir(mode=0o700)
        second.mkdir(mode=0o700)
        (first/"guard-marker").write_text("first workspace remains reachable\n")
        parent = second/"parent"
        protected = parent/"protected-workspace"
        protected.mkdir(parents=True, mode=0o700)
        (protected/"guard-marker").write_text("nested workspace remains reachable\n")
        config = base/"runtime.json"
        config.write_text(json.dumps({
            "state_dir": str(base/"state"),
            "controller_workspace_roots": [str(first), str(second), str(protected)],
            "hosts": {"disabled-fixture": {
                "ssh_target": "localhost", "platform": "linux",
                "remote_state_dir": str(base/"unused"),
                "execution_mode": "isolated", "allow_execute": False,
                "allow_pty": False, "allow_write": False,
                "allowed_read_path_prefixes": [str(second)],
                "allowed_write_path_prefixes": [str(second)]
            }}
        }))
        token = base/"token"
        token.write_text(secrets.token_hex(32))
        token.chmod(0o600)
        with socket.socket() as listening:
            listening.bind(("127.0.0.1", 0))
            port = listening.getsockname()[1]
        command = [
            str(binary), "mcp", "--path", str(second),
            "--bind", f"127.0.0.1:{port}",
            "--runtime-config", str(config),
            "--auth-token-file", str(token),
        ]
        logfile = base/"controller.log"
        with logfile.open("wb") as output:
            controller = subprocess.Popen(
                command, stdin=subprocess.DEVNULL, stdout=output, stderr=output
            )
            try:
                for _ in range(90):
                    if controller.poll() is not None:
                        raise RuntimeError(
                            "private fixture exited: "
                            + logfile.read_text(errors="replace")[-900:]
                        )
                    try:
                        client = Client(f"http://127.0.0.1:{port}/mcp", token.read_text())
                        break
                    except (OSError, RuntimeError):
                        time.sleep(.1)
                else:
                    raise TimeoutError("private fixture did not start")
                served = client.rpc("tools/list", {})["tools"]
                if args.successor_contract:
                    from dc_successor_contract import verify_successor
                    served = verify_successor(served, args.successor_contract)
                actual = {v["name"]: v for v in served}
                assert len(actual) == 50 and "directory_move" in actual
                passed("private 50-tool runtime discovered from isolated controller")

                client.call("directory_move", {
                    "source": str(first),
                    "destination": str(second/"improperly-moved-workspace")
                }, denied=True)
                assert first.is_dir() and (first/"guard-marker").read_text() == (
                    "first workspace remains reachable\n"
                )
                assert not (second/"improperly-moved-workspace").exists()
                passed("configured workspace root cannot be renamed under another root")

                client.call("directory_move", {
                    "source": str(parent),
                    "destination": str(second/"improperly-moved-parent")
                }, denied=True)
                assert parent.is_dir() and protected.is_dir()
                assert (protected/"guard-marker").read_text() == (
                    "nested workspace remains reachable\n"
                )
                assert not (second/"improperly-moved-parent").exists()
                passed("ancestor of nested configured root cannot be renamed")

                sibling = second/"ordinary"
                sibling.mkdir()
                (sibling/"keep").write_text("ordinary retained\n")
                result = client.call("directory_move", {
                    "source": str(sibling),
                    "destination": str(second/"ordinary-moved")
                })
                assert result["moved"] is True
                assert not sibling.exists()
                assert (second/"ordinary-moved/keep").read_text() == (
                    "ordinary retained\n"
                )
                passed("ordinary directory move within same root still succeeds")

                source = second/"ordinary-file"
                source.write_text("untouched file semantics\n")
                result = client.call("file_move", {
                    "source": str(source),
                    "destination": str(second/"ordinary-file-moved")
                })
                assert result["moved"] and not source.exists()
                assert (second/"ordinary-file-moved").read_text() == (
                    "untouched file semantics\n"
                )
                passed("ordinary no-replace file move still succeeds")
                result = {
                    "schema": "hepta-scoped-directory-root-guard-v1",
                    "complete": True,
                    "checks": tests,
                    "passed": len(tests),
                    "only_disposable_test_workspaces": True,
                    "changes_to_live_runtime_or_tunnel": False,
                    "chatgpt_origin": False,
                }
                pathlib.Path(args.out).write_text(json.dumps(result, indent=2) + "\n")
                print("ALL_PASS", len(tests), flush=True)
            finally:
                if controller.poll() is None:
                    controller.terminate()
                controller.wait(timeout=10)

if __name__ == "__main__":
    main()

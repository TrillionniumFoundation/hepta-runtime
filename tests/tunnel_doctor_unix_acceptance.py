#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Check a built full CLI against an isolated private Unix HTTP endpoint."""
import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import socketserver
import subprocess
import tempfile
import threading


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    actual = hashlib.sha256(binary.read_bytes()).hexdigest()
    if actual != args.sha256:
        raise SystemExit("candidate binary SHA256 mismatch")
    if args.output.exists():
        raise SystemExit("acceptance output already exists")
    paths = []
    lock = threading.Lock()

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *unused):
            pass

        def do_GET(self):
            with lock:
                paths.append(self.path)
            self.send_response(405 if self.path == "/mcp" else 404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
        daemon_threads = True

    # A short private path fits both Linux and macOS Unix-socket limits.
    with tempfile.TemporaryDirectory(prefix="htd-", dir="/tmp") as temporary:
        root = Path(temporary)
        socket = root / "bridge.sock"
        server = Server(str(socket), Handler)
        socket.chmod(0o600)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        profile = root / "profile.yaml"
        profile.write_text(
            'config_version: 1\ncontrol_plane:\n'
            '  tunnel_id: tunnel_0123456789abcdef0123456789abcdef\n'
            '  api_key: env:HEPTA_TEST_CONTROL_KEY\nmcp:\n'
            '  server_urls:\n    - channel: main\n      url: http://localhost/mcp\n'
            '      unix_socket: ' + json.dumps(str(socket)) + '\n'
            '  max_concurrent_requests: 0\n'
        )
        profile.chmod(0o600)
        try:
            # This diagnostic does not run a poller or use real account keys.
            result = subprocess.run(
                [str(binary), "doctor", "--config", str(profile),
                 "--health.listen-addr", "127.0.0.1:0", "--json"],
                cwd=root, env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                               "HOME": str(root), "HEPTA_TEST_CONTROL_KEY": "private-fixture-key"},
                capture_output=True, text=True, timeout=30,
            )
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=5)
        report = json.loads(result.stdout)
        with lock:
            observations = list(paths)
        checks = {check["id"]: check for check in report.get("checks", [])}
        passed = (result.returncode == 0 and report.get("result") == "ok"
                  and checks.get("mcp_server_reachable", {}).get("status") == "PASS"
                  and checks.get("oauth_metadata", {}).get("status") == "PASS"
                  and "/mcp" in observations
                  and any(path.startswith("/.well-known/") for path in observations))
        receipt = {"schema": 1, "passed": passed, "binary_sha256": actual,
                   "returncode": result.returncode, "requests": observations,
                   "doctor": report, "stderr": result.stderr}
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x") as target:
            json.dump(receipt, target, indent=2)
            target.write("\n")
        print(json.dumps({"passed": passed, "binary_sha256": actual, "output": str(args.output)}))
        if not passed:
            raise SystemExit(1)


if __name__ == "__main__":
    main()

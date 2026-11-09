#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Default tunnel routes select concurrent HTTP without broadening authority."""
import configparser
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import re
import shlex
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def environment(text):
    values = {}
    for line in text.splitlines():
        if line.strip() and not line.lstrip().startswith("#"):
            key, raw = line.split("=", 1)
            values[key] = shlex.split(raw)[0]
    return values


class DeploymentConfig(unittest.TestCase):
    def test_readonly_profile_selects_the_existing_private_http_bridge(self):
        profile = (ROOT / "deploy/chatgpt/hepta-chatgpt.yaml").read_text()
        mcp = profile.split("\nmcp:\n", 1)[1]
        self.assertRegex(mcp, r"(?m)^  server_urls:$")
        self.assertNotRegex(mcp, r"(?m)^  commands:$")
        self.assertRegex(mcp, r"(?m)^  max_concurrent_requests: 0$")
        values = {key: json.loads(raw) for key, raw in re.findall(r'^      (url|unix_socket): ("[^"\n]+")$', mcp, re.M)}
        self.assertEqual(values, {"url": "http://localhost/mcp", "unix_socket": "env:HEPTA_CHATGPT_BRIDGE_SOCKET"})
        service = configparser.ConfigParser(interpolation=None, strict=False)
        service.read(ROOT / "deploy/chatgpt/hepta-openai-tunnel.service")
        self.assertIn("hepta-chatgpt-bridge.service", service["Unit"]["Requires"].split())
        self.assertIn("hepta-chatgpt-bridge.service", service["Unit"]["After"].split())
        self.assertEqual(service["Service"]["Environment"],
                         "HEPTA_CHATGPT_BRIDGE_SOCKET=%t/hepta-chatgpt/bridge.sock")
        bridge = configparser.ConfigParser(interpolation=None)
        bridge.read(ROOT / "deploy/chatgpt/hepta-chatgpt-bridge.service")
        command = shlex.split(bridge["Service"]["ExecStart"])
        self.assertNotIn("--stdio", command)
        self.assertEqual(command[command.index("--socket") + 1], "%t/hepta-chatgpt/bridge.sock")
        self.assertEqual(command[command.index("--upstream") + 1], "http://127.0.0.1:8790/mcp")
        self.assertEqual(bridge["Service"]["RuntimeDirectoryMode"], "0700")
        binder = (ROOT / "deploy/chatgpt/hepta-chatgpt-tunnel-bind").read_text()
        self.assertIn('export HEPTA_CHATGPT_BRIDGE_SOCKET="$XDG_RUNTIME_DIR/hepta-chatgpt/bridge.sock"', binder)
        self.assertLess(binder.index("systemctl --user start hepta-chatgpt-bridge.service"),
                        binder.index('"$HOME/.local/bin/tunnel-client" doctor'))

    def test_system_provisioning_matches_the_existing_authenticated_native_http_example(self):
        spec = importlib.util.spec_from_file_location("hepta_provision", ROOT / "deploy/provision-tunnel.py")
        provision = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(provision)
        with tempfile.TemporaryDirectory(prefix="hepta-provision-test-") as temporary:
            root = Path(temporary)
            key = root / "input-key"
            key.write_text("sk-" + "x" * 32)
            key.chmod(0o600)
            (root / "mcp-token").write_text("fixture-private-runtime-token")
            writes = {}
            meta = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_size=35)
            with mock.patch.object(provision, "ROOT", root), \
                    mock.patch.object(provision.os, "geteuid", return_value=0), \
                    mock.patch.object(provision.os, "fstat", return_value=meta), \
                    mock.patch.object(provision.grp, "getgrnam", return_value=SimpleNamespace(gr_gid=123)), \
                    mock.patch.object(provision, "atomic", side_effect=lambda name, data, gid: writes.__setitem__(name, data)), \
                    mock.patch.object(provision.subprocess, "run") as service_calls, \
                    mock.patch("sys.argv", ["provision-tunnel.py", "--tunnel-id", "tunnel_fixture_only", "--key-file", str(key)]), \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                provision.main()
            actual = environment(writes["tunnel.env"].decode())
            example = environment((ROOT / "deploy/tunnel.env.example").read_text())
            actual.pop("CONTROL_PLANE_TUNNEL_ID")
            example.pop("CONTROL_PLANE_TUNNEL_ID")
            self.assertEqual(actual, example)
            self.assertEqual(actual["MCP_SERVER_URL"], "url=http://127.0.0.1:8787/mcp,channel=main")
            self.assertEqual(actual["MCP_MAX_CONCURRENT_REQUESTS"], "0")
            self.assertEqual(actual["MCP_EXTRA_HEADERS"], "X-Hepta-Runtime-Token: file:/etc/hepta-runtime/mcp-token")
            self.assertEqual(actual["MCP_DISCOVERY_EXTRA_HEADERS"], actual["MCP_EXTRA_HEADERS"])
            self.assertNotIn("MCP_COMMAND", actual)
            self.assertNotIn(key.read_text(), output.getvalue())
            self.assertEqual(service_calls.call_count, 2)


if __name__ == "__main__":
    unittest.main()

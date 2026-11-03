#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Private loopback MCP recovery; all credentials and data are generated here."""
import hashlib, json, os, pathlib, secrets, socket, struct, subprocess, sys
import tempfile, time, urllib.error, urllib.request

class Client:
    def __init__(self, port, token):
        self.url = f"http://127.0.0.1:{port}/mcp"
        self.token, self.session, self.i = token, None, 0
        self.protocol = "2026-07-28"
        initialized = self.rpc("initialize", {"protocolVersion": self.protocol, "capabilities": {},
            "clientInfo": {"name": "model-session-http-test", "version": "1"}})
        self.protocol = initialized["protocolVersion"]
        self.rpc("notifications/initialized", {}, notify=True)
    def rpc(self, method, params, notify=False):
        self.i += 1
        body = {"jsonrpc": "2.0", "method": method, "params": params}
        if not notify: body["id"] = self.i
        headers = {"Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "X-Hepta-Runtime-Token": self.token, "MCP-Protocol-Version": self.protocol,
            "Mcp-Method": method}
        if method == "tools/call": headers["Mcp-Name"] = params["name"]
        if self.session: headers["Mcp-Session-Id"] = self.session
        req = urllib.request.Request(self.url, data=json.dumps(body).encode(), headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                self.session = response.headers.get("Mcp-Session-Id", self.session)
                raw = response.read().decode()
        except urllib.error.HTTPError as error:
            detail = error.read(4096).decode(errors="replace")
            raise RuntimeError(f"HTTP {error.code} during {method}: {detail}") from error
        if notify: return None
        records = [json.loads(line[5:].strip()) for line in raw.splitlines()
            if line.startswith("data:") and line[5:].strip()]
        result = records[-1] if records else json.loads(raw)
        if "error" in result: raise RuntimeError(f"RPC {method}: {result['error']}")
        return result["result"]
    def call(self, name, args, denied=False):
        result = self.rpc("tools/call", {"name": name, "arguments": args})
        text = "\n".join(v.get("text", "") for v in result.get("content", []) if v.get("type") == "text")
        if denied:
            assert result.get("isError"), f"{name} should refuse this request"
            return
        assert not result.get("isError"), f"{name}: {text}"
        return json.loads(text)

class Server:
    def __init__(self, binary, root, config, token):
        self.log = open(root / f"server-{secrets.token_hex(4)}.log", "wb")
        token_file = root / "http-token"
        with open(token_file, "wb") as output:
            os.chmod(token_file, 0o600)
            output.write(token.encode())
        with socket.socket() as reserve:
            reserve.bind(("127.0.0.1", 0))
            self.port = reserve.getsockname()[1]
        self.process = subprocess.Popen([binary, "mcp", "--runtime-config", str(config),
            "--bind", f"127.0.0.1:{self.port}", "--auth-token-file", str(token_file)],
            cwd=root, env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "RUST_LOG": "error"},
            stdin=subprocess.DEVNULL, stdout=self.log, stderr=self.log)
        try:
            deadline = time.monotonic() + 15
            while True:
                if self.process.poll() is not None:
                    self.log.flush()
                    raise RuntimeError("isolated server exited: " +
                        pathlib.Path(self.log.name).read_text(errors="replace"))
                try:
                    self.client = Client(self.port, token)
                    break
                except (OSError, urllib.error.URLError):
                    if time.monotonic() >= deadline: raise
                    time.sleep(0.05)
        except BaseException:
            self.stop()
            raise
    def stop(self):
        if self.process.poll() is None: self.process.kill()
        self.process.wait(timeout=15)
        self.log.close()

def fixture():
    tensors, payload = {}, bytearray()
    for number in range(130):
        offset = len(payload)
        payload += struct.pack("<2f", number, number + 0.0625)
        tensors[f"t{number:04}"] = {"dtype": "F32", "shape": [2],
            "data_offsets": [offset, len(payload)]}
    header = json.dumps(tensors, separators=(",", ":"), sort_keys=True).encode()
    header += b" " * ((-len(header)) % 8)
    return struct.pack("<Q", len(header)) + header + payload

def main(binary):
    with tempfile.TemporaryDirectory(prefix="hepta-model-session-http-") as scratch:
        root = pathlib.Path(scratch)
        workspace, state, config = root / "workspace", root / "state", root / "policy.json"
        workspace.mkdir()
        policy = {"state_dir": str(state), "controller_workspace_roots": [str(workspace)],
            "hosts": {"denied": {"ssh_target": "never-connect-model-session-test",
                "remote_state_dir": str(root / "no-remote"), "allow_execute": False,
                "allow_pty": False, "allow_write": False, "allow_job_network": False}}}
        config.write_text(json.dumps(policy))
        source = workspace / "model.safetensors"
        content = fixture()
        source.write_bytes(content)
        source_hash = hashlib.sha256(content).hexdigest()
        token_a, token_b, server = secrets.token_hex(32), secrets.token_hex(32), None
        try:
            server = Server(binary, root, config, token_a)
            names = {item["name"] for item in server.client.rpc("tools/list", {}).get("tools", [])}
            assert {"rea_model_session_open", "rea_model_session_query", "rea_model_session_read", "rea_model_session_list"} <= names
            assert server.client.call("rea_model_session_list", {})["sessions"] == []
            opened = server.client.call("rea_model_session_open",
                {"path": str(source), "expected_sha256": source_hash})
            session_id = opened["session_id"]
            query = {"session_id": session_id, "collection": "tensors", "offset": 63, "limit": 66}
            read = {"session_id": session_id, "tensor_name": "t0063", "offset": 0, "length": 8}
            original_query = server.client.call("rea_model_session_query", query)
            original_read = server.client.call("rea_model_session_read", read)
            assert original_query["index_pages_read"] == 3
            assert original_query["directory_parse_count"] == 0
            assert original_read["bytes_hex"] == struct.pack("<2f", 63, 63.0625).hex()
            repeated = server.client.call("rea_model_session_open",
                {"path": str(source), "expected_sha256": source_hash})
            assert repeated["session_id"] == session_id and repeated["reused"]
            assert repeated["directory_parses_this_open"] == 0
            original_listing = server.client.call("rea_model_session_list", {})
            assert [item["session_id"] for item in original_listing["sessions"]] == [session_id]
            server.stop()
            server = None
            source.unlink()
            server = Server(binary, root, config, token_a)
            assert server.client.call("rea_model_session_list", {}) == original_listing
            assert server.client.call("rea_model_session_query", query) == original_query
            assert server.client.call("rea_model_session_read", read) == original_read
            server.stop()
            server = None
            server = Server(binary, root, config, token_b)
            assert server.client.call("rea_model_session_list", {})["sessions"] == []
            server.client.call("rea_model_session_query", query, denied=True)
            server.client.call("rea_model_session_read", read, denied=True)
            server.stop()
            server = None
            changed = dict(policy)
            changed["controller_workspace_roots"] = []
            config.write_text(json.dumps(changed))
            server = Server(binary, root, config, token_a)
            assert server.client.call("rea_model_session_list", {})["sessions"] == []
            server.client.call("rea_model_session_query", query, denied=True)
            server.stop()
            server = None
            config.write_text(json.dumps(policy))
            server = Server(binary, root, config, token_a)
            assert server.client.call("rea_model_session_read", read) == original_read
            snapshot = state / "rea-model-sessions-v1" / session_id / "snapshot.bin"
            with snapshot.open("r+b") as model:
                first = model.read(1)
                model.seek(0)
                model.write(bytes([first[0] ^ 0x80]))
                model.flush()
                os.fsync(model.fileno())
            server.client.call("rea_model_session_read", read, denied=True)
            print("REA_MODEL_SESSION_HTTP_QUALIFICATION " + json.dumps({
                "source_sha256": source_hash, "session_id": session_id,
                "cold_restart_same_credential": True, "source_absent_on_recovery": not source.exists(),
                "discovered_same_session_after_restart": True, "other_owner_and_policy_not_listed": True,
                "different_authenticated_owner_refused": True, "changed_policy_refused": True,
                "restored_policy_original_owner_recovers": True, "tampered_snapshot_refused": True,
                "page_result_identical_after_restart": True, "range_result_identical_after_restart": True,
                "production_credentials_used": False, "remote_host_contacted": False}, sort_keys=True),
                flush=True)
        finally:
            if server is not None: server.stop()

if __name__ == "__main__": main(sys.argv[1])

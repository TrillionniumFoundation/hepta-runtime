#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Disposable native V9 request-result compatibility fixture; never six-host or live qualification.

Starts only this script's loopback controllers with generated credentials and a
fixed local SSH-health emulator. No production config, token, service, remote
host or Desktop Commander is accessed. Explicit crash and storage faults affect
only private test-owned state. The emulator accepts only the frozen health argv
and never executes SSH, a caller command, a shell or a process-start operation.
"""
import argparse
import base64
import copy
import datetime
import hashlib
import json
import os
import pathlib
import re
import secrets
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy"))

ID_META = "io.hepta.runtime/request-v8"
ACK_META = "io.hepta.runtime/retention-v8"
RETAINED = {"host_list", "host_health", "effective_config"}
V7_SHA256 = "8ad53842e4aa41bbd1567ed99e956088baafea108b6fb0b9a8df979c72c794cc"
V8_SHA256 = "b64769210b9913fbdab28f7d0e95b7ef300d8710b3f1eeea74afcfac25b08318"
V9_SHA256 = "3eb628812d0c70b9af8393ecf9d0ce47f69b1438a134148f75ae2dd3132e6761"
PROTOCOL = "2026-07-28"
CLIENT_INFO = {"name": "hepta-v8-private-native-fixture", "version": "1"}
ALIAS = "v8-health-fixture"
TARGET = "v8-fixed-local-health-only"
HEALTH_COMMAND = "printf 'hepta-host-health-v1\\n'"
HEALTH_ARGV = [
    "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
    "-o", "StrictHostKeyChecking=yes", "-o", "ForwardAgent=no",
    "-o", "ClearAllForwardings=yes", "-o", "PermitLocalCommand=no",
    "-o", "RemoteCommand=none", "-o", "RequestTTY=no", "--",
    TARGET, HEALTH_COMMAND,
]
AUDIT_KEYS = {
    "request_id", "owner", "tool_name", "state",
    "accepted_unix_ms", "elapsed_ms",
}
PUBLIC_AUDIT_KEYS = AUDIT_KEYS - {"owner"}


def digest_bytes(data):
    return hashlib.sha256(data).hexdigest()


def digest(path):
    return digest_bytes(pathlib.Path(path).read_bytes())


def source_fingerprint():
    files = [ROOT / "Cargo.toml", ROOT / "Cargo.lock"]
    files += sorted(path for path in (ROOT / "src").rglob("*")
                    if path.is_file() and path.suffix in (".rs", ".py"))
    pins = {str(path.relative_to(ROOT)): {"bytes": path.stat().st_size, "sha256": digest(path)} for path in files}
    return digest_bytes(json.dumps(pins, sort_keys=True, separators=(",", ":")).encode())

def verify_explicit_pins(args, binary):
    expected = {
        "binary_sha256": (binary, args.expected_binary_sha256),
        "http_helper_sha256": (ROOT / "tests/runtime_http_acceptance.py", args.expected_http_helper_sha256),
        "contract_helper_sha256": (ROOT / "deploy/mcp_tool_contract.py", args.expected_contract_helper_sha256),
        "approval_loader_sha256": (ROOT / "tests/dc_successor_contract.py", args.expected_approval_loader_sha256),
    }
    observed = {}
    for key, (path, pin) in expected.items():
        if not re.fullmatch("[0-9a-f]{64}", pin): raise ValueError("explicit fresh SHA256 pin required")
        observed[key] = digest(path)
        assert observed[key] == pin, "explicit artifact or helper pin mismatch: " + key
    if not re.fullmatch("[0-9a-f]{64}", args.expected_source_fingerprint):
        raise ValueError("explicit fresh compiled source fingerprint required")
    observed["compiled_source_fingerprint"] = source_fingerprint()
    assert observed["compiled_source_fingerprint"] == args.expected_source_fingerprint, "compiled source fingerprint mismatch"
    return observed

def load_verified_helpers():
    # Explicit local helper hashes are verified before any helper code is imported.
    global ToolContract, make_contract, verify_successor
    from mcp_tool_contract import ToolContract, make_contract
    from dc_successor_contract import verify_successor


def until(predicate, seconds=15):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        found = predicate()
        if found:
            return found
        time.sleep(0.03)
    raise AssertionError("bounded private fixture observation deadline")


def write_private(path, data):
    with pathlib.Path(path).open("x", encoding="utf-8") as writer:
        writer.write(data)
    pathlib.Path(path).chmod(0o600)


class NativeClient:
    """Reviewed V7 HTTP pattern, with mandatory current-protocol request metadata."""
    def __init__(self, url, token):
        self.url = url
        self.token = token
        self.session = None
        self.serial = 0
        self.protocol = PROTOCOL
        initialized = self.rpc("initialize", {
            "protocolVersion": PROTOCOL, "capabilities": {},
            "clientInfo": CLIENT_INFO,
        })
        self.protocol = initialized["protocolVersion"]
        assert self.protocol in {"2025-06-18", "2025-11-25", PROTOCOL}
        self.rpc("notifications/initialized", {}, notify=True)

    def rpc(self, method, params, notify=False):
        self.serial += 1
        params = copy.deepcopy(params)
        if not notify and method != "initialize" and self.protocol == PROTOCOL:
            meta = params.setdefault("_meta", {})
            meta.setdefault("io.modelcontextprotocol/protocolVersion", PROTOCOL)
            meta.setdefault("io.modelcontextprotocol/clientCapabilities", {})
            meta.setdefault("io.modelcontextprotocol/clientInfo", CLIENT_INFO)
        request = {"jsonrpc": "2.0", "method": method, "params": params}
        if not notify:
            request["id"] = self.serial
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "X-Hepta-Runtime-Token": self.token,
            "MCP-Protocol-Version": self.protocol,
        }
        if self.session:
            headers["Mcp-Session-Id"] = self.session
        wire = urllib.request.Request(
            self.url, data=json.dumps(request).encode(), headers=headers,
        )
        with urllib.request.urlopen(wire, timeout=35) as response:
            self.session = response.headers.get("Mcp-Session-Id", self.session)
            raw = response.read(2 * 1024 * 1024 + 1)
            assert len(raw) <= 2 * 1024 * 1024
        if notify:
            return None
        text = raw.decode("utf-8")
        events = [
            json.loads(line[5:].strip()) for line in text.splitlines()
            if line.startswith("data:") and line[5:].strip()
        ]
        reply = events[-1] if events else json.loads(text)
        assert reply.get("id") == self.serial, (
            "native response identity mismatch", reply.get("id"), self.serial,
        )
        if "error" in reply:
            raise RuntimeError(reply["error"])
        return reply["result"]

    def raw_call(self, tool, params, meta=None):
        request = {"name": tool, "arguments": params}
        if meta is not None:
            request["_meta"] = meta
        raw = self.rpc("tools/call", request)
        wire_bytes = len(json.dumps(raw, ensure_ascii=False, separators=(",", ":")).encode())
        if tool in {"request_status", "request_result"}:
            assert wire_bytes <= 64 * 1024, "new lookup envelope exceeds 64 KiB after ID and ACK"
        if tool == "effective_config":
            assert wire_bytes <= 256 * 1024, "effective config fixture envelope exceeds 256 KiB"
        return raw

    def call(self, tool, params):
        raw = self.raw_call(tool, params)
        assert raw.get("isError") is not True
        return result_text(raw)


def result_text(raw):
    texts = [
        item["text"] for item in raw.get("content", [])
        if item.get("type") == "text"
    ]
    assert len(texts) == 1, "fixture expected one native text block"
    return json.loads(texts[0])


def request_identity(raw):
    assert raw.get("resultType", "complete") == "complete"
    marker = raw["_meta"][ID_META]
    assert set(marker) == {"request_id", "automatic_retry", "delivery_proven"}
    assert re.fullmatch("[0-9a-f]{64}", marker["request_id"])
    assert marker["automatic_retry"] is False
    assert marker["delivery_proven"] is False
    return marker["request_id"]


def retention_ack(raw, expected=None):
    ack = raw["_meta"][ACK_META]
    assert ack["automatic_retry"] is False
    assert type(ack["audit_completion_durable"]) is bool
    assert ack["semantics"] == (
        "native_generated_result_before_retention_ack_and_transport_normalization; delivery unproven"
    )
    if expected is not None:
        assert ack["result_state"] == expected
    return ack


def denied(client, tool, params, meta=None):
    try:
        raw = client.raw_call(tool, params, meta)
    except RuntimeError as error:
        assert isinstance(error.args[0], dict) and "code" in error.args[0]
        return {"kind": "jsonrpc_error", "code": error.args[0]["code"]}
    assert raw.get("isError") is True, "fixture refusal unexpectedly succeeded"
    return {"kind": "tool_error"}


def wrong_bearer_status(url, token, session):
    request = urllib.request.Request(
        url, data=b"{}", headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "X-Hepta-Runtime-Token": token,
            "MCP-Protocol-Version": PROTOCOL,
            "Mcp-Session-Id": session,
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code


def owned_history(client, **params):
    value = client.call("request_history", {"limit": 32, **params})
    assert value["ownership_scope"] == "authenticated_private_operator_credential"
    assert value["credential_metadata_resume"] is True
    assert value["cross_session_resume"] is True
    assert value["authenticated_chatgpt_caller_isolation"] is False
    for row in value["requests"]:
        assert set(row) == PUBLIC_AUDIT_KEYS
    return value


def all_owned_history(client):
    rows = []
    seen = set()
    cursor = None
    for _ in range(12):
        page = owned_history(client, **({"after_id": cursor} if cursor else {}))
        for row in page["requests"]:
            assert row["request_id"] not in seen
            seen.add(row["request_id"])
            rows.append(row)
        cursor = page["next_after_id"]
        if cursor is None:
            return rows
    raise AssertionError("bounded owned-history cursors did not terminate")


def excluded_call_identity(client, tool, params):
    before = {row["request_id"] for row in all_owned_history(client)}
    # Isolate the target call's millisecond timestamp from history observations.
    time.sleep(.003)
    raw = client.raw_call(tool, params)
    assert ID_META not in raw.get("_meta", {})
    assert ACK_META not in raw.get("_meta", {})
    time.sleep(.003)
    fresh = [row for row in all_owned_history(client)
             if row["request_id"] not in before and row["tool_name"] == tool]
    assert fresh, "excluded call absent from owned path-free audit cursors"
    # For request_history, subsequent observation calls also generate metadata;
    # the explicitly separated target is the first new accepted record.
    target = min(fresh, key=lambda row: (row["accepted_unix_ms"], row["request_id"]))
    return raw, target["request_id"]


def original_native(raw):
    original = copy.deepcopy(raw)
    # rmcp omits the default discriminator for negotiated legacy peers.
    original.setdefault("resultType", "complete")
    original["_meta"].pop(ACK_META)
    assert set(original["_meta"]) == {ID_META}
    return original


def reconstructed(client, request_id, expected_native=None, page_limit=4096):
    offset = 0
    assembled = bytearray()
    expected_digest = None
    expected_total = None
    pages = 0
    # Independent bounded pages; retain original IDs within the audit quota.
    while pages < 8192:
        raw = client.raw_call("request_result", {
            "request_id": request_id, "offset": offset, "limit": page_limit,
        })
        request_identity(raw)
        retention_ack(raw, "not_retained_policy")
        page = result_text(raw)
        assert page["request_id"] == request_id
        assert page["offset"] == offset
        assert page["automatic_retry"] is False
        assert page["delivery_proven"] is False
        assert page["immutable_snapshot"] is True
        assert page["format"] == (
            "serialized_native_CallToolResult_with_request_identity_before_retention_ack_and_transport_normalization"
        )
        assert page["total_bytes"] <= 65536
        if expected_digest is None:
            expected_digest = page["result_sha256"]
            expected_total = page["total_bytes"]
        assert page["result_sha256"] == expected_digest
        assert page["total_bytes"] == expected_total
        chunk = base64.b64decode(page["data_base64"], validate=True)
        assert len(chunk) <= page_limit
        assert page["next_offset"] == offset + len(chunk)
        assembled.extend(chunk)
        offset = page["next_offset"]
        pages += 1
        if page["eof"]:
            assert offset == expected_total
            break
        assert chunk, "nonterminal fixture page failed to advance"
    else:
        raise AssertionError("bounded original-result paging did not terminate")
    native_bytes = bytes(assembled)
    assert digest_bytes(native_bytes) == expected_digest
    assert len(native_bytes) == expected_total
    recovered = json.loads(native_bytes)
    assert recovered["resultType"] == "complete"
    assert ACK_META not in recovered.get("_meta", {})
    assert recovered["_meta"][ID_META]["request_id"] == request_id
    if expected_native is not None:
        assert recovered == expected_native, "retained original native envelope changed"
    # Repeated first page is immutable and uses independent cursors.
    repeated = client.call("request_result", {
        "request_id": request_id, "offset": 0, "limit": min(17, page_limit),
    })
    assert base64.b64decode(repeated["data_base64"], validate=True) == native_bytes[:min(17, page_limit)]
    assert repeated["result_sha256"] == expected_digest
    return native_bytes, {"pages": pages, "bytes": expected_total, "sha256": expected_digest}


class HTTPController:
    """Owns only children spawned in an isolated process group by this fixture."""
    def __init__(self, binary, workspace, config, tokenfile, env, logdir, tag="native"):
        self.binary = binary
        self.workspace = workspace
        self.config = config
        self.tokenfile = tokenfile
        self.env = env
        self.logdir = logdir
        self.tag = tag
        self.children = []
        self.child = None
        self.url = None

    def start(self):
        assert self.child is None or self.child.poll() is not None
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        self.url = f"http://127.0.0.1:{port}/mcp"
        logfile = self.logdir / f"{self.tag}-{len(self.children):02d}.log"
        with logfile.open("xb") as writer:
            logfile.chmod(0o600)
            self.child = subprocess.Popen([
                str(self.binary), "mcp", "--path", str(self.workspace),
                "--bind", f"127.0.0.1:{port}",
                "--runtime-config", str(self.config),
                "--auth-token-file", str(self.tokenfile),
            ], env=self.env, stdin=subprocess.DEVNULL, stdout=writer,
                stderr=writer, start_new_session=True)
        self.children.append(self.child)

        def ready():
            if self.child.poll() is not None:
                raise AssertionError("test-owned controller exited before readiness")
            try:
                return NativeClient(self.url, self.tokenfile.read_text().strip())
            except (OSError, RuntimeError):
                return None
        return until(ready)

    def stop(self, crash=False):
        if self.child is not None and self.child.poll() is None:
            os.killpg(self.child.pid, signal.SIGKILL if crash else signal.SIGTERM)
            try:
                self.child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(self.child.pid, signal.SIGKILL)
                self.child.wait(timeout=5)

    def cleanup(self):
        self.stop()
        for child in self.children:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=5)


def install_fixed_health_emulator(root):
    bindir = root / "bin"
    bindir.mkdir(mode=0o700)
    wrapper = bindir / "ssh"
    # Only exact fixed server-generated health argv is admitted. No shell fallback.
    code = (
        "#!/usr/bin/python3\n"
        "import json,os,pathlib,sys,time\n"
        f"root=pathlib.Path({str(root)!r})\n"
        f"expected={HEALTH_ARGV!r}\n"
        "if sys.argv[1:]!=expected:raise SystemExit('fixed health fixture argv refused')\n"
        "with (root/'ssh-count').open('a') as f:f.write('fixed-health\\n')\n"
        "if (root/'health-gate').exists():\n"
        " (root/'health-admitted').write_text('fixed-health-admitted')\n"
        " parent=os.getppid();deadline=time.monotonic()+15\n"
        " while (root/'health-gate').exists() and os.getppid()==parent:\n"
        "  if time.monotonic()>=deadline:raise SystemExit(86)\n"
        "  time.sleep(.02)\n"
        " if os.getppid()!=parent:raise SystemExit(86)\n"
        "sys.stdout.write('hepta-host-health-v1\\n');sys.stdout.flush()\n"
    )
    write_private(wrapper, code)
    wrapper.chmod(0o700)
    env = dict(os.environ)
    env["PATH"] = str(bindir) + ":" + env.get("PATH", "")
    return env


def health_count(root):
    counter = root / "ssh-count"
    return counter.read_text().count("fixed-health\n") if counter.exists() else 0


def pending_record(state, old_names):
    matches = []
    for path in (state / "request-results").glob("*.json"):
        if path.name not in old_names:
            value = json.loads(path.read_bytes())
            if value["tool_name"] == "host_health" and value["state"] == "unknown":
                matches.append(value)
    assert len(matches) <= 1
    return matches[0] if matches else None


def start_blocked_health(client, root):
    (root / "health-admitted").unlink(missing_ok=True)
    (root / "health-gate").touch(mode=0o600)
    outcome = {}

    def invoke():
        try:
            outcome["raw"] = client.raw_call("host_health", {"host": ALIAS})
        except Exception as error:
            # Never persist exception repr containing auth material or headers.
            outcome["error_type"] = type(error).__name__
    thread = threading.Thread(target=invoke, daemon=True)
    thread.start()
    until((root / "health-admitted").exists)
    return thread, outcome


def traceback_frames(frame):
    while frame is not None:
        yield frame
        frame = frame.tb_next


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--expected-binary-sha256", required=True)
    parser.add_argument("--expected-source-fingerprint", "--compiled-source-fingerprint", dest="expected_source_fingerprint", required=True)
    parser.add_argument("--expected-http-helper-sha256", required=True)
    parser.add_argument("--expected-contract-helper-sha256", required=True)
    parser.add_argument("--expected-approval-loader-sha256", required=True)
    parser.add_argument("--output", "--out", dest="output", required=True)
    contracts = parser.add_mutually_exclusive_group(required=True)
    contracts.add_argument("--contract")
    contracts.add_argument("--export-contract")
    args = parser.parse_args()
    binary = pathlib.Path(args.binary).resolve(strict=True)
    pins = verify_explicit_pins(args, binary)
    load_verified_helpers()
    contract_path = pathlib.Path(args.contract or args.export_contract).resolve()
    if args.contract:
        contract_path = contract_path.resolve(strict=True)
        ToolContract.load(contract_path, V9_SHA256)
    else:
        assert not contract_path.exists(), "never overwrite an earlier exported catalog"
    outfile = pathlib.Path(args.output).resolve()
    assert not outfile.exists(), "refusing to overwrite a previous fixture receipt"
    outfile.parent.mkdir(parents=True, exist_ok=True)
    logdir = outfile.parent / (outfile.stem + "-logs")
    logdir.mkdir(mode=0o700, exist_ok=False)
    report = {
        "schema": "hepta-dc-v9-request-results-native-fixture-v1",
        "recorded_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "origin": "disposable_native_http_fixture",
        "binary_sha256": digest(binary),
        "harness_sha256": digest(__file__),
        "explicit_observed_pins": pins,
        "adapted_from_script": "tests/dc_functional_v8_request_results_acceptance.py",
        "adapted_from_script_sha256": "802cc3f6230aa7a49cce11593bf1c11fc41941bb726f7dc2ab8e64ce0b944c10",
        "all_original_v8_request_result_checks_retained": True,
        "v9_async_start_cancel_qualified": False,
        "contract_sha256": digest(contract_path) if args.contract else None,
        "catalog_mode": "reviewed-pinned-contract" if args.contract else "unreviewed-export-candidate",
        "exact_reviewed_contract_qualified": False,
        "qualification_scope": "local_native_request_result_fixture_only",
        "checks": [], "complete": False,
        "installed_runtime_changed": False,
        "desktop_commander_changed": False,
        "real_ssh_qualified": False,
        "six_machine_qualified": False,
        "model_origin_qualified": False,
        "authenticated_chatgpt_caller_isolation": False,
        "job_pty_caller_ownership_qualified": False,
        "production_recovery_rollback_qualified": False,
        "full_dc_replacement_qualified": False,
        "fault_scope": "disposable local fixed read-only health emulator and private state",
        "limits": [
            "The native health emulator is a local fixture; no SSH authentication or real target health is proven.",
            "No existing credentials, runtime service, remote host, user data or Desktop Commander is accessed.",
            "The serialized native result precedes retention ACK; transport delivery and business success remain unproven.",
            "Controller crash and late storage failure are fixture faults around a fixed read-only challenge.",
            "Shared operator credentials share retained metadata; this does not prove ChatGPT user isolation.",
        ],
    }
    private_values = []
    controller = None
    current = "prepare disposable fixture"

    def save():
        encoded = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
        assert all(value not in encoded for value in private_values if value)
        outfile.write_text(encoded)
        outfile.chmod(0o600)

    def passed(name, details=None):
        report["checks"].append({"check": name, "result": "passed", "detail": details})
        save()
        print("PASS", name, flush=True)

    save()
    try:
        with tempfile.TemporaryDirectory(prefix="hepta-v8-results-fixture-") as tmp:
            root = pathlib.Path(tmp).resolve()
            root.chmod(0o700)
            workspace = root / "workspace"
            workspace.mkdir(mode=0o700)
            alternate = root / "alternate-workspace"
            alternate.mkdir(mode=0o700)
            state = root / "state"
            remote = root / "unused-remote"
            sentinel = "SECRET_VIEW_FIXTURE_" + secrets.token_hex(12)
            spoof = "CALLER_SPOOF_FIXTURE_" + secrets.token_hex(12)
            token_a = secrets.token_hex(32)
            token_b = secrets.token_hex(32)
            private_values.extend([token_a, token_b, sentinel, spoof])
            tokenfile = root / "token"
            write_private(tokenfile, token_a)
            fixture = workspace / "private-view.txt"
            write_private(fixture, sentinel + "\n")
            cfg = {
                "state_dir": str(state),
                "controller_workspace_roots": [str(workspace)],
                "hosts": {ALIAS: {
                    "ssh_target": TARGET, "platform": "linux",
                    "execution_mode": "isolated", "allow_execute": False,
                    "allow_pty": False, "allow_write": False,
                    "allow_job_network": False, "allow_detached_fallback": False,
                    "remote_state_dir": str(remote),
                    "allowed_read_path_prefixes": [str(workspace)],
                    "allowed_write_path_prefixes": [],
                }},
            }
            config = root / "runtime.json"
            write_private(config, json.dumps(cfg))
            env = install_fixed_health_emulator(root)
            controller = HTTPController(binary, workspace, config, tokenfile, env, logdir)
            client = controller.start()
            report["requested_protocol_version"] = PROTOCOL
            report["negotiated_protocol_version"] = client.protocol
            report["snapshot_comparison_normalization"] = (
                "legacy implicit resultType=complete restored; retention ACK removed"
                if client.protocol != PROTOCOL else "retention ACK removed; modern native fields unchanged"
            )

            current = "reviewed V9 catalog and exact V8 predecessor definitions"
            tools = client.rpc("tools/list", {})["tools"]
            if args.export_contract:
                contract_path.parent.mkdir(parents=True, exist_ok=True)
                write_private(contract_path, json.dumps(
                    make_contract(tools), indent=2, ensure_ascii=False,
                ) + "\n")
            reviewed = ToolContract.load(contract_path, V9_SHA256)
            reviewed.verify(tools)
            # Export verifies exact predecessors and candidate structure only.
            # Reviewed admission must follow explicit pinning in the shared helper.
            if args.contract:
                verify_successor(tools, contract_path)
                report["exact_reviewed_contract_qualified"] = True
            report["contract_sha256"] = digest(contract_path)
            v7 = ToolContract.load(
                ROOT / "deploy/contracts/hepta-runtime-full-operator-v7.json", V7_SHA256,
            )
            v8 = ToolContract.load(ROOT / "deploy/contracts/hepta-runtime-full-operator-v8.json", V8_SHA256)
            actual = {tool["name"]: tool for tool in tools}
            assert len(tools) == len(actual) == 62
            assert set(actual) - set(v8.by_name) == {"request_start", "request_cancel"}
            assert all(actual[name] == definition for name, definition in v8.by_name.items())
            assert set(v8.by_name) - set(v7.by_name) == {"request_status", "request_result"}
            assert all(actual[name] == definition for name, definition in v7.by_name.items())
            for name in ("request_status", "request_result"):
                assert actual[name]["inputSchema"]["additionalProperties"] is False
                assert "owner" not in actual[name]["inputSchema"].get("properties", {})
                assert actual[name]["annotations"]["readOnlyHint"] is True
            report["catalog_sha256"] = reviewed.catalog_sha256
            # Keep the historical reviewed V7 positive control; refuse unknown
            # self-consistent recomputed catalogs even when their hashes agree.
            verify_successor(v7.tools, ROOT / "deploy/contracts/hepta-runtime-full-operator-v7.json")
            verify_successor(v8.tools, ROOT / "deploy/contracts/hepta-runtime-full-operator-v8.json")
            negative_catalogs = []
            for label in ("original-v4-drift", "new-tool-hint-drift", "new-tool-owner-input"):
                mutated = copy.deepcopy(tools)
                tool = next(item for item in mutated if item["name"] == (
                    "shell_start" if label == "original-v4-drift" else "request_result"
                ))
                if label == "original-v4-drift":
                    tool["description"] += " unreviewed candidate"
                elif label == "new-tool-hint-drift":
                    tool["annotations"]["readOnlyHint"] = False
                else:
                    tool["inputSchema"]["properties"]["owner"] = {"type": "string"}
                unknown_path = root / (label + ".json")
                write_private(unknown_path, json.dumps(
                    make_contract(mutated), indent=2, ensure_ascii=False,
                ) + "\n")
                try:
                    verify_successor(mutated, unknown_path)
                except (ValueError, AssertionError):
                    negative_catalogs.append(label)
                else:
                    raise AssertionError("unknown self-consistent catalog was accepted")
            passed(current, {
                "tool_count": 62, "all_previous_definitions_exact": True,
                "all60_v8_definitions_exact": True,
                "only_v9_added_names": ["request_start", "request_cancel"],
                "new_tools": ["request_status", "request_result"],
                "old_v7_positive_control": True, "old_v8_positive_control": True,
                "recomputed_unknown_catalogs_refused": negative_catalogs,
                "reviewed_pin_verified": bool(args.contract),
                "export_requires_separate_explicit_review": bool(args.export_contract),
            })

            current = "three reviewed DTO tools retain exact native envelopes and server identities"
            originals = {}
            request_ids = {}
            reconstruction = {}
            for tool, params in [
                ("host_list", {}), ("effective_config", {}),
                ("host_health", {"host": ALIAS}),
            ]:
                raw = client.raw_call(tool, params)
                assert raw.get("isError") is not True
                request_id = request_identity(raw)
                assert retention_ack(raw, "stored")["audit_completion_durable"] is True
                original = original_native(raw)
                bytes_, detail = reconstructed(client, request_id, original, page_limit=257)
                assert raw["_meta"][ID_META]["request_id"] == request_id
                status = client.call("request_status", {"request_id": request_id})
                assert status["dispatch_state"] == "completed"
                assert status["result_state"] == "stored"
                assert status["result_bytes"] == len(bytes_)
                assert status["automatic_retry"] is False
                assert status["early_return_async_start_supported"] is False
                if tool == "host_health":
                    health = result_text(raw)
                    assert health["status"] == "healthy"
                    assert health["reachable"] is True and health["authenticated"] is True
                    assert health["diagnostics_redacted"] is True
                (logdir / (tool + ".native-result.json")).write_bytes(bytes_)
                (logdir / (tool + ".observed-response.json")).write_text(
                    json.dumps(raw, indent=2, ensure_ascii=False) + "\n",
                )
                request_ids[tool] = request_id
                originals[request_id] = original
                reconstruction[tool] = detail
            assert health_count(root) == 1
            passed(current, {
                "retained_tools": sorted(RETAINED), "native_pages": reconstruction,
                "actual_request_identity": "server-generated _meta; never JSON-RPC caller ID",
                "reference": "raw negotiated-protocol result minus retention ACK; legacy default complete discriminator restored",
                "wire_budget_checks": "effective_config <=256 KiB; lookup replies <=64 KiB including metadata",
                "boundaries": "actual small-fixture envelopes; maximum DTO boundary tests remain Rust-specific",
                "health_origin": "fixed local emulator; no real SSH qualification",
            })

            current = "oldest retained result stays readable while its owner audit quota is full"
            capacity_cfg = copy.deepcopy(cfg)
            capacity_cfg["state_dir"] = str(root / "capacity-state")
            capacity_config = root / "capacity-runtime.json"
            write_private(capacity_config, json.dumps(capacity_cfg))
            capacity_token = secrets.token_hex(32)
            private_values.append(capacity_token)
            capacity_tokenfile = root / "capacity-token"
            write_private(capacity_tokenfile, capacity_token)
            capacity = HTTPController(
                binary, workspace, capacity_config, capacity_tokenfile, env, logdir, tag="capacity-native",
            )
            try:
                capacity_client = capacity.start()
                oldest_raw = capacity_client.raw_call("host_list", {})
                oldest_id = request_identity(oldest_raw)
                retention_ack(oldest_raw, "stored")
                oldest_original = original_native(oldest_raw)
                for _ in range(127):
                    capacity_client.call("request_history", {"limit": 1})
                capacity_audit = root / "capacity-state" / "request-audit"
                assert len(list(capacity_audit.glob("*.json"))) == 128
                assert (capacity_audit / (oldest_id + ".json")).exists()
                offset = 0
                replayed = bytearray()
                page_count = 0
                while page_count < 65536:
                    if page_count % 31 == 0:
                        status = capacity_client.call("request_status", {"request_id": oldest_id})
                        assert status["result_state"] == "stored"
                        assert status["dispatch_state"] == "completed"
                    page = capacity_client.call("request_result", {
                        "request_id": oldest_id, "offset": offset, "limit": 1,
                    })
                    fragment = base64.b64decode(page["data_base64"], validate=True)
                    assert len(fragment) <= 1 and page["offset"] == offset
                    replayed.extend(fragment)
                    offset = page["next_offset"]
                    page_count += 1
                    assert (capacity_audit / (oldest_id + ".json")).exists()
                    assert len(list(capacity_audit.glob("*.json"))) == 128
                    if page["eof"]:
                        assert digest_bytes(bytes(replayed)) == page["result_sha256"]
                        break
                else:
                    raise AssertionError("one-byte quota fixture pagination exceeded bounded native result")
                assert json.loads(bytes(replayed)) == oldest_original
                reconstructed(capacity_client, oldest_id, oldest_original)
                assert len(list((root / "capacity-state" / "request-results").glob("*.json"))) == 1
                assert health_count(root) == 1
                passed(current, {
                    "owner_audit_quota": 128, "oldest_record_preserved": True,
                    "one_byte_pages_under_quota": page_count,
                    "repeated_status_preserves_target": True, "recursive_retained_payloads": 0,
                    "independent_capacity_fixture": True,
                })
            finally:
                capacity.cleanup()
                controller.children.extend(capacity.children)

            current = "large reviewed DTO remains live while bounded retention honestly reports overflow"
            overflow_cfg = copy.deepcopy(cfg)
            overflow_cfg["state_dir"] = str(root / "overflow-state")
            template = copy.deepcopy(cfg["hosts"][ALIAS])
            overflow_cfg["hosts"] = {
                f"overflow-{index:03d}-" + "a" * 40: copy.deepcopy(template)
                for index in range(256)
            }
            overflow_config = root / "overflow-runtime.json"
            write_private(overflow_config, json.dumps(overflow_cfg))
            overflow_token = secrets.token_hex(32)
            private_values.append(overflow_token)
            overflow_tokenfile = root / "overflow-token"
            write_private(overflow_tokenfile, overflow_token)
            overflow_controller = HTTPController(
                binary, workspace, overflow_config, overflow_tokenfile, env, logdir, tag="overflow-native",
            )
            try:
                overflow_client = overflow_controller.start()
                large_raw = overflow_client.raw_call("effective_config", {})
                overflow_id = request_identity(large_raw)
                ack = retention_ack(large_raw, "overflow")
                assert ack["audit_completion_durable"] is True
                large_dto = result_text(large_raw)
                assert large_dto["schema"] == "hepta-effective-config-v1"
                assert len(large_dto["hosts"]) == 256
                assert large_dto["controller"]["workspace_root_count"] == 1
                wire_size = len(json.dumps(
                    large_raw, ensure_ascii=False, separators=(",", ":"),
                ).encode())
                assert 64 * 1024 < wire_size <= 256 * 1024
                status = overflow_client.call("request_status", {"request_id": overflow_id})
                assert status["dispatch_state"] == "completed"
                assert status["result_state"] == "overflow"
                assert status["result_bytes"] is None
                denied(overflow_client, "request_result", {"request_id": overflow_id})
                ledger = json.loads((
                    root / "overflow-state" / "request-results" / (overflow_id + ".json")
                ).read_bytes())
                assert ledger["state"] == "overflow"
                assert ledger["payload_base64"] is None
                assert ledger["payload_bytes"] is None
                assert ledger["payload_sha256"] is None
                assert ledger["request_id"] == overflow_id
                (logdir / "overflow.effective-config.observed-response.json").write_text(
                    json.dumps(large_raw, ensure_ascii=False, separators=(",", ":")) + "\n",
                )
                passed(current, {
                    "configured_hosts": 256, "complete_live_dto_preserved": True,
                    "same_server_id": True, "live_wire_bytes": wire_size,
                    "retention_state": "overflow", "retained_payload_bytes": 0,
                    "native_request_result_refused": True,
                    "original_dispatch_separate_from_retention_limit": True,
                })
            finally:
                overflow_controller.cleanup()
                controller.children.extend(overflow_controller.children)

            current = "same private credential reconnect and controller restart preserve original bytes"
            fresh = NativeClient(client.url, token_a)
            assert fresh.session != client.session
            for request_id, original in originals.items():
                reconstructed(fresh, request_id, original)
            controller.stop()
            restarted = controller.start()
            for request_id, original in originals.items():
                reconstructed(restarted, request_id, original)
            assert health_count(root) == 1, "result retrieval replayed the fixed health operation"
            client = restarted
            passed(current, {"reconnect_and_restart": True, "health_replay_count": 0})

            current = "owner spoof, invalid identities and byte page bounds are refused"
            target_id = request_ids["host_list"]
            for tool in ("request_status", "request_result"):
                for extra in ("owner", "credential", "caller_id", "token", "host"):
                    denied(client, tool, {"request_id": target_id, extra: spoof})
                for invalid_id in ("", "../outside", "f" * 63, "g" * 64):
                    denied(client, tool, {"request_id": invalid_id})
            total = reconstruction["host_list"]["bytes"]
            for invalid in [
                {"limit": 0}, {"limit": 16385}, {"offset": total + 1},
                {"offset": -1}, {"limit": -1}, {"offset": 2**32},
            ]:
                denied(client, "request_result", {"request_id": target_id, **invalid})
            eof = client.call("request_result", {
                "request_id": target_id, "offset": total, "limit": 1,
            })
            assert eof["eof"] is True and eof["data_base64"] == ""
            supplied = copy.deepcopy(originals[target_id]["_meta"])
            supplied["owner"] = spoof
            supplied[ID_META]["request_id"] = "e" * 64
            raw = client.raw_call("host_list", {}, supplied)
            assert request_identity(raw) != "e" * 64
            assert retention_ack(raw, "stored")["audit_completion_durable"] is True
            # Request metadata must not be echoed into a result or persisted.
            assert spoof not in json.dumps(raw)
            passed(current, {"strict_argument_and_bounds_refusals": True, "caller_meta_does_not_select_identity": True})

            current = "view and metadata lookups never retain excluded or recursive payloads"
            viewed, viewed_id = excluded_call_identity(client, "view", {"path": str(fixture)})
            assert sentinel in viewed["content"][0]["text"]
            assert client.call("request_status", {"request_id": viewed_id})["result_state"] == "not_retained_policy"
            denied(client, "request_result", {"request_id": viewed_id})
            history_raw, history_id = excluded_call_identity(client, "request_history", {"limit": 32})
            assert result_text(history_raw)["ownership_scope"] == "authenticated_private_operator_credential"
            denied(client, "request_result", {"request_id": history_id})
            before_results = {p.name for p in (state / "request-results").glob("*.json")}
            looked = client.raw_call("request_result", {"request_id": target_id, "limit": 1})
            looked_id = request_identity(looked)
            retention_ack(looked, "not_retained_policy")
            status_raw = client.raw_call("request_status", {"request_id": target_id})
            status_id = request_identity(status_raw)
            retention_ack(status_raw, "not_retained_policy")
            denied(client, "request_result", {"request_id": looked_id})
            denied(client, "request_result", {"request_id": status_id})
            assert {p.name for p in (state / "request-results").glob("*.json")} == before_results
            for excluded_id in (viewed_id, history_id, looked_id, status_id):
                assert not (state / "request-results" / (excluded_id + ".json")).exists()
            passed(current, {"excluded_tools": ["view", "request_history", "request_status", "request_result"], "recursive_cache_count": 0})

            current = "controller crash leaves unknown result intent and never replays health"
            before_results = {p.name for p in (state / "request-results").glob("*.json")}
            thread, outcome = start_blocked_health(client, root)
            pending = until(lambda: pending_record(state, before_results))
            unknown_id = pending["request_id"]
            assert pending["payload_base64"] is None
            before_count = health_count(root)
            controller.stop(crash=True)
            thread.join(timeout=5)
            assert not thread.is_alive()
            assert "raw" not in outcome
            (root / "health-gate").unlink()
            client = controller.start()
            status = client.call("request_status", {"request_id": unknown_id})
            assert status["dispatch_state"] == "unknown"
            assert status["result_state"] == "unknown"
            denied(client, "request_result", {"request_id": unknown_id})
            assert health_count(root) == before_count
            assert any(row["request_id"] == unknown_id and row["state"] == "unknown"
                       for row in all_owned_history(client))
            passed(current, {
                "intent_id_origin": "test-owned durable pending record; response never delivered",
                "pending_unknown_after_restart": True,
                "health_lookup_replay_count": 0,
                "crash_scope": "only fixture controller process group",
            })

            current = "late result-store permissions fault preserves original content and same server ID"
            before_results = {p.name for p in (state / "request-results").glob("*.json")}
            thread, outcome = start_blocked_health(client, root)
            pending = until(lambda: pending_record(state, before_results))
            late_id = pending["request_id"]
            result_store = state / "request-results"
            result_store.chmod(0o750)
            try:
                (root / "health-gate").unlink()
                thread.join(timeout=8)
                assert not thread.is_alive()
                assert "raw" in outcome and "error_type" not in outcome
                raw = outcome["raw"]
                assert raw.get("isError") is not True
                assert request_identity(raw) == late_id
                ack = retention_ack(raw, "durability_unknown")
                assert ack["audit_completion_durable"] is True
                health = result_text(raw)
                assert health["status"] == "healthy" and health["reachable"] is True
                assert health["authenticated"] is True
            finally:
                result_store.chmod(0o700)
            before_count = health_count(root)
            status = client.call("request_status", {"request_id": late_id})
            assert status["dispatch_state"] == "completed"
            assert status["result_state"] == "unknown"
            denied(client, "request_result", {"request_id": late_id})
            assert health_count(root) == before_count
            passed(current, {
                "fault": "test-owned result directory widened only after fixed health admission",
                "original_health_content_preserved": True, "server_identity_preserved": True,
                "retention_failure_separate_from_dispatch": True, "automatic_replay_count": 0,
            })

            current = "whole config root and host revocation deny old bytes while path-free audit remains"
            controller.stop()
            revocations = []
            changed_roots = copy.deepcopy(cfg)
            changed_roots["controller_workspace_roots"] = [str(alternate)]
            changed_roots["hosts"][ALIAS]["allowed_read_path_prefixes"] = [str(alternate)]
            changed_host = copy.deepcopy(cfg)
            changed_host["hosts"] = {
                "revoked-v8-fixture": {
                    **changed_host["hosts"][ALIAS],
                    "ssh_target": "revoked-fixed-fixture-target",
                }
            }
            for label, revoked in [("root-policy-change", changed_roots), ("host-binding-change", changed_host)]:
                config.write_text(json.dumps(revoked))
                client = controller.start()
                before_count = health_count(root)
                for old_id in originals:
                    denied(client, "request_result", {"request_id": old_id})
                    # V8 conservatively denies whole request_status if policy binding changed.
                    denied(client, "request_status", {"request_id": old_id})
                audit = owned_history(client)
                encoded = json.dumps(audit)
                assert str(root) not in encoded and TARGET not in encoded
                assert any(row["request_id"] in originals for row in audit["requests"])
                assert health_count(root) == before_count
                revocations.append({"case": label, "old_bytes_refused": True, "path_free_audit_visible": True})
                controller.stop()
            config.write_text(json.dumps(cfg))
            client = controller.start()
            for old_id, original in originals.items():
                reconstructed(client, old_id, original)
            passed(current, {"cases": revocations, "restored_exact_policy_originals_unchanged": True})

            current = "credential rotation rejects old owner even with request owner metadata spoof"
            assert wrong_bearer_status(client.url, token_b, client.session) == 401
            controller.stop()
            tokenfile.write_text(token_b)
            tokenfile.chmod(0o600)
            client_b = controller.start()
            assert wrong_bearer_status(client_b.url, token_a, client_b.session) == 401
            for old_id in originals:
                denied(client_b, "request_status", {"request_id": old_id})
                denied(client_b, "request_result", {"request_id": old_id}, {
                    "owner": spoof, "request_id": old_id,
                    ID_META: {"request_id": old_id},
                })
            rows_b = owned_history(client_b)["requests"]
            assert not set(originals) & {row["request_id"] for row in rows_b}
            raw_b = client_b.raw_call("host_list", {})
            b_id = request_identity(raw_b)
            assert b_id not in originals
            retention_ack(raw_b, "stored")
            reconstructed(client_b, b_id, original_native(raw_b))
            passed(current, {
                "other_bearer_live_http_status": 401,
                "new_credential_old_owner_lookup": "refused",
                "caller_meta_cannot_select_old_scope": True,
                "new_credential_can_retain_own_result": True,
            })

            current = "private audit schema and bounded payload stores exclude credentials and arbitrary output"
            controller.stop()
            auditdir = state / "request-audit"
            resultdir = state / "request-results"
            assert stat.S_IMODE(auditdir.stat().st_mode) == 0o700
            assert stat.S_IMODE(resultdir.stat().st_mode) == 0o700
            audit_count = stored_count = pending_count = 0
            for path in auditdir.glob("*.json"):
                info = path.stat()
                assert not path.is_symlink() and info.st_nlink == 1
                assert stat.S_IMODE(info.st_mode) == 0o600
                raw = path.read_bytes()
                assert len(raw) <= 2048
                value = json.loads(raw)
                assert set(value) == AUDIT_KEYS
                assert all(private.encode() not in raw for private in private_values)
                assert str(root).encode() not in raw
                audit_count += 1
            for path in resultdir.glob("*.json"):
                info = path.stat()
                assert not path.is_symlink() and info.st_nlink == 1
                assert stat.S_IMODE(info.st_mode) == 0o600
                raw = path.read_bytes()
                assert len(raw) <= 96 * 1024
                value = json.loads(raw)
                assert value["tool_name"] in RETAINED
                assert all(private.encode() not in raw for private in private_values)
                assert str(root).encode() not in raw
                if value["state"] == "stored":
                    payload = base64.b64decode(value["payload_base64"], validate=True)
                    assert len(payload) == value["payload_bytes"] <= 65536
                    assert digest_bytes(payload) == value["payload_sha256"]
                    captured = json.loads(payload)
                    assert set(captured["_meta"]) == {ID_META}
                    assert captured["_meta"][ID_META]["request_id"] == value["request_id"]
                    assert all(private.encode() not in payload for private in private_values)
                    assert str(root).encode() not in payload
                    assert TARGET.encode() not in payload
                    stored_count += 1
                else:
                    assert value["payload_base64"] is None
                    pending_count += 1
            assert stored_count >= 4 and pending_count == 2
            assert all(child.poll() is not None for child in controller.children)
            passed(current, {
                "audit_records": audit_count, "retained_snapshots": stored_count,
                "unknown_fixture_fault_records": pending_count,
                "audit_schema_fields": 6, "stored_parameters_or_credentials": False,
                "arbitrary_view_output_retained": False, "owned_cleanup_confirmed": True,
            })
            assert verify_explicit_pins(args, binary) == pins, "artifact/helper/source inputs changed during fixture"
            report["candidate_hashes_stable"] = True
            report["complete"] = True
            report["passed"] = len(report["checks"])
            save()
    except BaseException as error:
        detail = str(error)
        for private in private_values:
            detail = detail.replace(private, "[redacted-test-input]")
        report["failure"] = {
            "check": current, "type": type(error).__name__, "detail": detail[:2048],
            "location": [
                {"function": frame.tb_frame.f_code.co_name,
                 "file": pathlib.Path(frame.tb_frame.f_code.co_filename).name,
                 "line": frame.tb_lineno}
                for frame in traceback_frames(error.__traceback__)
            ],
        }
        save()
        print("FAIL", current, type(error).__name__, flush=True)
    finally:
        if controller is not None:
            controller.cleanup()
        report["logs"] = []
        for path in sorted(logdir.iterdir()):
            raw = path.read_bytes()
            sanitized = raw
            for private in private_values:
                sanitized = sanitized.replace(private.encode(), b"[redacted-test-input]")
            if path.suffix == ".log":
                sanitized = b"".join(
                    b"[redacted authentication/header line]\n"
                    if any(key in line.lower() for key in (
                        b"x-hepta-runtime-token", b"authorization:", b"cookie:",
                        b"set-cookie:", b"mcp-session-id", b'"headers"',
                    )) else line
                    for line in sanitized.splitlines(keepends=True)
                )
            path.write_bytes(sanitized)
            path.chmod(0o600)
            report["logs"].append({
                "name": path.name, "sha256": digest(path), "bytes": len(sanitized),
                "redacted": sanitized != raw,
            })
        report["owned_cleanup_confirmed"] = (
            controller is None or all(child.poll() is not None for child in controller.children)
        )
        save()
    if not report["complete"]:
        raise SystemExit(1)
    print("ALL_PASS", report["passed"], flush=True)


if __name__ == "__main__":
    main()

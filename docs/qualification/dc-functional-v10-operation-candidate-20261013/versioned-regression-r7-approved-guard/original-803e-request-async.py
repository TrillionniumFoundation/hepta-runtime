#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""V9 private native HTTP async fixture; no SSH, six-host, model or DC qualification.

Only generated loopback controllers, private configuration/state/credentials and
an exact fixed-health SSH argv emulator are used. The emulator never invokes SSH,
a shell, a caller command or another target. Its owned children observe their
original controller and harness parents and exit at a fixed deadline. Cleanup
never signals a PID read from metadata. A crash signals only our Popen controller.

Export mode checks immutable V8 definitions plus exactly two additions and writes
an unreviewed candidate contract. It does not run execution acceptance. Reviewed
execution requires a separately pinned --contract and explicit SHA256 values.
"""
import argparse
import base64
import concurrent.futures
import copy
import datetime
import hashlib
import json
import os
import pathlib
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy"))
# V10 copies verify all executable helper bytes before importing them.
_V10_ROOT = pathlib.Path(__file__).resolve().parents[1]
_V10_VERSION = _V10_ROOT / "tests/dc_functional_v10_version_pin.py"
if not _V10_VERSION.is_file() or _V10_VERSION.is_symlink() or hashlib.sha256(_V10_VERSION.read_bytes()).hexdigest() != "399bb9767e84e3d97de0abfd25e38fed31a006ddd9f2e0e1ff21f4c39fd413b0":
    raise ValueError("reviewed V10 version helper differs")
sys.path.insert(0, str(_V10_ROOT / "tests"))
from dc_functional_v10_version_pin import verify_import_pins as _v10_verify_import_pins
_v10_verify_import_pins(_V10_ROOT)

from mcp_tool_contract import ToolContract, make_contract

V8_SHA256 = "b64769210b9913fbdab28f7d0e95b7ef300d8710b3f1eeea74afcfac25b08318"
V8_CONTRACT = ROOT / "deploy/contracts/hepta-runtime-full-operator-v8.json"
PROTOCOL = "2026-07-28"
CLIENT_INFO = {"name": "hepta-v9-private-native-async-fixture", "version": "1"}
ID_META = "io.hepta.runtime/request-v8"
ACK_META = "io.hepta.runtime/retention-v8"
ALIAS = "v9-health-fixture"
OTHER_ALIAS = "v9-other-health-fixture"
TARGET = "v9-fixed-local-health-only"
HEALTH_COMMAND = "printf 'hepta-host-health-v1\\n'"
HEALTH_ARGV = [
    "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
    "-o", "StrictHostKeyChecking=yes", "-o", "ForwardAgent=no",
    "-o", "ClearAllForwardings=yes", "-o", "PermitLocalCommand=no",
    "-o", "RemoteCommand=none", "-o", "RequestTTY=no", "--",
    TARGET, HEALTH_COMMAND,
]
BINDING_KEYS = {
    "request_id", "owner", "tool_name", "accepted_unix_ms",
    "key_hash", "request_hash", "policy_binding",
}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest_bytes(data):
    return hashlib.sha256(data).hexdigest()


def digest(path):
    path = pathlib.Path(path)
    assert path.is_file() and not path.is_symlink()
    return digest_bytes(path.read_bytes())


def source_identity():
    paths = set(ROOT.glob("src/**/*.rs")) | set(ROOT.glob("src/**/*.py"))
    paths.update([ROOT / "Cargo.toml", ROOT / "Cargo.lock"])
    entries = {}
    for path in sorted(paths, key=lambda item: item.relative_to(ROOT).as_posix()):
        assert path.is_file() and not path.is_symlink(), "source requires ordinary non-symlink files"
        raw = path.read_bytes()
        entries[path.relative_to(ROOT).as_posix()] = {"bytes": len(raw), "sha256": digest_bytes(raw)}
    head = subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip()
    dirty = subprocess.check_output([
        "git", "-C", str(ROOT), "status", "--porcelain", "--untracked-files=all",
        "--", "src", "Cargo.toml", "Cargo.lock",
    ], text=True)
    return {
        "base_HEAD": head, "dirty_source": bool(dirty.strip()),
        "source_fingerprint_algorithm": "sha256(canonical sorted relative path -> byte-count and sha256 map)",
        "source_code_fingerprint": digest_bytes(canonical(entries)), "source_files": entries,
    }


def private_write(path, data, mode=0o600):
    path = pathlib.Path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as writer:
        writer.write(data.encode() if isinstance(data, str) else data)
        writer.flush()
        os.fsync(writer.fileno())
    path.chmod(mode)


def until(predicate, seconds=12):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.025)
    raise AssertionError("bounded private fixture observation deadline")


def result_text(raw):
    texts = [item["text"] for item in raw.get("content", []) if item.get("type") == "text"]
    assert len(texts) == 1
    return json.loads(texts[0])


def request_identity(raw):
    assert raw.get("resultType", "complete") == "complete"
    value = raw["_meta"][ID_META]
    assert set(value) == {"request_id", "automatic_retry", "delivery_proven"}
    assert re.fullmatch("[0-9a-f]{64}", value["request_id"])
    assert value["automatic_retry"] is False and value["delivery_proven"] is False
    return value["request_id"]


class Client:
    def __init__(self, url, token):
        self.url, self.token, self.session, self.serial = url, token, None, 0
        self.protocol = PROTOCOL
        value = self.rpc("initialize", {
            "protocolVersion": PROTOCOL, "capabilities": {}, "clientInfo": CLIENT_INFO,
        })
        self.protocol = value["protocolVersion"]
        assert self.protocol in {PROTOCOL, "2025-06-18", "2025-11-25"}
        self.rpc("notifications/initialized", {}, notify=True)

    def payload(self, method, params, notify=False):
        self.serial += 1
        params = copy.deepcopy(params)
        if not notify and method != "initialize" and self.protocol == PROTOCOL:
            meta = params.setdefault("_meta", {})
            meta.setdefault("io.modelcontextprotocol/protocolVersion", PROTOCOL)
            meta.setdefault("io.modelcontextprotocol/clientCapabilities", {})
            meta.setdefault("io.modelcontextprotocol/clientInfo", CLIENT_INFO)
        value = {"jsonrpc": "2.0", "method": method, "params": params}
        if not notify:
            value["id"] = self.serial
        return json.dumps(value).encode()

    def headers(self):
        headers = {
            "Content-Type": "application/json", "Accept": "application/json, text/event-stream",
            "X-Hepta-Runtime-Token": self.token, "MCP-Protocol-Version": self.protocol,
        }
        if self.session:
            headers["Mcp-Session-Id"] = self.session
        return headers

    def rpc(self, method, params, notify=False):
        body = self.payload(method, params, notify)
        serial = self.serial
        wire = urllib.request.Request(self.url, data=body, headers=self.headers())
        with urllib.request.urlopen(wire, timeout=25) as response:
            self.session = response.headers.get("Mcp-Session-Id", self.session)
            raw = response.read(2 * 1024 * 1024 + 1)
        assert len(raw) <= 2 * 1024 * 1024
        if notify:
            return None
        text = raw.decode()
        events = [json.loads(line[5:].strip()) for line in text.splitlines()
                  if line.startswith("data:") and line[5:].strip()]
        reply = events[-1] if events else json.loads(text)
        assert reply.get("id") == serial
        if "error" in reply:
            raise RuntimeError(reply["error"])
        return reply["result"]

    def raw_call(self, name, arguments, meta=None):
        value = {"name": name, "arguments": arguments}
        if meta is not None:
            value["_meta"] = meta
        raw = self.rpc("tools/call", value)
        if name in {"request_start", "request_cancel", "request_status", "request_result"}:
            assert len(json.dumps(raw, ensure_ascii=False, separators=(",", ":")).encode()) <= 65536
        return raw

    def call(self, name, arguments):
        raw = self.raw_call(name, arguments)
        assert raw.get("isError") is not True, "native fixture request unexpectedly refused"
        return result_text(raw)


def denied(client, tool, params, meta=None):
    try:
        raw = client.raw_call(tool, params, meta)
    except RuntimeError as error:
        assert isinstance(error.args[0], dict) and "code" in error.args[0]
        return "jsonrpc_error"
    assert raw.get("isError") is True, "refusal unexpectedly dispatched or succeeded"
    return "tool_error"


def wrong_token_status(client, token):
    wire = urllib.request.Request(client.url, data=b"{}", headers={
        **client.headers(), "X-Hepta-Runtime-Token": token,
    })
    try:
        with urllib.request.urlopen(wire, timeout=5) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code


def proc_identity(pid):
    try:
        path = pathlib.Path("/proc") / str(pid)
        text = (path / "stat").read_text()
        tail = text[text.rfind(")") + 2:].split()
        return {"pid": pid, "uid": path.stat().st_uid, "start": tail[19], "state": tail[0]}
    except (FileNotFoundError, ProcessLookupError):
        return None


def original_alive(event):
    identity = proc_identity(event["pid"])
    return bool(identity and identity["uid"] == event["uid"]
                and identity["start"] == event["start"] and identity["state"] != "Z")


def install_wrapper(root):
    """Own helper accepts ONLY the fixed source-generated health argv."""
    bindir = root / "bin"
    bindir.mkdir(mode=0o700)
    wrapper = bindir / "ssh"
    harness = proc_identity(os.getpid())
    assert harness is not None
    code = (
        "#!/usr/bin/python3\n"
        "import fcntl,json,os,pathlib,sys,time\n"
        f"root=pathlib.Path({str(root)!r})\n"
        f"expected={HEALTH_ARGV!r}\n"
        f"harness={harness!r}\n"
        "def identity(pid):\n"
        " try:\n"
        "  p=pathlib.Path('/proc')/str(pid);s=(p/'stat').read_text();v=s[s.rfind(')')+2:].split()\n"
        "  return {'pid':pid,'uid':p.stat().st_uid,'start':v[19],'state':v[0]}\n"
        " except (FileNotFoundError,ProcessLookupError):return None\n"
        "def same(a,b):return bool(a and b and a['pid']==b['pid'] and a['uid']==b['uid'] and a['start']==b['start'] and b['state']!='Z')\n"
        "def event(value):\n"
        " fd=os.open(root/'events.jsonl',os.O_WRONLY|os.O_CREAT|os.O_APPEND|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)\n"
        " try:\n"
        "  fcntl.flock(fd,fcntl.LOCK_EX);os.write(fd,(json.dumps(value,sort_keys=True)+'\\n').encode());os.fsync(fd)\n"
        " finally:os.close(fd)\n"
        "if sys.argv[1:]!=expected:\n"
        " event({'event':'refused_nonfixed_argv'});raise SystemExit(85)\n"
        "parent=identity(os.getppid());mine=identity(os.getpid())\n"
        "if parent is None or mine is None:raise SystemExit(86)\n"
        "event({'event':'spawned',**mine,'parent_pid':parent['pid'],'parent_start':parent['start']})\n"
        "deadline=time.monotonic()+12\n"
        "while (root/'gate').exists():\n"
        " if time.monotonic()>=deadline or os.getppid()!=parent['pid'] or not same(parent,identity(parent['pid'])) or not same(harness,identity(harness['pid'])):\n"
        "  event({'event':'self_exit',**mine});raise SystemExit(86)\n"
        " time.sleep(.015)\n"
        "if not same(parent,identity(parent['pid'])) or not same(harness,identity(harness['pid'])):raise SystemExit(86)\n"
        "event({'event':'fixed_response',**mine})\n"
        "sys.stdout.write('hepta-host-health-v1\\n');sys.stdout.flush()\n"
    )
    private_write(wrapper, code, 0o700)
    env = {"PATH": str(bindir) + ":/usr/bin:/bin", "HOME": str(root),
           "LANG": "C.UTF-8", "RUST_LOG": "warn"}
    return wrapper, env


def events(root):
    path = root / "events.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def spawned(root):
    return [event for event in events(root) if event.get("event") == "spawned"]


def health_count(root):
    return len(spawned(root))


def set_gate(root):
    path = root / "gate"
    assert not path.exists()
    private_write(path, "fixed-health-gate\n")


def release_gate(root):
    (root / "gate").unlink(missing_ok=True)


class Controller:
    def __init__(self, binary, workspace, config, tokenfile, env, logdir):
        self.binary, self.workspace, self.config = binary, workspace, config
        self.tokenfile, self.env, self.logdir = tokenfile, env, logdir
        self.child, self.children, self.url = None, [], None

    def start(self):
        assert self.child is None or self.child.poll() is not None
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        self.url = f"http://127.0.0.1:{port}/mcp"
        logfile = self.logdir / f"controller-{len(self.children):02d}.log"
        private_write(logfile, b"")
        with logfile.open("ab") as writer:
            self.child = subprocess.Popen([
                str(self.binary), "mcp", "--path", str(self.workspace),
                "--bind", f"127.0.0.1:{port}", "--runtime-config", str(self.config),
                "--auth-token-file", str(self.tokenfile),
            ], env=self.env, stdin=subprocess.DEVNULL, stdout=writer, stderr=writer)
        self.children.append(self.child)
        def ready():
            assert self.child.poll() is None, "owned controller exited before readiness"
            try:
                return Client(self.url, self.tokenfile.read_text().strip())
            except (OSError, RuntimeError):
                return None
        return until(ready)

    def stop(self, crash=False):
        if self.child is not None and self.child.poll() is None:
            # Popen owns this exact unreaped child. Never use metadata PIDs or killpg.
            self.child.kill() if crash else self.child.terminate()
            try:
                self.child.wait(timeout=6)
            except subprocess.TimeoutExpired:
                self.child.kill()
                self.child.wait(timeout=5)
        assert self.child is None or self.child.poll() is not None

    def cleanup(self):
        self.stop()
        assert all(child.poll() is not None for child in self.children)


def start_request(client, operation, key):
    raw = client.raw_call("request_start", {"operation": operation, "idempotency_key": key})
    assert raw.get("isError") is not True
    value = result_text(raw)
    outer = request_identity(raw)
    inner = value["request_id"]
    assert re.fullmatch("[0-9a-f]{64}", inner)
    assert inner != outer, "outer observation and inner dispatch identities must be distinct"
    assert value["idempotency_binding_retained"] is True
    assert value["automatic_retry"] is False and value["delivery_proven"] is False
    assert value["execution_resume_after_restart"] is False
    assert value["admission_is_not_dispatch_completion"] is True
    assert value["ownership_scope"] == "authenticated_private_operator_credential"
    assert value["authenticated_chatgpt_caller_isolation"] is False
    return value


def local_outcome(state, request_id):
    path = state / "request-async-v9/.outcomes" / (request_id + ".json")
    return json.loads(path.read_bytes()) if path.exists() else None


def settled(client, state, request_id, expected="completed"):
    # Observe the owned atomic outcome file rather than consume audit capacity by
    # polling hundreds of native reads. Then verify the native public observation.
    until(lambda: local_outcome(state, request_id))
    def public_terminal():
        value = client.call("request_status", {"request_id": request_id})
        return value if not value["owned_future_active"] else None
    value = until(public_terminal, seconds=5)
    assert value["early_return_async_start_supported"] is True
    assert value["automatic_retry"] is False
    assert value["execution_resume_after_restart"] is False
    assert value["remote_termination_confirmed"] is False
    assert value["async_state"] == expected
    if expected == "completed":
        assert value["dispatch_state"] == "completed" and value["result_state"] == "stored"
    return value


def reconstruct(client, state, request_id):
    assembled = bytearray()
    offset, sha, total, pages = 0, None, None, 0
    for _ in range(160):
        page = client.call("request_result", {"request_id": request_id, "offset": offset, "limit": 509})
        assert page["request_id"] == request_id and page["offset"] == offset
        assert page["immutable_snapshot"] is True and page["automatic_retry"] is False
        assert page["delivery_proven"] is False
        assert page["total_bytes"] <= 65536
        if sha is None:
            sha, total = page["result_sha256"], page["total_bytes"]
        assert page["result_sha256"] == sha and page["total_bytes"] == total
        chunk = base64.b64decode(page["data_base64"], validate=True)
        assert len(chunk) <= 509 and page["next_offset"] == offset + len(chunk)
        assembled.extend(chunk)
        offset = page["next_offset"]
        pages += 1
        if page["eof"]:
            assert offset == total
            break
        assert chunk
    else:
        raise AssertionError("bounded native immutable paging did not finish")
    raw = bytes(assembled)
    assert len(raw) == total and digest_bytes(raw) == sha
    private_record = json.loads((state / "request-results" / (request_id + ".json")).read_bytes())
    assert private_record["state"] == "stored"
    assert raw == base64.b64decode(private_record["payload_base64"], validate=True)
    assert private_record["payload_sha256"] == sha
    native = json.loads(raw)
    assert native["resultType"] == "complete" and native.get("isError") is not True
    assert native["_meta"][ID_META]["request_id"] == request_id
    assert ACK_META not in native["_meta"]
    replay = client.call("request_result", {"request_id": request_id, "offset": 0, "limit": 17})
    assert base64.b64decode(replay["data_base64"], validate=True) == raw[:17]
    assert replay["result_sha256"] == sha
    return raw, result_text(native), {"sha256": sha, "bytes": total, "pages": pages}


def discard_ack_without_reading(client, operation, key, admitted):
    body = client.payload("tools/call", {"name": "request_start", "arguments": {
        "operation": operation, "idempotency_key": key,
    }})
    parsed = urllib.parse.urlsplit(client.url)
    headers = {
        **client.headers(), "Host": f"{parsed.hostname}:{parsed.port}",
        "Content-Length": str(len(body)), "Connection": "close",
    }
    wire = (f"POST {parsed.path} HTTP/1.1\r\n" +
            "".join(f"{name}: {value}\r\n" for name, value in headers.items()) + "\r\n").encode() + body
    with socket.create_connection((parsed.hostname, parsed.port), timeout=5) as sock:
        sock.sendall(wire)
        # Never recv/read the response or its generated ID. Admission is proven by
        # the fixed helper spawn only. Delivery beyond the caller remains unproven.
        admitted()
    return {"response_read": False, "client_received_request_id": False}


def verify_catalog(tools, args, contract_path):
    v8 = ToolContract.load(V8_CONTRACT, V8_SHA256)
    actual = {tool["name"]: tool for tool in tools}
    assert len(actual) == len(tools), "duplicate native names"
    assert set(actual) - set(v8.by_name) == {"request_start", "request_cancel"} | {"operation_start", "operation_status", "operation_result", "operation_cancel"}
    assert set(v8.by_name) <= set(actual)
    assert all(actual[name] == definition for name, definition in v8.by_name.items())
    v9 = ToolContract.load(ROOT / "deploy/contracts/hepta-runtime-full-operator-v9.json", "3eb628812d0c70b9af8393ecf9d0ce47f69b1438a134148f75ae2dd3132e6761")
    assert all(actual[name] == definition for name, definition in v9.by_name.items())
    assert set(actual) - set(v9.by_name) == {"operation_start", "operation_status", "operation_result", "operation_cancel"}
    for name in ["request_start", "request_cancel"]:
        schema = actual[name]["inputSchema"]
        assert schema["additionalProperties"] is False
        assert "owner" not in schema.get("properties", {})
        assert actual[name]["annotations"]["readOnlyHint"] is False
    assert actual["request_cancel"]["annotations"]["idempotentHint"] is True
    if args.export_contract:
        private_write(contract_path, json.dumps(make_contract(tools), indent=2, ensure_ascii=False) + "\n")
        reviewed = ToolContract.load(contract_path, digest(contract_path))
    else:
        reviewed = ToolContract.load(contract_path, args.expected_contract_sha256)
    reviewed.verify(tools)
    # A drifted, internally plausible definition must fail the pinned comparison.
    changed = copy.deepcopy(tools)
    next(tool for tool in changed if tool["name"] == "request_start")["description"] += " unreviewed drift"
    try:
        reviewed.verify(changed)
    except (ValueError, AssertionError):
        pass
    else:
        raise AssertionError("pinned native catalog drift was accepted")
    return reviewed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--output", "--out", dest="output", required=True)
    parser.add_argument("--expected-binary-sha256", required=True)
    parser.add_argument("--expected-source-fingerprint", required=True)
    parser.add_argument("--expected-contract-sha256")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--contract")
    group.add_argument("--export-contract")
    args = parser.parse_args()
    if args.contract and not args.expected_contract_sha256:
        parser.error("--contract requires separately reviewed --expected-contract-sha256")
    for pin in [args.expected_binary_sha256, args.expected_source_fingerprint] + (
        [args.expected_contract_sha256] if args.contract else []
    ):
        if re.fullmatch("[0-9a-f]{64}", pin) is None:
            parser.error("explicit lowercase SHA256 pins required")
    assert sys.platform.startswith("linux"), "owned helper identity fixture requires Linux /proc"
    binary = pathlib.Path(args.binary).resolve(strict=True)
    output = pathlib.Path(args.output).resolve()
    contract_path = pathlib.Path(args.contract or args.export_contract).resolve()
    assert not output.exists(), "never overwrite earlier acceptance evidence"
    if args.export_contract:
        assert not contract_path.exists(), "never overwrite earlier contract evidence"
        contract_path.parent.mkdir(parents=True, exist_ok=True)
    else:
        contract_path = contract_path.resolve(strict=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    logdir = output.parent / (output.stem + "-logs")
    logdir.mkdir(mode=0o700, exist_ok=False)
    before_source = source_identity()
    before_binary = digest(binary)
    before_harness = digest(__file__)
    helper_before = {"deploy/mcp_tool_contract.py": digest(ROOT / "deploy/mcp_tool_contract.py")}
    assert before_binary == args.expected_binary_sha256
    assert before_source["source_code_fingerprint"] == args.expected_source_fingerprint
    assert digest(V8_CONTRACT) == V8_SHA256
    before_contract = digest(contract_path) if args.contract else None
    report = {
        "schema": "hepta-dc-v9-request-async-native-private-fixture-v1",
        "recorded_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "origin": "native_http_private_fixed_health_fixture",
        "qualification_scope": "native_protocol_private_fixture_only",
        "source_before": before_source, "binary_sha256": before_binary,
        "harness_sha256": before_harness, "helper_sha256_before": helper_before.copy(),
        "contract_sha256": before_contract, "v8_contract_sha256": V8_SHA256,
        "catalog_mode": "unreviewed_export_candidate" if args.export_contract else "reviewed_explicit_pin",
        "exact_reviewed_contract_qualified": False, "catalog_export_complete": False,
        "checks": [], "complete": False, "owned_cleanup_confirmed": False,
        "installed_runtime_changed": False, "desktop_commander_changed": False,
        "real_ssh_qualified": False, "six_machine_qualified": False, "model_origin_qualified": False,
        "authenticated_chatgpt_caller_isolation": False, "full_dc_replacement_qualified": False,
        "production_recovery_rollback_qualified": False,
        "owner4_native_qualified": False, "global8_native_qualified": False,
        "global_limit_evidence": "separate actual Rust registry Slot unit tests; one HTTP credential cannot fill multiple owners",
        "limits": [
            "The fixed local wrapper proves native typed dispatch, not SSH authentication or real target health.",
            "All users of one verified operator credential share ownership; no ChatGPT caller isolation is proved.",
            "Cancellation controls an owned future; remote termination and business completion remain unproven.",
            "A single native HTTP credential permits owner4 evidence only; global8 needs separate registry unit evidence.",
            "Controller crash affects only our Popen child; helpers self-exit and no metadata PID is signalled.",
            "Redundant custody detects controlled primary deletion; arbitrary reset or deletion of all private history is not qualified.",
        ],
    }
    private_values = []
    controller, root, wrapper = None, None, None
    accepted = False
    current = "prepare private fixture"

    def sanitize(text):
        for value in private_values:
            text = text.replace(value, "[redacted-private-fixture-input]")
        return text

    def save():
        data = sanitize(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        output.write_text(data)
        output.chmod(0o600)

    def passed(name, detail=None):
        report["checks"].append({"check": name, "result": "passed", "detail": detail})
        save()
        print("PASS", name, flush=True)

    def key():
        value = secrets.token_hex(32)
        private_values.append(value)
        return value

    save()
    try:
        root = pathlib.Path(tempfile.mkdtemp(prefix="hepta-v9-async-native-private-")).resolve()
        root.chmod(0o700)
        workspace, alternate, state = (root / name for name in ["workspace", "alternate", "state"])
        for path in [workspace, alternate, state]:
            path.mkdir(mode=0o700)
        token_a, token_b = secrets.token_hex(32), secrets.token_hex(32)
        private_values.extend([token_a, token_b])
        tokenfile, config = root / "token", root / "runtime.json"
        private_write(tokenfile, token_a)
        host = {
            "ssh_target": TARGET, "platform": "linux", "remote_state_dir": str(root / "unused-remote"),
            "execution_mode": "isolated", "allow_execute": False, "allow_pty": False,
            "allow_write": False, "allow_job_network": False, "allow_detached_fallback": False,
            "allowed_read_path_prefixes": [str(workspace)], "allowed_write_path_prefixes": [],
        }
        cfg = {"state_dir": str(state), "controller_workspace_roots": [str(workspace)],
               "hosts": {ALIAS: host, OTHER_ALIAS: copy.deepcopy(host)}}
        private_write(config, json.dumps(cfg))
        wrapper, env = install_wrapper(root)
        helper_before["generated_fixed_health_wrapper"] = digest(wrapper)
        report["helper_sha256_before"] = helper_before.copy()
        controller = Controller(binary, workspace, config, tokenfile, env, logdir)
        client = controller.start()
        report["requested_protocol_version"] = PROTOCOL
        report["negotiated_protocol_version"] = client.protocol

        current = "V10 exact catalog preserves V8 and V9 predecessors plus four operation definitions"
        reviewed = verify_catalog(client.rpc("tools/list", {})["tools"], args, contract_path)
        report["contract_sha256"] = digest(contract_path)
        if args.export_contract:
            before_contract = report["contract_sha256"]
        report["catalog_sha256"] = reviewed.catalog_sha256
        report["exact_reviewed_contract_qualified"] = bool(args.contract)
        passed(current, {"all_v8_definitions_exact": True, "v8_added_names_in_v10": ["request_start", "request_cancel", "operation_start", "operation_status", "operation_result", "operation_cancel"],
                         "catalog_drift_refused": True, "hardcoded_total_count_used": False})
        if args.export_contract:
            report["catalog_export_complete"] = True
            report["execution_checks_skipped"] = True
        else:
            operation = {"tool": "host_health", "arguments": {"host": ALIAS}}
            expected_health_dispatches = 0
            current = "three typed async arms retain original DTO bytes with immutable pagination and SHA"
            details = {}
            for name, arguments in [("host_list", {}), ("effective_config", {}), ("host_health", {"host": ALIAS})]:
                admitted = start_request(client, {"tool": name, "arguments": arguments}, key())
                assert admitted["reused"] is False
                settled(client, state, admitted["request_id"])
                raw, dto, info = reconstruct(client, state, admitted["request_id"])
                if name == "host_health":
                    expected_health_dispatches += 1
                    assert dto["schema"] == "hepta-host-health-v1" and dto["status"] == "healthy"
                    assert dto["host"] == ALIAS and dto["authenticated"] is True
                else:
                    assert dto == client.call(name, {})
                details[name] = info
                assert raw and info["pages"] >= 1
            passed(current, details)

            current = "normal early reply leaves independent owned future running"
            expected_health_dispatches += 1
            count = health_count(root)
            set_gate(root)
            started = time.monotonic()
            admission = start_request(client, operation, key())
            elapsed = (time.monotonic() - started) * 1000
            inner = admission["request_id"]
            until(lambda: health_count(root) == count + 1)
            live = client.call("request_status", {"request_id": inner})
            assert live["async_state"] == "running" and live["owned_future_active"] is True
            assert live["dispatch_state"] == "accepted" and live["result_state"] == "unknown"
            assert (root / "gate").exists() and original_alive(spawned(root)[-1])
            release_gate(root)
            settled(client, state, inner)
            reconstruct(client, state, inner)
            passed(current, {"receipt_ms": elapsed, "reply_before_fixed_health_completion": True,
                             "outer_normal_reply_did_not_cancel_inner": True})

            current = "concurrent same-key retry returns one inner identity and one real dispatch"
            expected_health_dispatches += 1
            count = health_count(root)
            shared_key = key()
            set_gate(root)
            def retry_once(_):
                return start_request(Client(client.url, token_a), operation, shared_key)
            with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
                replies = list(pool.map(retry_once, range(6)))
            ids = {reply["request_id"] for reply in replies}
            assert len(ids) == 1 and sum(not reply["reused"] for reply in replies) == 1
            shared_id = next(iter(ids))
            until(lambda: health_count(root) == count + 1)
            assert health_count(root) == count + 1
            denied(client, "request_start", {"operation": {"tool":"host_health","arguments":{"host":OTHER_ALIAS}},
                                            "idempotency_key": shared_key})
            assert health_count(root) == count + 1
            release_gate(root)
            settled(client, state, shared_id)
            before, _, info = reconstruct(client, state, shared_id)
            late = client.call("request_cancel", {"request_id": shared_id})
            assert late["cancel_requested"] is False and late["remote_termination_confirmed"] is False
            after, _, later_info = reconstruct(client, state, shared_id)
            assert after == before and later_info["sha256"] == info["sha256"]
            assert health_count(root) == count + 1
            passed(current, {"same_key_callers": 6, "unique_inner_ids": 1, "typed_dispatches": 1,
                             "changed_arguments_refused": True, "late_cancel_snapshot_unchanged": True})

            current = "owner4 capacity preserves same-key lookup status and reconnect cancellation"
            expected_health_dispatches += 4
            count = health_count(root)
            set_gate(root)
            pending = [(key(), None) for _ in range(4)]
            pending = [(value, start_request(client, operation, value)["request_id"]) for value, _ in pending]
            until(lambda: health_count(root) == count + 4)
            journal_count = len(list((state / "request-async-v9").glob("*.json")))
            denied(client, "request_start", {"operation": operation, "idempotency_key": key()})
            assert len(list((state / "request-async-v9").glob("*.json"))) == journal_count
            duplicate = start_request(client, operation, pending[0][0])
            assert duplicate["reused"] is True and duplicate["request_id"] == pending[0][1]
            live = client.call("request_status", {"request_id": pending[0][1]})
            assert live["owned_future_active"] is True and health_count(root) == count + 4
            assert wrong_token_status(client, token_b) == 401
            reconnect = Client(client.url, token_a)
            cancelled = reconnect.call("request_cancel", {"request_id": pending[0][1]})
            assert cancelled["cancel_requested"] is True
            assert cancelled["cancellation_scope"] == "this_controller_owned_rust_future_only"
            assert cancelled["remote_termination_confirmed"] is False
            cancelled_status = settled(reconnect, state, pending[0][1], "cancelled_future")
            assert cancelled_status["dispatch_state"] == "unknown"
            assert cancelled_status["result_state"] == "not_completed"
            denied(reconnect, "request_result", {"request_id": pending[0][1]})
            repeated = start_request(reconnect, operation, pending[0][0])
            assert repeated["reused"] is True and repeated["request_id"] == pending[0][1]
            assert health_count(root) == count + 4
            release_gate(root)
            for _, request_id in pending[1:]:
                settled(client, state, request_id)
            report["owner4_native_qualified"] = True
            passed(current, {"active_fixed_challenges": 4, "fifth_new_key_refused_before_reservation": True,
                             "same_key_status_cancel_available_at_full_capacity": True,
                             "same_credential_new_session_cancel": True, "different_bearer_http_status": 401,
                             "global8_native_qualified": False})

            current = "lost ACK before caller reads ID reconciles same key without redispatch"
            expected_health_dispatches += 1
            count = health_count(root)
            lost_key = key()
            set_gate(root)
            lost = discard_ack_without_reading(client, operation, lost_key,
                                              lambda: until(lambda: health_count(root) == count + 1))
            recovered = start_request(Client(client.url, token_a), operation, lost_key)
            assert recovered["reused"] is True and health_count(root) == count + 1
            recovered_id = recovered["request_id"]
            live = client.call("request_status", {"request_id": recovered_id})
            assert live["owned_future_active"] is True
            release_gate(root)
            settled(client, state, recovered_id)
            reconstruct(client, state, recovered_id)
            assert health_count(root) == count + 1
            passed(current, {**lost, "same_key_recovered_original_id": True, "typed_dispatch_count": 1})

            current = "failed inner result admission freezes key and never replenishes a dispatch ID"
            count = health_count(root)
            failed_key = key()
            resultdir = state / "request-results"
            resultdir.chmod(0o750)
            try:
                failed = start_request(client, operation, failed_key)
            finally:
                resultdir.chmod(0o700)
            assert failed["async_state"] == "unknown"
            retry = start_request(client, operation, failed_key)
            assert retry["reused"] is True and retry["request_id"] == failed["request_id"]
            denied(client, "request_result", {"request_id": failed["request_id"]})
            assert health_count(root) == count
            passed(current, {"fixed_identity_after_admission_failure": True, "typed_dispatch_count": 0})

            current = "controller crash makes pending work unknown with no restart replay"
            expected_health_dispatches += 1
            count = health_count(root)
            crash_key = key()
            set_gate(root)
            crash = start_request(client, operation, crash_key)
            until(lambda: health_count(root) == count + 1)
            crash_id = crash["request_id"]
            controller.stop(crash=True)
            until(lambda: all(not original_alive(event) for event in spawned(root)), seconds=16)
            client = controller.start()
            status = client.call("request_status", {"request_id": crash_id})
            assert status["dispatch_state"] == "unknown" and status["result_state"] == "unknown"
            assert status["async_state"] == "unknown" and status["owned_future_active"] is False
            restored = start_request(client, operation, crash_key)
            assert restored["reused"] is True and restored["request_id"] == crash_id
            absent = client.call("request_cancel", {"request_id": crash_id})
            assert absent["cancel_requested"] is False
            assert absent["observation"] == "no_owned_future_present_no_replay"
            denied(client, "request_result", {"request_id": crash_id})
            assert health_count(root) == count + 1
            release_gate(root)
            passed(current, {"pending_dispatches_before_crash": 1, "restart_dispatches": 0,
                             "same_generated_id_reconciled": True, "unfinished_program_resumed": False,
                             "owned_helpers_self_exit_after_original_parent_exit": True})

            current = "current policy revocation rejects old async key and retained DTO"
            policy_key = key()
            policy_operation = {"tool": "host_list", "arguments": {}}
            policy_id = start_request(client, policy_operation, policy_key)["request_id"]
            settled(client, state, policy_id)
            original, _, _ = reconstruct(client, state, policy_id)
            controller.stop()
            changed = copy.deepcopy(cfg)
            changed["controller_workspace_roots"] = [str(alternate)]
            for entry in changed["hosts"].values():
                entry["allowed_read_path_prefixes"] = [str(alternate)]
            config.write_text(json.dumps(changed))
            client = controller.start()
            count = health_count(root)
            for name in ["request_status", "request_result", "request_cancel"]:
                denied(client, name, {"request_id": policy_id})
            denied(client, "request_start", {"operation": policy_operation, "idempotency_key": policy_key})
            assert health_count(root) == count
            controller.stop()
            config.write_text(json.dumps(cfg))
            client = controller.start()
            restored = start_request(client, policy_operation, policy_key)
            assert restored["reused"] is True and restored["request_id"] == policy_id
            exact, _, _ = reconstruct(client, state, policy_id)
            assert exact == original
            passed(current, {"changed_policy_old_key_and_receipts_refused": True,
                             "restored_policy_same_id_and_original_snapshot": True})

            current = "credential rotation cannot lookup cancel or spoof the old owner"
            assert wrong_token_status(client, token_b) == 401
            controller.stop()
            tokenfile.write_text(token_b)
            tokenfile.chmod(0o600)
            client_b = controller.start()
            assert wrong_token_status(client_b, token_a) == 401
            old_owner = next(
                json.loads(path.read_bytes())["owner"]
                for path in (state / "request-async-v9").glob("*.json")
                if json.loads(path.read_bytes())["request_id"] == policy_id
            )
            assert re.fullmatch("[0-9a-f]{64}", old_owner)
            for name in ["request_status", "request_result", "request_cancel"]:
                denied(client_b, name, {"request_id": policy_id})
                denied(client_b, name, {"request_id": policy_id}, {"owner": old_owner})
            owned_b = start_request(client_b, policy_operation, policy_key)
            assert owned_b["request_id"] != policy_id and owned_b["reused"] is False
            settled(client_b, state, owned_b["request_id"])
            controller.stop()
            tokenfile.write_text(token_a)
            tokenfile.chmod(0o600)
            client = controller.start()
            owned_a = start_request(client, policy_operation, policy_key)
            assert owned_a["request_id"] == policy_id and owned_a["reused"] is True
            passed(current, {"rotated_credential_old_ids_refused": True, "old_bearer_http_status": 401,
                             "same_literal_key_separate_credential_scope": True,
                             "caller_metadata_not_authority": True})

            current = "typed whitelist and cancel parser reject execution and authority inputs"
            count = health_count(root)
            for refused_operation in [
                {"tool":"shell_start","arguments":{"host":ALIAS,"command":"true"}},
                {"tool":"request_start","arguments":{}},
                {"tool":"host_health","arguments":{"host":ALIAS,"command":"true"}},
                {"tool":"host_health","arguments":{"host":ALIAS,"owner":"spoof"}},
                {"tool":"host_list","arguments":{"host":ALIAS}},
            ]:
                denied(client, "request_start", {"operation":refused_operation,"idempotency_key":key()})
            for field, value in [("pid",1234),("host",ALIAS),("signal","KILL"),("command","true"),("owner","spoof")]:
                denied(client, "request_cancel", {"request_id":policy_id,field:value})
            assert health_count(root) == count
            passed(current, {"non_whitelist_operations_and_unknown_fields_refused": True,
                             "arbitrary_pid_signal_host_command_owner_inputs_refused": True})

            current = "used key custody and audit faults refuse admission and receipt lookup without redispatch"
            expected_health_dispatches += 1
            count = health_count(root)
            deleted_key = key()
            original_admission = start_request(client, operation, deleted_key)
            deleted_id = original_admission["request_id"]
            settled(client, state, deleted_id)
            original_snapshot, _, original_snapshot_info = reconstruct(client, state, deleted_id)
            assert health_count(root) == count + 1
            journal = state / "request-async-v9"
            original_ids = {json.loads(path.read_bytes())["request_id"] for path in journal.glob("*.json")}
            primary = next(
                path for path in journal.glob("*.json")
                if json.loads(path.read_bytes())["request_id"] == deleted_id
            )
            occupancy = journal / ".occupied" / primary.name
            original_primary = primary.read_bytes()
            original_occupancy = occupancy.read_bytes()
            intent = journal / ".intents" / (deleted_id + ".json")
            original_intent = intent.read_bytes()
            assert json.loads(original_primary) == json.loads(original_occupancy) == json.loads(original_intent)
            # This is the established V8 native audit store, derived from this
            # fixture's explicit state config and original completed receipt.
            audit_path = state / "request-audit" / (deleted_id + ".json")
            custody_metadata = [
                state / ".request-async-v9-anchor.json", primary, occupancy, intent, audit_path,
                state / "request-results" / (deleted_id + ".json"),
                journal / ".outcomes" / (deleted_id + ".json"),
            ]
            custody_before = {str(path): path.read_bytes() for path in custody_metadata}
            fault_details = []

            def directory_ids(directory):
                return {json.loads(path.read_bytes())["request_id"] for path in directory.glob("*.json")}

            def refuse_used_key_and_receipts():
                denied(client, "request_start", {"operation": operation, "idempotency_key": deleted_key})
                for name in ["request_status", "request_result", "request_cancel"]:
                    denied(client, name, {"request_id": deleted_id})
                assert health_count(root) == count + 1

            def exact_owned_restore(path, original, label):
                observed = path.read_bytes() if path.exists() else None
                if observed is not None and observed != original:
                    private_write(logdir / (label + "-observed-owned-fault.bin"), observed)
                path.unlink(missing_ok=True)
                private_write(path, original)

            def prove_lookup_only_after_exact_restore():
                restored = start_request(client, operation, deleted_key)
                assert restored["reused"] is True and restored["request_id"] == deleted_id
                status = client.call("request_status", {"request_id": deleted_id})
                assert status["owned_future_active"] is False and status["async_state"] == "completed"
                assert status["dispatch_state"] == "completed" and status["result_state"] == "stored"
                restored_snapshot, _, restored_info = reconstruct(client, state, deleted_id)
                assert restored_snapshot == original_snapshot
                assert restored_info["sha256"] == original_snapshot_info["sha256"]
                assert directory_ids(journal) == original_ids
                assert directory_ids(journal / ".occupied") == original_ids
                assert directory_ids(journal / ".intents") == original_ids
                assert all(path.read_bytes() == custody_before[str(path)] for path in custody_metadata)
                assert health_count(root) == count + 1

            for damaged_side, damaged_path, original in [
                ("missing-primary", primary, original_primary),
                ("missing-occupancy", occupancy, original_occupancy),
            ]:
                report["active_controlled_custody_fault"] = {
                    "kind": damaged_side, "inner_request_id": deleted_id,
                    "original_sha256": digest_bytes(original), "scope": "exact_owned_fixture_record_only",
                }
                save()
                damaged_path.unlink()
                try:
                    for epoch in ["same-controller", "restarted-same-credential-controller"]:
                        if epoch.startswith("restarted"):
                            controller.stop()
                            client = controller.start()
                        refuse_used_key_and_receipts()
                        assert not damaged_path.exists()
                        assert directory_ids(journal) == original_ids - ({deleted_id} if damaged_path == primary else set())
                        assert directory_ids(journal / ".occupied") == original_ids - ({deleted_id} if damaged_path == occupancy else set())
                        assert directory_ids(journal / ".intents") == original_ids
                        assert all(path.read_bytes() == custody_before[str(path)]
                                   for path in custody_metadata if path != damaged_path)
                finally:
                    exact_owned_restore(damaged_path, original, damaged_side)
                prove_lookup_only_after_exact_restore()
                fault_details.append({"kind": damaged_side, "before_and_after_restart_refused": True,
                                      "exact_fixture_restore_lookup_only": True})

            report["active_controlled_custody_fault"] = {
                "kind": "both-key-markers-missing", "inner_request_id": deleted_id,
                "primary_original_sha256": digest_bytes(original_primary),
                "occupancy_original_sha256": digest_bytes(original_occupancy),
                "retained_intent_sha256": digest_bytes(original_intent),
                "scope": "exact_owned_fixture_primary_and_occupancy_only",
            }
            save()
            primary.unlink()
            occupancy.unlink()
            try:
                for epoch in ["same-controller", "restarted-same-credential-controller"]:
                    if epoch.startswith("restarted"):
                        controller.stop()
                        client = controller.start()
                    refuse_used_key_and_receipts()
                    assert not primary.exists() and not occupancy.exists()
                    assert directory_ids(journal) == original_ids - {deleted_id}
                    assert directory_ids(journal / ".occupied") == original_ids - {deleted_id}
                    assert directory_ids(journal / ".intents") == original_ids
                    assert all(path.read_bytes() == custody_before[str(path)]
                               for path in custody_metadata if path not in {primary, occupancy})
            finally:
                exact_owned_restore(primary, original_primary, "both-key-markers-missing-primary")
                exact_owned_restore(occupancy, original_occupancy, "both-key-markers-missing-occupancy")
            prove_lookup_only_after_exact_restore()
            fault_details.append({"kind": "both-key-markers-missing",
                                  "before_and_after_restart_refused": True,
                                  "independent_intent_and_completion_metadata_preserved": True,
                                  "exact_fixture_restore_lookup_only": True})

            original_audit = custody_before[str(audit_path)]
            mismatched_audit = json.loads(original_audit)
            # A valid filename/owner/tool/state with only a changed acceptance
            # timestamp exercises the full audit-identity gate rather than
            # relying on an invalid JSON or filename parser rejection.
            mismatched_audit["accepted_unix_ms"] += 1
            for label, damaged in [
                ("corrupt-owned-audit", b"{invalid-owned-audit-fixture"),
                ("mismatched-owned-audit-identity", json.dumps(mismatched_audit).encode()),
            ]:
                report["active_controlled_custody_fault"] = {
                    "kind": label, "inner_request_id": deleted_id,
                    "original_sha256": digest_bytes(original_audit),
                    "damaged_sha256": digest_bytes(damaged), "scope": "exact_owned_fixture_audit_only",
                }
                save()
                audit_path.unlink()
                private_write(audit_path, damaged)
                try:
                    refuse_used_key_and_receipts()
                    assert audit_path.read_bytes() == damaged
                    assert directory_ids(journal) == original_ids
                    assert directory_ids(journal / ".occupied") == original_ids
                    assert directory_ids(journal / ".intents") == original_ids
                    assert all(path.read_bytes() == custody_before[str(path)]
                               for path in custody_metadata if path != audit_path)
                finally:
                    exact_owned_restore(audit_path, original_audit, label)
                prove_lookup_only_after_exact_restore()
                fault_details.append({"kind": label, "same_key_status_result_cancel_refused": True,
                                      "exact_fixture_restore_lookup_only": True})
            report.pop("active_controlled_custody_fault", None)
            report["controlled_custody_faults"] = fault_details
            passed(current, {"cases": fault_details, "same_key_typed_dispatch_count": 1, "new_inner_ids": 0,
                             "restored_snapshot_sha256": original_snapshot_info["sha256"],
                             "restored_owned_future_active": False})

            current = "immutable private key journal stores only hashes and identity"
            controller.stop()
            journal = state / "request-async-v9"
            assert stat.S_IMODE(journal.stat().st_mode) == 0o700
            anchor_path = state / ".request-async-v9-anchor.json"
            anchor_info = anchor_path.lstat()
            anchor_raw = anchor_path.read_bytes()
            anchor = json.loads(anchor_raw)
            assert stat.S_ISREG(anchor_info.st_mode) and anchor_info.st_nlink == 1
            assert stat.S_IMODE(anchor_info.st_mode) == 0o600 and len(anchor_raw) <= 4096
            assert set(anchor) == {
                "device", "inode", "occupancy_device", "occupancy_inode", "intents_device", "intents_inode",
                "metadata_lock_device", "metadata_lock_inode", "controller_lock_device", "controller_lock_inode",
            }
            assert all(isinstance(value, int) and value >= 0 for value in anchor.values())
            for path, prefix in [
                (journal, ""), (journal / ".occupied", "occupancy_"), (journal / ".intents", "intents_"),
                (journal / ".lock", "metadata_lock_"), (journal / ".controller.lock", "controller_lock_"),
            ]:
                identity = path.lstat()
                assert (identity.st_dev, identity.st_ino) == (anchor[prefix + "device"], anchor[prefix + "inode"])
                if prefix.endswith("lock_"):
                    assert stat.S_ISREG(identity.st_mode) and identity.st_nlink == 1
                    assert stat.S_IMODE(identity.st_mode) == 0o600 and identity.st_size == 0
                else:
                    assert stat.S_ISDIR(identity.st_mode) and stat.S_IMODE(identity.st_mode) == 0o700
            occupied, intents = journal / ".occupied", journal / ".intents"
            assert stat.S_IMODE(occupied.stat().st_mode) == 0o700
            assert stat.S_IMODE(intents.stat().st_mode) == 0o700
            records = list(journal.glob("*.json"))
            occupancy_records = list(occupied.glob("*.json"))
            intent_records = list(intents.glob("*.json"))
            assert records and {path.name for path in records} == {path.name for path in occupancy_records}
            values = [json.loads(path.read_bytes()) for path in records]
            assert {path.name for path in intent_records} == {value["request_id"] + ".json" for value in values}
            assert all(value == json.loads((occupied / path.name).read_bytes()) ==
                       json.loads((intents / (value["request_id"] + ".json")).read_bytes())
                       for path, value in zip(records, values))
            for path in records + occupancy_records + intent_records:
                info = path.lstat()
                assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                assert stat.S_IMODE(info.st_mode) == 0o600
                raw = path.read_bytes()
                value = json.loads(raw)
                assert len(raw) <= 4096 and set(value) == BINDING_KEYS
                assert all(item.encode() not in raw for item in private_values)
                assert str(root).encode() not in raw and TARGET.encode() not in raw
                assert ALIAS.encode() not in raw and OTHER_ALIAS.encode() not in raw
                expected_name = value["request_id"] if path.parent == intents else value["key_hash"]
                assert path.name == expected_name + ".json"
            assert not any(event.get("event") == "refused_nonfixed_argv" for event in events(root))
            assert health_count(root) == expected_health_dispatches
            report["expected_fixed_health_dispatches"] = expected_health_dispatches
            passed(current, {"immutable_bindings": len(records), "occupied_bindings": len(occupancy_records),
                             "intent_bindings": len(intent_records),
                             "primary_occupancy_pairs_identical": True, "intent_primary_occupancy_bijection": True,
                             "raw_keys_parameters_or_credentials_stored": False,
                             "only_fixed_source_health_argv_executed": True})
            accepted = True
    except BaseException as error:
        report["failure"] = {
            "check": current, "type": type(error).__name__, "detail": sanitize(str(error))[:2048],
            "location": [{"function": frame.name, "file": pathlib.Path(frame.filename).name, "line": frame.lineno}
                         for frame in traceback.extract_tb(error.__traceback__)],
        }
        print("FAIL", current, type(error).__name__, flush=True)
    finally:
        cleanup_error = None
        try:
            if controller is not None:
                controller.cleanup()
            if root is not None:
                release_gate(root)
                until(lambda: all(not original_alive(event) for event in spawned(root)), seconds=18)
                report["owned_helper_spawns"] = len(spawned(root))
                report["owned_helper_original_identities_terminated"] = True
                report["owned_controller_exit_codes"] = [
                    child.returncode for child in controller.children
                ] if controller else []
                for original_path, target in [
                    (root / "events.jsonl", logdir / "fixed-health-events.jsonl"),
                    (wrapper, logdir / "fixed-health-wrapper.source.py"),
                ]:
                    if original_path is not None and original_path.exists():
                        private_write(target, original_path.read_bytes())
                (root / "token").unlink(missing_ok=True)
                report["owned_cleanup_confirmed"] = True
            else:
                report["owned_cleanup_confirmed"] = controller is None
        except BaseException as error:
            cleanup_error = type(error).__name__
            report["cleanup_failure"] = {"type": cleanup_error, "detail": sanitize(str(error))[:512]}
            report["owned_cleanup_confirmed"] = False
        try:
            after_source = source_identity()
            report["source_after"] = after_source
            report["binary_sha256_after"] = digest(binary)
            report["harness_sha256_after"] = digest(__file__)
            helper_after = {"deploy/mcp_tool_contract.py": digest(ROOT / "deploy/mcp_tool_contract.py")}
            if wrapper is not None and wrapper.exists():
                helper_after["generated_fixed_health_wrapper"] = digest(wrapper)
            report["helper_sha256_after"] = helper_after
            report["before_after_stable"] = (
                before_binary == report["binary_sha256_after"] and
                before_harness == report["harness_sha256_after"] and
                before_source["source_code_fingerprint"] == after_source["source_code_fingerprint"] and
                helper_before == helper_after and digest(V8_CONTRACT) == V8_SHA256 and
                (before_contract is None or digest(contract_path) == before_contract)
            )
            assert report["before_after_stable"], "source/binary/harness/helper/contract changed during fixture"
        except BaseException as error:
            report["identity_failure"] = {"type": type(error).__name__, "detail": sanitize(str(error))[:512]}
            report["before_after_stable"] = False
        report["logs"] = []
        for path in sorted(logdir.iterdir()):
            if not path.is_file():
                continue
            raw = path.read_bytes()
            text = sanitize(raw.decode("utf-8", errors="replace"))
            if path.suffix == ".log":
                text = "".join(
                    "[redacted authentication/header line]\n"
                    if any(marker in line.lower() for marker in (
                        "x-hepta-runtime-token", "authorization:", "cookie:", "set-cookie:",
                        "mcp-session-id", '"headers"',
                    )) else line for line in text.splitlines(keepends=True)
                )
            path.write_text(text)
            path.chmod(0o600)
            report["logs"].append({"name":path.name,"bytes":path.stat().st_size,
                                   "sha256":digest(path),"redacted":text.encode()!=raw})
        if root is not None:
            if report["owned_cleanup_confirmed"]:
                shutil.rmtree(root)
                report["private_fixture_removed"] = True
            else:
                (root / "token").unlink(missing_ok=True)
                report["preserved_owned_fixture_path"] = str(root)
                report["private_fixture_removed"] = False
        report["complete"] = bool(
            accepted and args.contract and report["exact_reviewed_contract_qualified"] and
            report["owned_cleanup_confirmed"] and report.get("before_after_stable") and
            "failure" not in report and "identity_failure" not in report
        )
        report["passed"] = len(report["checks"])
        save()
    if args.export_contract and report["catalog_export_complete"] and report["owned_cleanup_confirmed"] and report.get("before_after_stable"):
        print("CATALOG_EXPORTED_UNREVIEWED", report["contract_sha256"], flush=True)
        return
    if not report["complete"]:
        raise SystemExit(1)
    print("ALL_PASS_NATIVE_PRIVATE_FIXTURE", report["passed"], flush=True)


if __name__ == "__main__":
    main()

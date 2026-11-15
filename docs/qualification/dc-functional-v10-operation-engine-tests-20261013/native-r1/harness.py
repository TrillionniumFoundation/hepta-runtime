#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Disposable V10 operation protocol fixture; never a replacement qualification.

Generated loopback controllers, credentials and state only. A private SSH PATH
adapter accepts ONLY two exact compiled read-only helper sources and their
frozen source-generated argv, then runs those helpers against this fixture's
configured private read root. It never calls SSH, shell, sudo or process_start.
Controller faults signal only Popen children created by this harness. Receipts
contain hashes and typed states, never fixture output, raw errors or credentials.
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
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy"))
from mcp_tool_contract import ToolContract, make_contract

PROTOCOL = "2026-07-28"
CLIENT_INFO = {"name": "hepta-v10-private-native-operation-fixture", "version": "1"}
ALIAS = "v10-read-fixture"
TARGET = "v10-local-readonly-helper"
STORE = "request-operations-v10"
FORMAT = "serialized_original_native_sdk_payload_before_operation_metadata_and_transport_normalization"
ADDITIONS = {"operation_start", "operation_status", "operation_result", "operation_cancel"}
TOOLS = {
    "read_multiple_files", "file_info", "binary_read", "process_status",
    "process_read", "process_wait", "process_list", "hardware_snapshot",
    "service_status", "network_inspect",
}
BINDING_KEYS = {
    "request_id", "owner", "tool_name", "accepted_unix_ms", "key_hash",
    "request_hash", "policy_binding", "ledger_identity",
}


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def digest_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


def digest(path):
    path = pathlib.Path(path)
    assert path.is_file() and not path.is_symlink(), "ordinary file required"
    return digest_bytes(path.read_bytes())


def source_identity():
    paths = set(ROOT.glob("src/**/*.rs")) | set(ROOT.glob("src/**/*.py"))
    paths.update({ROOT / "Cargo.toml", ROOT / "Cargo.lock"})
    records = {}
    for path in sorted(paths, key=lambda item: item.relative_to(ROOT).as_posix()):
        assert path.is_file() and not path.is_symlink()
        raw = path.read_bytes()
        records[path.relative_to(ROOT).as_posix()] = {"bytes": len(raw), "sha256": digest_bytes(raw)}
    return {
        "base_HEAD": subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip(),
        "source_code_fingerprint": digest_bytes(canonical(records)),
        "source_files": records,
    }


def private_write(path, data):
    path = pathlib.Path(path)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as writer:
        writer.write(data.encode() if isinstance(data, str) else data)
        writer.flush()
        os.fsync(writer.fileno())


def until(predicate, seconds=15):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(.025)
    raise AssertionError("bounded fixture observation deadline")


def text_result(raw):
    parts = [part["text"] for part in raw.get("content", []) if part.get("type") == "text"]
    assert len(parts) == 1, "exact one native text block required"
    return json.loads(parts[0])


def normalized_native(raw):
    raw = copy.deepcopy(raw)
    raw.setdefault("resultType", "complete")
    return raw


class Client:
    def __init__(self, url, token):
        self.url, self.token, self.session, self.serial = url, token, None, 0
        self.protocol = PROTOCOL
        result = self.rpc("initialize", {
            "protocolVersion": PROTOCOL, "capabilities": {}, "clientInfo": CLIENT_INFO,
        })
        self.protocol = result["protocolVersion"]
        assert self.protocol in {PROTOCOL, "2025-11-25", "2025-06-18"}
        self.rpc("notifications/initialized", {}, notify=True)

    def rpc(self, method, parameters, notify=False):
        self.serial += 1
        parameters = copy.deepcopy(parameters)
        if not notify and method != "initialize" and self.protocol == PROTOCOL:
            meta = parameters.setdefault("_meta", {})
            meta.setdefault("io.modelcontextprotocol/protocolVersion", PROTOCOL)
            meta.setdefault("io.modelcontextprotocol/clientCapabilities", {})
            meta.setdefault("io.modelcontextprotocol/clientInfo", CLIENT_INFO)
        body = {"jsonrpc": "2.0", "method": method, "params": parameters}
        if not notify:
            body["id"] = self.serial
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "X-Hepta-Runtime-Token": self.token,
            "MCP-Protocol-Version": self.protocol,
        }
        if self.session:
            headers["Mcp-Session-Id"] = self.session
        request = urllib.request.Request(self.url, data=json.dumps(body).encode(), headers=headers)
        with urllib.request.urlopen(request, timeout=35) as response:
            self.session = response.headers.get("Mcp-Session-Id", self.session)
            wire = response.read(2 * 1024 * 1024 + 1)
        assert len(wire) <= 2 * 1024 * 1024
        if notify:
            return None
        text = wire.decode()
        events = [json.loads(line[5:].strip()) for line in text.splitlines()
                  if line.startswith("data:") and line[5:].strip()]
        result = events[-1] if events else json.loads(text)
        assert result.get("id") == self.serial
        if "error" in result:
            raise RuntimeError(result["error"])
        return result["result"]

    def raw_call(self, tool, arguments, meta=None):
        request = {"name": tool, "arguments": arguments}
        if meta is not None:
            request["_meta"] = meta
        result = self.rpc("tools/call", request)
        if tool in ADDITIONS:
            assert len(json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode()) <= 65536
        return result

    def call(self, tool, arguments):
        result = self.raw_call(tool, arguments)
        assert result.get("isError") is not True, "operation API unexpectedly refused"
        return text_result(result)


def denied(client, tool, arguments, meta=None):
    try:
        result = client.raw_call(tool, arguments, meta)
    except RuntimeError as error:
        assert isinstance(error.args[0], dict) and "code" in error.args[0]
        return "jsonrpc_error"
    assert result.get("isError") is True, "expected fail-closed refusal"
    return "tool_error"


def proc_identity(pid):
    try:
        path = pathlib.Path("/proc") / str(pid)
        value = (path / "stat").read_text()
        fields = value[value.rfind(")") + 2:].split()
        return {"pid": pid, "uid": path.stat().st_uid, "start": fields[19], "state": fields[0]}
    except (FileNotFoundError, ProcessLookupError):
        return None


def alive(original):
    current = proc_identity(original["pid"])
    return bool(current and current["uid"] == original["uid"]
                and current["start"] == original["start"] and current["state"] != "Z")


def event_rows(root):
    path = root / "events.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def shell_quote(value):
    return "'" + value.replace("'", "'\"'\"'") + "'"


def helper_sources():
    source = ROOT / "src/mcp/runtime"
    binary = "\n".join((source / name).read_text() for name in (
        "file_metadata.py", "inode_patch.py", "binary_file.py",
    ))
    multi = "__name__ = 'hepta_multi_read_helpers'\n" + (source / "file_metadata.py").read_text()
    multi += "\n" + (source / "binary_file.py").read_text()
    multi += "\n" + (source / "multi_read_host.py").read_text() + "\nrun_multi_read()\n"
    return {"binary": binary, "multi": multi}


def install_wrapper(root):
    """Known immutable read-only Python source only; no generic argv dispatch."""
    bindir = root / "bin"
    bindir.mkdir(mode=0o700)
    commands = {"python3 -c " + shell_quote(code): code for code in helper_sources().values()}
    harness = proc_identity(os.getpid())
    assert harness
    prefix = [
        "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
        "-o", "StrictHostKeyChecking=yes", "-o", "ForwardAgent=no", TARGET,
    ]
    code = (
        "#!/usr/bin/python3\n"
        "import fcntl,json,os,pathlib,sys,time\n"
        f"root=pathlib.Path({str(root)!r})\n"
        f"commands={commands!r}\n"
        f"prefix={prefix!r}\n"
        f"harness={harness!r}\n"
        "def identity(pid):\n"
        " try:\n"
        "  p=pathlib.Path('/proc')/str(pid);s=(p/'stat').read_text();v=s[s.rfind(')')+2:].split()\n"
        "  return {'pid':pid,'uid':p.stat().st_uid,'start':v[19],'state':v[0]}\n"
        " except (FileNotFoundError,ProcessLookupError):return None\n"
        "def same(a,b):return bool(a and b and a['uid']==b['uid'] and a['start']==b['start'] and b['state']!='Z')\n"
        "if len(sys.argv)!=len(prefix)+2 or sys.argv[1:-1]!=prefix or sys.argv[-1] not in commands:raise SystemExit(85)\n"
        "raw=sys.stdin.buffer.read(8193)\n"
        "if len(raw)>8192:raise SystemExit(87)\n"
        "try:q=json.loads(raw)\n"
        "except Exception:raise SystemExit(87)\n"
        "work=root/'workspace'\n"
        "def allowed(path):\n"
        " p=pathlib.Path(path);return p.parent==work and (p.name=='fixture.txt' or p.name.startswith('missing-'))\n"
        "source=commands[sys.argv[-1]]\n"
        "if source.startswith(\"__name__ = 'hepta_multi_read_helpers'\"):\n"
        " if set(q)!={'files','max_file_bytes','max_response_bytes'} or not 1<=len(q['files'])<=16:raise SystemExit(87)\n"
        " if any(set(f)!={'path','root'} or f['root']!=str(work) or not allowed(f['path']) for f in q['files']):raise SystemExit(87)\n"
        "else:\n"
        " if q.get('op') not in {'info','read'} or q.get('root')!=str(work) or not allowed(q.get('path','')):raise SystemExit(87)\n"
        " if set(q)-{'op','root','path','offset','limit','expected_version'}:raise SystemExit(87)\n"
        "mine=identity(os.getpid());parent=identity(os.getppid())\n"
        "fd=os.open(root/'events.jsonl',os.O_WRONLY|os.O_CREAT|os.O_APPEND|os.O_NOFOLLOW,0o600)\n"
        "try:\n"
        " fcntl.flock(fd,fcntl.LOCK_EX);os.write(fd,(json.dumps(mine,sort_keys=True)+'\\n').encode());os.fsync(fd)\n"
        "finally:os.close(fd)\n"
        "deadline=time.monotonic()+30\n"
        "while (root/'gate').exists():\n"
        " if time.monotonic()>deadline or not same(parent,identity(parent['pid'])) or not same(harness,identity(harness['pid'])):raise SystemExit(86)\n"
        " time.sleep(.02)\n"
        "if not same(parent,identity(parent['pid'])) or not same(harness,identity(harness['pid'])):raise SystemExit(86)\n"
        "readfd,writefd=os.pipe()\n"
        "if os.write(writefd,raw)!=len(raw):raise SystemExit(88)\n"
        "os.close(writefd);os.dup2(readfd,0);os.close(readfd)\n"
        "os.execv('/usr/bin/python3',['python3','-c',source])\n"
    )
    wrapper = bindir / "ssh"
    private_write(wrapper, code)
    wrapper.chmod(0o700)
    env = dict(os.environ)
    env["PATH"] = str(bindir) + ":" + env.get("PATH", "")
    return env, digest(wrapper)


class Controller:
    def __init__(self, binary, workspace, config, tokenfile, env):
        self.binary, self.workspace, self.config, self.tokenfile, self.env = (
            binary, workspace, config, tokenfile, env,
        )
        self.children = []
        self.child = None
        self.logs = []

    def start(self):
        assert self.child is None or self.child.poll() is not None
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        self.url = f"http://127.0.0.1:{port}/mcp"
        log = tempfile.TemporaryFile(mode="w+b")
        self.logs.append(log)
        self.child = subprocess.Popen([
            str(self.binary), "mcp", "--path", str(self.workspace),
            "--bind", f"127.0.0.1:{port}", "--runtime-config", str(self.config),
            "--auth-token-file", str(self.tokenfile),
        ], env=self.env, stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
        self.children.append(self.child)

        def ready():
            if self.child.poll() is not None:
                raise AssertionError("private controller exited before readiness")
            try:
                return Client(self.url, self.tokenfile.read_text().strip())
            except (OSError, RuntimeError):
                return None
        return until(ready)

    def stop(self, crash=False):
        if self.child is not None and self.child.poll() is None:
            if crash:
                os.kill(self.child.pid, signal.SIGKILL)
            else:
                os.killpg(self.child.pid, signal.SIGTERM)
            try:
                self.child.wait(timeout=8)
            except subprocess.TimeoutExpired:
                os.killpg(self.child.pid, signal.SIGKILL)
                self.child.wait(timeout=5)

    def cleanup(self):
        self.stop()
        for child in self.children:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=5)

    def log_metadata(self, forbidden):
        receipts = []
        for log in self.logs:
            log.flush()
            log.seek(0)
            raw = log.read(16 * 1024 * 1024 + 1)
            assert len(raw) <= 16 * 1024 * 1024
            assert all(secret not in raw for secret in forbidden), "private output leaked to controller logs"
            receipts.append({"bytes": len(raw), "sha256": digest_bytes(raw), "plaintext_markers_absent": True})
        return receipts

    def close_logs(self):
        for log in self.logs:
            log.close()


def start_operation(client, tool, arguments, key):
    result = client.call("operation_start", {
        "operation": {"tool": tool, "arguments": arguments}, "idempotency_key": key,
    })
    assert re.fullmatch("[0-9a-f]{64}", result["operation_id"])
    assert result["tool_name"] == tool
    assert result["automatic_retry"] is False and result["delivery_proven"] is False
    assert result["idempotency_binding_retained"] is True
    return result


def operation_status(client, operation_id):
    value = client.call("operation_status", {"operation_id": operation_id})
    assert value["operation_id"] == operation_id
    assert value["automatic_retry"] is False and value["delivery_proven"] is False
    return value


def settled(client, operation_id):
    return until(lambda: value if (value := operation_status(client, operation_id))["async_state"]
                 in {"completed", "failed", "cancelled_future", "cancelled_before_dispatch", "unknown"}
                 else None, seconds=20)


def reconstructed(client, operation_id, expected=None, page_limit=16384):
    offset, result, hashes, total, count = 0, bytearray(), set(), None, 0
    while count < 1_048_577:
        value = client.call("operation_result", {
            "operation_id": operation_id, "offset": offset, "limit": page_limit,
        })
        assert value["operation_id"] == operation_id and value["offset"] == offset
        assert value["automatic_retry"] is False and value["delivery_proven"] is False
        assert value["immutable_snapshot"] is True and value["format"] == FORMAT
        assert value["payload_kind"] in {"native_result", "native_error"}
        assert 0 <= value["total_bytes"] <= 1_048_576
        if total is None:
            total = value["total_bytes"]
        assert total == value["total_bytes"]
        hashes.add(value["result_sha256"])
        assert len(hashes) == 1
        chunk = base64.b64decode(value["data_base64"], validate=True)
        assert len(chunk) <= min(page_limit, 16384)
        assert value["next_offset"] == offset + len(chunk)
        result.extend(chunk)
        offset = value["next_offset"]
        count += 1
        if value["eof"]:
            assert offset == total
            break
        assert chunk, "nonterminal result page must advance"
    else:
        raise AssertionError("bounded operation result pagination did not terminate")
    raw = bytes(result)
    assert len(raw) == total and digest_bytes(raw) in hashes
    recovered = json.loads(raw)
    if value["payload_kind"] == "native_result":
        recovered = normalized_native(recovered)
    if expected is not None:
        assert recovered == normalized_native(expected), "retained original native SDK payload changed"
    first = client.call("operation_result", {"operation_id": operation_id, "offset": 0, "limit": 13})
    assert base64.b64decode(first["data_base64"], validate=True) == raw[:13]
    assert first["result_sha256"] == digest_bytes(raw)
    return recovered, {"bytes": len(raw), "sha256": digest_bytes(raw), "pages": count,
                       "payload_kind": value["payload_kind"]}


def private_state_scan(state, forbidden):
    files = []
    for path in sorted(state.rglob("*")):
        assert not path.is_symlink(), "fixture state unexpectedly contains symlink"
        metadata = path.stat()
        if stat.S_ISDIR(metadata.st_mode):
            if path.name.startswith("request-operations") or STORE in path.parts:
                assert stat.S_IMODE(metadata.st_mode) == 0o700
            continue
        if stat.S_ISREG(metadata.st_mode):
            if STORE in path.parts or path.name == ".request-operations-v10-anchor.json":
                assert stat.S_IMODE(metadata.st_mode) == 0o600 and metadata.st_nlink == 1
            raw = path.read_bytes()
            assert all(secret not in raw for secret in forbidden), "raw private value leaked to persisted state"
            files.append({"relative_path": str(path.relative_to(state)),
                          "bytes": len(raw), "sha256": digest_bytes(raw)})
    return files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--expected-binary-sha256", required=True)
    parser.add_argument("--expected-source-fingerprint", required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--previous-contract", required=True)
    parser.add_argument("--expected-previous-contract-sha256", required=True)
    parser.add_argument("--expected-contract-sha256")
    parser.add_argument("--output", "--out", dest="output", required=True)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--contract")
    selection.add_argument("--export-contract")
    args = parser.parse_args()
    binary = pathlib.Path(args.binary).resolve(strict=True)
    previous = pathlib.Path(args.previous_contract).resolve(strict=True)
    contract_path = pathlib.Path(args.contract or args.export_contract).resolve()
    outfile = pathlib.Path(args.output).resolve()
    assert not outfile.exists(), "never overwrite earlier evidence"
    assert digest(binary) == args.expected_binary_sha256
    assert digest(previous) == args.expected_previous_contract_sha256
    baseline = source_identity()
    assert baseline["base_HEAD"] == args.expected_head
    assert baseline["source_code_fingerprint"] == args.expected_source_fingerprint
    if args.contract:
        assert args.expected_contract_sha256, "explicit independently reviewed contract SHA required"
        assert digest(contract_path) == args.expected_contract_sha256
    else:
        assert not contract_path.exists()
    outfile.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "schema": "hepta-dc-v10-operation-private-native-fixture-v1",
        "recorded_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "origin": "disposable_native_http_with_exact_local_readonly_helpers",
        "binary_sha256": digest(binary), "harness_sha256": digest(__file__),
        "source": baseline, "previous_contract_sha256": digest(previous),
        "contract_sha256": digest(contract_path) if args.contract else None,
        "catalog_mode": "pinned-review" if args.contract else "unreviewed-export-only",
        "qualification_scope": "private_native_operation_protocol_only",
        "complete": False, "checks": [],
        "real_ssh_qualified": False, "six_machine_qualified": False,
        "model_origin_qualified": False, "business_replacement_qualified": False,
        "authenticated_chatgpt_caller_isolation": False,
        "installed_runtime_changed": False, "desktop_commander_changed": False,
        "production_recovery_rollback_qualified": False,
        "full_dc_replacement_qualified": False,
        "limits": [
            "Fixed local SSH adapter executes exact readonly native helper source under test-only policy.",
            "Only four result-bearing arms receive native fixture execution; ten closed arms require Rust parser coverage and real-host acceptance.",
            "Global eight-slot and two-owner limits require separate Rust tests; one native token proves only the four-owner slot limit.",
            "Immutable key capacity has no eviction or TTL promise.",
            "Cancellation controls the owned read future; no remote effect reversal or output delivery is proven.",
        ],
    }
    forbidden, controllers, controller = [], [], None
    phase = "prepare"
    helper_events = []
    root = None

    def save():
        encoded = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
        assert all(secret.decode("utf-8", "ignore") not in encoded for secret in forbidden if secret)
        outfile.write_text(encoded)
        outfile.chmod(0o600)

    def passed(name, detail=None):
        report["checks"].append({"check": name, "result": "passed", "detail": detail})
        save()
        print("PASS", name, flush=True)

    save()
    try:
        if True:
            temporary = tempfile.mkdtemp(prefix="hepta-v10-operation-fixture-")
            root = pathlib.Path(temporary)
            root.chmod(0o700)
            workspace = root / "workspace"
            workspace.mkdir(mode=0o700)
            state = root / "state"
            token = secrets.token_hex(32)
            rotated = secrets.token_hex(32)
            marker = "PRIVATE_V10_RESULT_" + secrets.token_hex(16)
            private_key = "PRIVATE_V10_KEY_" + secrets.token_hex(16)
            spoof = "PRIVATE_V10_SPOOF_" + secrets.token_hex(16)
            forbidden.extend(value.encode() for value in (token, rotated, marker, private_key, spoof))
            forbidden.append(base64.b64encode(marker.encode())[:-4])
            data = (marker + "\n" + ("read-only-fixture-data\n" * 2800)).encode()
            assert 32768 < len(data) < 65536
            fixture = workspace / "fixture.txt"
            private_write(fixture, data)
            tokenfile = root / "token"
            private_write(tokenfile, token)
            cfg = {
                "state_dir": str(state), "controller_workspace_roots": [str(workspace)],
                "hosts": {ALIAS: {
                    "ssh_target": TARGET, "platform": "linux", "execution_mode": "operator",
                    "remote_state_dir": str(root / "unused-job-state"),
                    "allow_execute": False, "allow_pty": False, "allow_write": False,
                    "allow_job_network": False, "allow_detached_fallback": False,
                    "allowed_read_path_prefixes": [str(workspace)],
                    "allowed_write_path_prefixes": [],
                }},
            }
            config = root / "runtime.json"
            private_write(config, json.dumps(cfg))
            env, wrapper_sha = install_wrapper(root)
            report["readonly_helper_adapter_sha256"] = wrapper_sha
            report["readonly_helper_source_sha256"] = {
                name: digest_bytes(code.encode()) for name, code in helper_sources().items()
            }
            controller = Controller(binary, workspace, config, tokenfile, env)
            controllers.append(controller)
            client = controller.start()

            phase = "exact pinned V9 predecessors and four closed V10 definitions"
            tools = client.rpc("tools/list", {})["tools"]
            old = ToolContract.load(previous, args.expected_previous_contract_sha256)
            actual = {tool["name"]: tool for tool in tools}
            assert len(tools) == len(actual) == len(old.tools) + 4
            assert set(actual) - set(old.by_name) == ADDITIONS
            assert all(actual[name] == definition for name, definition in old.by_name.items())
            for name in ADDITIONS:
                assert actual[name]["inputSchema"]["additionalProperties"] is False
                assert "owner" not in actual[name]["inputSchema"].get("properties", {})
            if args.export_contract:
                contract_path.parent.mkdir(parents=True, exist_ok=True)
                private_write(contract_path, json.dumps(make_contract(tools), indent=2, ensure_ascii=False) + "\n")
                report["contract_sha256"] = digest(contract_path)
                report["catalog_exported"] = True
                report["execution_acceptance_run"] = False
                report["complete"] = True
                passed(phase, {"new_definitions": sorted(ADDITIONS), "predecessors_unchanged": True})
                return 0
            reviewed = ToolContract.load(contract_path, args.expected_contract_sha256)
            reviewed.verify(tools)
            report["execution_acceptance_run"] = True
            passed(phase, {"new_definitions": sorted(ADDITIONS), "predecessors_unchanged": True})

            phase = "closed operation selection refuses effects, recursion, raw targets and unknown fields"
            before = len(event_rows(root))
            refusals = []
            for tool in ("process_start", "process_cancel", "binary_write", "binary_upload",
                         "privileged_action", "host_signal", "maintenance_apply",
                         "operation_start", "request_start", "arbitrary_tool"):
                refusals.append(denied(client, "operation_start", {
                    "operation": {"tool": tool, "arguments": {}}, "idempotency_key": private_key + tool,
                }))
            for extra in ("owner", "executable", "ssh_target", "pid"):
                refusals.append(denied(client, "operation_start", {
                    "operation": {"tool": "process_list", "arguments": {}, extra: spoof},
                    "idempotency_key": private_key + extra,
                }))
            refusals.append(denied(client, "operation_start", {
                "operation": {"tool": "process_list", "arguments": {"owner": spoof}},
                "idempotency_key": private_key + "arguments-extra",
            }))
            assert len(event_rows(root)) == before
            passed(phase, {"refusal_count": len(refusals), "helper_dispatches": 0})

            phase = "four native result arms preserve exact original arbitrary SDK payloads"
            successes = []
            retained = {}
            calls = [
                ("read_multiple_files", {"host": ALIAS, "paths": [str(fixture)],
                 "max_file_bytes": 65536, "max_response_bytes": 262144}),
                ("file_info", {"host": ALIAS, "path": str(fixture)}),
                ("binary_read", {"host": ALIAS, "path": str(fixture), "limit": 65536}),
                ("process_list", {"host": ALIAS}),
            ]
            for index, (tool, arguments) in enumerate(calls):
                original = client.raw_call(tool, arguments)
                assert original.get("isError") is not True
                result = start_operation(client, tool, arguments, private_key + f"-native-{index}")
                assert result["reused"] is False
                status = settled(client, result["operation_id"])
                assert status["async_state"] == "completed" and status["payload_available"] is True
                recovered, metadata = reconstructed(client, result["operation_id"], original, page_limit=16384)
                retained[tool] = (result["operation_id"], arguments, metadata)
                if tool == "read_multiple_files":
                    assert marker in json.dumps(recovered)
                    assert metadata["pages"] > 1
                if tool == "binary_read":
                    recovered_text = text_result(recovered)
                    assert base64.b64decode(recovered_text["data_base64"], validate=True) == data
                    assert metadata["pages"] > 1
                successes.append({"tool": tool, **metadata})
            passed(phase, {"results": successes})

            phase = "page bounds refuse zero, overlarge limits and past-end cursors"
            native_id, _, native_metadata = retained["binary_read"]
            for cursor in (
                {"operation_id": native_id, "limit": 0},
                {"operation_id": native_id, "limit": 16385},
                {"operation_id": native_id, "offset": native_metadata["bytes"] + 1, "limit": 13},
            ):
                denied(client, "operation_result", cursor)
            reconstructed(client, native_id, page_limit=16384)
            passed(phase, {"invalid_page_requests_refused": 3, "retained_bytes_unchanged": True})

            phase = "same credential reconnect and repeated key return the original identity without dispatch"
            reconnect = Client(controller.url, token)
            before = len(event_rows(root))
            original_id, arguments, _ = retained["read_multiple_files"]
            repeated = start_operation(reconnect, "read_multiple_files", arguments, private_key + "-native-0")
            assert repeated["reused"] is True and repeated["operation_id"] == original_id
            reconstructed(reconnect, original_id, page_limit=16384)
            assert len(event_rows(root)) == before
            denied(reconnect, "operation_start", {
                "operation": {"tool": "file_info", "arguments": {"host": ALIAS, "path": str(fixture)}},
                "idempotency_key": private_key + "-native-0",
            })
            assert len(event_rows(root)) == before
            passed(phase, {"same_identity": True, "new_helper_dispatches": 0})

            phase = "read-only native error payloads remain exact and encrypted"
            missing = workspace / ("missing-" + marker)
            error_arguments = {"host": ALIAS, "path": str(missing)}
            original_error = reconnect.raw_call("file_info", error_arguments)
            assert original_error.get("isError") is True
            result = start_operation(reconnect, "file_info", error_arguments, private_key + "-error")
            status = settled(reconnect, result["operation_id"])
            assert status["async_state"] == "failed" and status["payload_available"] is True
            _, metadata = reconstructed(reconnect, result["operation_id"], original_error)
            assert metadata["payload_kind"] == "native_result"
            passed(phase, metadata)

            phase = "early start survives its HTTP response and cancels only its owned read future"
            private_write(root / "gate", b"")
            before = len(event_rows(root))
            started = time.monotonic()
            blocked = start_operation(reconnect, "file_info", calls[1][1], private_key + "-blocked")
            assert time.monotonic() - started < 2.5, "start waited for gated read completion"
            until(lambda: len(event_rows(root)) == before + 1)
            assert (root / "gate").exists()
            fresh = Client(controller.url, token)
            observed = operation_status(fresh, blocked["operation_id"])
            assert observed["async_state"] in {"queued", "running"}
            assert observed["payload_available"] is False
            denied(fresh, "operation_result", {"operation_id": blocked["operation_id"]})
            repeated = start_operation(fresh, "file_info", calls[1][1], private_key + "-blocked")
            assert repeated["operation_id"] == blocked["operation_id"] and repeated["reused"] is True
            assert len(event_rows(root)) == before + 1
            cancelled = fresh.call("operation_cancel", {"operation_id": blocked["operation_id"]})
            assert cancelled["operation_id"] == blocked["operation_id"]
            observed = settled(fresh, blocked["operation_id"])
            assert observed["async_state"] in {"cancelled_future", "cancelled_before_dispatch"}
            assert observed["payload_available"] is False
            until(lambda: all(not alive(event) for event in event_rows(root)[before:]))
            (root / "gate").unlink()
            reconstructed(fresh, retained["binary_read"][0])
            passed(phase, {"early_return_observed": True, "same_identity": True, "new_mcp_session_query": True,
                           "cancel_scope": "owned_future_only", "result_delivery_proven": False})

            phase = "four owned active slots refuse a fifth but leave repeated keys and status usable"
            private_write(root / "gate", b"")
            blocked_slots = []
            before = len(event_rows(root))
            for index in range(4):
                blocked_slots.append(start_operation(fresh, "file_info", calls[1][1], private_key + f"-slot-{index}"))
            until(lambda: len(event_rows(root)) == before + 4)
            denied(fresh, "operation_start", {
                "operation": {"tool": "file_info", "arguments": calls[1][1]},
                "idempotency_key": private_key + "-slot-fifth",
            })
            denied(fresh, "request_start", {
                "operation": {"tool": "host_list", "arguments": {}},
                "idempotency_key": private_key + "-v9-shared-slot-fifth",
            })
            repeat = start_operation(fresh, "file_info", calls[1][1], private_key + "-slot-0")
            assert repeat["operation_id"] == blocked_slots[0]["operation_id"] and repeat["reused"]
            operation_status(fresh, repeat["operation_id"])
            assert len(event_rows(root)) == before + 4
            for item in blocked_slots:
                fresh.call("operation_cancel", {"operation_id": item["operation_id"]})
                assert settled(fresh, item["operation_id"])["async_state"] in {
                    "cancelled_future", "cancelled_before_dispatch",
                }
            until(lambda: all(not alive(event) for event in event_rows(root)[before:]))
            (root / "gate").unlink()
            passed(phase, {"active_owner_limit": 4, "new_fifth_dispatches": 0,
                           "existing_key_and_status_queryable": True, "v9_new_start_refused_while_v10_full": True,
                           "global_limit_native_proven": False})

            phase = "controller crash leaves unknown identity and never replays its used key on restart"
            private_write(root / "gate", b"")
            before = len(event_rows(root))
            crashed = start_operation(fresh, "file_info", calls[1][1], private_key + "-crash")
            until(lambda: len(event_rows(root)) == before + 1)
            controller.stop(crash=True)
            until(lambda: all(not alive(event) for event in event_rows(root)[before:]))
            (root / "gate").unlink()
            fresh = controller.start()
            unknown = operation_status(fresh, crashed["operation_id"])
            assert unknown["async_state"] == "unknown" and unknown["payload_available"] is False
            repeat = start_operation(fresh, "file_info", calls[1][1], private_key + "-crash")
            assert repeat["operation_id"] == crashed["operation_id"] and repeat["reused"]
            assert len(event_rows(root)) == before + 1
            denied(fresh, "operation_result", {"operation_id": crashed["operation_id"]})
            passed(phase, {"identity_retained": True, "state": "unknown", "new_dispatches_after_restart": 0})

            phase = "lookup traffic beyond audit quota preserves the oldest encrypted native payload"
            before = len(event_rows(root))
            oldest = retained["read_multiple_files"][0]
            for _ in range(140):
                operation_status(fresh, oldest)
            reconstructed(fresh, oldest, page_limit=16384)
            assert len(event_rows(root)) == before
            passed(phase, {"lookup_calls": 140, "oldest_payload_readable": True, "new_dispatches": 0})

            phase = "authenticated ciphertext damage refuses plaintext result and never redispatches"
            untouched_id = retained["binary_read"][0]
            payload = state / STORE / ".payloads" / (untouched_id + ".bin")
            assert payload.is_file() and stat.S_IMODE(payload.stat().st_mode) == 0o600
            raw_ciphertext = bytearray(payload.read_bytes())
            assert len(raw_ciphertext) > 32
            raw_ciphertext[-1] ^= 1
            payload.write_bytes(raw_ciphertext)
            before = len(event_rows(root))
            denied(fresh, "operation_result", {"operation_id": untouched_id})
            assert len(event_rows(root)) == before
            passed(phase, {"authenticated_corruption_refused": True, "new_dispatches": 0})

            phase = "wrong token and spoofed client metadata cannot disclose retained operations"
            bad_request = urllib.request.Request(controller.url, data=b"{}", headers={
                "Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                "X-Hepta-Runtime-Token": rotated, "MCP-Protocol-Version": PROTOCOL,
            })
            try:
                with urllib.request.urlopen(bad_request, timeout=5) as response:
                    wrong_status = response.status
            except urllib.error.HTTPError as error:
                wrong_status = error.code
            assert wrong_status in {401, 403}
            forged_id = "0" * 64
            denied(fresh, "operation_status", {"operation_id": forged_id}, meta={"owner": spoof})
            denied(fresh, "operation_result", {"operation_id": forged_id}, meta={"owner": spoof})
            passed(phase, {"wrong_token_http_status": wrong_status, "forged_owner_refused": True})

            phase = "controller restart with policy change or credential rotation denies previous encrypted ownership"
            assert operation_status(fresh, oldest)["payload_available"] is True
            reconstructed(fresh, oldest)
            controller.stop()
            revoked = copy.deepcopy(cfg)
            revoked["hosts"][ALIAS]["allowed_read_path_prefixes"] = []
            config.write_text(json.dumps(revoked))
            config.chmod(0o600)
            fresh = controller.start()
            positive = start_operation(fresh, "process_list", {"host": ALIAS}, private_key + "-revoked-positive")
            assert settled(fresh, positive["operation_id"])["payload_available"] is True
            reconstructed(fresh, positive["operation_id"])
            denied(fresh, "operation_status", {"operation_id": oldest})
            denied(fresh, "operation_result", {"operation_id": oldest})
            controller.stop()
            config.write_text(json.dumps(cfg))
            config.chmod(0o600)
            tokenfile.write_text(rotated)
            tokenfile.chmod(0o600)
            fresh = controller.start()
            positive = start_operation(fresh, "process_list", {"host": ALIAS}, private_key + "-rotated-positive")
            assert settled(fresh, positive["operation_id"])["payload_available"] is True
            reconstructed(fresh, positive["operation_id"])
            denied(fresh, "operation_status", {"operation_id": oldest})
            denied(fresh, "operation_result", {"operation_id": oldest})
            passed(phase, {"policy_revocation_refused": True, "credential_rotation_refused": True,
                           "new_policy_and_new_credential_engine_positive_controls": True,
                           "controller_restart_used": True, "live_file_reload_revocation_supported": False})

            phase = "deleting a primary used-key record cannot grant another operation permit"
            receipt = start_operation(fresh, "file_info", calls[1][1], private_key + "-deleted-primary")
            assert settled(fresh, receipt["operation_id"])["payload_available"]
            matches = []
            for path in (state / STORE).glob("*.json"):
                value = json.loads(path.read_bytes())
                if value.get("request_id") == receipt["operation_id"]:
                    matches.append(path)
            assert len(matches) == 1
            primary = matches[0]
            occupancy = state / STORE / ".occupied" / primary.name
            assert occupancy.is_file()
            occupancy_digest = digest(occupancy)
            primary.unlink()
            before = len(event_rows(root))
            denied(fresh, "operation_start", {
                "operation": {"tool": "file_info", "arguments": calls[1][1]},
                "idempotency_key": private_key + "-deleted-primary",
            })
            assert digest(occupancy) == occupancy_digest and not primary.exists()
            assert len(event_rows(root)) == before
            passed(phase, {"independent_occupancy_retained": True, "new_dispatches": 0,
                           "fail_closed": True})

            phase = "private persisted metadata, ciphertext, logs and receipt contain no raw private marker"
            controller.stop()
            helper_events = event_rows(root)
            until(lambda: all(not alive(event) for event in helper_events))
            report["private_state_files"] = private_state_scan(state, forbidden)
            report["controller_logs"] = controller.log_metadata(forbidden)
            report["owned_helper_instances"] = len(helper_events)
            passed(phase, {"private_value_count": len(forbidden), "plaintext_markers_absent": True,
                           "ordinary_0600_single_link_v10_files": True})

            phase = "final source, artifact, helper, contract and owned cleanup pins"
            assert source_identity() == baseline
            assert digest(binary) == args.expected_binary_sha256
            assert digest(contract_path) == args.expected_contract_sha256
            assert digest(previous) == args.expected_previous_contract_sha256
            assert digest(root / "bin/ssh") == wrapper_sha
            report["owned_controller_cleanup"] = all(child.poll() is not None for child in controller.children)
            report["owned_helper_cleanup"] = all(not alive(event) for event in helper_events)
            assert report["owned_controller_cleanup"] and report["owned_helper_cleanup"]
            report["complete"] = True
            passed(phase, {"all_pins_unchanged": True, "owned_cleanup_complete": True})
            return 0
    except Exception as error:
        report["failed_phase"] = phase
        report["error_type"] = type(error).__name__
        report["error_frames"] = [
            {"file": pathlib.Path(frame.filename).name, "line": frame.lineno, "function": frame.name}
            for frame in traceback.extract_tb(error.__traceback__)
        ]
        report["complete"] = False
        save()
        print("FAIL", phase, type(error).__name__, flush=True)
        return 1
    finally:
        for item in controllers:
            item.cleanup()
            item.close_logs()
        if root is not None and root.exists():
            events = event_rows(root)
            until(lambda: all(not alive(event) for event in events), seconds=35)
            report["owned_controller_cleanup"] = all(child.poll() is not None for item in controllers for child in item.children)
            report["owned_helper_cleanup"] = all(not alive(event) for event in events)
            save()
            shutil.rmtree(root)


if __name__ == "__main__":
    sys.exit(main())

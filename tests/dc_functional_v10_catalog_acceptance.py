#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""V10 exact native and modern facade catalog/lookup acceptance in private fixtures.

Preserves the thirteen V8 checks and adds its reviewed historical positive control.
V9 admission/cancellation definitions are exact-catalog controls; their lifecycle
is covered by a separate harness.

Creates only a loopback controller, generated credential and stdio facade. All
configured hosts deny execution and are never contacted. No installed runtime,
real SSH, ChatGPT model-origin or full Desktop Commander qualification is claimed.
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
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time

# V10 copies verify all executable helper bytes before importing them.
_V10_ROOT = pathlib.Path(__file__).resolve().parents[1]
_V10_VERSION = _V10_ROOT / "tests/dc_functional_v10_version_pin.py"
if not _V10_VERSION.is_file() or _V10_VERSION.is_symlink() or hashlib.sha256(_V10_VERSION.read_bytes()).hexdigest() != "399bb9767e84e3d97de0abfd25e38fed31a006ddd9f2e0e1ff21f4c39fd413b0":
    raise ValueError("reviewed V10 version helper differs")
sys.path.insert(0, str(_V10_ROOT / "tests"))
from dc_functional_v10_version_pin import verify_import_pins as _v10_verify_import_pins
_v10_verify_import_pins(_V10_ROOT)

ROOT = pathlib.Path(__file__).resolve().parents[1]
V5_SHA256 = "f3fd365ae69e1189c550c4314c4fdfb12f4c80d8cc86d1bc0aca6bd1bf7c4cba"
V6_SHA256 = "de23cec290a0c22d248575c92b656d2a194a8306b85cc92b68aedea4fe0db3c8"
V7_SHA256 = "8ad53842e4aa41bbd1567ed99e956088baafea108b6fb0b9a8df979c72c794cc"
V8_SHA256 = "b64769210b9913fbdab28f7d0e95b7ef300d8710b3f1eeea74afcfac25b08318"
V9_SHA256 = "12994454084369fb31e44f0e1ceb7a7f2ace5bbed33057789399cf895e70d553"
PREDECESSOR_HARNESS_SHA256 = "69a3d206c3f4fe5f125611e91557ed3730adcb886ba6ff01aca5ae5a4e477add"
HELPER_PATHS = {
    "http_helper_sha256": ROOT / "tests/runtime_http_acceptance.py",
    "contract_helper_sha256": ROOT / "deploy/mcp_tool_contract.py",
    "approval_loader_sha256": ROOT / "tests/dc_successor_contract_v10.py",
    "facade_sha256": ROOT / "deploy/chatgpt_full_operator.py",
}
ID_META = "io.hepta.runtime/request-v8"
ACK_META = "io.hepta.runtime/retention-v8"
SERVER_INFO = "io.modelcontextprotocol/serverInfo"
MODERN_META = {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientCapabilities": {},
    "io.modelcontextprotocol/clientInfo": {"name": "dc-v9-catalog-fixture", "version": "1"},
}


def digest(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def source_identity():
    """Use the real six-host harness's canonical Cargo plus src fingerprint."""
    paths = set(ROOT.glob("src/**/*.rs")) | set(ROOT.glob("src/**/*.py"))
    paths.update([ROOT / "Cargo.toml", ROOT / "Cargo.lock"])
    entries = {}
    for path in sorted(paths, key=lambda item: item.relative_to(ROOT).as_posix()):
        if path.is_symlink() or not path.is_file():
            raise ValueError("source fingerprint requires regular non-symlink files")
        raw = path.read_bytes()
        entries[path.relative_to(ROOT).as_posix()] = {
            "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
        }
    canonical = json.dumps(
        entries, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode()
    return {
        "source_fingerprint_algorithm": "sha256(canonical sorted relative path -> byte-count and sha256 map)",
        "source_code_fingerprint": hashlib.sha256(canonical).hexdigest(),
        "source_files": entries,
    }


def observed_pins(binary, source):
    return {
        "binary_sha256": digest(binary),
        "source_code_fingerprint": source["source_code_fingerprint"],
        **{name: digest(path) for name, path in HELPER_PATHS.items()},
    }


def load_helpers_after_pin():
    # Loading a helper executes Python; explicit pins must match first.
    global Client, ToolContract, make_contract, verify_successor
    sys.path.insert(0, str(ROOT / "tests"))
    sys.path.insert(0, str(ROOT / "deploy"))
    from runtime_http_acceptance import Client
    from mcp_tool_contract import ToolContract, make_contract
    from dc_successor_contract_v10 import V8_SHA256 as approved_v8, verify_successor
    assert approved_v8 == V8_SHA256, "approval loader V8 review pin drift"


def text_result(raw):
    values = [item["text"] for item in raw.get("content", []) if item.get("type") == "text"]
    assert len(values) == 1, "fixture requires one text result"
    return json.loads(values[0])


def marker(raw, expected):
    identity = raw["_meta"][ID_META]
    assert set(identity) == {"request_id", "automatic_retry", "delivery_proven"}
    request_id = identity["request_id"]
    assert len(request_id) == 64 and all(c in "0123456789abcdef" for c in request_id)
    assert identity["automatic_retry"] is False
    assert identity["delivery_proven"] is False
    ack = raw["_meta"][ACK_META]
    assert ack["result_state"] == expected
    assert ack["automatic_retry"] is False
    assert ack["audit_completion_durable"] is True
    return request_id


def expect_native_denied(client, name, arguments):
    try:
        value = client.rpc("tools/call", {"name": name, "arguments": arguments})
    except RuntimeError as error:
        assert isinstance(error.args[0], dict) and "code" in error.args[0]
        return
    assert value.get("isError") is True, "native owner override was accepted"


def verify_original(raw, data, facade=False):
    original = json.loads(data)
    reference = copy.deepcopy(raw)
    reference.setdefault("resultType", "complete")
    reference["_meta"].pop(ACK_META)
    if facade:
        reference["_meta"].pop(SERVER_INFO)
    assert original == reference
    assert set(original["_meta"]) == {ID_META}
    assert ACK_META not in original["_meta"]
    return original


def native_original(client, request_id):
    assembled = bytearray()
    offset = 0
    pinned = None
    for _ in range(4096):
        raw = client.rpc("tools/call", {
            "name": "request_result",
            "arguments": {"request_id": request_id, "offset": offset, "limit": 37},
        })
        marker(raw, "not_retained_policy")
        assert len(json.dumps(raw, separators=(",", ":")).encode()) <= 65536
        page = text_result(raw)
        assert page["request_id"] == request_id and page["offset"] == offset
        assert page["immutable_snapshot"] is True and page["automatic_retry"] is False
        chunk = base64.b64decode(page["data_base64"], validate=True)
        assert page["next_offset"] == offset + len(chunk)
        if pinned is None:
            pinned = page["result_sha256"]
        assert pinned == page["result_sha256"]
        assembled.extend(chunk)
        offset = page["next_offset"]
        if page["eof"]:
            assert offset == page["total_bytes"]
            assert hashlib.sha256(assembled).hexdigest() == pinned
            return bytes(assembled)
        assert chunk
    raise AssertionError("native result fixture page count exceeded bound")


class Facade:
    """The reviewed V7 stdio framing pattern, with dynamic requests after ID capture."""
    def __init__(self, command, logfile):
        self.serial = 0
        self.buffer = b""
        self.rows = []
        self.logfile = logfile
        self.writer = logfile.open("xb")
        logfile.chmod(0o600)
        self.child = subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=self.writer, bufsize=0, start_new_session=True,
        )

    def rpc(self, method, params):
        self.serial += 1
        params = copy.deepcopy(params)
        supplied = params.setdefault("_meta", {})
        for key, value in MODERN_META.items():
            supplied.setdefault(key, copy.deepcopy(value))
        request = {"jsonrpc": "2.0", "id": self.serial, "method": method, "params": params}
        self.child.stdin.write((json.dumps(request) + "\n").encode())
        self.child.stdin.flush()
        deadline = time.monotonic() + 40
        while b"\n" not in self.buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.child.stdout], [], [], remaining)[0]:
                raise TimeoutError("bounded facade request/reply deadline")
            block = os.read(self.child.stdout.fileno(), 65536)
            if not block:
                raise RuntimeError("facade ended before response")
            self.buffer += block
            assert len(self.buffer) <= 1024 * 1024
        line, self.buffer = self.buffer.split(b"\n", 1)
        response = json.loads(line)
        assert response.get("id") == request["id"]
        self.rows.append({"request": request, "response": response})
        return response

    def call(self, name, arguments, expected=None):
        response = self.rpc("tools/call", {"name": name, "arguments": arguments})
        assert "error" not in response
        result = response["result"]
        assert result.get("isError") is not True
        assert result["resultType"] == "complete"
        assert SERVER_INFO in result["_meta"]
        if expected is not None:
            marker(result, expected)
        if name in {"request_status", "request_result"}:
            assert len(json.dumps(result, separators=(",", ":")).encode()) <= 65536
        return result

    def denied(self, name, arguments):
        response = self.rpc("tools/call", {"name": name, "arguments": arguments})
        assert "error" in response or response.get("result", {}).get("isError") is True

    def stop(self, graceful=True):
        if self.child.poll() is None:
            if graceful:
                self.child.stdin.close()
                try:
                    code = self.child.wait(timeout=15)
                    assert code == 0, "facade failed on clean EOF"
                except subprocess.TimeoutExpired:
                    os.killpg(self.child.pid, signal.SIGKILL)
                    self.child.wait(timeout=5)
                    raise
            else:
                os.killpg(self.child.pid, signal.SIGTERM)
                try:
                    self.child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(self.child.pid, signal.SIGKILL)
                    self.child.wait(timeout=5)
        self.writer.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--contract", required=True)
    parser.add_argument("--out", "--output", dest="out", required=True)
    parser.add_argument("--expected-binary-sha256", required=True)
    parser.add_argument("--expected-source-fingerprint", required=True)
    parser.add_argument("--expected-http-helper-sha256", required=True)
    parser.add_argument("--expected-contract-helper-sha256", required=True)
    parser.add_argument("--expected-approval-loader-sha256", required=True)
    parser.add_argument("--expected-facade-sha256", required=True)
    args = parser.parse_args()
    expected_pins = {
        "binary_sha256": args.expected_binary_sha256,
        "source_code_fingerprint": args.expected_source_fingerprint,
        "http_helper_sha256": args.expected_http_helper_sha256,
        "contract_helper_sha256": args.expected_contract_helper_sha256,
        "approval_loader_sha256": args.expected_approval_loader_sha256,
        "facade_sha256": args.expected_facade_sha256,
    }
    if any(re.fullmatch("[0-9a-f]{64}", value) is None for value in expected_pins.values()):
        raise ValueError("all explicit pins require lowercase SHA256")
    binary = pathlib.Path(args.binary).resolve(strict=True)
    source_before = source_identity()
    pins_before = observed_pins(binary, source_before)
    assert pins_before == expected_pins, "candidate binary, source or helper differs from explicit pins"
    path = pathlib.Path(args.contract).resolve(strict=True)
    assert digest(path) == V9_SHA256, "unreviewed V10 contract file"
    load_helpers_after_pin()
    reviewed = ToolContract.load(path, V9_SHA256)
    outfile = pathlib.Path(args.out).resolve()
    assert not outfile.exists(), "never overwrite a prior acceptance receipt"
    outfile.parent.mkdir(parents=True, exist_ok=True)
    logdir = outfile.parent / (outfile.stem + "-logs")
    logdir.mkdir(mode=0o700, exist_ok=False)
    report = {
        "schema": "hepta-dc-functional-v9-catalog-native-facade-v1",
        "adapted_from_harness": "tests/dc_functional_v8_catalog_acceptance.py",
        "adapted_from_harness_sha256": PREDECESSOR_HARNESS_SHA256,
        "predecessor_checks_preserved": 13, "expected_checks": 14,
        "expected_pins": expected_pins, "observed_pins_before": pins_before,
        "source_before": source_before,
        "v9_background_lifecycle_qualified": False,
        "recorded_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "binary_sha256": digest(binary), "contract_sha256": digest(path),
        "harness_sha256": digest(__file__), "catalog_sha256": reviewed.catalog_sha256,
        "tool_count": 66, "checks": [], "complete": False,
        "origin": "isolated local native controller and modern stdio facade",
        "qualification_scope": "local_native_and_facade_contract_lookup_protocol_only",
        "target_health_probed": False, "real_ssh_qualified": False,
        "six_machine_qualified": False, "chatgpt_originated": False,
        "installed_runtime_changed": False, "desktop_commander_changed": False,
        "full_dc_replacement_qualified": False,
        "native_to_modern_normalization": "facade preserves native ID/ACK and adds existing serverInfo/resultType metadata",
    }
    controller = None
    facade = None
    token = ""
    current = "prepare exact pinned catalog"

    def save():
        encoded = json.dumps(report, indent=2) + "\n"
        assert not token or token not in encoded
        outfile.write_text(encoded)
        outfile.chmod(0o600)

    def passed(name, details=None):
        report["checks"].append({"check": name, "result": "passed", "detail": details})
        save()
        print("PASS", name, flush=True)

    save()
    try:
        for version, pin in [(5, V5_SHA256), (6, V6_SHA256), (7, V7_SHA256), (8, V8_SHA256)]:
            current = f"reviewed historical V{version} positive control"
            previous_path = ROOT / f"deploy/contracts/hepta-runtime-full-operator-v{version}.json"
            previous = ToolContract.load(previous_path, pin)
            assert len(verify_successor(previous.tools, previous_path)) == 50
            passed(current, {"original_fifty_projection_exact": True})

        current = "pinned V10 contract rejects changed live catalog"
        tampered = copy.deepcopy(reviewed.tools)
        tampered[0]["description"] += " unreviewed wire drift"
        try:
            verify_successor(tampered, path)
        except (ValueError, AssertionError):
            pass
        else:
            raise AssertionError("pinned V10 catalog accepted live definition drift")
        passed(current)

        current = "unknown self-consistent original new-hint owner-input and extra-tool catalogs are refused"
        with tempfile.TemporaryDirectory(prefix="hepta-v9-contract-negative-") as temporary:
            negatives = []
            for name in (
                "original-v4", "new-tool-hint", "new-tool-owner", "extra-tool",
                "v9-start-hint", "v9-start-owner", "v9-cancel-hint", "v9-cancel-owner",
            ):
                tools = copy.deepcopy(reviewed.tools)
                if name == "extra-tool":
                    extra = copy.deepcopy(tools[0])
                    extra["name"] = "unreviewed_fixture_tool"
                    tools.append(extra)
                else:
                    selected_name = (
                        "shell_start" if name == "original-v4" else
                        "request_start" if name.startswith("v9-start-") else
                        "request_cancel" if name.startswith("v9-cancel-") else
                        "request_result"
                    )
                    selected = next(tool for tool in tools if tool["name"] == selected_name)
                    if name == "original-v4":
                        selected["description"] += " unreviewed self-consistent drift"
                    elif name == "new-tool-hint" or name.endswith("-hint"):
                        selected["annotations"]["readOnlyHint"] = not selected["annotations"]["readOnlyHint"]
                    else:
                        selected["inputSchema"]["properties"]["owner"] = {"type": "string"}
                unknown = pathlib.Path(temporary) / (name + ".json")
                unknown.write_text(json.dumps(make_contract(tools), indent=2) + "\n")
                unknown.chmod(0o600)
                try:
                    verify_successor(tools, unknown)
                except (ValueError, AssertionError):
                    negatives.append(name)
                else:
                    raise AssertionError("unreviewed recomputed successor admitted")
        passed(current, {"cases": negatives})

        with tempfile.TemporaryDirectory(prefix="hepta-v9-catalog-") as temporary:
            root = pathlib.Path(temporary).resolve()
            root.chmod(0o700)
            workspace = root / "workspace"
            workspace.mkdir(mode=0o700)
            token = secrets.token_hex(32)
            tokenfile = root / "token"
            tokenfile.write_text(token)
            tokenfile.chmod(0o600)
            cfg = root / "runtime.json"
            cfg.write_text(json.dumps({
                "state_dir": str(root / "state"),
                "controller_workspace_roots": [str(workspace)],
                "hosts": {"disabled-fixture": {
                    "ssh_target": "deliberately-not-contacted.invalid",
                    "platform": "linux", "remote_state_dir": str(root / "unused"),
                    "allow_execute": False, "allow_pty": False, "allow_write": False,
                    "allowed_read_path_prefixes": [str(workspace)],
                    "allowed_write_path_prefixes": [],
                }},
            }))
            cfg.chmod(0o600)
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                port = sock.getsockname()[1]
            url = f"http://127.0.0.1:{port}/mcp"
            with (logdir / "native.log").open("xb") as log:
                controller = subprocess.Popen([
                    str(binary), "mcp", "--path", str(workspace),
                    "--bind", f"127.0.0.1:{port}", "--runtime-config", str(cfg),
                    "--auth-token-file", str(tokenfile),
                ], stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
            (logdir / "native.log").chmod(0o600)
            for _ in range(120):
                if controller.poll() is not None:
                    raise AssertionError("disposable controller exited before ready")
                try:
                    native = Client(url, token)
                    break
                except (OSError, RuntimeError):
                    time.sleep(.1)
            else:
                raise TimeoutError("native controller readiness deadline")

            current = "native V10 exact catalog preserves all62 V9 definitions and adds only four operation definitions"
            tools = native.rpc("tools/list", {})["tools"]
            byname = {tool["name"]: tool for tool in tools}
            v8path = ROOT / "deploy/contracts/hepta-runtime-full-operator-v8.json"
            v8 = ToolContract.load(v8path, V8_SHA256)
            assert len(tools) == len(byname) == 66
            assert set(byname) - set(v8.by_name) == {"request_start", "request_cancel"} | {"operation_start", "operation_status", "operation_result", "operation_cancel"}
            assert all(byname[name] == definition for name, definition in v8.by_name.items())
            v9 = ToolContract.load(ROOT / "deploy/contracts/hepta-runtime-full-operator-v9.json", "3eb628812d0c70b9af8393ecf9d0ce47f69b1438a134148f75ae2dd3132e6761")
            assert all(byname[name] == definition for name, definition in v9.by_name.items())
            assert set(byname) - set(v9.by_name) == {"operation_start", "operation_status", "operation_result", "operation_cancel"}
            reviewed.verify(tools)
            assert len(verify_successor(tools, path)) == 50
            passed(current)

            current = "new lookup schemas refuse owner and advertise accurate read-only hints"
            for name in ("request_status", "request_result"):
                assert byname[name]["annotations"] == {
                    "readOnlyHint": True, "destructiveHint": False,
                    "idempotentHint": True, "openWorldHint": False,
                }
                schema = byname[name]["inputSchema"]
                assert schema["additionalProperties"] is False
                assert "owner" not in schema["properties"]
                assert set(schema["required"]) == {"request_id"}
            assert set(byname["request_status"]["inputSchema"]["properties"]) == {"request_id"}
            assert set(byname["request_result"]["inputSchema"]["properties"]) == {"request_id", "offset", "limit"}
            for name in ("request_start", "request_cancel"):
                assert byname[name]["annotations"] == reviewed.by_name[name]["annotations"]
                assert byname[name]["inputSchema"] == reviewed.by_name[name]["inputSchema"]
                assert byname[name]["inputSchema"]["additionalProperties"] is False
                assert "owner" not in byname[name]["inputSchema"]["properties"]
            assert set(byname["request_start"]["inputSchema"]["properties"]) == {"operation", "idempotency_key"}
            assert set(byname["request_start"]["inputSchema"]["required"]) == {"operation", "idempotency_key"}
            assert set(byname["request_cancel"]["inputSchema"]["properties"]) == {"request_id"}
            assert set(byname["request_cancel"]["inputSchema"]["required"]) == {"request_id"}
            passed(current)

            current = "native host_list server ID ACK and original envelope lookup"
            native_raw = native.rpc("tools/call", {"name": "host_list", "arguments": {}})
            native_id = marker(native_raw, "stored")
            native_data = native_original(native, native_id)
            verify_original(native_raw, native_data)
            status = native.call("request_status", {"request_id": native_id})
            assert status["result_state"] == "stored" and status["dispatch_state"] == "completed"
            passed(current, {"native_original_bytes": len(native_data), "identity_is_server_generated": True})

            current = "legacy native history envelope has no V8 overlay and rejects owner spoof"
            native_history = native.rpc("tools/call", {"name": "request_history", "arguments": {}})
            assert ID_META not in native_history.get("_meta", {})
            assert ACK_META not in native_history.get("_meta", {})
            assert text_result(native_history)["ownership_scope"] == "authenticated_private_operator_credential"
            for name in ("request_history", "request_status", "request_result"):
                params = {} if name == "request_history" else {"request_id": native_id}
                expect_native_denied(native, name, {**params, "owner": "a" * 64})
            for name, params in [
                ("request_start", {
                    "idempotency_key": "native-catalog-owner-spoof",
                    "operation": {"tool": "host_list", "arguments": {}},
                }),
                ("request_cancel", {"request_id": native_id}),
            ]:
                expect_native_denied(native, name, {**params, "owner": "a" * 64})
            passed(current)

            facade = Facade([
                sys.executable, str(ROOT / "deploy/chatgpt_full_operator.py"), "--stdio",
                "--upstream", url, "--token-file", str(tokenfile),
                "--contract", str(path), "--contract-sha256", V9_SHA256,
                "--acknowledge-full-operator",
            ], logdir / "facade.stderr.log")

            current = "modern facade discover and exact V10 catalog"
            discover = facade.rpc("server/discover", {})
            assert "error" not in discover
            assert discover["result"]["resultType"] == "complete"
            assert discover["result"]["cacheScope"] == "private"
            listed = facade.rpc("tools/list", {})
            assert "error" not in listed
            assert listed["result"]["resultType"] == "complete"
            assert listed["result"]["cacheScope"] == "private"
            reviewed.verify(listed["result"]["tools"])
            passed(current, {"modern_protocol": "2026-07-28", "native_catalog_count": 62})

            current = "modern facade preserves dynamic host_list ID ACK status and original result pages"
            host_raw = facade.call("host_list", {}, expected="stored")
            target_id = marker(host_raw, "stored")
            assert target_id != native_id
            status_raw = facade.call("request_status", {"request_id": target_id}, expected="not_retained_policy")
            status = text_result(status_raw)
            assert status["request_id"] == target_id
            assert status["dispatch_state"] == "completed" and status["result_state"] == "stored"
            assembled = bytearray()
            offset = 0
            result_call_id = None
            for _ in range(4096):
                result_raw = facade.call("request_result", {
                    "request_id": target_id, "offset": offset, "limit": 31,
                }, expected="not_retained_policy")
                result_call_id = marker(result_raw, "not_retained_policy")
                page = text_result(result_raw)
                assert page["request_id"] == target_id and page["offset"] == offset
                chunk = base64.b64decode(page["data_base64"], validate=True)
                assert page["next_offset"] == offset + len(chunk)
                assembled.extend(chunk)
                offset = page["next_offset"]
                if page["eof"]:
                    assert offset == page["total_bytes"]
                    assert hashlib.sha256(assembled).hexdigest() == page["result_sha256"]
                    break
                assert chunk
            else:
                raise AssertionError("facade page count exceeded bound")
            verify_original(host_raw, bytes(assembled), facade=True)
            (logdir / "facade.host-list.native-result.json").write_bytes(bytes(assembled))
            passed(current, {
                "captured_server_ID_drives_lookup": True,
                "ID_ACK_and_modern_serverInfo_coexist": True,
                "original_native_bytes_before_ACK": len(assembled),
            })

            current = "modern facade history remains without V8 overlay and lookup responses are not recursively retained"
            history_raw = facade.call("request_history", {"limit": 32})
            assert ID_META not in history_raw.get("_meta", {})
            assert ACK_META not in history_raw.get("_meta", {})
            assert set(history_raw["_meta"]) == {SERVER_INFO}
            assert text_result(history_raw)["credential_metadata_resume"] is True
            assert text_result(history_raw)["authenticated_chatgpt_caller_isolation"] is False
            facade.denied("request_result", {"request_id": result_call_id})
            facade.denied("request_result", {"request_id": marker(status_raw, "not_retained_policy")})
            passed(current, {"existing_modern_serverInfo_metadata_only": True, "recursive_cache": False})

            current = "modern facade refuses owner spoof on history search and new lookups"
            for name, arguments in [
                ("request_history", {"owner": "a" * 64}),
                ("request_status", {"request_id": target_id, "owner": "a" * 64}),
                ("request_result", {"request_id": target_id, "owner": "a" * 64}),
                ("request_start", {
                    "idempotency_key": "facade-catalog-owner-spoof",
                    "operation": {"tool": "host_list", "arguments": {}},
                    "owner": "a" * 64,
                }),
                ("request_cancel", {"request_id": target_id, "owner": "a" * 64}),
                ("search_start", {
                    "host": "disabled-fixture", "root": str(workspace),
                    "query": "fixture", "kind": "files", "owner": "a" * 64,
                }),
            ]:
                facade.denied(name, arguments)
            passed(current, {"configured_host_operations": 0})

            facade.stop()
            for row in facade.rows:
                assert token not in json.dumps(row)
            (logdir / "facade.protocol.json").write_text(json.dumps(facade.rows, indent=2) + "\n")
            controller.terminate()
            controller.wait(timeout=10)
            assert controller.poll() is not None and facade.child.poll() == 0
            assert len(report["checks"]) == 14, "original thirteen checks plus V8 positive control required"
            report["complete"] = True
            report["passed"] = len(report["checks"])
            report["owned_cleanup_confirmed"] = True
            save()
    except BaseException as error:
        detail = str(error).replace(token, "[redacted-test-token]") if token else str(error)
        report["failure"] = {"check": current, "type": type(error).__name__, "detail": detail[:2048]}
        save()
        print("FAIL", current, type(error).__name__, flush=True)
    finally:
        if facade is not None and facade.child.poll() is None:
            facade.stop(graceful=False)
        if controller is not None and controller.poll() is None:
            os.killpg(controller.pid, signal.SIGTERM)
            try:
                controller.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(controller.pid, signal.SIGKILL)
                controller.wait(timeout=5)
        report["logs"] = []
        for logfile in sorted(logdir.iterdir()):
            data = logfile.read_bytes()
            sanitized = data.replace(token.encode(), b"[redacted-test-token]") if token else data
            logfile.write_bytes(sanitized)
            logfile.chmod(0o600)
            report["logs"].append({"name": logfile.name, "sha256": digest(logfile), "bytes": len(sanitized)})
        report["owned_cleanup_confirmed"] = (
            (controller is None or controller.poll() is not None) and
            (facade is None or facade.child.poll() is not None)
        )
        try:
            report["source_after"] = source_identity()
            report["observed_pins_after"] = observed_pins(binary, report["source_after"])
            report["artifact_identity_stable"] = (
                report["observed_pins_after"] == expected_pins
                and report["source_after"] == source_before
                and digest(path) == V9_SHA256
            )
            if not report["artifact_identity_stable"]:
                report["complete"] = False
        except BaseException as error:
            report["complete"] = False
            report["artifact_verification_failure"] = {
                "type": type(error).__name__, "detail": str(error)[:2048],
            }
        save()
    if not report["complete"]:
        raise SystemExit(1)
    print("ALL_PASS", report["passed"], flush=True)


if __name__ == "__main__":
    main()

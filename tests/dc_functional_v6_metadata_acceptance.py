#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Native v6 request metadata/configuration acceptance, never a live cutover.

Uses an isolated controller and throwaway credentials. Six targets receive only
fixed read-only health probes. Transport-invalid/facade-local refusals are outside
this native dispatch history. Cursor deletion simulates retention expiry; actual
retention eviction is separately tested by the request-audit Rust suite.
"""
import argparse
import copy
import hashlib
import json
import os
import pathlib
import secrets
import socket
import stat
import subprocess
import tempfile
import time

from dc_successor_contract import verify_successor
from runtime_http_acceptance import Client

HOSTS = {"main", "pocket4", "rog", "mac", "x230", "ai395"}
PUBLIC_RECORD_KEYS = {"request_id", "tool_name", "state", "accepted_unix_ms", "elapsed_ms"}
PRIVATE_RECORD_KEYS = PUBLIC_RECORD_KEYS | {"owner"}
FORBIDDEN_CONFIG_KEYS = {
    "ssh_target", "state_dir", "remote_state_dir", "controller_workspace_roots",
    "allowed_read_path_prefixes", "allowed_write_path_prefixes", "protected_path_prefixes",
    "privileged_actions", "checkpoint_binary", "checkpoint_binary_sha256",
    "env", "credentials", "token", "raw_config", "policy_hash", "policy_fingerprint",
}
PERMISSIONS = (
    "allow_execute", "allow_pty", "allow_write", "allow_job_network", "allow_detached_fallback",
)


def digest(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def keys(value):
    result = set()
    if isinstance(value, dict):
        result.update(value)
        for child in value.values():
            result.update(keys(child))
    elif isinstance(value, list):
        for child in value:
            result.update(keys(child))
    return result


def history(client, **params):
    value = client.call("request_history", params)
    assert value["session_scope"] == "native_mcp_session_only"
    assert value["cross_session_resume"] is False
    assert value["history_is_live"] is True
    assert value["automatic_operation_retry"] is False
    assert value["retention"] == {"global": 512, "per_session": 128}
    assert not ({"owner", "caller_id", "parameters", "output", "error", "credentials"} & keys(value))
    for record in value["requests"]:
        assert set(record) == PUBLIC_RECORD_KEYS
        assert record["state"] in {"accepted", "completed", "failed", "unknown"}
        assert len(record["request_id"]) == 64
    return value


def expect_denied(client, name, arguments):
    try:
        raw = client.rpc("tools/call", {"name": name, "arguments": arguments})
    except RuntimeError as error:
        payload = error.args[0] if error.args else {}
        assert isinstance(payload, dict) and "code" in payload
        return "jsonrpc_error"
    assert raw.get("isError") is True, "request unexpectedly succeeded"
    return "tool_error"


def start_controller(binary, workspace, token_file, config, root, processes, evidence_dir):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    logfile = evidence_dir / ("native-" + str(len(processes)) + ".log")
    writer = logfile.open("xb")
    logfile.chmod(0o600)
    command = [
        str(binary), "mcp", "--path", str(workspace), "--bind", f"127.0.0.1:{port}",
        "--auth-token-file", str(token_file),
    ]
    if config is not None:
        command += ["--runtime-config", str(config)]
    child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=writer, stderr=writer)
    writer.close()
    processes.append(child)
    for _ in range(120):
        if child.poll() is not None:
            raise RuntimeError("disposable native controller exited before readiness")
        try:
            return Client(f"http://127.0.0.1:{port}/mcp", token_file.read_text().strip())
        except (OSError, RuntimeError):
            time.sleep(.1)
    raise RuntimeError("disposable native controller readiness deadline exceeded")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--contract", required=True)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--runtime-config")
    source.add_argument("--local-fixture", action="store_true")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    binary = pathlib.Path(args.binary).resolve(strict=True)
    contract = pathlib.Path(args.contract).resolve(strict=True)
    outfile = pathlib.Path(args.out)
    if outfile.exists():
        raise ValueError("refusing to overwrite an earlier receipt")
    evidence_dir = outfile.parent / (outfile.stem + "-logs")
    evidence_dir.mkdir(parents=True, mode=0o700, exist_ok=False)
    report = {
        "schema": "hepta-dc-v6-native-metadata-acceptance-v1",
        "origin": "native_python_mcp_client",
        "binary_sha256": digest(binary),
        "contract_sha256": digest(contract),
        "checks": [], "complete": False,
        "installed_service_changed": False, "dc_stopped": False,
        "target_files_changed": False, "model_origin_qualified": False,
        "target_health_probed": False,
        "qualification_scope": "local_metadata_protocol_only" if args.local_fixture else "native_six_host_metadata_and_readonly_health",
        "native_log_directory": str(evidence_dir),
        "native_log_redaction": "throwaway auth token, sentinel inputs, caller metadata and auth/header lines are redacted before delivery",
        "full_dc_replacement_qualified": False,
        "limits": [
            "Only native MCP session scope is qualified; no authenticated ChatGPT caller isolation.",
            "No secure cross-session or service-restart history resume is claimed.",
            "Transport-invalid requests and facade-local refusals do not reach native dispatch audit.",
            "Cursor expiry is safely simulated by deleting one test-owned metadata receipt.",
            "This does not qualify actual audit finish failure during a real side-effecting operation.",
        ],
    }
    token = sentinel = caller = session_spoof = ""
    processes = []
    current = "prepare isolated controller"

    def save():
        outfile.write_text(json.dumps(report, indent=2) + "\n")

    def passed(name, detail=None):
        report["checks"].append({"check": name, "result": "passed", "detail": detail})
        save()
        print("PASS", name, flush=True)

    def safe_error(error):
        value = str(error)
        for private in (token, sentinel, caller, session_spoof):
            if private:
                value = value.replace(private, "[redacted]")
        return value[:4096]

    save()
    try:
        original = None if args.local_fixture else json.loads(pathlib.Path(args.runtime_config).read_text())
        if original is not None:
            assert set(original["hosts"]) == HOSTS
        with tempfile.TemporaryDirectory(prefix="hepta-v6-metadata-") as temporary:
            root = pathlib.Path(temporary).resolve()
            workspace = root / "workspace"
            workspace.mkdir(mode=0o700)
            token = secrets.token_hex(32)
            sentinel = "SECRET_SENTINEL_" + secrets.token_hex(16)
            caller = "CALLER_SPOOF_" + secrets.token_hex(16)
            session_spoof = "SESSION_SPOOF_" + secrets.token_hex(16)
            token_file = root / "token"
            token_file.write_text(token)
            token_file.chmod(0o600)
            state = root / "state"
            config = root / "runtime.json"
            if original is None:
                original = {"hosts": {host: {
                    "ssh_target": "not-probed.invalid",
                    "platform": "macos" if host == "mac" else "linux",
                    "execution_mode": "isolated",
                    "remote_state_dir": str(root / "not-probed" / host),
                    "allow_execute": False, "allow_pty": False, "allow_write": False,
                    "allow_job_network": False, "allow_detached_fallback": False,
                    "allowed_read_path_prefixes": [str(workspace)],
                    "allowed_write_path_prefixes": [],
                } for host in sorted(HOSTS)}}
            cloned = copy.deepcopy(original)
            cloned["state_dir"] = str(state)
            cloned["controller_workspace_roots"] = [str(workspace)]
            config.write_text(json.dumps(cloned))
            config.chmod(0o600)
            client = start_controller(binary, workspace, token_file, config, root, processes, evidence_dir)
            current = "exact reviewed v6 catalog"
            tools = client.rpc("tools/list", {})["tools"]
            verify_successor(tools, contract)
            assert len(tools) == 58
            byname = {tool["name"]: tool for tool in tools}
            assert byname["effective_config"]["annotations"]["readOnlyHint"] is True
            assert byname["request_history"]["annotations"]["readOnlyHint"] is True
            passed(current, {"tools": 58, "old_v4_and_v5_definitions_unchanged": True})

            current = "effective configuration projection"
            projected = client.call("effective_config", {})
            assert projected["schema"] == "hepta-effective-config-v1"
            assert projected["scope"] == "loaded_runtime_policy_capabilities"
            assert projected["policy_mutation_supported"] is False
            assert projected["target_probe_performed"] is False
            assert projected["controller"]["workspace_root_count"] == 1
            assert set(row["alias"] for row in projected["hosts"]) == HOSTS
            assert not (FORBIDDEN_CONFIG_KEYS & keys(projected))
            for row in projected["hosts"]:
                selected = cloned["hosts"][row["alias"]]
                assert row["platform"] == selected.get("platform", "linux")
                assert row["execution_mode"] == selected.get("execution_mode", "isolated")
                assert row["permissions"] == {flag: selected.get(flag, False) for flag in PERMISSIONS}
                assert row["file_api"]["read_root_count"] == len(selected.get("allowed_read_path_prefixes", []))
                assert row["file_api"]["write_root_count"] == len(selected.get("allowed_write_path_prefixes", []))
                assert row["named_privileged_action_count"] == len(selected.get("privileged_actions", {}))
            encoded = json.dumps(projected)
            private_values = [str(root), str(state), str(workspace), token]
            private_values += [host["remote_state_dir"] for host in cloned["hosts"].values()]
            private_values += [host["ssh_target"] for host in cloned["hosts"].values()
                               if host["ssh_target"] not in HOSTS]
            assert all(private not in encoded for private in private_values if len(private) > 1)
            passed(current, {"six_aliases": sorted(HOSTS), "raw_policy_and_private_values_absent": True})

            if args.local_fixture:
                report["health_probe_skip_reason"] = "local protocol fixture; targets are deliberately never contacted"
                save()
            else:
                current = "six-host fixed read-only health probes"
                health = {}
                report["target_health_probed"] = True
                for host in sorted(HOSTS):
                    result = client.call("host_health", {"host": host})
                    assert result["reachable"] is True and result["authenticated"] is True
                    assert result["diagnostics_redacted"] is True
                    health[host] = result["status"]
                passed(current, health)

            current = "secret output and rejection metadata redaction"
            fixture = workspace / "output-fixture.txt"
            fixture.write_text(sentinel + "\n")
            viewed = client.call("view", {"path": str(fixture)})
            assert sentinel in str(viewed)
            assert expect_denied(client, sentinel, {}) == "jsonrpc_error"
            expect_denied(client, "host_health", {"host": "main", sentinel: sentinel})
            expect_denied(client, "effective_config", {"token": sentinel})
            expect_denied(client, "shell_start", {"host": "main"})
            client.rpc("tools/call", {
                "name": "host_list", "arguments": {},
                "_meta": {"caller": caller, "session": session_spoof, "secret": sentinel},
            })
            observed = history(client, limit=32)
            records = observed["requests"]
            states = {(row["tool_name"], row["state"]) for row in records}
            assert ("_unknown_tool", "failed") in states
            assert ("host_health", "failed") in states
            assert ("effective_config", "failed") in states
            assert ("shell_start", "unknown") in states
            assert ("view", "completed") in states
            assert all(private not in json.dumps(observed) for private in (token, sentinel, caller, session_spoof))
            old_ids = {row["request_id"] for row in records}
            passed(current, {
                "unknown_name_redacted": True, "readonly_parameter_refusal_recorded": True,
                "write_parameter_failure_conservatively_unknown": True,
                "output_errors_and_untrusted_meta_not_logged": True,
            })

            current = "independent retained-history pagination and strict limits"
            first = history(client, limit=2)
            replay = history(client, limit=2)
            assert [row["request_id"] for row in first["requests"]] == [row["request_id"] for row in replay["requests"]]
            seen = set()
            page = first
            for _ in range(64):
                page_ids = [row["request_id"] for row in page["requests"]]
                assert len(page_ids) <= 2 and not (seen & set(page_ids))
                seen.update(page_ids)
                cursor = page.get("next_after_id")
                if cursor is None:
                    break
                page = history(client, after_id=cursor, limit=2)
            else:
                raise AssertionError("bounded history pagination did not terminate")
            assert old_ids <= seen
            for invalid in (0, 33):
                expect_denied(client, "request_history", {"limit": invalid})
            expect_denied(client, "request_history", {"owner": "a" * 64})
            passed(current, {"overlapping_page_ids_stable": True, "unique_paged_records": len(seen),
                             "invalid_limits_and_owner_override_denied": True})

            current = "fresh authenticated native session cannot see or use old ownership"
            fresh = Client(client.url, token)
            fresh_view = history(fresh, limit=32)
            assert not (old_ids & {row["request_id"] for row in fresh_view["requests"]})
            expect_denied(fresh, "request_history", {"after_id": first["requests"][0]["request_id"]})
            passed(current, {"same_token_new_session_old_ids_absent": True, "cross_owner_cursor_denied": True})

            current = "simulated retained cursor expiry"
            audit_dir = state / "request-audit"
            expired_id = first["requests"][0]["request_id"]
            expired = audit_dir / (expired_id + ".json")
            assert expired.is_file() and not expired.is_symlink()
            expired.unlink()
            expect_denied(client, "request_history", {"after_id": expired_id})
            passed(current, {"only_disposable_own_record_deleted": True, "expired_cursor_refused": True})

            current = "private physical request metadata contains no payload or private input"
            assert stat.S_IMODE(audit_dir.stat().st_mode) == 0o700
            metadata_count = 0
            for path in audit_dir.iterdir():
                assert path.is_file() and not path.is_symlink()
                info = path.stat()
                assert stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
                raw = path.read_bytes()
                assert len(raw) <= 2048
                data = json.loads(raw)
                assert set(data) == PRIVATE_RECORD_KEYS
                for private in (token, sentinel, caller, session_spoof, "_meta", str(workspace), str(root)):
                    assert private.encode() not in raw
                metadata_count += 1
            passed(current, {"private_records": metadata_count, "directory_mode": "0700", "record_mode": "0600",
                             "payload_paths_credentials_and_meta_absent": True})

            current = "wide audit directory fails before dispatch without publication"
            before = {path.name: digest(path) for path in audit_dir.iterdir()}
            audit_dir.chmod(0o755)
            try:
                expect_denied(client, "effective_config", {})
                after = {path.name: digest(path) for path in audit_dir.iterdir()}
                assert before == after, "pre-intent refusal changed persisted request metadata"
            finally:
                audit_dir.chmod(0o700)
            assert client.call("effective_config", {})["schema"] == "hepta-effective-config-v1"
            passed(current, {"pre_dispatch_refused": True, "record_set_unchanged": True, "safe_permissions_restored": True})

            current = "standalone controller refuses hidden runtime tools"
            standalone = start_controller(binary, workspace, token_file, None, root, processes, evidence_dir)
            standalone_names = {tool["name"] for tool in standalone.rpc("tools/list", {})["tools"]}
            assert "effective_config" not in standalone_names and "request_history" not in standalone_names
            for hidden in ("effective_config", "request_history", "host_health"):
                assert expect_denied(standalone, hidden, {}) == "jsonrpc_error"
            passed(current, {"hidden_runtime_catalog_and_dispatch_consistent": True})
            report["complete"] = True
            report["passed"] = len(report["checks"])
            save()
    except BaseException as error:
        report["failed_check"] = current
        report["failure_exception_type"] = type(error).__name__
        report["failure_message"] = safe_error(error)
        save()
        print("FAIL", current, type(error).__name__, flush=True)
    finally:
        for child in processes:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=10)
        report["native_logs"] = []
        for logfile in sorted(evidence_dir.glob("*.log")):
            raw = logfile.read_bytes()
            sanitized = raw
            for private in (token, sentinel, caller, session_spoof):
                if private:
                    sanitized = sanitized.replace(private.encode(), b"[redacted]")
            lines = []
            for line in sanitized.splitlines(keepends=True):
                lowered = line.lower()
                if any(header in lowered for header in (b"x-hepta-runtime-token", b"authorization:", b"cookie:", b"set-cookie:", b"mcp-session-id", b'"headers"')):
                    lines.append(b"[redacted authentication/header line]\n")
                else:
                    lines.append(line)
            sanitized = b"".join(lines)
            logfile.write_bytes(sanitized)
            logfile.chmod(0o600)
            report["native_logs"].append({
                "path": str(logfile), "bytes": len(sanitized), "sha256": digest(logfile),
                "redacted": sanitized != raw, "raw_diagnostics_preserved_except_private_inputs": True,
            })
        save()
    if not report["complete"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

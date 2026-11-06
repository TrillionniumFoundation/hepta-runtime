#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Real HTTP kill/restart and authorization; generated credentials only."""
import hashlib
import json
import os
import pathlib
import secrets
import selectors
import subprocess
import sys
import tempfile


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def body(client, name="rea_get_evidence_bundle", arguments=None):
    reply = client.rpc("tools/call", {"name": name, "arguments": arguments or {}})
    assert not reply.get("isError"), reply
    return {"content": reply["content"],
            "structured": json.dumps(reply.get("structuredContent"), ensure_ascii=False, separators=(",", ":")),
            "provenance": reply.get("_meta", {}).get("provenance")}


def count(client):
    value = client.call("rea_get_evidence_bundle", {"detail": "summary"})["result"]
    return value["total_retained_records"], value["unknown_revisions"]


def write_sync(path, value):
    with path.open("wb") as output:
        output.write(value)
        output.flush()
        os.fsync(output.fileno())


def stdio_denied(binary, config, root):
    log = (root / "stdio.log").open("wb")
    process = subprocess.Popen([binary, "mcp", "--runtime-config", str(config)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "RUST_LOG": "error"}, cwd=root)
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    def send(message):
        process.stdin.write(json.dumps(message).encode() + b"\n")
        process.stdin.flush()
    def receive(identity):
        for _ in range(20):
            assert selector.select(15), "stdio authority test timed out"
            raw = process.stdout.readline()
            assert raw, "stdio authority test exited before a response"
            message = json.loads(raw)
            if message.get("id") == identity:
                return message["result"]
        raise AssertionError("unexpected stdio notification sequence")
    try:
        send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2026-07-28", "capabilities": {},
            "clientInfo": {"name": "checkpoint-stdio-denial", "version": "1"}}})
        receive(1)
        send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
        for identity, (name, args) in enumerate((
            ("rea_evidence_session_checkpoint", {}),
            ("rea_evidence_session_list", {}),
            ("rea_evidence_session_resume", {"checkpoint_id": "ecp1_" + "a" * 64})), 2):
            send({"jsonrpc": "2.0", "id": identity, "method": "tools/call", "params": {"name": name, "arguments": args}})
            response = receive(identity)
            assert response.get("isError"), response
            assert "stdio" in json.dumps(response).lower(), response
        process.stdin.close()
        process.wait(timeout=15)
        assert process.returncode == 0
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=15)
        selector.close()
        process.stdout.close()
        if not process.stdin.closed:
            process.stdin.close()
        log.close()


def main(binary, tests_path):
    tests = pathlib.Path(tests_path)
    sys.path.insert(0, str(tests))
    # Reuse the already reviewed real HTTP transport and private token fixture.
    # The Rust wrapper invokes Python -B, so importing this helper writes no cache.
    from rea_model_session_http import Client, Server
    fixture = tests / "fixtures/rea_evidence_checkpoint/unknown-verified.json"
    fixture_bytes = fixture.read_bytes()
    assert hashlib.sha256(fixture_bytes).hexdigest() == "97e4e75d4e56c9c7eca22c91a0b0309be475141d22724027e96b3f1049c96215"
    with tempfile.TemporaryDirectory(prefix="hepta-evidence-checkpoint-http-") as scratch:
        root = pathlib.Path(scratch)
        workspace, state, config = root / "workspace", root / "state", root / "policy.json"
        workspace.mkdir(mode=0o700)
        policy = {"state_dir": str(state), "controller_workspace_roots": [str(workspace)],
            "hosts": {"denied": {"ssh_target": "never-connect-checkpoint-test",
                "remote_state_dir": str(root / "no-remote"), "allow_execute": False,
                "allow_pty": False, "allow_write": False, "allow_job_network": False}}}
        config.write_text(json.dumps(policy))
        source = workspace / "unknown-bundle.json"
        source.write_bytes(fixture_bytes)
        apk = workspace / "rotation-v31.apk"
        apk.write_bytes((tests / "fixtures/rea_apk_signature/rotation-v31.apk").read_bytes())
        token_a, token_b = secrets.token_hex(32), secrets.token_hex(32)
        server = None
        process_ids = []
        try:
            server = Server(binary, root, config, token_a)
            process_ids.append(server.process.pid)
            names = {item["name"] for item in server.client.rpc("tools/list", {}).get("tools", [])}
            assert {"rea_evidence_session_checkpoint", "rea_evidence_session_resume", "rea_evidence_session_list"} <= names
            assert count(server.client) == (0, 0)
            assert server.client.call("rea_evidence_session_list", {})["total"] == 0
            try:
                Client(server.port, token_b)
            except RuntimeError as error:
                assert "HTTP 401 during initialize" in str(error), error
            else:
                raise AssertionError("wrong HTTP token initialized a session")
            imported = server.client.call("rea_import_evidence_bundle", {"path": str(source)})
            assert imported["result"] == {"imported": 3, "unknowns_added": 3, "total": 3}
            direct = server.client.call("rea_inspect_apk_signature_evidence", {
                "path": str(apk), "detail": "complete",
                "view": {"kind": "apk-signature", "collection": "signers"}})
            assert direct["operation"] == "inspect_analysis_view"
            parent_id = direct["normalized_result"]["parent_evidence_id"]
            later = server.client.call("rea_inspect_analysis_view", {
                "source": {"kind": "retained-evidence", "evidence_id": parent_id},
                "view": {"kind": "apk-signature", "collection": "signers"}})
            assert direct["evidence_id"] == later["evidence_id"]
            expected_counts = count(server.client)
            assert expected_counts[1] == 3
            original = body(server.client)
            checkpoint = server.client.call("rea_evidence_session_checkpoint", {})
            checkpoint_id = checkpoint["checkpoint_id"]
            assert checkpoint["durability"] == "file_and_directory_sync_confirmed"
            assert checkpoint["automatic_checkpoint"] is False and not checkpoint["reused"]
            again = server.client.call("rea_evidence_session_checkpoint", {})
            assert again["checkpoint_id"] == checkpoint_id and again["reused"]
            server.stop()
            server = None
            source.unlink()
            apk.unlink()

            server = Server(binary, root, config, token_a)
            process_ids.append(server.process.pid)
            assert count(server.client) == (0, 0), "a new server session must stay cold-empty"
            first_page = server.client.call("rea_evidence_session_list", {"limit": 1})
            assert first_page["total"] == 1 and first_page["checkpoints"][0]["checkpoint_id"] == checkpoint_id
            restored = server.client.call("rea_evidence_session_resume", {"checkpoint_id": checkpoint_id})
            assert restored["restored"]
            assert count(server.client) == expected_counts
            assert body(server.client) == original
            server.client.call("rea_evidence_session_resume", {"checkpoint_id": checkpoint_id}, denied=True)
            assert body(server.client) == original
            empty = Client(server.port, token_a)
            assert count(empty) == (0, 0), "same credential must not implicitly load another session"
            empty.call("rea_evidence_session_checkpoint", {})
            server.client.call("rea_evidence_session_list", {"offset": 1, "limit": 1}, denied=True)
            server.client.call("rea_evidence_session_list", {"offset": 1, "limit": 1,
                "expected_catalog_sha256": first_page["catalog_sha256"]}, denied=True)
            fresh = server.client.call("rea_evidence_session_list", {"limit": 1})
            continued = server.client.call("rea_evidence_session_list", {"offset": 1, "limit": 1,
                "expected_catalog_sha256": fresh["catalog_sha256"]})
            assert fresh["total"] == 2 and continued["total"] == 2 and continued["exhausted"]
            assert fresh["checkpoints"][0]["checkpoint_id"] != continued["checkpoints"][0]["checkpoint_id"]
            server.stop()
            server = None

            server = Server(binary, root, config, token_b)
            process_ids.append(server.process.pid)
            assert server.client.call("rea_evidence_session_list", {})["total"] == 0
            server.client.call("rea_evidence_session_resume", {"checkpoint_id": checkpoint_id}, denied=True)
            assert count(server.client) == (0, 0)
            server.stop()
            server = None
            changed = dict(policy)
            changed["controller_workspace_roots"] = []
            config.write_text(json.dumps(changed))
            server = Server(binary, root, config, token_a)
            process_ids.append(server.process.pid)
            assert server.client.call("rea_evidence_session_list", {})["total"] == 0
            server.client.call("rea_evidence_session_resume", {"checkpoint_id": checkpoint_id}, denied=True)
            server.client.call("rea_evidence_session_list", {"offset": 1, "limit": 1,
                "expected_catalog_sha256": fresh["catalog_sha256"]}, denied=True)
            server.stop()
            server = None
            config.write_text(json.dumps(policy))
            server = Server(binary, root, config, token_a)
            process_ids.append(server.process.pid)
            checkpoint_path = state / "rea-evidence-checkpoints-v1" / checkpoint_id
            retention_path, manifest_path = checkpoint_path / "retention.json", checkpoint_path / "manifest.json"
            retention, manifest = retention_path.read_bytes(), manifest_path.read_bytes()
            damaged = b"{}"
            write_sync(retention_path, damaged)
            server.client.call("rea_evidence_session_resume", {"checkpoint_id": checkpoint_id}, denied=True)
            server.client.call("rea_evidence_session_list", {"limit": 1}, denied=True)
            assert count(server.client) == (0, 0)
            rehashed = json.loads(manifest)
            rehashed["retention_sha256"] = hashlib.sha256(damaged).hexdigest()
            rehashed["retention_bytes"] = len(damaged)
            write_sync(manifest_path, canonical(rehashed))
            server.client.call("rea_evidence_session_resume", {"checkpoint_id": checkpoint_id}, denied=True)
            assert count(server.client) == (0, 0)
            write_sync(retention_path, retention)
            write_sync(manifest_path, manifest)
            server.client.call("rea_evidence_session_resume", {"checkpoint_id": checkpoint_id})
            assert body(server.client) == original
            server.stop()
            server = None
            stdio_denied(binary, config, root)
            print("REA_EVIDENCE_CHECKPOINT_HTTP_QUALIFICATION " + json.dumps({
                "fixture_sha256": hashlib.sha256(fixture_bytes).hexdigest(), "checkpoint_id": checkpoint_id,
                "server_process_ids": process_ids, "cold_restart_same_credential": True,
                "default_new_session_empty": True, "explicit_resume_only": True,
                "source_and_apk_absent_on_resume": not source.exists() and not apk.exists(),
                "complete_unknown_history_and_wire_orders_identical": True,
                "same_content_reconciles_same_checkpoint_id": True,
                "different_http_token_refused": True, "different_owner_and_policy_refused": True,
                "nonempty_resume_refused_without_mutation": True,
                "catalog_continuation_binds_complete_set_and_authority": True,
                "damaged_sidecar_and_rehashed_manifest_refused": True,
                "stdio_checkpoint_resume_list_refused": True,
                "production_credentials_used": False, "remote_host_contacted": False,
                "qualified": False}, sort_keys=True), flush=True)
        finally:
            if server is not None:
                server.stop()


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])

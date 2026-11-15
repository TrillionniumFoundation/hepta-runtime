#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Disposable native credential-scope protocol and localhost search acceptance.

Credentials are generated solely for this fixture. Existing tokens, services and
Desktop Commander are never read or changed. SSH fault admission is injected with
a controller-local PATH wrapper; real search uses the pinned localhost SSH path.
Explicit --local-fixture instead accepts only the fixed search-helper source on
a private fixture alias, executes it locally, and never qualifies SSH or health.
"""
from dc_functional_v9_version_pin import add_helper_pins, verify_helper_pins
import argparse, base64, copy, hashlib, json, os, pathlib, re, secrets, select, signal, socket
import subprocess, sys, tempfile, threading, time, urllib.error, urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy"))
from mcp_tool_contract import ToolContract, make_contract
from runtime_http_acceptance import Client
from dc_successor_contract import verify_successor, V9_SHA256

def digest(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

ID_META = "io.hepta.runtime/request-v8"
ACK_META = "io.hepta.runtime/retention-v8"

def source_fingerprint():
    files = [ROOT / "Cargo.toml", ROOT / "Cargo.lock"]
    files += sorted(path for path in (ROOT / "src").rglob("*")
                    if path.is_file() and path.suffix in (".rs", ".py"))
    pins = {str(path.relative_to(ROOT)): {"bytes": path.stat().st_size, "sha256": digest(path)} for path in files}
    return hashlib.sha256(json.dumps(pins, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def recover_cached_native(client, raw, tool_name):
    marker = raw["_meta"][ID_META]; request_id = marker["request_id"]
    assert re.fullmatch("[0-9a-f]{64}", request_id)
    assert marker["automatic_retry"] is False and marker["delivery_proven"] is False
    ack = raw["_meta"][ACK_META]
    assert ack["result_state"] == "stored" and ack["audit_completion_durable"] is True
    status = client.call("request_status", {"request_id": request_id})
    assert status["request_id"] == request_id and status["tool_name"] == tool_name
    assert status["dispatch_state"] == "completed" and status["result_state"] == "stored"
    offset = 0; assembled = bytearray(); pinned = None; pages = 0
    for _ in range(64):
        reply = client.rpc("tools/call", {"name": "request_result", "arguments": {"request_id": request_id, "offset": offset, "limit": 4096}})
        assert not reply.get("isError")
        assert len(json.dumps(reply, ensure_ascii=False, separators=(",", ":")).encode()) <= 65536
        page = json.loads(reply["content"][0]["text"]); pages += 1
        chunk = base64.b64decode(page["data_base64"], validate=True)
        assert page["request_id"] == request_id and page["offset"] == offset
        assert page["automatic_retry"] is False and page["delivery_proven"] is False
        assert page["next_offset"] == offset + len(chunk) and len(assembled) + len(chunk) <= 65536
        assembled.extend(chunk); offset = page["next_offset"]
        if pinned is None: pinned = page["result_sha256"]
        assert page["result_sha256"] == pinned
        if page["eof"]:
            assert offset == page["total_bytes"] and hashlib.sha256(assembled).hexdigest() == pinned
            break
        assert chunk
    else: raise AssertionError("bounded original result paging did not terminate")
    original = copy.deepcopy(raw); original.setdefault("resultType", "complete")
    original["_meta"].pop(ACK_META)
    assert set(original["_meta"]) == {ID_META} and json.loads(assembled) == original
    return {"request_id": request_id, "tool_name": tool_name, "result_sha256": pinned,
            "original_native_bytes": len(assembled), "pages": pages, "automatic_replay": False,
            "boundary": "original_native_result_before_ack_and_transport_normalization"}

def all_history(client):
    rows = []; after = None; seen = set()
    for _ in range(8):
        page = client.call("request_history", {"limit": 32, **({"after_id": after} if after else {})})
        assert page["ownership_scope"] == "authenticated_private_operator_credential"
        assert page["authenticated_chatgpt_caller_isolation"] is False
        for row in page["requests"]:
            assert row["request_id"] not in seen
            seen.add(row["request_id"]); rows.append(row)
        after = page["next_after_id"]
        if after is None: return rows
    raise AssertionError("bounded owned history pagination did not terminate")


def bounded_until(predicate, seconds=15):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(.03)
    raise AssertionError("bounded fixture observation deadline exceeded")

def denied(client, name, params):
    try:
        result = client.rpc("tools/call", {"name": name, "arguments": params})
    except RuntimeError:
        return
    assert result.get("isError") is True, "scoped operation unexpectedly accepted"

def history(client):
    value = client.call("request_history", {"limit": 32})
    assert value["ownership_scope"] == "authenticated_private_operator_credential"
    assert value["cross_session_resume"] is True
    assert value["credential_metadata_resume"] is True
    assert value["authenticated_chatgpt_caller_isolation"] is False
    assert value["retention"] == {"global": 512, "per_owner": 128}
    return value

def raw_status(url, token, sid, method="POST", body=None):
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
               "X-Hepta-Runtime-Token": token, "MCP-Protocol-Version": "2025-06-18"}
    if sid:
        headers["Mcp-Session-Id"] = sid
    request = urllib.request.Request(url, data=body if body is not None else b"{}", headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--expected-binary-sha256", required=True)
    parser.add_argument("--expected-source-fingerprint", "--compiled-source-fingerprint", "--binary-core-fingerprint", dest="expected_source_fingerprint", required=True)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--runtime-config")
    source.add_argument("--local-fixture", action="store_true")
    parser.add_argument("--out", required=True)
    catalog = parser.add_mutually_exclusive_group(required=True)
    catalog.add_argument("--contract")
    catalog.add_argument("--export-contract")
    add_helper_pins(parser)
    args = parser.parse_args()
    verify_helper_pins(args, ROOT)
    binary = pathlib.Path(args.binary).resolve(strict=True)
    for value in (args.expected_binary_sha256, args.expected_source_fingerprint):
        if not re.fullmatch("[0-9a-f]{64}", value):
            raise ValueError("explicit binary SHA256 and compiled source fingerprint required")
    assert digest(binary) == args.expected_binary_sha256, "native artifact differs from explicit expected SHA256"
    assert source_fingerprint() == args.expected_source_fingerprint, "loaded source differs from explicitly fingerprinted artifact"

    if args.contract:
        ToolContract.load(pathlib.Path(args.contract), V9_SHA256)
    outfile = pathlib.Path(args.out)
    assert not outfile.exists(), "never overwrite an earlier evidence receipt"
    outfile.parent.mkdir(parents=True, exist_ok=True)
    logdir = outfile.parent / (outfile.stem + "-logs")
    logdir.mkdir(mode=0o700)
    report = {"schema": "hepta-v9-private-credential-result-metadata-acceptance-v1",
              "origin": "native_python_mcp_client", "binary_sha256": digest(binary),
              "expected_binary_sha256": args.expected_binary_sha256,
              "compiled_source_fingerprint": args.expected_source_fingerprint,
              "observed_source_fingerprint": source_fingerprint(),
              "adapted_from_script": "tests/dc_functional_v7_credential_scope_acceptance.py",
              "adapted_from_script_sha256": "3950cd87925b669f80f0e0bb3d26eb13794a3c1488eb3f2837d1184fac7cb688",
              "original_v7_metadata_search_checks_retained": True,
              "all_v7_definitions_exact": True,
              "real_ssh_cached_readonly_result_qualified": False,
              "checks": [], "complete": False, "dc_stopped": False,
              "installed_service_changed": False, "model_origin_qualified": False,
              "full_dc_replacement_qualified": False,
              "scope": "single_private_operator_credential_metadata_and_bounded_DTO_results_only",
              "target_search": "pinned_controller_local_search_helper_emulator" if args.local_fixture else "disposable_real_localhost_ssh",
              "qualification_scope": "local_native_protocol_fixture_only" if args.local_fixture else "private_native_credential_scope_with_real_localhost_search",
              "target_health_probed": False,
              "six_host_health_qualified": False,
              "real_ssh_search_qualified": False,
              "lost_intent_fault": "controller-local SSH PATH admission stall, not a production target outage",
              "running_process_resume_qualified": False,
              "chatgpt_caller_isolation_qualified": False,
              "process_pty_caller_ownership_qualified": False, 'adapted_from_V8_named_harness': 'tests/dc_functional_v8_credential_scope_acceptance.py', 'adapted_from_V8_harness_sha256': '6c88511d0ef15d5a8d33c976f2aae7baecf544817af46798723e5cdfbd06bf65', 'V9_async_request_start_cancel_qualified_by_this_regression_adapter': False}
    children = []
    token_a = token_b = owner = ""
    def save():
        outfile.write_text(json.dumps(report, indent=2) + "\n")
    def passed(name, detail=None):
        report["checks"].append({"check": name, "result": "passed", "detail": detail})
        save()
        print("PASS", name, flush=True)
    def stop(child, kill=False):
        if child.poll() is None:
            child.kill() if kill else child.terminate()
            child.wait(timeout=10)
    if args.local_fixture:
        report["health_probe_skip_reason"] = "private local fixture; no SSH connection or target health is tested"
    save()
    try:
        with tempfile.TemporaryDirectory(prefix="hepta-v8-credential-scope-") as tmp:
            root = pathlib.Path(tmp).resolve()
            workspace = root / "workspace"; workspace.mkdir(mode=0o700)
            state = root / "state"; remote = root / "remote"
            fixture = workspace / "fixture.txt"; fixture.write_text("scope fixture needle\n")
            token_a = secrets.token_hex(32); token_b = secrets.token_hex(32)
            tokenfile = root / "token"; tokenfile.write_text(token_a); tokenfile.chmod(0o600)
            original = json.loads(pathlib.Path(args.runtime_config).read_text()) if args.runtime_config else {
                "hosts": {"main": {"ssh_target": "fixture-local-only" if args.local_fixture else "localhost", "platform": "linux", "execution_mode": "operator",
                    "allow_execute": False, "allow_write": True, "allow_pty": False,
                    "remote_state_dir": str(remote), "allowed_read_path_prefixes": [str(workspace)],
                    "allowed_write_path_prefixes": [str(workspace)]}}}
            cfg = copy.deepcopy(original)
            cfg["state_dir"] = str(state); cfg["controller_workspace_roots"] = [str(workspace)]
            cfg["hosts"]["main"]["remote_state_dir"] = str(remote)
            cfg["hosts"]["main"]["allowed_read_path_prefixes"] = [str(workspace)]
            cfg["hosts"]["main"]["allowed_write_path_prefixes"] = [str(workspace)]
            cfg["hosts"]["main"]["allow_write"] = True
            config = root / "runtime.json"; config.write_text(json.dumps(cfg)); config.chmod(0o600)
            bindir = root / "bin"; bindir.mkdir()
            gate = root / "stall"; admitted = root / "admitted"; counter = root / "ssh-count"
            wrapper = bindir / "ssh"
            transport = "os.execv('/usr/bin/ssh',['ssh',*sys.argv[1:]])\n"
            if args.local_fixture:
                expected_helper_sha = digest(ROOT / "src/mcp/runtime/search_worker.py")
                transport = (
                    "if len(sys.argv)<3 or sys.argv[-2]!='fixture-local-only':raise SystemExit('fixture alias refused')\n"
                    + "command=shlex.split(sys.argv[-1])\n"
                    + "if len(command)!=3 or command[:2]!=['python3','-c']:raise SystemExit('fixture helper command refused')\n"
                    + "if hashlib.sha256(command[2].encode()).hexdigest()!=" + repr(expected_helper_sha)
                    + ":raise SystemExit('unreviewed fixture helper refused')\n"
                    + "os.execv('/usr/bin/python3',['/usr/bin/python3','-c',command[2]])\n")
            wrapper.write_text("#!/usr/bin/python3\nimport hashlib,os,pathlib,shlex,sys,time\n"
                + "base=pathlib.Path(" + repr(str(root)) + ")\n"
                + "with (base/'ssh-count').open('a') as f:f.write('call\\n')\n"
                + "if (base/'stall').exists():\n"
                + " (base/'admitted').write_text('admitted')\n"
                + " parent=os.getppid();deadline=time.monotonic()+20\n"
                + " while os.getppid()==parent and time.monotonic()<deadline:time.sleep(.02)\n"
                + " raise SystemExit(86)\n"
                + transport)
            wrapper.chmod(0o700)
            env = dict(os.environ); env["PATH"] = str(bindir) + ":" + env.get("PATH", "")
            def start():
                with socket.socket() as sock:
                    sock.bind(("127.0.0.1", 0)); port = sock.getsockname()[1]
                log = logdir / ("native-" + str(len(children)) + ".log")
                with log.open("xb") as writer:
                    log.chmod(0o600)
                    child = subprocess.Popen([str(binary), "mcp", "--path", str(workspace),
                        "--bind", f"127.0.0.1:{port}", "--runtime-config", str(config),
                        "--auth-token-file", str(tokenfile)], env=env, stdin=subprocess.DEVNULL,
                        stdout=writer, stderr=writer)
                children.append(child)
                def ready():
                    if child.poll() is not None:
                        raise AssertionError("disposable native controller exited before readiness")
                    try:
                        return Client(f"http://127.0.0.1:{port}/mcp", tokenfile.read_text())
                    except (OSError, RuntimeError):
                        return None
                return child, bounded_until(ready)
            child, client = start()
            tools = client.rpc("tools/list", {})["tools"]
            baseline_path = ROOT / "deploy/contracts/hepta-runtime-full-operator-v4.json"
            v4 = ToolContract.load(baseline_path, "d36610d575146805f4c02d89210abd360b4d42acc8736d1966f20d0d724704b1")
            actual = {tool["name"]: tool for tool in tools}
            assert all(actual[name] == value for name, value in v4.by_name.items())
            assert len(tools) == 62
            contract_path = pathlib.Path(args.contract or args.export_contract)
            if args.export_contract:
                assert not contract_path.exists()
                contract_path.write_text(json.dumps(make_contract(tools), indent=2, ensure_ascii=False) + "\n")
                contract_path.chmod(0o600)
            contract = ToolContract.load(contract_path, V9_SHA256); contract.verify(tools)
            verify_successor(tools, contract_path)
            report["contract_sha256"] = digest(contract_path)
            passed("v9 exact native contract preserves all sixty V8 predecessor definitions", {"tool_count": 62, "v4_exact": True, "v8_exact": True})
            if args.runtime_config:
                report["target_health_probed"] = True
                health = {}
                for host in sorted(cfg["hosts"]):
                    result = client.call("host_health", {"host": host})
                    assert result["reachable"] is True and result["authenticated"] is True
                    health[host] = result["status"]
                report["six_host_health_qualified"] = set(cfg["hosts"]) == {"main","pocket4","rog","mac","x230","ai395"}
                passed("sequential configured-host authenticated readonly health", health)
            cached = []
            reviewed_dtos = [("host_list", {}), ("effective_config", {})]
            if not args.local_fixture: reviewed_dtos.append(("host_health", {"host": "main"}))
            for name, params in reviewed_dtos:
                raw = client.rpc("tools/call", {"name": name, "arguments": params})
                assert not raw.get("isError")
                if name == "host_health":
                    dto = json.loads(raw["content"][0]["text"])
                    assert dto["reachable"] is True and dto["authenticated"] is True
                cached.append((name, raw, recover_cached_native(client, raw, name)))
            report["cached_readonly_results"] = [item[2] for item in cached]
            report["real_ssh_cached_readonly_result_qualified"] = not args.local_fixture
            passed("reviewed readonly DTO original results recover by exact server IDs",
                   {"methods": [item[0] for item in cached], "real_ssh_health": not args.local_fixture,
                    "replayed_tools": False, "same_verified_credential": True})
            for method in ("POST", "GET", "DELETE"):
                assert raw_status(client.url, token_b, client.session, method) == 401
            passed("stolen session id with another bearer rejected on POST GET DELETE")

            client.call("host_list", {})
            first = history(client)
            ids = {row["request_id"] for row in first["requests"]}
            cursor = first["requests"][0]["request_id"]
            fresh = Client(client.url, token_a)
            assert fresh.session != client.session
            resumed = history(fresh)
            assert ids <= {row["request_id"] for row in resumed["requests"]}
            assert fresh.call("request_history", {"after_id": cursor})["credential_metadata_resume"] is True
            denied(fresh, "request_history", {"owner": "a" * 64})
            passed("same credential reconnect resumes retained history and cursor without owner override")
            for name, raw, prior in cached:
                restored = recover_cached_native(fresh, raw, name)
                assert restored["result_sha256"] == prior["result_sha256"]
            passed("same credential reconnect recovers immutable readonly result snapshots without replay")

            params = {"host": "main", "root": str(workspace), "query": "needle", "kind": "content",
                      "max_results": 10, "max_entries": 100, "max_bytes": 65536, "timeout_seconds": 5}
            launched = client.call("search_start", params)
            search_id = launched["search"]["search_id"]
            assert launched["ownership_scope"] == "authenticated_private_operator_credential"
            def terminal():
                value = fresh.call("search_results", {"search_id": search_id, "limit": 2})
                return value if value.get("snapshot", {}).get("snapshot_ready") is True else None
            terminal_page = bounded_until(terminal)
            assert terminal_page["snapshot"]["results"]
            assert terminal_page["session_resume_after_restart"] is False
            report["real_ssh_search_qualified"] = not args.local_fixture
            passed("pinned local helper fixture snapshot resumes across native sessions" if args.local_fixture else "real localhost SSH search terminal snapshot resumes across native sessions")

            running = client.call("search_start", params)
            interrupted_id = running["search"]["search_id"]
            local_search = state / "search" / (interrupted_id + ".json")
            assert json.loads(local_search.read_text())["state"] == "running"
            auditdir = state / "request-audit"
            owner = json.loads(next(auditdir.glob("*.json")).read_text())["owner"]
            existing = {p.name for p in auditdir.glob("*.json")}
            gate.touch()
            lost = []
            def blocked():
                try: client.call("host_health", {"host": "main"})
                except Exception as error: lost.append(type(error).__name__)
            worker = threading.Thread(target=blocked, daemon=True); worker.start()
            bounded_until(admitted.exists)
            def admitted_record():
                rows = [json.loads(p.read_text()) for p in auditdir.glob("*.json") if p.name not in existing]
                matches = [row for row in rows if row["tool_name"] == "host_health" and row["state"] == "unknown"]
                return matches[0] if matches else None
            unknown = bounded_until(admitted_record)
            old_session = client.session
            stop(child, kill=True); worker.join(timeout=5); assert not worker.is_alive()
            gate.unlink()
            child2, after = start()
            resumed_rows = all_history(after)
            for name, raw, prior in cached:
                restored = recover_cached_native(after, raw, name)
                assert restored["result_sha256"] == prior["result_sha256"]
            saved = next(row for row in resumed_rows if row["request_id"] == unknown["request_id"])
            assert saved["state"] == "unknown"
            before_count = counter.read_text().count("call")
            interrupted = after.call("search_results", {"search_id": interrupted_id})
            assert interrupted["search"]["state"] == "interrupted"
            assert interrupted["search"]["reason"] == "controller_restarted_no_session_resume"
            assert interrupted["unfinished_search_after_controller_restart"] == "interrupted_without_relaunch"
            assert interrupted["metadata_resume_after_restart"] is True
            assert counter.read_text().count("call") == before_count
            assert len(list((remote / "search").glob("[0-9a-f]*"))) == 2
            stable = after.call("search_results", {"search_id": search_id})
            assert stable["snapshot"]["snapshot_ready"] is True
            passed("controller crash retains unknown request and interrupted search without SSH replay",
                   {"unknown_dispatch_retained": True, "launched_search_metadata_interrupted": True,
                    "terminal_snapshot_preserved": True, "interrupted_lookup_remote_calls": 0,
                    "fault_injection": "only the lost host_health intent used local SSH admission stall"})

            # Independently wait for the actual detached worker's bounded terminal receipt.
            target_record = remote / "search" / interrupted_id / "record.json"
            bounded_until(lambda: json.loads(target_record.read_text())["state"] in
                          {"completed", "limited", "cancelled", "failed", "interrupted"}, 15)
            passed("both owned pinned local helper workers reached terminal receipts" if args.local_fixture else "both owned localhost search workers reached terminal receipts")

            # Retained metadata must satisfy the current administrator host and root policy.
            stop(child2)
            def revoke_check(label, revoked_cfg):
                config.write_text(json.dumps(revoked_cfg))
                controller, scoped = start()
                before_calls = counter.read_text().count("call")
                listing = scoped.call("search_list", {"limit": 32})
                assert listing["searches"] == [] and listing["next_after_id"] is None
                for name, sid in [("search_results", search_id), ("search_results", interrupted_id),
                                  ("search_stop", search_id), ("search_stop", interrupted_id)]:
                    raw = scoped.rpc("tools/call", {"name": name, "arguments": {"search_id": sid}})
                    assert raw.get("isError") is True
                    assert str(workspace) not in json.dumps(raw)
                    assert sid not in json.dumps(raw)
                assert counter.read_text().count("call") == before_calls
                assert unknown["request_id"] in {row["request_id"] for row in all_history(scoped)}
                for _, _, item in cached:
                    denied(scoped, "request_status", {"request_id": item["request_id"]})
                    denied(scoped, "request_result", {"request_id": item["request_id"]})
                stop(controller)
                passed(label, {"old_roots_and_ids_not_returned": True, "target_rpc_calls": 0,
                               "path_free_credential_history_preserved": True})
            root_revoked = copy.deepcopy(cfg)
            root_revoked["hosts"]["main"]["allowed_read_path_prefixes"] = []
            revoke_check("same credential restart after read-root revoke hides and refuses retained searches",
                         root_revoked)
            host_revoked = copy.deepcopy(cfg)
            previous_host = host_revoked["hosts"].pop("main")
            if not host_revoked["hosts"]:
                host_revoked["hosts"]["revoked-main"] = previous_host
            revoke_check("same credential restart after host revoke hides and refuses retained searches",
                         host_revoked)
            config.write_text(json.dumps(cfg))
            tokenfile.write_text(token_b); tokenfile.chmod(0o600)
            child3, rotated = start()
            assert raw_status(rotated.url, token_a, old_session) == 401
            body = json.dumps({"jsonrpc": "2.0", "id": 55, "method": "tools/call",
                              "params": {"name": "request_history", "arguments": {}}}).encode()
            assert raw_status(rotated.url, token_b, old_session, body=body) == 404
            spoofed = rotated.rpc("tools/call", {"name": "host_list", "arguments": {},
                                                 "_meta": {"owner": owner, "caller": owner, "session": old_session}})
            assert not spoofed.get("isError")
            new_rows = all_history(rotated)
            assert not ids & {row["request_id"] for row in new_rows}
            assert not {unknown["request_id"]} & {row["request_id"] for row in new_rows}
            denied(rotated, "request_history", {"after_id": cursor})
            for _, _, item in cached:
                denied(rotated, "request_status", {"request_id": item["request_id"]})
                denied(rotated, "request_result", {"request_id": item["request_id"]})
            denied(rotated, "search_results", {"search_id": search_id})
            denied(rotated, "search_stop", {"search_id": interrupted_id})
            passed("credential rotation revokes old bearer session cursors and searches despite metadata spoof")
            encoded = json.dumps(new_rows) + json.dumps(report)
            assert all(value not in encoded for value in (token_a, token_b, owner))
            passed("credential material and internal principal are absent from returned metadata and receipt")
            stop(child3)

            # Stdio remains a distinct random native owner; it has no verified HTTP extension.
            stdio_config = root / "stdio-runtime.json"
            stdio_cfg = copy.deepcopy(cfg); stdio_cfg["state_dir"] = str(root / "stdio-state")
            stdio_config.write_text(json.dumps(stdio_cfg))
            def stdio_history():
                log = logdir / ("stdio-" + str(len(children)) + ".log")
                with log.open("xb") as writer:
                    log.chmod(0o600)
                    proc = subprocess.Popen([str(binary), "mcp", "--path", str(workspace), "--runtime-config",
                        str(stdio_config)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=writer, text=True)
                children.append(proc)
                def rpc(method, params, ident):
                    request = {"jsonrpc": "2.0", "method": method, "params": params}
                    if ident is not None: request["id"] = ident
                    proc.stdin.write(json.dumps(request) + "\n"); proc.stdin.flush()
                    if ident is None: return None
                    assert select.select([proc.stdout], [], [], 15)[0], "stdio fixture response deadline"
                    response = json.loads(proc.stdout.readline())
                    assert "error" not in response
                    return response["result"]
                rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                    "clientInfo": {"name": "credential-scope-stdio", "version": "1"}}, 1)
                rpc("notifications/initialized", {}, None)
                rpc("tools/call", {"name": "host_list", "arguments": {}}, 2)
                raw = rpc("tools/call", {"name": "request_history", "arguments": {}}, 3)
                value = json.loads(raw["content"][0]["text"])
                assert value["ownership_scope"] == "native_mcp_session_only"
                assert value["credential_metadata_resume"] is False and value["cross_session_resume"] is False
                proc.stdin.close(); proc.wait(timeout=10)
                return {row["request_id"] for row in value["requests"]}
            stdio_a = stdio_history(); stdio_b = stdio_history()
            assert stdio_a and stdio_b and not stdio_a & stdio_b
            passed("real stdio restart preserves random-session isolation and refuses metadata-resume claim")
            assert digest(binary) == args.expected_binary_sha256 and source_fingerprint() == args.expected_source_fingerprint
            report["candidate_hashes_stable"] = True
        assert digest(binary) == args.expected_binary_sha256 and source_fingerprint() == args.expected_source_fingerprint
        report["candidate_hashes_stable"] = True
        report["complete"] = True
        report["owned_cleanup_confirmed"] = all(child.poll() is not None for child in children)
        assert report["owned_cleanup_confirmed"]
        report["logs"] = [{"name": p.name, "sha256": digest(p)} for p in sorted(logdir.iterdir())]
        save()
    except Exception as error:
        detail = str(error)
        for value in (token_a, token_b, owner):
            if value: detail = detail.replace(value, "[redacted]")
        report["failure"] = {"type": type(error).__name__, "detail": detail[:2048]}
        save()
        raise
    finally:
        for child in children:
            stop(child)
        for log in logdir.iterdir():
            text = log.read_text(errors="replace")
            for value in (token_a, token_b, owner):
                if value: text = text.replace(value, "[redacted]")
            log.write_text(text)

if __name__ == "__main__":
    main()

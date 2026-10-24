#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""V7 private-credential native search lifecycle on six actual SSH hosts.

Private disposable controller + target roots only. Never stop DC, installed
runtime, business services, PTYs, or external processes. Failed receipts/logs
remain available; no model-origin or complete replacement qualification claim.
HTTP ownership is one verified private operator credential shared by its users.
Stdio's random native-session ownership is covered by the separate V7 credential
scope acceptance; this HTTP matrix does not qualify ChatGPT caller isolation.
"""
import argparse
import concurrent.futures
import datetime
import hashlib
import json
import os
import pathlib
import secrets
import shlex
import socket
import subprocess
import time
import traceback
import uuid
import re
import stat
import sys
import urllib.error
import urllib.request

from dc_parity_release_six_host_acceptance import HOSTS, services
from runtime_http_acceptance import Client
from dc_successor_contract import V7_SHA256
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "deploy"))
from mcp_tool_contract import ToolContract

ROOT = pathlib.Path(__file__).resolve().parents[1]
TERMINAL = {"completed", "limited", "cancelled", "failed", "interrupted"}


def digest(path):
    with pathlib.Path(path).open("rb") as data:
        return hashlib.file_digest(data, "sha256").hexdigest()


def source_identity():
    paths = set(ROOT.glob("src/**/*.rs")) | set(ROOT.glob("src/**/*.py"))
    paths.update([ROOT / "Cargo.toml", ROOT / "Cargo.lock"])
    entries = {}
    for path in sorted(paths, key=lambda item: item.relative_to(ROOT).as_posix()):
        if path.is_symlink() or not path.is_file():
            raise ValueError("source fingerprint requires regular non-symlink files")
        raw = path.read_bytes()
        entries[path.relative_to(ROOT).as_posix()] = {
            "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    canonical = json.dumps(entries, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return {
        "base_HEAD": subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip(),
        "dirty_source": bool(subprocess.check_output(["git", "-C", str(ROOT), "status", "--porcelain",
            "--untracked-files=all", "--", "src", "Cargo.toml", "Cargo.lock"], text=True).strip()),
        "source_fingerprint_algorithm": "sha256(canonical sorted relative path -> byte-count and sha256 map)",
        "source_code_fingerprint": hashlib.sha256(canonical).hexdigest(),
        "source_files": entries}


def helper_identity():
    names = [__file__, ROOT / "tests/runtime_http_acceptance.py",
             ROOT / "tests/dc_parity_release_six_host_acceptance.py",
             ROOT / "tests/dc_successor_contract.py", ROOT / "deploy/mcp_tool_contract.py"]
    return {str(pathlib.Path(path).resolve().relative_to(ROOT)): digest(path) for path in names}


def scope(value):
    assert value["ownership_scope"] == "authenticated_private_operator_credential", value
    assert value["authenticated_chatgpt_caller_isolation"] is False, value
    assert value["credential_metadata_resume"] is True, value
    assert value["metadata_resume_after_restart"] is True, value
    assert value["session_resume_after_restart"] is False, value
    assert value["unfinished_search_after_controller_restart"] == "interrupted_without_relaunch", value
    return value


def deny(client, tool, params, private_root):
    try:
        raw = client.rpc("tools/call", {"name": tool, "arguments": params})
    except RuntimeError as error:
        text = str(error)
    else:
        assert raw.get("isError") is True, (tool, "scoped operation unexpectedly accepted")
        text = "\n".join(item.get("text", "") for item in raw.get("content", []) if item.get("type") == "text")
    assert private_root not in text and "input.txt" not in text, "private search path leaked in refusal"


def old_token_status(url, token, session):
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
               "X-Hepta-Runtime-Token": token, "MCP-Protocol-Version": "2025-06-18",
               "Mcp-Session-Id": session}
    body = json.dumps({"jsonrpc": "2.0", "id": 991, "method": "tools/list", "params": {}}).encode()
    try:
        with urllib.request.urlopen(urllib.request.Request(url, data=body, headers=headers), timeout=5) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code


def test_host(name, target, binary, receipt_dir, contract, expected_binary):
    output = receipt_dir / (name + ".json")
    work = receipt_dir / (name + "-controller")
    work.mkdir(mode=0o700)
    report = {"host": name, "ssh_target": target, "model_origin": False,
              "checks": [], "complete": False, "cross_session_resume_qualified": False,
              "credential_metadata_resume_qualified": False, "running_process_resume_qualified": False,
              "authenticated_chatgpt_caller_isolation": False,
              "stdio_session_isolation_qualified": False, "owned_fixture_cleanup_confirmed": False}
    controller = None
    log = None
    target_dir = "/tmp/hepta-search-v7-native-" + uuid.uuid4().hex
    fixture_created = False
    token = token_a = token_b = ""
    checks_complete = False

    def save():
        encoded = json.dumps(report, indent=2)
        for secret in (token_a, token_b):
            if secret:
                encoded = encoded.replace(secret, "[credential-redacted]")
        output.write_text(encoded + "\n")
        output.chmod(0o600)

    def passed(check, detail=None):
        report["checks"].append({"check": check, "result": "passed", "detail": detail})
        save()

    def ssh_python(code):
        result = subprocess.run(["ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
                                 "-o", "StrictHostKeyChecking=yes", "-o", "ForwardAgent=no", target,
                                 "/usr/bin/python3 -c " + shlex.quote(code)],
                                text=True, capture_output=True, timeout=35)
        if result.returncode:
            raise RuntimeError("SSH fixture operation failed: " + result.stderr)
        return json.loads(result.stdout)

    def terminal(client, identity):
        for _ in range(100):
            value = client.call("search_results", {"search_id": identity, "cursor": 0, "limit": 7})
            if value["search"]["state"] in TERMINAL:
                return value
            time.sleep(0.1)
        raise AssertionError("bounded native search never produced terminal receipt")

    try:
        bootstrap = """import pathlib,os,json,sys
p=pathlib.Path(TARGET);p.mkdir(mode=0o700);p=p.resolve()
(p/'data').mkdir(mode=0o700)
(p/'data'/'input.txt').write_text('needle 中文\\nother\\n' + 'needle row\\n'*40,encoding='utf-8')
(p/'outside').write_text('needle OUTSIDE_SECRET',encoding='utf-8')
(p/'data'/'escape').symlink_to(p/'outside')
os.link(p/'outside',p/'data'/'hardlink')
os.mkfifo(p/'data'/'fifo')
(p/'data'/'binary').write_bytes(b'needle\\0binary')
protected='Protected' if sys.platform=='darwin' else 'protected'
(p/'data'/protected).mkdir()
(p/'data'/protected/'secret').write_text('needle PROTECTED_SECRET')
print(json.dumps({'root':str(p),'uid':os.getuid(),'platform':'linux' if sys.platform=='linux' else 'macos'}))
""".replace("TARGET", repr(target_dir))
        meta = ssh_python(bootstrap)
        target_dir = meta["root"]
        fixture_created = True
        report["target_fixture"] = target_dir
        passed("actual SSH account and private disposable native fixture", meta)
        token = token_a = secrets.token_hex(32)
        token_b = secrets.token_hex(32)
        token_path = work / "token"
        token_path.write_text(token)
        token_path.chmod(0o600)
        (work / "workspace").mkdir()
        host = {"ssh_target": target, "platform": meta["platform"], "remote_state_dir": target_dir + "/state",
                "execution_mode": "isolated", "allow_execute": False, "allow_pty": False,
                "allow_write": False, "allowed_read_path_prefixes": [target_dir + "/data"],
                "protected_path_prefixes": [target_dir + "/data/protected"]}
        config = {"state_dir": str(work / "state"), "controller_workspace_roots": [str(work / "workspace")],
                  "hosts": {name: host}}
        config_path = work / "runtime.json"
        config_path.write_text(json.dumps(config))
        config_path.chmod(0o600)
        with socket.socket() as channel:
            channel.bind(("127.0.0.1", 0))
            port = channel.getsockname()[1]
        url = f"http://127.0.0.1:{port}/mcp"

        def connect():
            for _ in range(80):
                if controller.poll() is not None:
                    raise RuntimeError("isolated test controller exited; see retained log")
                try:
                    return Client(url, token)
                except (OSError, RuntimeError):
                    time.sleep(.1)
            raise RuntimeError("isolated test controller unavailable")

        def stop_controller():
            if controller is not None and controller.poll() is None:
                controller.terminate()
                try:
                    controller.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    controller.kill()
                    controller.wait(timeout=10)
            if log is not None and not log.closed:
                log.close()

        def start_controller():
            nonlocal controller, log
            assert digest(binary) == expected_binary, "candidate binary changed during acceptance"
            log = (work / "controller.log").open("ab")
            controller = subprocess.Popen([str(binary), "mcp", "--path", str(work / "workspace"),
                                           "--bind", f"127.0.0.1:{port}", "--runtime-config", str(work / "runtime.json"),
                                           "--auth-token-file", str(token_path)],
                                          stdin=subprocess.DEVNULL, stdout=log, stderr=log)
            return connect()

        client = start_controller()
        tools = client.rpc("tools/list", {})["tools"]
        contract.verify(tools)
        catalog = {row["name"]: row for row in tools}
        assert {"search_start", "search_results", "search_list", "search_stop"} <= catalog.keys()
        assert catalog["search_results"]["annotations"]["readOnlyHint"]
        assert catalog["search_list"]["annotations"]["readOnlyHint"]
        assert not catalog["search_start"]["annotations"]["readOnlyHint"]
        assert not catalog["search_stop"]["annotations"]["readOnlyHint"]
        passed("actual MCP catalog exactly matches reviewed V7 contract and truthful lifecycle annotations")
        params = {"host": name, "root": target_dir + "/data", "query": "needle", "kind": "content"}
        started = scope(client.call("search_start", params))
        assert not started.get("launch_uncertain"), started
        identity = started["search"]["search_id"]
        result = scope(terminal(client, identity))
        assert result["search"]["state"] == "completed", result
        page = result["snapshot"]
        stats = page["statistics"]
        assert stats["results"] == 41 and stats["skipped_symlinks"] == 1 and stats["skipped_hardlinks"] == 1
        assert stats["skipped_special"] == 1 and stats["skipped_protected"] == 1
        assert stats["skipped_binary_or_non_utf8"] == 1
        assert all(row["path"] == "input.txt" for row in page["results"])
        assert "OUTSIDE_SECRET" not in json.dumps(result) and "PROTECTED_SECRET" not in json.dumps(result)
        passed("native Unicode content results, authorized roots and symlink/hardlink/FIFO/protected refusal", stats)
        second = client.call("search_results", {"search_id": identity, "cursor": page["next_cursor"], "limit": 7})
        assert second["snapshot"]["results"][0]["line"] > page["results"][-1]["line"]
        assert client.call("search_results", {"search_id": identity, "cursor": 0, "limit": 7}) == result
        ssh_python("import pathlib,json;pathlib.Path(" + repr(target_dir + "/data/input.txt") + ").write_text('changed');print('{}')")
        assert client.call("search_results", {"search_id": identity, "cursor": 0, "limit": 7}) == result
        passed("independent cursors and immutable terminal pages after original file changes")
        other = Client(url, token)
        assert other.session != client.session
        assert scope(other.call("search_results", {"search_id": identity, "cursor": 0, "limit": 7})) == result
        stop_terminal = scope(other.call("search_stop", {"search_id": identity}))
        assert stop_terminal["stop_requested"] is False and stop_terminal["already_terminal"] is True
        assert {r["search_id"] for r in scope(other.call("search_list", {}))["searches"]} == {identity}
        assert {r["search_id"] for r in scope(client.call("search_list", {}))["searches"]} == {identity}
        passed("same verified credential shares immutable pages and metadata across distinct HTTP sessions",
               {"scope": "single_private_operator_credential", "chatgpt_caller_isolation": False})
        client.call("search_start", {**params, "root": target_dir + "/outside"}, denied=True)
        client.call("search_start", {**params, "owner": "spoof"}, denied=True)
        client.call("search_start", {**params, "max_results": 1001}, denied=True)
        files = client.call("search_start", {**params, "query": "input", "kind": "files"})
        files = terminal(client, files["search"]["search_id"])
        assert files["snapshot"]["results"] == [{"path": "input.txt"}]
        passed("literal native file-name search and caller owner/resource/outside-root denial")
        abandoned=Client(url,token)
        unpolled=[]
        for _ in range(4):
            row=abandoned.call("search_start",{**params,"kind":"files","query":"input"})
            unpolled.append(row["search"]["search_id"])
        time.sleep(.2)
        fresh=Client(url,token)
        replacement=fresh.call("search_start",{**params,"kind":"files","query":"input"})
        replacement_id=replacement["search"]["search_id"]
        assert terminal(fresh,replacement_id)["search"]["state"]=="completed"
        expected_ids = {identity, files["search"]["search_id"], replacement_id, *unpolled}
        assert {row["search_id"] for row in scope(fresh.call("search_list",{}))["searches"]} == expected_ids
        assert all(json.loads((work/"state/search"/(old+".json")).read_text())["state"]=="completed" for old in unpolled)
        passed("same-credential unpolled searches reconcile without quota denial and retain credential-scoped metadata")
        ssh_python("import pathlib,json;pathlib.Path(" + repr(target_dir + "/data/slow.txt") + ").write_bytes(b'x\\n'*(2*1024*1024));print('{}')")
        slow = client.call("search_start", {**params, "query": "never-present", "timeout_seconds": 30})
        slow_id = slow["search"]["search_id"]
        stop = client.call("search_stop", {"search_id": slow_id})
        assert stop["native"]["stop_requested"], stop
        stopped = terminal(client, slow_id)
        assert stopped["search"]["state"] == "cancelled", stopped
        assert client.call("search_results", {"search_id": slow_id, "cursor": 0, "limit": 7}) == stopped
        passed("real credential-owned stop produces durable cancelled immutable snapshot without external PID signals")
        interrupted = client.call("search_start", {**params, "query": "never-present", "timeout_seconds": 30})
        interrupted_id = interrupted["search"]["search_id"]
        assert not interrupted.get("launch_uncertain"), interrupted
        assert interrupted["search"]["state"] not in TERMINAL, "restart fixture was already terminal"
        before_ids = {p.name for p in (work / "state/search").glob("*.json")}
        stop_controller()
        client = start_controller()
        assert scope(client.call("search_results", {"search_id": identity, "cursor": 0, "limit": 7})) == result
        recovered = scope(client.call("search_results", {"search_id": interrupted_id, "cursor": 0, "limit": 7}))
        assert recovered["search"]["state"] == "interrupted" and recovered["snapshot_ready"] is False
        assert recovered["results"] == [] and recovered["next_cursor"] is None
        stopped_after_restart = scope(client.call("search_stop", {"search_id": interrupted_id}))
        assert stopped_after_restart["stop_requested"] is False and stopped_after_restart["already_terminal"] is True
        persisted = json.loads((work / "state/search" / (interrupted_id + ".json")).read_text())
        assert persisted["state"] == "interrupted"
        assert persisted["reason"] == "controller_restarted_no_session_resume"
        listed = {row["search_id"] for row in scope(client.call("search_list", {}))["searches"]}
        assert identity in listed and interrupted_id in listed
        assert {p.name for p in (work / "state/search").glob("*.json")} == before_ids
        passed("same credential resumes terminal pages after controller restart; unfinished metadata is interrupted without relaunch")

        old_session = client.session
        stop_controller()
        token = token_b
        token_path.write_text(token); token_path.chmod(0o600)
        rotated = start_controller()
        assert old_token_status(url, token_a, old_session) == 401
        for old_id in (identity, interrupted_id):
            for tool in ("search_results", "search_stop"):
                deny(rotated, tool, {"search_id": old_id}, target_dir)
        assert scope(rotated.call("search_list", {}))["searches"] == []
        passed("rotated credential refuses old credential searches and bearer; private root does not leak")

        stop_controller()
        token = token_a
        token_path.write_text(token); token_path.chmod(0o600)
        client = start_controller()
        assert scope(client.call("search_results", {"search_id": identity, "cursor": 0, "limit": 7})) == result
        passed("restored original test credential resumes its original retained terminal metadata")

        stop_controller()
        host["allowed_read_path_prefixes"] = []
        config_path.write_text(json.dumps(config))
        revoked = start_controller()
        for old_id in (identity, interrupted_id):
            for tool in ("search_results", "search_stop"):
                deny(revoked, tool, {"search_id": old_id}, target_dir)
        assert scope(revoked.call("search_list", {}))["searches"] == []
        passed("current read-root revocation refuses old receipt access and omits revoked metadata")

        stop_controller()
        host["allowed_read_path_prefixes"] = [target_dir + "/data"]
        config_path.write_text(json.dumps(config))
        client = start_controller()
        assert scope(client.call("search_results", {"search_id": identity, "cursor": 0, "limit": 7})) == result
        assert scope(client.call("search_results", {"search_id": interrupted_id}))["search"]["state"] == "interrupted"
        passed("restored private fixture policy resumes immutable pages without reexecuting interrupted search")
        report["credential_metadata_resume_qualified"] = True
        checks_complete = True
    except BaseException as error:
        report["failure"] = str(error)
        report["traceback"] = traceback.format_exc()
    finally:
        try:
            if controller is not None and controller.poll() is None:
                controller.terminate()
                try:
                    controller.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    controller.kill(); controller.wait(timeout=10)
            if log is not None and not log.closed:
                log.close()
            report["disposable_controller_stopped"] = controller is None or controller.poll() is not None
            (work / "token").unlink(missing_ok=True)
            if (work / "controller.log").exists():
                log_path = work / "controller.log"
                raw = log_path.read_bytes()
                for secret in (token_a, token_b):
                    if secret:
                        raw = raw.replace(secret.encode(), b"[credential-redacted]")
                log_path.write_bytes(raw); log_path.chmod(0o600)
                report["controller_log_sha256"] = digest(log_path)
            if fixture_created:
                bindings = {}
                for path in (work / "state/search").glob("*.json"):
                    if path.is_symlink() or not path.is_file():
                        raise AssertionError("cleanup refuses non-ordinary controller search receipt")
                    record = json.loads(path.read_text())
                    identity = path.stem
                    assert re.fullmatch("[0-9a-f]{64}", identity) and record["id"] == identity
                    assert record["host"] == name and record["ssh_target"] == target
                    assert record["remote_state_dir"] == target_dir + "/state"
                    assert re.fullmatch("[0-9a-f]{64}", record["owner"])
                    bindings[identity] = record["owner"]
                cleanup = """
import hashlib,json,os,pathlib,re,shutil,stat,time
p=pathlib.Path(FIXTURE);bindings=BINDINGS;remove=REMOVE
assert p.name.startswith('hepta-search-v7-native-') and re.fullmatch('hepta-search-v7-native-[0-9a-f]{32}',p.name)
st=p.lstat();assert stat.S_ISDIR(st.st_mode) and st.st_uid==os.getuid() and st.st_mode&0o077==0
base=p/'state'/'search'
def regular(path):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 with os.fdopen(fd,'rb') as f:
  info=os.fstat(f.fileno())
  assert stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and info.st_nlink==1 and info.st_mode&0o077==0
  raw=f.read(131073);assert len(raw)<=131072
 return raw
def records():
 rows={}
 if not base.exists():return rows
 info=base.lstat();assert stat.S_ISDIR(info.st_mode) and info.st_uid==os.getuid() and info.st_mode&0o077==0
 for path in base.iterdir():
  if path.name.startswith('.'):continue
  assert path.name in bindings,'unbound target search; retained'
  info=path.lstat();assert stat.S_ISDIR(info.st_mode) and info.st_uid==os.getuid() and info.st_mode&0o077==0
  row=json.loads(regular(path/'record.json'));assert row['owner']==bindings[path.name]
  rows[path.name]=row
 return rows
rows=records()
for identity,row in rows.items():
 if row['state'] not in TERMINAL:
  path=base/identity/'cancel'
  try:fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  except FileExistsError:regular(path)
  else:os.fsync(fd);os.close(fd)
deadline=time.monotonic()+20
while any(row['state'] not in TERMINAL for row in rows.values()) and time.monotonic()<deadline:
 time.sleep(.1);rows=records()
terminal=all(row['state'] in TERMINAL for row in rows.values())
receipt={'mechanism':'owned_fixture_cooperative_cancel_then_terminal_receipts','known_searches':len(bindings),
 'target_searches':len(rows),'terminal_worker_receipts_confirmed':terminal,'process_exit_confirmed':False,
 'fixture_retained':True,'deleted':False,
 'target_record_sha256':{identity:hashlib.sha256(regular(base/identity/'record.json')).hexdigest() for identity in rows}}
if terminal and remove:
 shutil.rmtree(p);receipt.update(fixture_retained=False,deleted=True)
print(json.dumps(receipt))
""".replace("FIXTURE", repr(target_dir)).replace("BINDINGS", repr(bindings)).replace("REMOVE", repr(checks_complete)).replace("TERMINAL", repr(TERMINAL))
                report["owned_fixture_cleanup"] = ssh_python(cleanup)
                report["owned_fixture_cleanup_confirmed"] = report["owned_fixture_cleanup"]["deleted"]
            report["complete"] = checks_complete and report["owned_fixture_cleanup_confirmed"] and report["disposable_controller_stopped"]
        except BaseException as cleanup_error:
            report["complete"] = False
            report["cleanup_failure"] = {"type": type(cleanup_error).__name__, "detail": str(cleanup_error)}
            report["target_fixture_retained"] = True
        report["passed"] = len(report["checks"])
        save()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--contract", required=True)
    parser.add_argument("--expected-binary-sha256", required=True)
    parser.add_argument("--expected-source-fingerprint", required=True)
    parser.add_argument("--receipt-dir", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--host", choices=[row[0] for row in HOSTS])
    parser.add_argument("--max-workers", type=int, choices=(1, 2), default=1)
    args = parser.parse_args()
    for value in (args.expected_binary_sha256, args.expected_source_fingerprint):
        if re.fullmatch("[0-9a-f]{64}", value) is None:
            raise ValueError("explicit lowercase SHA256 required")
    binary = pathlib.Path(args.binary).resolve(strict=True)
    assert digest(binary) == args.expected_binary_sha256, "candidate binary differs from expected release"
    contract_path = pathlib.Path(args.contract).resolve(strict=True)
    contract = ToolContract.load(contract_path, V7_SHA256)
    before_source = source_identity()
    assert before_source["source_code_fingerprint"] == args.expected_source_fingerprint, "candidate source differs from expected release"
    before_helpers = helper_identity()
    outfile = pathlib.Path(args.out).resolve()
    assert not outfile.exists(), "never overwrite prior receipt"
    directory = pathlib.Path(args.receipt_dir).resolve()
    directory.mkdir(parents=True, mode=0o700, exist_ok=False)
    outfile.parent.mkdir(parents=True, exist_ok=True)
    baseline = services()
    if any(row.get("ActiveState") != "active" or row.get("MainPID") == "0" for row in baseline.values()):
        raise RuntimeError("protective installed runtime/DC services must remain active")
    report = {
        "schema": "hepta-private-credential-search-six-native-hosts-v7",
        "recorded_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "binary_sha256": digest(binary), "expected_binary_sha256": args.expected_binary_sha256,
        "expected_source_fingerprint": args.expected_source_fingerprint,
        "source_before": before_source, "helpers_before": before_helpers,
        "reviewed_contract_file_sha256": V7_SHA256, "contract_catalog_sha256": contract.catalog_sha256,
        "origin": "native_python_authenticated_mcp_client", "model_origin": False,
        "ownership_scope": "single_verified_private_operator_credential_shared_by_its_users",
        "installed_runtime_or_DC_restarted": False,
        "cross_session_resume_qualified": False, "credential_metadata_resume_qualified": False,
        "running_process_resume_qualified": False, "chatgpt_caller_isolation_qualified": False,
        "stdio_session_isolation_qualified": False, "full_dc_replacement_qualified": False,
        "protected_services_before": baseline, "results": [], "complete": False,
        "selected_complete": False, "max_workers": args.max_workers}
    selected = [row for row in HOSTS if not args.host or row[0] == args.host]
    report["selected_hosts"] = [row[0] for row in selected]
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.max_workers) as executor:
            futures = [executor.submit(test_host, name, target, binary, directory, contract,
                                       args.expected_binary_sha256) for name, target in selected]
            for future in concurrent.futures.as_completed(futures):
                row = future.result()
                report["results"].append(row)
                print("TARGET", row["host"], "complete", row["complete"], "checks", row.get("passed"), flush=True)
    except BaseException as error:
        report["failure"] = {"type": type(error).__name__, "detail": str(error)}
    finally:
        try:
            report["protected_services_after"] = services()
            report["service_identity_stable"] = report["protected_services_after"] == baseline
            report["binary_sha256_after"] = digest(binary)
            report["source_after"] = source_identity()
            report["helpers_after"] = helper_identity()
            report["artifact_identity_stable"] = (
                report["binary_sha256_after"] == args.expected_binary_sha256
                and report["source_after"] == before_source
                and report["helpers_after"] == before_helpers
                and digest(contract_path) == V7_SHA256)
            report["selected_complete"] = (
                len(report["results"]) == len(selected)
                and all(row["complete"] for row in report["results"])
                and report["service_identity_stable"] and report["artifact_identity_stable"])
            report["complete"] = report["selected_complete"] and len(selected) == len(HOSTS)
            report["credential_metadata_resume_qualified"] = (
                report["complete"] and all(row["credential_metadata_resume_qualified"] for row in report["results"]))
        except BaseException as error:
            report["verification_failure"] = {"type": type(error).__name__, "detail": str(error)}
        with outfile.open("x") as handle:
            handle.write(json.dumps(report, indent=2) + "\n")
        outfile.chmod(0o600)
    if not report["selected_complete"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

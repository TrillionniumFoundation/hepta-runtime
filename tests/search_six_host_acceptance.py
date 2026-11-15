#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Authenticated native candidate search lifecycle on six actual SSH hosts.

Private disposable controller + target roots only. Never stop DC, installed
runtime, business services, PTYs, or external processes. Failed receipts/logs
remain available; no model-origin or complete replacement qualification claim.
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

from dc_parity_release_six_host_acceptance import HOSTS, services
from runtime_http_acceptance import Client

ROOT = pathlib.Path(__file__).resolve().parents[1]
TERMINAL = {"completed", "limited", "cancelled", "failed", "interrupted"}


def digest(path):
    with pathlib.Path(path).open("rb") as data:
        return hashlib.file_digest(data, "sha256").hexdigest()


def test_host(name, target, binary, receipt_dir):
    output = receipt_dir / (name + ".json")
    work = receipt_dir / (name + "-controller")
    work.mkdir(mode=0o700)
    report = {"host": name, "ssh_target": target, "model_origin": False,
              "checks": [], "complete": False, "cross_session_resume_qualified": False}
    controller = None
    log = None
    target_dir = "/tmp/hepta-search-native-" + uuid.uuid4().hex

    def save():
        output.write_text(json.dumps(report, indent=2) + "\n")

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
        report["target_fixture"] = target_dir
        passed("actual SSH account and private disposable native fixture", meta)
        token = secrets.token_hex(32)
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
        (work / "runtime.json").write_text(json.dumps(config))
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

        def start_controller():
            nonlocal controller, log
            log = (work / "controller.log").open("ab")
            controller = subprocess.Popen([str(binary), "mcp", "--path", str(work / "workspace"),
                                           "--bind", f"127.0.0.1:{port}", "--runtime-config", str(work / "runtime.json"),
                                           "--auth-token-file", str(token_path)],
                                          stdin=subprocess.DEVNULL, stdout=log, stderr=log)
            return connect()

        client = start_controller()
        catalog = {row["name"]: row for row in client.rpc("tools/list", {})["tools"]}
        assert {"search_start", "search_results", "search_list", "search_stop"} <= catalog.keys()
        assert catalog["search_results"]["annotations"]["readOnlyHint"]
        assert catalog["search_list"]["annotations"]["readOnlyHint"]
        assert not catalog["search_start"]["annotations"]["readOnlyHint"]
        assert not catalog["search_stop"]["annotations"]["readOnlyHint"]
        passed("authenticated MCP exposes truthful search lifecycle annotations")
        params = {"host": name, "root": target_dir + "/data", "query": "needle", "kind": "content"}
        started = client.call("search_start", params)
        assert not started.get("launch_uncertain"), started
        identity = started["search"]["search_id"]
        result = terminal(client, identity)
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
        for tool in ("search_results", "search_stop"):
            denied = other.call(tool, {"search_id": identity}, denied=True)
            assert target_dir not in denied and "input.txt" not in denied
        assert other.call("search_list", {})["searches"] == []
        assert {r["search_id"] for r in client.call("search_list", {})["searches"]} == {identity}
        passed("same-auth-token distinct MCP session cannot list/read/stop another search or leak root")
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
        assert {row["search_id"] for row in fresh.call("search_list",{})["searches"]}=={replacement_id}
        assert all(json.loads((work/"state/search"/(old+".json")).read_text())["state"]=="completed" for old in unpolled)
        passed("abandoned native sessions' unpolled completed searches are internally reconciled without quota denial or metadata exposure")
        ssh_python("import pathlib,json;pathlib.Path(" + repr(target_dir + "/data/slow.txt") + ").write_bytes(b'x\\n'*(2*1024*1024));print('{}')")
        slow = client.call("search_start", {**params, "query": "never-present", "timeout_seconds": 30})
        slow_id = slow["search"]["search_id"]
        stop = client.call("search_stop", {"search_id": slow_id})
        assert stop["native"]["stop_requested"], stop
        stopped = terminal(client, slow_id)
        assert stopped["search"]["state"] == "cancelled", stopped
        assert client.call("search_results", {"search_id": slow_id, "cursor": 0, "limit": 7}) == stopped
        passed("real owner-only stop produces durable cancelled immutable snapshot without external PID signals")
        interrupted = client.call("search_start", {**params, "query": "never-present", "timeout_seconds": 30})
        interrupted_id = interrupted["search"]["search_id"]
        controller.terminate()
        controller.wait(timeout=10)
        log.close()
        client = start_controller()
        client.call("search_results", {"search_id": interrupted_id}, denied=True)
        client.call("search_stop", {"search_id": interrupted_id}, denied=True)
        assert client.call("search_list", {})["searches"] == []
        persisted = json.loads((work / "state/search" / (interrupted_id + ".json")).read_text())
        assert persisted["state"] == "interrupted"
        assert persisted["reason"] == "controller_restarted_no_session_resume"
        passed("actual disposable controller restart persists interrupted receipt and denies new-session resume")
        report["passed"] = len(report["checks"])
        report["complete"] = True
    except BaseException as error:
        report["failure"] = str(error)
        report["traceback"] = traceback.format_exc()
    finally:
        if controller is not None and controller.poll() is None:
            controller.terminate()
            controller.wait(timeout=10)
        if log is not None and not log.closed:
            log.close()
        (work / "token").unlink(missing_ok=True)
        if (work / "controller.log").exists():
            report["controller_log_sha256"] = digest(work / "controller.log")
        save()
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--receipt-dir", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--host", choices=[row[0] for row in HOSTS])
    args = parser.parse_args()
    binary = pathlib.Path(args.binary).resolve(strict=True)
    directory = pathlib.Path(args.receipt_dir).resolve()
    directory.mkdir(parents=True, mode=0o700, exist_ok=False)
    baseline = services()
    if any(row.get("ActiveState") != "active" or row.get("MainPID") == "0" for row in baseline.values()):
        raise RuntimeError("protective installed runtime/DC services must remain active")
    report = {"schema": "hepta-search-six-native-hosts-v1", "recorded_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "binary_sha256": digest(binary), "source_head": subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip(),
              "model_origin": False, "installed_runtime_or_DC_restarted": False, "cross_session_resume_qualified": False,
              "full_dc_replacement_qualified": False, "protected_services_before": baseline, "results": [], "complete": False}
    selected = [row for row in HOSTS if not args.host or row[0] == args.host]
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(test_host, name, target, binary, directory) for name, target in selected]
            for future in concurrent.futures.as_completed(futures):
                row = future.result()
                report["results"].append(row)
                print("TARGET", row["host"], "complete", row["complete"], "checks", row.get("passed"), flush=True)
    finally:
        report["protected_services_after"] = services()
        report["service_identity_stable"] = report["protected_services_after"] == baseline
        report["complete"] = len(report["results"]) == len(selected) and all(row["complete"] for row in report["results"]) and report["service_identity_stable"]
        with pathlib.Path(args.out).open("x") as handle:
            handle.write(json.dumps(report, indent=2) + "\n")
    if not report["complete"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

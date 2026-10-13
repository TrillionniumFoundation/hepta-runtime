#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Owned temporary-controller v6 -> installed-v4 artifact -> v6 rollback.

Never stop/restart/configure a production service, refresh ChatGPT tools, stop
Desktop Commander, or touch a business workload. The installed artifact is read
through its pinned /proc executable descriptor and copied to a new private file.
This proves temporary-controller format/interoperability only: no production
rollback, ChatGPT caller ownership, business replacement or DC-off qualification.
"""
import argparse
import hashlib
import json
import os
import pathlib
import re
import secrets
import shlex
import socket
import stat
import subprocess
import time
import traceback

from dc_parity_release_six_host_acceptance import services
from dc_functional_v6_operator_six_host_acceptance import source_identity
from runtime_http_acceptance import Client

ROOT = pathlib.Path(__file__).resolve().parents[1]
PRODUCTION_UNIT = "hepta-runtime-operator.service"
OLD_SHA256 = "db181570e9e65f9e6a962d013dd4880eedc5b0cda1c71508f84388a4a8d8072b"
HOST = "main"
SSH_TARGET = "localhost"


def sha256(path):
    with pathlib.Path(path).open("rb") as reader:
        return hashlib.file_digest(reader, "sha256").hexdigest()


def process_identity(pid):
    value = pathlib.Path(f"/proc/{pid}/stat").read_text()
    fields = value.rsplit(") ", 1)[1].split()
    return {"pid": pid, "start_ticks": int(fields[19]), "uid": pathlib.Path(f"/proc/{pid}").stat().st_uid}


def capture_production_pin(baseline):
    """Pin the already installed unit once; never follow a new/candidate PID."""
    fields = dict(baseline[PRODUCTION_UNIT])
    raw_pid = fields.get("MainPID", "0")
    if fields.get("ActiveState") != "active" or not raw_pid.isdigit() or int(raw_pid) <= 0:
        raise RuntimeError("installed production unit is not active with a valid PID")
    identity = process_identity(int(raw_pid))
    if identity["uid"] != os.getuid():
        raise RuntimeError("installed user-unit process owner differs from operator UID")
    pin = {"unit": PRODUCTION_UNIT, "service_fields": fields, "identity": identity}
    verify_production_pin(pin)
    return pin


def verify_production_pin(pin):
    if pin["unit"] != PRODUCTION_UNIT:
        raise RuntimeError("production artifact may only use the installed unit")
    if services()[PRODUCTION_UNIT] != pin["service_fields"]:
        raise RuntimeError("installed production unit/PID changed; refusing to follow another process")
    if process_identity(pin["identity"]["pid"]) != pin["identity"]:
        raise RuntimeError("pinned production process start identity or owner changed")


def copy_installed_artifact(destination, production_pin):
    verify_production_pin(production_pin)
    before = production_pin["identity"]
    reference = pathlib.Path(f"/proc/{before['pid']}/exe")
    source_path = os.readlink(reference)
    source = os.open(reference, os.O_RDONLY | os.O_CLOEXEC)
    output = None
    try:
        inode = os.fstat(source)
        if not stat.S_ISREG(inode.st_mode):
            raise RuntimeError("pinned production executable is not an ordinary artifact")
        output = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        digest = hashlib.sha256()
        while True:
            part = os.read(source, 1024 * 1024)
            if not part:
                break
            digest.update(part)
            view = memoryview(part)
            while view:
                count = os.write(output, view)
                if count <= 0:
                    raise RuntimeError("private rollback artifact copy did not progress")
                view = view[count:]
        os.fsync(output)
        os.fchmod(output, 0o700)
        after_inode = os.fstat(source)
        if (inode.st_dev, inode.st_ino, inode.st_size, inode.st_mtime_ns) != (after_inode.st_dev, after_inode.st_ino, after_inode.st_size, after_inode.st_mtime_ns):
            raise RuntimeError("production executable descriptor changed while reading")
        if digest.hexdigest() != OLD_SHA256 or sha256(destination) != OLD_SHA256:
            raise RuntimeError("installed artifact SHA256 differs from the explicit rollback pin")
        verify_production_pin(production_pin)
        return {"production_unit": PRODUCTION_UNIT, "service_fields": production_pin["service_fields"],
                "source_proc": str(reference), "source_path": source_path, "source_identity": before,
                "sha256": digest.hexdigest(), "bytes": inode.st_size, "private_copy": str(destination)}
    finally:
        os.close(source)
        if output is not None:
            os.close(output)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, help="Qualified v6 candidate executable; never an install target")
    parser.add_argument("--expected-candidate-sha256", required=True)
    parser.add_argument("--candidate-contract", required=True)
    parser.add_argument("--receipt-dir", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--expected-head")
    parser.add_argument("--expected-source-fingerprint")
    args = parser.parse_args()
    candidate = pathlib.Path(args.binary).resolve(strict=True)
    if not stat.S_ISREG(candidate.stat().st_mode) or not os.access(candidate, os.X_OK):
        raise RuntimeError("candidate must be an executable ordinary file")
    if sha256(candidate) != args.expected_candidate_sha256:
        raise RuntimeError("candidate SHA256 differs from its exact qualified artifact")
    candidate_contract = json.loads(pathlib.Path(args.candidate_contract).read_text())
    old_contract = json.loads((ROOT / "deploy/contracts/hepta-runtime-full-operator-v4.json").read_text())
    if old_contract["tool_count"] != 50 or len(old_contract["tools"]) != 50:
        raise RuntimeError("frozen original 50-definition v4 contract required")
    folder = pathlib.Path(args.receipt_dir).resolve()
    folder.mkdir(parents=True, mode=0o700, exist_ok=False)
    if stat.S_IMODE(folder.stat().st_mode) != 0o700 or folder.stat().st_uid != os.getuid():
        raise RuntimeError("new owned private receipt directory required")
    output = pathlib.Path(args.out).absolute()
    if output.exists() or output.is_symlink():
        raise RuntimeError("receipt output must be absent")
    baseline = services()
    if any(row.get("ActiveState") != "active" or row.get("MainPID") == "0" for row in baseline.values()):
        raise RuntimeError("production Runtime/Facade/DC must remain active")
    production_pin = capture_production_pin(baseline)
    source_before = source_identity()
    if args.expected_head and source_before["base_HEAD"] != args.expected_head:
        raise RuntimeError("source HEAD differs from expected committed HEAD")
    if args.expected_source_fingerprint and source_before["source_code_fingerprint"] != args.expected_source_fingerprint:
        raise RuntimeError("compile-input fingerprint differs from supplied build pin")
    report = {"schema": "hepta-v6-owned-temporary-controller-v4-rollback-v1",
              "source_head": source_before["base_HEAD"], "source_head_is_compiled_code_claim": False,
              "source_before": source_before, "expected_head": args.expected_head,
              "expected_compiled_source_fingerprint": args.expected_source_fingerprint,
              "harness_sha256": sha256(pathlib.Path(__file__).resolve()),
              "installed_production_pin": production_pin,
              "candidate_binary_sha256": args.expected_candidate_sha256,
              "candidate_contract_sha256": sha256(args.candidate_contract),
              "v4_contract_sha256": sha256(ROOT / "deploy/contracts/hepta-runtime-full-operator-v4.json"),
              "production_rollback_tested": False, "production_service_restarted": False,
              "chatgpt_tool_refresh_requested": False, "model_origin": False,
              "chatgpt_caller_identity_tested": False, "business_replacement_tested": False,
              "DC_off_tested": False, "full_dc_replacement_qualified": False,
              "protected_services_before": baseline, "checks": [], "complete": False,
              "cleanup": {"owned_workloads_stopped": False, "target_fixture_removed": False}}
    token = secrets.token_hex(32)
    token_path = folder / "token"
    controller = None
    client = None
    target = None
    raw_logs = []
    known_jobs = set()
    known_ptys = set()
    key = secrets.token_hex(16)
    job_key = "v6-rollback-" + key + "-job"
    pty_key = "v6-rollback-" + key + "-pty"
    expected_pty = "dpty-" + hashlib.sha256((HOST + "\0" + pty_key).encode()).hexdigest()
    job_params = None

    def redact(text):
        text = text.replace(token, "[REDACTED_TEST_TOKEN]")
        return re.sub(r"(?i)(authorization|x-hepta-runtime-token|password|access_token)(\s*[:=]\s*)([^\s,;\"'{}]+)",
                      r"\1\2[REDACTED]", text)

    def save():
        body = redact(json.dumps(report, indent=2) + "\n").encode()
        temporary = folder / "receipt-next.json"
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as writer:
                writer.write(body)
                writer.flush()
                os.fsync(writer.fileno())
        except BaseException:
            raise
        os.replace(temporary, output)

    def passed(check, detail=None):
        report["checks"].append({"check": check, "result": "passed", "detail": detail})
        save()
        print("PASS", check, flush=True)

    def ssh(code):
        result = subprocess.run(["ssh", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                                 "-o", "ForwardAgent=no", "-o", "ConnectTimeout=8", SSH_TARGET,
                                 "/usr/bin/python3 -c " + shlex.quote(code)],
                                capture_output=True, text=True, timeout=25)
        if result.returncode:
            raise RuntimeError("owned localhost fixture operation failed: " + redact(result.stderr[:4096]))
        return json.loads(result.stdout)

    def stop_controller():
        nonlocal controller, client
        client = None
        if controller is not None and controller.poll() is None:
            controller.terminate()
            try:
                controller.wait(timeout=10)
            except subprocess.TimeoutExpired:
                # This Popen object belongs to this test, never a production PID.
                controller.kill()
                controller.wait(timeout=10)
        controller = None

    def start_controller(binary, phase):
        nonlocal controller, client
        if sha256(binary) not in (args.expected_candidate_sha256, OLD_SHA256):
            raise RuntimeError("test-controller binary changed before launch")
        log_path = folder / (phase + ".raw.log")
        raw_logs.append(log_path)
        descriptor = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(descriptor, "wb") as log:
            controller = subprocess.Popen([str(binary), "mcp", "--path", str(folder / "workspace"),
                                           "--bind", f"127.0.0.1:{port}", "--runtime-config", str(folder / "runtime.json"),
                                           "--auth-token-file", str(token_path)],
                                          stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        for _ in range(80):
            if controller.poll() is not None:
                raise RuntimeError("owned test controller exited; retained redacted phase log")
            try:
                client = Client(url, token)
                return client
            except (OSError, RuntimeError):
                time.sleep(.1)
        raise RuntimeError("owned test controller endpoint unavailable")

    def catalog(expected):
        actual = client.rpc("tools/list", {})["tools"]
        names = {row["name"]: row for row in actual}
        pinned = {row["name"]: row for row in expected["tools"]}
        assert len(actual) == expected["tool_count"] and names == pinned, "exact tool definitions differ"
        return len(actual)

    def pty_until(sid, marker, timeout=15):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = client.call("pty_read", {"host": HOST, "session_id": sid, "offset": 0, "limit": 4096})
            if marker in value["text"]:
                return value
            if value["status"]["state"] != "running":
                raise AssertionError("owned terminal exited before expected marker")
            time.sleep(.1)
        raise AssertionError("owned terminal marker absent")

    def job_until_begin(identity):
        for _ in range(40):
            state = client.call("process_status", {"host": HOST, "job_id": identity})
            text = client.call("process_read", {"host": HOST, "job_id": identity, "limit": 4096})["stdout"]["text"]
            if "BEGIN\n" in text:
                assert state["state"] == "running", "job ended before rollback started"
                return state
            time.sleep(.1)
        raise AssertionError("owned long-job BEGIN not observed")

    def recover_owned_refs():
        if target is None:
            return
        for path in (folder / "state/jobs").glob("*.json"):
            row = json.loads(path.read_text())
            if row.get("host") == HOST and row.get("ssh_target") == SSH_TARGET and row.get("cwd") == target + "/data" and row.get("idempotency_key") == job_key:
                known_jobs.add(row["id"])
        if (folder / "state/terminals" / (expected_pty + ".json")).exists():
            row = json.loads((folder / "state/terminals" / (expected_pty + ".json")).read_text())
            if row.get("host") == HOST and row.get("ssh_target") == SSH_TARGET and row.get("remote_state_dir") == target + "/remote-state" and row.get("request", {}).get("cwd") == target + "/data":
                known_ptys.add(expected_pty)

    try:
        old_binary = folder / "qualified-installed-v4"
        report["old_artifact"] = copy_installed_artifact(old_binary, production_pin)
        passed("pinned production executable descriptor copied privately without live artifact mutation", report["old_artifact"])
        meta = ssh("import os,pathlib,json,tempfile; p=pathlib.Path(tempfile.mkdtemp(prefix='hepta-v6-rollback-target-')).resolve();os.chmod(p,0o700);(p/'data').mkdir(mode=0o700);(p/'data'/'search.txt').write_text('rollback-owned-search');print(json.dumps({'path':str(p),'uid':os.getuid()}))")
        target = meta["path"]
        assert pathlib.PurePosixPath(target).parent == pathlib.PurePosixPath("/tmp") and pathlib.PurePosixPath(target).name.startswith("hepta-v6-rollback-target-")
        report["target_fixture"] = meta
        (folder / "workspace").mkdir(mode=0o700)
        token_path.write_text(token)
        token_path.chmod(0o600)
        host = {"ssh_target": SSH_TARGET, "platform": "linux", "execution_mode": "operator", "remote_state_dir": target + "/remote-state",
                "allow_execute": True, "allow_pty": True, "allow_write": True, "allow_job_network": True,
                "allow_detached_fallback": True, "allowed_read_path_prefixes": [target + "/data"], "allowed_write_path_prefixes": [target + "/data"]}
        (folder / "runtime.json").write_text(json.dumps({"state_dir": str(folder / "state"), "controller_workspace_roots": [str(folder / "workspace")], "hosts": {HOST: host}}))
        with socket.socket() as channel:
            channel.bind(("127.0.0.1", 0))
            port = channel.getsockname()[1]
        url = f"http://127.0.0.1:{port}/mcp"
        start_controller(candidate, "v6-initial")
        passed("initial v6 exact frozen tool definitions", {"tool_count": catalog(candidate_contract)})
        history = client.call("request_history", {"limit": 32})
        owner_cursor = history["requests"][0]["request_id"]
        search = client.call("search_start", {"host": HOST, "root": target + "/data", "kind": "content", "query": "rollback-owned-search"})
        search_id = search["search"]["search_id"]
        for _ in range(40):
            search = client.call("search_results", {"search_id": search_id})
            if search["search"]["state"] == "completed":
                break
            time.sleep(.1)
        else:
            raise AssertionError("owned bounded metadata-search fixture did not complete")
        terminal_code = "import os,sys;print('OWNER_PID='+str(os.getpid()),flush=True);\nfor value in sys.stdin:\n value=value.strip();print('ACK_'+value,flush=True)\n if value=='QUIT':break"
        pty_params = {"host": HOST, "executable": "/usr/bin/python3", "args": ["-c", terminal_code],
                      "cwd": target + "/data", "idempotency_key": pty_key}
        terminal = client.call("pty_start", pty_params)
        sid = terminal["session_id"]
        assert sid == expected_pty and terminal["persistent_across_runtime_restart"]
        known_ptys.add(sid)
        initial_pty = pty_until(sid, "OWNER_PID=")
        pty_pid = int(re.search(r"OWNER_PID=(\d+)", initial_pty["text"]).group(1))
        client.call("pty_write", {"host": HOST, "session_id": sid, "data": "V6\n", "request_id": key + "-input-v6"})
        pty_until(sid, "ACK_V6")
        job_code = "import time,pathlib; p=pathlib.Path('once');p.open('a').write('1');print('BEGIN',flush=True);time.sleep(8);print('END',flush=True)"
        job_params = {"host": HOST, "executable": "/usr/bin/python3", "args": ["-c", job_code],
                      "cwd": target + "/data", "timeout_seconds": 30, "idempotency_key": job_key}
        started = client.call("process_start", job_params)
        jid = started["job"]["id"]
        known_jobs.add(jid)
        initial_state = job_until_begin(jid)
        passed("v6 creates owned in-flight once-job and real persistent terminal", {"job_id": jid, "job_state": initial_state["state"], "pty_session_id": sid, "pty_pid": pty_pid})
        stop_controller()
        start_controller(old_binary, "v4-rollback")
        passed("temporary old-controller rollback exposes all original 50 exact definitions", {"tool_count": catalog(old_contract)})
        reused = client.call("process_start", job_params)
        assert reused["reused"] and reused["job"]["id"] == jid
        rolled_job = client.call("process_status", {"host": HOST, "job_id": jid})
        assert rolled_job["state"] == "running", "8-second job finished before rollback's running proof"
        assert "BEGIN\n" in client.call("process_read", {"host": HOST, "job_id": jid, "limit": 4096})["stdout"]["text"]
        reused_pty = client.call("pty_start", pty_params)
        assert reused_pty["reused"] and reused_pty["session_id"] == sid and reused_pty["status"]["pid"] == pty_pid
        v4_input = {"host": HOST, "session_id": sid, "data": "V4\n", "request_id": key + "-input-v4"}
        assert client.call("pty_write", v4_input)["complete"]
        assert pty_until(sid, "ACK_V4")["status"]["pid"] == pty_pid
        passed("old v4 controller reuses same running v6-owned job and same-PID PTY with actual stdin/stdout")
        stop_controller()
        start_controller(candidate, "v6-forward")
        assert catalog(candidate_contract) == candidate_contract["tool_count"]
        assert client.call("process_start", job_params)["job"]["id"] == jid
        same_pty = client.call("pty_start", pty_params)
        assert same_pty["reused"] and same_pty["session_id"] == sid and same_pty["status"]["pid"] == pty_pid
        assert client.call("pty_write", v4_input)["reused"]
        assert client.call("pty_write", {"host": HOST, "session_id": sid, "data": "FORWARD\n", "request_id": key + "-input-forward"})["complete"]
        final_pty = pty_until(sid, "ACK_FORWARD")
        assert final_pty["text"].count("ACK_V6") == 1 and final_pty["text"].count("ACK_V4") == 1 and final_pty["text"].count("ACK_FORWARD") == 1
        for _ in range(10):
            final_job = client.call("process_wait", {"host": HOST, "job_id": jid, "timeout_seconds": 5})
            if final_job["state"] != "running":
                break
        assert final_job["state"] == "succeeded" and final_job["output_complete"]
        logs = client.call("process_read", {"host": HOST, "job_id": jid, "limit": 4096})
        assert logs["stdout"]["text"] == "BEGIN\nEND\n" and logs["stderr"]["text"] == ""
        once = ssh("import pathlib,json;print(json.dumps({'content':pathlib.Path(" + repr(target + "/data/once") + ").read_text()}))")
        assert once["content"] == "1"
        passed("forward v6 same identities, once-only process side effect and deduplicated persistent PTY input", {"job_id": jid, "pty_session_id": sid, "pty_pid": pty_pid, "once_bytes": 1})
        for tool, parameters in [("request_history", {"after_id": owner_cursor}), ("search_results", {"search_id": search_id}), ("search_stop", {"search_id": search_id})]:
            denied = client.call(tool, parameters, denied=True)
            assert target not in denied
        assert client.call("search_list", {})["searches"] == []
        fresh = client.call("request_history", {"limit": 32})
        assert owner_cursor not in {row["request_id"] for row in fresh["requests"]}
        passed("new native MCP session denies old history/search owner; persistent jobs do not counterfeit session resume")
        report["passed"] = len(report["checks"])
        report["workflow_passed"] = True
    except BaseException as error:
        report["failure"] = redact(str(error)[:4096])
        report["traceback"] = redact(traceback.format_exc())
    finally:
        cleanup_errors = []
        try:
            recover_owned_refs()
            if target is not None and (known_jobs or known_ptys):
                if controller is None or controller.poll() is not None or client is None:
                    stop_controller()
                    start_controller(candidate, "v6-owned-cleanup")
                for jid in known_jobs:
                    client.call("process_cancel", {"host": HOST, "job_id": jid, "grace_seconds": 2})
                    status = client.call("process_wait", {"host": HOST, "job_id": jid, "timeout_seconds": 10})
                    if status["state"] not in ("succeeded", "failed", "cancelled", "timed_out") or not status.get("output_complete"):
                        raise RuntimeError("owned job termination not confirmed; fixture retained")
                for sid in known_ptys:
                    client.call("pty_close", {"host": HOST, "session_id": sid})
                    for _ in range(50):
                        status = client.call("pty_read", {"host": HOST, "session_id": sid, "offset": 0, "limit": 4096})
                        if status["status"]["state"] == "exited" and status.get("output_complete"):
                            break
                        time.sleep(.1)
                    else:
                        raise RuntimeError("owned terminal termination not confirmed; fixture retained")
                report["cleanup"]["owned_workloads_stopped"] = True
            elif target is not None:
                report["cleanup"]["owned_workloads_stopped"] = True
            if target is not None and report["cleanup"]["owned_workloads_stopped"]:
                # Archive bounded test output before removing only this owned target tree.
                archives = ssh("import pathlib,json,hashlib,os,shutil; p=pathlib.Path(" + repr(target) + ");assert p.parent==pathlib.Path('/tmp') and p.name.startswith('hepta-v6-rollback-target-') and not p.is_symlink() and p.stat().st_uid==os.getuid();a=[]\nfor f in p.rglob('*.log'):\n if f.is_file() and not f.is_symlink():\n  b=f.read_bytes();assert len(b)<=65536;a.append({'path':str(f.relative_to(p)),'sha256':hashlib.sha256(b).hexdigest(),'text':b.decode('utf-8','replace')})\nshutil.rmtree(p);print(json.dumps({'archives':a,'removed':not p.exists()}))")
                report["target_archives"] = archives["archives"]
                report["cleanup"]["target_fixture_removed"] = archives["removed"]
        except BaseException as error:
            cleanup_errors.append(redact(str(error)[:4096]))
        finally:
            stop_controller()
            token_path.unlink(missing_ok=True)
            for raw in raw_logs:
                if raw.exists():
                    sanitized = raw.with_name(raw.name.replace(".raw.log", ".log"))
                    sanitized.write_text(redact(raw.read_text(errors="replace")))
                    sanitized.chmod(0o600)
                    raw.unlink()
            report["phase_logs"] = [{"path": str(path), "sha256": sha256(path)} for path in folder.glob("*.log")]
            report["cleanup"]["errors"] = cleanup_errors
            try:
                report["protected_services_after"] = services()
                report["service_identity_stable"] = report["protected_services_after"] == baseline
                verify_production_pin(production_pin)
                report["installed_production_identity_after"] = process_identity(production_pin["identity"]["pid"])
                report["installed_production_identity_stable"] = report["installed_production_identity_after"] == production_pin["identity"]
            except Exception as error:
                report["service_identity_stable"] = False
                report["installed_production_identity_stable"] = False
                report["protected_service_observation_error_type"] = type(error).__name__
            try:
                source_after = source_identity()
                report["source_after"] = source_after
                report["source_fingerprint_stable"] = source_after["source_code_fingerprint"] == source_before["source_code_fingerprint"]
                report["source_head_stable"] = source_after["base_HEAD"] == source_before["base_HEAD"]
                report["candidate_hashes_stable"] = (sha256(candidate) == args.expected_candidate_sha256
                    and sha256(args.candidate_contract) == report["candidate_contract_sha256"]
                    and sha256(pathlib.Path(__file__).resolve()) == report["harness_sha256"]
                    and report["source_fingerprint_stable"] and report["source_head_stable"])
            except Exception as error:
                report["candidate_hashes_stable"] = False
                report["source_observation_error_type"] = type(error).__name__
            report["complete"] = bool(report.get("workflow_passed") and not cleanup_errors
                and report["cleanup"]["target_fixture_removed"] and report["service_identity_stable"]
                and report["installed_production_identity_stable"] and report["candidate_hashes_stable"])
            save()
    print("TEMPORARY_ROLLBACK_COMPLETE", report["complete"], flush=True)
    if not report["complete"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

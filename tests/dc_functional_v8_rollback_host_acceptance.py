#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Owned temporary-controller v8 -> installed-v4 artifact -> v8 rollback.

Never stop/restart/configure a production service, refresh ChatGPT tools, stop
Desktop Commander, or touch a business workload. The installed artifact is read
through its pinned /proc executable descriptor and copied to a new private file.
Sequential fixed-host cohort; each selected target uses a disposable controller on main.
Both directions preserve genuine owned jobs/PTYs. Credential metadata resumes
without search replay; legacy missing-nonce jobs remain non-authoritative and
cannot be adopted or canceled by V8. Only a disposable main controller is tested:
no production restart/rollback, ChatGPT caller ownership, business or DC-off.
Mac target identities use ps_lstart/UID with best-effort non-atomic semantics.
"""
import argparse
import datetime
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
import sys
import time
import tempfile
import shutil
import traceback

from dc_parity_release_six_host_acceptance import HOSTS, services
from dc_functional_v6_operator_six_host_acceptance import source_identity
from runtime_http_acceptance import Client
from dc_successor_contract import REVIEWED_SUCCESSORS, verify_successor, V8_SHA256

ROOT = pathlib.Path(__file__).resolve().parents[1]
PRODUCTION_UNIT = "hepta-runtime-operator.service"
OLD_SHA256 = "db181570e9e65f9e6a962d013dd4880eedc5b0cda1c71508f84388a4a8d8072b"
OLD_CONTRACT_SHA256 = "d36610d575146805f4c02d89210abd360b4d42acc8736d1966f20d0d724704b1"
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


def load_reviewed_contract(args):
    digest = sha256(args.candidate_contract)
    if args.expected_contract_sha256 and digest != args.expected_contract_sha256:
        raise RuntimeError("candidate contract differs from the explicit contract-file pin")
    version = REVIEWED_SUCCESSORS.get(digest)
    if digest != V8_SHA256 or version != 8:
        raise RuntimeError("exact reviewed V8 contract required; newer versions need separately reviewed qualification")
    value = json.loads(pathlib.Path(args.candidate_contract).read_text())
    verify_successor(value["tools"], pathlib.Path(args.candidate_contract))
    return value, version


def harness_inputs():
    paths = [pathlib.Path(__file__).resolve(), ROOT / "tests/dc_successor_contract.py",
             ROOT / "tests/runtime_http_acceptance.py", ROOT / "deploy/mcp_tool_contract.py",
             ROOT / "tests/dc_functional_v6_operator_six_host_acceptance.py",
             ROOT / "tests/dc_parity_release_six_host_acceptance.py",
             ROOT / "deploy/contracts/hepta-runtime-full-operator-v4.json"]
    return {str(path.relative_to(ROOT)): {"bytes": path.stat().st_size, "sha256": sha256(path)}
            for path in paths}


def run_cohort(args):
    """Run selected fixed aliases serially; each member owns its own fixtures."""
    binary = pathlib.Path(args.binary).resolve(strict=True)
    if not stat.S_ISREG(binary.stat().st_mode) or not os.access(binary, os.X_OK) or sha256(binary) != args.expected_candidate_sha256:
        raise RuntimeError("cohort candidate executable differs from its sealed artifact")
    contract, version = load_reviewed_contract(args)
    source_before = source_identity()
    if source_before["base_HEAD"] != args.expected_head or source_before["source_code_fingerprint"] != args.expected_source_fingerprint:
        raise RuntimeError("cohort source differs from the sealed HEAD/compile-input fingerprint")
    before_inputs = harness_inputs()
    if before_inputs["deploy/contracts/hepta-runtime-full-operator-v4.json"]["sha256"] != OLD_CONTRACT_SHA256:
        raise RuntimeError("original installed-v4 contract differs from its frozen exact-definition pin")
    baseline = services()
    if any(row.get("ActiveState") != "active" or row.get("MainPID") == "0" for row in baseline.values()):
        raise RuntimeError("protected installed services must remain active before the cohort")
    production_pin = capture_production_pin(baseline)
    directory = pathlib.Path(args.receipt_dir).absolute()
    if directory.is_symlink():raise RuntimeError("cohort output directory may not be a symlink")
    output = pathlib.Path(args.out).absolute()
    if output.exists() or output.is_symlink():raise RuntimeError("never replace earlier cohort evidence")
    directory.mkdir(parents=True, mode=0o700, exist_ok=False)
    info = directory.stat()
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise RuntimeError("new owned private cohort directory required")
    selected = [name for name, _ in HOSTS if name in args.host]
    report = {"schema": "hepta-successor-real-target-temporary-controller-rollback-cohort-v1",
        "recorded_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "selected_hosts": selected, "max_workers": 1, "host_order": "fixed main-first order; no parallel native or SSH member experiments",
        "controller_host": "main", "origin": "local_native_client_real_configured_target_fixtures",
        "candidate_binary_sha256": args.expected_candidate_sha256,
        "candidate_contract_sha256": sha256(args.candidate_contract), "candidate_contract_version": version,
        "source_before": source_before, "harness_inputs_before": before_inputs,
        "protected_services_before": baseline, "installed_production_pin": production_pin,
        "protected_service_identity_scope": "main PROTECTED units only; target business-service restart is not qualified",
        "production_service_restarted": False, "production_rollback_tested": False,
        "chatgpt_originated": False, "app_refreshed": False, "DC_off_tested": False,
        "full_dc_replacement_qualified": False, "results": [], "complete": False,
        "complete_six_configured_target_cohort": False, "selected_complete": False}
    member_process = None
    current_host = None
    def save():
        temporary = directory / "cohort-receipt-next.json"
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as writer:
            json.dump(report, writer, ensure_ascii=False, indent=2); writer.write("\n"); writer.flush(); os.fsync(writer.fileno())
        os.replace(temporary, output)
    save()
    try:
        for name in selected:
            current_host = name
            member_dir = directory / name
            member_receipt = directory / (name + ".json")
            member_log = directory / (name + ".log")
            command = [sys.executable, str(pathlib.Path(__file__).resolve()), "--member", "--host", name,
                "--max-workers", "1", "--binary", str(binary),
                "--expected-candidate-sha256", args.expected_candidate_sha256,
                "--candidate-contract", str(pathlib.Path(args.candidate_contract).resolve()),
                "--expected-contract-sha256", report["candidate_contract_sha256"],
                "--expected-head", args.expected_head,
                "--expected-source-fingerprint", args.expected_source_fingerprint,
                "--receipt-dir", str(member_dir), "--out", str(member_receipt)]
            fd = os.open(member_log, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as writer:
                member_process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=writer, stderr=writer)
                while member_process.poll() is None:
                    try:member_process.wait(timeout=20)
                    except subprocess.TimeoutExpired:
                        print("RUNNING", name, "owned temporary-controller rollback member", flush=True)
                code = member_process.returncode
            member_process = None
            data = json.loads(member_receipt.read_text()) if member_receipt.exists() else {}
            row = {"host": name, "exit": code, "receipt": str(member_receipt),
                "receipt_sha256": sha256(member_receipt) if member_receipt.exists() else None,
                "log": str(member_log), "log_sha256": sha256(member_log),
                "complete": data.get("complete") is True, "passed": data.get("passed"),
                "private_authentication_removed": data.get("private_authentication_removed") is True,
                "cleanup": data.get("cleanup"), "target_platform": data.get("target_fixture", {}).get("platform"),
                "binding_verified": (data.get("target_host") == name
                    and data.get("candidate_binary_sha256") == report["candidate_binary_sha256"]
                    and data.get("candidate_contract_sha256") == report["candidate_contract_sha256"]
                    and data.get("source_before", {}).get("source_code_fingerprint") == args.expected_source_fingerprint
                    and data.get("source_before", {}).get("base_HEAD") == args.expected_head
                    and data.get("harness_sha256") == before_inputs[pathlib.Path(__file__).resolve().relative_to(ROOT).as_posix()]["sha256"])}
            report["results"].append(row); save()
            print("TARGET", name, "exit", code, "complete", row["complete"], "checks", row["passed"], flush=True)
    except BaseException as error:
        report["failure_type"] = type(error).__name__
        report["failure_phase"] = current_host or "cohort setup"
        report["failure_frames"] = [{"file": frame.filename, "line": frame.lineno, "function": frame.name}
                                    for frame in traceback.extract_tb(error.__traceback__)]
        # Do not terminate a member with unknown effects. Its bounded fixture
        # workflow retains the same references and performs its own cleanup.
        if member_process is not None and member_process.poll() is None:
            report["member_in_progress_preserved"] = {"host": current_host, "pid": member_process.pid,
                "receipt": str(directory / (current_host + ".json")), "automatic_retry": False}
    finally:
        try:
            report["protected_services_after"] = services()
            report["service_identity_stable"] = report["protected_services_after"] == baseline
            verify_production_pin(production_pin)
            report["installed_production_identity_stable"] = True
        except Exception as error:
            report["service_identity_stable"] = False; report["installed_production_identity_stable"] = False
            report["protected_service_observation_error_type"] = type(error).__name__
        try:
            report["source_after"] = source_identity(); report["harness_inputs_after"] = harness_inputs()
            report["sealed_inputs_stable"] = (report["source_after"]["base_HEAD"] == args.expected_head
                and report["source_after"]["source_code_fingerprint"] == args.expected_source_fingerprint
                and report["harness_inputs_after"] == before_inputs
                and sha256(binary) == args.expected_candidate_sha256
                and sha256(args.candidate_contract) == report["candidate_contract_sha256"])
        except Exception as error:
            report["sealed_inputs_stable"] = False; report["source_observation_error_type"] = type(error).__name__
        report["selected_complete"] = (len(report["results"]) == len(selected)
            and all(row["exit"] == 0 and row["complete"] and row["binding_verified"]
                    and row["private_authentication_removed"] and row["cleanup"] ==
                    {"owned_workloads_stopped": True, "target_fixture_removed": True, "errors": []}
                    for row in report["results"])
            and report["service_identity_stable"] and report["installed_production_identity_stable"]
            and report["sealed_inputs_stable"] and "failure_type" not in report)
        report["complete_six_configured_target_cohort"] = report["selected_complete"] and set(selected) == {name for name, _ in HOSTS}
        report["complete"] = report["complete_six_configured_target_cohort"]
        save()
    print("SELECTED_ROLLBACK_COMPLETE", report["selected_complete"], "SIX_CONFIGURED_TARGETS", report["complete"], flush=True)
    if not report["selected_complete"]:raise SystemExit(1)


def main():
    global HOST, SSH_TARGET
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, help="Qualified v8 candidate executable; never an install target")
    parser.add_argument("--expected-candidate-sha256", "--binaryexpectedSHA", dest="expected_candidate_sha256", required=True)
    parser.add_argument("--candidate-contract", "--contract", dest="candidate_contract", required=True)
    parser.add_argument("--expected-contract-sha256", required=True)
    parser.add_argument("--receipt-dir", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--expected-head", "--HEAD", dest="expected_head", required=True)
    parser.add_argument("--expected-source-fingerprint", "--FP", dest="expected_source_fingerprint", required=True)
    parser.add_argument("--host", nargs="+", choices=[name for name, _ in HOSTS], required=True)
    parser.add_argument("--max-workers", type=int, choices=[1], default=1)
    parser.add_argument("--member", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if len(set(args.host)) != len(args.host):raise ValueError("duplicate configured target alias")
    if not args.member:
        run_cohort(args)
        return
    if len(args.host) != 1:raise ValueError("a private cohort member requires one configured alias")
    HOST = args.host[0]; SSH_TARGET = dict(HOSTS)[HOST]
    candidate = pathlib.Path(args.binary).resolve(strict=True)
    if not stat.S_ISREG(candidate.stat().st_mode) or not os.access(candidate, os.X_OK):
        raise RuntimeError("candidate must be an executable ordinary file")
    if sha256(candidate) != args.expected_candidate_sha256:
        raise RuntimeError("candidate SHA256 differs from its exact qualified artifact")
    candidate_contract, contract_version = load_reviewed_contract(args)
    if sha256(ROOT / "deploy/contracts/hepta-runtime-full-operator-v4.json") != OLD_CONTRACT_SHA256:
        raise RuntimeError("original installed-v4 contract differs from its frozen exact-definition pin")
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
    member_inputs_before = harness_inputs()
    if args.expected_head and source_before["base_HEAD"] != args.expected_head:
        raise RuntimeError("source HEAD differs from expected committed HEAD")
    if args.expected_source_fingerprint and source_before["source_code_fingerprint"] != args.expected_source_fingerprint:
        raise RuntimeError("compile-input fingerprint differs from supplied build pin")
    report = {"schema": "hepta-successor-owned-temporary-controller-real-host-member-rollback-v1",
              "source_head": source_before["base_HEAD"], "source_head_is_compiled_code_claim": False,
              "source_before": source_before, "expected_head": args.expected_head,
              "expected_compiled_source_fingerprint": args.expected_source_fingerprint,
              "harness_sha256": sha256(pathlib.Path(__file__).resolve()),
              "harness_inputs_before": member_inputs_before,
              "installed_production_pin": production_pin,
              "candidate_binary_sha256": args.expected_candidate_sha256,
              "candidate_contract_sha256": sha256(args.candidate_contract),
              "v4_contract_sha256": sha256(ROOT / "deploy/contracts/hepta-runtime-full-operator-v4.json"),
              "production_rollback_tested": False, "production_service_restarted": False,
              "qualification_scope": "one actual configured target with owned temporary main-controller forward/reverse interoperability only",
              "target_host": HOST, "ssh_target": SSH_TARGET, "controller_host": "main",
              "candidate_contract_version": contract_version,
              "complete_six_host_cohort": False,
              "protected_service_identity_scope": "main PROTECTED units only; no remote production-service restart qualification",
              "target_process_identity_scope": "Linux boot+proc_start_ticks/UID" if HOST != "mac" else "macOS ps_lstart/UID best effort, non-atomic",
              "process_pty_ownership": "trusted operator account; no per-ChatGPT-caller ownership",
              "metadata_ownership": "verified private credential shared by its users; no ChatGPT caller isolation",
              "automatic_operation_retry": False, "six_host_rollback_tested": False,
              "chatgpt_tool_refresh_requested": False, "model_origin": False,
              "chatgpt_caller_identity_tested": False, "business_replacement_tested": False,
              "DC_off_tested": False, "full_dc_replacement_qualified": False,
              "protected_services_before": baseline, "checks": [], "complete": False,
              "cleanup": {"owned_workloads_stopped": False, "target_fixture_removed": False}}
    token = secrets.token_hex(32)
    auth_parent = pathlib.Path.home() / ".local/state/hepta-runtime-acceptance"
    auth_parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    auth_info = auth_parent.lstat()
    if auth_parent.is_symlink() or not stat.S_ISDIR(auth_info.st_mode) or auth_info.st_uid != os.getuid() or stat.S_IMODE(auth_info.st_mode) != 0o700:
        raise RuntimeError("private fixture authentication directory identity/mode refused")
    auth_directory = pathlib.Path(tempfile.mkdtemp(prefix="hepta-v8-rollback-auth-", dir=auth_parent))
    token_path = auth_directory / "token"
    controller = None
    client = None
    target = None
    raw_logs = []
    known_jobs = set()
    known_ptys = set()
    key = secrets.token_hex(16)
    job_key = "v8-rollback-" + key + "-job"
    pty_key = "v8-rollback-" + key + "-pty"
    expected_pty = "dpty-" + hashlib.sha256((HOST + "\0" + pty_key).encode()).hexdigest()
    job_params = None
    legacy_job_key = "v8-rollback-" + key + "-legacy-job"
    legacy_pty_key = "v8-rollback-" + key + "-legacy-pty"
    expected_legacy_pty = "dpty-" + hashlib.sha256((HOST + "\0" + legacy_pty_key).encode()).hexdigest()
    expected_ptys = {expected_pty, expected_legacy_pty}
    job_keys = {job_key, legacy_job_key}
    ssh_counter = folder / "native-ssh-count.log"
    native_environment = dict(os.environ)
    config_path = folder / "runtime.json"
    saved_config = None
    owned_searches = set()

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
        result = subprocess.run(["/usr/bin/ssh", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                                 "-o", "ForwardAgent=no", "-o", "ConnectTimeout=8", SSH_TARGET,
                                 "/usr/bin/python3 -c " + shlex.quote(code)],
                                capture_output=True, text=True, timeout=25)
        if result.returncode:
            raise RuntimeError("owned configured-host fixture operation failed: " + redact(result.stderr[:4096]))
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
        report["active_phase"] = phase
        save()
        log_path = folder / (phase + ".raw.log")
        raw_logs.append(log_path)
        descriptor = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(descriptor, "wb") as log:
            controller = subprocess.Popen([str(binary), "mcp", "--path", str(folder / "workspace"),
                                           "--bind", f"127.0.0.1:{port}", "--runtime-config", str(folder / "runtime.json"),
                                           "--auth-token-file", str(token_path)],
                                          stdin=subprocess.DEVNULL, stdout=log, stderr=log, env=native_environment)
        report.setdefault("owned_controller_processes", []).append({"phase": phase, "pid": controller.pid,
            "binary_sha256": sha256(binary), "production_service": False})
        save()
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
            if row.get("host") == HOST and row.get("ssh_target") == SSH_TARGET and row.get("cwd") == target + "/data" and row.get("idempotency_key") in job_keys:
                known_jobs.add(row["id"])
        for expected in expected_ptys:
            path = folder / "state/terminals" / (expected + ".json")
            if path.exists():
                row = json.loads(path.read_text())
                if row.get("host") == HOST and row.get("ssh_target") == SSH_TARGET and row.get("remote_state_dir") == target + "/remote-state" and row.get("request", {}).get("cwd") == target + "/data":
                    known_ptys.add(expected)

    def native_ssh_count():
        return len(ssh_counter.read_bytes()) if ssh_counter.exists() else 0

    def metadata_scope(value, search=False):
        assert value["ownership_scope"] == "authenticated_private_operator_credential"
        assert value["credential_metadata_resume"] is True
        assert value["authenticated_chatgpt_caller_isolation"] is False
        if search:
            assert value["metadata_resume_after_restart"] is True and value["session_resume_after_restart"] is False
        else:
            assert value["session_scope"] == "authenticated_private_operator_credential"
            assert value["cross_session_resume"] is True
        return value

    def owned_target(code):
        guard = "import os,pathlib; base=pathlib.Path(" + repr(target) + ");assert base.is_absolute() and base.name.startswith('hepta-v8-rollback-target-') and not base.is_symlink() and base.stat().st_uid==os.getuid();assert (base/'.fixture-owner').is_file() and not (base/'.fixture-owner').is_symlink() and (base/'.fixture-owner').read_text()==" + repr(key) + "\n"
        return ssh(guard + code)

    def release_jobs():
        if target is not None:
            owned_target("import json; (base/'data'/'release-new').write_text('owned release');(base/'data'/'release-legacy').write_text('owned release');print(json.dumps({'released':True}))")

    def await_terminal(jid, timeout=20):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = client.call("process_status", {"host": HOST, "job_id": jid})
            if value["state"] in ("succeeded", "failed", "cancelled", "timed_out") and value.get("output_complete"):
                return value
            time.sleep(.1)
        raise RuntimeError("owned job not confirmed terminal; fixture retained")

    def process_observation(name, min_tick=None):
        code = """import json,subprocess,sys,time
p=base/'data'/MARKER;deadline=time.monotonic()+5
while True:
 d=json.loads(p.read_text())
 if MIN_TICK is None or d['tick']>MIN_TICK:break
 if time.monotonic()>deadline:raise ValueError('owned legacy activity did not advance')
 time.sleep(.025)
pid=d['pid']
if sys.platform=='linux':
 raw=pathlib.Path('/proc/'+str(pid)+'/stat').read_text();ticks=int(raw.rsplit(') ',1)[1].split()[19])
 actual={'kind':'proc_start_ticks','value':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()+':'+str(ticks)}
 uid=pathlib.Path('/proc/'+str(pid)).stat().st_uid
else:
 actual={'kind':'ps_lstart','value':subprocess.check_output(['ps','-p',str(pid),'-o','lstart='],text=True,timeout=3).strip()}
 uid=int(subprocess.check_output(['ps','-p',str(pid),'-o','uid='],text=True,timeout=3).strip())
assert d['uid']==os.getuid()==uid and actual==d['identity'] and actual['value']
print(json.dumps(d))
""".replace("MARKER", repr(name)).replace("MIN_TICK", repr(min_tick))
        return owned_target(code)

    def new_process_observation():
        return process_observation('new-process-identity.json')

    def legacy_observation(min_tick=None):
        return process_observation('legacy-activity.json', min_tick)

    def legacy_artifacts(jid):
        local = json.loads((folder / "state/jobs" / (jid + ".json")).read_text())
        job_dir = local["remote_job_dir"]
        assert pathlib.PurePosixPath(job_dir).is_relative_to(pathlib.PurePosixPath(target + "/remote-state"))
        return owned_target("import hashlib,json; j=pathlib.Path(" + repr(job_dir) + ");request=json.loads((j/'request.json').read_text());started=json.loads((j/'started.json').read_text());assert request['job_id']==" + repr(jid) + ";print(json.dumps({'request_sha256':hashlib.sha256((j/'request.json').read_bytes()).hexdigest(),'started_sha256':hashlib.sha256((j/'started.json').read_bytes()).hexdigest(),'launch_nonce_present':'launch_nonce' in request,'supervisor_identity_present':'supervisor_identity' in started,'cancel_request_present':(j/'cancel-request.json').exists()}))")

    def pty_cursor(sid, offset=0):
        value = client.call("pty_read", {"host": HOST, "session_id": sid, "offset": offset, "limit": 4096, "raw_bytes": True})
        data = bytes.fromhex(value["bytes_hex"])
        assert value["offset"] == offset and value["next_offset"] == offset + len(data)
        return value, data

    try:
        old_binary = folder / "qualified-installed-v4"
        report["old_artifact"] = copy_installed_artifact(old_binary, production_pin)
        passed("pinned production executable descriptor copied privately without live artifact mutation", report["old_artifact"])
        host_environment = ssh("import os,pathlib,json,sys,tempfile;print(json.dumps({'temporary_root':str(pathlib.Path(tempfile.gettempdir()).resolve()),'uid':os.getuid(),'platform':sys.platform}))")
        assert host_environment["platform"] == ("darwin" if HOST == "mac" else "linux"), "actual target platform differs from fixed configured-host expectation"
        temporary_root = pathlib.PurePosixPath(host_environment["temporary_root"])
        assert temporary_root.is_absolute()
        target = str(temporary_root / ("hepta-v8-rollback-target-" + key))
        # Persist the exact random owned reference BEFORE remote mkdir so a lost
        # SSH response never loses the fixture identity or triggers a retry.
        report["target_fixture_creation"] = {"path": target, "host": HOST,
            "platform": host_environment["platform"], "ownership_marker": ".fixture-owner",
            "automatic_retry": False, "creation_outcome": "not_yet_confirmed"}
        save()
        meta = ssh("import os,pathlib,json,sys; p=pathlib.Path(" + repr(target) + ");assert p.is_absolute() and not p.exists() and not p.is_symlink();p.mkdir(mode=0o700);(p/'.fixture-owner').write_text(" + repr(key) + ");os.chmod(p/'.fixture-owner',0o600);(p/'data').mkdir(mode=0o700);(p/'data'/'search.txt').write_text('rollback-owned-search');print(json.dumps({'path':str(p),'uid':os.getuid(),'platform':sys.platform}))")
        assert meta["path"] == target and meta["uid"] == host_environment["uid"] and meta["platform"] == host_environment["platform"]
        report["target_fixture"] = meta
        report["target_fixture_creation"]["creation_outcome"] = "confirmed_owned"
        save()
        (folder / "workspace").mkdir(mode=0o700)
        descriptor = os.open(token_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "w") as writer:
            writer.write(token); writer.flush(); os.fsync(writer.fileno())
        bin_dir = folder / "owned-bin"; bin_dir.mkdir(mode=0o700)
        wrapper = bin_dir / "ssh"
        wrapper.write_text("#!/usr/bin/python3\nimport os,pathlib,sys\nwith pathlib.Path(" + repr(str(ssh_counter)) + ").open('ab') as f:f.write(b'1')\nos.execv('/usr/bin/ssh',['ssh',*sys.argv[1:]])\n")
        wrapper.chmod(0o700)
        native_environment["PATH"] = str(bin_dir) + os.pathsep + native_environment.get("PATH", "")
        host = {"ssh_target": SSH_TARGET, "platform": "macos" if HOST == "mac" else "linux", "execution_mode": "operator", "remote_state_dir": target + "/remote-state",
                "allow_execute": True, "allow_pty": True, "allow_write": True, "allow_job_network": True,
                "allow_detached_fallback": True, "allowed_read_path_prefixes": [target + "/data"], "allowed_write_path_prefixes": [target + "/data"]}
        saved_config = {"state_dir": str(folder / "state"), "controller_workspace_roots": [str(folder / "workspace")], "hosts": {HOST: host}}
        config_path.write_text(json.dumps(saved_config)); config_path.chmod(0o600)
        with socket.socket() as channel:
            channel.bind(("127.0.0.1", 0))
            port = channel.getsockname()[1]
        url = f"http://127.0.0.1:{port}/mcp"
        start_controller(candidate, "v8-initial")
        passed("initial v8 exact frozen tool definitions", {"tool_count": catalog(candidate_contract)})
        history = metadata_scope(client.call("request_history", {"limit": 32}))
        owner_cursor = history["requests"][0]["request_id"]
        search = client.call("search_start", {"host": HOST, "root": target + "/data", "kind": "content", "query": "rollback-owned-search"})
        metadata_scope(search, search=True)
        search_id = search["search"]["search_id"]; owned_searches.add(search_id)
        for _ in range(40):
            search = client.call("search_results", {"search_id": search_id})
            if search["search"]["state"] == "completed":
                break
            time.sleep(.1)
        else:
            raise AssertionError("owned bounded metadata-search fixture did not complete")
        terminal_snapshot = client.call("search_results", {"search_id": search_id, "cursor": 0, "limit": 2})
        assert terminal_snapshot["snapshot"]["snapshot_ready"] is True
        stable_snapshot_sha = hashlib.sha256(json.dumps(terminal_snapshot["snapshot"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        terminal_code = "import os,sys;print('OWNER_PID='+str(os.getpid()),flush=True);\nfor value in sys.stdin:\n value=value.strip();print('ACK_'+value,flush=True)\n if value=='QUIT':break"
        pty_params = {"host": HOST, "executable": "/usr/bin/python3", "args": ["-c", terminal_code],
                      "cwd": target + "/data", "idempotency_key": pty_key}
        terminal = client.call("pty_start", pty_params)
        sid = terminal["session_id"]
        assert sid == expected_pty and terminal["persistent_across_runtime_restart"]
        known_ptys.add(sid)
        initial_pty = pty_until(sid, "OWNER_PID=")
        pty_pid = int(re.search(r"OWNER_PID=(\d+)", initial_pty["text"]).group(1))
        client.call("pty_write", {"host": HOST, "session_id": sid, "data": "V8\n", "request_id": key + "-input-v8"})
        pty_until(sid, "ACK_V8")
        job_code = """import json,os,time,pathlib,subprocess,sys
p=pathlib.Path('once');f=p.open('a');f.write('1');f.flush();os.fsync(f.fileno());f.close()
if sys.platform=='linux':
 raw=pathlib.Path('/proc/'+str(os.getpid())+'/stat').read_text();ticks=int(raw.rsplit(') ',1)[1].split()[19])
 identity={'kind':'proc_start_ticks','value':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()+':'+str(ticks)}
else:
 identity={'kind':'ps_lstart','value':subprocess.check_output(['ps','-p',str(os.getpid()),'-o','lstart='],text=True,timeout=3).strip()}
assert identity['value']
pathlib.Path('new-process-identity.json').write_text(json.dumps({'pid':os.getpid(),'uid':os.geteuid(),'identity':identity}))
print('BEGIN',flush=True);deadline=time.monotonic()+180
while not pathlib.Path('release-new').exists() and time.monotonic()<deadline:time.sleep(.05)
print('END',flush=True)
"""
        job_params = {"host": HOST, "executable": "/usr/bin/python3", "args": ["-c", job_code],
                      "cwd": target + "/data", "timeout_seconds": 240, "idempotency_key": job_key}
        started = client.call("process_start", job_params)
        jid = started["job"]["id"]
        known_jobs.add(jid)
        initial_state = job_until_begin(jid)
        new_process_pin = new_process_observation()
        new_runner_pin = legacy_artifacts(jid)
        assert new_runner_pin["launch_nonce_present"] is True and new_runner_pin["supervisor_identity_present"] is True
        first_page = client.call("process_read", {"host": HOST, "job_id": jid, "stdout_offset": 0, "stderr_offset": 0, "limit": 2})
        assert bytes.fromhex(first_page["stdout"]["bytes_hex"]) == b"BE" and first_page["stdout"]["next_offset"] == 2
        assert bytes.fromhex(first_page["stderr"]["bytes_hex"]) == b"" and first_page["stderr"]["next_offset"] == 0
        # Native start records running before its detached worker completes.
        # Freeze this actual unpolled controller receipt; no state is fabricated.
        unfinished = metadata_scope(client.call("search_start", {"host": HOST, "root": target + "/data", "kind": "content", "query": "rollback-owned-search", "timeout_seconds": 5}), search=True)
        interrupted_id = unfinished["search"]["search_id"]; owned_searches.add(interrupted_id)
        unfinished_record = folder / "state/search" / (interrupted_id + ".json")
        assert json.loads(unfinished_record.read_text())["state"] == "running"
        report["unfinished_search_scope"] = "real launched search with unpolled controller receipt; no running target-worker claim"
        passed("v8 creates owned in-flight once-job and real persistent terminal", {"job_id": jid, "job_state": initial_state["state"], "pty_session_id": sid, "pty_pid": pty_pid})
        stop_controller()
        start_controller(old_binary, "v4-rollback")
        passed("temporary old-controller rollback exposes all original 50 exact definitions", {"tool_count": catalog(old_contract)})
        reused = client.call("process_start", job_params)
        assert reused["reused"] and reused["job"]["id"] == jid
        rolled_job = client.call("process_status", {"host": HOST, "job_id": jid})
        assert rolled_job["state"] == "running", "owned release-gated job ended before rollback's running proof"
        assert new_process_observation() == new_process_pin and legacy_artifacts(jid) == new_runner_pin
        assert "BEGIN\n" in client.call("process_read", {"host": HOST, "job_id": jid, "limit": 4096})["stdout"]["text"]
        middle_page = client.call("process_read", {"host": HOST, "job_id": jid, "stdout_offset": 2, "stderr_offset": 0, "limit": 4096})
        assert bytes.fromhex(middle_page["stdout"]["bytes_hex"]) == b"GIN\n" and middle_page["stdout"]["next_offset"] == 6
        reused_pty = client.call("pty_start", pty_params)
        assert reused_pty["reused"] and reused_pty["session_id"] == sid and reused_pty["status"]["pid"] == pty_pid
        v4_input = {"host": HOST, "session_id": sid, "data": "V4\n", "request_id": key + "-input-v4"}
        assert client.call("pty_write", v4_input)["complete"]
        assert pty_until(sid, "ACK_V4")["status"]["pid"] == pty_pid
        passed("old v4 controller reuses same running v8-owned job and same-PID PTY with actual stdin/stdout")
        stop_controller()
        start_controller(candidate, "v8-forward")
        assert catalog(candidate_contract) == candidate_contract["tool_count"]
        assert client.call("process_start", job_params)["job"]["id"] == jid
        same_pty = client.call("pty_start", pty_params)
        assert same_pty["reused"] and same_pty["session_id"] == sid and same_pty["status"]["pid"] == pty_pid
        assert client.call("pty_write", v4_input)["reused"]
        assert client.call("pty_write", {"host": HOST, "session_id": sid, "data": "FORWARD\n", "request_id": key + "-input-forward"})["complete"]
        final_pty = pty_until(sid, "ACK_FORWARD")
        assert final_pty["text"].count("ACK_V8") == 1 and final_pty["text"].count("ACK_V4") == 1 and final_pty["text"].count("ACK_FORWARD") == 1
        assert new_process_observation() == new_process_pin and legacy_artifacts(jid) == new_runner_pin
        owned_target("import json;(base/'data'/'release-new').write_text('owned release');print(json.dumps({'released':True}))")
        for _ in range(10):
            final_job = client.call("process_wait", {"host": HOST, "job_id": jid, "timeout_seconds": 5})
            if final_job["state"] != "running":
                break
        assert final_job["state"] == "succeeded" and final_job["output_complete"]
        logs = client.call("process_read", {"host": HOST, "job_id": jid, "limit": 4096})
        assert logs["stdout"]["text"] == "BEGIN\nEND\n" and logs["stderr"]["text"] == ""
        final_page = client.call("process_read", {"host": HOST, "job_id": jid, "stdout_offset": 6, "stderr_offset": 0, "limit": 4096})
        assert bytes.fromhex(final_page["stdout"]["bytes_hex"]) == b"END\n" and final_page["stdout"]["eof"] is True
        assert final_page["stdout"]["next_offset"] == 10 and final_page["stderr"]["next_offset"] == 0
        once = ssh("import pathlib,json;print(json.dumps({'content':pathlib.Path(" + repr(target + "/data/once") + ").read_text()}))")
        assert once["content"] == "1"
        passed("forward v8 same identities, once-only process side effect and deduplicated persistent PTY input", {"job_id": jid, "pty_session_id": sid, "pty_pid": pty_pid, "once_bytes": 1, "process_identity": new_process_pin, "runner_binding": new_runner_pin})
        resumed = metadata_scope(client.call("request_history", {"after_id": owner_cursor}))
        fresh = metadata_scope(client.call("request_history", {"limit": 32}))
        assert owner_cursor in {row["request_id"] for row in fresh["requests"]}
        old_page = metadata_scope(client.call("search_results", {"search_id": search_id, "cursor": 0, "limit": 2}), search=True)
        assert hashlib.sha256(json.dumps(old_page["snapshot"], sort_keys=True, separators=(",", ":")).encode()).hexdigest() == stable_snapshot_sha
        before_count = native_ssh_count()
        interrupted = metadata_scope(client.call("search_results", {"search_id": interrupted_id}), search=True)
        assert interrupted["search"]["state"] == "interrupted" and interrupted["snapshot_ready"] is False
        assert interrupted["search"]["reason"] == "controller_restarted_no_session_resume"
        assert interrupted["unfinished_search_after_controller_restart"] == "interrupted_without_relaunch"
        assert native_ssh_count() == before_count
        stopped = client.call("search_stop", {"search_id": interrupted_id})
        assert stopped["already_terminal"] is True and stopped["stop_requested"] is False
        assert native_ssh_count() == before_count
        listed = client.call("search_list", {"limit": 32})
        assert {row["search_id"] for row in listed["searches"]} == owned_searches
        assert native_ssh_count() == before_count
        passed("same credential resumes old history/cursor and immutable terminal search; unfinished controller metadata interrupts without RPC or replay",
               {"cursor_retained": True, "terminal_snapshot_sha256": stable_snapshot_sha,
                "interrupted_search_id": interrupted_id, "interrupted_lookup_remote_calls": 0,
                "authenticated_chatgpt_caller_isolation": False})

        # Reverse leg: create genuine legacy references with the preserved v4,
        # never adopt or retrofit their missing supervisor/nonce authority.
        stop_controller(); start_controller(old_binary, "v4-legacy-create")
        assert catalog(old_contract) == 50
        legacy_code = """import json,os,pathlib,signal,time,subprocess,sys
base=pathlib.Path('.');once=base/'legacy-once';f=once.open('a');f.write('1');f.flush();os.fsync(f.fileno());f.close()
if sys.platform=='linux':
 raw=pathlib.Path('/proc/'+str(os.getpid())+'/stat').read_text();ticks=int(raw.rsplit(') ',1)[1].split()[19])
 identity={'kind':'proc_start_ticks','value':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()+':'+str(ticks)}
else:
 identity={'kind':'ps_lstart','value':subprocess.check_output(['ps','-p',str(os.getpid()),'-o','lstart='],text=True,timeout=3).strip()}
assert identity['value']
term_count=0;tick=0
def store():
 p=base/'legacy-activity.json';t=base/'legacy-activity.tmp';t.write_text(json.dumps({'pid':os.getpid(),'uid':os.geteuid(),'identity':identity,'tick':tick,'term_count':term_count}));os.replace(t,p)
def term(sig,frame):
 global term_count
 term_count+=1;store()
signal.signal(signal.SIGTERM,term);store();print('LEGACY_BEGIN',flush=True)
deadline=time.monotonic()+180
while not (base/'release-legacy').exists() and time.monotonic()<deadline:
 tick+=1;store();time.sleep(.1)
print('LEGACY_END',flush=True)
"""
        legacy_params = {"host": HOST, "executable": "/usr/bin/python3", "args": ["-u", "-c", legacy_code],
                         "cwd": target + "/data", "timeout_seconds": 240, "idempotency_key": legacy_job_key}
        legacy_start = client.call("process_start", legacy_params)
        legacy_jid = legacy_start["job"]["id"]; known_jobs.add(legacy_jid)
        for _ in range(50):
            legacy_output = client.call("process_read", {"host": HOST, "job_id": legacy_jid, "limit": 4096})
            if legacy_output["stdout"]["text"] == "LEGACY_BEGIN\n":break
            time.sleep(.1)
        else:raise AssertionError("owned legacy job BEGIN absent")
        legacy_before = legacy_observation()
        legacy_pin = legacy_artifacts(legacy_jid)
        report["legacy_binding_observation"] = legacy_pin
        report["legacy_physical_process_before"] = legacy_before
        save()
        # The preserved v4 already has a supervisor start identity. Its actual
        # missing launch nonce, not absence of all old identity metadata, is the
        # new cancellation authority boundary. Never delete/adopt that identity.
        assert legacy_pin["launch_nonce_present"] is False, "preserved v4 unexpectedly supplied a V8 launch nonce"
        assert legacy_pin["cancel_request_present"] is False and legacy_before["term_count"] == 0
        legacy_pty_params = {**pty_params, "idempotency_key": legacy_pty_key}
        legacy_terminal = client.call("pty_start", legacy_pty_params)
        legacy_sid = legacy_terminal["session_id"]; known_ptys.add(legacy_sid)
        assert legacy_sid == expected_legacy_pty and legacy_terminal["persistent_across_runtime_restart"]
        legacy_ready = pty_until(legacy_sid, "OWNER_PID=")
        legacy_pid = int(re.search(r"OWNER_PID=(\d+)", legacy_ready["text"]).group(1))
        legacy_v4_input = {"host": HOST, "session_id": legacy_sid, "data": "LEGACY_V4\n", "request_id": key + "-legacy-input-v4"}
        assert client.call("pty_write", legacy_v4_input)["complete"]
        pty_until(legacy_sid, "ACK_LEGACY_V4")
        legacy_first_page, legacy_first_bytes = pty_cursor(legacy_sid)
        legacy_offset = legacy_first_page["next_offset"]
        passed("old v4 creates genuine unbound active job and persistent same-PID PTY", {"job_id": legacy_jid,
               "process_pid": legacy_before["pid"], "process_identity": legacy_before["identity"],
               "pty_session_id": legacy_sid, "pty_pid": legacy_pid, "legacy_binding": legacy_pin})
        stop_controller(); start_controller(candidate, "v8-legacy-forward")
        assert catalog(candidate_contract) == candidate_contract["tool_count"]
        legacy_status = client.call("process_status", {"host": HOST, "job_id": legacy_jid})
        assert legacy_status["state"] == "owner_unknown" and legacy_status["status_authoritative"] is False
        assert legacy_status["automatic_retry"] is False
        prefix = client.call("process_read", {"host": HOST, "job_id": legacy_jid, "stdout_offset": 0, "stderr_offset": 0, "limit": 3})
        assert bytes.fromhex(prefix["stdout"]["bytes_hex"]) == b"LEG" and prefix["stdout"]["next_offset"] == 3
        legacy_cancel = client.call("process_cancel", {"host": HOST, "job_id": legacy_jid, "grace_seconds": 1})
        assert legacy_cancel["result"] == "cancel_unknown" and legacy_cancel["outcome"] == "unknown"
        assert legacy_cancel["automatic_retry"] is False and legacy_cancel["termination_confirmed"] is False
        after_refusal = legacy_observation(legacy_before["tick"])
        assert after_refusal["pid"] == legacy_before["pid"] and after_refusal["identity"] == legacy_before["identity"]
        assert after_refusal["term_count"] == 0 and legacy_artifacts(legacy_jid) == legacy_pin
        v8_legacy_pty = client.call("pty_start", legacy_pty_params)
        assert v8_legacy_pty["reused"] and v8_legacy_pty["session_id"] == legacy_sid and v8_legacy_pty["status"]["pid"] == legacy_pid
        assert client.call("pty_write", legacy_v4_input)["reused"]
        legacy_v8_input = {"host": HOST, "session_id": legacy_sid, "data": "LEGACY_V8\n", "request_id": key + "-legacy-input-v8"}
        assert client.call("pty_write", legacy_v8_input)["complete"]
        pty_until(legacy_sid, "ACK_LEGACY_V8")
        legacy_middle_page, legacy_middle_bytes = pty_cursor(legacy_sid, legacy_offset)
        assert legacy_middle_page["status"]["pid"] == legacy_pid
        legacy_offset = legacy_middle_page["next_offset"]
        passed("v8 missing legacy nonce refuses cancellation without effect, preserves active process/archives and same-PID PTY",
               {"status": legacy_status, "cancel_response": legacy_cancel, "physical_progress_before": legacy_before["tick"],
                "physical_progress_after": after_refusal["tick"], "term_signals_observed": 0, "authority_adopted": False})
        stop_controller(); start_controller(old_binary, "v4-legacy-return")
        assert catalog(old_contract) == 50
        assert client.call("process_start", legacy_params)["job"]["id"] == legacy_jid
        legacy_again = legacy_observation(after_refusal["tick"])
        assert legacy_again["pid"] == legacy_before["pid"] and legacy_again["term_count"] == 0
        assert client.call("pty_start", legacy_pty_params)["status"]["pid"] == legacy_pid
        assert client.call("pty_write", legacy_v8_input)["reused"]
        v4_return_input = {"host": HOST, "session_id": legacy_sid, "data": "LEGACY_V4_RETURN\n", "request_id": key + "-legacy-input-v4-return"}
        assert client.call("pty_write", v4_return_input)["complete"]
        pty_until(legacy_sid, "ACK_LEGACY_V4_RETURN")
        stop_controller(); start_controller(candidate, "v8-legacy-final")
        assert catalog(candidate_contract) == candidate_contract["tool_count"]
        assert client.call("process_status", {"host": HOST, "job_id": legacy_jid})["status_authoritative"] is False
        assert client.call("pty_start", legacy_pty_params)["status"]["pid"] == legacy_pid
        assert client.call("pty_write", v4_return_input)["reused"]
        assert client.call("pty_write", {"host": HOST, "session_id": legacy_sid, "data": "LEGACY_V8_RETURN\n", "request_id": key + "-legacy-input-v8-return"})["complete"]
        legacy_final_pty = pty_until(legacy_sid, "ACK_LEGACY_V8_RETURN")
        final_lines = legacy_final_pty["text"].splitlines()
        for marker in ("ACK_LEGACY_V4", "ACK_LEGACY_V8", "ACK_LEGACY_V4_RETURN", "ACK_LEGACY_V8_RETURN"):
            assert final_lines.count(marker) == 1
        legacy_final_page, legacy_final_bytes = pty_cursor(legacy_sid, legacy_offset)
        combined_pty = legacy_first_bytes + legacy_middle_bytes + legacy_final_bytes
        whole_pty = pty_cursor(legacy_sid)[1]
        assert combined_pty == whole_pty and legacy_final_page["status"]["pid"] == legacy_pid
        assert legacy_artifacts(legacy_jid) == legacy_pin
        release_jobs(); legacy_final = await_terminal(legacy_jid)
        assert legacy_final["state"] == "succeeded" and legacy_final["exit_code"] == 0
        legacy_logs = client.call("process_read", {"host": HOST, "job_id": legacy_jid, "stdout_offset": 3, "stderr_offset": 0, "limit": 4096})
        assert bytes.fromhex(legacy_logs["stdout"]["bytes_hex"]) == b"ACY_BEGIN\nLEGACY_END\n"
        assert legacy_logs["stdout"]["eof"] is True and bytes.fromhex(legacy_logs["stderr"]["bytes_hex"]) == b""
        legacy_once = owned_target("import json;print(json.dumps({'once':(base/'data'/'legacy-once').read_text(),'term_count':json.loads((base/'data'/'legacy-activity.json').read_text())['term_count']}))")
        assert legacy_once == {"once": "1", "term_count": 0}
        passed("old-v4→v8→v4→v8 preserves same IDs/PIDs, physical once=1, no signals/adoption and exact independent archive cursors",
               {"job_id": legacy_jid, "pty_session_id": legacy_sid, "pty_pid": legacy_pid,
                "once": 1, "term_count": 0, "pty_archive_sha256": hashlib.sha256(whole_pty).hexdigest()})

        # Reconnect rights never bypass current read-root policy. Change only
        # the disposable controller configuration; retain production policy.
        stop_controller()
        revoked = json.loads(json.dumps(saved_config)); revoked["hosts"][HOST]["allowed_read_path_prefixes"] = []
        config_path.write_text(json.dumps(revoked))
        start_controller(candidate, "v8-owned-read-policy-revoked")
        before_count = native_ssh_count()
        assert client.call("search_list", {"limit": 32})["searches"] == []
        for old_search in owned_searches:
            for tool in ("search_results", "search_stop"):
                refused = client.call(tool, {"search_id": old_search}, denied=True)
                assert target not in refused and old_search not in refused
        assert native_ssh_count() == before_count
        assert owner_cursor in {row["request_id"] for row in metadata_scope(client.call("request_history", {"limit": 32}))["requests"]}
        passed("same credential retained metadata respects current search read-root revocation with zero target RPC")
        stop_controller(); config_path.write_text(json.dumps(saved_config)); start_controller(candidate, "v8-owned-policy-restored")
        assert {row["search_id"] for row in client.call("search_list", {"limit": 32})["searches"]} == owned_searches
        report["passed"] = len(report["checks"])
        report["workflow_passed"] = True
    except BaseException as error:
        frames = traceback.extract_tb(error.__traceback__)
        report["failure_type"] = type(error).__name__
        report["failure_phase"] = report.get("active_phase", "fixture preparation")
        report["failure_frames"] = [{"file": str(frame.filename), "line": frame.lineno,
                                     "function": frame.name} for frame in frames]
        fallback = type(error).__name__ + (" at " + pathlib.Path(frames[-1].filename).name + ":" + str(frames[-1].lineno) if frames else "")
        report["failure"] = redact((str(error) or fallback)[:4096])
        report["traceback"] = "\n".join("File " + frame.filename + ", line " + str(frame.lineno) + ", in " + frame.name for frame in frames)
        # Stack identity only: never repr local variables, HTTP headers or tokens.
    finally:
        cleanup_errors = []
        try:
            if saved_config is not None:
                config_path.write_text(json.dumps(saved_config))
            release_jobs()
            recover_owned_refs()
            if target is not None and (known_jobs or known_ptys):
                if controller is None or controller.poll() is not None or client is None:
                    stop_controller()
                    start_controller(candidate, "v8-owned-cleanup")
                for jid in known_jobs:
                    status = await_terminal(jid, timeout=20)
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
                terminal_searches = owned_target("import json,time; ids=" + repr(sorted(owned_searches)) + ";deadline=time.monotonic()+15;result={}\nfor identity in ids:\n p=base/'remote-state'/'search'/identity/'record.json'\n while True:\n  row=json.loads(p.read_text())\n  if row['state'] in ('completed','limited','cancelled','failed','interrupted'):break\n  if time.monotonic()>deadline:raise ValueError('owned search worker not confirmed terminal; fixture retained')\n  time.sleep(.05)\n result[identity]={'state':row['state'],'snapshot_ready':row['snapshot_ready']}\nprint(json.dumps(result))")
                report["owned_search_workers_terminal"] = terminal_searches
                # Archive bounded test output before removing only this owned target tree.
                archives = ssh("import pathlib,json,hashlib,os,shutil; p=pathlib.Path(" + repr(target) + ");assert p.is_absolute() and p.name.startswith('hepta-v8-rollback-target-') and not p.is_symlink() and p.stat().st_uid==os.getuid();assert (p/'.fixture-owner').is_file() and not (p/'.fixture-owner').is_symlink() and (p/'.fixture-owner').read_text()==" + repr(key) + ";a=[]\nfor f in p.rglob('*.log'):\n if f.is_file() and not f.is_symlink():\n  b=f.read_bytes();assert len(b)<=65536;a.append({'path':str(f.relative_to(p)),'sha256':hashlib.sha256(b).hexdigest(),'text':b.decode('utf-8','replace')})\nshutil.rmtree(p);print(json.dumps({'archives':a,'removed':not p.exists()}))")
                report["target_archives"] = archives["archives"]
                report["cleanup"]["target_fixture_removed"] = archives["removed"]
        except BaseException as error:
            cleanup_errors.append(redact(str(error)[:4096]))
        finally:
            stop_controller()
            report["private_authentication_cleanup_pending"] = True
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
                report["harness_inputs_after"] = harness_inputs()
                report["harness_inputs_stable"] = report["harness_inputs_after"] == member_inputs_before
                report["source_fingerprint_stable"] = source_after["source_code_fingerprint"] == source_before["source_code_fingerprint"]
                report["source_head_stable"] = source_after["base_HEAD"] == source_before["base_HEAD"]
                report["candidate_hashes_stable"] = (sha256(candidate) == args.expected_candidate_sha256
                    and sha256(args.candidate_contract) == report["candidate_contract_sha256"]
                    and sha256(pathlib.Path(__file__).resolve()) == report["harness_sha256"]
                    and report["source_fingerprint_stable"] and report["source_head_stable"]
                    and report["harness_inputs_stable"])
            except Exception as error:
                report["candidate_hashes_stable"] = False
                report["source_observation_error_type"] = type(error).__name__
            report["complete"] = bool(report.get("workflow_passed") and not cleanup_errors
                and report["cleanup"]["target_fixture_removed"] and report["service_identity_stable"]
                and report["installed_production_identity_stable"] and report["candidate_hashes_stable"])
            if report["complete"]:
                shutil.rmtree(auth_directory)
                report["private_authentication_cleanup_pending"] = False
                report["private_authentication_removed"] = True
            else:
                report["retained_private_authentication_directory"] = str(auth_directory)
                report["private_authentication_mode"] = "0700 directory; 0600 single-link token; never commit"
            save()
    print("TEMPORARY_ROLLBACK_COMPLETE", report["complete"], flush=True)
    if not report["complete"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Six original running jobs survive SIGKILL of their own isolated controller.

Run only on x230 with the existing frozen six-host operator records and a held
current SSH agent. Every host receives one fresh private fixture and one new
native job. Failed or uncertain effects retain their original identities; this
driver never relaunches, cleans remote artifacts, or changes a runtime service.
This tests controller death, not target reboot, power loss or owner transfer.
"""
import argparse
import base64
import concurrent.futures
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shlex
import signal
import socket
import subprocess
import sys
import threading
import time

sys.dont_write_bytecode = True
import x230_observation_benchmark as bench

DEV_ROOT = Path("/home/qian/hepta-runtime-optimization-20261023")
HOSTS = ("ai395", "mac", "main", "pocket4", "rog", "x230")
INPUT = ("0123456789abcdef" * 256).encode()
MARKER = b"EXECUTED\n"
RELEASE = b"RELEASE\n"
GATE_SECONDS = 210
TARGET_SECONDS = 240
REMOTE_LIMIT = 2 * 1024 * 1024

# All filesystem operations are relative to pinned descriptors. A receipt can
# identify only the new fixture created by this invocation; never an old residue.
REMOTE = r'''import base64, hashlib, json, os, re, socket, stat, sys
p = json.loads(base64.b64decode(sys.argv[1], validate=True))
assert p["mode"] in ("prepare", "inspect", "release")
assert p["host"] in ("ai395", "mac", "main", "pocket4", "rog", "x230")
assert re.fullmatch(r"[0-9a-f]{24}", p["nonce"])
name = "running-recovery-" + p["nonce"] + "-" + p["host"]
assert p["name"] == name
expected_platform = "darwin" if p["host"] == "mac" else "linux"
assert sys.platform == expected_platform
def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
def identity(info):
    return [info.st_dev, info.st_ino, info.st_uid, info.st_mode]
def stamp(info):
    return identity(info) + [info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]
def directory_at(parent, component):
    assert component and component not in (".", "..") and "/" not in component
    return os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                   dir_fd=parent)
def absolute_directory(path):
    assert path.startswith("/") and path != "/"
    parts = path.split("/")[1:]
    assert all(x and x not in (".", "..") for x in parts)
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    for component in parts:
        child = directory_at(fd, component)
        os.close(fd)
        fd = child
    info = os.fstat(fd)
    assert info.st_uid == os.geteuid() and not stat.S_IMODE(info.st_mode) & 0o022
    return fd
def checked_read(parent, component, limit, optional=False):
    assert "/" not in component and component not in (".", "..")
    try:
        fd = os.open(component, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                     dir_fd=parent)
    except FileNotFoundError:
        if optional:
            return None
        raise
    try:
        before = os.fstat(fd)
        assert stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
        assert before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600
        assert 0 <= before.st_size <= limit
        with os.fdopen(os.dup(fd), "rb") as stream:
            data = stream.read(limit + 1)
        after = os.stat(component, dir_fd=parent, follow_symlinks=False)
        assert len(data) == before.st_size and stamp(before) == stamp(os.fstat(fd)) == stamp(after)
        return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                "base64": base64.b64encode(data).decode()}
    finally:
        os.close(fd)
def exclusive_write(parent, component, data):
    fd = os.open(component, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=parent)
    try:
        with os.fdopen(os.dup(fd), "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        info = os.fstat(fd)
        assert info.st_uid == os.geteuid() and info.st_nlink == 1
        assert stat.S_IMODE(info.st_mode) == 0o600
    finally:
        os.close(fd)
    os.fsync(parent)
base = absolute_directory(p["base"])
if p["mode"] == "prepare":
    os.mkdir(name, mode=0o700, dir_fd=base)
fixture = directory_at(base, name)
info = os.fstat(fixture)
assert info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700
origin = {"schema": "hepta-six-running-fixture/v1", "nonce": p["nonce"], "host": p["host"],
          "base": p["base"], "name": name, "source_job_id": p["source_job_id"],
          "source_record_sha256": p["source_record_sha256"], "fixture_identity": identity(info)}
if p["mode"] == "prepare":
    exclusive_write(fixture, ".canary-origin.json", canonical(origin))
    os.fsync(base)
else:
    assert p["fixture_identity"] == identity(info)
    stored = checked_read(fixture, ".canary-origin.json", 8192)
    assert base64.b64decode(stored["base64"], validate=True) == canonical(origin)
result = {"mode": p["mode"], "host": p["host"], "nonce": p["nonce"],
          "fixture_identity": identity(info), "hostname": socket.gethostname(),
          "platform": sys.platform, "uid": os.geteuid(), "files": {}}
if p["mode"] == "release":
    assert re.fullmatch(r"[0-9a-f]+-[0-9a-f]+-[0-9a-f]+", p["job_id"])
    # Check the original request binding again before the single create-only gate.
    jobs = directory_at(fixture, "jobs")
    job = directory_at(jobs, p["job_id"])
    raw = checked_read(job, "request.json", 65536)
    request = json.loads(base64.b64decode(raw["base64"], validate=True))
    assert request["job_id"] == p["job_id"] and request["launch_nonce"] == p["launch_nonce"]
    marker = checked_read(fixture, "execution-marker", 128)
    assert base64.b64decode(marker["base64"], validate=True) == b"EXECUTED\n"
    assert checked_read(fixture, "release-marker", 128, optional=True) is None
    exclusive_write(fixture, "release-marker", b"RELEASE\n")
    result["files"]["release-marker"] = checked_read(fixture, "release-marker", 128)
elif p["mode"] == "inspect":
    assert re.fullmatch(r"[0-9a-f]+-[0-9a-f]+-[0-9a-f]+", p["job_id"])
    jobs = directory_at(fixture, "jobs")
    job = directory_at(jobs, p["job_id"])
    for component, limit in (("execution-marker", 128), ("release-marker", 128)):
        result["files"][component] = checked_read(fixture, component, limit, optional=True)
    assert type(p["terminal"]) is bool
    observed = [("stdin.bin", 4096), ("request.json", 65536),
                ("exit.json", 1048576), ("exit.witness.json", 4096)]
    if p["terminal"]:
        observed.extend((("stdout.log", 16384), ("stderr.log", 16384)))
    for component, limit in observed:
        result["files"][component] = checked_read(job, component, limit, optional=True)
assert identity(os.stat(name, dir_fd=base, follow_symlinks=False)) == identity(info)
print(json.dumps(result, sort_keys=True, separators=(",", ":")))
'''

CHILD = r'''import hashlib, json, os, stat, sys, time
data = sys.stdin.buffer.read()
p = json.loads(sys.argv[1])
assert len(data) == 4096 and hashlib.sha256(data).hexdigest() == p["stdin_sha256"]
fd = os.open(p["fixture"], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
info = os.fstat(fd)
assert [info.st_dev, info.st_ino, info.st_uid, info.st_mode] == p["fixture_identity"]
marker = os.open("execution-marker", os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW,
                 0o600, dir_fd=fd)
try:
    m = os.fstat(marker)
    assert stat.S_ISREG(m.st_mode) and m.st_nlink == 1 and m.st_uid == os.geteuid()
    assert stat.S_IMODE(m.st_mode) == 0o600
    assert os.write(marker, b"EXECUTED\n") == 9
    os.fsync(marker)
finally:
    os.close(marker)
os.fsync(fd)
print("BEGIN " + p["host"], flush=True)
print("HEPTA-CANARY-STDERR " + p["host"], file=sys.stderr, flush=True)
deadline = time.monotonic() + 210
while True:
    if time.monotonic() >= deadline:
        raise SystemExit("private release gate timed out")
    try:
        gate = os.open("release-marker", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                       dir_fd=fd)
    except FileNotFoundError:
        time.sleep(.05)
        continue
    with os.fdopen(gate, "rb") as stream:
        m = os.fstat(stream.fileno())
        assert stat.S_ISREG(m.st_mode) and m.st_nlink == 1 and m.st_uid == os.geteuid()
        assert stat.S_IMODE(m.st_mode) == 0o600 and stream.read(9) == b"RELEASE\n"
    break
print("END " + p["host"] + " " + hashlib.sha256(data).hexdigest(), flush=True)
'''


def decoded(files, name, required=True):
    item = files.get(name)
    if item is None:
        bench.need(not required, "missing independent file: " + name)
        return None
    raw = base64.b64decode(item["base64"], validate=True)
    bench.need(len(raw) == item["bytes"] and bench.digest(raw) == item["sha256"],
               "independent file transport digest differs: " + name)
    return raw


def private_wrapper(profile_data, agent, directory):
    directory.mkdir(mode=0o700)
    options = {
        "IdentityAgent": agent, "UserKnownHostsFile": profile_data["known_hosts"],
        "GlobalKnownHostsFile": "/dev/null", "BatchMode": "yes", "ConnectTimeout": "8",
        "ConnectionAttempts": "1", "StrictHostKeyChecking": "yes", "ForwardAgent": "no",
        "ForwardX11": "no", "ClearAllForwardings": "yes", "ControlMaster": "no",
        "ControlPath": "none", "ControlPersist": "no", "ProxyCommand": "none",
        "ProxyJump": "none", "IdentityFile": "none", "CertificateFile": "none",
        "PreferredAuthentications": "publickey", "PasswordAuthentication": "no",
        "KbdInteractiveAuthentication": "no", "IdentitiesOnly": "no", "AddKeysToAgent": "no",
        "UpdateHostKeys": "no", "KnownHostsCommand": "none", "LocalCommand": "none",
        "PermitLocalCommand": "no", "RequestTTY": "no",
    }
    command = ["/usr/bin/ssh", "-F", profile_data["ssh_config"]]
    for key, value in options.items():
        command.extend(["-o", key + "=" + value])
    raw = ("#!/bin/sh\nexec " + " ".join(map(shlex.quote, command)) + ' "$@"\n').encode()
    path = directory / "ssh"
    bench.create_file(path, raw, 0o700)
    return path, bench.digest(raw)



def collect_controller_records(registry, expected_ids, saved_records):
    """Read after shutdown; a partial failure must still retain every readable identity."""
    records, errors, observed = [], [], []
    try:
        paths = sorted(registry.glob("*.json")) if registry.exists() else []
    except OSError as error:
        return {"records": [], "errors": [{"path": str(registry), "error": str(error)}],
                "exact_original_set": False}
    for path in paths:
        row = {"path": str(path)}
        try:
            raw = bench.read_file(path, 65536)
            row["sha256"] = bench.digest(raw)
            value = json.loads(raw)
            host, job_id = value["host"], value["id"]
            row.update(job_id=job_id, host=host, launch_state=value["launch_state"],
                       idempotency_key=value.get("idempotency_key"),
                       remote_job_dir=value["remote_job_dir"],
                       original_bytes_unchanged=raw == saved_records.get(host))
            bench.need(path.name == job_id + ".json", "controller filename/identity mismatch")
            observed.append((host, job_id))
        except (OSError, ValueError, KeyError, TypeError, RuntimeError) as error:
            row["error"] = type(error).__name__ + ": " + str(error)[:1000]
            errors.append({"path": str(path), "error": row["error"]})
        records.append(row)
    exact = (not errors and len(paths) == len(observed) == 6
             and set(expected_ids) == set(saved_records) == set(HOSTS)
             and set(observed) == set(expected_ids.items())
             and all(row.get("original_bytes_unchanged") is True for row in records))
    return {"records": records, "errors": errors, "exact_original_set": exact}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--profile-template", type=Path, required=True)
    parser.add_argument("--frozen-jobs", type=Path, required=True)
    parser.add_argument("--socket-parent", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=2)
    args = parser.parse_args()
    out = args.out.absolute()
    bench.need(sys.platform == "linux" and out.parent == DEV_ROOT and out.resolve() == out
               and not os.path.lexists(out) and 1 <= args.workers <= 8,
               "run on x230 with a fresh direct child of the existing development directory")
    out.mkdir(mode=0o700)
    report_path = out / "report.json"
    report = {
        "schema": "hepta-six-running-controller-recovery/v1", "passed": False,
        "started_unix": time.time(), "controller_hostname": socket.gethostname(),
        "scope": "six new private operator jobs; same original jobs across owned-controller SIGKILL",
        "not_covered": ["target reboot", "physical power loss", "WAN partition",
                        "production owner transfer", "transactional exactly-once external effects"],
        "automatic_rpc_retries": 0, "remote_cleanup_operations": 0,
        "production_service_mutations": 0, "target_timeout_seconds": TARGET_SECONDS,
        "release_gate_timeout_seconds": GATE_SECONDS, "hosts": {}, "native_calls": [],
        "ssh_calls": [], "phases": [],
    }
    lock = threading.Lock()
    serial = 0
    active = None
    jobs = []
    binary_before = agent_before = None
    saved_records = {}
    requests = {}

    def checkpoint(phase):
        with lock:
            report["phase"] = phase
            report["phases"].append({"phase": phase, "unix": time.time()})
            bench.save_report(report_path, report)

    def next_serial():
        nonlocal serial
        with lock:
            serial += 1
            return serial

    def native(host, tool, arguments):
        bench.need(host in HOSTS and tool in {"process_start", "process_status", "process_read"}
                   and arguments["host"] == host, "unexpected native canary route")
        number = next_serial()
        row = {"sequence": number, "host": host, "tool": tool, "phase": report.get("phase"),
               "arguments_sha256": bench.digest(bench.canonical(arguments)),
               "started_unix": time.time(), "okay": False, "automatic_retry": False}
        started = time.monotonic()
        try:
            reply = active.rpc("tools/call", {"name": tool, "arguments": arguments}, timeout=50)
            raw = bench.canonical(reply)
            raw_path = out / f"native-{number:04d}-{host}-{tool}.json"
            bench.create_file(raw_path, raw)
            row.update(reply_path=str(raw_path), response_sha256=bench.digest(raw))
            bench.need("error" not in reply and not reply.get("result", {}).get("isError", False),
                       "native call refused: " + host + "/" + tool)
            texts = [item["text"] for item in reply["result"].get("content", [])
                     if item.get("type") == "text"]
            bench.need(texts, "native response has no JSON text")
            result = json.loads(texts[0])
            bench.need(result.get("audit_recorded") is True and "audit_warning" not in result,
                       "native result lacks durable audit acknowledgement")
            if tool != "process_start":
                bench.need(result.get("job_id") == arguments["job_id"], "observation identity changed")
            row["okay"] = True
            return result
        except BaseException as error:
            row["error"] = type(error).__name__ + ": " + str(error)[:1500]
            row["effect_unknown"] = tool == "process_start"
            raise
        finally:
            row["elapsed_ms"] = 1000 * (time.monotonic() - started)
            with lock:
                report["native_calls"].append(row)

    def remote(host, mode, extra=None):
        host_record = report["hosts"][host]
        payload = {key: host_record[key] for key in (
            "base", "name", "source_job_id", "source_record_sha256")}
        payload.update(host=host, nonce=report["nonce"], mode=mode)
        if mode != "prepare":
            payload["fixture_identity"] = host_record["prepare"]["fixture_identity"]
        if extra:
            payload.update(extra)
        number = next_serial()
        encoded = base64.b64encode(bench.canonical(payload)).decode()
        command = "/usr/bin/python3 -I -S - " + shlex.quote(encoded)
        row = {"sequence": number, "host": host, "mode": mode, "started_unix": time.time(),
               "payload_sha256": bench.digest(bench.canonical(payload)), "okay": False,
               "automatic_retry": False, "mutation_attempted": mode in {"prepare", "release"}}
        started = time.monotonic()
        try:
            result = subprocess.run([str(wrapper), "-T", host_record["ssh_target"], command],
                                    input=REMOTE.encode(), stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, timeout=20, check=False,
                                    env={"PATH": "/usr/bin:/bin", "LANG": "C", "SSH_AUTH_SOCK": agent})
            for stream, raw in (("stdout", result.stdout), ("stderr", result.stderr)):
                path = out / f"ssh-{number:04d}-{host}-{mode}.{stream}"
                bench.create_file(path, raw)
                row[stream] = {"path": str(path), "bytes": len(raw), "sha256": bench.digest(raw)}
            row["returncode"] = result.returncode
            bench.need(result.returncode == 0 and len(result.stdout) <= REMOTE_LIMIT
                       and len(result.stderr) <= 65536, "fixed SSH helper failed: " + host + "/" + mode)
            value = json.loads(result.stdout)
            bench.need(value.get("host") == host and value.get("mode") == mode
                       and value.get("nonce") == report["nonce"], "SSH helper identity differs")
            if mode != "prepare":
                bench.need(value["fixture_identity"] == host_record["prepare"]["fixture_identity"],
                           "remote fixture directory identity changed")
            row["okay"] = True
            return value
        except BaseException as error:
            row["error"] = type(error).__name__ + ": " + str(error)[:1500]
            row["effect_unknown"] = mode in {"prepare", "release"}
            if isinstance(error, subprocess.TimeoutExpired):
                for stream, raw in (("stdout", error.stdout or b""), ("stderr", error.stderr or b"")):
                    path = out / f"ssh-{number:04d}-{host}-{mode}-timeout.{stream}"
                    bench.create_file(path, raw)
                    row[stream] = {"path": str(path), "bytes": len(raw), "sha256": bench.digest(raw)}
            raise
        finally:
            row["elapsed_ms"] = 1000 * (time.monotonic() - started)
            with lock:
                report["ssh_calls"].append(row)

    def parallel(phase, operation):
        checkpoint(phase)
        failures = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            pending = {pool.submit(operation, host): host for host in HOSTS}
            for future in concurrent.futures.as_completed(pending):
                host = pending[future]
                try:
                    value = future.result()
                    report["hosts"][host][phase] = value
                except BaseException as error:
                    item = {"type": type(error).__name__, "reason": str(error)[:1500]}
                    report["hosts"][host][phase] = {"error": item}
                    failures.append(host)
                with lock:
                    bench.save_report(report_path, report)
        bench.need(not failures, phase + " failed on " + ",".join(failures))

    def ref(host):
        return {"host": host, "job_id": report["hosts"][host]["job_id"]}

    def read_args(host):
        return {**ref(host), "stdout_offset": 0, "stderr_offset": 0, "limit": 16384}

    def independent_running(host):
        proof = remote(host, "inspect", {"job_id": ref(host)["job_id"], "terminal": False})
        files = proof["files"]
        bench.need(decoded(files, "execution-marker") == MARKER, "execution marker is not exactly one")
        bench.need(decoded(files, "release-marker", False) is None, "gate released before recovery")
        bench.need(decoded(files, "stdin.bin") == INPUT, "original persisted stdin differs")
        request = json.loads(decoded(files, "request.json"))
        nonce = request.get("launch_nonce")
        bench.need(request.get("job_id") == ref(host)["job_id"]
                   and type(request.get("terminal_publication_protocol")) is int
                   and request["terminal_publication_protocol"] == 1
                   and isinstance(nonce, str) and re.fullmatch(r"[0-9a-f]{32}", nonce),
                   "remote original request publication binding differs")
        bench.need(decoded(files, "exit.json", False) is None
                   and decoded(files, "exit.witness.json", False) is None,
                   "original job has a terminal receipt before release")
        return {"proof": proof, "launch_nonce": nonce}

    def close_checked():
        nonlocal active
        receipt = active.close()
        active = None
        report["shutdown"] = receipt
        bench.need(receipt["exit_code"] == 0 and receipt["shutdown_method"] == "stdin_eof"
                   and not receipt["observed_descendant_survivors"]
                   and receipt["reader_error"] is None and receipt["unmatched_responses"] == 0,
                   "restarted private controller normal shutdown differs")
        return receipt

    try:
        checkpoint("preflight")
        jobs = bench.load_jobs(args.frozen_jobs)
        bench.need(tuple(job["host"] for job in jobs) == HOSTS, "frozen host membership/order differs")
        report["nonce"] = secrets.token_hex(12)
        report["script_sha256"] = bench.digest(bench.read_file(Path(__file__), 262144))
        report["benchmark_helper_sha256"] = bench.digest(bench.read_file(Path(bench.__file__), 262144))
        report["remote_helper_sha256"] = bench.digest(REMOTE.encode())
        report["workload_sha256"] = bench.digest(CHILD.encode())
        agent = os.environ.get("SSH_AUTH_SOCK", "")
        bench.need(agent.startswith("/"), "held current SSH_AUTH_SOCK is required")
        agent_before = bench.agent_identity(agent)
        candidate = args.candidate.absolute()
        binary_before = bench.digest(bench.read_file(candidate, 128 * 1024 * 1024))
        report["candidate_sha256"] = binary_before
        profile, report["profile"] = bench.fresh_profile(
            args.profile_template, out / "profile", args.socket_parent, agent)
        profile_data = json.loads(bench.read_file(profile))
        wrapper, report["ssh_wrapper_sha256"] = private_wrapper(profile_data, agent, out / "bin")
        for job in jobs:
            original = job["record"]
            bench.need(original["executable"] == "/usr/bin/python3"
                       and original["args"][:2] == ["-I", "-S"]
                       and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", original["ssh_target"]),
                       "original interpreter or fixed SSH alias provenance differs")
            old_job = PurePosixPath(original["remote_job_dir"])
            bench.need(old_job.is_absolute() and old_job.name == original["id"]
                       and old_job.parent.name == "jobs" and ".." not in old_job.parts,
                       "original remote state provenance differs")
            base = old_job.parent.parent
            name = "running-recovery-" + report["nonce"] + "-" + job["host"]
            report["hosts"][job["host"]] = {
                "base": str(base), "name": name, "fixture": str(base / name),
                "ssh_target": original["ssh_target"], "executable": original["executable"],
                "source_job_id": job["id"], "source_record_sha256": job["record_sha256"],
                "source_record_path": str(job["path"]), "release_attempted": False,
            }
        checkpoint("fixture_creation_intents")
        parallel("prepare", lambda host: remote(host, "prepare"))
        report["distinct_reported_hostnames"] = len({
            report["hosts"][host]["prepare"]["hostname"] for host in HOSTS}) == 6
        bench.need(report["distinct_reported_hostnames"],
                   "six SSH aliases did not report six distinct hostnames; do not infer six machines")
        state = out / "state"
        state.mkdir(mode=0o700)
        (state / "jobs").mkdir(mode=0o700)
        config_hosts = {}
        input_sha = bench.digest(INPUT)
        for host in HOSTS:
            item = report["hosts"][host]
            config_hosts[host] = {
                "execution_mode": "operator", "ssh_target": item["ssh_target"],
                "platform": "macos" if host == "mac" else "linux",
                "remote_state_dir": item["fixture"], "allow_execute": True,
                "allow_pty": False, "allow_write": False, "allow_job_network": True,
                "allow_detached_fallback": host == "mac", "privileged_actions": {},
            }
            child_config = {
                "host": host, "fixture": item["fixture"],
                "fixture_identity": item["prepare"]["fixture_identity"], "stdin_sha256": input_sha,
            }
            request = {
                "host": host, "executable": item["executable"],
                "args": ["-I", "-S", "-u", "-c", CHILD, bench.canonical(child_config).decode().strip()],
                "cwd": item["fixture"], "env": {}, "stdin": INPUT.decode(),
                "timeout_seconds": TARGET_SECONDS,
                "idempotency_key": "six-running-" + report["nonce"] + "-" + host,
            }
            requests[host] = request
            bench.create_file(out / (host + "-request.json"), bench.canonical(request))
            item.update(request_sha256=bench.digest(bench.canonical(request)),
                        idempotency_key=request["idempotency_key"])
        config = out / "runtime.json"
        bench.create_file(config, bench.canonical({
            "state_dir": str(state), "controller_workspace_roots": [], "hosts": config_hosts}))
        report.update(stdin_bytes=len(INPUT), stdin_sha256=input_sha, runtime_config=str(config))
        first = out / "first-controller"
        first.mkdir(mode=0o700)
        active = bench.Controller(candidate, config, profile, first, args.workers, path_prefix=wrapper.parent)
        report["first_startup"] = active.startup

        def launch(host):
            result = native(host, "process_start", requests[host])
            record = result["job"]
            bench.need(result.get("reused") is False and record["host"] == host
                       and record["launch_state"] == "launched" and result["launch"]["ok"] is True,
                       "new private job not acknowledged")
            job_id = record["id"]
            bench.need(re.fullmatch(r"[0-9a-f]+-[0-9a-f]+-[0-9a-f]+", job_id)
                       and PurePosixPath(record["remote_job_dir"])
                       == PurePosixPath(report["hosts"][host]["fixture"]) / "jobs" / job_id,
                       "new job escaped private fixture")
            raw = bench.read_file(state / "jobs" / (job_id + ".json"), 65536)
            with lock:
                report["hosts"][host]["job_id"] = job_id
                saved_records[host] = raw
            return {"job": record, "launch": result["launch"], "record_sha256": bench.digest(raw)}

        parallel("launch", launch)

        def confirm_running(host):
            deadline = time.monotonic() + 20
            while True:
                status = native(host, "process_status", ref(host))
                output = native(host, "process_read", read_args(host))
                prefix = bytes.fromhex(output["stdout"]["bytes_hex"])
                expected = ("BEGIN " + host + "\n").encode()
                bench.need(status.get("state") in {"running", "activating"}
                           and prefix in (b"", expected), "job became terminal or output differed before crash")
                if status.get("state") == "running" and prefix == expected:
                    return {"status": status, "stdout_sha256": bench.digest(prefix)}
                bench.need(time.monotonic() < deadline, "running BEGIN confirmation deadline")
                time.sleep(.2)

        parallel("before_crash_running", confirm_running)
        parallel("before_crash_independent", independent_running)
        checkpoint("kill_only_owned_controller")
        bench.need(active.child.poll() is None and bench.process_stat(active.child.pid)[0] == active.birth,
                   "controller identity changed before intentional SIGKILL")
        pidfd = os.pidfd_open(active.child.pid, 0)
        try:
            bench.need(bench.process_stat(active.child.pid)[0] == active.birth,
                       "controller identity changed after pidfd open")
            signal.pidfd_send_signal(pidfd, signal.SIGKILL)
        finally:
            os.close(pidfd)
        active.child.wait(timeout=10)
        time.sleep(.3)
        report["intentional_crash"] = active.close()
        active = None
        crash = report["intentional_crash"]
        bench.need(crash["exit_code"] == -signal.SIGKILL and not crash["observed_descendant_survivors"]
                   and crash["reader_error"] is None and crash["unmatched_responses"] == 0,
                   "owned-controller abrupt process cleanup differs")
        bench.need(bench.agent_identity(agent) == agent_before, "held agent changed before restart")
        restart = out / "restarted-controller"
        restart.mkdir(mode=0o700)
        active = bench.Controller(candidate, config, profile, restart, args.workers, path_prefix=wrapper.parent)
        report["restart_startup"] = active.startup

        def recover(host):
            status = native(host, "process_status", ref(host))
            bench.need(status.get("state") == "running", "original job not running after restart")
            reused = native(host, "process_start", requests[host])
            bench.need(reused.get("reused") is True and reused.get("retried_launch") is False
                       and reused["job"]["id"] == ref(host)["job_id"] and reused.get("launch") is None
                       and reused.get("status", {}).get("job_id") == ref(host)["job_id"]
                       and reused["status"].get("state") == "running",
                       "same-key lookup did not retain running original without relaunch")
            bench.need(bench.read_file(state / "jobs" / (ref(host)["job_id"] + ".json"), 65536)
                       == saved_records[host], "controller job record changed during reuse")
            return {"first_status": status, "same_key_reuse": reused}

        parallel("recover_same_original", recover)
        parallel("after_crash_independent", independent_running)
        for host in HOSTS:
            before = report["hosts"][host]["before_crash_independent"]
            after = report["hosts"][host]["after_crash_independent"]
            bench.need(before["launch_nonce"] == after["launch_nonce"]
                       and before["proof"]["files"]["request.json"] == after["proof"]["files"]["request.json"],
                       "original remote request changed across controller crash")
            report["hosts"][host]["release_attempted"] = True
        # Persist every gate intent before any release RPC. Each is sent once.
        checkpoint("release_create_only_intents")

        def release(host):
            return remote(host, "release", {
                "job_id": ref(host)["job_id"],
                "launch_nonce": report["hosts"][host]["after_crash_independent"]["launch_nonce"]})

        parallel("release", release)

        def complete(host):
            deadline = time.monotonic() + 45
            while True:
                status = native(host, "process_status", ref(host))
                if status.get("state") == "succeeded":
                    break
                bench.need(status.get("state") in {"running", "activating", "finalizing"}
                           and time.monotonic() < deadline, "original job failed or did not finish")
                time.sleep(.3)
            expected_stdout = ("BEGIN " + host + "\nEND " + host + " " + input_sha + "\n").encode()
            expected_stderr = ("HEPTA-CANARY-STDERR " + host + "\n").encode()
            bench.need(status.get("exit_code") == 0 and status.get("output_complete") is True
                       and status.get("output_durable") is True
                       and status.get("terminal_publication_confirmed") is True
                       and status.get("log_synced") == {"stdout": True, "stderr": True}
                       and status.get("log_truncated") == {"stdout": False, "stderr": False}
                       and status.get("log_errors") == {"stdout": None, "stderr": None}
                       and not status.get("timed_out") and not status.get("cancelled"),
                       "terminal durable capture receipt differs")
            bench.need(status.get("log_bytes") == {
                "stdout": {"seen": len(expected_stdout), "stored": len(expected_stdout)},
                "stderr": {"seen": len(expected_stderr), "stored": len(expected_stderr)}},
                "terminal log byte counters differ")
            output = native(host, "process_read", read_args(host))
            proof = remote(host, "inspect", {"job_id": ref(host)["job_id"], "terminal": True})
            files = proof["files"]
            bench.need(decoded(files, "stdin.bin") == INPUT and decoded(files, "execution-marker") == MARKER
                       and decoded(files, "release-marker") == RELEASE, "input or exactly-once marker differs")
            outputs = {}
            for stream, expected in (("stdout", expected_stdout), ("stderr", expected_stderr)):
                part = output[stream]
                data = bytes.fromhex(part["bytes_hex"])
                bench.need(data == expected and part["offset"] == 0
                           and part["next_offset"] == part["size"] == len(expected) and part["eof"] is True
                           and decoded(files, stream + ".log") == expected,
                           "complete native/persisted output differs: " + stream)
                outputs[stream] = {"bytes": len(data), "sha256": bench.digest(data)}
            publication = {name: json.loads(decoded(files, name))
                           for name in ("request.json", "exit.json", "exit.witness.json")}
            nonce = report["hosts"][host]["after_crash_independent"]["launch_nonce"]
            for name, value in publication.items():
                bench.need(type(value.get("terminal_publication_protocol")) is int
                           and value["terminal_publication_protocol"] == 1
                           and value.get("job_id") == ref(host)["job_id"]
                           and value.get("launch_nonce") == nonce,
                           "publication identity differs: " + name)
            bench.need(publication["exit.witness.json"].get("exit_sha256")
                       == bench.digest(decoded(files, "exit.json")), "witness exact-byte digest differs")
            bench.need(all(status.get(key) == value for key, value in publication["exit.json"].items()),
                       "native status differs from persisted exit receipt")
            bench.need(files["request.json"]
                       == report["hosts"][host]["before_crash_independent"]["proof"]["files"]["request.json"],
                       "original remote request changed before terminal proof")
            bench.need(bench.read_file(state / "jobs" / (ref(host)["job_id"] + ".json"), 65536)
                       == saved_records[host], "controller original record changed at completion")
            return {"status": status, "outputs": outputs, "independent_proof": proof,
                    "execution_count": 1, "original_identity_preserved": True,
                    "terminal_publication_confirmed": True}

        parallel("terminal", complete)
        checkpoint("normal_shutdown")
        report["shutdown"] = close_checked()
        report["passed"] = True
        checkpoint("completed")
    except BaseException as error:
        report["error"] = {"type": type(error).__name__, "reason": str(error)[:2000]}
        report["passed"] = False
    finally:
        if active is not None:
            try:
                report["interrupted_shutdown"] = active.close()
            except BaseException as error:
                report["cleanup_error"] = type(error).__name__ + ": " + str(error)[:1500]
            report["passed"] = False
        try:
            report["source_originals_unchanged"] = bool(jobs) and all(
                bench.read_file(job["path"], 65536) == job["record_bytes"] for job in jobs)
            report["binary_unchanged"] = binary_before is not None and (
                bench.digest(bench.read_file(args.candidate, 128 * 1024 * 1024)) == binary_before)
            report["current_agent_unchanged"] = agent_before is not None and (
                bench.agent_identity(os.environ["SSH_AUTH_SOCK"]) == agent_before)
        except BaseException as error:
            report["final_check_error"] = type(error).__name__ + ": " + str(error)[:1500]
            report["passed"] = False
        expected_ids = {host: row["job_id"] for host, row in report["hosts"].items()
                        if "job_id" in row}
        final_records = collect_controller_records(out / "state" / "jobs", expected_ids, saved_records)
        report["retained_controller_records"] = final_records["records"]
        report["final_controller_record_errors"] = final_records["errors"]
        report["controller_records_unchanged_after_shutdown"] = final_records["exact_original_set"]
        report["new_start_call_count"] = sum(row["tool"] == "process_start" and row["phase"] == "launch"
                                              for row in report["native_calls"])
        report["same_key_lookup_call_count"] = sum(
            row["tool"] == "process_start" and row["phase"] == "recover_same_original"
            for row in report["native_calls"])
        report["passed"] = report["passed"] and all(report.get(key) is True for key in (
            "source_originals_unchanged", "binary_unchanged", "current_agent_unchanged",
            "distinct_reported_hostnames", "controller_records_unchanged_after_shutdown"))
        if report["passed"]:
            report["passed"] = report["new_start_call_count"] == report["same_key_lookup_call_count"] == 6
        report["finished_unix"] = time.time()
        try:
            bench.save_report(report_path, report)
        except BaseException as error:
            report["passed"] = False
            report["report_save_error"] = type(error).__name__ + ": " + str(error)[:1000]
            fallback = out / f"report-final-{os.getpid()}-{time.time_ns()}.json"
            try:
                bench.create_file(fallback, bench.canonical(report))
                report_path = fallback
            except BaseException:
                print(json.dumps({"unsaved_canary_report": report}), file=sys.stderr, flush=True)
    print(json.dumps({"report": str(report_path), "passed": report["passed"], "error": report.get("error"),
                      "job_ids": {host: row.get("job_id") for host, row in report["hosts"].items()}}),
          flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())

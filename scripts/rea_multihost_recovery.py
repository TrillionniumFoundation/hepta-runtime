#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Finite real-host recovery profile; never a replacement-qualification gate.

Run this script on desktop after the final Runtime path and SHA have been supplied.
It starts only private HTTP controllers and two original, bounded Runtime jobs.
No installed service, SSH configuration, host trust file or existing directory is
modified. Failure evidence and all private state are retained.
"""

import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import select
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time
import traceback

sys.dont_write_bytecode = True
SCHEMA = "hepta.rea.multihost-recovery.v1"
PROTOCOL = "2025-06-18"
MAX_REPLY = 8 * 1024 * 1024
SSH = ["/usr/bin/ssh", "-oBatchMode=yes", "-oStrictHostKeyChecking=yes",
       "-oUpdateHostKeys=no", "-oConnectTimeout=10", "-oControlMaster=no", "-oControlPath=none"]
SCP = ["/usr/bin/scp", "-q", "-oBatchMode=yes", "-oStrictHostKeyChecking=yes",
       "-oUpdateHostKeys=no", "-oConnectTimeout=10", "-oControlMaster=no", "-oControlPath=none"]
SSH_WRAPPER = b'#!/bin/sh\nexec /usr/bin/ssh -oUpdateHostKeys=no "$@"\n'


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def encoded(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True) + "\n").encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def metadata(info):
    return {key: getattr(info, "st_" + key) for key in
            ("dev", "ino", "size", "mode", "uid", "nlink", "mtime_ns", "ctime_ns")}


def safe_path(path):
    path = Path(path)
    require(path.is_absolute() and str(path) != "/" and
            re.fullmatch(r"/[A-Za-z0-9_./-]+", str(path)) is not None and
            all(part not in (".", "..") for part in str(path).split("/")[1:]),
            "an absolute normalized ASCII private path is required")
    current = Path("/")
    for part in path.parts[1:]:
        current /= part
        try:
            info = current.lstat()
        except FileNotFoundError:
            break
        require(not stat.S_ISLNK(info.st_mode), "symlink in private path")
    return path


def checked_file(path, limit=None, kernel_exe=False):
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
    if not kernel_exe:
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
                "expected a single-link regular file")
        require(limit is None or before.st_size <= limit, "file exceeds read bound")
        sha = hashlib.sha256()
        chunks = [] if limit is not None else None
        count = 0
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            count += len(chunk)
            require(limit is None or count <= limit, "file grew beyond its read bound")
            sha.update(chunk)
            if chunks is not None:
                chunks.append(chunk)
        require(metadata(before) == metadata(os.fstat(fd)), "file changed during read")
        result = {**metadata(before), "sha256": sha.hexdigest(), "path": str(path)}
        if chunks is not None:
            result["data"] = b"".join(chunks)
        return result
    finally:
        os.close(fd)


def write_new(path, data, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 mode)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def save_receipt(path, value):
    # Only this runner's explicitly-created receipt is replaceable.
    temporary = path.with_name(path.name + ".next")
    write_new(temporary, encoded(value))
    if path.exists():
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                and info.st_nlink == 1, "receipt path changed")
    os.replace(temporary, path)
    sync_directory(path.parent)


def run_command(argv, timeout=30, data=None):
    result = subprocess.run(argv, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout, check=False, env=dict(os.environ, LC_ALL="C"))
    require(len(result.stdout) <= MAX_REPLY and len(result.stderr) <= MAX_REPLY,
            "command output exceeds its bound")
    require(result.returncode == 0,
            "command failed: " + repr(argv[:3]) + ": " +
            result.stderr.decode("utf-8", errors="replace")[-3000:])
    return result.stdout


def transport_profile(root, remote_alias):
    selected = shutil.which("ssh")
    require(selected is not None and Path(selected).resolve() == Path("/usr/bin/ssh").resolve(),
            "the inherited SSH executable differs from the explicit fixture transport")
    wrapper = checked_file(root / "bin" / "ssh", 4096)
    require(wrapper["data"] == SSH_WRAPPER, "private SSH wrapper bytes changed")
    aliases = {}
    for alias in ("localhost", remote_alias):
        # This is the final argv policy of the reviewed wrapper plus the native
        # Runtime ssh_base. -G reads effective configuration without connecting.
        raw = run_command(["/usr/bin/ssh", "-G", "-oUpdateHostKeys=no", "-T",
            "-oBatchMode=yes", "-oConnectTimeout=8", "-oStrictHostKeyChecking=yes",
            "-oForwardAgent=no", alias])
        effective = dict(line.split(" ", 1) for line in raw.decode().splitlines() if " " in line)
        require(effective.get("updatehostkeys") in ("false", "no") and
                effective.get("stricthostkeychecking") in ("true", "yes"),
                "fixture SSH trust policy is not the reviewed policy")
        trust = []
        for field in ("userknownhostsfile", "globalknownhostsfile"):
            for spelling in shlex.split(effective.get(field, "")):
                if spelling == "none":
                    continue
                path = Path(spelling).expanduser()
                try:
                    identity = checked_file(path.resolve(strict=True))
                except FileNotFoundError:
                    identity = None
                trust.append({"configured_path": str(path), "identity": identity})
        aliases[alias] = {"effective_sha256": digest(raw), "trust_files": trust,
            "options": {key: effective.get(key) for key in ("hostname", "user", "port",
                "stricthostkeychecking", "updatehostkeys", "checkhostip", "userknownhostsfile")}}
    return {"scope": "private controller Popen PATH only; not an unwrapped production profile",
        "wrapper_path": str(root / "bin" / "ssh"), "wrapper_utf8": SSH_WRAPPER.decode(),
        "wrapper_sha256": digest(SSH_WRAPPER), "ssh_binary": checked_file(Path("/usr/bin/ssh").resolve()),
        "shell_binary": checked_file(Path("/bin/sh").resolve()), "aliases": aliases}


def boot_id():
    return Path("/proc/sys/kernel/random/boot_id").read_text().strip()


def process_stat(pid):
    raw = Path(f"/proc/{int(pid)}/stat").read_text()
    fields = raw.rsplit(") ", 1)[1].split()
    return {"pid": int(pid), "state": fields[0], "ppid": int(fields[1]),
            "pgid": int(fields[2]), "sid": int(fields[3]), "start_ticks": fields[19],
            "boot_id": boot_id(), "identity": {"kind": "proc_start_ticks",
                                                "value": boot_id() + ":" + fields[19]}}


def same_process(expected):
    try:
        current = process_stat(expected["pid"])
    except FileNotFoundError:
        return False
    return current["identity"] == expected["identity"] and current["state"] not in ("Z", "X")


def proc_snapshot(pgid=None, leader=None, tracked=()):
    visible = False
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields = line.split()
        if len(fields) > 6 and fields[4] == "/proc":
            boundary = fields.index("-")
            options = (fields[5] + "," + fields[boundary + 3]).split(",")
            visible = fields[boundary + 1] == "proc" and all(
                not item.startswith("hidepid=") or item == "hidepid=0" for item in options)
    require(visible, "complete /proc visibility is unavailable; cleanup remains unknown")
    processes = {}
    errors = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            row = process_stat(int(entry.name))
            processes[row["pid"]] = row
        except FileNotFoundError:
            pass
        except (OSError, ValueError, IndexError) as error:
            errors.append({"pid": entry.name, "error": type(error).__name__})
    require(not errors, "incomplete process enumeration; cleanup remains unknown")
    members = [p for p in processes.values() if p["pgid"] == pgid and p["state"] not in ("Z", "X")]
    descendants = set([leader]) if leader is not None else set()
    while True:
        added = {p["pid"] for p in processes.values() if p["ppid"] in descendants} - descendants
        if not added:
            break
        descendants.update(added)
    retained = []
    for expected in tracked:
        current = processes.get(expected["pid"])
        if current and current["identity"] == expected["identity"] and current["state"] not in ("Z", "X"):
            retained.append(current)
    return {"visibility_complete": True, "live_group": members, "tracked_live": retained,
            "descendants": [processes[p] for p in sorted(descendants) if p in processes]}


def platform_profile():
    flags = []
    model = None
    for line in Path("/proc/cpuinfo").read_text().splitlines():
        if line.startswith("flags") and not flags:
            flags = line.split(":", 1)[1].split()
        if line.startswith("model name") and model is None:
            model = line.split(":", 1)[1].strip()
    return {"uname": list(os.uname()), "glibc": os.confstr("CS_GNU_LIBC_VERSION"),
            "uid": os.geteuid(), "home": str(Path.home()), "boot_id": boot_id(),
            "cpu_model": model, "cpu_flags": flags,
            "python": checked_file(Path(sys.executable).resolve()), "python_version": sys.version,
            "proc_visibility": proc_snapshot()["visibility_complete"]}


def marker(root, run_id):
    root = safe_path(root)
    info = root.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) == 0o700, "private root identity/permissions changed")
    record = json.loads(checked_file(root / "owner.json", 16384)["data"])
    require(record["run_id"] == run_id and record["uid"] == os.geteuid()
            and record["device"] == info.st_dev and record["inode"] == info.st_ino,
            "private root no longer identifies this run")
    return root


def worker_configuration(root):
    # RuntimeConfig requires one declared host. It is deliberately disabled;
    # this worker never connects to localhost or submits another workload.
    return {"state_dir": str(root / "worker-state"),
        "controller_workspace_roots": [str(root / "workspace")],
        "hosts": {"disabled-fixture-host": {
            "ssh_target": "localhost", "platform": "linux", "execution_mode": "operator",
            "remote_state_dir": str(root / "disabled-worker-jobs"),
            "allow_execute": False, "allow_pty": False, "allow_write": False,
            "allow_job_network": False, "allow_detached_fallback": False,
            "allowed_read_path_prefixes": [], "allowed_write_path_prefixes": [],
            "privileged_actions": {}}}}



def private_authority(root, run_id, role, provision=False):
    """Provision or read only this run's explicitly selected private fence."""
    root = marker(root, run_id)
    require(role in ("worker", "controller"), "unknown private authority role")
    authority = safe_path(root / (role + "-authority"))
    state = safe_path(root / (role + "-state"))
    directory_ids = {}
    for label, path in (("authority", authority), ("state", state)):
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
                and stat.S_IMODE(info.st_mode) == 0o700,
                "private authority/state directory is not owned mode 0700")
        directory_ids[label] = {key: getattr(info, "st_" + key)
                               for key in ("dev", "ino", "mode", "uid")}
    config = checked_file(root / (role + "-config.json"), 16384)
    config_raw = config.pop("data")
    require(json.loads(config_raw)["state_dir"] == str(state),
            "private authority state differs from its actual configuration")
    document = {"schema": "hepta-effect-owner-fence-v1", "owner": "v4", "epoch": 1,
                "phase": "admitting", "state_root": str(state),
                "predecessor_state_root": None}
    if provision:
        require(not tuple(authority.iterdir()), "fresh private authority is not empty")
        write_new(authority / ".owner.lock", b"", 0o600)
        write_new(authority / ".owner.json", encoded(document), 0o600)
        sync_directory(authority)
    lock = checked_file(authority / ".owner.lock", 4096)
    owner = checked_file(authority / ".owner.json", 4096)
    require(lock.pop("data") == b"" and owner.pop("data") == encoded(document),
            "private owner lock/document bytes differ")
    for row in (lock, owner):
        require(row["uid"] == os.geteuid() and stat.S_IMODE(row["mode"]) == 0o600
                and row["nlink"] == 1, "private owner record is not an owned 0600 single-link file")
    return {"schema": "hepta.rea.private-owner-authority.v1", "role": role,
            "run_id": run_id, "root": str(root), "authority": str(authority),
            "state_root": str(state), "directories": directory_ids,
            "configuration": config, "owner_document": document,
            "lock": lock, "owner": owner, "required_fence": True}

def create_root(root, run_id, source):
    root = safe_path(root)
    require(root.parent.is_dir(), "private parent must already exist")
    root.mkdir(mode=0o700)
    info = root.stat()
    write_new(root / "owner.json", encoded({"schema": SCHEMA, "run_id": run_id,
              "uid": os.geteuid(), "device": info.st_dev, "inode": info.st_ino}))
    write_new(root / "runner.py", source, 0o500)
    for name in ("workspace", "worker-state", "worker-authority", "jobs", "evidence", "bin"):
        (root / name).mkdir(mode=0o700)
    write_new(root / "bin" / "ssh", SSH_WRAPPER, 0o500)
    write_new(root / "worker-token", (secrets.token_hex(32) + "\n").encode())
    write_new(root / "worker-config.json", encoded(worker_configuration(root)))
    authority = private_authority(root, run_id, "worker", provision=True)
    sync_directory(root)
    return {"root": str(root), "owner": json.loads((root / "owner.json").read_text()),
            "runner_sha256": digest(source), "platform": platform_profile(),
            "authority_before": authority}


class HttpClient:
    def __init__(self, port, token, wire=None, session=None, initialize=True):
        self.port, self.token, self.wire = port, token, wire
        self.session, self.sequence = session, 0
        self.connection = http.client.HTTPConnection("127.0.0.1", port, timeout=50)
        self.stream = None
        self.initialization = None
        if initialize:
            self.initialization = self.rpc("initialize", {"protocolVersion": PROTOCOL,
                "capabilities": {}, "clientInfo": {"name": "rea-finite-multihost", "version": "1"}})
            self.rpc("notifications/initialized", {}, notify=True)
            require(bool(self.session), "HTTP initialization omitted session identity")

    def headers(self):
        result = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                  "X-Hepta-Runtime-Token": self.token, "MCP-Protocol-Version": PROTOCOL}
        if self.session:
            result["Mcp-Session-Id"] = self.session
        return result

    def log(self, value):
        if self.wire is not None:
            self.wire.write(encoded({"at_monotonic_ns": time.monotonic_ns(), **value}))
            self.wire.flush()

    def rpc(self, method, params, notify=False):
        self.sequence += 1
        request = {"jsonrpc": "2.0", "method": method, "params": params}
        if not notify:
            request["id"] = self.sequence
        self.log({"request": request, "session": self.session})
        self.connection.request("POST", "/mcp", body=encoded(request), headers=self.headers())
        response = self.connection.getresponse()
        self.session = response.getheader("Mcp-Session-Id", self.session)
        raw = response.read(MAX_REPLY + 1)
        require(len(raw) <= MAX_REPLY and 200 <= response.status < 300,
                f"HTTP response refused or oversized: {response.status}")
        text = raw.decode("utf-8")
        self.log({"response_utf8": text, "status": response.status, "session": self.session})
        if notify:
            return None
        events = [json.loads(line[5:].strip()) for line in text.splitlines()
                  if line.startswith("data:") and line[5:].strip()]
        replies = events if events else [json.loads(text)]
        reply = next((item for item in reversed(replies) if item.get("id") == self.sequence), None)
        require(reply is not None and "error" not in reply, "RPC failure: " + repr(reply))
        return reply["result"]

    def call(self, name, arguments):
        result = self.rpc("tools/call", {"name": name, "arguments": arguments})
        require(not result.get("isError"), "tool failed: " + name + ": " + repr(result))
        text = "\n".join(c["text"] for c in result.get("content", []) if c.get("type") == "text")
        return json.loads(text)

    def open_event_stream(self):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        connection.request("GET", "/mcp", headers=self.headers())
        response = connection.getresponse()
        require(response.status == 200 and "text/event-stream" in response.getheader("Content-Type", ""),
                "real MCP event stream was not established")
        require(connection.sock is not None, "event stream has no live TCP socket")
        endpoints = {"local": connection.sock.getsockname(), "remote": connection.sock.getpeername()}
        self.stream = (connection, response)
        return endpoints

    def disconnect(self):
        if self.stream:
            connection, response = self.stream
            if connection.sock:
                connection.sock.shutdown(socket.SHUT_RDWR)
            response.close()
            connection.close()
            self.stream = None
        self.connection.close()


def abi_profile(runtime, expected):
    require(not any(os.environ.get(key) for key in ("LD_PRELOAD", "LD_LIBRARY_PATH")),
            "host dynamic-loader overrides are outside this finite profile")
    identity = checked_file(runtime)
    require(identity["sha256"] == expected, "Runtime SHA differs from the supplied final identity")
    with open(runtime, "rb") as stream:
        header = stream.read(64)
    require(header[:6] == b"\x7fELF\x02\x01" and int.from_bytes(header[18:20], "little") == 62,
            "this finite profile requires a little-endian x86_64 ELF")
    require(os.uname().machine == "x86_64", "host architecture differs from the selected profile")
    versions = run_command(["/usr/bin/readelf", "--version-info", str(runtime)]).decode()
    notes = run_command(["/usr/bin/readelf", "-n", str(runtime)]).decode()
    needed = sorted(set(re.findall(r"GLIBC_([0-9.]+)", versions)), key=lambda s: tuple(map(int, s.split("."))))
    available = tuple(map(int, os.confstr("CS_GNU_LIBC_VERSION").split()[-1].split(".")))
    require(not needed or tuple(map(int, needed[-1].split("."))) <= available,
            "Runtime requires a newer glibc than this host")
    flags = set(platform_profile()["cpu_flags"])
    if "x86-64-v3" in notes:
        require({"avx2", "fma", "bmi1", "bmi2"} <= flags, "ELF ISA requirement exceeds host CPU")
    if "x86-64-v4" in notes:
        require({"avx512f", "avx512bw", "avx512dq", "avx512vl"} <= flags, "ELF ISA requirement exceeds host CPU")
    dependencies = run_command(["/usr/bin/ldd", str(runtime)]).decode()
    require("not found" not in dependencies, "a selected Runtime shared library is missing")
    version = run_command([str(runtime), "--version"]).decode().strip()
    require(version, "the final native Runtime did not return its version")
    return {"binary": identity, "glibc_requirements": needed, "elf_notes": notes,
            "loader_report": dependencies, "actual_version": version,
            "cpu_note_is_not_complete_instruction_attestation": True}


def host_action(request):
    root = marker(request["root"], request["run_id"])
    action = request["action"]
    if action == "publish":
        incoming = root / "runtime.incoming"
        identity = checked_file(incoming)
        require(identity["sha256"] == request["sha256"], "transferred final Runtime hash mismatch")
        require(identity["size"] == request["size"], "transferred final Runtime length mismatch")
        os.chmod(incoming, 0o500, follow_symlinks=False)
        # Atomic create-only publication. The temporary second link is removed
        # before any execution; every subsequently admitted file is single-link.
        os.link(incoming, root / "hepta-runtime", follow_symlinks=False)
        incoming.unlink()
        sync_directory(root)
        return abi_profile(root / "hepta-runtime", request["sha256"])
    if action == "port":
        with socket.socket() as selected:
            selected.bind(("127.0.0.1", 0))
            return {"port": selected.getsockname()[1]}
    if action == "worker_probe":
        configuration = checked_file(root / "worker-config.json", 16384)
        require(json.loads(configuration["data"]) == worker_configuration(root),
                "disabled worker configuration changed")
        token = checked_file(root / "worker-token", 256)["data"].decode().strip()
        client = HttpClient(request["port"], token)
        try:
            hosts = client.call("host_list", {})
            rows = hosts.get("hosts", [])
            require(len(rows) == 1 and rows[0].get("name") == "disabled-fixture-host" and
                    all(rows[0].get(flag) is False for flag in ("allow_execute", "allow_pty", "allow_write")),
                    "worker private profile contains an enabled or unexpected host")
            denied = client.rpc("tools/call", {"name": "file_info", "arguments": {
                "host": "disabled-fixture-host", "path": str(root / "worker-config.json")}})
            require(denied.get("isError") is True, "disabled worker read roots admitted a host file read")
            return {"initialization": client.initialization, "host_list": hosts,
                    "session": client.session, "configuration_sha256": configuration["sha256"],
                    "disabled_read_roots_rejection": denied}
        finally:
            client.disconnect()
    if action == "authority":
        return private_authority(root, request["run_id"], "worker")
    if action == "binary":
        return checked_file(root / "hepta-runtime")
    if action == "job_snapshot":
        job_id = request["job_id"]
        require(re.fullmatch(r"[A-Za-z0-9-]{1,96}", job_id) is not None, "invalid owned job id")
        job = root / "jobs" / "jobs" / job_id
        require(str(job) == request["job_dir"], "job is outside this run's private namespace")
        safe_path(job)
        files = {}
        for name in ("owner-intent.json", "started.json", "child.json", "launch.json", "exit.json", "exit.witness.json"):
            try:
                info = checked_file(job / name, 65536)
                files[name] = {"sha256": info["sha256"], "value": json.loads(info["data"])}
            except FileNotFoundError:
                pass
        child = files.get("child.json", {}).get("value")
        require(child is not None and child.get("identity", {}).get("kind") == "proc_start_ticks",
                "original native child binding is unavailable")
        current = None
        try:
            current = process_stat(child["pid"])
        except FileNotFoundError:
            pass
        if current and current["identity"] == child["identity"] and current["state"] not in ("Z", "X"):
            if request.get("hash_executable"):
                executable = checked_file(f"/proc/{child['pid']}/exe", kernel_exe=True)
                require(executable["sha256"] == request["sha256"], "actual worker image is not the final Runtime")
                require(process_stat(child["pid"])["identity"] == child["identity"], "worker identity changed while hashing")
                current["executable"] = executable
        snapshot = proc_snapshot(child["pid"], child["pid"], request.get("tracked", []))
        return {"files": files, "current_child": current, **snapshot}
    raise RuntimeError("unknown closed host action")


# This bootstrap executes only before this run has any Runtime process. It
# creates a fresh private namespace and installs this exact reviewed runner.
BOOTSTRAP = r'''
import base64,json,os,pathlib,stat,sys
q=json.load(sys.stdin);p=pathlib.Path(q["root"])
if not p.is_absolute() or str(p)=="/" or any(x in (".","..") for x in str(p).split("/")[1:]):raise SystemExit("invalid root")
cur=pathlib.Path("/")
for part in p.parts[1:-1]:
 cur/=part
 if not stat.S_ISDIR(cur.lstat().st_mode) or cur.is_symlink():raise SystemExit("unsafe parent")
os.mkdir(p,0o700)
code=base64.b64decode(q["source"],validate=True)
fd=os.open(p/"runner.py",os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o500)
with os.fdopen(fd,"wb") as f:f.write(code);f.flush();os.fsync(f.fileno())
# The installed reviewed module completes private-file creation itself.
os.execv(sys.executable,[sys.executable,"-I","-S",str(p/"runner.py"),"--bootstrap-finish",q["run_id"]])
'''


def bootstrap_finish(run_id):
    root = Path(__file__).parent
    info = root.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) == 0o700, "unsafe new private namespace")
    source = checked_file(root / "runner.py", 256 * 1024)["data"]
    write_new(root / "owner.json", encoded({"schema": SCHEMA, "run_id": run_id,
              "uid": os.geteuid(), "device": info.st_dev, "inode": info.st_ino}))
    for name in ("workspace", "worker-state", "worker-authority", "jobs", "evidence", "bin"):
        (root / name).mkdir(mode=0o700)
    write_new(root / "bin" / "ssh", SSH_WRAPPER, 0o500)
    write_new(root / "worker-token", (secrets.token_hex(32) + "\n").encode())
    write_new(root / "worker-config.json", encoded(worker_configuration(root)))
    authority = private_authority(root, run_id, "worker", provision=True)
    sync_directory(root)
    return {"root": str(root), "owner": json.loads((root / "owner.json").read_text()),
            "runner_sha256": digest(source), "platform": platform_profile(),
            "authority_before": authority}


class Host:
    def __init__(self, name, root, alias, run_id):
        self.name, self.root, self.alias, self.run_id = name, safe_path(root), alias, run_id
        require(alias is None or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}", alias),
                "an existing administrator-configured SSH alias is required")

    def initialize(self, source):
        if self.alias is None:
            return create_root(self.root, self.run_id, source)
        request = {"root": str(self.root), "run_id": self.run_id,
                   "source": base64.b64encode(source).decode()}
        return json.loads(run_command(SSH + [self.alias, shlex.join(["/usr/bin/python3", "-I", "-S", "-c", BOOTSTRAP])],
                                      data=encoded(request)))

    def action(self, action, **arguments):
        request = {"root": str(self.root), "run_id": self.run_id, "action": action, **arguments}
        if self.alias is None:
            return host_action(request)
        command = shlex.join(["/usr/bin/python3", "-I", "-S", str(self.root / "runner.py"), "--internal-host-action"])
        return json.loads(run_command(SSH + [self.alias, command], data=encoded(request), timeout=90))


def copy_final(source, destination, expected):
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, "unsafe final Runtime source")
        output = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        sha = hashlib.sha256()
        with os.fdopen(output, "wb") as stream:
            while True:
                data = os.read(fd, 1024 * 1024)
                if not data:
                    break
                sha.update(data)
                stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        require(sha.hexdigest() == expected and metadata(before) == metadata(os.fstat(fd)),
                "final Runtime changed or does not match the selected SHA; retained without execution")
    finally:
        os.close(fd)


class Controller:
    def __init__(self, runtime, root, port, label, expected, registry):
        self.root, self.label = root, label
        self.stdout = (root / "evidence" / (label + "-stdout.log")).open("xb")
        self.stderr = (root / "evidence" / (label + "-stderr.log")).open("xb")
        self.closed = False
        self.pidfd, self.identity, self.binary = None, None, None
        environment = dict(os.environ, RUST_LOG="info", LC_ALL="C",
            PATH=str(root / "bin") + os.pathsep + os.environ.get("PATH", os.defpath),
            HEPTA_EFFECT_OWNER_FENCE_DIR=str(root / "controller-authority"),
            HEPTA_EFFECT_OWNER_SELF="v4", HEPTA_EFFECT_OWNER_FENCE_REQUIRED="1")
        self.process = subprocess.Popen([str(runtime), "mcp", "--path", str(root / "workspace"),
            "--runtime-config", str(root / "controller-config.json"), "--bind", f"127.0.0.1:{port}",
            "--auth-token-file", str(root / "controller-token")], cwd=root,
            env=environment, stdin=subprocess.DEVNULL, stdout=self.stdout, stderr=self.stderr,
            start_new_session=True)
        # Retain custody even if the following identity/hash admission fails.
        # No poll/wait is allowed before stop's final group observation.
        registry.append(self)
        self.pidfd = os.pidfd_open(self.process.pid)
        self.identity = process_stat(self.process.pid)
        require(self.identity["pgid"] == self.process.pid and self.identity["sid"] == self.process.pid,
                "controller did not enter its private process group")
        self.binary = checked_file(f"/proc/{self.process.pid}/exe", kernel_exe=True)
        require(self.binary["sha256"] == expected, "controller is not the supplied final Runtime")
        self.port = port

    def alive(self):
        return (self.pidfd is not None and self.identity is not None
                and not select.select([self.pidfd], [], [], 0)[0] and same_process(self.identity))

    def stop(self, crash=False):
        if self.closed:
            return self.close_receipt
        pid = self.process.pid
        if self.pidfd is None:
            self.pidfd = os.pidfd_open(pid)
        if self.identity is None:
            # This direct Popen child has never been reaped, so its PID cannot
            # have been recycled even after an early initialization failure.
            self.identity = process_stat(pid)
        require(process_stat(pid)["identity"] == self.identity["identity"], "owned controller identity changed")
        require(self.identity["pgid"] == pid and self.identity["sid"] == pid,
                "private controller group ownership is unavailable")
        # Keep the original leader unreaped until every group signal is over.
        try:
            os.killpg(pid, signal.SIGKILL if crash else signal.SIGTERM)
        except ProcessLookupError:
            require(bool(select.select([self.pidfd], [], [], 0)[0]), "live controller group disappeared")
        forced = False
        if not select.select([self.pidfd], [], [], 15)[0]:
            forced = True
            os.killpg(pid, signal.SIGKILL)
            require(bool(select.select([self.pidfd], [], [], 10)[0]), "owned controller exit unconfirmed")
        observed = os.waitid(os.P_PIDFD, self.pidfd, os.WEXITED | os.WNOWAIT | os.WNOHANG)
        require(observed is not None, "original controller exit observation unavailable")
        group = proc_snapshot(pid)
        if group["live_group"]:
            forced = True
            os.killpg(pid, signal.SIGKILL)
            until = time.monotonic() + 5
            while group["live_group"] and time.monotonic() < until:
                time.sleep(0.05)
                group = proc_snapshot(pid)
        require(not group["live_group"], "private controller group cleanup remains unknown")
        code = self.process.wait(timeout=1)
        os.close(self.pidfd)
        self.stdout.close()
        self.stderr.close()
        self.closed = True
        self.close_receipt = {"identity": self.identity, "binary": self.binary,
            "signal": "SIGKILL" if crash else "SIGTERM", "forced_cleanup": forced,
            "exit_code": code, "original_leader_reaped": True, "original_group_stopped": True}
        return self.close_receipt


def wait_client(controller, root, wire):
    token = checked_file(root / "controller-token", 256)["data"].decode().strip()
    deadline = time.monotonic() + 40
    last = None
    while time.monotonic() < deadline:
        require(controller.alive(), "private controller exited during startup")
        try:
            return HttpClient(controller.port, token, wire)
        except (OSError, http.client.HTTPException) as error:
            last = type(error).__name__
            time.sleep(0.2)
    raise RuntimeError("private HTTP startup deadline: " + str(last))


def read_logs(client, host, job_id):
    result = {"stdout": bytearray(), "stderr": bytearray()}
    offsets = {"stdout": 0, "stderr": 0}
    pages = []
    for _ in range(4096):
        response = client.call("process_read", {"host": host, "job_id": job_id,
            "stdout_offset": offsets["stdout"], "stderr_offset": offsets["stderr"], "limit": 113})
        page = {}
        for stream in result:
            part = response[stream]
            data = bytes.fromhex(part["bytes_hex"])
            require(part["next_offset"] == offsets[stream] + len(data), "non-contiguous original log cursor")
            result[stream].extend(data)
            require(len(result[stream]) <= MAX_REPLY, "owned log exceeds profile limit")
            offsets[stream] = part["next_offset"]
            page[stream] = {key: part.get(key) for key in ("size", "next_offset", "eof")}
        pages.append(page)
        if all(response[s]["eof"] for s in result):
            return {s: bytes(value) for s, value in result.items()}, pages
    raise RuntimeError("owned log pagination exceeds its fixed budget")


def stable_binding(snapshot):
    return {name: snapshot["files"][name] for name in
            ("owner-intent.json", "started.json", "child.json")}


def checked_terminal(status):
    require(status.get("state") == "cancelled" and status.get("cancelled") is True,
            "original native job is not authoritatively cancelled")
    require(status.get("terminal_publication_confirmed") is True,
            "original terminal publication witness is unconfirmed")
    require(status.get("output_complete") is True and status.get("output_durable") is True,
            "original output is not complete and durable")


def checked_owner_terminal(snapshot, job_id):
    files = snapshot["files"]
    require(all(name in files for name in ("started.json", "exit.json", "exit.witness.json")),
            "original owner terminal files are absent; process disappearance is insufficient")
    started = files["started.json"]["value"]
    terminal = files["exit.json"]["value"]
    witness = files["exit.witness.json"]["value"]
    nonce = started.get("launch_nonce")
    require(isinstance(nonce, str) and re.fullmatch(r"[a-f0-9]{32}", nonce),
            "original launch nonce is unavailable")
    require(started.get("job_id") == job_id and all(
        item.get("terminal_publication_protocol") == 1 and item.get("job_id") == job_id
        and item.get("launch_nonce") == nonce for item in (terminal, witness)),
        "terminal publication is not bound to the original job and launch")
    require(witness.get("exit_sha256") == files["exit.json"]["sha256"],
            "original owner publication witness does not match its terminal bytes")
    require(terminal.get("effect_outcome") != "unknown" and terminal.get("status_authoritative") is not False,
            "original owner retained an unknown terminal outcome")


def execute(args):
    require(sys.platform == "linux" and hasattr(os, "pidfd_open") and hasattr(os, "P_PIDFD"),
            "Linux pidfd and non-reaping waitid are required")
    require(re.fullmatch(r"[a-f0-9]{64}", args.runtime_sha256), "the supplied final SHA is required")
    require(not any(os.environ.get(key) for key in ("LD_PRELOAD", "LD_LIBRARY_PATH")),
            "ambient dynamic-loader overrides are outside this profile")
    source_path = safe_path(args.runtime)
    selected = checked_file(source_path)
    require(selected["sha256"] == args.runtime_sha256, "selected final Runtime SHA mismatch")
    source = checked_file(Path(__file__).resolve(), 256 * 1024)["data"]
    run_id = secrets.token_hex(16)
    root = safe_path(args.desktop_root)
    hosts = [Host("desktop", root, None, run_id),
             Host("x230", args.x230_root, args.x230_ssh_alias, run_id)]
    require(hosts[0].root != hosts[1].root, "host-specific private roots must be explicit")
    receipt = {"schema": SCHEMA, "run_id": run_id, "selected_runtime": selected,
        "runner_sha256": digest(source), "public_gates": 0, "capability": 0,
        "replacement_qualified": False, "full_multihost_matrix": False,
        "full_cost_comparison": False, "limited_profile_passed": False,
        "topology": "one private desktop HTTP controller; same-SHA native Runtime jobs on desktop and x230",
        "controller_restart_hosts": ["desktop"], "worker_hosts": ["desktop", "x230"],
        "phases": [], "hosts": {}, "controllers": [], "jobs": {},
        "cleanup": {"complete": False, "directories_retained": True}}
    controllers, clients, jobs = [], [], []
    pending_starts = {}
    client = None
    wire = None
    failure = None
    began = time.monotonic()

    def phase(name, detail):
        receipt["phases"].append({"name": name, "elapsed_seconds": time.monotonic() - began,
                                  "detail": detail})
        save_receipt(root / "receipt.json", receipt)
        print(json.dumps({"phase": name, "run_id": run_id}), flush=True)

    try:
        for host in hosts:
            prepared = host.initialize(source)
            require(prepared["runner_sha256"] == digest(source), "remote runner source mismatch")
            receipt["hosts"][host.name] = prepared
        phase("fresh-private-directories", {"preexisting_directory_reuse": False})
        receipt["transport_fixture"] = transport_profile(root, args.x230_ssh_alias)
        phase("explicit-private-ssh-wrapper", receipt["transport_fixture"])
        copy_final(source_path, root / "runtime.incoming", args.runtime_sha256)
        receipt["hosts"]["desktop"]["abi"] = hosts[0].action("publish", sha256=args.runtime_sha256, size=selected["size"])
        remote = hosts[1]
        run_command(SCP + [str(root / "hepta-runtime"), f"{remote.alias}:{remote.root}/runtime.incoming"], timeout=300)
        receipt["hosts"]["x230"]["abi"] = remote.action("publish", sha256=args.runtime_sha256, size=selected["size"])
        require(receipt["hosts"]["desktop"]["abi"]["actual_version"] ==
                receipt["hosts"]["x230"]["abi"]["actual_version"], "same-SHA native version output differs")
        phase("same-final-binary-staged", {"sha256": args.runtime_sha256, "bytes_per_host": selected["size"]})
        (root / "controller-state").mkdir(mode=0o700)
        (root / "controller-authority").mkdir(mode=0o700)
        write_new(root / "controller-token", (secrets.token_hex(32) + "\n").encode())
        configuration = {"state_dir": str(root / "controller-state"),
            "controller_workspace_roots": [str(root / "workspace")], "hosts": {}}
        for host in hosts:
            configuration["hosts"][host.name] = {"ssh_target": host.alias or "localhost",
                "platform": "linux", "execution_mode": "operator",
                "remote_state_dir": str(host.root / "jobs"), "allow_execute": True,
                "allow_pty": False, "allow_write": True, "allow_job_network": True,
                "allow_detached_fallback": False,
                "allowed_read_path_prefixes": [str(host.root)],
                "allowed_write_path_prefixes": [str(host.root)], "privileged_actions": {}}
        write_new(root / "controller-config.json", encoded(configuration))
        receipt["configuration_sha256"] = digest(encoded(configuration))
        receipt["controller_authority_before"] = private_authority(
            root, run_id, "controller", provision=True)
        port = hosts[0].action("port")["port"]
        wire = (root / "evidence" / "mcp-wire.jsonl").open("xb")

        def start_controller(label):
            owner = Controller(root / "hepta-runtime", root, port, label, args.runtime_sha256, controllers)
            receipt["controllers"].append({"label": label, "identity": owner.identity, "binary": owner.binary})
            connected = wait_client(owner, root, wire)
            clients.append(connected)
            schema = connected.rpc("tools/list", {})
            names = {tool["name"] for tool in schema["tools"]}
            require({"process_start", "process_status", "process_read", "process_cancel"} <= names,
                    "final native controller lacks required public operations")
            receipt["controllers"][-1].update({"initialization": connected.initialization,
                "session": connected.session, "tool_schema_sha256": digest(encoded(schema))})
            return owner, connected

        controller, client = start_controller("controller-a")
        for host in hosts:
            worker_port = host.action("port")["port"]
            request = {"host": host.name, "executable": str(host.root / "hepta-runtime"),
                "args": ["mcp", "--path", str(host.root / "workspace"), "--runtime-config",
                         str(host.root / "worker-config.json"), "--bind", f"127.0.0.1:{worker_port}",
                         "--auth-token-file", str(host.root / "worker-token")],
                "cwd": str(host.root / "workspace"), "timeout_seconds": 600,
                "memory_max_bytes": 768 * 1024 * 1024, "cpu_quota_percent": 50, "nice": 5,
                "env": {"RUST_LOG": "info", "LC_ALL": "C", "HEPTA_EFFECT_OWNER_FENCE_DIR": str(host.root / "worker-authority"),
                        "HEPTA_EFFECT_OWNER_SELF": "v4", "HEPTA_EFFECT_OWNER_FENCE_REQUIRED": "1"},
                "idempotency_key": run_id + "-" + host.name + "-original"}
            pending_starts[host.name] = request
            receipt["jobs"][host.name] = {"request": request, "admission": "unconfirmed"}
            phase("admitting-native-worker", {"host": host.name, "idempotency_key": request["idempotency_key"]})
            started = client.call("process_start", request)
            job_id = started["job"]["id"]
            row = {"host": host, "job_id": job_id, "job_dir": started["job"]["remote_job_dir"], "request": request}
            jobs.append(row)
            receipt["jobs"][host.name] = {"request": request, "start": started}
            require(started.get("reused") is False and started.get("launch", {}).get("backend") == "systemd",
                    "fresh native job did not use the original systemd supervisor")
            require(started["job"].get("launch_state") == "launched" and started["launch"].get("ok") is True,
                    "original launch acknowledgement is not confirmed")
            del pending_starts[host.name]
            deadline = time.monotonic() + 60
            while True:
                status = client.call("process_status", {"host": host.name, "job_id": job_id})
                require(status.get("state") not in ("failed", "cancelled", "succeeded", "timed_out", "effect_unknown"),
                        "native worker exited before readiness: " + repr(status))
                try:
                    worker = host.action("worker_probe", port=worker_port)
                    break
                except (RuntimeError, OSError):
                    require(time.monotonic() < deadline, "native worker readiness deadline")
                    time.sleep(0.2)
            snapshot = host.action("job_snapshot", job_id=job_id, job_dir=row["job_dir"],
                                   sha256=args.runtime_sha256, hash_executable=True)
            child = snapshot["current_child"]
            require(child is not None and child["state"] not in ("Z", "X") and child["pgid"] == child["pid"],
                    "original native worker process group is unavailable")
            row["binding"], row["tracked"] = stable_binding(snapshot), snapshot["descendants"]
            row["initial_logs"], pages = read_logs(client, host.name, job_id)
            require(row["initial_logs"]["stderr"], "native worker startup emitted no retained diagnostic bytes")
            receipt["jobs"][host.name].update({"worker_http": worker, "initial_snapshot": snapshot,
                "initial_log_pages": pages, "initial_log_hashes": {s: digest(v) for s, v in row["initial_logs"].items()}})
        phase("both-native-workers-live", {"worker_sha256": args.runtime_sha256})
        stream = client.open_event_stream()
        old_session = client.session
        client.disconnect()
        require(controller.alive(), "TCP disconnect stopped the private controller")
        token = checked_file(root / "controller-token", 256)["data"].decode().strip()
        client = HttpClient(port, token, wire, session=old_session, initialize=False)
        clients.append(client)
        for row in jobs:
            require(client.call("process_status", {"host": row["host"].name, "job_id": row["job_id"]})["state"] == "running",
                    "original job was lost across TCP reconnect")
        phase("actual-tcp-disconnect-reconnect", {"socket": stream, "same_mcp_session": old_session,
              "controller_identity_unchanged": controller.alive(), "network_partition_injected": False})
        client.disconnect()
        client = HttpClient(port, token, wire)
        clients.append(client)
        require(client.session != old_session, "new client reused the old MCP session")
        for row in jobs:
            replay = client.call("process_start", row["request"])
            require(replay.get("reused") is True and replay["job"]["id"] == row["job_id"],
                    "fresh-session retry did not reconcile the original job")
        phase("new-session-original-job-reconciliation", {"new_session": client.session})
        for connected in clients:
            connected.disconnect()
        phase("controller-a-crash", controller.stop(crash=True))
        controller, client = start_controller("controller-b")
        for row in jobs:
            host = row["host"]
            require(client.call("process_status", {"host": host.name, "job_id": row["job_id"]})["state"] == "running",
                    "original job did not survive the controller crash")
            replay = client.call("process_start", row["request"])
            require(replay.get("reused") is True and replay["job"]["id"] == row["job_id"],
                    "cold controller failed exact idempotency reconciliation")
            snapshot = host.action("job_snapshot", job_id=row["job_id"], job_dir=row["job_dir"])
            require(stable_binding(snapshot) == row["binding"], "original owner or child identity changed")
            logs, pages = read_logs(client, host.name, row["job_id"])
            require(all(logs[s].startswith(row["initial_logs"][s]) for s in logs), "original log prefix changed")
            receipt["jobs"][host.name]["cold_running_snapshot"] = snapshot
            receipt["jobs"][host.name]["cold_running_pages"] = pages
        phase("cold-controller-original-running-jobs", {"controller": "controller-b"})
        for row in jobs:
            host = row["host"]
            acknowledgement = client.call("process_cancel", {"host": host.name, "job_id": row["job_id"], "grace_seconds": 5})
            receipt["jobs"][host.name]["cancel_acknowledgement"] = acknowledgement
            deadline = time.monotonic() + 40
            while True:
                status = client.call("process_status", {"host": host.name, "job_id": row["job_id"]})
                if status.get("state") == "cancelled":
                    break
                require(time.monotonic() < deadline and status.get("state") not in
                        ("failed", "succeeded", "timed_out", "effect_unknown"),
                        "cancelled original outcome remains unknown: " + repr(status))
                time.sleep(0.2)
            checked_terminal(status)
            snapshot = host.action("job_snapshot", job_id=row["job_id"], job_dir=row["job_dir"], tracked=row["tracked"])
            checked_owner_terminal(snapshot, row["job_id"])
            require(stable_binding(snapshot) == row["binding"], "cancellation changed original job identity")
            require(not snapshot["live_group"] and not snapshot["tracked_live"], "owned native process cleanup unconfirmed")
            logs, pages = read_logs(client, host.name, row["job_id"])
            require(all(logs[s].startswith(row["initial_logs"][s]) for s in logs), "cancelled output lost original bytes")
            row["terminal_snapshot"], row["terminal_logs"] = snapshot, logs
            for stream, data in logs.items():
                write_new(root / "evidence" / f"{host.name}-{stream}.bin", data)
            receipt["jobs"][host.name].update({"terminal_status": status, "terminal_snapshot": snapshot,
                "terminal_log_pages": pages, "terminal_log_hashes": {s: digest(v) for s, v in logs.items()}})
        phase("original-cancellation-and-durable-readback", {"hosts": [h.name for h in hosts]})
        client.disconnect()
        phase("controller-b-cold-stop", controller.stop())
        controller, client = start_controller("controller-c")
        for row in jobs:
            host = row["host"]
            status = client.call("process_status", {"host": host.name, "job_id": row["job_id"]})
            checked_terminal(status)
            snapshot = host.action("job_snapshot", job_id=row["job_id"], job_dir=row["job_dir"], tracked=row["tracked"])
            checked_owner_terminal(snapshot, row["job_id"])
            require(snapshot["files"] == row["terminal_snapshot"]["files"], "original durable receipts changed after cold recovery")
            require(not snapshot["live_group"] and not snapshot["tracked_live"], "cancelled native process reappeared")
            logs, pages = read_logs(client, host.name, row["job_id"])
            require(logs == row["terminal_logs"], "original complete log bytes changed after cold recovery")
            receipt["jobs"][host.name]["cold_terminal_status"] = status
            receipt["jobs"][host.name]["cold_terminal_pages"] = pages
        phase("cold-controller-cancelled-results-recovered", {"controller": "controller-c"})
        receipt["limited_profile_passed"] = True
    except BaseException as error:
        failure = error
        receipt["failure"] = {"type": type(error).__name__, "message": str(error), "traceback": traceback.format_exc()}
    finally:
        cleanup_errors = []
        for host, request in pending_starts.items():
            cleanup_errors.append({"host": host, "idempotency_key": request["idempotency_key"],
                "error": "original process_start acknowledgement is unknown; no new key or workload retry submitted",
                "configured_original_job_timeout_seconds": request["timeout_seconds"]})
        if failure is not None and client is not None and controllers and controllers[-1].alive():
            for row in jobs:
                try:
                    client.call("process_cancel", {"host": row["host"].name, "job_id": row["job_id"], "grace_seconds": 5})
                except BaseException as error:
                    cleanup_errors.append({"host": row["host"].name, "job_id": row["job_id"], "error": str(error)})
        for connected in clients:
            try:
                connected.disconnect()
            except OSError as error:
                cleanup_errors.append({"client_disconnect": str(error)})
        for owner in reversed(controllers):
            if not owner.closed:
                try:
                    receipt["controllers"].append({"label": owner.label + "-cleanup", "close": owner.stop()})
                except BaseException as error:
                    cleanup_errors.append({"controller": owner.label, "error": str(error)})
        for row in jobs:
            try:
                final = row["host"].action("job_snapshot", job_id=row["job_id"], job_dir=row["job_dir"], tracked=row.get("tracked", []))
                checked_owner_terminal(final, row["job_id"])
                require(not final["live_group"] and not final["tracked_live"], "owned job remains live")
            except BaseException as error:
                cleanup_errors.append({"host": row["host"].name, "job_id": row["job_id"], "error": str(error)})
        try:
            receipt["source_after"] = checked_file(source_path)
            require(receipt["source_after"] == selected, "selected source binary changed during the profile")
            for host in hosts:
                after = host.action("binary")
                require(after["sha256"] == args.runtime_sha256, "staged final binary changed")
                receipt["hosts"][host.name]["binary_after"] = after
                authority_after = host.action("authority")
                require(authority_after == receipt["hosts"][host.name]["authority_before"],
                        "original private worker authority changed")
                receipt["hosts"][host.name]["authority_after"] = authority_after
            if "controller_authority_before" in receipt:
                authority_after = private_authority(root, run_id, "controller")
                require(authority_after == receipt["controller_authority_before"],
                        "original private controller authority changed")
                receipt["controller_authority_after"] = authority_after
            receipt["transport_fixture_after"] = transport_profile(root, args.x230_ssh_alias)
            require(receipt["transport_fixture_after"] == receipt["transport_fixture"],
                    "fixture SSH policy, executable or configured trust files changed")
        except BaseException as error:
            cleanup_errors.append({"identity_recheck": str(error)})
        if wire:
            wire.flush()
            os.fsync(wire.fileno())
            wire.close()
        receipt["cleanup"].update({"complete": not cleanup_errors, "errors": cleanup_errors})
        receipt["limited_profile_passed"] &= not cleanup_errors
        receipt["elapsed_seconds"] = time.monotonic() - began
        receipt["limitations"] = [
            "Only one private desktop controller is restarted; x230 controller restart is not exercised.",
            "TCP disconnect and local controller crash are real; no host reboot, network partition or storage fault is injected.",
            "Workers are the selected native Runtime serving disabled-host private HTTP profiles, not REA engine/device workloads.",
            "Original PGID and already observed descendants are checked; arbitrary escaped descendants are not fully enumerated across time.",
            "Private accounts and directories reduce accidental interference; hostile same-UID actors are outside this proof.",
            "Artifact CPU notes and exercised paths do not attest every instruction or complete shared-library closure.",
            "The private controller uses an explicitly recorded SSH wrapper fixing UpdateHostKeys=no; unwrapped production recovery is not qualified.",
            "Failed or successful evidence directories are retained; this is not a full cost comparison or replacement qualification."]
        owned_root = False
        try:
            marker(root, run_id)
            owned_root = True
        except (OSError, RuntimeError, KeyError, ValueError):
            pass
        if owned_root:
            save_receipt(root / "receipt.json", receipt)
    print(json.dumps({"receipt": str(root / "receipt.json"), "limited_profile_passed": receipt["limited_profile_passed"],
                      "public_gates": 0, "capability": 0}), flush=True)
    return 0 if receipt["limited_profile_passed"] else 1


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--bootstrap-finish":
        print(json.dumps(bootstrap_finish(sys.argv[2])))
        return 0
    if sys.argv[1:] == ["--internal-host-action"]:
        raw = sys.stdin.buffer.read(131073)
        require(len(raw) <= 131072, "host action exceeds its bound")
        print(json.dumps(host_action(json.loads(raw))))
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("plan", help="print the finite profile without starting or copying any Runtime")
    run = sub.add_parser("run", help="execute only after the final binary path and exact SHA are supplied")
    run.add_argument("--runtime", required=True, type=Path)
    run.add_argument("--runtime-sha256", required=True)
    run.add_argument("--desktop-root", required=True, type=Path)
    run.add_argument("--x230-root", required=True, type=Path)
    run.add_argument("--x230-ssh-alias", default="x230-ts")
    args = parser.parse_args()
    if args.command == "plan":
        print(json.dumps({"schema": SCHEMA, "execution_started": False,
            "requires_final_binary_path_and_sha256": True, "public_gates": 0, "capability": 0,
            "controller_restart_hosts": ["desktop"], "worker_hosts": ["desktop", "x230"],
            "phases": ["new private directories", "same final binary ABI/hash check on both hosts",
                "two original native Runtime jobs", "real TCP close and same-session reconnect",
                "fresh MCP session exact-key reconciliation", "private controller SIGKILL and cold restart",
                "cancel original jobs and read durable paginated bytes", "second cold restart and identical original readback"],
            "existing_services_modified": False, "ssh_trust_modified": False,
            "failure_policy": "retain directories and receipts; cancel only known original jobs; unknown never becomes success"}, indent=2))
        return 0
    return execute(args)


if __name__ == "__main__":
    raise SystemExit(main())

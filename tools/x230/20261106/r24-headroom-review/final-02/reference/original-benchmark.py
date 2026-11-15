#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Read-only six-host native MCP ABBA comparison on fresh isolated controllers.

Only process_status/process_read are admitted by this driver. Existing six job
records are copied byte-for-byte; no start, cancel, service or remote write API is
called. Both binaries use the same stdio MCP transport and newly pinned SSH pool
profile bound to this invocation's SSH_AUTH_SOCK. This is a bounded observation
sample and normal-controller-restart check, not a power-loss or launch benchmark.
"""
import argparse
import concurrent.futures
import hashlib
import json
import math
import os
from pathlib import Path
import queue
import re
import socket
import stat
import struct
import subprocess
import sys
import threading
import time

import allocator_environment as allocator
from observation_resources import Resources, counters, cpu_seconds, open_new

HOSTS = {"ai395", "mac", "main", "pocket4", "rog", "x230"}
TOOLS = {"process_status", "process_read"}
MAX_MESSAGE = 1024 * 1024


def need(value, reason):
    if not value:
        raise RuntimeError(reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read_file(path, maximum=16 * 1024 * 1024):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
             "input must be a single-link regular file: " + str(path))
        need(before.st_size <= maximum, "input exceeds size bound")
        with os.fdopen(os.dup(fd), "rb") as stream:
            data = stream.read(maximum + 1)
        need(len(data) == before.st_size and identity(before) == identity(os.fstat(fd))
             == identity(path.lstat()), "input changed while reading")
        return data
    finally:
        os.close(fd)


def create_file(path, data, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def save_report(path, report):
    temporary = path.with_suffix(".next")
    create_file(temporary, canonical(report))
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def agent_identity(path):
    before = Path(path).lstat()
    need(stat.S_ISSOCK(before.st_mode) and before.st_uid == os.getuid(),
         "current SSH agent socket must be account-owned")
    def exact(stream, count):
        chunks = bytearray()
        while len(chunks) < count:
            chunk = stream.recv(count - len(chunks))
            need(chunk, "SSH agent closed during identity observation")
            chunks.extend(chunk)
        return bytes(chunks)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(5)
        stream.connect(path)
        peer = struct.unpack("3i", stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        need(peer[1] == os.getuid(), "SSH agent peer UID differs")
        stream.sendall(b"\0\0\0\1\x0b")
        length = struct.unpack(">I", exact(stream, 4))[0]
        need(5 <= length <= 65536, "SSH agent identity frame is out of bounds")
        data = exact(stream, length)
        need(data[0] == 12 and 1 <= int.from_bytes(data[1:5], "big") <= 64,
             "current SSH agent has no bounded usable key list")
    after = Path(path).lstat()
    need(identity(before) == identity(after), "SSH agent socket changed")
    return {"socket_identity": identity(before), "peer": peer,
            "identity_frame_sha256": digest(data)}


def fresh_profile(template_path, output, socket_parent, agent):
    old_raw = read_file(template_path, 262144)
    old = json.loads(old_raw)
    need(old["schema"] == "hepta-observation-ssh-pool/v1"
         and old["allow_bounded_cached_authentication"] is True, "unsupported profile template")
    raw_config = read_file(old["ssh_config"], 262144)
    raw_known = read_file(old["known_hosts"], 262144)
    need(digest(raw_config) == old["ssh_config_sha256"]
         and digest(raw_known) == old["known_hosts_sha256"], "historical SSH inputs changed")
    output.mkdir(mode=0o700)
    config, known = output / "ssh_config", output / "known_hosts"
    rewritten, replacements = [], 0
    for line in raw_config.decode().splitlines():
        fields = line.split()
        if fields and fields[0].lower() == "userknownhostsfile":
            need(len(fields) == 2 and fields[1] == old["known_hosts"],
                 "unrecognized known-hosts reference")
            line = " UserKnownHostsFile " + str(known)
            replacements += 1
        rewritten.append(line)
    need(replacements >= 1, "explicit known-hosts reference missing")
    create_file(config, ("\n".join(rewritten) + "\n").encode())
    create_file(known, raw_known)
    parent = Path(socket_parent)
    pin = parent.lstat()
    need(parent.resolve() == parent and stat.S_ISDIR(pin.st_mode)
         and pin.st_uid == os.getuid() and stat.S_IMODE(pin.st_mode) == 0o700,
         "socket parent must be an existing private direct directory")
    # Native checks its final socket path, but OpenSSH first binds a temporary
    # path with a dot plus 16 random characters. Reserve that suffix too, plus
    # a ten-digit PID and six-digit pool sequence for this bounded experiment.
    # A short direct private parent such as /home/qian/hx230-opt-20261023 fits;
    # a symlink or a shorter unverified alias is not an acceptable substitute.
    pool_component = len("/hp-o-") + 10 + 1 + 32
    control_component = len("/m-") + 6
    openssh_temporary_suffix = 1 + 16
    socket_bytes_with_nul = (len(os.fsencode(parent)) + pool_component
                             + control_component + openssh_temporary_suffix + 1)
    need(socket_bytes_with_nul <= 108,
         "socket parent exceeds conservative OpenSSH temporary-path budget; use a shorter private directory")
    spec = {"schema": "hepta-observation-ssh-pool/v1",
            "allow_bounded_cached_authentication": True,
            "ssh_config": str(config), "ssh_config_sha256": digest(read_file(config)),
            "known_hosts": str(known), "known_hosts_sha256": digest(raw_known),
            "ssh_sha256": digest(read_file("/usr/bin/ssh")),
            "false_sha256": digest(read_file("/usr/bin/false")),
            "shell_sha256": digest(read_file(Path("/bin/sh").resolve(strict=True))),
            "agent_socket": agent, "socket_parent": str(parent)}
    path = output / "profile.json"
    create_file(path, canonical(spec))
    return path, {"template_sha256": digest(old_raw), "new_profile_sha256": digest(read_file(path)),
                  "historical_agent_not_reused": True, "current_agent_bound": True}


def load_jobs(directory):
    jobs = []
    paths = sorted(Path(directory).glob("*.json"))
    need(len(paths) == 6, "exactly six frozen records are required")
    for path in paths:
        raw = read_file(path, 65536)
        record = json.loads(raw)
        need(path.name == record["id"] + ".json" and record["launch_state"] == "launched"
             and record["execution_mode"] == "operator" and record["system_jobctl"] is False,
             "frozen job identity or backend mismatch")
        marker = record["args"][-1]
        need(re.fullmatch("HEPTA-A16-ONCE-" + re.escape(record["host"]) + "-[0-9a-f]{24}", marker),
             "original synthetic marker mismatch")
        jobs.append({"host": record["host"], "id": record["id"], "record": record,
                     "record_bytes": raw, "record_sha256": digest(raw),
                     "expected": (marker + "\n").encode(), "path": path})
    need({job["host"] for job in jobs} == HOSTS, "six-host membership differs")
    return sorted(jobs, key=lambda row: row["host"])


def load_topology(path, profile_template):
    """Bind alias meaning to this exact pinned profile, never to another controller."""
    raw = read_file(path, 65536)
    value = json.loads(raw)
    need(value.get("schema") == "hepta-x230-benchmark-topology/v1"
         and value.get("profile_template_sha256") == digest(read_file(profile_template, 262144))
         and set(value.get("hosts", {})) == HOSTS, "topology is not bound to this profile/alias set")
    for host, item in value["hosts"].items():
        need(item.get("platform") in {"linux", "macos"}
             and isinstance(item.get("machine_group"), str) and 0 < len(item["machine_group"]) <= 256
             and not any(character in item["machine_group"] for character in "\r\n\0"),
             "invalid explicit platform/machine group: " + host)
        need(all(other["platform"] == item["platform"] for other in value["hosts"].values()
                 if other.get("machine_group") == item["machine_group"]),
             "one machine group has inconsistent platforms")
    receipt = {"file": "topology.json", "bytes": len(raw), "sha256": digest(raw),
               "profile_template_sha256": value["profile_template_sha256"], "hosts": value["hosts"],
               "alias_count": len(HOSTS),
               "physical_machine_groups": len({item["machine_group"] for item in value["hosts"].values()})}
    return raw, receipt


def check_prepared_topology(prepared_hosts, topology):
    expected = topology["hosts"]
    need(set(prepared_hosts) == set(expected) == HOSTS, "prepared topology aliases differ")
    for host in HOSTS:
        observed = prepared_hosts[host]["prepare"]
        need(observed["platform"] == ("darwin" if expected[host]["platform"] == "macos" else "linux"),
             "prepared host platform differs: " + host)
        for other in HOSTS:
            need((observed["hostname"] == prepared_hosts[other]["prepare"]["hostname"])
                 == (expected[host]["machine_group"] == expected[other]["machine_group"]),
                 "prepared host grouping differs: " + host + "/" + other)
    return {"verified": True, "alias_count": len(HOSTS),
            "distinct_reported_hostnames": len({row["prepare"]["hostname"] for row in prepared_hosts.values()}),
            "scope": "reported hostname equivalence and sys.platform compared to this profile's frozen preflight"}


def fixture(path, jobs, topology):
    path.mkdir(mode=0o700)
    state = path / "state"
    state.mkdir(mode=0o700)
    registry = state / "jobs"
    registry.mkdir(mode=0o700)
    hosts = {}
    for job in jobs:
        record = job["record"]
        hosts[job["host"]] = {"execution_mode": "operator", "ssh_target": record["ssh_target"],
            "platform": topology["hosts"][job["host"]]["platform"],
            "remote_state_dir": str(Path(record["remote_job_dir"]).parent.parent),
            "allow_execute": False, "allow_pty": False, "allow_write": False,
            "allow_job_network": False, "privileged_actions": {}}
        create_file(registry / (job["id"] + ".json"), job["record_bytes"])
    config = path / "runtime.json"
    create_file(config, canonical({"state_dir": str(state), "controller_workspace_roots": [], "hosts": hosts}))
    return config


def process_stat(pid):
    value = counters(pid)
    return value["birth_ticks"], cpu_seconds(value)


class Controller:
    def __init__(self, binary, config, profile, directory, workers, path_prefix=None, file_pool=False, allocator_values=None):
        self.binary = Path(binary)
        self.directory = directory
        self.rows = []
        self.pending = {}
        self.lock = threading.Lock()
        self.write_lock = threading.Lock()
        self.serial = 0
        self.unmatched = 0
        self.reader_error = None
        self.reader_eof = False
        self.transport = open_new(directory / "transport-responses.jsonl")
        self.transport_index = open_new(directory / "transport-responses.index.jsonl")
        self.transport_hash = hashlib.sha256()
        self.transport_index_hash = hashlib.sha256()
        self.transport_bytes = self.transport_index_bytes = self.transport_frames = 0
        self.stderr = (directory / "stderr.log").open("xb")
        argv = [str(binary), "mcp", "--runtime-config", str(config), "--runtime-prewarm",
                "--runtime-audit-group-commit", "--runtime-observation-pool-profile", str(profile)]
        if file_pool:
            argv.append("--runtime-file-observation-pool")
        env = {"PATH": (str(path_prefix) + ":" if path_prefix is not None else "") + "/usr/bin:/bin", "LANG": "C", "SHELL": "/bin/sh",
               "SSH_AUTH_SOCK": os.environ["SSH_AUTH_SOCK"], "TOKIO_WORKER_THREADS": str(workers), "RUST_LOG": "warn"}
        allocator_values = allocator.checked(allocator_values or {})
        env = allocator.child_environment(env, allocator_values)
        started_ns = time.monotonic_ns()
        self.child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=self.stderr, cwd=directory, env=env, start_new_session=True)
        self.birth = process_stat(self.child.pid)[0]
        self.resources = Resources(self.child.pid, directory)
        self.reader = threading.Thread(target=self.read_loop, daemon=True)
        self.reader.start()
        try:
            initialize = {}
            reply = self.rpc("initialize", {"protocolVersion": "2025-03-26", "capabilities": {},
                             "clientInfo": {"name": "hepta-x230-observation-abba", "version": "1"}}, 120, initialize)
            need("result" in reply and "error" not in reply, "MCP initialization failed")
            self.notify("notifications/initialized", {})
            ready_ns = time.monotonic_ns()
            self.startup = {"pid": self.child.pid, "birth_ticks": self.birth,
                            "start_monotonic_ns": started_ns, "ready_monotonic_ns": ready_ns,
                            "ready_ms": (ready_ns - started_ns) / 1e6,
                            "initialize_rpc": initialize,
                            "server_info": reply["result"].get("serverInfo"),
                            "stdio_protocol": reply["result"].get("protocolVersion")}
            self.startup["allocator_environment"] = allocator.observe(
                self.child.pid, self.birth, allocator_values, env, "after-native-initialize")
        except BaseException:
            self.close()
            raise

    def read_loop(self):
        try:
            while True:
                read_start = time.monotonic_ns()
                line = self.child.stdout.readline(MAX_MESSAGE + 1)
                received = time.monotonic_ns()
                if not line:
                    self.reader_eof = True
                    break
                entry = {"sequence": self.transport_frames, "offset": self.transport_bytes,
                         "bytes": len(line), "sha256": digest(line),
                         "read_start_monotonic_ns": read_start,
                         "received_monotonic_ns": received, "complete_line": line.endswith(b"\n")}
                self.transport.write(line)
                self.transport_hash.update(line)
                self.transport_bytes += len(line)
                self.transport_frames += 1
                try:
                    need(len(line) <= MAX_MESSAGE and line.endswith(b"\n"), "MCP response size/framing violation")
                    reply = json.loads(line)
                    need(isinstance(reply, dict), "MCP response must be an object")
                    entry["has_id"] = "id" in reply
                    entry["rpc_id"] = reply.get("id")
                except Exception as error:
                    entry["parse_error"] = type(error).__name__ + ": " + str(error)[:160]
                    raise
                finally:
                    index_line = canonical(entry)
                    self.transport_index.write(index_line)
                    self.transport_index_hash.update(index_line)
                    self.transport_index_bytes += len(index_line)
                if "id" not in reply:
                    continue
                with self.lock:
                    waiter = self.pending.pop(reply["id"], None)
                    if waiter is None:
                        self.unmatched += 1
                if waiter is not None:
                    waiter.put((reply, {"file": "transport-responses.jsonl", **entry}))
        except Exception as error:
            self.reader_error = type(error).__name__ + ": " + str(error)[:250]
        finally:
            with self.lock:
                pending = list(self.pending.values())
                self.pending.clear()
            for waiter in pending:
                waiter.put(({"error": {"code": -32099, "message": self.reader_error or "native stdio closed"}}, None))

    def notify(self, method, params):
        with self.write_lock:
            self.child.stdin.write(canonical({"jsonrpc": "2.0", "method": method, "params": params}))
            self.child.stdin.flush()

    def rpc(self, method, params, timeout=50, evidence=None):
        proof = evidence if evidence is not None else {}
        proof["rpc_start_monotonic_ns"] = time.monotonic_ns()
        with self.lock:
            self.serial += 1
            identity = self.serial
            waiter = queue.Queue(maxsize=1)
            self.pending[identity] = waiter
        request = canonical({"jsonrpc": "2.0", "id": identity, "method": method, "params": params})
        proof.update(request_id=identity, request_sha256=digest(request), request_bytes=len(request))
        try:
            with self.write_lock:
                proof["send_start_monotonic_ns"] = time.monotonic_ns()
                self.child.stdin.write(request)
                self.child.stdin.flush()
                proof["send_end_monotonic_ns"] = time.monotonic_ns()
            reply, transport = waiter.get(timeout=timeout)
            proof["transport_response"] = transport
            proof["response_dequeued_monotonic_ns"] = time.monotonic_ns()
            need(reply.get("id", identity) == identity, "MCP response identity differs")
            return reply
        finally:
            proof["rpc_end_monotonic_ns"] = time.monotonic_ns()
            with self.lock:
                self.pending.pop(identity, None)

    def call(self, tool, job, purpose):
        need(tool in TOOLS, "effectful or unsupported benchmark tool")
        args = {"host": job["host"], "job_id": job["id"]}
        if tool == "process_read":
            args.update(stdout_offset=0, stderr_offset=0, limit=16384)
        started_ns = time.monotonic_ns()
        row = {"tool": tool, "host": job["host"], "job_id": job["id"], "purpose": purpose,
               "automatic_retry": False, "start_monotonic": started_ns / 1e9,
               "start_monotonic_ns": started_ns, "start_unix": time.time(), "rpc": {}}
        dto = None
        try:
            reply = self.rpc("tools/call", {"name": tool, "arguments": args}, evidence=row["rpc"])
            row["response_sha256"] = digest(canonical(reply))
            if "error" in reply:
                row["rpc_error"] = reply["error"]
                raise RuntimeError("native RPC refused")
            result = reply["result"]
            row["isError"] = bool(result.get("isError", False))
            if row["isError"]:
                row["native_error"] = "\n".join(x.get("text", "") for x in result.get("content", []) if x.get("type") == "text")[:2048]
                raise RuntimeError("native observation refused")
            texts = [x["text"] for x in result.get("content", []) if x.get("type") == "text"]
            need(texts, "native observation has no JSON text")
            dto = json.loads(texts[0])
            need(dto.get("job_id") == job["id"] and dto.get("audit_recorded") is True
                 and "audit_warning" not in dto, "job identity or durable audit differs")
            if tool == "process_status":
                need(dto.get("state") == "succeeded" and dto.get("exit_code") == 0
                     and dto.get("output_complete") is True and not dto.get("cancelled")
                     and not dto.get("timed_out"), "original job terminal state differs")
                need(dto.get("log_bytes") == {"stdout": {"seen": len(job["expected"]), "stored": len(job["expected"])},
                                               "stderr": {"seen": 0, "stored": 0}}
                     and dto.get("log_truncated") == {"stdout": False, "stderr": False}
                     and dto.get("log_errors") == {"stdout": None, "stderr": None}, "original capture completeness differs")
            else:
                for name, expected in [("stdout", job["expected"]), ("stderr", b"")]:
                    part = dto[name]
                    data = bytes.fromhex(part["bytes_hex"])
                    need(data == expected and part["offset"] == 0
                         and part["next_offset"] == part["size"] == len(expected)
                         and part["eof"] is True, "complete original output or cursor differs")
                    row[name + "_sha256"] = digest(data)
                    row[name + "_bytes"] = len(data)
            row["dto_sha256"] = digest(canonical(dto))
            row["okay"] = True
        except Exception as error:
            row["okay"] = False
            row["error_type"] = type(error).__name__
            row["reason"] = str(error)[:500]
        finally:
            row["end_monotonic_ns"] = time.monotonic_ns()
            row["elapsed_ms"] = (row["end_monotonic_ns"] - row["start_monotonic_ns"]) / 1e6
            with self.lock:
                self.rows.append(row)
        return row

    def close(self):
        shutdown_method = "already_exited" if self.child.poll() is not None else "stdin_eof"
        if self.child.poll() is None:
            if self.child.stdin and not self.child.stdin.closed:
                self.child.stdin.close()
            try:
                self.child.wait(30)
            except subprocess.TimeoutExpired:
                shutdown_method = "sigterm_after_eof_timeout"
                self.child.terminate()
                try:
                    self.child.wait(10)
                except subprocess.TimeoutExpired:
                    shutdown_method = "sigkill_after_sigterm_timeout"
                    self.child.kill()
                    self.child.wait(10)
        self.reader.join(2)
        need(not self.reader.is_alive(), "transport reader did not stop")
        self.child.stdout.close()
        for stream in (self.transport, self.transport_index):
            stream.flush()
            os.fsync(stream.fileno())
            stream.close()
        self.stderr.close()
        resources = self.resources.stop()
        survivors = []
        for (pid, born) in self.resources.seen:
            if pid == self.child.pid:
                continue
            try:
                if process_stat(pid)[0] == born:
                    survivors.append({"pid": pid, "birth_ticks": born})
            except (FileNotFoundError, ProcessLookupError):
                pass
        return {"exit_code": self.child.returncode, "shutdown_method": shutdown_method,
                "resources": resources,
                "transport_capture": {"schema": "hepta-native-raw-transport/v1",
                    "frames": self.transport_frames, "reader_eof": self.reader_eof,
                    "raw": {"file": "transport-responses.jsonl", "bytes": self.transport_bytes,
                            "sha256": self.transport_hash.hexdigest()},
                    "index": {"file": "transport-responses.index.jsonl", "bytes": self.transport_index_bytes,
                              "sha256": self.transport_index_hash.hexdigest()}},
                "observed_descendant_survivors": survivors, "unmatched_responses": self.unmatched,
                "reader_error": self.reader_error}


def cell(controller, jobs, concurrency, count):
    resources_before = controller.resources.snapshot()
    before = counters(controller.child.pid)
    need(before["birth_ticks"] == controller.birth, "controller identity changed before benchmark cell")
    started_ns = time.monotonic_ns()
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        rows = list(pool.map(lambda index: controller.call(
            "process_status" if (index // 6) % 2 == 0 else "process_read",
            jobs[index % 6], "C" + str(concurrency)), range(count)))
    finished_ns = time.monotonic_ns()
    seconds = (finished_ns - started_ns) / 1e9
    after = counters(controller.child.pid)
    need(after["birth_ticks"] == controller.birth, "controller identity changed after benchmark cell")
    need(before["clock_ticks_per_second"] == after["clock_ticks_per_second"], "CPU clock rate changed")
    controller_cpu_seconds = (after["utime_ticks"] + after["stime_ticks"]
                              - before["utime_ticks"] - before["stime_ticks"]) / before["clock_ticks_per_second"]
    need(controller_cpu_seconds >= 0, "controller CPU counter moved backwards")
    resources_after = controller.resources.snapshot()
    latency = sorted(row["elapsed_ms"] for row in rows)
    successful = sum(row["okay"] for row in rows)
    return {"concurrency": concurrency, "calls": count, "successes": successful,
            "seconds": seconds, "completion_rps": count / seconds, "successful_rps": successful / seconds,
            "p50_ms": latency[math.ceil(count * .50) - 1], "p95_ms": latency[math.ceil(count * .95) - 1],
            "p99_ms": latency[math.ceil(count * .99) - 1], "max_ms": max(latency),
            "controller_cpu_seconds": controller_cpu_seconds,
            "controller_cpu_ms_per_call": 1000 * controller_cpu_seconds / count,
            "controller_cpu_source": "same-PID/start-ticks /proc/stat utime+stime before/after cell",
            "raw_timing": {"start_monotonic_ns": started_ns, "end_monotonic_ns": finished_ns,
                           "controller_before": before, "controller_after": after,
                           "cpu_counter_interval_brackets_wall_interval": True},
            "sampled_resources_before": resources_before,
            "sampled_resources_after": resources_after,
            "sampled_tree_cpu_seconds_delta": (resources_after["sampled_tree_cpu_seconds"]
                                                - resources_before["sampled_tree_cpu_seconds"]),
            "sampled_cpu_seconds_delta_by_scope": {
                scope: resources_after["sampled_cpu_seconds_by_scope"][scope]
                       - resources_before["sampled_cpu_seconds_by_scope"][scope]
                for scope in resources_before["sampled_cpu_seconds_by_scope"]},
            "sampled_tree_cpu_seconds_delta_is_lower_bound": False,
            "sampled_tree_cpu_seconds_delta_is_performance_numerator": False,
            "no_success_filtering": True, "rows": rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--arena-max", type=int, choices=allocator.ALLOWED_ARENA_MAX, default=1,
                        help="identical explicit MALLOC_ARENA_MAX for both A and B; default 1")
    parser.add_argument("--profile-template", type=Path, required=True)
    parser.add_argument("--topology", type=Path, required=True,
                        help="frozen alias/platform/machine-group preflight bound to this profile")
    parser.add_argument("--frozen-jobs", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--socket-parent", type=Path, required=True)
    parser.add_argument("--calls", type=int, default=96, help="balanced status/read calls per concurrency cell; multiple of 12")
    parser.add_argument("--concurrency", type=int, nargs="+", default=[1, 4, 8])
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--order", choices=["ABBA", "AB"], default="ABBA")
    args = parser.parse_args()
    need(args.calls > 0 and args.calls % 12 == 0 and max(args.concurrency) <= 32
         and min(args.concurrency) >= 1 and args.workers > 0, "invalid bounded benchmark dimensions")
    args.out = args.out.absolute()
    need(args.out.resolve() == args.out and not args.out.exists(), "output must be a fresh direct path")
    args.out.mkdir(mode=0o700)
    jobs = load_jobs(args.frozen_jobs)
    topology_raw, topology = load_topology(args.topology, args.profile_template)
    create_file(args.out / "topology.json", topology_raw)
    agent = os.environ.get("SSH_AUTH_SOCK", "")
    need(agent.startswith("/"), "held current SSH_AUTH_SOCK required")
    agent_before = agent_identity(agent)
    binaries = {"A": args.baseline.absolute(), "B": args.candidate.absolute()}
    binary_hashes = {key: digest(read_file(path, 128 * 1024 * 1024)) for key, path in binaries.items()}
    profile, profile_receipt = fresh_profile(args.profile_template, args.out / "profile", args.socket_parent, agent)
    report = {"schema": "hepta-x230-readonly-observation-abba/v2", "started_unix": time.time(),
        "transport": "native stdio MCP, one concurrent session per controller", "order": args.order,
        "binary_sha256": binary_hashes, "profile": profile_receipt,
        "six_originals": [{"host": j["host"], "job_id": j["id"], "record_sha256": j["record_sha256"],
                           "stdout_sha256": digest(j["expected"]), "stdout_bytes": len(j["expected"])} for j in jobs],
        "effect_starts": 0, "remote_mutation_tool_calls": 0, "automatic_rpc_retries": 0,
        "calls_per_cell": args.calls, "concurrency": args.concurrency, "tokio_workers": args.workers,
        "scope": "operator Python backend; completed jobs; warm observations; normal controller restart",
        "topology": topology,
        "instrumentation": {"complete_transport_bytes_retained": True,
            "monotonic_clock": time.get_clock_info("monotonic").implementation,
            "monotonic_clock_resolution_seconds": time.get_clock_info("monotonic").resolution,
            "trace_buffer_bytes": 65536, "fsync_per_message": False,
            "capture_and_sampling_wall_overhead_included": True,
            "comparable_directly_to_pre_r16_harness": False},
        "not_covered": ["new launches", "system jobctl", "target reboot", "physical power loss", "WAN partition"],
        "rounds": [], "passed": False}
    allocator_arms = {arm: allocator.configured(args.arena_max) for arm in "AB"}
    report["allocator_configuration"] = allocator.run_metadata(allocator_arms, binary_hashes)
    report["allocator_configuration"]["comparison_contract"] = "same-allocator-two-binaries/v1"
    report["allocator_configuration"]["same_allocator_environment"] = True
    path = args.out / "report.json"
    active = None
    try:
        for number, version in enumerate(args.order):
            need(agent_identity(agent) == agent_before, "current SSH agent identity changed before round")
            need(digest(read_file(binaries[version], 128 * 1024 * 1024)) == binary_hashes[version], "binary changed")
            directory = args.out / f"round-{number}-{version}"
            config = fixture(directory, jobs, topology)
            first = directory / "first"
            first.mkdir(mode=0o700)
            row = {"index": number, "version": version, "cells": [], "passed": False}
            report["rounds"].append(row)
            active = Controller(binaries[version], config, profile, first, args.workers,
                                allocator_values=allocator_arms[version])
            row["startup"] = active.startup
            row["initial_complete_outputs"] = [active.call("process_read", job, "preflight_complete_output") for job in jobs]
            need(all(x["okay"] for x in row["initial_complete_outputs"]), "six-host output preflight failed")
            for concurrency in args.concurrency:
                result = cell(active, jobs, concurrency, args.calls)
                row["cells"].append(result)
                save_report(path, report)
                print(json.dumps({"round": number, "version": version, **{k: v for k, v in result.items() if k != "rows"}}), flush=True)
            row["shutdown"] = active.close()
            active = None
            need(row["shutdown"]["exit_code"] == 0 and row["shutdown"]["shutdown_method"] == "stdin_eof"
                 and not row["shutdown"]["observed_descendant_survivors"]
                 and row["shutdown"]["reader_error"] is None
                 and row["shutdown"]["resources"]["sampler_error"] is None
                 and row["shutdown"]["transport_capture"]["reader_eof"] is True
                 and row["shutdown"]["unmatched_responses"] == 0,
                 "controller failed normal shutdown or retained observed children")
            restart = directory / "restart"
            restart.mkdir(mode=0o700)
            active = Controller(binaries[version], config, profile, restart, args.workers,
                                allocator_values=allocator_arms[version])
            row["restart_startup"] = active.startup
            row["restart_checks"] = [active.call(tool, job, "restart_same_original")
                                      for job in jobs for tool in ("process_status", "process_read")]
            row["restart_shutdown"] = active.close()
            active = None
            need(all(x["okay"] for x in row["restart_checks"]), "original readback failed after restart")
            need(row["restart_shutdown"]["exit_code"] == 0
                 and row["restart_shutdown"]["shutdown_method"] == "stdin_eof"
                 and not row["restart_shutdown"]["observed_descendant_survivors"]
                 and row["restart_shutdown"]["reader_error"] is None
                  and row["restart_shutdown"]["resources"]["sampler_error"] is None
                  and row["restart_shutdown"]["transport_capture"]["reader_eof"] is True
                 and row["restart_shutdown"]["unmatched_responses"] == 0,
                 "restarted controller cleanup failed")
            for job in jobs:
                need(read_file(job["path"], 65536) == job["record_bytes"], "source original metadata changed")
                need(read_file(directory / "state/jobs" / (job["id"] + ".json"), 65536) == job["record_bytes"],
                     "copied original metadata changed")
            row["passed"] = all(x["successes"] == x["calls"] for x in row["cells"])
            save_report(path, report)
        need(agent_identity(agent) == agent_before, "current SSH agent changed after experiment")
        need(allocator.source_sha256() == report["allocator_configuration"]["helper_sha256"],
             "allocator helper changed during experiment")
        report["passed"] = all(row["passed"] for row in report["rounds"])
    except BaseException as error:
        report["error"] = {"type": type(error).__name__, "reason": str(error)[:1000]}
    finally:
        if active is not None:
            report["interrupted_shutdown"] = active.close()
        report["finished_unix"] = time.time()
        try:
            report["source_originals_unchanged"] = all(read_file(j["path"], 65536) == j["record_bytes"] for j in jobs)
        except Exception as error:
            report["source_originals_unchanged"] = False
            report["source_originals_final_check_error"] = type(error).__name__ + ": " + str(error)[:500]
        try:
            report["binary_hashes_unchanged"] = all(digest(read_file(p, 128 * 1024 * 1024)) == binary_hashes[k] for k, p in binaries.items())
        except Exception as error:
            report["binary_hashes_unchanged"] = False
            report["binary_hashes_final_check_error"] = type(error).__name__ + ": " + str(error)[:500]
        try:
            report["topology_manifest_unchanged"] = read_file(args.topology, 65536) == topology_raw
        except Exception as error:
            report["topology_manifest_unchanged"] = False
            report["topology_final_check_error"] = type(error).__name__ + ": " + str(error)[:500]
        report["passed"] = (report["passed"] and report["source_originals_unchanged"]
                            and report["binary_hashes_unchanged"] and report["topology_manifest_unchanged"])
        save_report(path, report)
    print(json.dumps({"report": str(path), "passed": report["passed"], "error": report.get("error")}), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())


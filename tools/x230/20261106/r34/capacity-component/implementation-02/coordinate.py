#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""One six-host native capacity cell. Unsealed input is refused before any write/effect.

Only the one child driver owns DIRECT. These helper SSH processes are outside it.
This file is source preparation only until root supplies actual qualified bindings.
"""
import argparse
import concurrent.futures
import importlib.util
import json
import os
from pathlib import Path
import re
import select
import shlex
import signal
import stat
import subprocess
import threading
import time

import prepare_build as binding

ROOT = Path(__file__).resolve().parent
HOSTS = ("ai395", "mac", "main", "pocket4", "rog", "x230")
BASE_ARGS = ["-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "-o",
             "StrictHostKeyChecking=yes", "-o", "ForwardAgent=no"]
MAX_GAP_NS = 250_000_000
SAMPLE_SECONDS = 0.05


def need(value, reason):
    binding.need(value, reason)


def create_json(path, value):
    binding.create(path, binding.encoded(value))


def rust_quote(value):
    return "'" + value.replace("'", "'\"'\"'") + "'"


def helper_source(name):
    return (binding.regular(ROOT / "component/fixtures/common.py").decode() + "\n"
            + binding.regular(ROOT / ("component/fixtures/" + name)).decode())


def expected_wrapper(profile):
    options = {
        "IdentityAgent": profile["agent_socket"], "UserKnownHostsFile": profile["known_hosts"],
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
    argv = ["/usr/bin/ssh", "-F", profile["ssh_config"]]
    for key, value in options.items():
        argv += ["-o", key + "=" + value]
    raw = ("#!/bin/sh\nexec " + " ".join(map(shlex.quote, argv)) + ' "$@"\n').encode()
    return raw, argv


def expected_cancel(source):
    raw = binding.regular(Path(source) / "src/mcp/runtime/jobs.rs").decode()
    def constant(name):
        rows = re.findall(r"const " + name + r': &str = r#"(.*?)"#;', raw, re.S)
        need(len(rows) == 1 and all(ord(ch) < 128 for ch in rows[0]), "fixed ASCII cancellation constant differs")
        return rows[0]
    # These assembly expressions are unchanged in R24/R34. They are classification,
    # not an alternate execution path: only the real native::cancel invokes them.
    need('private_remote_code(&format!("{BOUND_OBSERVATION_CODE}\\n{code}"))' in raw
         and '"REMOTE_DIRECTORY_SOURCE = {}\\nexec(REMOTE_DIRECTORY_SOURCE)\\n{}"' in raw,
         "original cancellation assembly expression changed")
    code = ("REMOTE_DIRECTORY_SOURCE = " + json.dumps(constant("PRIVATE_DIRECTORY_CODE"), ensure_ascii=False)
            + "\nexec(REMOTE_DIRECTORY_SOURCE)\n" + constant("BOUND_OBSERVATION_CODE")
            + "\n" + constant("CANCEL_CODE"))
    return rust_quote("python3") + " -c " + rust_quote(code)


def proc_identity(pid):
    raw = Path("/proc") / str(pid) / "stat"
    value = raw.read_text()
    right = value.rfind(") ")
    need(right >= 0, "malformed original process stat")
    fields = value[right + 2:].split()
    return {"pid": pid, "birth_ticks": int(fields[19]), "ppid": int(fields[1]), "state": fields[0]}


def same_process(left, right):
    return (left["pid"], left["birth_ticks"]) == (right["pid"], right["birth_ticks"])


def pidfd_exited(fd):
    poller = select.poll()
    poller.register(fd, select.POLLIN)
    events = poller.poll(0)
    need(not any(mask & (select.POLLERR | select.POLLNVAL) for _, mask in events), "owned pidfd poll failed")
    return any(mask & select.POLLIN for _, mask in events)


class OriginalChild:
    """Own one Popen plus pidfd; WNOWAIT observation precedes an actual waitpid reap."""
    def __init__(self, argv, environment, directory, stdin_raw=b""):
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700)
        binding.create(self.directory / "stdin.bin", stdin_raw)
        self.input = open(self.directory / "stdin.bin", "rb")
        self.output = open(self.directory / "stdout", "xb", buffering=0)
        self.error = open(self.directory / "stderr", "xb", buffering=0)
        os.chmod(self.directory / "stdout", 0o600)
        os.chmod(self.directory / "stderr", 0o600)
        self.process = None
        self.pidfd = None
        self.status = None
        self.signals = []
        self.setup_error = None
        self.finish_result = None
        self.finish_attempt = 0
        self.started_ns = time.monotonic_ns()
        try:
            self.process = subprocess.Popen(argv, stdin=self.input, stdout=self.output, stderr=self.error,
                                            env=environment, start_new_session=True)
        except BaseException:
            self.close_files()
            raise
        self.identity = {"pid": self.process.pid, "birth_ticks": None, "ppid": os.getpid(), "state": "unobserved"}
        try:
            self.pidfd = os.pidfd_open(self.process.pid)
            self.identity = proc_identity(self.process.pid)
            need(self.identity["ppid"] == os.getpid(), "new process has a different parent")
        except Exception as error:
            # Return the owned handle to the caller even when post-spawn setup failed.
            # A failed constructor must not hide an admitted local child.
            self.setup_error = type(error).__name__ + ": " + str(error)

    def exited(self):
        if self.status is not None:
            return True
        result = os.waitid(os.P_PID, self.process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        if result is None:
            return False
        need(result.si_pid == self.process.pid, "waitid observed another child")
        return True

    def reap(self):
        if self.status is None:
            need(self.exited(), "original child is not ready to reap")
            waited, status = os.waitpid(self.process.pid, 0)
            need(waited == self.process.pid, "actual waitpid did not reap the original child")
            self.status = os.waitstatus_to_exitcode(status)
            self.process.returncode = self.status
        return self.status

    def send(self, number):
        if number not in self.signals and not self.exited():
            if self.pidfd is not None:
                signal.pidfd_send_signal(self.pidfd, number)
            else:
                # Only a just-created, still-unreaped direct child can reach this
                # setup-failure branch. WNOWAIT above preserves its PID reservation;
                # ECHILD raises and grants no numeric signal authority.
                os.kill(self.process.pid, number)
            self.signals.append(number)

    def close_files(self):
        for name in ("input", "output", "error"):
            value = getattr(self, name, None)
            if value is not None and not value.closed:
                value.close()
        if self.pidfd is not None:
            os.close(self.pidfd)
            self.pidfd = None

    def finish(self, deadline_ns, stdout_limit, stderr_limit):
        if self.finish_result is not None and self.status is not None:
            return self.finish_result
        failure = self.setup_error
        errors = []
        try:
            while failure is None and not self.exited():
                if time.monotonic_ns() >= deadline_ns:
                    failure = "owned child deadline"
                    break
                if os.fstat(self.output.fileno()).st_size > stdout_limit or os.fstat(self.error.fileno()).st_size > stderr_limit:
                    failure = "owned child output limit"
                    break
                time.sleep(SAMPLE_SECONDS)
            if failure is not None:
                self.send(signal.SIGTERM)
                until = time.monotonic_ns() + 2_000_000_000
                while not self.exited() and time.monotonic_ns() < until:
                    time.sleep(SAMPLE_SECONDS)
                if not self.exited():
                    self.send(signal.SIGKILL)
                until = time.monotonic_ns() + 5_000_000_000
                while not self.exited() and time.monotonic_ns() < until:
                    time.sleep(SAMPLE_SECONDS)
            need(self.exited(), "original child could not be observed exited; retain original handle as failed")
            self.reap()
        except Exception as error:
            errors.append(type(error).__name__ + ": " + str(error))
            failure = failure or "owned original wait/cleanup failed"
        try:
            self.output.flush()
            self.error.flush()
            os.fsync(self.output.fileno())
            os.fsync(self.error.fileno())
        except Exception as error:
            errors.append("original stream sync: " + str(error))
            failure = failure or "original stream retention failed"
        result = {"identity": self.identity, "returncode": self.status, "actual_waitpid_reaped": self.status is not None,
                  "started_monotonic_ns": self.started_ns, "finished_monotonic_ns": time.monotonic_ns(),
                  "signals": list(self.signals), "failure": failure, "errors": errors,
                  "setup_error": self.setup_error, "original_handle_retained": self.status is None}
        self.finish_attempt += 1
        name = "result.json" if self.finish_attempt == 1 else f"cleanup-result-{self.finish_attempt:02}.json"
        try:
            create_json(self.directory / name, result)
            self.finish_result = result
        finally:
            if self.status is not None:
                self.close_files()
        return result


class Remote:
    def __init__(self, root, wrapper, config, environment):
        self.root, self.wrapper, self.config, self.environment = root, wrapper, config, environment
        self.source = helper_source("coordinate_remote.py")
        self.command = rust_quote("/usr/bin/python3") + " -I -S -c " + rust_quote(self.source)
        self.counter = 0
        self.lock = threading.Lock()
        self.rows = []
        self.children = []

    def call(self, host, mode, ticket, job_id=None, launch_nonce=None, kind=None, terminal=False):
        with self.lock:
            index = self.counter
            self.counter += 1
        name = f"remote-{index:04}-{host}-{mode}-{kind or 'none'}"
        payload = {"mode": mode, "ticket": ticket, "job_id": job_id, "launch_nonce": launch_nonce, "kind": kind, "terminal": terminal}
        raw = binding.encoded(payload)
        need(len(raw) <= 4096, "bounded private coordinator payload exceeded")
        argv = [self.wrapper, *BASE_ARGS, self.config["hosts"][host]["ssh_target"], self.command]
        child = OriginalChild(argv, self.environment, self.root / name, raw)
        with self.lock:
            self.children.append(child)
        record = child.finish(child.started_ns + 12_000_000_000, 2 * 1024 * 1024, 262144)
        record.update(host=host, mode=mode, kind=kind, directory=name)
        with self.lock:
            self.rows.append(record)
        need(record["actual_waitpid_reaped"] is True and record["returncode"] == 0
             and record["failure"] is None and not record["signals"], "fixed private helper failed; no retry")
        value = json.loads(binding.regular(self.root / name / "stdout", 2 * 1024 * 1024))
        need(value["schema"] == "hepta-r34-capacity-remote/v1" and value["mode"] == mode
             and value["ticket"]["host"] == host and value["ticket"]["nonce"] == ticket["nonce"], "remote receipt identity differs")
        if mode != "prepare":
            need(value["ticket"] == ticket, "remote fixture identity changed")
        return value

    def finish_owned(self):
        rows = []
        for child in self.children:
            if child.status is None:
                try:
                    rows.append(child.finish(time.monotonic_ns(), 2 * 1024 * 1024, 262144))
                except Exception as error:
                    rows.append({"identity": child.identity, "actual_waitpid_reaped": False,
                                 "error": str(error), "original_handle_retained": True})
        return rows


def decoded(files, name, optional=False):
    row = files.get(name)
    if row is None:
        need(optional, "missing original private file: " + name)
        return None
    raw = bytes.fromhex(row["bytes_hex"])
    need(len(raw) == row["bytes"] and binding.sha(raw) == row["sha256"], "private receipt transport differs")
    return raw


def parallel(hosts, callback):
    values, errors = {}, {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        pending = {executor.submit(callback, host): host for host in hosts}
        for future in concurrent.futures.as_completed(pending):
            host = pending[future]
            try:
                values[host] = future.result()
            except Exception as error:
                errors[host] = type(error).__name__ + ": " + str(error)
    return values, errors


class Events:
    def __init__(self, path):
        self.path, self.offset, self.pending, self.rows = path, 0, b"", []
        self.identity = None

    def read(self):
        if not self.path.exists():
            return self.rows
        fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            need(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1
                 and stat.S_IMODE(info.st_mode) == 0o600 and self.offset <= info.st_size <= 4 * 1024 * 1024,
                 "unsafe or oversized component event stream")
            identity = (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode, info.st_nlink)
            need(self.identity in (None, identity), "component event stream was replaced")
            self.identity = identity
            stream.seek(self.offset)
            raw = stream.read(4 * 1024 * 1024 + 1)
            self.offset += len(raw)
            current = self.path.lstat()
            need((current.st_dev, current.st_ino, current.st_uid, current.st_gid, current.st_mode, current.st_nlink) == identity,
                 "component event stream changed during observation")
        self.pending += raw
        parts = self.pending.split(b"\n")
        self.pending = parts.pop()
        for part in parts:
            row = json.loads(part)
            need(row["schema"] == "hepta-r34-capacity-event/v1" and row["sequence"] == len(self.rows), "event stream gap")
            self.rows.append(row)
        return self.rows

    def event(self, name):
        rows = [row for row in self.read() if row["event"] == name]
        need(len(rows) <= 1, "duplicate component phase")
        return rows[0] if rows else None


class Occupancy:
    def __init__(self, child, root, prefix, gate_command, cancel_command, profile, config):
        self.child, self.prefix, self.gate_command, self.cancel_command = child, prefix, gate_command, cancel_command
        self.profile, self.config = profile, config
        self.trace = open(root / "occupancy.jsonl", "xb", buffering=0)
        os.chmod(root / "occupancy.jsonl", 0o600)
        self.rows, self.originals, self.fds = [], {}, {}
        self.targets = {row["ssh_target"]: name for name, row in config["hosts"].items()}

    def classify(self, argv):
        size = len(self.prefix)
        if argv[:size] == self.prefix and argv[size:size + len(BASE_ARGS)] == BASE_ARGS and len(argv) == size + len(BASE_ARGS) + 2:
            target, command = argv[-2:]
            need(target in self.targets, "unfrozen direct target")
            if command == self.gate_command:
                return "gate", self.targets[target]
            if command == self.cancel_command:
                return "cancel", self.targets[target]
            return "unexpected_direct", self.targets[target]
        if argv and Path(argv[0]).name == "ssh":
            controls = [arg.split("=", 1)[1] for arg in argv if arg.startswith("ControlPath=")]
            prefix = self.profile["socket_parent"] + "/hp-o-" + str(self.child.process.pid) + "-"
            if argv[:3] == ["/usr/bin/ssh", "-F", self.profile["ssh_config"]] and len(controls) == 1 and controls[0].startswith(prefix):
                return "observation_pool", None
            return "unclassified_ssh", None
        return "other", None

    def sample(self):
        row = {"monotonic_ns": time.monotonic_ns(), "processes": [], "errors": []}
        pending = [(self.child.process.pid, None)]
        seen = set()
        while pending:
            pid, parent = pending.pop()
            if pid in seen:
                continue
            seen.add(pid)
            need(len(seen) <= 128, "owned process inventory exceeded")
            try:
                before = proc_identity(pid)
                need(before["state"] not in ("Z", "X"), "observed process already exited")
                if parent is None:
                    need(same_process(before, self.child.identity), "controller generation changed")
                else:
                    need(before["ppid"] == parent["pid"] and same_process(proc_identity(parent["pid"]), parent), "observed parent changed")
                path = Path("/proc") / str(pid)
                raw = (path / "cmdline").read_bytes()
                need(len(raw) <= 262144, "owned argv exceeds bound")
                argv = [part.decode() for part in raw.rstrip(b"\x00").split(b"\x00")]
                kind, host = ("controller", None) if parent is None else self.classify(argv)
                children = set()
                for task in (path / "task").iterdir():
                    children.update(int(item) for item in (task / "children").read_text().split())
                after = proc_identity(pid)
                need(same_process(before, after) and before["ppid"] == after["ppid"], "process generation changed during sample")
                key = (pid, before["birth_ticks"])
                if parent is not None and key not in self.fds:
                    fd = os.pidfd_open(pid)
                    if not same_process(proc_identity(pid), before) or pidfd_exited(fd):
                        os.close(fd)
                        raise RuntimeError("process exited while pinning owned generation")
                    self.fds[key] = fd
                record = {**before, "kind": kind, "host": host, "argv_sha256": binding.sha(raw)}
                row["processes"].append(record)
                self.originals[key] = record
                pending.extend((child, before) for child in sorted(children))
            except (OSError, UnicodeError, ValueError, RuntimeError) as error:
                row["errors"].append({"pid": pid, "reason": str(error)})
        row["finished_monotonic_ns"] = time.monotonic_ns()
        need(len(self.rows) < 4096, "occupancy sample budget exceeded")
        self.trace.write(binding.encoded(row).replace(b"\n", b"") + b"\n")
        self.rows.append(row)
        return row

    def finish(self, force=False):
        survivors, signals = [], []
        for key, fd in self.fds.items():
            if not pidfd_exited(fd):
                survivors.append(self.originals[key])
                if force:
                    signal.pidfd_send_signal(fd, signal.SIGKILL)
                    signals.append({"pid": key[0], "birth_ticks": key[1], "signal": signal.SIGKILL})
        until = time.monotonic_ns() + 5_000_000_000
        while force and any(not pidfd_exited(fd) for fd in self.fds.values()) and time.monotonic_ns() < until:
            time.sleep(SAMPLE_SECONDS)
        remaining = [self.originals[key] for key, fd in self.fds.items() if not pidfd_exited(fd)]
        for fd in self.fds.values():
            os.close(fd)
        self.fds.clear()
        self.trace.flush()
        os.fsync(self.trace.fileno())
        self.trace.close()
        return {"observed_survivors_before_forced_cleanup": survivors, "signals": signals,
                "observed_survivors_after_cleanup": remaining,
                "external_absence_is_not_original_owner_reap_proof": True}


def gates_in(row):
    return [item for item in row["processes"] if item["kind"] == "gate"]


def expected_counts(victim):
    peer = "ai395" if victim == "x230" else "main"
    return {host: 2 if host in (victim, peer) else 1 for host in HOSTS}


def gate_barrier(row, victim):
    counts = {host: 0 for host in HOSTS}
    for item in gates_in(row):
        counts[item["host"]] += 1
    return (not row["errors"] and counts == expected_counts(victim)
            and not any(item["kind"] in ("cancel", "unexpected_direct", "unclassified_ssh") for item in row["processes"]))


def load_plan(path):
    raw = binding.regular(path)
    plan = json.loads(raw)
    need(plan.get("schema") == "hepta-r34-capacity-coordinator/v1" and plan.get("status") == "sealed_actual_inputs",
         "component run inputs remain unsealed")
    need(plan["arm"] in ("A", "B") and plan["victim"] in ("x230", "mac")
         and re.fullmatch(r"[0-9a-f]{24}", plan["nonce"]), "unfrozen cell role")
    need(hasattr(os, "pidfd_open") and hasattr(os, "WNOWAIT") and hasattr(signal, "pidfd_send_signal"),
         "owned Linux pidfd/waitid facilities are required before any effect")
    manifest_raw = binding.bound_file(plan["component_source_manifest"])
    manifest = json.loads(manifest_raw)
    need(manifest["schema"] == "hepta-r34-capacity-component-source/v1", "source manifest schema differs")
    for row in manifest["files"]:
        need(not Path(row["path"]).is_absolute() and ".." not in Path(row["path"]).parts, "unsafe component source name")
        body = binding.regular(ROOT / row["path"])
        need(len(body) == row["bytes"] and binding.sha(body) == row["sha256"], "component source differs")
    binary_raw = binding.bound_file(plan["driver_binary"], 128 * 1024 * 1024)
    need(binary_raw.startswith(b"\x7fELF"), "actual component ELF required")
    build = json.loads(binding.bound_file(plan["component_build_report"]))
    need(build.get("schema") == "hepta-r34-capacity-component-arm-build/v1" and build.get("passed") is True
         and build.get("arm") == plan["arm"] and build.get("binary") == plan["driver_binary"], "actual successful arm build differs")
    pair_raw = binding.bound_file(plan["component_pair_report"])
    pair = json.loads(pair_raw)
    need(pair.get("schema") == "hepta-r34-capacity-component-arm-build/v1" and pair.get("passed") is True
         and pair.get("arm") == "B" and pair.get("pair_closed") is True
         and pair.get("plan_sha256") == build.get("plan_sha256")
         and pair.get("graph_receipt") == build.get("graph_receipt"), "both actual component arm builds must be closed before any cell")
    first_raw = binding.bound_file(pair["baseline_arm_report"])
    first = json.loads(first_raw)
    need(build.get("component_source_manifest") == pair.get("component_source_manifest")
         == first.get("component_source_manifest") == plan["component_source_manifest"],
         "run source revision differs from the actual compiled A/B component revision")
    need(first.get("arm") == "A" and first.get("passed") is True
         and first.get("clock") == pair.get("clock")
         and pair.get("clock", {}).get("kind") == "linux:CLOCK_MONOTONIC"
         and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", pair.get("clock", {}).get("boot_id", "")) is not None
         and first["binary_preserved_monotonic_ns"] < pair["first_build_submitted_monotonic_ns"],
         "shared target A-preserve-before-B ordering differs")
    own_report_sha = binding.sha(first_raw) if plan["arm"] == "A" else binding.sha(pair_raw)
    need(own_report_sha == plan["component_build_report"]["sha256"], "selected arm is outside the closed A/B pair")
    binding.bound_file(first["binary"], 128 * 1024 * 1024)
    binding.bound_file(pair["binary"], 128 * 1024 * 1024)
    binding.full_map(plan["runtime_arm"]["source_root"], plan["runtime_arm"]["compile_inputs"])
    binding.full_map(plan["runtime_arm"]["source_root"], plan["runtime_arm"]["include_inputs"])
    binding.qualified_arm(plan["arm"], plan["runtime_arm"])
    need(build.get("runtime_compile_inputs") == plan["runtime_arm"]["compile_inputs"]
         and build.get("runtime_include_inputs") == plan["runtime_arm"]["include_inputs"], "ELF runtime map binding differs")
    config = json.loads(binding.bound_file(plan["runtime_config"]))
    output = Path(plan["output_directory"])
    need(output.is_absolute() and config["state_dir"] == str(output / "runtime-state")
         and not os.path.lexists(output), "component must use a new private controller state/output namespace")
    profile = json.loads(binding.bound_file(plan["observation_profile"]))
    need(profile["schema"] == "hepta-observation-ssh-pool/v1" and profile["allow_bounded_cached_authentication"] is True,
         "original observation profile policy differs")
    for name, key in (("ssh_config", "ssh_config_sha256"), ("known_hosts", "known_hosts_sha256")):
        need(binding.sha(binding.regular(Path(profile[name]))) == profile[key], "pinned SSH input differs")
    need(binding.sha(binding.regular(Path("/usr/bin/ssh"))) == profile["ssh_sha256"], "actual SSH ELF differs")
    wrapper_raw, prefix = expected_wrapper(profile)
    need(binding.bound_file(plan["ssh_wrapper"]) == wrapper_raw, "private wrapper differs from original helper policy")
    need(set(config["hosts"]) == set(HOSTS) == set(plan["source_records"]), "exact six configured/provenance hosts required")
    need(len({row["ssh_target"] for row in config["hosts"].values()}) == 6, "duplicate aliases do not establish six-host capacity")
    tickets = {}
    for host in HOSTS:
        old_raw = binding.bound_file(plan["source_records"][host])
        old = json.loads(old_raw)
        need(old["host"] == host and old["launch_state"] == "launched" and old["execution_mode"] == "operator"
             and old["system_jobctl"] is False and old["executable"] == "/usr/bin/python3" and old["args"][:2] == ["-I", "-S"]
             and old["ssh_target"] == config["hosts"][host]["ssh_target"], "frozen operator provenance differs")
        old_job = Path(old["remote_job_dir"])
        need(old_job.is_absolute() and old_job.name == old["id"] and old_job.parent.name == "jobs", "original remote state provenance differs")
        base, name = str(old_job.parent.parent), "r34-capacity-" + plan["nonce"] + "-" + host
        need(config["hosts"][host]["remote_state_dir"] == base + "/" + name, "config does not select the fresh fixture")
        platform = "darwin" if config["hosts"][host].get("platform") == "macos" else "linux"
        tickets[host] = {"nonce": plan["nonce"], "host": host, "victim": plan["victim"], "base": base, "name": name,
                         "fixture_identity": None, "source_job_id": old["id"], "source_record_sha256": binding.sha(old_raw),
                         "expected_platform": platform}
    allowed_environment = {"MALLOC_ARENA_MAX", "MALLOC_TRIM_THRESHOLD_", "MALLOC_MMAP_THRESHOLD_", "RAYON_NUM_THREADS", "TOKIO_WORKER_THREADS"}
    need(isinstance(plan["environment"], dict) and set(plan["environment"]) <= allowed_environment
         and all(isinstance(value, str) and value.isdigit() for value in plan["environment"].values()), "unfrozen component environment")
    environment = os.environ.copy()
    for key in allowed_environment:
        environment.pop(key, None)
    environment.update(plan["environment"])
    environment["PATH"] = str(Path(plan["ssh_wrapper"]["path"]).parent) + ":/usr/local/bin:/usr/bin:/bin"
    environment["SSH_AUTH_SOCK"] = profile["agent_socket"]
    for key in ("LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH"):
        need(not environment.get(key), "injected loader environment is outside the component comparison")
    return plan, raw, config, profile, prefix, tickets, environment


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    args = parser.parse_args()
    plan, input_raw, config, profile, prefix, tickets, environment = load_plan(args.input)
    output = Path(plan["output_directory"])
    need(output.is_absolute() and output.parent.resolve(strict=True) == output.parent and not os.path.lexists(output),
         "create-only cell output required")
    output.mkdir(mode=0o700)
    binding.create(output / "input.json", input_raw)
    control = output / "control"
    control.mkdir(mode=0o700)
    remote = Remote(output, plan["ssh_wrapper"]["path"], config, environment)
    driver = tracker = resources = None
    events = Events(output / "driver" / "events.jsonl")
    jobs, launches, requests, release_attempts = {}, {}, {}, set()
    release_lock = threading.Lock()
    primary_error, cleanup_errors, report = None, [], {}
    release_future = victim_future = None
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=2)

    def command(action, reason=None):
        value = {"schema": "hepta-r34-capacity-control/v1", "nonce": plan["nonce"], "action": action, "jobs": jobs}
        if reason is not None:
            value["reason"] = reason
        create_json(control / (action + ".json"), value)

    def inspect(host, terminal=False):
        return remote.call(host, "inspect", tickets[host], jobs[host], launches.get(host), terminal=terminal)

    def release(host, kind):
        key = (host, kind)
        with release_lock:
            need(key not in release_attempts, "private release was already attempted; no automatic retry")
            release_attempts.add(key)
        return remote.call(host, "release", tickets[host], jobs[host], launches[host], kind)

    def wait_event(name, deadline):
        while time.monotonic_ns() < deadline:
            event = events.event(name)
            starts = events.event("starts_joined")
            if starts is not None and starts["data"]["errors"]:
                jobs.update(starts["data"]["jobs"])
                raise RuntimeError("one or more original starts failed; retain primary error and reconcile known jobs")
            if event is not None:
                return event
            need(not driver.exited(), "original driver ended before " + name)
            if tracker is not None:
                tracker.sample()
            time.sleep(SAMPLE_SECONDS)
        raise TimeoutError("coordinator phase deadline: " + name)

    try:
        prepared, failures = parallel(HOSTS, lambda host: remote.call(host, "prepare", tickets[host]))
        for host, result in prepared.items():
            tickets[host] = result["ticket"]
        create_json(output / "prepared-fixtures.json", {"results": prepared, "errors": failures})
        need(not failures and len(prepared) == 6, "fresh private fixture preparation failed; no driver launched")
        map_sha = binding.sha(binding.encoded(plan["runtime_arm"]["compile_inputs"]))
        cell = {"schema": "hepta-r34-capacity-cell/v1", "status": "sealed_actual_cell", "arm": plan["arm"],
                "nonce": plan["nonce"], "victim": plan["victim"], "runtime_config": plan["runtime_config"]["path"],
                "observation_profile": plan["observation_profile"]["path"], "output_directory": str(output / "driver"),
                "control_directory": str(control), "fixtures": tickets,
                "bindings": {"driver_binary_sha256": plan["driver_binary"]["sha256"], "runtime_source_map_sha256": map_sha,
                             "runtime_qualification_report_sha256": plan["runtime_arm"]["qualification_report"]["sha256"],
                             "component_build_report_sha256": plan["component_build_report"]["sha256"],
                             "scenario_sources_sha256": plan["component_source_manifest"]["sha256"]}}
        create_json(output / "cell.json", cell)
        driver = OriginalChild([plan["driver_binary"]["path"], str(output / "cell.json")], environment, output / "driver-process")
        need(driver.setup_error is None, "original driver post-spawn identity setup failed")
        gate_source = helper_source("gate.py")
        gate_command = rust_quote("/usr/bin/python3") + " -I -S -c " + rust_quote(gate_source)
        tracker = Occupancy(driver, output, prefix, gate_command, expected_cancel(plan["runtime_arm"]["source_root"]), profile, config)
        spec = importlib.util.spec_from_file_location("r34_original_resources", ROOT / "reference/observation_resources.py")
        resource_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(resource_module)
        resources = resource_module.Resources(driver.process.pid, output)
        started = wait_event("jobs_started", driver.started_ns + 90_000_000_000)
        jobs.update(started["data"]["jobs"])
        need(set(jobs) == set(HOSTS), "six original jobs were not established")
        proofs, failures = parallel(HOSTS, inspect)
        create_json(output / "jobs-before-gates.json", {"results": proofs, "errors": failures})
        need(not failures, "original ready inspection failed")
        for host, proof in proofs.items():
            files = proof["files"]
            request_raw = decoded(files, "request.json")
            request = json.loads(request_raw)
            ready = json.loads(decoded(files, "workload.ready.json"))
            need(ready["job_id"] == jobs[host] and request["job_id"] == jobs[host]
                 and decoded(files, "exit.witness.json", True) is None, "fixture was not an existing live original job")
            launches[host], requests[host] = request["launch_nonce"], binding.sha(request_raw)
        command("start-gates")
        submitted = wait_event("gates_submitted", time.monotonic_ns() + 15_000_000_000)
        barrier_deadline = submitted["data"]["barrier_deadline_monotonic_ns"]
        barrier = None
        while time.monotonic_ns() < barrier_deadline:
            proofs, failures = parallel(HOSTS, inspect)
            create_json(output / ("gate-ready-round-" + str(len(remote.rows)) + ".json"), {"results": proofs, "errors": failures})
            need(not failures, "gate ready inspection failed; no automatic retry")
            ready = True
            for host, proof in proofs.items():
                for index in range(expected_counts(plan["victim"])[host]):
                    body = decoded(proof["files"], f"gate-{index}.ready.json", True)
                    ready = ready and body is not None
                    need(decoded(proof["files"], f"gate-{index}.finished.json", True) is None, "gate ended before barrier")
                    if body is not None:
                        value = json.loads(body)
                        need(value["nonce"] == plan["nonce"] and value["host"] == host and value["role"] == f"gate-{index}"
                             and value["ttl_seconds"] == 30, "gate ready receipt differs")
            sample = tracker.sample()
            need(not any(row["event"] == "gate_completed" for row in events.read()), "original ordinary call ended before barrier")
            if ready and gate_barrier(sample, plan["victim"]) and time.monotonic_ns() < barrier_deadline:
                barrier = sample
                break
            time.sleep(SAMPLE_SECONDS)
        need(barrier is not None, "eight shared ordinary slots were not established within the fixed deadline")
        report["barrier"] = barrier
        command("cancel")
        dispatched = wait_event("cancel_dispatch", barrier_deadline)
        dispatch = dispatched["monotonic_ns"]
        release_at = dispatch + 3_000_000_000
        report["cancel_dispatch"] = dispatched

        def scheduled_release():
            while time.monotonic_ns() < release_at:
                time.sleep(max(0, min(SAMPLE_SECONDS, (release_at - time.monotonic_ns()) / 1_000_000_000)))
            began = time.monotonic_ns()
            gate_values, gate_errors = parallel(HOSTS, lambda host: release(host, "gate"))
            # Phase timing is fixed, not conditional on which arm's cancellation returns.
            other_values, other_errors = parallel([host for host in HOSTS if host != plan["victim"]], lambda host: release(host, "job"))
            return {"planned_monotonic_ns": release_at, "dispatch_monotonic_ns": began,
                    "gate_results": gate_values, "gate_errors": gate_errors,
                    "nonvictim_job_results": other_values, "nonvictim_job_errors": other_errors,
                    "victim_job_was_released": False}

        def observe_held_cancel():
            rows = []
            for _ in range(24):
                if time.monotonic_ns() >= release_at:
                    break
                before = time.monotonic_ns()
                proof = inspect(plan["victim"])
                after = time.monotonic_ns()
                raw = decoded(proof["files"], "cancel-request.json", True)
                row = {"begin_monotonic_ns": before, "end_monotonic_ns": after,
                       "cancel_request": None if raw is None else json.loads(raw),
                       "cancel_request_sha256": None if raw is None else binding.sha(raw)}
                rows.append(row)
                if raw is not None:
                    need(row["cancel_request"]["job_id"] == jobs[plan["victim"]]
                         and row["cancel_request"]["launch_nonce"] == launches[plan["victim"]], "held cancel identity differs")
                    return {"rows": rows, "observed_before_release": after < release_at}
                time.sleep(SAMPLE_SECONDS)
            return {"rows": rows, "observed_before_release": False}

        release_future = pool.submit(scheduled_release)
        victim_future = pool.submit(observe_held_cancel)
        while not driver.exited() and time.monotonic_ns() < driver.started_ns + 180_000_000_000:
            tracker.sample()
            events.read()
            time.sleep(SAMPLE_SECONDS)
        need(driver.exited(), "original driver did not finish its bounded operations/cleanup")
        release_report = release_future.result()
        report["release"] = release_report
        report["held_cancel_receipt"] = victim_future.result()
        need(report["held_cancel_receipt"]["observed_before_release"] is (plan["arm"] == "B"),
             "original remote cancel-request did not match this arm's held-gate boundary")
        need(not release_report["gate_errors"] and not release_report["nonvictim_job_errors"]
             and 0 <= release_report["dispatch_monotonic_ns"] - release_at <= MAX_GAP_NS,
             "fixed release phase failed or was late")
        driver_result = driver.finish(time.monotonic_ns() + 1_000_000_000, 1048576, 1048576)
        report["driver_process"] = driver_result
        need(driver_result["returncode"] == 0 and not driver_result["signals"], "driver primary/cleanup phase failed")
        report["driver_result"] = json.loads(binding.regular(output / "driver/driver-result.json", 16 * 1024 * 1024))
        value = report["driver_result"]
        need(value["direct_shutdown_awaited"] is True and value["direct_shutdown_error"] is None
             and value["pool_shutdown_awaited"] is True and value["pool_shutdown_error"] is None
             and value["operation_error"] is None, "original owner cleanup was not confirmed")
        reconciled = {row["host"]: row for row in value["operation"]["job_reconciliation"]}
        need(set(reconciled) == set(HOSTS) and not value["operation"]["job_reconciliation_errors"],
             "all six original jobs must have complete native reconciliation")
        final, failures = parallel(HOSTS, lambda host: inspect(host, terminal=True))
        report["final_private_inspection"] = {"results": final, "errors": failures}
        need(not failures, "original terminal inspection failed")
        for host, proof in final.items():
            files = proof["files"]
            need(binding.sha(decoded(files, "request.json")) == requests[host], "original request changed")
            terminal_raw = decoded(files, "exit.json")
            terminal = json.loads(terminal_raw)
            witness = json.loads(decoded(files, "exit.witness.json"))
            need(terminal["job_id"] == witness["job_id"] == jobs[host]
                 and terminal["launch_nonce"] == witness["launch_nonce"] == launches[host]
                 and witness["exit_sha256"] == binding.sha(terminal_raw), "original terminal/witness identity differs")
            need(witness["terminal_publication_protocol"] == terminal["terminal_publication_protocol"] == 1,
                 "original durable terminal publication protocol differs")
            status = reconciled[host]["terminal_status"]
            need(status["terminal_publication_confirmed"] is True and status["audit_recorded"] is True
                 and all(status.get(key) == item for key, item in terminal.items()), "native status differs from original terminal bytes")
            finished = json.loads(decoded(files, "workload.finished.json"))
            reason = "sigterm_cleanup_finished" if host == plan["victim"] else "released"
            need(finished["reason"] == reason and finished["job_id"] == jobs[host], "fixture finished by a different mechanism")
            need(terminal["output_complete"] is True and terminal["output_durable"] is True
                 and terminal["log_synced"] == {"stdout": True, "stderr": True}
                 and terminal["log_truncated"] == {"stdout": False, "stderr": False}
                 and terminal["log_errors"] == {"stdout": None, "stderr": None}
                 and terminal["timed_out"] is False and terminal["exit_code"] == 0
                 and terminal["cancelled"] is (host == plan["victim"]), "original terminal/output contract differs")
            expected_logs = {"stdout": f"BEGIN {host} {plan['nonce']}\nEND {host} {reason}\n".encode(),
                             "stderr": f"OWNED-COMPONENT {host}\n".encode()}
            read = json.loads(binding.regular(output / f"driver/read-{host}.json", 65536))
            need(read["job_id"] == jobs[host] and read["audit_recorded"] is True
                 and decoded(files, "stdin.bin") == f"HEPTA-R34-CAPACITY {plan['nonce']} {host}\n".encode(),
                 "original input/output read binding differs")
            for stream, expected in expected_logs.items():
                part = read[stream]
                need(decoded(files, stream + ".log") == expected
                     and terminal["log_bytes"][stream] == {"seen": len(expected), "stored": len(expected)}
                     and part["offset"] == 0 and part["next_offset"] == part["size"] == len(expected)
                     and part["eof"] is True and bytes.fromhex(part["bytes_hex"]) == expected, "original output bytes/cursors differ")
            key = json.loads(binding.regular(output / f"driver/original-key-{host}.json", 1048576))
            need(key["reused"] is True and key["retried_launch"] is False and key["launch"] is None
                 and key["job"]["id"] == key["status"]["job_id"] == jobs[host], "original key reconciliation differs")
            for index in range(expected_counts(plan["victim"])[host]):
                role = f"gate-{host}-{index}"
                gate_raw = binding.regular(output / f"driver/{role}.stdout", 65536)
                gate = json.loads(gate_raw)
                ready = json.loads(decoded(files, f"gate-{index}.ready.json"))
                need(gate_raw == decoded(files, f"gate-{index}.finished.json")
                     and gate["schema"] == "hepta-r34-capacity-gate-finished/v1" and gate["reason"] == "released"
                     and gate["nonce"] == plan["nonce"] and gate["host"] == host and gate["role"] == f"gate-{index}"
                     and gate["process"] == ready["process"] and gate["fixture_identity"] == tickets[host]["fixture_identity"],
                     "original gate result or independent finish receipt differs")
            if host == plan["victim"]:
                need(decoded(files, "job-release.json", True) is None and finished["signals"] >= 1, "victim was normal-released instead of cancelled")
                cancel_request_raw = decoded(files, "cancel-request.json")
                cancel_request = json.loads(cancel_request_raw)
                need(cancel_request["job_id"] == jobs[host] and cancel_request["launch_nonce"] == launches[host],
                     "final original cancellation intent identity differs")
                if plan["arm"] == "B":
                    held = [row for row in report["held_cancel_receipt"]["rows"] if row["cancel_request"] is not None]
                    need(held and held[-1]["cancel_request_sha256"] == binding.sha(cancel_request_raw),
                         "held cancellation intent differs from original terminal-stage intent")
        initial = {(item["pid"], item["birth_ticks"]) for item in gates_in(barrier)}
        rows = [row for row in tracker.rows if dispatch <= row["monotonic_ns"]
                and row["monotonic_ns"] <= row["finished_monotonic_ns"] < release_at]
        times = [dispatch, *[row["monotonic_ns"] for row in rows], release_at]
        need(rows and max(b - a for a, b in zip(times, times[1:])) <= MAX_GAP_NS, "occupancy coverage gap; cannot infer reserve from low latency")
        witnesses = []
        for row in rows:
            need(not row["errors"], "occupancy identity gap during measured interval")
            need({(item["pid"], item["birth_ticks"]) for item in gates_in(row)} == initial, "original ordinary gate generations changed")
            cancel = [item for item in row["processes"] if item["kind"] == "cancel"]
            need(not any(item["kind"] in ("unexpected_direct", "unclassified_ssh") for item in row["processes"]), "unclassified transport in capacity witness")
            need(len(cancel) <= (1 if plan["arm"] == "B" else 0), "observed direct capacity exceeded this arm's bound")
            if len(cancel) == 1:
                need(cancel[0]["host"] == plan["victim"], "extra direct child is not the original victim cancellation")
                witnesses.append(row)
        need(plan["arm"] == "A" or witnesses, "ninth direct child/third victim-target child not witnessed")
        cancel = json.loads(binding.regular(output / "driver/cancel.result.json", 65536))
        need(cancel["library_returned"] is True and cancel["response"].get("termination_confirmed") is False
             and cancel["response"].get("job_id") == jobs[plan["victim"]]
             and cancel["response"].get("result") in ("stop_requested", "term_sent")
             and cancel["response"].get("outcome") != "unknown" and cancel["response"].get("audit_recorded") is True
             and cancel["response"].get("automatic_retry") is False
             and cancel["response"].get("atomic_identity") is (tickets[plan["victim"]]["expected_platform"] == "linux"),
             "original cancellation ACK differs")
        if plan["arm"] == "A":
            need(cancel["finished_monotonic_ns"] >= release_at, "baseline returned while all eight ordinary gates should be held")
        report["occupancy_witness"] = {"measurement_samples": len(rows), "reserve_overlap_samples": len(witnesses),
                                        "first_overlap": witnesses[0] if witnesses else None, "sample_gap_limit_ns": MAX_GAP_NS}
        report["cancel_timing"] = {key: cancel[key] for key in ("dispatch_monotonic_ns", "entry_monotonic_ns", "finished_monotonic_ns")}
    except Exception as error:
        primary_error = type(error).__name__ + ": " + str(error)
    finally:
        if primary_error is not None and driver is not None:
            try:
                starts = events.event("starts_joined")
                if starts is not None:
                    jobs.update(starts["data"]["jobs"])
                command("abort", primary_error)
            except Exception as error:
                cleanup_errors.append("abort control: " + str(error))
            # Preserve unknown release attempts. Never resend one that may already have taken effect.
            for host in sorted(jobs):
                try:
                    if host not in launches:
                        proof = inspect(host)
                        launches[host] = json.loads(decoded(proof["files"], "request.json"))["launch_nonce"]
                    for kind in ("gate", "job"):
                        if (host, kind) not in release_attempts:
                            release(host, kind)
                except Exception as error:
                    cleanup_errors.append(host + " private failure release: " + str(error))
        if release_future is not None:
            try:
                report.setdefault("release", release_future.result())
            except Exception as error:
                cleanup_errors.append("release worker: " + str(error))
        if victim_future is not None:
            try:
                report.setdefault("held_cancel_receipt", victim_future.result())
            except Exception as error:
                cleanup_errors.append("held cancel inspection: " + str(error))
        pool.shutdown(wait=True)
        report["coordinator_ssh_cleanup"] = remote.finish_owned()
        if any(row.get("actual_waitpid_reaped") is not True for row in report["coordinator_ssh_cleanup"]):
            cleanup_errors.append("one or more original coordinator SSH children remain unconfirmed")
        if driver is not None and driver.status is None:
            try:
                report["driver_process"] = driver.finish(driver.started_ns + 180_000_000_000, 1048576, 1048576)
                need(report["driver_process"]["actual_waitpid_reaped"] is True, "original driver reap remains unconfirmed")
            except Exception as error:
                cleanup_errors.append("original driver wait: " + str(error))
        if resources is not None:
            try:
                report["resources"] = resources.stop()
            except Exception as error:
                cleanup_errors.append("original resource sampler: " + str(error))
        if tracker is not None:
            try:
                report["observed_descendant_cleanup"] = tracker.finish(force=True)
                need(not report["observed_descendant_cleanup"]["observed_survivors_before_forced_cleanup"], "observed transport descendants survived original owner shutdown")
            except Exception as error:
                cleanup_errors.append("observed descendant cleanup: " + str(error))
        try:
            binding.full_map(plan["runtime_arm"]["source_root"], plan["runtime_arm"]["compile_inputs"])
            binding.full_map(plan["runtime_arm"]["source_root"], plan["runtime_arm"]["include_inputs"])
            binding.bound_file(plan["driver_binary"], 128 * 1024 * 1024)
            for key in ("runtime_config", "observation_profile", "ssh_wrapper", "component_source_manifest", "component_build_report", "component_pair_report"):
                binding.bound_file(plan[key])
        except Exception as error:
            cleanup_errors.append("final frozen input check: " + str(error))
        report.update(schema="hepta-r34-native-direct-capacity-cell/v1", arm=plan["arm"], nonce=plan["nonce"], victim=plan["victim"],
                      primary_error=primary_error, cleanup_errors=cleanup_errors,
                      passed=primary_error is None and not cleanup_errors, original_jobs=jobs, original_launch_nonces=launches,
                      remote_calls=remote.rows, automatic_retries=0, candidate_adopted=False,
                      full_mcp_global_capacity_established=False, normal_runtime_performance_established=False,
                      scope="one process production DIRECT with real six-host SSH and original native cancellation")
        create_json(output / "report.json", report)
    print(json.dumps({"report": str(output / "report.json"), "passed": report["passed"], "scope": report["scope"]}, sort_keys=True))
    raise SystemExit(0 if report["passed"] else 1)


def interrupted(signum, _frame):
    # Preserve the primary failure before the normal original-job/handle cleanup.
    # SIGINT from the unchanged outer owned-stage cleanup must not bypass it as
    # KeyboardInterrupt and accidentally leave primary_error unset.
    raise RuntimeError("capacity coordinator interrupted by signal " + str(signum))


if __name__ == "__main__":
    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, interrupted)
    main()

#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Qualify ordinary public jobs after a real native v26 Worker installation.

The external Python/C fixtures do not supply installed policy or success
receipts. The administrator pins the native installer, compiler, completed cold
report and Store package. This driver invokes that ordinary installer once,
then exercises the configuration and nineteen controller members it published.
The existing hosted Worker campaign remains a separate required gate.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import signal
import stat
import subprocess
import sys
import time
import traceback


ROLES = (
    "HIA_AGENT_NATIVE_TOOL_CATALOG.json", "hia-agent-job-terminal-receipt",
    "hia-agent-mcp-catalog", "hia-agent-mcp-input-schema",
    "hia-agent-mcp-negotiation", "hia-agent-mcp-proof-schema",
    "hia-agent-mcp-reply", "hia-agent-mcp-request", "hia-agent-mcp-response-schema",
    "hia-agent-mcp-terminal", "hia-agent-mcp-uri", "hia-job-cancel",
    "hia-job-entry", "hia-job-launch", "hia-job-observation", "hia-job-receipt",
    "hia-job-submit", "hia-job-supervisor", "hia-worker-prepare",
)
JOB_ROLES = {"entry": "hia-job-entry", "submit": "hia-job-submit",
             "observation": "hia-job-observation", "cancel": "hia-job-cancel",
             "launcher": "hia-job-launch"}
ROLE_LIMITS = {"hia-job-entry": 2 << 20, "hia-job-submit": 4 << 20,
               "hia-job-observation": 2 << 20,
               "HIA_AGENT_NATIVE_TOOL_CATALOG.json": 64 << 20}
WORKER_FIELDS = ("worker_sha256", "backend_sha256", "catalog_sha256",
                 "native_helpers_sha256", "python_executable", "native_helpers_manifest")
HOST = "public_native"
STDIN = "public-native-stdin\n"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def strict_json(raw):
    def fields(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON field: " + key)
            result[key] = value
        return result

    def constant(value):
        raise RuntimeError("nonfinite JSON value: " + value)

    return json.loads(raw, object_pairs_hook=fields, parse_constant=constant)


def is_pin(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def ordinary(path, limit, *, mode=None):
    """Capture one ordinary, stable, independently owned physical file."""
    path = Path(path)
    require(path.is_absolute() and path.parent.resolve(strict=True) == path.parent,
            "noncanonical file parent: " + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_uid in {0, os.geteuid()} and before.st_mode & 0o022 == 0
                and 0 <= before.st_size <= limit,
                "unsafe ordinary file: " + str(path))
        if mode is not None:
            require(stat.S_IMODE(before.st_mode) == mode, "wrong file mode: " + str(path))
        chunks = []
        remaining = before.st_size
        while remaining:
            data = os.read(fd, min(remaining, 65536))
            require(bool(data), "short ordinary-file read")
            chunks.append(data)
            remaining -= len(data)
        require(os.read(fd, 1) == b"", "ordinary file grew during capture")
        after = os.fstat(fd)
        current = path.stat(follow_symlinks=False)
        def stamp(info):
            return (info.st_dev, info.st_ino, info.st_mode, info.st_uid,
                    info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        require(stamp(before) == stamp(after) == stamp(current),
                "ordinary file changed during capture")
        return b"".join(chunks)
    finally:
        os.close(fd)


def file_pin(path, expected, limit=512 << 20):
    require(is_pin(expected), "an explicit lowercase input SHA256 is required")
    raw = ordinary(path, limit)
    require(sha(raw) == expected, "input SHA256 differs: " + str(path))
    return {"path": str(path), "bytes": len(raw), "sha256": expected}


def controller_manifest(raw):
    value = strict_json(raw)
    require(type(value) is dict and set(value) == {"schema", "files"}
            and value["schema"] == "hepta.hia.mcp.controller.v26"
            and type(value["files"]) is dict and set(value["files"]) == set(ROLES)
            and all(is_pin(pin) for pin in value["files"].values()),
            "a complete nineteen-role v26 controller is required")
    return value


def install_receipt(raw, package_pin):
    value = strict_json(raw)
    require(type(value) is dict
            and value.get("schema") == "hepta.hia.native-worker-install.v1"
            and value.get("installed") is True and value.get("source_attested") is True
            and value.get("package_sha256") == package_pin,
            "ordinary native installation did not publish a bound success receipt")
    return value


def installed_binding(installation, base_config, catalog):
    """Check real published bytes, not synthetic controller/config receipts."""
    config_path = installation / "runtime-config.json"
    config_bytes = ordinary(config_path, 64 << 20, mode=0o600)
    config = strict_json(config_bytes)
    require(type(config) is dict and type(config.get("hosts")) is dict
            and type(config.get("hia_worker")) is dict,
            "native installer omitted its runtime configuration")
    require(config["hia_worker"].get("host") == HOST and HOST in config["hosts"],
            "native configuration selected another host")
    host = config["hosts"][HOST]
    require(type(host) is dict and host.get("platform") == "linux"
            and host.get("execution_mode") == "operator"
            and host.get("allow_execute") is True and host.get("allow_write") is True
            and host.get("allow_detached_fallback") is False,
            "native public campaign requires the original strict Linux operator policy")
    entries = host.get("native_jobs")
    require(type(entries) is dict and set(entries) == set(JOB_ROLES),
            "native installer omitted a complete host native_jobs profile")
    directories = set()
    for key, role in JOB_ROLES.items():
        pin = entries[key]
        require(type(pin) is dict and set(pin) == {"executable", "sha256"}
                and type(pin["executable"]) is str and is_pin(pin["sha256"]),
                "malformed installed job role: " + role)
        path = Path(pin["executable"])
        require(path.is_absolute() and path.name == role
                and path.resolve(strict=True) == path
                and path.is_relative_to(installation / "controller"),
                "job role is not from this real installation")
        directories.add(path.parent)
    require(len(directories) == 1, "native roles were mixed across controller installations")
    directory = directories.pop()
    require(directory.parent == installation / "controller" and is_pin(directory.name),
            "controller directory is not its installed package identity")
    manifest_path = directory / "hia-controller.json"
    manifest_bytes = ordinary(manifest_path, 16384)
    manifest = controller_manifest(manifest_bytes)
    actual = {}
    for role, expected in manifest["files"].items():
        raw = ordinary(directory / role, ROLE_LIMITS.get(role, 1 << 20))
        require(sha(raw) == expected, "installed controller role differs: " + role)
        if role == ROLES[0]:
            require(raw == catalog, "installed catalog differs from the Runtime contract")
        else:
            require(len(raw) >= 64 and raw[:7] == b"\x7fELF\x02\x01\x01"
                    and raw[16:20] == b"\x02\x00\x3e\x00",
                    "installed role is not the native executable contract: " + role)
        actual[role] = {"sha256": expected, "bytes": len(raw)}
    for key, role in JOB_ROLES.items():
        require(entries[key]["sha256"] == manifest["files"][role],
                "host role pin differs from the installed controller")
    worker = config["hia_worker"]
    require(all(is_pin(worker.get(key)) for key in WORKER_FIELDS[:4]),
            "native Worker identity is incomplete")
    require(worker.get("python_executable") == str(installation / "hia-agent-worker")
            and worker.get("native_helpers_manifest") == str(installation / "worker.json"),
            "native Worker compatibility paths do not name this installation")
    profile = ordinary(installation / "worker.json", 64 << 20)
    require(sha(profile) == worker["native_helpers_sha256"], "installed Worker profile pin differs")
    entry = ordinary(installation / "hia-agent-worker", 64 << 20)
    require(len(entry) >= 64 and entry[:7] == b"\x7fELF\x02\x01\x01",
            "the bound Worker is not a native ELF")
    require(worker["catalog_sha256"] == sha(catalog), "bound Worker catalog pin differs")
    original, observed = copy.deepcopy(base_config), copy.deepcopy(config)
    observed["hosts"][HOST].pop("native_jobs")
    for document in (original, observed):
        for key in WORKER_FIELDS:
            document["hia_worker"].pop(key, None)
    require(observed == original, "native binding changed unrelated host or runtime policy")
    return config_path, config, manifest_path, {
        "runtime_config_sha256": sha(config_bytes), "controller_manifest_sha256": sha(manifest_bytes),
        "controller_directory": str(directory), "roles": actual,
        "worker_entry_sha256": sha(entry), "worker_profile_sha256": sha(profile)}


def validate_witness(request, terminal_raw, witness, job_id):
    terminal = strict_json(terminal_raw)
    require(type(request) is dict and type(terminal) is dict and type(witness) is dict,
            "job witness records must be objects")
    nonce = request.get("launch_nonce")
    require(type(nonce) is str and re.fullmatch(r"[0-9a-f]{32}", nonce) is not None,
            "original request nonce is incomplete")
    for value in (request, terminal, witness):
        require(type(value.get("terminal_publication_protocol")) is int
                and value["terminal_publication_protocol"] == 1
                and value.get("job_id") == job_id and value.get("launch_nonce") == nonce,
                "terminal witness does not identify the original job")
    require(witness.get("exit_sha256") == sha(terminal_raw),
            "terminal witness does not bind the actual terminal bytes")
    require(terminal.get("output_complete") is True and terminal.get("output_durable") is True,
            "job output was not completely and durably published")
    require(type(terminal.get("exit_code")) is int,
            "witnessed terminal exit code is not an exact integer")
    return terminal


def validate_observation(observed, job_id):
    require(type(observed) is dict and observed.get("job_id") == job_id
            and observed.get("terminal_publication_confirmed") is True
            and observed.get("automatic_retry") is False
            and type(observed.get("exit_code")) is int,
            "terminal observation lost its typed outcome, identity or no-replay condition")
    return observed


def decode_stream(stream, offset):
    require(type(stream) is dict and type(stream.get("offset")) is int
            and stream["offset"] == offset and type(stream.get("bytes_hex")) is str
            and type(stream.get("eof")) is bool, "invalid public stream cursor")
    raw = bytes.fromhex(stream["bytes_hex"])
    require(type(stream.get("next_offset")) is int
            and stream["next_offset"] == offset + len(raw),
            "public stream cursor omitted or duplicated bytes")
    return raw, stream["next_offset"]


def validate_output_counts(terminal, streams):
    counts, eofs = terminal.get("log_bytes"), terminal.get("log_eof")
    require(type(counts) is dict and type(eofs) is dict,
            "terminal stream counts or EOFs are missing")
    for name, raw in streams.items():
        count = counts.get(name)
        require(type(count) is dict and set(count) == {"seen", "stored"}
                and all(type(count[field]) is int and count[field] == len(raw)
                        for field in ("seen", "stored")) and eofs.get(name) is True,
                "terminal byte counts differ from public output")


def trace_native_install(path, installer):
    raw = path.read_bytes()
    pending, calls = {}, []
    for line in raw.decode(errors="strict").splitlines():
        prefix = re.fullmatch(r"(?:\[pid\s+(\d+)\]|(\d+))\s+(.*)", line)
        require(prefix is not None, "native execution trace omitted a process identity")
        pid, payload = prefix[1] or prefix[2], prefix[3]
        resumed = re.fullmatch(r"<\.\.\. (execve|execveat) resumed>(.*)", payload)
        if resumed:
            require(pid in pending and pending[pid][0] == resumed[1],
                    "native execution trace has an unmatched syscall continuation")
            _, original = pending.pop(pid)
            payload = original + resumed[2]
        call = re.match(r"^(execve|execveat)\(", payload)
        if call is None:
            require(payload.startswith(("--- ", "+++ ")),
                    "unexpected line in the native execution trace")
            continue
        if payload.endswith("<unfinished ...>"):
            require(pid not in pending, "native execution trace duplicated an unfinished syscall")
            pending[pid] = (call[1], payload[:-len("<unfinished ...>")])
            continue
        require(pid not in pending, "native execution trace lost an unfinished syscall")
        result = re.search(r"\)\s+= (-?\d+)(?:\s+[^\n]*)?$", payload)
        require(result is not None and int(result[1]) <= 0,
                "native execution trace has an unconfirmed syscall result")
        calls.append((call[1], payload, int(result[1])))
    require(not pending, "native execution trace retains an unfinished syscall")
    direct = [call for call in calls if call[0] == "execve"]
    require(len(direct) == 1
            and direct[0][1].startswith("execve(" + json.dumps(str(installer)) + ", ")
            and direct[0][2] == 0,
            "native installer trace contains an unexpected pathname execution")
    native = [call for call in calls if call[0] == "execveat"]
    require(bool(native) and all(re.match(r'^execveat\(\d+, "", ', call[1])
            and re.search(r", AT_EMPTY_PATH\s*\)\s+= ", call[1]) for call in native),
            "native installation did not retain its descriptor execution trace")
    successful = sum(call[2] == 0 for call in native)
    require(successful > 0, "native installation has no successful descriptor execution")
    return {"pathname_execs": len(direct), "descriptor_attempts": len(native),
            "descriptor_execs": successful, "descriptor_failures": len(native) - successful,
            "sha256": sha(raw), "bytes": len(raw)}


def write_json(path, value):
    with path.open("w", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=True, sort_keys=True, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def run_owned(argv, output, name, *, cwd, env, timeout):
    """Keep actual stdout/stderr and never replay a timed-out invocation."""
    started = time.monotonic_ns()
    with (output / (name + ".stdout")).open("xb") as stdout, \
            (output / (name + ".stderr")).open("xb") as stderr:
        child = subprocess.Popen(list(map(str, argv)), cwd=cwd, env=env,
                                 stdout=stdout, stderr=stderr, start_new_session=True)
        timed_out = False
        try:
            code = child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(child.pid, signal.SIGTERM)
            try:
                code = child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                code = child.wait(timeout=10)
    result = {"argv": list(map(str, argv)), "pid": child.pid, "exit_code": code,
              "timed_out": timed_out, "elapsed_ns": time.monotonic_ns() - started,
              "stdout_sha256": sha((output / (name + ".stdout")).read_bytes()),
              "stderr_sha256": sha((output / (name + ".stderr")).read_bytes())}
    write_json(output / (name + ".command.json"), result)
    require(not timed_out and code == 0, name + " failed; original output is retained")
    return result


def load_common(root, expected):
    require(re.fullmatch(r"[0-9a-f]{40}", expected) is not None, "full Runtime commit required")
    actual = subprocess.check_output(["git", "--no-replace-objects", "-C", str(root),
                                      "rev-parse", "HEAD"], text=True).strip()
    require(actual == expected, "qualification source is not the selected Runtime")
    for relative in ("tests/hia_installed_public_jobs_integration.py",
                     "tests/hia_native_helper_mcp_integration.py",
                     "tests/fixtures/hia_public_native_jobs.c"):
        expected_bytes = subprocess.check_output(["git", "--no-replace-objects", "-C", str(root),
                                                   "show", expected + ":" + relative])
        require(ordinary(root / relative, 2 << 20) == expected_bytes,
                "qualification source differs from the selected commit: " + relative)
    require(Path(__file__).resolve() == root / "tests/hia_installed_public_jobs_integration.py",
            "qualification driver is outside the selected source")
    spec = importlib.util.spec_from_file_location(
        "hia_public_common", root / "tests/hia_native_helper_mcp_integration.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("runtime", "runtime-source", "hepta", "native-installer", "compiler",
                 "cold-report", "package", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("runtime", "native-installer", "compiler", "cold-report", "package"):
        parser.add_argument("--" + name + "-sha256", required=True)
    parser.add_argument("--expected-runtime-source", required=True)
    parser.add_argument("--expected-hepta-source", required=True)
    connection = parser.add_mutually_exclusive_group(required=True)
    connection.add_argument("--ssh-target", help="Existing authenticated same-host SSH endpoint")
    connection.add_argument("--allow-disposable-sshd", action="store_true")
    parser.add_argument("--install-timeout-seconds", type=int, default=3600)
    parser.add_argument("--cc", default="/usr/bin/cc")
    parser.add_argument("--strace", default="/usr/bin/strace")
    args = parser.parse_args(argv)
    require(sys.flags.isolated == 1 and sys.dont_write_bytecode is True,
            "qualification requires Python -I -B")
    require(sys.platform == "linux" and os.uname().machine == "x86_64" and os.geteuid() != 0,
            "qualification requires a non-root Linux x86_64 operator")
    require(1 <= args.install_timeout_seconds <= 604800, "invalid installation deadline")
    if args.allow_disposable_sshd:
        require(os.environ.get("GITHUB_ACTIONS") == "true"
                and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted",
                "disposable SSH remains restricted to the explicitly selected GitHub-hosted runner")
    else:
        require(args.ssh_target and not args.ssh_target.startswith("-")
                and not any(ord(ch) < 32 for ch in args.ssh_target), "invalid existing SSH target")
    os.umask(0o077)
    output = args.output.resolve()
    output.mkdir(mode=0o700)
    private = output / "private"
    private.mkdir(mode=0o700)
    report = {"schema": "hepta.runtime.installed-public-native-jobs.v1", "status": "HOLD",
              "checks": {}, "jobs": [], "transport_sessions": [], "negative_controls": {},
              "scope": {"ordinary_native_installer": True, "public_generic_jobs": True,
                        "native_worker_identity_query": True, "all_eleven_native_hia_tools": False,
                        "rust_controller_retired": False, "old_stack_removal_qualified": False}}
    transport = ssh = common = None
    journal = (output / "public-calls.jsonl").open("xb")
    config_path = config = manifest_path = binding = None
    started = time.monotonic_ns()
    originals = []
    intents = []
    cleanup_errors = []

    def save():
        report["elapsed_ns"] = time.monotonic_ns() - started
        write_json(output / "report.json", report)

    def close_transport():
        nonlocal transport
        if transport is not None:
            report["transport_sessions"].append({"initialize": transport.initialized,
                "protocol": transport.protocol_records, "stderr": transport.stderr()})
            transport.close()
            transport = None
            save()

    def command(selected_config, selected_manifest, selected_pin):
        return [str(args.runtime), "mcp", "--path", str(output),
                "--runtime-config", str(selected_config),
                "--hia-controller-manifest", str(selected_manifest),
                "--hia-controller-sha256", selected_pin]

    def open_transport(selected_config=None):
        from tools.hia_agent_native_transport import MCPStdio
        return MCPStdio(command(selected_config or config_path, manifest_path,
                                binding["controller_manifest_sha256"]),
                        cwd=args.runtime_source, env=env, timeout=60)

    def call(name, arguments):
        return common.generic_call(transport, name, arguments, journal)

    def inventory():
        result = call("process_list", {"host": HOST})
        require(result.get("inventory_complete") is True, "public inventory is incomplete")
        return sorted(job["id"] for job in result["jobs"])

    def observe_terminal(job_id):
        deadline = time.monotonic() + 90
        observed = call("process_status", {"host": HOST, "job_id": job_id})
        while observed.get("terminal_publication_confirmed") is not True:
            require(time.monotonic() < deadline, "original public job lacks a terminal witness")
            observed = call("process_wait", {"host": HOST, "job_id": job_id, "timeout_seconds": 10})
        return validate_observation(observed, job_id)

    def capture_output(job_id):
        offsets = {"stdout": 0, "stderr": 0}
        captures = {"stdout": bytearray(), "stderr": bytearray()}
        pages = []
        for page_index in range(64):
            response = call("process_read", {"host": HOST, "job_id": job_id,
                "stdout_offset": offsets["stdout"], "stderr_offset": offsets["stderr"],
                "limit": 7 if page_index == 0 else 16384})
            require(response.get("job_id") == job_id, "public read changed job identity")
            for name in offsets:
                stream = response.get(name)
                raw, next_offset = decode_stream(stream, offsets[name])
                captures[name].extend(raw)
                offsets[name] = next_offset
            pages.append(response)
            if all(response[name].get("eof") is True for name in offsets):
                break
        else:
            raise RuntimeError("public output did not reach its original EOF")
        return {name: bytes(data) for name, data in captures.items()}, pages

    def witness(record):
        directory = Path(record["remote_job_dir"])
        require(directory == Path(config["hosts"][HOST]["remote_state_dir"]) / "jobs" / record["id"],
                "job directory changed its configured host binding")
        request_raw = ordinary(directory / "request.json", 16 << 20, mode=0o600)
        exit_raw = ordinary(directory / "exit.json", 1 << 20, mode=0o600)
        witness_raw = ordinary(directory / "exit.witness.json", 4096, mode=0o600)
        request = strict_json(request_raw)
        require(request.get("request_digest") == record.get("request_digest"),
                "remote request differs from the durable public request")
        terminal = validate_witness(request, exit_raw, strict_json(witness_raw), record["id"])
        evidence = output / ("job-" + record["id"])
        evidence.mkdir(mode=0o700)
        for name, raw in (("request.json", request_raw), ("exit.json", exit_raw),
                          ("exit.witness.json", witness_raw)):
            (evidence / name).write_bytes(raw)
        return terminal, {"directory": str(directory), "request_sha256": sha(request_raw),
            "exit_sha256": sha(exit_raw), "witness_sha256": sha(witness_raw)}

    def start(name, tool, arguments, expected_code=None, expected_streams=None):
        key = "public-native-" + args.expected_runtime_source[:12] + "-" + name
        require(not key.startswith("hia-agent-"), "campaign must exercise ordinary public keys")
        arguments = {"host": HOST, "cwd": str(inputs), "timeout_seconds": 120,
                     "idempotency_key": key, **arguments}
        common.record(journal, {"phase": "single_start", "name": name, "tool": tool,
                                "arguments": arguments})
        intents.append({"name": name, "tool": tool, "arguments": arguments})
        report["start_intents"] = intents
        save()
        result = call(tool, arguments)
        record = result.get("job")
        require(type(record) is dict and type(record.get("id")) is str
                and record.get("idempotency_key") == key and result.get("reused") is False,
                "new public job did not retain one new durable identity")
        originals.append(record)
        row = {"name": name, "tool": tool, "arguments": arguments, "start": result}
        report["jobs"].append(row)
        save()
        if name == "cancel":
            deadline = time.monotonic() + 30
            while True:
                ready = call("process_read", {"host": HOST, "job_id": record["id"], "limit": 64})
                if bytes.fromhex(ready.get("stdout", {}).get("bytes_hex", "")) == b"ready\n":
                    break
                require(time.monotonic() < deadline, "cancellable original child did not become ready")
                time.sleep(0.05)
            row["cancel"] = call("process_cancel", {"host": HOST, "job_id": record["id"],
                                                     "grace_seconds": 1})
        observation = observe_terminal(record["id"])
        streams, pages = capture_output(record["id"])
        terminal, retained = witness(record)
        require(observation.get("exit_code") == terminal.get("exit_code"),
                "public status disagrees with the actual witnessed terminal bytes")
        if expected_code is not None:
            require(terminal.get("exit_code") == expected_code
                    and observation.get("state") == ("succeeded" if expected_code == 0 else "failed"),
                    "public native job returned the wrong terminal result")
        if expected_streams is not None:
            require(streams == expected_streams, "public read did not preserve exact workload bytes")
        validate_output_counts(terminal, streams)
        for stream, raw in streams.items():
            (output / ("job-" + record["id"]) / (stream + ".log")).write_bytes(raw)
        if name == "cancel":
            require(terminal.get("cancelled") is True and observation.get("state") == "cancelled",
                    "public cancellation did not confirm the original child outcome")
        row.update(status=observation, terminal=terminal, read_pages=pages, retained=retained)
        save()
        return row, streams

    try:
        save()
        for name in ("runtime", "runtime_source", "hepta", "native_installer", "compiler", "cold_report", "package"):
            setattr(args, name, getattr(args, name).resolve(strict=True))
        require(not output.is_relative_to(args.hepta) and not output.is_relative_to(args.runtime_source),
                "qualification evidence must not modify the source checkout")
        common = load_common(args.runtime_source, args.expected_runtime_source)
        report["sources"] = {"runtime": common.source_identity(args.runtime_source, args.expected_runtime_source),
                             "hepta": common.source_identity(args.hepta, args.expected_hepta_source)}
        report["source_imports"] = common.prepare_source_imports(
            [args.hepta, args.runtime_source], private / "python-import-cache")
        sys.path.insert(0, str(args.hepta))
        env = {key: value for key, value in common.clean_environment().items()
               if not key.startswith(("HIA_LOCAL_MCP_", "HEPTA_RUNTIME_WORKER_"))}
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        report["inputs"] = {name: file_pin(getattr(args, name), getattr(args, name + "_sha256"))
                            for name in ("runtime", "native_installer", "compiler", "cold_report", "package")}
        for name in ("runtime", "native_installer"):
            require(ordinary(getattr(args, name), 512 << 20)[:7] == b"\x7fELF\x02\x01\x01",
                    "qualification selected a hosted executable: " + name)
        if args.allow_disposable_sshd:
            ssh = common.DisposableSSH(private, output, env)
            ssh.start()
            target, env = ssh.target, ssh.env
        else:
            target = args.ssh_target
        # Prove the SSH endpoint shares this exact owned filesystem, not merely
        # a matching username. All later direct witness reads depend on this.
        sentinel = private / "same-host-sentinel"
        sentinel.write_bytes(os.urandom(32))
        info = sentinel.stat()
        ssh_command = ["ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
                       "-o", "StrictHostKeyChecking=yes", "-o", "ForwardAgent=no", target]
        probe = subprocess.run(ssh_command + ["/usr/bin/stat -c '%d:%i:%u:%a' -- " + shlex.quote(str(sentinel))],
                               env=env, capture_output=True, timeout=15)
        (output / "same-host.stdout").write_bytes(probe.stdout)
        (output / "same-host.stderr").write_bytes(probe.stderr)
        require(probe.returncode == 0 and probe.stdout.strip() ==
                f"{info.st_dev}:{info.st_ino}:{os.geteuid()}:600".encode(),
                "existing SSH target is not this same owned filesystem and account")
        kernel_probe = subprocess.run(ssh_command + ["/usr/bin/cat -- /proc/sys/kernel/random/boot_id "
                                      + shlex.quote(str(sentinel))],
                                      env=env, capture_output=True, timeout=15)
        require(kernel_probe.returncode == 0 and kernel_probe.stdout ==
                Path("/proc/sys/kernel/random/boot_id").read_bytes() + sentinel.read_bytes(),
                "SSH endpoint does not share the actual kernel boot and private sentinel bytes")
        report["checks"]["same_host_ssh_identity"] = True
        inputs = private / "inputs"
        inputs.mkdir(mode=0o700)
        installation = private / "native-installation"
        base_config = {"state_dir": str(private / "controller-state"),
            "controller_workspace_roots": [str(output)],
            "hosts": {HOST: {"execution_mode": "operator", "ssh_target": target,
                "platform": "linux", "remote_state_dir": str(private / "owner-state"),
                "allow_execute": True, "allow_write": True, "allow_job_network": True,
                "allow_detached_fallback": False, "allowed_cwd_prefixes": [str(private)],
                "allowed_read_path_prefixes": [str(private), str(args.hepta), "/usr/bin", "/bin"],
                "allowed_write_path_prefixes": [str(private)]}},
            "hia_worker": {"host": HOST, "python_executable": "/unbound/native-worker",
                "working_directory": str(installation), "state_root": str(private / "worker-state"),
                "artifact_roots": [str(inputs)], "worker_sha256": "0" * 64,
                "backend_sha256": "0" * 64, "catalog_sha256": "0" * 64,
                "native_helpers_sha256": "0" * 64, "native_helpers_manifest": "/unbound/worker.json",
                "timeout_seconds": 120, "memory_max_bytes": 1073741824}}
        base_path = private / "input-runtime-config.json"
        write_json(base_path, base_config)
        native_env = {"PATH": "", "LANG": "C", "LC_ALL": "C"}
        install_command = [args.strace, "-f", "-qq", "-s", "4096", "-e", "trace=execve,execveat",
            "-o", str(output / "native-install.exec.trace"), str(args.native_installer),
            "--source", str(args.hepta), "--output", str(installation),
            "--compiler", str(args.compiler), "--cold-report", str(args.cold_report),
            "--package", str(args.package), "--package-sha256", args.package_sha256,
            "--runtime-config", str(base_path), "--artifact-root", str(inputs),
            "--timeout-seconds", str(args.install_timeout_seconds)]
        report["installation_command"] = run_owned(install_command, output, "native-install",
            cwd=args.hepta, env=native_env, timeout=args.install_timeout_seconds + 30)
        report["installation_receipt"] = install_receipt(
            (output / "native-install.stdout").read_bytes(), args.package_sha256)
        require((output / "native-install.stderr").read_bytes() == b"", "native installation emitted stderr")
        report["installation_trace"] = trace_native_install(output / "native-install.exec.trace", args.native_installer)
        catalog = ordinary(args.runtime_source / "src/mcp/hia_tool_catalog.json", 1 << 20)
        config_path, config, manifest_path, binding = installed_binding(installation, base_config, catalog)
        report["installation_binding"] = binding
        report["checks"]["actual_native_installation_and_nineteen_role_binding"] = True
        save()
        fixture = inputs / "public-native-fixture"
        report["fixture_build"] = run_owned([args.cc, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
            str(args.runtime_source / "tests/fixtures/hia_public_native_jobs.c"), "-o", str(fixture)],
            output, "fixture-build", cwd=inputs, env=env, timeout=30)
        fixture.chmod(0o500)
        alias = inputs / "public-native-alias"
        alias.symlink_to(fixture.name)
        entry_info = fixture.stat()
        report["fixture_sha256"] = sha(ordinary(fixture, 1 << 20))
        def workload(path, mode, extra=()):
            return {"executable": str(path), "args": [mode, str(entry_info.st_dev), str(entry_info.st_ino), *extra],
                    "env": {"PATH": "", "HIA_PUBLIC_EXPECTED_ARGV0": str(path)}}
        transport = open_transport()
        listing = transport.list_tools()
        require({"process_start", "process_status", "process_read", "process_wait", "process_cancel", "shell_start"}
                <= {tool["name"] for tool in listing}, "public lifecycle tools were not registered")
        require(inventory() == [], "qualification controller already owns unrelated jobs")
        expected = {"stdout": bytes((i * 13 + 7) & 255 for i in range(131109)),
                    "stderr": bytes((i * 3 + 11) & 255 for i in range(8193))}
        regular, _ = start("regular", "process_start", {**workload(fixture, "streams"), "stdin": STDIN}, 17, expected)
        start("symlink", "process_start", {**workload(alias, "streams"), "stdin": STDIN}, 17, expected)
        start("default-shell", "shell_start", {"command": "printf 'native-shell-out\\n'; printf 'native-shell-err\\n' >&2; exit 7",
              "env": {"PATH": ""}}, 7, {"stdout": b"native-shell-out\n", "stderr": b"native-shell-err\n"})
        worker = config["hia_worker"]
        _, worker_streams = start("worker-identity", "process_start", {
            "executable": worker["python_executable"], "args": ["-B", "-E", "-s", "-m", "hepta.hia_agent_worker",
                "--installation-manifest", "--native-helpers-manifest", worker["native_helpers_manifest"],
                "--expected-native-helpers-sha256", worker["native_helpers_sha256"]],
            "env": {"PATH": ""}, "cwd": worker["working_directory"]}, 0)
        queried = strict_json(worker_streams["stdout"])
        require(worker_streams["stderr"] == b"" and type(queried) is dict
                and all(queried.get(field) == worker[field] for field in WORKER_FIELDS[:4]),
                "public installed-native Worker identity differs from its real configuration")
        report["worker_identity_query"] = queried
        start("cancel", "process_start", workload(fixture, "cancel"), expected_streams={"stdout": b"ready\n", "stderr": b""})
        report["checks"]["ordinary_process_symlink_shell_worker_and_cancel"] = True
        ids_before = inventory()
        close_transport()
        transport = open_transport()
        reused = call(regular["tool"], regular["arguments"])
        require(reused.get("reused") is True and reused.get("retried_launch") is False
                and reused.get("job", {}).get("id") == regular["start"]["job"]["id"]
                and inventory() == ids_before, "completed public request relaunched after reconnect")
        require(observe_terminal(regular["start"]["job"]["id"])["exit_code"] == 17,
                "reconnected public status lost the original terminal outcome")
        retained, pages = capture_output(regular["start"]["job"]["id"])
        require(retained == expected, "reconnected public reads changed retained bytes")
        report["reconnect"] = {"reused": reused, "read_pages": pages, "job_ids": ids_before}
        report["checks"]["reconnect_retains_original_identity_bytes_and_witness"] = True
        # A deliberately corrupted witness belongs only to this completed test
        # job. Preserve the original inode and restore it before any later call.
        original_record = regular["start"]["job"]
        witness_path = Path(original_record["remote_job_dir"]) / "exit.witness.json"
        original_bytes = ordinary(witness_path, 4096, mode=0o600)
        held_path = witness_path.with_name("qualification-held-exit-witness.json")
        require(not held_path.exists(), "witness negative-control holding path exists")
        forged = strict_json(original_bytes)
        forged["exit_sha256"] = "0" * 64
        witness_path.rename(held_path)
        forged_bytes = (json.dumps(forged, sort_keys=True) + "\n").encode()
        try:
            with witness_path.open("xb") as stream:
                stream.write(forged_bytes)
            rejected = call("process_status", {"host": HOST, "job_id": original_record["id"]})
            require(rejected.get("terminal_publication_confirmed") is False
                    and rejected.get("automatic_retry") is False,
                    "public STATUS accepted a witness for different terminal bytes")
            report["negative_controls"]["changed_witness_digest"] = rejected
        finally:
            require(ordinary(witness_path, 4096, mode=0o600) == forged_bytes,
                    "witness changed outside its owned negative control; preserve both paths")
            witness_path.unlink()
            held_path.rename(witness_path)
        require(ordinary(witness_path, 4096, mode=0o600) == original_bytes
                and observe_terminal(original_record["id"])["exit_code"] == 17
                and inventory() == ids_before, "original witness was not restored without replay")
        close_transport()
        # Even the unused cancel role must be admitted before a new process
        # can reach SSH. This uses a separate private controller and state root.
        wrong = copy.deepcopy(config)
        wrong["state_dir"] = str(private / "wrong-pin-controller")
        wrong["hosts"][HOST]["remote_state_dir"] = str(private / "wrong-pin-owner")
        wrong["hosts"][HOST]["native_jobs"]["cancel"]["sha256"] = "0" * 64
        wrong_path = private / "wrong-role-pin.json"
        write_json(wrong_path, wrong)
        transport = open_transport(wrong_path)
        marker = inputs / "must-not-execute"
        bad_args = {"host": HOST, "cwd": str(inputs), "timeout_seconds": 10,
                    "idempotency_key": "public-native-unused-role-pin-negative",
                    **workload(fixture, "marker", [str(marker)])}
        common.record(journal, {"phase": "negative_intent", "tool": "process_start", "arguments": bad_args})
        refusal = transport.rpc("tools/call", {"name": "process_start", "arguments": bad_args})
        common.record(journal, {"phase": "negative_response", "result": refusal})
        require(refusal.get("isError") is True and "native job artifact hia-job-cancel" in json.dumps(refusal)
                and not marker.exists() and not Path(wrong["hosts"][HOST]["remote_state_dir"]).exists(),
                "wrong unused role pin reached remote execution or selected a fallback")
        report["negative_controls"]["unused_role_pin"] = refusal
        close_transport()
        # Refusal checks use only an invalid inventory or pin. They never act
        # as substitute successful installations, and never execute workloads.
        bad_directory = private / "missing-role-controller"
        bad_directory.mkdir(mode=0o700)
        missing = controller_manifest(ordinary(manifest_path, 16384))
        missing["files"].pop("hia-job-observation")
        bad_manifest = bad_directory / "hia-controller.json"
        write_json(bad_manifest, missing)
        for name, selected, pin, reason in (
            ("missing-controller-role", bad_manifest, sha(bad_manifest.read_bytes()), "role inventory"),
            ("wrong-controller-pin", manifest_path, "0" * 64, "manifest identity")):
            invocation = command(config_path, selected, pin)
            child = subprocess.run(invocation, input=b"", capture_output=True, cwd=args.runtime_source,
                                   env=env, timeout=30)
            (output / (name + ".stdout")).write_bytes(child.stdout)
            (output / (name + ".stderr")).write_bytes(child.stderr)
            require(child.returncode != 0 and not child.stdout and reason in child.stderr.decode(errors="replace"),
                    "invalid controller admission did not refuse before serving MCP")
            report["negative_controls"][name] = {"exit_code": child.returncode,
                "stderr": child.stderr.decode(errors="replace"), "manifest_sha256": pin}
        report["checks"]["live_role_manifest_and_terminal_witness_refusals"] = True
        require(installed_binding(installation, base_config, catalog)[3] == binding,
                "native installation changed during public qualification")
        for name, expected_input in report["inputs"].items():
            require(file_pin(getattr(args, name), getattr(args, name + "_sha256")) == expected_input,
                    "input identity changed during public qualification")
        require(common.source_identity(args.runtime_source, args.expected_runtime_source) == report["sources"]["runtime"]
                and common.source_identity(args.hepta, args.expected_hepta_source) == report["sources"]["hepta"],
                "selected source changed during public qualification")
        report["checks"]["original_inputs_and_installation_retained"] = True
        report["status"] = "PASS"
    except BaseException as exc:
        report["status"] = "HOLD"
        report["error"] = {"type": type(exc).__name__, "message": str(exc), "traceback": traceback.format_exc()}
    finally:
        # Reconcile only identities under this fresh controller that match an
        # original intent. A lost START response never causes a new START.
        if report["status"] != "PASS" and common is not None and config_path is not None:
            try:
                close_transport()
                transport = open_transport()
                known = {row["id"]: row for row in originals}
                requested = {row["arguments"]["idempotency_key"] for row in intents}
                listed = call("process_list", {"host": HOST})
                require(listed.get("inventory_complete") is True, "cleanup inventory incomplete")
                for row in listed["jobs"]:
                    require(type(row.get("id")) is str
                            and re.fullmatch(r"[A-Za-z0-9_-]+", row["id"]) is not None,
                            "invalid identity in cleanup inventory")
                    retained = strict_json(ordinary(
                        Path(config["state_dir"]) / "jobs" / (row["id"] + ".json"),
                        4 << 20, mode=0o600))
                    require(retained.get("id") == row["id"]
                            and retained.get("host") == HOST
                            and retained.get("idempotency_key") in requested,
                            "unexpected identity in the fresh qualification controller")
                    known[row["id"]] = retained
                report["reconciled_original_job_ids"] = sorted(known)
                report["start_intents_without_acknowledgement"] = sorted(requested -
                    {row["idempotency_key"] for row in originals})
                for record in known.values():
                    observation = call("process_status", {"host": HOST, "job_id": record["id"]})
                    if observation.get("terminal_publication_confirmed") is not True:
                        call("process_cancel", {"host": HOST, "job_id": record["id"], "grace_seconds": 1})
                        final = call("process_wait", {"host": HOST, "job_id": record["id"], "timeout_seconds": 30})
                        if final.get("terminal_publication_confirmed") is not True:
                            cleanup_errors.append("original job remains unconfirmed: " + record["id"])
            except Exception as exc:
                cleanup_errors.append("original job reconciliation: " + str(exc))
        try:
            close_transport()
        except Exception as exc:
            cleanup_errors.append("MCP close: " + str(exc))
        if ssh is not None:
            try:
                cleanup_errors.extend(ssh.close())
            except Exception as exc:
                cleanup_errors.append("disposable SSH close: " + str(exc))
        report["cleanup_errors"] = cleanup_errors
        if cleanup_errors:
            report["status"] = "HOLD"
        save()
        journal.close()
    print(json.dumps({"status": report["status"], "report": str(output / "report.json"),
                      "checks": report["checks"]}, sort_keys=True))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Qualify a fixed Runtime/Hepta candidate through real stdio MCP and loopback SSH.

This is an explicitly disposable GitHub-hosted-runner integration. The worker
journal and JSON adapter remain hosted Python; the scalar identity helper and
emitted workload images execute actual HIA machine code. It does not establish
production deployment, unfamiliar-model learning, or net optimization benefit.
"""
from __future__ import annotations

import argparse
import copy
from hashlib import sha256
import json
import os
from pathlib import Path
import pwd
import re
import select
import socket
import stat
import subprocess
import sys
import time
import traceback


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    return sha256(Path(path).read_bytes()).hexdigest()


def write_json(path, value):
    with Path(path).open("w", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, indent=2, ensure_ascii=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def record(stream, event):
    stream.write(encoded(event) + b"\n")
    stream.flush()
    os.fsync(stream.fileno())


def clean_environment():
    return {key: value for key, value in os.environ.items()
            if not key.startswith(("HEPTA_HIA_", "HIA_TRANSPORT_"))
            and key not in {"PYTHONPATH", "PYTHONHOME"}}


def source_identity(root, expected):
    require(re.fullmatch(r"[0-9a-f]{40}", expected) is not None,
            "source identity must be a complete commit")
    actual = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"],
                                     text=True).strip()
    require(actual == expected, "checked-out source differs from the frozen candidate")
    dirty = subprocess.check_output(
        ["git", "-C", str(root), "status", "--porcelain", "--untracked-files=no"],
        text=True)
    require(not dirty, "tracked source changed during qualification")
    tree = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD^{tree}"], text=True).strip()
    return {"commit": actual, "tree": tree}


def consumer_main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("--hepta", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--bundle-sha256", required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--artifact-root", type=Path, required=True)
    args = parser.parse_args(argv)
    sys.path.insert(0, str(args.hepta))
    from hepta.hia_native_helpers import native_helpers_scope
    from hepta.hia_agent_service import HIAAgentService
    with native_helpers_scope(str(args.bundle), args.bundle_sha256):
        service = HIAAgentService(args.state_root, artifact_roots=[args.artifact_root])
        try:
            for raw in sys.stdin.buffer:
                request = json.loads(raw)
                try:
                    action = request["action"]
                    if action == "probe":
                        from hepta.hia_agent_identity_native import installed_agent_identity
                        image = installed_agent_identity(os.environ["HEPTA_HIA_AGENT_IDENTITY_MANIFEST"])
                        result = {"u64_max": image.uint64("18446744073709551615"),
                                  "u64_overflow": image.uint64("18446744073709551616"),
                                  "lowercase_digest": image.digest("a" * 64),
                                  "uppercase_digest": image.digest("A" * 64),
                                  "installation": service.identities}
                    elif action == "acquire":
                        result = service.acquire_slot(request["slot"])
                    elif action == "invoke":
                        result = service.invoke_lease(request["lease"], "transform", [9])
                    elif action == "release":
                        result = service.release_slot(request["lease"])
                    elif action == "inspect":
                        result = service.inspect_slot(request["slot"])
                    elif action == "exit":
                        break
                    else:
                        raise ValueError("unknown consumer action")
                    response = {"ok": True, "result": result}
                except Exception as exc:
                    response = {"ok": False, "error": {"type": type(exc).__name__,
                                "code": getattr(exc, "code", None), "message": str(exc)}}
                sys.stdout.buffer.write(encoded(response) + b"\n")
                sys.stdout.buffer.flush()
        finally:
            service.close()


class Consumer:
    def __init__(self, command, *, cwd, env, output, journal):
        self.log = (output / "consumer.stderr.log").open("xb")
        self.process = subprocess.Popen(command, cwd=cwd, env=env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.log,
            bufsize=0, start_new_session=True)
        self.pending = b""
        self.journal = journal

    def call(self, action, **arguments):
        request = {"action": action, **arguments}
        record(self.journal, {"phase": "consumer_intent", "request": request})
        self.process.stdin.write(encoded(request) + b"\n")
        self.process.stdin.flush()
        deadline = time.monotonic() + 30
        while b"\n" not in self.pending:
            remaining = deadline - time.monotonic()
            require(remaining > 0, "consumer observation timed out; preserve the original lease")
            ready, _, _ = select.select([self.process.stdout], [], [], min(remaining, 1))
            if ready:
                chunk = os.read(self.process.stdout.fileno(), 65536)
                require(bool(chunk), "consumer exited without a complete response")
                self.pending += chunk
                require(len(self.pending) <= 1024 * 1024, "consumer response exceeds bound")
            elif self.process.poll() is not None:
                raise RuntimeError("consumer exited before its response")
        line, self.pending = self.pending.split(b"\n", 1)
        response = json.loads(line)
        record(self.journal, {"phase": "consumer_response",
                             "request": request, "response": response})
        return response

    def result(self, action, **arguments):
        response = self.call(action, **arguments)
        require(response["ok"] is True, "consumer rejected: " + json.dumps(response))
        return response["result"]

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.write(encoded({"action": "exit"}) + b"\n")
            self.process.stdin.flush()
            self.process.stdin.close()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.terminate()
                self.process.wait(timeout=10)
        self.log.close()


class DisposableSSH:
    """Own only this runner's temporary agent, localhost daemon and host-key entry."""

    def __init__(self, private, output, environment):
        self.private = private
        self.output = output
        self.env = dict(environment)
        self.agent = self.daemon = None
        self.streams = []
        self.known = None
        self.known_before = None
        self.known_after = None
        self.known_mode = None
        self.created_ssh_dir = False
        self.linger_enabled_here = False
        self.commands = []

    def run(self, argv, *, timeout=30, check=True):
        result = subprocess.run([str(x) for x in argv], env=self.env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        event = {"argv": [str(x) for x in argv], "returncode": result.returncode,
                 "stdout": result.stdout.decode("utf-8", "replace"),
                 "stderr": result.stderr.decode("utf-8", "replace")}
        self.commands.append(event)
        write_json(self.output / "ssh-setup.json", self.commands)
        if check:
            require(result.returncode == 0, "disposable SSH setup failed: " + json.dumps(event))
        return result

    def start(self):
        user = pwd.getpwuid(os.getuid())
        require(user.pw_uid != 0, "the integration requires a non-root runner identity")
        for name in ("client_key", "host_key"):
            self.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                      "-f", self.private / name])
        authorized = self.private / "authorized_keys"
        authorized.write_bytes((self.private / "client_key.pub").read_bytes())
        authorized.chmod(0o600)
        with socket.socket() as bound:
            bound.bind(("127.0.0.1", 0))
            self.port = bound.getsockname()[1]
        self.target = "ssh://" + user.pw_name + "@127.0.0.1:" + str(self.port)

        ssh_dir = Path(user.pw_dir) / ".ssh"
        require(not ssh_dir.is_symlink(), "refuse a linked SSH configuration directory")
        if not ssh_dir.exists():
            ssh_dir.mkdir(mode=0o700)
            self.created_ssh_dir = True
        self.known = ssh_dir / "known_hosts"
        require(not self.known.is_symlink(), "refuse a linked known_hosts file")
        if self.known.exists():
            require(stat.S_ISREG(self.known.stat().st_mode), "known_hosts must be a regular file")
            self.known_before = self.known.read_bytes()
            self.known_mode = stat.S_IMODE(self.known.stat().st_mode)
        original = self.known_before or b""
        hostkey = (self.private / "host_key.pub").read_text().split()
        entry = ("[127.0.0.1]:" + str(self.port) + " " + " ".join(hostkey[:2]) + "\n").encode()
        self.known_after = original + (b"\n" if original and not original.endswith(b"\n") else b"") + entry
        self.known.write_bytes(self.known_after)
        self.known.chmod(0o600)

        agent_log = (self.output / "ssh-agent.log").open("xb")
        self.streams.append(agent_log)
        self.env["SSH_AUTH_SOCK"] = str(self.private / "agent.sock")
        self.env.pop("SSH_AGENT_PID", None)
        self.agent = subprocess.Popen(
            ["ssh-agent", "-D", "-a", self.env["SSH_AUTH_SOCK"]],
            stdout=agent_log, stderr=subprocess.STDOUT, env=self.env)
        deadline = time.monotonic() + 10
        while not Path(self.env["SSH_AUTH_SOCK"]).exists():
            require(self.agent.poll() is None and time.monotonic() < deadline,
                    "disposable ssh-agent did not start")
            time.sleep(0.05)
        self.run(["ssh-add", self.private / "client_key"])

        linger = self.run(["loginctl", "show-user", user.pw_name, "-p", "Linger", "--value"],
                          check=False)
        if linger.returncode != 0 or linger.stdout.strip() != b"yes":
            self.run(["sudo", "-n", "loginctl", "enable-linger", user.pw_name])
            self.linger_enabled_here = True
        self.run(["sudo", "-n", "systemctl", "start", "user@" + str(user.pw_uid) + ".service"])
        self.run(["sudo", "-n", "mkdir", "-p", "/run/sshd"])

        config = self.private / "sshd_config"
        config.write_text("\n".join([
            "Port " + str(self.port), "ListenAddress 127.0.0.1",
            "HostKey " + str(self.private / "host_key"),
            "AuthorizedKeysFile " + str(authorized),
            "PidFile " + str(self.private / "sshd.pid"),
            "AllowUsers " + user.pw_name, "PermitRootLogin no",
            "PasswordAuthentication no", "KbdInteractiveAuthentication no",
            "PubkeyAuthentication yes", "AuthenticationMethods publickey",
            "UsePAM yes", "StrictModes yes", "AllowTcpForwarding no",
            "AllowAgentForwarding no", "X11Forwarding no", "PermitTunnel no",
            "LogLevel VERBOSE", "PrintMotd no", "PrintLastLog no", "UseDNS no",
        ]) + "\n")
        self.run(["sudo", "-n", "/usr/sbin/sshd", "-t", "-f", config])
        daemon_log = (self.output / "sshd.log").open("xb")
        self.streams.append(daemon_log)
        self.daemon = subprocess.Popen(
            ["sudo", "-n", "/usr/sbin/sshd", "-D", "-e", "-f", str(config)],
            stdout=daemon_log, stderr=subprocess.STDOUT, env=self.env,
            start_new_session=True)
        deadline = time.monotonic() + 10
        while True:
            require(self.daemon.poll() is None and time.monotonic() < deadline,
                    "disposable sshd did not listen")
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.05)
        self.run(["ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
                  "-o", "StrictHostKeyChecking=yes", "-o", "ForwardAgent=no",
                  self.target, "/usr/bin/true"])
        # Exercise the same user-systemd resource controls required by the
        # existing owner, without enabling its detached fallback.
        unit = "hia-integration-probe-" + str(user.pw_uid) + "-" + str(self.port)
        probe = ("env XDG_RUNTIME_DIR=/run/user/" + str(user.pw_uid)
                 + " DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/" + str(user.pw_uid)
                 + "/bus /usr/bin/systemd-run --user --quiet --collect --wait --unit="
                 + unit + " --property=CPUQuota=100% --property=MemoryMax=67108864"
                 + " /usr/bin/true")
        self.run(["ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
                  "-o", "StrictHostKeyChecking=yes", "-o", "ForwardAgent=no",
                  self.target, probe])
        return self

    def close(self):
        errors = []
        for process, privileged in ((self.daemon, True), (self.agent, False)):
            if process is not None and process.poll() is None:
                try:
                    if privileged:
                        self.run(["sudo", "-n", "/bin/kill", "-TERM", str(process.pid)])
                    else:
                        process.terminate()
                    process.wait(timeout=10)
                except Exception as exc:
                    errors.append(type(exc).__name__ + ": " + str(exc))
        if self.daemon is not None and self.daemon.poll() is not None:
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.2):
                    errors.append("the disposable SSH listener still accepts connections")
            except OSError:
                pass
        if self.known_after is not None:
            if self.known.exists() and self.known.read_bytes() == self.known_after:
                if self.known_before is None:
                    self.known.unlink()
                else:
                    self.known.write_bytes(self.known_before)
                    self.known.chmod(self.known_mode)
            else:
                errors.append("known_hosts changed outside this test; preserved instead of overwriting")
        if self.created_ssh_dir:
            try:
                self.known.parent.rmdir()
            except OSError:
                pass
        if self.linger_enabled_here:
            result = self.run(["sudo", "-n", "loginctl", "disable-linger",
                               pwd.getpwuid(os.getuid()).pw_name], check=False)
            if result.returncode:
                errors.append("unable to restore the runner's original linger setting")
        for stream in self.streams:
            stream.close()
        return errors


def generic_call(transport, name, arguments, journal):
    record(journal, {"phase": "owner_intent", "tool": name, "arguments": arguments})
    result = transport.rpc("tools/call", {"name": name, "arguments": arguments})
    record(journal, {"phase": "owner_response", "tool": name, "result": result})
    require(result.get("isError") is not True, "owner tool rejected " + name + ": " + json.dumps(result))
    if isinstance(result.get("structuredContent"), dict):
        return result["structuredContent"]
    for item in result.get("content", []):
        if item.get("type") == "text":
            try:
                value = json.loads(item["text"])
            except ValueError:
                continue
            if isinstance(value, dict):
                return value
    raise RuntimeError("owner tool returned no complete JSON observation")


def job_ids(transport, journal):
    result = generic_call(transport, "process_list", {"host": "loopback"}, journal)
    require(result.get("inventory_complete") is True, "job inventory was incomplete")
    return sorted(job["id"] for job in result["jobs"])


def invocation_matches(result, lease):
    require(result.get("status") == "returned" and result.get("values") == [16]
            and result.get("termination_confirmed") is True
            and result.get("generation") == lease["generation"]
            and result.get("artifact") == lease["artifact"],
            "native consumer did not execute the exact retained generation")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--runtime-source", type=Path, required=True)
    parser.add_argument("--hepta", type=Path, required=True)
    parser.add_argument("--expected-runtime-source", required=True)
    parser.add_argument("--expected-hepta-source", required=True)
    parser.add_argument("--cold-report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--allow-disposable-sshd", action="store_true")
    args = parser.parse_args(argv)
    require(args.allow_disposable_sshd and os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted",
            "this test requires an explicitly authorized disposable GitHub-hosted runner")
    require(sys.platform == "linux" and os.uname().machine == "x86_64",
            "the selected image contract is Linux x86_64 LP64")
    os.umask(0o077)
    output = args.output.resolve()
    require(output.is_relative_to(Path(os.environ["RUNNER_TEMP"]).resolve()),
            "evidence must live in this runner's temporary directory")
    output.mkdir(mode=0o700)
    private = output.with_name(output.name + ".private")
    private.mkdir(mode=0o700)
    report = {"schema": "hepta.runtime.hia-native-helper-integration.v1",
              "status": "STARTED", "checks": {}, "transport_sessions": [],
              "scope": {"transport": "actual_stdio_mcp_to_existing_owner_over_loopback_openssh",
                        "native_helpers": ["HEPTA_HIA_AGENT_IDENTITY_MANIFEST"],
                        "worker_json_and_journal": "hosted_python",
                        "production_deployed": False,
                        "whole_worker_native": False,
                        "fresh_model_learning_test": False,
                        "net_optimization_benefit_proved": False}}
    journal = (output / "calls.jsonl").open("xb")
    ssh = transport = consumer = client = None
    config_path = None
    cleanup_errors = []
    started = time.monotonic_ns()
    env = clean_environment()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    runtime = args.runtime.resolve()
    hepta = args.hepta.resolve()
    runtime_source = args.runtime_source.resolve()
    state_root = private / "worker-state"
    inputs = output / "inputs"
    inputs.mkdir(mode=0o700)

    def save():
        report["elapsed_ns"] = str(time.monotonic_ns() - started)
        if client is not None:
            report["calls"] = client.records
        write_json(output / "report.json", report)

    def close_transport():
        nonlocal transport
        if transport is not None:
            report["transport_sessions"].append({
                "initialize": transport.initialized, "protocol": transport.protocol_records,
                "stderr": transport.stderr()})
            transport.close()
            transport = None
            save()

    def open_transport(config_path):
        from tools.hia_agent_native_transport import MCPStdio
        return MCPStdio([str(runtime), "mcp", "--path", str(output),
                         "--runtime-config", str(config_path)],
                        cwd=runtime_source, env=ssh.env, timeout=180)

    try:
        save()
        report["sources"] = {
            "runtime": source_identity(runtime_source, args.expected_runtime_source),
            "hepta": source_identity(hepta, args.expected_hepta_source)}
        report["runtime_binary_sha256"] = digest(runtime)
        report["client_sha256"] = digest(__file__)
        report["python"] = {"executable": sys.executable, "version": sys.version}
        sys.path.insert(0, str(hepta))
        from tools.build_hia_agent_identity import build
        from tools.hia_agent_native_qualification import ToolClient, Session, scripted_loop, campaign_binding
        cold_bytes = args.cold_report.read_bytes()
        cold = json.loads(cold_bytes)
        require(cold.get("status") == "COLD_SELFHOST_REPLAY_PASS"
                and cold.get("qualification_wall_limit_seconds") == 180
                and cold.get("cleanup_wall_limit_seconds") == 3,
                "unchanged-budget cold qualification is incomplete; native integration remains HOLD")
        nested_path = Path(cold["nested_report"])
        require(nested_path.resolve().is_relative_to(args.cold_report.resolve().with_suffix(".cold")),
                "cold report does not name its own source-only qualification")
        require(digest(nested_path) == cold["nested_report_sha256"],
                "cold nested report drifted")
        nested = json.loads(nested_path.read_bytes())
        compiler = Path(nested["generations"][-1]["produced_image"]).resolve()
        require(compiler.is_relative_to(args.cold_report.resolve().with_suffix(".cold")),
                "B3 must come from the original cold qualification")
        manifest = build(output / "native-helper", compiler, args.cold_report.resolve())
        bundle = output / "native-helpers.json"
        write_json(bundle, {"schema": "hepta.hia.native-helpers.v1",
            "target": "linux-x86_64-lp64", "abi": "hia-byte-six-argument-v1",
            "helpers": [{"selector": "HEPTA_HIA_AGENT_IDENTITY_MANIFEST",
                         "manifest_path": str(manifest), "manifest_sha256": digest(manifest)}]})
        bundle_sha = digest(bundle)
        worker_command = [sys.executable, "-B", "-E", "-s", "-m", "hepta.hia_agent_worker",
            "--installation-manifest", "--native-helpers-manifest", str(bundle),
            "--expected-native-helpers-sha256", bundle_sha]
        installed = subprocess.run(worker_command, cwd=hepta, env=env,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        (output / "installation.stdout.json").write_bytes(installed.stdout)
        (output / "installation.stderr.log").write_bytes(installed.stderr)
        require(installed.returncode == 0, "real worker rejected the installed native helper")
        pins = json.loads(installed.stdout)
        require(pins["native_helpers_sha256"] == bundle_sha, "installation omitted selected helper")
        require(pins["catalog_sha256"] == digest(hepta / "docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json")
                == digest(runtime_source / "src/mcp/hia_tool_catalog.json"),
                "Runtime and Hepta do not share exactly the same catalog bytes")
        report["installation"] = pins
        report["cold_report_sha256"] = sha256(cold_bytes).hexdigest()
        report["native_build"] = json.loads((manifest.parent / "build.json").read_bytes())
        report["checks"]["common_catalog_and_native_installation"] = True
        save()

        ssh = DisposableSSH(private, output, env)
        ssh.start()
        config = {"state_dir": str(private / "controller-state"),
            "controller_workspace_roots": [str(output)],
            "hosts": {"loopback": {
                "execution_mode": "operator", "ssh_target": ssh.target,
                "platform": "linux", "remote_state_dir": str(private / "owner-state"),
                "allow_execute": True, "allow_write": True, "allow_job_network": True,
                "allow_detached_fallback": False,
                "allowed_read_path_prefixes": [str(hepta), str(output), str(private),
                                                str(Path(sys.executable).parent), "/usr/bin"],
                "allowed_write_path_prefixes": [str(private), str(output)]}},
            "hia_worker": {"host": "loopback", "python_executable": sys.executable,
                "working_directory": str(hepta), "state_root": str(state_root),
                "artifact_roots": [str(inputs)], **pins,
                "native_helpers_manifest": str(bundle),
                "timeout_seconds": 120, "memory_max_bytes": 1073741824}}
        config_path = output / "runtime-config.json"
        write_json(config_path, config)
        consumer = Consumer(
            [sys.executable, "-B", str(Path(__file__).resolve()), "--consumer",
             "--hepta", str(hepta), "--bundle", str(bundle), "--bundle-sha256", bundle_sha,
             "--state-root", str(state_root), "--artifact-root", str(inputs)],
            cwd=hepta, env=ssh.env, output=output, journal=journal)
        probe = consumer.result("probe")
        require(probe == {"u64_max": 18446744073709551615, "u64_overflow": None,
                          "lowercase_digest": True, "uppercase_digest": False,
                          "installation": pins}, "native identity byte guards did not execute as specified")
        report["native_identity_probe"] = probe
        report["checks"]["actual_identity_image_accept_and_reject"] = True
        transport = open_transport(config_path)
        listing = transport.list_tools()
        report["tools_list"] = listing
        sys.path.insert(0, str(runtime_source / "deploy"))
        from hia_mcp_catalog import freeze, verify_native
        verify_native(listing)
        frozen_contract = json.loads(
            (runtime_source / "deploy/contracts/hepta-hia-agent-native-v1.json").read_bytes())
        require(frozen_contract == freeze(), "frozen HIA family contract differs from registered tools")
        report["checks"]["actual_tools_list_and_frozen_family_contract_match"] = True
        catalog_path = hepta / "docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json"
        expected_tools = {tool["name"] for tool in json.loads(catalog_path.read_bytes())["tools"]}
        require(expected_tools <= {tool["name"] for tool in listing}, "MCP omitted registered HIA tools")
        lease_evidence = {}

        def qualified_call(tool, arguments):
            if tool != "hia_rollback":
                return transport.call(tool, arguments)
            lease = consumer.result("acquire", slot=arguments["target_slot"])
            require(lease["generation"] == arguments["expected_current"]["generation"],
                    "consumer did not pin the currently adopted generation")
            before = consumer.result("invoke", lease=lease)
            invocation_matches(before, lease)
            response = transport.call(tool, arguments)
            require(response["status"] == "completed", "MCP rollback was not completed")
            retained = consumer.result("invoke", lease=lease)
            invocation_matches(retained, lease)
            following = consumer.result("acquire", slot=arguments["target_slot"])
            require(following["generation"] == arguments["retained_generation"]
                    and following["artifact"] != lease["artifact"],
                    "new lease did not observe the retained baseline after rollback")
            after = consumer.result("invoke", lease=following)
            invocation_matches(after, following)
            released = consumer.result("release", lease=lease)
            following_released = consumer.result("release", lease=following)
            require(released["released"] is True and following_released["released"] is True,
                    "consumer lease release was not durable")
            refused = consumer.call("invoke", lease=lease)
            require(refused.get("ok") is False
                    and refused.get("error", {}).get("code") == "E_HIA_LEASE",
                    "released lease remained callable")
            lease_evidence.update(before=before, retained_after_rollback=retained,
                                  following_generation=after, released=released,
                                  released_lease_refusal=refused)
            report["lease_consumption"] = lease_evidence
            save()
            return response

        client = ToolClient(qualified_call, catalog_path=catalog_path,
                            journal=lambda event: record(journal, event))
        campaign = campaign_binding("native-helper-" + args.expected_runtime_source[:12]
                                    + "-" + args.expected_hepta_source[:12])
        report["campaign"] = campaign
        session = Session(client, prefix=campaign["request_prefix"])
        report["scenario"] = scripted_loop(session, target_slot=campaign["target_slot"])
        require(len(lease_evidence) > 0, "scripted qualification did not exercise a consumer lease")
        report["checks"]["eleven_tool_scripted_loop"] = True
        report["checks"]["native_lease_survives_rollback_and_release_refuses"] = True
        save()

        original = next(row for row in client.records if row["tool"] == "hia_artifact"
                        and row.get("response", {}).get("status") == "completed")
        ids_before = job_ids(transport, journal)
        owner_key = "hia-agent-" + sha256(encoded(
            {"tool": original["tool"], "key": original["arguments"]["request_key"]})).hexdigest()
        records = [json.loads(path.read_bytes())
                   for path in (private / "controller-state" / "jobs").glob("*.json")]
        matching = [row for row in records if row.get("idempotency_key") == owner_key]
        require(len(matching) == 1, "original mutation must have one durable owner record")
        owner = matching[0]
        require(owner["id"] in ids_before, "MCP inventory omitted the original operation")
        report["original_operation"] = owner
        retained_output = generic_call(transport, "process_read",
            {"host": "loopback", "job_id": owner["id"], "limit": 16384}, journal)
        require(retained_output.get("job_id") == owner["id"]
                and retained_output.get("stdout", {}).get("eof") is True
                and retained_output["stdout"].get("offset") == 0,
                "original worker report was not retained completely")
        retained_report = json.loads(bytes.fromhex(retained_output["stdout"]["bytes_hex"]))
        expected_profile_sha = sha256(encoded(config["hia_worker"])).hexdigest()
        bound_request = {"schema": "hia-agent-worker-request-v1", "tool": original["tool"],
                         "arguments": original["arguments"], "profile_sha256": expected_profile_sha,
                         "catalog_sha256": pins["catalog_sha256"]}
        expected_request_sha = sha256(encoded(bound_request)).hexdigest()
        require(retained_report.get("schema") == "hia-agent-worker-report-v1"
                and retained_report.get("complete") is True
                and retained_report.get("request_sha256") == expected_request_sha
                and retained_report.get("profile_sha256") == expected_profile_sha
                and retained_report.get("tool") == original["tool"]
                and retained_report.get("response") == original["response"]
                and all(retained_report.get(key) == value for key, value in pins.items()),
                "retained worker report lost its original request, profile or native-image binding")
        report["retained_original_worker_report"] = retained_report
        report["checks"]["actual_request_profile_and_helper_bound_report_retained"] = True
        close_transport()
        transport = open_transport(config_path)
        replay = transport.call(original["tool"], original["arguments"])
        require(replay == original["response"], "restart replay changed the original domain response")
        require(job_ids(transport, journal) == ids_before, "restart replay launched a second job")
        observation = generic_call(transport, "process_status",
            {"host": "loopback", "job_id": owner["id"]}, journal)
        require(observation.get("job_id") == owner["id"]
                and observation.get("state") == "succeeded"
                and observation.get("exit_code") == 0
                and observation.get("terminal_publication_confirmed") is True,
                "the original completed job lacks a bound terminal owner observation")
        report["old_operation_observation"] = observation
        report["replayed_response"] = replay
        report["checks"]["restart_exact_replay_without_new_job"] = True
        report["checks"]["old_operation_observed_through_native_owner"] = True
        save()

        close_transport()
        wrong = copy.deepcopy(config)
        wrong["hia_worker"]["native_helpers_sha256"] = "0" * 64 if bundle_sha != "0" * 64 else "1" * 64
        wrong_path = output / "wrong-native-pin-config.json"
        write_json(wrong_path, wrong)
        transport = open_transport(wrong_path)
        wrong_arguments = {"section": "manifest"}
        unknown = transport.call("hia_describe", wrong_arguments)
        require(unknown.get("status") == "unknown"
                and unknown.get("error", {}).get("retry_action") == "observe_original"
                and isinstance(unknown.get("operation", {}).get("job_id"), str),
                "wrong helper pin must retain an UNKNOWN original operation")
        unknown_ids = job_ids(transport, journal)
        repeated = transport.call("hia_describe", wrong_arguments)
        require(repeated.get("operation") == unknown["operation"]
                and repeated.get("status") == "unknown"
                and job_ids(transport, journal) == unknown_ids,
                "same failed request launched another job or lost UNKNOWN")
        close_transport()
        transport = open_transport(wrong_path)
        after_restart = transport.call("hia_describe", wrong_arguments)
        require(after_restart.get("operation") == unknown["operation"]
                and after_restart.get("status") == "unknown"
                and job_ids(transport, journal) == unknown_ids,
                "UNKNOWN operation identity changed across runtime restart")
        failed_observation = generic_call(transport, "process_status",
            {"host": "loopback", "job_id": unknown["operation"]["job_id"]}, journal)
        require(failed_observation.get("job_id") == unknown["operation"]["job_id"]
                and failed_observation.get("state") == "failed"
                and failed_observation.get("exit_code") == 2
                and failed_observation.get("terminal_publication_confirmed") is True,
                "wrong-pin failure lacks a confirmed original worker exit")
        failed_output = generic_call(transport, "process_read",
            {"host": "loopback", "job_id": unknown["operation"]["job_id"], "limit": 16384},
            journal)
        report["wrong_pin_original_failure"] = {"response": unknown,
            "repeat": repeated, "after_restart": after_restart,
            "owner_status": failed_observation, "owner_output": failed_output}
        report["checks"]["wrong_pin_unknown_keeps_original_job_across_restart"] = True
        report["sources_after"] = {
            "runtime": source_identity(runtime_source, args.expected_runtime_source),
            "hepta": source_identity(hepta, args.expected_hepta_source)}
        require(report["sources_after"] == report["sources"], "candidate source identity drifted")
        report["checks"]["fixed_candidate_source_preserved"] = True
        report["status"] = "PASS"
    except BaseException as exc:
        report["status"] = "HOLD"
        report["error"] = {"type": type(exc).__name__, "message": str(exc),
                           "traceback": traceback.format_exc()}
    finally:
        # On an interrupted scenario, reconcile only this fresh controller's
        # original job IDs. Cancellation observations never turn HOLD into PASS.
        if report["status"] != "PASS" and transport is not None:
            try:
                cleanup_jobs = job_ids(transport, journal)
                for job_id in cleanup_jobs:
                    status = generic_call(transport, "process_status",
                        {"host": "loopback", "job_id": job_id}, journal)
                    if status.get("terminal_publication_confirmed") is not True:
                        generic_call(transport, "process_cancel",
                            {"host": "loopback", "job_id": job_id}, journal)
                        observed = generic_call(transport, "process_wait",
                            {"host": "loopback", "job_id": job_id, "timeout_seconds": 30}, journal)
                        if observed.get("terminal_publication_confirmed") is not True:
                            cleanup_errors.append("original job termination unconfirmed: " + job_id)
                report["cleanup_original_job_ids"] = cleanup_jobs
            except Exception as exc:
                cleanup_errors.append("original job reconciliation: " + str(exc))
        if consumer is not None:
            try:
                consumer.close()
            except Exception as exc:
                cleanup_errors.append("consumer: " + str(exc))
        try:
            close_transport()
        except Exception as exc:
            cleanup_errors.append("MCP: " + str(exc))
        if ssh is not None:
            try:
                cleanup_errors.extend(ssh.close())
            except Exception as exc:
                cleanup_errors.append("SSH: " + str(exc))
        report["cleanup_errors"] = cleanup_errors
        if cleanup_errors:
            report["status"] = "HOLD"
        save()
        journal.close()
    print(json.dumps({"status": report["status"], "output": str(output / "report.json"),
                      "checks": report["checks"]}, sort_keys=True))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--consumer":
        consumer_main(sys.argv[2:])
    else:
        raise SystemExit(main())

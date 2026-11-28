#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Actual HIA bootstrap + static read ELF over an owned loopback SSH server.

The temporary SSH server, keys and Python comparisons are qualification fixtures.
This does not install a configured-host public route or qualify SSH cancellation.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import pwd
import shlex
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_local_service as shared
import test_multi_service as multi
sys.path.insert(0, str(shared.ROOT / "scripts"))
from hia_native_loader import NativeModule

SERVICE_SUITE_RESULTS = []
REMOTE_SESSION_COUNTS = {"sessions": 0, "responses": 0}
COUNTS = {"native_bootstrap_calls": 0, "ssh_invocations": 0, "actual_elf_responses": 0,
          "binary_read_original_comparisons": 0, "multi_read_original_comparisons": 0,
          "file_info_original_comparisons": 0, "truncated_elf_refusals": 0,
          "invalid_elf_refusals": 0}


def request(size: int, root: bytes) -> bytes:
    return b"HLRBQ001" + struct.pack("<7Q", size, len(root), 0, 0, 0, 0, 0) + root


class LoopbackSSH:
    def __init__(self, parent: Path):
        self.owner = tempfile.TemporaryDirectory(prefix="native-read-ssh-", dir=parent)
        self.root = Path(self.owner.name)
        self.process = None
        self.log = None
        try:
            self.start()
        except BaseException:
            self.close()
            raise

    def start(self):
        self.ssh = shutil.which("ssh")
        self.sshd = shutil.which("sshd") or "/usr/sbin/sshd"
        self.keygen = shutil.which("ssh-keygen")
        if not self.ssh or not Path(self.sshd).is_file() or not self.keygen:
            self.close()
            raise RuntimeError("ssh, sshd and ssh-keygen are required; transport proof cannot be skipped")
        for name in ("host", "client"):
            subprocess.run([self.keygen, "-q", "-t", "ed25519", "-N", "", "-f",
                            str(self.root / name)], check=True, capture_output=True)
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            self.port = probe.getsockname()[1]
        self.user = pwd.getpwuid(os.getuid()).pw_name
        config = self.root / "sshd_config"
        config.write_text("\n".join([
            f"Port {self.port}", "ListenAddress 127.0.0.1",
            f"HostKey {self.root / 'host'}", f"PidFile {self.root / 'sshd.pid'}",
            f"AuthorizedKeysFile {self.root / 'client.pub'}", "StrictModes yes",
            "UsePAM no", "PasswordAuthentication no", "KbdInteractiveAuthentication no",
            "PubkeyAuthentication yes", "AuthenticationMethods publickey",
            "PermitEmptyPasswords no", "PermitUserEnvironment no", "PermitTTY no",
            "AllowTcpForwarding no", "X11Forwarding no", f"AllowUsers {self.user}",
            "LogLevel VERBOSE", "",
        ]))
        host_public = (self.root / "host.pub").read_text().split()
        self.known_hosts = self.root / "known_hosts"
        self.known_hosts.write_text(f"[127.0.0.1]:{self.port} {host_public[0]} {host_public[1]}\n")
        subprocess.run([self.sshd, "-t", "-f", str(config)], check=True, capture_output=True)
        self.log = (self.root / "sshd.log").open("wb")
        self.process = subprocess.Popen([self.sshd, "-D", "-e", "-f", str(config)],
                                        stdin=subprocess.DEVNULL, stdout=self.log, stderr=self.log,
                                        start_new_session=True)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError("owned sshd exited: " + (self.root / "sshd.log").read_text())
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=.2) as connection:
                    if connection.recv(256).startswith(b"SSH-"):
                        break
            except OSError:
                time.sleep(.02)
        else:
            raise RuntimeError("owned loopback sshd did not become ready")

    def argv(self, command: str) -> list[str]:
        return [self.ssh, "-F", "/dev/null", "-T", "-p", str(self.port),
                "-i", str(self.root / "client"), "-o", "BatchMode=yes",
                "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
                "-o", "UserKnownHostsFile=" + str(self.known_hosts),
                "-o", "GlobalKnownHostsFile=/dev/null", "-o", "ConnectTimeout=5",
                self.user + "@127.0.0.1", command]

    def run(self, command: str, payload: bytes) -> tuple[int, bytes, bytes]:
        # A private pipe lets a writer fragment the actual stream while communicate
        # independently drains stdout/stderr. No expected result enters transport.
        read_fd, write_fd = os.pipe()
        process = subprocess.Popen(self.argv("cd " + shlex.quote(str(self.root)) + "; " + command),
                                   stdin=read_fd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True)
        os.close(read_fd)
        errors = []
        def write():
            try:
                at = 0
                sizes = (1, 17, 4093, 65535, 2, 8191)
                index = 0
                while at < len(payload):
                    end = min(len(payload), at + sizes[index % len(sizes)])
                    while at < end:
                        written = os.write(write_fd, payload[at:end])
                        if written <= 0:
                            raise RuntimeError("zero-byte qualification pipe write")
                        at += written
                    index += 1
            except BrokenPipeError:
                pass
            except BaseException as exc:
                errors.append(repr(exc))
            finally:
                os.close(write_fd)
        writer = threading.Thread(target=write, daemon=True)
        writer.start()
        try:
            out, err = process.communicate(timeout=45)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
            raise
        finally:
            writer.join(timeout=5)
        if writer.is_alive() or errors:
            raise RuntimeError(f"fixture stream writer did not close: {errors}")
        COUNTS["ssh_invocations"] += 1
        return process.returncode, out, err

    def close(self):
        if self.process is not None and self.process.poll() is None:
            os.killpg(self.process.pid, signal.SIGTERM)
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait(timeout=5)
        if self.log is not None:
            self.log.close()
        self.owner.cleanup()


class NativeReadBootstrapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        shared.NativeServiceTests.setUpClass()
        multi.MultiServiceTests.setUpClass()
        cls.service_manifest = shared.NativeServiceTests.manifest
        cls.service_metadata = shared.NativeServiceTests.metadata
        cls.executable = shared.NativeServiceTests.executable
        cls.elf = cls.executable.read_bytes()
        cls.original = shared.NativeServiceTests.original
        cls.bootstrap_manifest = Path(os.environ["HIA_BOOTSTRAP_MANIFEST"]).resolve(strict=True)
        cls.bootstrap_metadata = json.loads(cls.bootstrap_manifest.read_bytes())
        source = shared.ROOT / "native/native_read_bootstrap.hepta"
        if hashlib.sha256(source.read_bytes()).hexdigest() != cls.bootstrap_metadata["source_sha256"]:
            raise ValueError("bootstrap manifest is not bound to current HIA")
        cls.module = NativeModule(cls.bootstrap_manifest,
                                  manifest_sha256=hashlib.sha256(cls.bootstrap_manifest.read_bytes()).hexdigest())
        cls.addClassCleanup(cls.module.close)
        fixture_root = Path(os.environ["HIA_READ_TRANSPORT_FIXTURE_ROOT"]).resolve(strict=True)
        cls.ssh = LoopbackSSH(fixture_root)
        cls.addClassCleanup(cls.ssh.close)

    def command(self, root: Path, size: int | None = None) -> str:
        raw = request(len(self.elf) if size is None else size, os.fsencode(root))
        response = self.module.invoke(raw, output_capacity=32768, workspace_capacity=4096)
        COUNTS["native_bootstrap_calls"] += 1
        self.assertEqual(response[:8], b"HLRBR001")
        self.assertEqual(struct.unpack_from("<Q", response, 56)[0], len(response)-64)
        self.assertEqual(struct.unpack_from("<Q", response, 32)[0], len(os.fsencode(root)))
        return response[64:].decode()

    def round_trip(self, command: str, payload: bytes):
        before = set(Path("/tmp").glob(".hepta-hia-read-*"))
        result = self.ssh.run(command, payload)
        self.assertFalse(set(Path("/tmp").glob(".hepta-hia-read-*")) - before,
                         "owned bootstrap directory survived completed SSH request")
        return result

    def test_native_admission_and_capacity_refusals(self):
        valid = request(len(self.elf), b"/tmp")
        invalid = [b"", valid[:63], b"wronghdr" + valid[8:],
                   request(0, b"/tmp"), request(0xffff0000, b"/tmp"),
                   request(1, b""), request(1, b"relative"), request(1, b"/\0bad"),
                   request(1, b"/\xff"), request(1, b"/" + b"x"*4095),
                   valid + b"x", valid[:24] + struct.pack("<Q", 1) + valid[32:]]
        with self.module.session(output_capacity=32768, workspace_capacity=4096) as native:
            for frame in invalid:
                before = bytes(native._output)[:native.output_capacity]
                code, output, work = native.invoke_raw(frame)
                COUNTS["native_bootstrap_calls"] += 1
                self.assertEqual(code, 0xffffffff)
                self.assertEqual(bytes(native._output)[:-16], before)
        with self.module.session(output_capacity=64, workspace_capacity=4096) as native:
            before = bytes(native._output)[:-16]
            code, output, work = native.invoke_raw(valid)
            COUNTS["native_bootstrap_calls"] += 1
            self.assertEqual(code, 0xfffffffe)
            self.assertEqual(bytes(native._output)[:-16], before)

    def test_actual_three_tools_and_shell_quoted_roots(self):
        for name in ("ordinary", "root' ; touch HIA_BOOTSTRAP_SENTINEL ; #\n雪😀", "quote\"\\tab\t"):
            with self.subTest(root=name):
                root = self.ssh.root / name
                root.mkdir()
                binary = root / "binary"
                binary.write_bytes(bytes(range(256))*3 + b"\0\xffend")
                first = root / "text"
                first.write_text('line one\nquote " slash \\ 雪😀\0', encoding="utf-8")
                second = root / "second"
                second.write_text("other text\r\n", encoding="utf-8")
                frames = [shared.init(1), b'{"jsonrpc":"2.0","method":"notifications/initialized"}',
                          shared.req("tools/list", identity=2)]
                args = [
                    ("binary_read", {"host": "native-local", "path": str(binary), "offset": 7, "limit": 11}),
                    ("read_multiple_files", {"host": "native-local", "paths": [str(first), str(second)]}),
                    ("file_info", {"host": "native-local", "path": str(binary)}),
                ]
                for identity, (tool, arguments) in enumerate(args, 3):
                    frames.append(shared.req("tools/call", {"name": tool, "arguments": arguments}, identity))
                command = self.command(root)
                code, out, err = self.round_trip(command, self.elf + b"\n".join(frames) + b"\n")
                self.assertEqual(code, 0, err)
                responses = [json.loads(line) for line in out.splitlines()]
                self.assertEqual([item["id"] for item in responses], [1, 2, 3, 4, 5])
                COUNTS["actual_elf_responses"] += len(responses)
                self.assertEqual([tool["name"] for tool in responses[1]["result"]["tools"]],
                                 ["host_list", "binary_read", "read_multiple_files", "file_info"])
                expected = [
                    self.original.main({"op": "read", "root": str(root), "path": str(binary),
                                        "offset": 7, "limit": 11, "expected_version": None}),
                    multi.MultiServiceTests.original({"files": [{"path": str(path), "root": str(root)}
                                                                for path in (first, second)],
                                                       "max_file_bytes": 16384, "max_response_bytes": 65536}),
                    self.original.main({"op": "info", "root": str(root), "path": str(binary)}),
                ]
                for response, original, counter in zip(responses[2:], expected, (
                        "binary_read_original_comparisons", "multi_read_original_comparisons",
                        "file_info_original_comparisons"), strict=True):
                    result = response["result"]
                    self.assertFalse(result["isError"])
                    self.assertEqual(result["content"], [{"type": "text", "text":
                                     json.dumps(original, ensure_ascii=False, sort_keys=True,
                                                separators=(",", ":"))}])
                    COUNTS[counter] += 1
                self.assertFalse((self.ssh.root / "HIA_BOOTSTRAP_SENTINEL").exists())

    def test_short_image_never_consumes_request_as_a_successful_helper(self):
        root = self.ssh.root / "truncated"
        root.mkdir()
        code, out, err = self.round_trip(self.command(root), self.elf[:-1])
        self.assertEqual(code, 125, err)
        self.assertEqual(out, b"")
        COUNTS["truncated_elf_refusals"] += 1

    def test_complete_original_service_suites_over_ssh(self):
        import test_info_service as info
        from hia_native_local_read_qualification import admit_suite
        baseline_session = shared.Session
        module = self.module
        elf = self.elf
        ssh = self.ssh
        class RemoteSession(baseline_session):
            def __init__(self, executable, root):
                self.root = Path(root)
                if Path(executable).read_bytes() != elf:
                    raise ValueError("remote service source executable changed")
                reply = module.invoke(request(len(elf), os.fsencode(root)),
                                      output_capacity=32768, workspace_capacity=4096)
                command = reply[64:].decode()
                self.proc = subprocess.Popen(ssh.argv(command), stdin=subprocess.PIPE,
                                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                             env={"PATH": ""})
                self.buffer = b""
                self.proc.stdin.write(elf)
                self.proc.stdin.flush()
                REMOTE_SESSION_COUNTS["sessions"] += 1
                COUNTS["native_bootstrap_calls"] += 1
            def receive(self):
                response = super().receive()
                REMOTE_SESSION_COUNTS["responses"] += 1
                return response
        before = set(Path("/tmp").glob(".hepta-hia-read-*"))
        shared.Session = RemoteSession
        try:
            for name, owner, case in (
                    ("test_local_service", shared, shared.NativeServiceTests),
                    ("test_multi_service", multi, multi.MultiServiceTests),
                    ("test_info_service", info, info.InfoServiceTests)):
                for counter in shared.COUNTS:
                    shared.COUNTS[counter] = 0
                for counter in owner.COUNTS:
                    owner.COUNTS[counter] = 0
                suite = unittest.defaultTestLoader.loadTestsFromTestCase(case)
                result = unittest.TextTestRunner(verbosity=1).run(suite)
                counts = dict(owner.COUNTS)
                if owner is not shared:
                    counts["all_actual_elf_responses"] = shared.COUNTS["elf_requests"]
                proof = {
                    "name": name, "status": "pass" if result.wasSuccessful() else "fail",
                    "tests_run": result.testsRun, "skipped": len(result.skipped),
                    "errors": len(result.errors), "failures": len(result.failures),
                    "expected_failures": len(result.expectedFailures),
                    "unexpected_successes": len(result.unexpectedSuccesses),
                    "python_isolated": sys.flags.isolated, "python_optimize": sys.flags.optimize,
                    "counts": counts,
                    "manifest_sha256": hashlib.sha256(self.service_manifest.read_bytes()).hexdigest(),
                    "executable_sha256": self.service_metadata["executable_sha256"],
                }
                SERVICE_SUITE_RESULTS.append(proof)
                admit_suite(name, proof, proof["manifest_sha256"], proof["executable_sha256"])
                self.assertTrue(result.wasSuccessful(), name)
        finally:
            shared.Session = baseline_session
        self.assertFalse(set(Path("/tmp").glob(".hepta-hia-read-*")) - before)
        # The retained framing regression invokes the ELF directly for two final
        # EOF responses. Every other response in the three suites traverses SSH.
        self.assertEqual(REMOTE_SESSION_COUNTS["responses"], 413)

    def test_invalid_complete_image_is_refused_and_cleaned(self):
        root = self.ssh.root / "bad-exec"
        root.mkdir()
        code, out, err = self.round_trip(self.command(root, 4), b"\x7fELF")
        self.assertNotEqual(code, 0)
        self.assertEqual(out, b"")
        COUNTS["invalid_elf_refusals"] += 1


if __name__ == "__main__":
    result = unittest.main(exit=False, verbosity=2)
    proof = {
        "schema": "hepta.runtime.native-read-bootstrap-transport-test.v1",
        "status": "pass" if result.result.wasSuccessful() else "fail",
        "tests_run": result.result.testsRun, "skipped": len(result.result.skipped),
        "errors": len(result.result.errors), "failures": len(result.result.failures),
             "expected_failures": len(result.result.expectedFailures),
             "unexpected_successes": len(result.result.unexpectedSuccesses),
             "python_isolated": sys.flags.isolated, "python_optimize": sys.flags.optimize,
        "counts": COUNTS, "complete_original_service_suites": SERVICE_SUITE_RESULTS,
        "remote_sessions": REMOTE_SESSION_COUNTS, "direct_eof_responses_in_retained_suite": 2,
        "ssh_target": "owned loopback server with ephemeral host/client keys",
        "existing_sshd_configuration_changed": False, "configured_host_alias_mapping": False,
        "default_public_route": False, "ssh_cancellation_qualified": False,
        "remote_parent_death_qualified": False, "whole_runtime_replaced": False,
    }
    if hasattr(NativeReadBootstrapTests, "bootstrap_metadata"):
        proof["bootstrap_source_sha256"] = NativeReadBootstrapTests.bootstrap_metadata["source_sha256"]
        proof["bootstrap_image_sha256"] = NativeReadBootstrapTests.bootstrap_metadata["image_sha256"]
        proof["read_executable_sha256"] = NativeReadBootstrapTests.service_metadata["executable_sha256"]
    if os.environ.get("HIA_READ_TRANSPORT_RESULT"):
        Path(os.environ["HIA_READ_TRANSPORT_RESULT"]).write_text(
            json.dumps(proof, indent=2, sort_keys=True) + "\n")
    print(json.dumps(proof, sort_keys=True))
    raise SystemExit(0 if result.result.wasSuccessful() else 1)

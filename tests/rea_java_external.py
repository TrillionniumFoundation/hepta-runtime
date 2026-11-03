#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Explicit real JADX qualification via native worker and the existing SSH job owner.

Only Java source authored below is compiled and inspected. No fixture class/JAR is
executed. The selected installed JDK and JADX engine execute as trusted tools.
Requires pre-existing localhost SSH/systemd; does not install or modify them.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import queue
import shutil
import subprocess
import threading
import time
import zipfile


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def private_write(path, value):
    data = value if isinstance(value, bytes) else json.dumps(value, separators=(",", ":")).encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def set_fence(root, phase):
    authority = root / "authority"
    with (authority / ".owner.lock").open("r+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        nxt = authority / ".owner-next.json"
        private_write(nxt, {
            "schema": "hepta-effect-owner-fence-v1", "owner": "v4", "epoch": 1,
            "phase": phase, "state_root": str(root / "controller-state"),
            "predecessor_state_root": None,
        })
        nxt.replace(authority / ".owner.json")
        directory = os.open(authority, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


class Mcp:
    def __init__(self, runtime, root):
        self.root = root
        self.replies = queue.Queue()
        self.sequence = 0
        self.log = (root / "controller-stderr.log").open("ab")
        env = dict(os.environ, HEPTA_EFFECT_OWNER_FENCE_DIR=str(root / "authority"),
                   HEPTA_EFFECT_OWNER_SELF="v4", HEPTA_EFFECT_OWNER_FENCE_REQUIRED="1")
        self.child = subprocess.Popen([str(runtime), "mcp", "--runtime-config", str(root / "config.json")],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.log,
                                      text=True, env=env)
        def read():
            for line in self.child.stdout:
                self.replies.put(line)
            self.replies.put(None)
        self.reader = threading.Thread(target=read, daemon=True)
        self.reader.start()
        self.request("initialize", {"protocolVersion": "2026-07-28", "capabilities": {},
                                   "clientInfo": {"name": "owned-jadx-qualification", "version": "1"}})
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})

    def send(self, value):
        self.child.stdin.write(json.dumps(value, separators=(",", ":")) + "\n")
        self.child.stdin.flush()

    def request(self, method, params):
        self.sequence += 1
        identity = self.sequence
        self.send({"jsonrpc": "2.0", "id": identity, "method": method, "params": params})
        deadline = time.monotonic() + 60
        while True:
            line = self.replies.get(timeout=max(0.01, deadline - time.monotonic()))
            if line is None:
                raise RuntimeError("MCP controller exited; see controller-stderr.log")
            reply = json.loads(line)
            if reply.get("id") != identity:
                continue
            assert "error" not in reply, reply
            return reply["result"]

    def raw(self, name, arguments):
        return self.request("tools/call", {"name": name, "arguments": arguments})

    def call(self, name, arguments):
        result = self.raw(name, arguments)
        assert result.get("isError") is not True, (name, result)
        return json.loads(result["content"][0]["text"])

    def complete(self, request):
        deadline = time.monotonic() + 125
        while time.monotonic() < deadline:
            result = self.call("rea_static_read", request)
            if result.get("complete") is True:
                return result
            time.sleep(0.1)
        raise TimeoutError("original job did not produce a complete retained outcome")

    def close(self):
        self.child.stdin.close()
        try:
            self.child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.child.kill()
            self.child.wait()
        self.reader.join(timeout=2)
        self.log.close()


def fixture(java_home, root):
    source = root / "OwnedFixture.java"
    private_write(source, b'public class OwnedFixture { public static int add(int left, int right) { return left + right; } public String label() { return "HEPTA_OWNED_JADX_FIXTURE"; } }\n')
    cancel_source = root / "OwnedCancelFixture.java"
    text = "public class OwnedCancelFixture {\n" + "\n".join(
        f"public static class Entry{i} {{ public int value(int x) {{ return x + {i}; }} }}"
        for i in range(256)) + "\n}\n"
    private_write(cancel_source, text.encode())
    classes = root / "classes"
    classes.mkdir(mode=0o700)
    subprocess.run([str(java_home / "bin/javac"), "--release", "17", "-g:none", "-d", str(classes),
                    str(source), str(cancel_source)], check=True, capture_output=True, timeout=30)
    jar = root / "OwnedCancelFixture.jar"
    with zipfile.ZipFile(jar, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(classes.glob("OwnedCancelFixture*.class")):
            archive.write(path, path.name)
    return classes / "OwnedFixture.class", jar


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--java-home", type=Path, required=True)
    parser.add_argument("--jadx-home", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--allow-local-ssh", action="store_true")
    parser.add_argument("--execution-mode", choices=("operator", "isolated"), required=True)
    args = parser.parse_args()
    assert args.allow_local_ssh, "Explicit --allow-local-ssh is required"
    runtime, java_home, jadx_home = (path.resolve(strict=True) for path in
                                    (args.runtime, args.java_home, args.jadx_home))
    root = args.workspace.absolute()
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    root = root.resolve(strict=True)
    source_runtime = runtime
    runtime = root / "hepta-runtime-qualified"
    shutil.copyfile(source_runtime, runtime)
    runtime.chmod(0o500)
    for name in ("controller-state", "jobs", "authority"):
        (root / name).mkdir(mode=0o700)
    private_write(root / "authority/.owner.lock", b"")
    set_fence(root, "admitting")
    artifact, cancellation_artifact = fixture(java_home, root)
    jar = jadx_home / "lib/jadx-1.5.6-all.jar"
    components = ["release", "lib/modules", "lib/server/libjvm.so", "lib/libjava.so",
                  "lib/libzip.so", "lib/libnio.so", "lib/libjli.so"]
    version_result = subprocess.run([str(java_home / "bin/java"), "--version"], check=True,
                                    capture_output=True, timeout=10, env={"LC_ALL": "C"})
    assert not version_result.stderr
    version = version_result.stdout.decode().splitlines()[0]
    profile = {
        "host": "local", "runtime_executable": str(runtime), "runtime_sha256": digest(runtime),
        "provider": "jadx", "backend_executable": str(java_home / "bin/java"),
        "backend_sha256": digest(java_home / "bin/java"), "backend_version": version,
        "working_directory": str(root), "input_roots": [str(root)],
        "allowed_operations": ["classes", "sources"], "max_artifact_bytes": 33554432,
        "max_output_bytes": 65536, "timeout_seconds": 120, "memory_max_bytes": 1073741824,
        "java_engine": {
            "java_home": str(java_home), "jar_path": str(jar), "jar_sha256": digest(jar),
            "engine_version": "1.5.6",
            "release_archive_sha256": "545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974",
            "runtime_files": {name: digest(java_home / name) for name in sorted(components)},
        },
    }
    config = {
        "state_dir": str(root / "controller-state"), "controller_workspace_roots": [str(root)],
        "hosts": {"local": {
            "ssh_target": "localhost", "platform": "linux", "execution_mode": args.execution_mode, "remote_state_dir": str(root / "jobs"),
            "allow_execute": True, "allow_write": True, "allow_job_network": args.execution_mode == "operator",
            "allow_detached_fallback": False, "allowed_cwd_prefixes": [] if args.execution_mode == "operator" else [str(root)],
            "allowed_read_path_prefixes": [str(root), str(runtime.parent), str(java_home), str(jadx_home)],
            "allowed_write_path_prefixes": [str(root)],
        }},
        "rea_static_profiles": {"owned_jadx": profile},
    }
    private_write(root / "config.json", config)
    server = None
    result = {"schema": "hepta.rea.jadx-native-qualification.v1", "workspace": str(root),
              "runtime_sha256": profile["runtime_sha256"], "java_engine": profile["java_engine"],
              "backend_sha256": profile["backend_sha256"], "backend_version": version,
              "targets_run_by_harness": 0, "execution_mode": args.execution_mode,
              "isolated_host_qualification": args.execution_mode == "isolated", "rea_full_parity": False, "checks": []}
    try:
        server = Mcp(runtime, root)
        names = {entry["name"] for entry in server.request("tools/list", {})["tools"]}
        assert {"rea_static_profiles", "rea_static_start", "rea_static_status", "rea_static_read", "rea_static_cancel"} <= names
        admitted_profile = server.call("rea_static_profiles", {})["profiles"][0]
        def request(key, operation, selected):
            return {"profile": "owned_jadx", "profile_sha256": admitted_profile["profile_sha256"],
                    "idempotency_key": key, "operation": operation, "artifact_path": str(selected),
                    "artifact_sha256": digest(selected)}
        classes_request = request("owned-jadx-classes", "classes", artifact)
        sources_request = request("owned-jadx-sources", "sources", artifact)
        private_write(root / "requests.json", {"classes": classes_request, "sources": sources_request})

        direct = {"schema": "hepta.rea.static-request.v1", "profile": profile,
                  "request": classes_request, "protected_roots": []}
        native = subprocess.run([str(runtime), "rea-static-worker"],
                                input=(json.dumps(direct, separators=(",", ":")) + "\n").encode(),
                                capture_output=True, timeout=125,
                                env=dict(os.environ, TOKIO_WORKER_THREADS="1"))
        private_write(root / "native-worker-stderr.txt", native.stderr)
        assert native.returncode == 0, native.stderr.decode(errors="replace")
        direct_report = json.loads(native.stdout)
        assert direct_report["backend_success"] is True, direct_report
        direct_observation = json.loads(direct_report["stdout"])
        assert direct_observation["observed_class_count"] == 1, direct_observation
        assert direct_observation["rows"][0]["class_name"] == "OwnedFixture"
        assert direct_report["scratch"]["removed_after_operation"] is True
        assert direct_report["network_syscalls_denied"] is True
        private_write(root / "native-worker-report.json", direct_report)
        result["checks"].append("actual_native_worker_owned_class")

        first = server.call("rea_static_start", classes_request)
        assert first["job"]["execution_mode"] == args.execution_mode
        private_write(root / "initial-job.json", first)
        assert first["job"].get("launch_state") != "launch_unknown", first
        replay = server.call("rea_static_start", classes_request)
        assert replay["job"]["id"] == first["job"]["id"] and replay["reused"] is True
        completed = server.complete(classes_request)
        assert completed["process_succeeded"] is True, completed
        observation = json.loads(completed["report"]["stdout"])
        assert observation["rows"][0]["class_name"] == "OwnedFixture"
        assert observation["target_executed"] is False and observation["external_plugins_loaded"] is False
        result["classes_job_id"] = first["job"]["id"]
        private_write(root / "classes-result.json", completed)
        result["checks"].append("actual_jadx_mcp_classes_same_key_same_job")

        server.call("rea_static_start", sources_request)
        sources = server.complete(sources_request)
        assert sources["process_succeeded"] is True, sources
        source = json.loads(sources["report"]["stdout"])
        assert source["source_semantics_validated"] is False
        row = source["rows"][0]
        assert row["source_preview_complete"] is True
        assert "HEPTA_OWNED_JADX_FIXTURE" in row["source_preview"], row
        assert row["source_sha256"] == hashlib.sha256(row["source_preview"].encode()).hexdigest()
        private_write(root / "sources-result.json", sources)
        result["checks"].append("actual_jadx_bounded_source_preview_and_digest")

        server.close()
        server = Mcp(runtime, root)
        recovered = server.call("rea_static_start", classes_request)
        assert recovered["job"]["id"] == first["job"]["id"]
        assert server.complete(classes_request) == completed
        result["checks"].append("controller_restart_original_result_without_relaunch")
        changed = dict(classes_request, operation="sources")
        assert server.raw("rea_static_start", changed).get("isError") is True
        rebound = dict(classes_request, profile_sha256="0" * 64)
        assert server.raw("rea_static_start", rebound).get("isError") is True
        missing = dict(classes_request, idempotency_key="never-submitted")
        assert server.raw("rea_static_status", missing).get("isError") is True
        result["checks"].append("changed_payload_profile_rebinding_and_unsubmitted_observation_rejected")

        cancellation = request("owned-jadx-cancel", "sources", cancellation_artifact)
        private_write(root / "cancel-request.json", cancellation)
        active = server.call("rea_static_start", cancellation)
        result["cancel_job_id"] = active["job"]["id"]
        set_fence(root, "frozen")
        status_before = server.call("rea_static_status", cancellation)
        assert status_before["job"]["id"] == active["job"]["id"]
        assert server.complete(classes_request) == completed
        assert server.raw("rea_static_start", cancellation).get("isError") is True
        cancel = server.call("rea_static_cancel", cancellation)
        assert cancel["cancellation_requested"] is True and cancel["termination_confirmed"] is False
        cancelled = server.complete(cancellation)
        terminal = server.call("rea_static_status", cancellation)
        assert cancelled["process_succeeded"] is False, cancelled
        assert terminal["status"]["state"] in ("cancelled", "failed"), terminal
        private_write(root / "cancellation-result.json", {"before": status_before, "cancel": cancel,
                                                        "result": cancelled, "terminal": terminal})
        set_fence(root, "admitting")
        after = server.call("rea_static_start", cancellation)
        assert after["job"]["id"] == active["job"]["id"]
        assert after["reused"] is True
        result["checks"].append("frozen_owner_observation_cancel_original_job_and_no_relaunch")
        result["cancel_terminal_state"] = terminal["status"]["state"]
        assert digest(artifact) == classes_request["artifact_sha256"]
        assert digest(cancellation_artifact) == cancellation["artifact_sha256"]
        result["checks"].append("inspected_artifact_bytes_unchanged")
        # Only this newly created workspace's terminal-job scratch is removed.
        leftover = list(root.glob(".hepta-rea-jadx-*"))
        for path in leftover:
            assert path.is_dir() and not path.is_symlink() and path.stat().st_uid == os.getuid()
            shutil.rmtree(path)
        result["cancelled_private_scratch_removed_by_harness"] = len(leftover)
        result["qualified"] = True
    except Exception as error:
        result["qualified"] = False
        result["failure"] = repr(error)
        raise
    finally:
        if server is not None:
            server.close()
        private_write(root / "qualification.json", result)
        print("REA_JADX_NATIVE_QUALIFICATION " + json.dumps(result, separators=(",", ":")), flush=True)


if __name__ == "__main__":
    main()

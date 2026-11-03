#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Real Ghidra import-only qualification on self-authored ELF, never executed."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
from rea_java_external import Mcp, digest, private_write, set_fence
from rea_java_kernel_probe import java_observation, process_identity, run_observed_worker

RELEASE_SHA = "2c2cd776db3c1f6a097ba418922378ac3649cadd5e844a6f5f088ae628a7be67"


def live_java(unit, mode, deadline):
    arguments = ["systemctl"] + (["--user"] if mode == "operator" else [])
    while time.monotonic() < deadline:
        current = subprocess.run(arguments + ["show", unit, "--property=ControlGroup", "--value"],
                                 check=True, capture_output=True, text=True, timeout=10).stdout.strip()
        if current:
            assert current.endswith("/" + unit + ".service"), current
            group = Path("/sys/fs/cgroup") / current.lstrip("/")
            try:
                for pid in (group / "cgroup.procs").read_text().split():
                    value = java_observation(int(pid))
                    if value is not None:
                        return value
            except FileNotFoundError:
                pass
        time.sleep(0.1)
    raise TimeoutError("Ghidra Java source process did not become observable")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--java-home", type=Path, required=True)
    parser.add_argument("--ghidra-home", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--execution-mode", choices=("operator", "isolated"), required=True)
    parser.add_argument("--allow-local-ssh", action="store_true")
    args = parser.parse_args()
    assert args.allow_local_ssh
    original_runtime, java_home, ghidra_home = (path.resolve(strict=True) for path in
                                               (args.runtime, args.java_home, args.ghidra_home))
    root = args.workspace.absolute()
    root.mkdir(mode=0o700, exist_ok=False)
    root = root.resolve(strict=True)
    runtime = root / "hepta-runtime-qualified"
    shutil.copyfile(original_runtime, runtime)
    runtime.chmod(0o500)
    for name in ("controller-state", "jobs", "authority"):
        (root / name).mkdir(mode=0o700)
    private_write(root / "authority/.owner.lock", b"")
    set_fence(root, "admitting")
    source = root / "owned.c"
    private_write(source, b"extern int owned_external; int hepta_ghidra_owned(int value) { return value + owned_external; }\n")
    artifact = root / "owned.o"
    subprocess.run(["cc", "-c", "-O0", "-fno-stack-protector", str(source), "-o", str(artifact)],
                   check=True, capture_output=True, timeout=30)
    cancellation_source = root / "owned_cancel.c"
    private_write(cancellation_source, "\n".join(
        f"int owned_cancel_{index}(int value) {{ return value + {index}; }}" for index in range(1000)).encode())
    cancellation_artifact = root / "owned_cancel.o"
    subprocess.run(["cc", "-c", "-O0", "-fno-stack-protector", str(cancellation_source), "-o", str(cancellation_artifact)],
                   check=True, capture_output=True, timeout=30)
    files = {}
    for path in sorted((ghidra_home / "Ghidra").rglob("*")):
        assert not path.is_symlink()
        if path.is_file():
            files[str(path.relative_to(ghidra_home))] = digest(path)
    manifest = {"schema": "hepta.rea.ghidra-installation.v1", "engine_version": "12.2",
                "release_archive_sha256": RELEASE_SHA, "files": files}
    manifest_path = root / "ghidra-installation.json"
    private_write(manifest_path, manifest)
    components = ["release", "lib/modules", "lib/server/libjvm.so", "lib/libjava.so",
                  "lib/libzip.so", "lib/libnio.so", "lib/libjli.so"]
    version_result = subprocess.run([str(java_home / "bin/java"), "--version"], check=True,
                                    capture_output=True, timeout=10, env={"LC_ALL": "C"})
    assert not version_result.stderr
    version = version_result.stdout.decode().splitlines()[0]
    profile = {"host": "local", "runtime_executable": str(runtime), "runtime_sha256": digest(runtime),
               "provider": "ghidra", "backend_executable": str(java_home / "bin/java"),
               "backend_sha256": digest(java_home / "bin/java"), "backend_version": version,
               "working_directory": str(root), "input_roots": [str(root)], "allowed_operations": ["inventory"],
               "max_artifact_bytes": 8388608, "max_output_bytes": 65536, "timeout_seconds": 120,
               "memory_max_bytes": 1610612736,
               "ghidra_engine": {"java_home": str(java_home), "installation_root": str(ghidra_home),
                                 "manifest_path": str(manifest_path), "manifest_sha256": digest(manifest_path),
                                 "engine_version": "12.2", "release_archive_sha256": RELEASE_SHA,
                                 "runtime_files": {name: digest(java_home / name) for name in sorted(components)}}}
    config = {"state_dir": str(root / "controller-state"), "controller_workspace_roots": [str(root)],
              "hosts": {"local": {"ssh_target": "localhost", "platform": "linux", "execution_mode": args.execution_mode,
                                  "remote_state_dir": str(root / "jobs"), "allow_execute": True, "allow_write": True,
                                  "allow_job_network": args.execution_mode == "operator", "allow_detached_fallback": False,
                                  "allowed_cwd_prefixes": [] if args.execution_mode == "operator" else [str(root)],
                                  "allowed_read_path_prefixes": [str(root), str(java_home), str(ghidra_home)],
                                  "allowed_write_path_prefixes": [str(root)]}},
              "rea_static_profiles": {"owned_ghidra": profile}}
    private_write(root / "config.json", config)
    result = {"schema": "hepta.rea.ghidra-native-qualification.v1", "workspace": str(root),
              "runtime_sha256": profile["runtime_sha256"], "backend_sha256": profile["backend_sha256"],
              "backend_version": version, "ghidra_engine": profile["ghidra_engine"],
              "execution_mode": args.execution_mode, "isolated_host_qualification": args.execution_mode == "isolated",
              "targets_run_by_harness": 0, "rea_full_parity": False, "checks": []}
    server = None
    try:
        server = Mcp(runtime, root)
        admitted = server.call("rea_static_profiles", {})["profiles"][0]
        def request(key, path):
            return {"profile": "owned_ghidra", "profile_sha256": admitted["profile_sha256"],
                    "idempotency_key": key, "operation": "inventory", "artifact_path": str(path),
                    "artifact_sha256": digest(path)}
        normal = request("owned-ghidra-inventory", artifact)
        private_write(root / "requests.json", {"inventory": normal})
        worker = {"schema": "hepta.rea.static-request.v1", "profile": profile,
                  "request": normal, "protected_roots": []}
        native, flags = run_observed_worker(runtime, worker)
        private_write(root / "native-worker-stderr.txt", native.stderr)
        assert native.returncode == 0, native.stderr.decode(errors="replace")
        direct = json.loads(native.stdout)
        assert direct["backend_success"] is True, direct
        observation = json.loads(direct["stdout"])
        assert observation["engine_version"] == "12.2" and observation["operation"] == "inventory"
        assert "ELF" in observation["format"] and observation["language_id"]
        assert any(row["name"] == ".text" for row in observation["memory_blocks"]), observation
        assert any(row["qualified_name"].endswith("hepta_ghidra_owned") for row in observation["imported_symbols"]), observation
        assert all(observation[key] is False for key in (
            "target_executed", "auto_analysis_performed", "decompilation_performed", "external_libraries_loaded", "project_saved"))
        assert direct["scratch"]["removed_after_operation"] is True and direct["network_syscalls_denied"] is True
        private_write(root / "native-worker-report.json", direct)
        private_write(root / "native-kernel-observation.json", flags)
        result["checks"].append("actual_fixed_ghidra_elf_import_memory_symbols_and_java_kernel_flags")
        first = server.call("rea_static_start", normal)
        private_write(root / "initial-job.json", first)
        assert first["job"]["execution_mode"] == args.execution_mode
        assert first["job"].get("launch_state") != "launch_unknown", first
        replay = server.call("rea_static_start", normal)
        assert replay["job"]["id"] == first["job"]["id"] and replay["reused"] is True
        completed = server.complete(normal)
        assert completed["process_succeeded"] is True, completed
        assert json.loads(completed["report"]["stdout"])["language_id"] == observation["language_id"]
        private_write(root / "inventory-result.json", completed)
        result["inventory_job_id"] = first["job"]["id"]
        result["checks"].append("actual_ghidra_mcp_original_job_and_same_key_replay")
        server.close()
        server = Mcp(runtime, root)
        assert server.call("rea_static_start", normal)["job"]["id"] == first["job"]["id"]
        assert server.complete(normal) == completed
        result["checks"].append("controller_restart_original_report_without_relaunch")
        rebound = dict(normal, profile_sha256="0" * 64)
        assert server.raw("rea_static_start", rebound).get("isError") is True
        absent = dict(normal, idempotency_key="never-submitted")
        assert server.raw("rea_static_status", absent).get("isError") is True
        cancellation = request("owned-ghidra-live-cancel", cancellation_artifact)
        private_write(root / "cancel-request.json", cancellation)
        active = server.call("rea_static_start", cancellation)
        private_write(root / "cancel-initial-job.json", active)
        java = live_java(active["job"]["unit"], args.execution_mode, time.monotonic() + 100)
        assert java["NoNewPrivs"] == "1" and java["Seccomp"] == "2", java
        private_write(root / "live-cancel-java-kernel-flags.json", java)
        set_fence(root, "frozen")
        assert server.call("rea_static_status", cancellation)["job"]["id"] == active["job"]["id"]
        cancel = server.call("rea_static_cancel", cancellation)
        assert cancel["cancellation_requested"] is True and cancel["termination_confirmed"] is False
        terminal_output = server.complete(cancellation)
        terminal = server.call("rea_static_status", cancellation)
        assert terminal_output["process_succeeded"] is False, terminal_output
        assert terminal["status"]["state"] in ("cancelled", "failed"), terminal
        deadline = time.monotonic() + 10
        while process_identity(java["pid"]) == java["start_time"]:
            assert time.monotonic() < deadline, "Original Java child survived original-job cancellation"
            time.sleep(0.05)
        assert server.complete(normal) == completed
        set_fence(root, "admitting")
        assert server.call("rea_static_start", cancellation)["job"]["id"] == active["job"]["id"]
        private_write(root / "cancellation-result.json", {"cancel": cancel, "terminal": terminal,
                                                         "result": terminal_output, "original_java": java,
                                                         "original_java_process_gone": True})
        result["cancel_job_id"] = active["job"]["id"]
        result["cancel_terminal_state"] = terminal["status"]["state"]
        result["checks"].append("frozen_original_owner_cancel_live_ghidra_java_process_and_no_relaunch")
        assert digest(artifact) == normal["artifact_sha256"]
        assert digest(cancellation_artifact) == cancellation["artifact_sha256"]
        leftovers = list(root.glob(".hepta-rea-ghidra-*"))
        for path in leftovers:
            assert path.is_dir() and not path.is_symlink() and path.stat().st_uid == os.getuid()
            shutil.rmtree(path)
        result["cancelled_private_scratch_removed_by_harness"] = len(leftovers)
        result["qualified"] = True
    except Exception as error:
        result["qualified"] = False
        result["failure"] = repr(error)
        raise
    finally:
        if server is not None:
            server.close()
        private_write(root / "qualification.json", result)
        print("REA_GHIDRA_NATIVE_QUALIFICATION " + json.dumps(result, separators=(",", ":")), flush=True)


if __name__ == "__main__":
    main()

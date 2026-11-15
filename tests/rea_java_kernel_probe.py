#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Observe this fixed worker's Java child kernel flags. No network challenge is sent."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import threading
import time
from rea_java_external import private_write


def status_fields(pid):
    text = Path(f"/proc/{pid}/status").read_text()
    fields = dict(line.split(":", 1) for line in text.splitlines() if ":" in line)
    return {key: fields.get(key, "").strip() for key in ("Name", "NoNewPrivs", "Seccomp", "Seccomp_filters")}


def process_identity(pid):
    try:
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
    except (OSError, IndexError):
        return None


def java_observation(pid):
    try:
        executable = os.readlink(f"/proc/{pid}/exe")
        with open(f"/proc/{pid}/cmdline", "rb") as source:
            command = source.read(131072)
        if not executable.endswith("/bin/java") or b"--source\0" not in command:
            return None
        return {"pid": pid, "start_time": process_identity(pid), "executable": executable,
                **status_fields(pid)}
    except (OSError, ProcessLookupError):
        return None


def run_observed_worker(runtime, request, timeout=125):
    child = subprocess.Popen([str(runtime), "rea-static-worker"], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             env=dict(os.environ, TOKIO_WORKER_THREADS="1"))
    try:
        parent_flags = status_fields(child.pid)
    except OSError:
        parent_flags = {}
    observed = {}
    finished = threading.Event()
    def observe():
        while not finished.is_set():
            try:
                children = set()
                for path in Path(f"/proc/{child.pid}/task").glob("*/children"):
                    try:
                        children.update(int(value) for value in path.read_text().split())
                    except (OSError, ValueError):
                        pass
                for pid in sorted(children)[:128]:
                    value = java_observation(pid)
                    if value is not None:
                        observed[(pid, value["start_time"])] = value
            except OSError:
                pass
            finished.wait(0.05)
    watcher = threading.Thread(target=observe, daemon=True)
    watcher.start()
    try:
        stdout, stderr = child.communicate((json.dumps(request, separators=(",", ":")) + "\n").encode(), timeout=timeout)
    except BaseException:
        child.kill()
        child.wait()
        raise
    finally:
        finished.set()
        watcher.join(timeout=2)
    completed = subprocess.CompletedProcess(child.args, child.returncode, stdout, stderr)
    observations = list(observed.values())
    assert observations, "The fixed Java source child was not observed"
    assert all(value["NoNewPrivs"] == "1" and value["Seccomp"] == "2" for value in observations), observations
    evidence = {"scope": "kernel flags observed on this fixed worker's Java source child",
                "worker_pid": child.pid, "worker_kernel_flags": parent_flags,
                "java_children": observations, "network_connect_probe_performed": False,
                "limitation": "Seccomp mode and NoNewPrivs observations do not independently decode the installed BPF rules"}
    return completed, evidence


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    args = parser.parse_args()
    root = args.workspace.resolve(strict=True)
    config = json.loads((root / "config.json").read_text())
    request = json.loads((root / "requests.json").read_text())["classes"]
    request = dict(request, idempotency_key="owned-native-kernel-observation")
    profile = config["rea_static_profiles"][request["profile"]]
    worker = {"schema": "hepta.rea.static-request.v1", "profile": profile,
              "request": request, "protected_roots": []}
    destination = root / "native-kernel-observation.json"
    assert not destination.exists()
    result, evidence = run_observed_worker(Path(profile["runtime_executable"]), worker)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    report = json.loads(result.stdout)
    assert report["backend_success"] is True and report["network_syscalls_denied"] is True
    assert report["scratch"]["removed_after_operation"] is True
    evidence.update({"runtime_sha256": profile["runtime_sha256"], "report_declares_network_syscalls_denied": True,
                     "native_report_id": report["native_report_id"]})
    private_write(destination, evidence)
    private_write(root / "native-kernel-probe-report.json", report)
    print("REA_JAVA_KERNEL_OBSERVATION " + json.dumps(evidence, separators=(",", ":")), flush=True)


if __name__ == "__main__":
    main()

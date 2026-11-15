#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Require the original durable owner's cleanup; never remove scratch in a harness."""
from pathlib import Path
import os
import signal
import subprocess
import time


def assert_owner_cleanup(output, terminal, job, workspace):
    status = terminal["status"]
    receipt = status.get("scratch_cleanup")
    assert isinstance(receipt, dict), "missing original owner scratch cleanup receipt"
    assert receipt == output.get("scratch_cleanup"), (receipt, output)
    assert receipt["schema"] == "hepta.rea.engine-scratch-cleanup.v1", receipt
    assert receipt["job_id"] == job["id"] == output["job_id"] == status["job_id"], receipt
    assert receipt["launch_nonce"] == status["launch_nonce"], receipt
    assert receipt["state"] == "removed" and receipt["removed"] is True, receipt
    assert receipt["durable"] is True and receipt["worker_adopted"] is True, receipt
    assert receipt["original_process_group_stopped"] is True and receipt["original_child_reaped"] is True, receipt
    assert output["cleanup_complete"] is True, output
    if job["execution_mode"] == "operator":
        assert not (Path(job["remote_job_dir"]) / "engine-scratch").exists(), job
    leftovers = list(Path(workspace).glob(".hepta-rea-ghidra-*")) + list(Path(workspace).glob(".hepta-rea-jadx-*"))
    assert not leftovers, ("worker used scratch outside its original owner", [str(path) for path in leftovers])
    return receipt


def control_group(job, mode):
    command = ["systemctl"] + (["--user"] if mode == "operator" else [])
    group = subprocess.run(command + ["show", job["unit"], "--property=ControlGroup", "--value"],
                           check=True, capture_output=True, text=True, timeout=10).stdout.strip()
    assert group.endswith("/" + job["unit"] + ".service"), (job, group)
    return Path("/sys/fs/cgroup") / group.lstrip("/")


def identity(pid):
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        return {"start_time":fields[19], "state":fields[0], "process_group":int(fields[2])}
    except FileNotFoundError:
        return None


def assert_original_group_membership(job, runtime, mode, processes):
    """Observe this fixed worker and engines in the same original PGID."""
    group = control_group(job, mode)
    workers = []
    for item in (group / "cgroup.procs").read_text().split():
        pid = int(item)
        try:
            before = identity(pid)
            command = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
            if os.readlink(f"/proc/{pid}/exe") == str(runtime) and command[1:2] == [b"rea-static-worker"]:
                assert before is not None and before["process_group"] == pid, (job, before)
                current = identity(pid)
                assert current is not None and current["start_time"] == before["start_time"] and current["process_group"] == pid
                workers.append({"pid":pid, **before})
        except (FileNotFoundError, ProcessLookupError):
            continue
    assert len(workers) == 1, ("original fixed group leader is unconfirmed", workers)
    observed = []
    for process in processes:
        current = identity(process["pid"])
        assert current is not None and current["start_time"] == process["start_time"], process
        assert current["process_group"] == workers[0]["pid"], ("engine escaped original group", process, current, workers)
        observed.append({**process, "process_group":current["process_group"]})
    return {"scope":"original_process_group", "worker":workers[0], "engines":observed,
            "arbitrary_escaped_descendants_qualified":False}


def signal_original_worker(job, runtime, mode, signum):
    group = control_group(job, mode)
    for item in (group / "cgroup.procs").read_text().split():
        pid = int(item)
        try:
            before = identity(pid)
            executable = os.readlink(f"/proc/{pid}/exe")
            command = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
            if executable != str(runtime) or command[1:2] != [b"rea-static-worker"]:
                continue
            fd = os.pidfd_open(pid, 0)
            try:
                current = identity(pid)
                assert current is not None and before["start_time"] == current["start_time"]
                assert current["process_group"] == pid
                assert os.readlink(f"/proc/{pid}/exe") == str(runtime)
                signal.pidfd_send_signal(fd, signum)
                return {"pid":pid, "start_time":before["start_time"], "executable":executable,
                        "signal":signum, "atomic_identity":True, "control_group":str(group),
                        "process_group":current["process_group"]}
            finally:
                os.close(fd)
        except (FileNotFoundError, ProcessLookupError):
            continue
    raise AssertionError("original fixed worker was not observable in its owned cgroup")


def wait_source_java(job, mode, timeout=110):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        group = control_group(job, mode)
        for item in (group / "cgroup.procs").read_text().split():
            pid = int(item)
            try:
                before = identity(pid)
                executable = os.readlink(f"/proc/{pid}/exe")
                command = Path(f"/proc/{pid}/cmdline").read_bytes()
                if not executable.endswith("/bin/java") or b"--source\0" not in command:
                    continue
                flags = dict(line.split(":",1) for line in Path(f"/proc/{pid}/status").read_text().splitlines() if ":" in line)
                assert flags["NoNewPrivs"].strip() == "1" and flags["Seccomp"].strip() == "2"
                assert before["start_time"] == identity(pid)["start_time"]
                observed = {"pid":pid,"start_time":before["start_time"],"executable":executable,
                            "NoNewPrivs":"1","Seccomp":"2","control_group":str(group)}
                observed["original_group"] = assert_original_group_membership(job, Path(job["executable"]), mode, [observed])
                return observed
            except (FileNotFoundError, ProcessLookupError):
                continue
        time.sleep(.05)
    raise TimeoutError("real Java source engine did not become observable")


def assert_original_processes_stopped(processes):
    deadline = time.monotonic() + 10
    result = []
    for process in processes:
        while True:
            current = identity(process["pid"])
            if current is None or current["start_time"] != process["start_time"] or current["state"] in ("Z", "X"):
                result.append({**process, "after":current, "original_live":False})
                break
            assert time.monotonic() < deadline, ("original engine process still runs", process, current)
            time.sleep(.05)
    return result

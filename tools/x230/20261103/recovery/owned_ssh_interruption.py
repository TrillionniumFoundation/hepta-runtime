#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Identify one private controller-owned SSH master before a bounded interruption.

This module never discovers arbitrary hosts or signals a numeric PID supplied by
the caller. The caller supplies its live Popen controller and the private profile
it just created. A signal is sent only through a pidfd after repeating all proofs.
"""
import os
from pathlib import Path
import re
import select
import signal
import socket
import stat
import struct

import x230_observation_benchmark as bench


def master_control_path(argv, controller_pid, target, profile):
    """Validate the fixed native master argv; slaves and inherited profiles fail."""
    bench.need(len(argv) >= 10 and argv[:3] == ["/usr/bin/ssh", "-F", profile["ssh_config"]]
               and argv[-2:] == ["--", target], "SSH master executable/profile/host differs")
    options, flags = {}, []
    index = 3
    while index < len(argv) - 2:
        value = argv[index]
        if value == "-o":
            bench.need(index + 1 < len(argv) - 2 and "=" in argv[index + 1],
                       "SSH option lacks a single value")
            key, value = argv[index + 1].split("=", 1)
            key = key.lower()
            bench.need(key not in options, "duplicate SSH option")
            options[key] = value
            index += 2
        else:
            flags.append(value)
            index += 1
    bench.need(flags == ["-T", "-N", "-n"], "not a foreground, no-session SSH master")
    for name, value in {"controlmaster": "yes", "controlpersist": "no",
                        "forkafterauthentication": "no", "proxycommand": "none",
                        "proxyjump": "none", "forwardagent": "no",
                        "identityagent": profile["agent_socket"],
                        "userknownhostsfile": profile["known_hosts"]}.items():
        bench.need(options.get(name) == value, "SSH master option differs: " + name)
    path = Path(options.get("controlpath", ""))
    parent = Path(profile["socket_parent"])
    bench.need(path.is_absolute() and ".." not in path.parts and path.parent.parent == parent
               and re.fullmatch(r"hp-o-" + str(controller_pid) + r"-[0-9a-f]{32}", path.parent.name)
               and re.fullmatch(r"m-[0-9]+", path.name), "SSH socket escaped this controller root")
    return path


def process_identity(pid):
    born = bench.process_stat(pid)[0]
    root = Path("/proc") / str(pid)
    status = dict(line.split(":", 1) for line in (root / "status").read_text().splitlines()
                  if ":" in line)
    raw = (root / "cmdline").read_bytes()
    bench.need(len(raw) <= 65536 and raw.endswith(b"\0"), "unbounded or incomplete SSH argv")
    argv = [part.decode("utf-8") for part in raw[:-1].split(b"\0")]
    executable = (root / "exe").stat()
    bench.need(bench.process_stat(pid)[0] == born, "SSH process generation changed")
    return {"pid": pid, "birth_ticks": born, "ppid": int(status["PPid"]),
            "uids": tuple(map(int, status["Uid"].split())), "argv": argv,
            "executable": (executable.st_dev, executable.st_ino),
            "session": os.getsid(pid), "process_group": os.getpgid(pid)}


def verify_master(controller, pid, target, profile):
    bench.need(controller.child.poll() is None
               and bench.process_stat(controller.child.pid)[0] == controller.birth,
               "private controller identity changed")
    value = process_identity(pid)
    ssh = Path("/usr/bin/ssh").stat()
    bench.need(value["ppid"] == controller.child.pid
               and value["uids"] == (os.getuid(),) * 4
               and value["session"] == value["process_group"] == controller.child.pid
               and value["executable"] == (ssh.st_dev, ssh.st_ino),
               "SSH is not an original direct child of this private controller")
    path = master_control_path(value["argv"], controller.child.pid, target, profile)
    directories = []
    for directory in (path.parent.parent, path.parent):
        info = directory.lstat()
        bench.need(directory.resolve(strict=True) == directory and stat.S_ISDIR(info.st_mode)
                   and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
                   "SSH socket root is not a private real directory")
        directories.append((str(directory), info.st_dev, info.st_ino, info.st_uid, info.st_mode))
    before = path.lstat()
    bench.need(stat.S_ISSOCK(before.st_mode) and before.st_uid == os.getuid()
               and before.st_nlink == 1, "SSH control socket is not the original account socket")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(1)
        stream.connect(str(path))
        peer = struct.unpack("3i", stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    bench.need(peer[0] == pid and peer[1] == os.getuid()
               and bench.identity(path.lstat()) == bench.identity(before),
               "SSH control peer or inode differs")
    after = process_identity(pid)
    bench.need(after == value, "SSH process changed during socket proof")
    for directory, dev, inode, uid, mode in directories:
        now = Path(directory).lstat()
        bench.need((now.st_dev, now.st_ino, now.st_uid, now.st_mode) == (dev, inode, uid, mode),
                   "private socket directory changed during proof")
    value.update(control_path=str(path), control_socket=bench.identity(before),
                 peer=peer, private_directories=directories,
                 argv_sha256=bench.digest(b"\0".join(arg.encode() for arg in value.pop("argv")) + b"\0"))
    return value


def find_master(controller, target, profile):
    """Read only the live controller's direct children, including its owner thread."""
    children = set()
    bench.need(controller.child.poll() is None
               and bench.process_stat(controller.child.pid)[0] == controller.birth,
               "controller is not the original live child")
    for task in (Path("/proc") / str(controller.child.pid) / "task").iterdir():
        try:
            children.update(map(int, (task / "children").read_text().split()))
        except (FileNotFoundError, ProcessLookupError):
            continue
    matching = []
    for pid in children:
        try:
            candidate = process_identity(pid)
        except (FileNotFoundError, ProcessLookupError):
            continue
        argv = candidate["argv"]
        if argv and argv[0] == "/usr/bin/ssh" and argv[-2:] == ["--", target] \
                and "ControlMaster=yes" in argv:
            matching.append(verify_master(controller, pid, target, profile))
    bench.need(len(matching) == 1, "expected exactly one provable private host master")
    return matching[0]


def interrupt_master(controller, target, profile, original):
    """SIGKILL only the reverified original kernel process; never unlink its socket."""
    bench.need(verify_master(controller, original["pid"], target, profile) == original,
               "master changed after interruption intent was persisted")
    pidfd = os.pidfd_open(original["pid"], 0)
    try:
        bench.need(verify_master(controller, original["pid"], target, profile) == original,
                   "master changed after pidfd open")
        signal.pidfd_send_signal(pidfd, signal.SIGKILL)
        poller = select.poll()
        poller.register(pidfd, select.POLLIN)
        terminal = bool(poller.poll(3000))
        return {"signal_sent": True, "signal": "SIGKILL", "pidfd_terminal_observed": terminal,
                "controller_pid": controller.child.pid, "master_pid": original["pid"],
                "master_birth_ticks": original["birth_ticks"],
                "socket_removed_by_harness": False, "network_or_service_changes": False}
    finally:
        os.close(pidfd)

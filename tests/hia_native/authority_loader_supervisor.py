"""Closed qualification faults for one owned private-token or owner probe.

The kernel executes ordinary syscalls. Selected tests inject explicit errno
completions or mutate only the declared owned fixture at a syscall boundary.
No file-content or credential validation is implemented in this supervisor.
"""
from pathlib import Path
import argparse
import array
import ctypes
import errno
import hashlib
import json
import os
import select
import signal
import socket
import sys
import time


class Filter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte), ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint)]


class Program(ctypes.Structure):
    _fields_ = [("length", ctypes.c_ushort), ("filter", ctypes.POINTER(Filter))]


class Data(ctypes.Structure):
    _fields_ = [("nr", ctypes.c_int), ("arch", ctypes.c_uint), ("ip", ctypes.c_uint64), ("args", ctypes.c_uint64 * 6)]


class Notification(ctypes.Structure):
    _fields_ = [("id", ctypes.c_uint64), ("pid", ctypes.c_uint), ("flags", ctypes.c_uint), ("data", Data)]


class Response(ctypes.Structure):
    _fields_ = [("id", ctypes.c_uint64), ("value", ctypes.c_int64), ("error", ctypes.c_int), ("flags", ctypes.c_uint)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--fixture", type=Path)
    parser.add_argument("--kind", choices=["token", "owner"], default="token")
    parser.add_argument("--mode", choices=["observe", "open_eintr", "read_eintr", "read_error", "read_zero",
        "read_error_after_prefix", "read_and_close_error", "stat_and_close_error",
        "stat_before_eintr", "stat_after_eintr", "stat_after_error", "close_eintr", "close_error",
        "rewrite", "chmod", "hardlink", "replace_path", "replace_after_stat"], required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    assert command and ctypes.sizeof(Notification) == 80 and ctypes.sizeof(Response) == 24
    executable = Path(command[0]).resolve(strict=True)
    image_before = hashlib.sha256(executable.read_bytes()).hexdigest()
    identity = None
    if args.kind == "token":
        assert args.fixture is not None
        owned = args.fixture.stat()
        assert owned.st_uid == os.geteuid()
        identity = (owned.st_dev, owned.st_ino)
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    libc = ctypes.CDLL(None, use_errno=True)
    pid = os.fork()
    if pid == 0:
        parent.close()
        try:
            if libc.prctl(38, 1, 0, 0, 0):
                raise OSError(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS")
            numbers = [0, 3, 5, 107, 257, 262, 332]
            raw = [Filter(0x20, 0, 0, 0)]
            for index, number in enumerate(numbers):
                raw.append(Filter(0x15, len(numbers) - index, 0, number))
            raw += [Filter(0x06, 0, 0, 0x7fff0000), Filter(0x06, 0, 0, 0x7fc00000)]
            filters = (Filter * len(raw))(*raw)
            program = Program(len(raw), filters)
            listener = libc.syscall(317, 1, 8, ctypes.byref(program))
            if listener < 0:
                raise OSError(ctypes.get_errno(), "seccomp notification unavailable")
            os.set_inheritable(listener, False)
            child.sendmsg([b"L"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [listener]))])
            os.execve(str(executable), command, dict(os.environ))
        except BaseException as error:
            os.write(2, (str(error) + "\n").encode())
            os._exit(75)
    child.close()
    listener = None
    wait_status = None
    events = []
    fired = False
    secondary_fired = False
    read_count = 0
    armed = False
    started = time.monotonic()
    try:
        if not select.select([parent], [], [], 5)[0]:
            raise RuntimeError("owned probe could not install fixed syscall supervisor")
        message, ancillary, _, _ = parent.recvmsg(1, socket.CMSG_SPACE(4))
        assert message == b"L" and len(ancillary) == 1
        descriptors = array.array("i")
        descriptors.frombytes(ancillary[0][2][:4])
        listener = descriptors[0]
        parent.close()
        while True:
            ended, status = os.waitpid(pid, os.WNOHANG)
            if ended:
                wait_status = status
                break
            if time.monotonic() - started > 15:
                raise RuntimeError("owned loader probe exceeded the qualification deadline")
            if not select.select([listener], [], [], 0.05)[0]:
                continue
            note = Notification()
            if libc.ioctl(listener, 0xc0502100, ctypes.byref(note)):
                if ctypes.get_errno() in (errno.EINTR, errno.ENOENT):
                    continue
                raise OSError(ctypes.get_errno(), "SECCOMP_IOCTL_NOTIF_RECV")
            assert note.pid == pid and note.data.arch == 0xc000003e
            answer = Response(note.id, 0, 0, 1)
            nr, syscall_args = note.data.nr, note.data.args
            action = None
            if nr == 257:
                if args.kind == "token" and syscall_args[2] == 0xa0800:
                    action, armed = "open_token", True
                elif args.kind == "owner" and syscall_args[2] == 0x80000:
                    if 0x400000 <= note.data.ip < 0x500000:
                        action, armed = "open_owner", True
                    else:
                        # Only the declared child is inspected, and no inspected
                        # bytes are logged. Rust std may copy its literal path.
                        memory = os.open(f"/proc/{pid}/mem", os.O_RDONLY | os.O_CLOEXEC)
                        try:
                            literal = os.pread(memory, 32, int(syscall_args[1])).split(b"\0", 1)[0]
                        finally:
                            os.close(memory)
                        if literal == b"/dev/urandom":
                            action, armed = "open_owner", True
            elif nr == 107 and armed:
                action = "geteuid"
            elif nr in (0, 3, 5, 262, 332):
                fd = int(syscall_args[0])
                target = False
                try:
                    link = os.readlink(f"/proc/{pid}/fd/{fd}")
                    if args.kind == "owner":
                        target = link == "/dev/urandom"
                    else:
                        observed = os.stat(f"/proc/{pid}/fd/{fd}")
                        target = (observed.st_dev, observed.st_ino) == identity
                except (FileNotFoundError, PermissionError):
                    pass
                if target:
                    if nr == 0:
                        action = "read"
                        read_count += 1
                    elif nr == 3:
                        action = "close"
                    else:
                        action = "stat_after" if read_count else "stat_before"
            if action:
                event = {"syscall": nr, "action": action, "effect": "kernel_continue"}
                if nr in (0, 3, 5, 262, 332):
                    for line in Path(f"/proc/{pid}/fdinfo/{int(syscall_args[0])}").read_text().splitlines():
                        if line.startswith("pos:"):
                            event["descriptor_offset_before"] = int(line.split()[1])
                if nr == 257:
                    event["flags"] = int(syscall_args[2])
                if nr == 0:
                    event["requested_bytes"] = int(syscall_args[2])
                wanted = {
                    "open_eintr": ("open_token" if args.kind == "token" else "open_owner", errno.EINTR),
                    "read_eintr": ("read", errno.EINTR), "read_error": ("read", errno.EIO),
                    "stat_before_eintr": ("stat_before", errno.EINTR),
                    "stat_after_eintr": ("stat_after", errno.EINTR),
                    "stat_after_error": ("stat_after", errno.EIO),
                    "close_eintr": ("close", errno.EINTR), "close_error": ("close", errno.EIO)}.get(args.mode)
                if args.mode == "read_error_after_prefix" and read_count >= 2:
                    wanted = ("read", errno.EIO)
                if args.mode == "read_and_close_error":
                    wanted = ("read", errno.EIO)
                if args.mode == "stat_and_close_error":
                    wanted = ("stat_after", errno.EIO)
                if not fired and wanted and action == wanted[0]:
                    answer.error, answer.flags = -wanted[1], 0
                    event.update(effect="injected_errno", errno=wanted[1])
                    fired = True
                if fired and not secondary_fired and args.mode in ("read_and_close_error", "stat_and_close_error") and action == "close":
                    answer.error, answer.flags = -errno.EIO, 0
                    event.update(effect="injected_errno", errno=errno.EIO)
                    secondary_fired = True
                if not fired and args.mode == "read_zero" and action == "read":
                    answer.value, answer.flags = 0, 0
                    event["effect"] = "injected_zero_read"
                    fired = True
                if not fired and ((action == "read" and args.mode in ("rewrite", "replace_path"))
                    or (action == "close" and args.mode == "replace_after_stat")):
                    if args.mode == "rewrite":
                        args.fixture.write_bytes(b"Y" * 32)
                        os.utime(args.fixture, ns=(owned.st_atime_ns, owned.st_mtime_ns + 1000000000))
                    else:
                        args.fixture.rename(args.fixture.with_suffix(".retained"))
                        args.fixture.write_bytes(b"Y" * 32)
                        args.fixture.chmod(0o600)
                    event["effect"] = "owned_fixture_" + args.mode
                    fired = True
                if not fired and action == "stat_after" and args.mode in ("chmod", "hardlink"):
                    if args.mode == "chmod":
                        args.fixture.chmod(0o640)
                    else:
                        os.link(args.fixture, args.fixture.with_suffix(".second-link"))
                    event["effect"] = "owned_fixture_" + args.mode
                    fired = True
                events.append(event)
                if action == "close":
                    armed = False
            if libc.ioctl(listener, 0xc0182101, ctypes.byref(answer)) and ctypes.get_errno() != errno.ENOENT:
                raise OSError(ctypes.get_errno(), "SECCOMP_IOCTL_NOTIF_SEND")
    finally:
        if wait_status is None:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            _, wait_status = os.waitpid(pid, 0)
        if listener is not None:
            os.close(listener)
        parent.close()
        args.log.write_text(json.dumps({"schema": "hepta.runtime.authority-loader.kernel-trace.v1",
            "mode": args.mode, "kind": args.kind, "events": events, "fault_fired": fired,
            "secondary_fault_fired": secondary_fired,
            "exit_code": os.waitstatus_to_exitcode(wait_status), "owned_process_reaped": True,
            "executable_sha256": image_before, "executable_unchanged": hashlib.sha256(executable.read_bytes()).hexdigest() == image_before},
            sort_keys=True, separators=(",", ":")) + "\n")
    assert args.mode == "observe" or fired, "declared fixed boundary fault did not fire"
    assert args.mode not in ("read_and_close_error", "stat_and_close_error") or secondary_fired
    raise SystemExit(os.waitstatus_to_exitcode(wait_status))


if __name__ == "__main__":
    main()

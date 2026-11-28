#!/usr/bin/env python3
"""Fault controls for entropy syscalls of one directly forked owned ELF.

No external PID is accepted. Synthetic bytes are written only to the owned
child's currently notified buffer, bounded by its 128-byte RNG request.
"""
import argparse, array, ctypes, errno, hashlib, json, os, select, socket, struct, sys
from pathlib import Path
ROOT = Path(os.environ.get("HIA_REFERENCE_RUNTIME", Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(ROOT / "tests/hia_native"))
from io_fault_supervisor import Filter, Program, Notification, Response
MODES = ["observe", "eintr", "eio", "enosys", "eagain", "zero", "oversized", "partial", "partial_error",
         "probe_enosys", "probe_eperm", "probe_eintr", "probe_eio", "probe_eagain", "fallback_eintr",
         "fallback_open_error", "fallback_poll_error", "fallback_urandom_open_error",
         "fallback_read_error", "fallback_partial", "fallback_partial_error"]
class IoVec(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("length", ctypes.c_size_t)]
def device_for_fd(pid, fd):
    try:
        return os.readlink(f"/proc/{pid}/fd/{fd}")
    except FileNotFoundError:
        return None
def main_literal_addresses(pid, executable, raw, literal):
    elf_type = struct.unpack_from("<H", raw, 16)[0]
    bias = 0
    if elf_type == 3:
        mappings = []
        for line in Path(f"/proc/{pid}/maps").read_text().splitlines():
            fields = line.split()
            if len(fields) >= 6 and fields[-1] == str(executable):
                mappings.append(int(fields[0].split("-")[0], 16) - int(fields[2], 16))
        if not mappings:
            return set()
        bias = min(mappings)
    phoff = struct.unpack_from("<Q", raw, 32)[0]
    phsize, count = struct.unpack_from("<HH", raw, 54)
    addresses = set()
    at = raw.find(literal)
    while at >= 0:
        for index in range(count):
            kind, flags, offset, virtual, physical, size, memory, alignment = struct.unpack_from(
                "<IIQQQQQQ", raw, phoff + index * phsize)
            if kind == 1 and offset <= at and at + len(literal) <= offset + size:
                addresses.add(bias + virtual + at - offset)
        at = raw.find(literal, at + 1)
    return addresses
def apply_fault(libc, pid, mode, kind, call, address, size, response, event):
    error, count = None, None
    if kind == "probe":
        if mode.startswith("fallback_") or mode == "probe_enosys":
            error = errno.ENOSYS
        elif mode.startswith("probe_"):
            error = {"probe_eperm": errno.EPERM, "probe_eintr": errno.EINTR,
                     "probe_eio": errno.EIO, "probe_eagain": errno.EAGAIN}[mode]
    elif kind == "open_random":
        if call == 1 and mode == "fallback_eintr": error = errno.EINTR
        if call == 1 and mode == "fallback_open_error": error = errno.EACCES
    elif kind == "poll":
        if mode == "fallback_eintr" and call <= 2: error = errno.EINTR if call == 1 else errno.EAGAIN
        if mode == "fallback_poll_error" and call == 1: error = errno.EIO
    elif kind == "open_urandom":
        if mode == "fallback_eintr" and call == 1: error = errno.EINTR
        if mode == "fallback_urandom_open_error" and call == 1: error = errno.EACCES
    elif kind in ("getrandom", "read_urandom"):
        direct = kind == "getrandom"
        if direct and mode in ("eio", "enosys", "eagain"):
            error = {"eio": errno.EIO, "enosys": errno.ENOSYS, "eagain": errno.EAGAIN}[mode]
        elif call == 1 and mode in ("eintr", "fallback_eintr"):
            error = errno.EINTR
        elif call == 1 and mode == "fallback_read_error":
            error = errno.EIO
        elif mode in ("zero", "oversized"):
            response.value = 0 if mode == "zero" else size + 1
            response.flags = 0
            event.update(completion="injected_return", returned=response.value)
        elif mode in ("partial", "fallback_partial"):
            count = 1
        elif mode in ("partial_error", "fallback_partial_error"):
            if call == 1: count = min(5, size)
            elif call == 2: error = errno.EIO
    if error is not None:
        response.error, response.flags = -error, 0
        event.update(completion="injected_error", error=error)
    if count is not None:
        assert 1 <= count <= size <= 128
        synthetic = bytes([(call * 17) & 255]) * count
        owned = ctypes.create_string_buffer(synthetic)
        local, remote = IoVec(ctypes.addressof(owned), count), IoVec(address, count)
        written = libc.process_vm_writev(pid, ctypes.byref(local), 1, ctypes.byref(remote), 1, 0)
        if written != count:
            raise OSError(ctypes.get_errno(), "owned synthetic completion write failed")
        response.value, response.flags = count, 0
        event.update(completion="synthetic_partial_bytes", returned=count)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument("--mode", required=True, choices=MODES)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    assert len(command) == 1 and Path(command[0]).is_absolute()
    executable = Path(command[0]).resolve(strict=True)
    raw = executable.read_bytes()
    assert raw[:7] == b"\x7fELF\x02\x01\x01" and struct.unpack_from("<H", raw, 18)[0] == 62
    assert ctypes.sizeof(Notification) == 80 and ctypes.sizeof(Response) == 24
    libc = ctypes.CDLL(None, use_errno=True)
    libc.process_vm_writev.argtypes = [ctypes.c_int, ctypes.POINTER(IoVec), ctypes.c_ulong,
                                      ctypes.POINTER(IoVec), ctypes.c_ulong, ctypes.c_ulong]
    libc.process_vm_writev.restype = ctypes.c_ssize_t
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    pid = os.fork()
    if pid == 0:
        parent.close()
        try:
            if libc.prctl(38, 1, 0, 0, 0):
                raise OSError(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS")
            code = [Filter(0x20, 0, 0, 0)]
            for number in (0, 3, 7, 257, 318):
                code.extend((Filter(0x15, 0, 1, number), Filter(0x06, 0, 0, 0x7fc00000)))
            code.append(Filter(0x06, 0, 0, 0x7fff0000))
            filters = (Filter * len(code))(*code)
            program = Program(len(code), filters)
            listener = libc.syscall(317, 1, 8, ctypes.byref(program))
            if listener < 0:
                raise OSError(ctypes.get_errno(), "seccomp notification unavailable")
            os.set_inheritable(listener, False)
            child.sendmsg([b"L"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [listener]))])
            os.execve(str(executable), [str(executable)], dict(os.environ, PATH=""))
        except BaseException as error:
            os.write(2, (str(error) + "\n").encode())
            os._exit(76)
    child.close()
    if not select.select([parent], [], [], 5)[0]:
        os.kill(pid, 9)
        os.waitpid(pid, 0)
        raise RuntimeError("owned child could not install seccomp notification")
    _, ancillary, _, _ = parent.recvmsg(1, socket.CMSG_SPACE(4))
    parent.close()
    descriptors = array.array("i")
    descriptors.frombytes(ancillary[0][2][:4])
    listener = descriptors[0]
    events, counts, origin = [], {}, None
    wait_status = None
    try:
        while True:
            ended, status = os.waitpid(pid, os.WNOHANG)
            if ended:
                wait_status = status
                break
            if not select.select([listener], [], [], .1)[0]:
                continue
            note = Notification()
            if libc.ioctl(listener, 0xc0502100, ctypes.byref(note)):
                if ctypes.get_errno() in (errno.EINTR, errno.ENOENT):
                    continue
                raise OSError(ctypes.get_errno(), "SECCOMP_IOCTL_NOTIF_RECV")
            assert note.pid == pid
            response = Response(note.id, 0, 0, 1)
            kind, address, size = None, None, None
            number = int(note.data.nr)
            values = list(map(int, note.data.args))
            if number == 318 and values[2] == 0 and values[1] <= 128:
                address, size = values[:2]
                kind = "probe" if size == 0 else "getrandom"
            elif number == 257:
                for name in ("random", "urandom"):
                    if values[1] in main_literal_addresses(pid, executable, raw, ("/dev/" + name + "\0").encode()):
                        assert ctypes.c_int(values[0]).value == -100 and values[2] == 0x80000
                        kind = "open_" + name
            elif number == 7 and values[1] == 1 and ctypes.c_int(values[2]).value == -1:
                assert any(device_for_fd(pid, int(p.name)) == "/dev/random" for p in Path(f"/proc/{pid}/fd").iterdir())
                kind = "poll"
            elif number in (0, 3):
                device = device_for_fd(pid, values[0])
                if device in ("/dev/random", "/dev/urandom"):
                    if number == 0:
                        assert device == "/dev/urandom"
                        kind, address, size = "read_urandom", values[1], values[2]
                    else:
                        kind = "close_" + device.rsplit("/", 1)[1]
            if kind is not None:
                counts[kind] = counts.get(kind, 0) + 1
                event = {"kind": kind, "call": counts[kind], "completion": "kernel"}
                if kind == "read_urandom" or kind.startswith("close_"):
                    event["device_fd"] = values[0]
                if size is not None:
                    event["requested"] = size
                if size:
                    assert 1 <= size <= 128
                    if origin is None:
                        origin = address
                    assert origin <= address and address + size <= origin + 128
                    event["destination_delta"] = address - origin
                apply_fault(libc, pid, args.mode, kind, counts[kind], address, size, response, event)
                events.append(event)
            if libc.ioctl(listener, 0xc0182101, ctypes.byref(response)) and ctypes.get_errno() != errno.ENOENT:
                raise OSError(ctypes.get_errno(), "SECCOMP_IOCTL_NOTIF_SEND")
    finally:
        os.close(listener)
        if wait_status is None:
            os.kill(pid, 9)
            _, wait_status = os.waitpid(pid, 0)
        args.log.write_text(json.dumps({"events": events, "owned_child_reaped": True,
                                       "executable_sha256": hashlib.sha256(raw).hexdigest()}, sort_keys=True) + "\n")
    raise SystemExit(os.waitstatus_to_exitcode(wait_status))

if __name__ == "__main__":
    main()

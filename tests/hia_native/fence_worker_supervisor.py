#!/usr/bin/env python3
"""Observe and fault only a directly forked, manifest-pinned native fixture.

The sole code fault is UD2 at the fixed owner entry, after an observed owned
flock or directory-read completion. No external PID, address or bytes are
accepted. On the actual SIGILL stop the original instruction is restored;
the production handler receives the genuine kernel signal and si_code.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import signal
import struct

MASK = (1 << 64) - 1
WALL = 0x40000000
TRACEME, PEEK, POKE, SYSCALL = 0, 2, 5, 24
GETREGS, SETOPTIONS, GETEVENTMSG, GETSIGINFO, SYSCALL_INFO = 12, 0x4200, 0x4201, 0x4202, 0x420e
OPTIONS = 1 | 8 | 0x100000


class Registers(ctypes.Structure):
    _fields_ = [(name, ctypes.c_ulonglong) for name in (
        "r15 r14 r13 r12 rbp rbx r11 r10 r9 r8 rax rcx rdx rsi rdi orig_rax "
        "rip cs eflags rsp ss fs_base gs_base ds es fs gs").split()]


LIBC = ctypes.CDLL(None, use_errno=True)
LIBC.ptrace.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p]
LIBC.ptrace.restype = ctypes.c_long


def ptrace(request, pid, address=0, data=0):
    ctypes.set_errno(0)
    result = LIBC.ptrace(request, pid, address, data)
    error = ctypes.get_errno()
    if result == -1 and error:
        raise OSError(error, "owned ptrace operation failed")
    return result


def word(pid, address):
    return ptrace(PEEK, pid, address) & MASK


def registers(pid):
    value = Registers()
    ptrace(GETREGS, pid, 0, ctypes.byref(value))
    return value


def syscall_info(pid):
    data = ctypes.create_string_buffer(128)
    count = ptrace(SYSCALL_INFO, pid, len(data), ctypes.byref(data))
    if count < 24:
        raise AssertionError("kernel syscall observation unavailable")
    raw = data.raw
    op = raw[0]
    if op == 1:
        return op, struct.unpack_from("<7Q", raw, 24)
    if op == 2:
        return op, struct.unpack_from("<q", raw, 24)[0]
    raise AssertionError(("unexpected kernel syscall observation", op))


def blocked(pid):
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        if line.startswith("SigBlk:"):
            return int(line.split()[1], 16)
    raise AssertionError("owned signal mask missing")


def registry(pid, context):
    node, boundary = word(pid, context), word(pid, context + 760)
    owned, borrowed, seen = [], [], set()
    in_borrowed = False
    while node:
        if node in seen or len(seen) >= 1024:
            raise AssertionError("owned fixture descriptor chain differs")
        seen.add(node)
        if node == boundary:
            in_borrowed = True
        (borrowed if in_borrowed else owned).append(word(pid, node + 16))
        node = word(pid, node)
    if boundary and boundary not in seen:
        raise AssertionError("borrowed descriptor boundary missing")
    return owned, borrowed


def native_address(raw, offset):
    phoff, = struct.unpack_from("<Q", raw, 32)
    width, count = struct.unpack_from("<HH", raw, 54)
    found = []
    for index in range(count):
        kind, flags, start, virtual, _, size, _, _ = struct.unpack_from(
            "<IIQQQQQQ", raw, phoff + index * width)
        if kind == 1 and flags == 5 and start <= offset < start + size:
            found.append(virtual + offset - start)
    if len(found) != 1:
        raise AssertionError("fixed native image mapping differs")
    return found[0]


def retain_unannounced_stop(parent, tid, status, live, held):
    """Hold an early initial stop without reading or restarting its task."""
    assert os.WIFSTOPPED(status)
    if tid in live:
        return False
    assert tid > 0 and tid != parent and os.WSTOPSIG(status) == signal.SIGSTOP and status >> 16 == 0
    # This fixture only clones from its one parent, which cannot issue the
    # next clone while its current PTRACE_EVENT_CLONE stop remains pending.
    assert not held
    held[tid] = status
    return True


def confirm_owned_worker(parent, announcer, child, live, held):
    """Bind an initial stop only to the owned parent's GETEVENTMSG result."""
    assert announcer == parent and announcer in live and child > 0 and child not in live
    assert not held or set(held) == {child}
    live.add(child)
    return held.pop(child, None)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--mode", required=True, choices=("admission", "cache"))
    parser.add_argument("--block-sigill", action="store_true")
    parser.add_argument("--state-root", required=True, type=Path)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_bytes())
    executable = (args.manifest.parent / manifest["executable"]).resolve(strict=True)
    raw = executable.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == manifest["elf_sha256"]
    assert raw[:7] == b"\x7fELF\x02\x01\x01" and struct.unpack_from("<HH", raw, 16) == (2, 62)
    assert len(manifest["members"]) == 5 and manifest["worker_limit"] == 512
    for index, member in enumerate(manifest["members"]):
        assert member["id"] == index
        image = raw[member["offset"]:member["offset"] + member["image_bytes"]]
        assert len(image) == member["image_bytes"] and hashlib.sha256(image).hexdigest() == member["image_sha256"]
    owner = manifest["members"][0]
    address = native_address(raw, owner["offset"])
    expected_word = struct.unpack_from("<Q", raw, owner["offset"])[0]
    events, live, exits, pending, initial_masks = [], set(), {}, {}, {}
    injected = None
    restored = False
    retired_regions = set()
    pending_retirement = None
    failure = None
    held_stops, early_stops = {}, []
    pid = os.fork()
    if pid == 0:
        try:
            if args.block_sigill:
                signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGILL})
            ptrace(TRACEME, 0)
            os.execve(str(executable), [str(executable), "--state-root", str(args.state_root)],
                      dict(os.environ, PATH=""))
        except BaseException as error:
            os.write(2, (str(error) + "\n").encode())
            os._exit(76)
    live.add(pid)

    def initial_worker_stop(tid):
        assert tid in live and tid != pid and tid not in initial_masks
        initial_masks[tid] = blocked(tid)
        events.append({"kind": "initial_worker_mask", "tid": tid, "mask": initial_masks[tid]})

    try:
        got, status = os.waitpid(pid, 0)
        assert got == pid and os.WIFSTOPPED(status) and os.WSTOPSIG(status) == signal.SIGTRAP
        assert Path(f"/proc/{pid}/exe").resolve() == executable
        ptrace(SETOPTIONS, pid, 0, OPTIONS)
        ptrace(SYSCALL, pid)
        while live:
            tid, status = os.waitpid(-1, WALL)
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                assert tid in live and (tid != pid or not held_stops)
                live.remove(tid)
                exits[tid] = os.waitstatus_to_exitcode(status)
                events.append({"kind": "kernel_task_reaped", "tid": tid, "exit": exits[tid]})
                continue
            if retain_unannounced_stop(pid, tid, status, live, held_stops):
                continue
            sig, event = os.WSTOPSIG(status), status >> 16
            if event == 3:
                child = ctypes.c_ulonglong()
                ptrace(GETEVENTMSG, tid, 0, ctypes.byref(child))
                initial_status = confirm_owned_worker(pid, tid, child.value, live, held_stops)
                events.append({"kind": "kernel_clone", "tid": child.value})
                if initial_status is not None:
                    early_stops.append({"tid": child.value, "status": initial_status, "announced_by": tid})
                    initial_worker_stop(child.value)
                    ptrace(SYSCALL, child.value)
            elif sig == signal.SIGSTOP and tid != pid:
                initial_worker_stop(tid)
            elif sig == (signal.SIGTRAP | 0x80):
                op, value = syscall_info(tid)
                if op == 1:
                    pending[tid] = value
                    number, a0, a1, _, _, _, _ = value
                    if injected is not None and tid == injected["tid"] and number == 3:
                        assert a0 in injected["owned_fds"] and a0 not in injected["borrowed_fds"]
                        events.append({"kind": "fault_cleanup_close", "tid": tid, "fd": a0})
                    if injected is not None and tid == injected["tid"] and number == 60:
                        assert a0 == 0
                        events.append({"kind": "worker_sys_exit", "tid": tid, "status": a0})
                    if injected is not None and tid == pid and number == 11 and a0 not in retired_regions and a0 in (
                            injected["context"], injected["stack"]):
                        assert pending_retirement is None
                        assert word(tid, injected["job"] + 8) == injected["job_id"]
                        clear = word(tid, injected["job"] + 72) & 0xffffffff
                        assert clear == 0
                        assert a1 == (88088576 if a0 == injected["context"] else 1118208)
                        pending_retirement = {"kind": "retire_after_clear_tid", "tid": tid,
                            "region": "context" if a0 == injected["context"] else "stack",
                            "address": a0, "job_id": injected["job_id"],
                            "clear_tid": clear, "parent_mask": blocked(tid)}
                else:
                    entry = pending.pop(tid, None)
                    if tid == pid and pending_retirement is not None:
                        assert entry is not None and entry[0] == 11 and value == 0
                        pending_retirement["kernel_return"] = value
                        events.append(pending_retirement)
                        retired_regions.add(pending_retirement["address"])
                        pending_retirement = None
                    if entry is not None and tid != pid and injected is None:
                        number, a0, a1, _, _, _, _ = entry
                        selected = (args.mode == "admission" and number == 73 and a1 == 1 and value == 0
                                    or args.mode == "cache" and number == 217 and value > 0)
                        if selected:
                            regs = registers(tid)
                            context = regs.r15
                            assert regs.fs_base == context and word(tid, context + 744) == 1
                            assert word(tid, context + 776) == 1
                            held = word(tid, context + 728)
                            assert held == (1 if args.mode == "cache" else 0)
                            assert word(tid, address) == expected_word
                            owned, borrowed = registry(tid, context)
                            assert owned and (bool(borrowed) == (args.mode == "cache"))
                            job = word(tid, context + 752)
                            injected = {"tid": tid, "context": context, "job": job,
                                        "job_id": word(tid, job + 8),
                                        "stack": word(tid, job + 56), "owned_fds": owned,
                                        "borrowed_fds": borrowed, "cache_held": held,
                                        "initial_signal_mask": initial_masks[tid]}
                            ptrace(POKE, tid, address, (expected_word & ~0xffff) | 0x0b0f)
                            events.append({"kind": "armed_fixed_owner_ud2", "tid": tid,
                                           "trigger_syscall": number, "kernel_return": value,
                                           "owner_file_offset": owner["offset"], **injected})
            elif sig == signal.SIGILL:
                assert injected is not None and tid == injected["tid"] and not restored
                regs = registers(tid)
                assert regs.rip == address and word(tid, address) == ((expected_word & ~0xffff) | 0x0b0f)
                info = ctypes.create_string_buffer(128)
                ptrace(GETSIGINFO, tid, 0, ctypes.byref(info))
                signo, error, code = struct.unpack_from("<iii", info.raw)
                assert signo == 4 and error == 0 and code > 0 and blocked(tid) & 8 == 0
                if args.block_sigill:
                    assert injected["initial_signal_mask"] & 8
                ptrace(POKE, tid, address, expected_word)
                restored = True
                events.append({"kind": "actual_kernel_sigill", "tid": tid, "si_code": code,
                               "restored_original_instruction": True, "worker_signal_mask": blocked(tid)})
                ptrace(SYSCALL, tid, 0, sig)
                continue
            else:
                raise AssertionError(("unexpected owned ptrace stop", tid, sig, event))
            ptrace(SYSCALL, tid)
        assert not held_stops and exits[pid] == 0 and all(code == 0 for code in exits.values())
        assert injected is not None and restored
        cleanup = [e["fd"] for e in events if e["kind"] == "fault_cleanup_close"]
        assert sorted(cleanup) == sorted(injected["owned_fds"])
        retirement = [e for e in events if e["kind"] == "retire_after_clear_tid"]
        assert sorted(e["region"] for e in retirement) == ["context", "stack"]
        if args.block_sigill:
            assert all(e["parent_mask"] & 8 for e in retirement)
        assert sum(e["kind"] == "worker_sys_exit" for e in events) == 1
    except BaseException as error:
        failure = repr(error)
        raise
    finally:
        if live or held_stops:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            while live or held_stops:
                tid, status = os.waitpid(-1, WALL)
                if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                    live.discard(tid)
                    held_stops.pop(tid, None)
                    exits[tid] = os.waitstatus_to_exitcode(status)
                elif os.WIFSTOPPED(status) and tid in live:
                    ptrace(SYSCALL, tid, 0, signal.SIGKILL)
        report = {"schema": "hepta.effect-fence.actual-worker-fault.v1",
                  "status": "PASS" if failure is None else "FAIL", "failure": failure,
                  "mode": args.mode, "inherited_blocked_sigill": args.block_sigill,
                  "executable_sha256": hashlib.sha256(raw).hexdigest(),
                  "manifest_sha256": hashlib.sha256(args.manifest.read_bytes()).hexdigest(),
                  "supervisor_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  "owned_parent": pid, "all_owned_tasks_reaped": not live and not held_stops,
                  "exit_statuses": exits, "events": events,
                  "initial_stops_before_clone": early_stops,
                  "fault_is_synthetic": True, "kernel_sigill_is_actual": restored,
                  "complete_effect_fence_owner": False}
        args.report.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    main()

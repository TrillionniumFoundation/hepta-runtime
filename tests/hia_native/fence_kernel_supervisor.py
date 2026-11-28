#!/usr/bin/env python3
"""Paired original/native controls confined to one owned fixture and child.

Filesystem races mutate only the prevalidated private fixture. Syscall errors
are identified in the trace as injected; ordinary IO and the scan clock remain
real kernel operations. No external PID or arbitrary fault address is accepted.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fence_worker_supervisor import ptrace, registers, syscall_info, word, WALL, TRACEME, SYSCALL, SETOPTIONS, GETEVENTMSG, OPTIONS, MASK
import ctypes

CASES = ("owner_replace", "owner_touch", "lock_replace", "authority_rebind", "state_rebind",
         "root_eintr", "owner_open_eintr", "lock_eintr", "owner_read_eintr", "owner_partial",
         "owner_partial_eio", "owner_close_eio", "job_replace", "job_touch", "jobs_changed",
         "predecessor_rebind", "scan_deadline", "job_read_eintr", "job_partial_eio")


def cstring(pid, address):
    value = bytearray()
    for offset in range(0, 4096, 8):
        chunk = word(pid, address + offset).to_bytes(8, "little")
        if 0 in chunk:
            value.extend(chunk[:chunk.index(0)])
            return bytes(value)
        value.extend(chunk)
    raise AssertionError("fixture pathname exceeds observation bound")


def fd_name(pid, descriptor):
    try:
        return os.readlink(f"/proc/{pid}/fd/{descriptor}")
    except FileNotFoundError:
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--case", required=True, choices=CASES)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--state-root", required=True, type=Path)
    args = parser.parse_args()
    executable = args.binary.resolve(strict=True)
    raw = executable.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == args.sha256
    fixture = args.fixture.resolve(strict=True)
    assert fixture.name.startswith("hia-effect-owner-") and args.state_root == fixture / "state"
    for path in (fixture, fixture / "authority", fixture / "state", fixture / "prior"):
        info = path.lstat()
        assert stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and info.st_mode & 0o777 == 0o700
    events, pending, live, exits = [], {}, set(), {}
    fault_count, partial_done, failure = 0, False, None
    pid = os.fork()
    if pid == 0:
        try:
            ptrace(TRACEME, 0)
            os.execve(str(executable), [str(executable), "--state-root", str(args.state_root)],
                      dict(os.environ, PATH=""))
        except BaseException as error:
            os.write(2, (str(error) + "\n").encode())
            os._exit(76)
    live.add(pid)

    def mutate():
        case = args.case
        owner = fixture / "authority/.owner.json"
        job = fixture / "prior/jobs/one.json"
        if case in ("owner_replace", "job_replace", "lock_replace"):
            target = {"owner_replace": owner, "job_replace": job,
                      "lock_replace": fixture / "authority/.owner.lock"}[case]
            replacement = target.with_name(target.name + ".owned-replacement")
            descriptor = os.open(replacement, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as out:
                out.write(target.read_bytes())
            replacement.replace(target)
        elif case in ("owner_touch", "job_touch"):
            target = owner if case == "owner_touch" else job
            info = target.stat()
            os.utime(target, ns=(info.st_atime_ns, info.st_mtime_ns + 1000000000))
        elif case in ("authority_rebind", "state_rebind", "predecessor_rebind"):
            name = {"authority_rebind": "authority", "state_rebind": "state", "predecessor_rebind": "prior"}[case]
            target = fixture / name
            old = fixture / (name + ".retained")
            target.rename(old)
            target.mkdir(mode=0o700)
            if name == "authority":
                for leaf in (".owner.lock", ".owner.json"):
                    shutil.copyfile(old / leaf, target / leaf)
                    (target / leaf).chmod(0o600)
        elif case == "jobs_changed":
            path = fixture / "prior/jobs/added.json"
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as out:
                out.write(b'{"id":"added","host":"local","idempotency_key":null}')
        else:
            raise AssertionError("unexpected owned mutation")

    try:
        got, status = os.waitpid(pid, 0)
        assert got == pid and os.WIFSTOPPED(status) and os.WSTOPSIG(status) == signal.SIGTRAP
        assert Path(f"/proc/{pid}/exe").resolve() == executable
        ptrace(SETOPTIONS, pid, 0, OPTIONS)
        ptrace(SYSCALL, pid)
        while live:
            tid, status = os.waitpid(-1, WALL)
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                assert tid in live
                live.remove(tid)
                exits[tid] = os.waitstatus_to_exitcode(status)
                continue
            assert os.WIFSTOPPED(status) and tid in live
            sig, event = os.WSTOPSIG(status), status >> 16
            if event == 3:
                child = ctypes.c_ulonglong()
                ptrace(GETEVENTMSG, tid, 0, ctypes.byref(child))
                assert child.value not in live
                live.add(child.value)
            elif sig == signal.SIGSTOP and tid != pid:
                pass
            elif sig == (signal.SIGTRAP | 0x80):
                op, value = syscall_info(tid)
                if op == 1:
                    number, a0, a1, a2, _, _, _ = value
                    label = fd_name(pid, a0) if number in (0, 3, 73, 217) else None
                    owner_read = number == 0 and label == str(fixture / "authority/.owner.json")
                    job_read = number == 0 and label == str(fixture / "prior/jobs/one.json")
                    item = {"number": number, "label": label, "owner_read": owner_read, "job_read": job_read}
                    mode = args.case
                    error = None
                    if fault_count == 0:
                        if mode == "root_eintr" and number == 257 and cstring(tid, a1) == b"/":
                            error = 4
                        elif mode == "owner_open_eintr" and number == 257 and cstring(tid, a1) == b".owner.json":
                            error = 4
                        elif mode == "lock_eintr" and number == 73 and a1 == 1 and label == str(fixture / "authority/.owner.lock"):
                            error = 4
                        elif (mode == "owner_read_eintr" and owner_read) or (mode == "job_read_eintr" and job_read):
                            error = 4
                        partial_case = (mode in ("owner_partial", "owner_partial_eio") and owner_read
                                        or mode == "job_partial_eio" and job_read)
                        if partial_case and not partial_done:
                            regs = registers(tid)
                            assert regs.rdx > 1
                            regs.rdx = 1
                            ptrace(13, tid, 0, ctypes.byref(regs))
                            item["partial"] = True
                            partial_done = True
                        elif partial_case and partial_done and mode.endswith("_eio"):
                            error = 5
                    if error is not None:
                        regs = registers(tid)
                        regs.orig_rax = MASK
                        ptrace(13, tid, 0, ctypes.byref(regs))
                        item["inject_error"] = error
                    if mode == "owner_close_eio" and fault_count == 0 and number == 3 and label == str(fixture / "authority/.owner.json"):
                        item["after_close_error"] = 5
                    pending[tid] = item
                else:
                    item = pending.pop(tid, None)
                    if item is not None:
                        if "inject_error" in item:
                            assert value == -38
                            regs = registers(tid)
                            regs.rax = (-item["inject_error"]) & MASK
                            ptrace(13, tid, 0, ctypes.byref(regs))
                            fault_count += 1
                            events.append({"kind": "injected_errno", "tid": tid,
                                           "syscall": item["number"], "errno": item["inject_error"]})
                        elif "after_close_error" in item:
                            assert value == 0
                            regs = registers(tid)
                            regs.rax = (-item["after_close_error"]) & MASK
                            ptrace(13, tid, 0, ctypes.byref(regs))
                            fault_count += 1
                            events.append({"kind": "actual_close_then_injected_errno", "tid": tid, "errno": 5,
                                           "kernel_return": value})
                        elif item.get("partial"):
                            assert value == 1
                            events.append({"kind": "actual_kernel_partial_read", "tid": tid, "bytes": value})
                            if args.case == "owner_partial":
                                fault_count += 1
                        elif fault_count == 0 and value > 0:
                            owner_race = item["owner_read"] and args.case in (
                                "owner_replace", "owner_touch", "lock_replace", "authority_rebind", "state_rebind")
                            job_race = item["job_read"] and args.case in (
                                "job_replace", "job_touch", "jobs_changed", "predecessor_rebind")
                            if owner_race or job_race:
                                mutate()
                                fault_count += 1
                                events.append({"kind": "actual_fixture_mutation_after_read", "tid": tid,
                                               "mutation": args.case, "kernel_read_bytes": value})
                            elif args.case == "scan_deadline" and item["number"] == 217 and item["label"] == str(fixture / "prior/jobs"):
                                started = time.monotonic()
                                time.sleep(30.05)
                                elapsed = time.monotonic() - started
                                assert elapsed >= 30.05
                                fault_count += 1
                                events.append({"kind": "actual_monotonic_scan_elapsed", "tid": tid,
                                               "paused_seconds": elapsed, "original_bound_seconds": 30,
                                               "clock_was_not_modified": True})
            else:
                raise AssertionError(("unexpected original/native stop", tid, sig, event))
            ptrace(SYSCALL, tid)
        assert fault_count == 1 and exits[pid] == 0 and all(code == 0 for code in exits.values())
        if args.case.endswith("_partial_eio"):
            assert sum(e["kind"] == "actual_kernel_partial_read" for e in events) == 1
    except BaseException as error:
        failure = repr(error)
        raise
    finally:
        if live:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            while live:
                tid, status = os.waitpid(-1, WALL)
                if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                    live.discard(tid)
                    exits[tid] = os.waitstatus_to_exitcode(status)
                elif os.WIFSTOPPED(status):
                    ptrace(SYSCALL, tid, 0, signal.SIGKILL)
        report = {"schema": "hepta.effect-fence.paired-kernel-control.v1",
                  "status": "PASS" if failure is None else "FAIL", "failure": failure,
                  "case": args.case, "executable_sha256": hashlib.sha256(raw).hexdigest(),
                  "supervisor_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  "parent_pid": pid, "all_owned_tasks_reaped": not live,
                  "exit_statuses": exits, "events": events, "fault_count": fault_count,
                  "complete_effect_fence_owner": False}
        args.report.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    main()

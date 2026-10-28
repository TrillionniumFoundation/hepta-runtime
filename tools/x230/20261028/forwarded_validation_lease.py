#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Hold one forwarded-agent validation lease over one existing trusted SSH route.

main creates one SSH client to x230-ts; remote creates one source-pinned native
runner. A nonce and strictly consecutive heartbeat sequence bind the lease to
that stream. EOF, HUP, TERM, missing heartbeats or the active deadline revoke it.
The wrapper never reconnects, retries a launch, signals an enumerated PID, or
modifies SSH trust, credentials, services, other tasks or previous evidence.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import select
import shlex
import signal
import stat
import subprocess
import sys
import time


HEARTBEAT_SECONDS = 10
HEARTBEAT_TIMEOUT = 35
MAIN_ACTIVE_SECONDS = 3600
REMOTE_ACTIVE_SECONDS = 3300
RUNNER_TERM_GRACE = 90
SSH_EOF_GRACE = 150
FORCED_REAP_GRACE = 10
STOP_SIGNALS = []


def parent_death_signal(parent_pid):
    """Called in this wrapper's single-threaded fork child before exec."""
    # A hard wrapper death should revoke its SSH/runner child as well. Restore
    # SIGTERM's default before exec so a pre-exec death cannot be swallowed by
    # this wrapper's inherited Python cancellation handler.
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    libc.prctl.restype = ctypes.c_int
    if libc.prctl(1, signal.SIGTERM, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_PDEATHSIG failed")
    if os.getppid() != parent_pid:
        os.kill(os.getpid(), signal.SIGTERM)

# The SSH command verifies and executes the exact uploaded wrapper bytes, rather
# than trusting a subsequent path reopen for Python code loading. No secret or
# authentication material is embedded in the bootstrap or arguments.
BOOTSTRAP = r'''import hashlib,os,stat,sys
p,expected=sys.argv[1:3]
fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
try:
 m=os.fstat(fd)
 assert stat.S_ISREG(m.st_mode) and m.st_uid==os.geteuid() and m.st_nlink==1 and not m.st_mode&0o022 and m.st_size<=1048576
 chunks=[]
 while True:
  b=os.read(fd,65536)
  if not b:break
  chunks.append(b)
 raw=b''.join(chunks)
 n=os.fstat(fd)
 assert (m.st_dev,m.st_ino,m.st_size,m.st_mtime_ns,m.st_ctime_ns)==(n.st_dev,n.st_ino,n.st_size,n.st_mtime_ns,n.st_ctime_ns)
 assert len(raw)==m.st_size and hashlib.sha256(raw).hexdigest()==expected
finally:os.close(fd)
sys.argv=[p]+sys.argv[3:]
exec(compile(raw,p,'exec'),{'__name__':'__main__','__file__':p})
'''


def need(condition, message):
    if not condition:
        raise RuntimeError(message)


def utc():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def stamp(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def direct(path, exists=True):
    path = Path(path)
    need(path.is_absolute() and ".." not in path.parts and path.resolve(strict=exists) == path,
         "direct absolute path required: " + str(path))
    if not exists:
        need(path.parent.is_dir() and not os.path.lexists(path), "fresh path required: " + str(path))
    return path


def file_receipt(path, maximum=None, contents=False, sync=False):
    path = direct(path)
    fd = os.open(path, (os.O_RDWR if sync else os.O_RDONLY) | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
             and before.st_nlink == 1 and not before.st_mode & 0o022,
             "file must be owned, regular, singly linked and not group/world writable: " + str(path))
        need(maximum is None or before.st_size <= maximum, "file exceeds read bound")
        if sync:
            os.fsync(fd)
        digest, size, chunks = hashlib.sha256(), 0, []
        while True:
            block = os.read(fd, 65536)
            if not block:
                break
            size += len(block)
            need(maximum is None or size <= maximum, "file grew beyond read bound")
            digest.update(block)
            if contents:
                chunks.append(block)
        need(size == before.st_size and stamp(before) == stamp(os.fstat(fd)) == stamp(path.lstat()),
             "file changed during receipt")
        receipt = {"path": str(path), "sha256": digest.hexdigest(), "bytes": size, "identity": stamp(before)}
        return (receipt, b"".join(chunks)) if contents else receipt
    finally:
        os.close(fd)


def create(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def save(path, value):
    temporary = path.with_name(path.name + ".next")
    create(temporary, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode())
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def emit(value):
    try:
        print(json.dumps(value, sort_keys=True), flush=True)
    except (BrokenPipeError, OSError):
        # Authoritative evidence is the private durable report. Losing SSH stdout
        # cannot interrupt the cleanup path or fabricate a remote completion.
        pass


def agent_identity():
    path = Path(os.environ.get("SSH_AUTH_SOCK", ""))
    need(path.is_absolute(), "current SSH_AUTH_SOCK is required")
    info = path.lstat()
    need(stat.S_ISSOCK(info.st_mode) and info.st_uid == os.geteuid(), "current agent must be an owned direct socket")
    return {"path": str(path), "identity": stamp(info)}


def native_output(arguments):
    required = {"--qualification", "--qualification-sha256", "--test-audit", "--test-audit-sha256", "--out", "--socket-parent"}
    need(not any(x in ("-h", "--help") for x in arguments), "help is not a validation run")
    for option in required:
        need(arguments.count(option) == 1, "native runner requires exactly one " + option)
        index = arguments.index(option)
        need(index + 1 < len(arguments) and not arguments[index + 1].startswith("--"), "missing value for " + option)
    return direct(Path(arguments[arguments.index("--out") + 1]), exists=False)


class Heartbeats:
    def __init__(self, nonce):
        self.nonce, self.buffer, self.sequence = nonce, b"", -1
        self.last_received = None

    def consume(self, data, now):
        need(data, "heartbeat stream EOF")
        self.buffer += data
        need(len(self.buffer) <= 8192, "heartbeat buffer exceeds bound")
        accepted = []
        while b"\n" in self.buffer:
            line, self.buffer = self.buffer.split(b"\n", 1)
            need(0 < len(line) <= 1024, "invalid heartbeat line length")
            value = json.loads(line)
            need(isinstance(value, dict) and set(value) == {"nonce", "sequence"}
                 and value["nonce"] == self.nonce and type(value["sequence"]) is int
                 and value["sequence"] == self.sequence + 1, "heartbeat identity or sequence differs")
            self.sequence = value["sequence"]
            self.last_received = now
            accepted.append({"sequence": self.sequence, "received_monotonic": now})
        return accepted


class OwnedChild:
    """Only this object's actual waitpid may reap its original direct child."""
    def __init__(self, argv, row, **kwargs):
        self.row, self.pidfd, self.custody = row, None, True
        parent_pid = os.getpid()
        self.process = subprocess.Popen(argv, start_new_session=True,
                                        preexec_fn=lambda: parent_death_signal(parent_pid), **kwargs)
        row.update(pid=self.process.pid, launched=True, original_child_reaped=False, signals=[], argv=argv,
                   parent_death_signal="SIGTERM", parent_pid=parent_pid)
        try:
            self.pidfd = os.pidfd_open(self.process.pid, 0)
            row["pidfd_opened"] = True
        except BaseException as error:
            row["pidfd_error"] = type(error).__name__ + ": " + str(error)
            self.terminate(1)
            raise

    def reap(self):
        if self.row["original_child_reaped"]:
            return True
        try:
            observed = os.waitid(os.P_PID, self.process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if observed is None:
                return False
            need(observed.si_pid == self.process.pid, "waitid returned another child")
            waited, status = os.waitpid(self.process.pid, os.WNOHANG)
            need(waited == self.process.pid, "waitpid did not reap the original child")
            self.process.returncode = os.waitstatus_to_exitcode(status)
            self.row.update(original_child_reaped=True, actual_waitpid=waited, raw_wait_status=status,
                            returncode=self.process.returncode)
            return True
        except ChildProcessError as error:
            self.custody = False
            self.row["custody_error"] = str(error)
            raise RuntimeError("original child custody lost; no signal is authorized") from error

    def send(self, signum):
        if self.reap():
            return
        need(self.custody, "original child custody unavailable")
        if self.pidfd is not None:
            signal.pidfd_send_signal(self.pidfd, signum)
            target = "original_child_pidfd"
        else:
            # pidfd_open failed after Popen. This unreaped direct child has no
            # other reaper; never use this fallback after ECHILD or any reap.
            os.kill(self.process.pid, signum)
            target = "original_unreaped_child"
        self.row["signals"].append({"signal": signal.Signals(signum).name, "target": target, "monotonic": time.monotonic()})

    def wait_for(self, seconds):
        until = time.monotonic() + seconds
        while not self.reap():
            if time.monotonic() >= until:
                return False
            time.sleep(0.1)
        return True

    def terminate(self, grace):
        if self.reap():
            return
        self.send(signal.SIGTERM)
        if not self.wait_for(grace):
            self.send(signal.SIGKILL)
            need(self.wait_for(FORCED_REAP_GRACE), "original child not reaped after forced cleanup")

    def close(self):
        self.row["custody_retained_until_reap"] = self.custody and self.row.get("original_child_reaped", False)
        if self.pidfd is not None:
            os.close(self.pidfd)
            self.pidfd = None


def prepare(args, role):
    need(sys.platform == "linux" and hasattr(os, "pidfd_open") and hasattr(os, "WNOWAIT")
         and hasattr(signal, "pidfd_send_signal"), "Linux original-child custody primitives required")
    os.umask(0o077)
    args.out = direct(args.out, exists=False)
    args.out.mkdir(mode=0o700)
    row = {"schema": "hepta-forwarded-validation-" + role + "-lease/v1", "passed": False,
           "started_utc": utc(), "role": role, "launch_attempts": 0, "automatic_retries": 0,
           "production_services_changed": False, "phase": "preflight", "child": {},
           "cleanup_scope": "owned unreaped direct child; native runner owns its stage helper cleanup; no broad PID or process-group scan"}
    save(args.out / "report.json", row)
    return row


def remote(args):
    report = prepare(args, "remote")
    path = args.out / "report.json"
    child = None
    started = time.monotonic()
    try:
        need(re.fullmatch(r"[0-9a-f]{32}", args.nonce) is not None, "invalid lease nonce")
        report["nonce"] = args.nonce
        wrapper = file_receipt(Path(__file__).absolute(), 1048576)
        need(wrapper["sha256"] == args.self_sha256, "remote wrapper SHA differs")
        runner = file_receipt(args.runner, 1048576)
        need(runner["sha256"] == args.runner_sha256, "native runner SHA differs")
        output = native_output(args.runner_args)
        need(output != args.out and not output.is_relative_to(args.out), "native output must be separate from lease evidence")
        agent = agent_identity()
        report.update(wrapper=wrapper, runner=runner, native_output=str(output), agent=agent,
                      active_budget_seconds=REMOTE_ACTIVE_SECONDS, heartbeat_timeout_seconds=HEARTBEAT_TIMEOUT,
                      cleanup_grace_seconds=RUNNER_TERM_GRACE, phase="waiting_for_first_heartbeat")
        save(path, report)
        lease = Heartbeats(args.nonce)
        stdin = sys.stdin.fileno()
        with (args.out / "heartbeats.jsonl").open("xb") as journal:
            def receive(timeout):
                if select.select([stdin], [], [], timeout)[0]:
                    rows = lease.consume(os.read(stdin, 4096), time.monotonic())
                    for row in rows:
                        journal.write((json.dumps(row) + "\n").encode())
                    journal.flush()
            while lease.last_received is None:
                need(not STOP_SIGNALS, "signal revoked lease before admission")
                need(time.monotonic() - started < HEARTBEAT_TIMEOUT, "initial heartbeat deadline expired")
                receive(0.2)
            report["phase"] = "admitted"
            report["admitted_sequence"] = lease.sequence
            report["admitted_utc"] = utc()
            save(args.out / "admission.json", report)
            save(path, report)
            emit({"event": "lease_admitted", "nonce": args.nonce, "out": str(args.out), "runner_sha256": args.runner_sha256})
            with (args.out / "runner.stdout").open("xb") as stdout, (args.out / "runner.stderr").open("xb") as stderr:
                receive(0)
                need(not STOP_SIGNALS and time.monotonic() - lease.last_received < HEARTBEAT_TIMEOUT, "lease expired before launch")
                need(file_receipt(args.runner, 1048576)["sha256"] == args.runner_sha256, "native runner changed before launch")
                report.update(phase="launch_intent", launch_attempts=1)
                save(path, report)
                child = OwnedChild(["/usr/bin/python3", "-I", "-B", str(args.runner), *args.runner_args], report["child"],
                                   cwd=args.out, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, env=dict(os.environ))
                report["phase"] = "running"
                save(path, report)
                while True:
                    need(not STOP_SIGNALS, "signal revoked remote lease")
                    now = time.monotonic()
                    need(now - started < REMOTE_ACTIVE_SECONDS, "remote absolute active deadline expired")
                    need(now - lease.last_received < HEARTBEAT_TIMEOUT, "heartbeat lease expired")
                    need(agent_identity() == agent, "forwarded agent identity changed")
                    if child.reap():
                        break
                    receive(0.2)
                need(report["child"]["returncode"] == 0, "native runner failed")
                native_receipt, raw = file_receipt(output / "report.json", 64 * 1024 * 1024, contents=True)
                value = json.loads(raw)
                need(value.get("schema") == "hepta-x230-composed-native-validation/v1"
                     and value.get("passed") is True and value.get("complete") is True
                     and not value.get("error"), "native validation report is not complete and successful")
                report["native_report"] = native_receipt
                need(file_receipt(args.runner, 1048576)["sha256"] == args.runner_sha256
                     and file_receipt(Path(__file__).absolute(), 1048576)["sha256"] == args.self_sha256,
                     "wrapper or native runner changed")
                report.update(passed=True, phase="complete", last_heartbeat_sequence=lease.sequence)
                stdout.flush()
                stderr.flush()
                os.fsync(stdout.fileno())
                os.fsync(stderr.fileno())
            os.fsync(journal.fileno())
    except BaseException as error:
        report.update(passed=False, phase="failed", error=type(error).__name__ + ": " + str(error))
    finally:
        if child is not None:
            try:
                if not child.reap():
                    report["phase"] = "revoking"
                    save(path, report)
                    child.terminate(RUNNER_TERM_GRACE)
            except BaseException as error:
                report.update(passed=False, cleanup_error=type(error).__name__ + ": " + str(error))
            child.close()
        report.update(finished_utc=utc(), elapsed_seconds=time.monotonic() - started,
                      stop_signals=list(STOP_SIGNALS), phase="complete" if report["passed"] else "failed")
        for name in ("runner.stdout", "runner.stderr", "heartbeats.jsonl"):
            if (args.out / name).exists():
                try:
                    report[name.replace(".", "_")] = file_receipt(args.out / name, sync=True)
                except Exception as error:
                    report.update(passed=False, evidence_error=str(error))
        report["phase"] = "complete" if report["passed"] else "failed"
        save(path, report)
        emit({"event": "lease_completed", "nonce": args.nonce, "out": str(args.out), "passed": report["passed"],
              "runner_sha256": args.runner_sha256, "report_sha256": file_receipt(path)["sha256"],
              "error": report.get("error"), "original_child_reaped": report["child"].get("original_child_reaped", False)})
    return 0 if report["passed"] else 1


def main_side(args):
    report = prepare(args, "main")
    path = args.out / "report.json"
    started, child = time.monotonic(), None
    nonce = secrets.token_hex(16)
    report["nonce"] = nonce
    try:
        wrapper = file_receipt(Path(__file__).absolute(), 1048576)
        need(re.fullmatch(r"[0-9a-f]{64}", args.runner_sha256) is not None, "invalid runner SHA")
        for remote_path in (args.remote_script, args.runner, args.remote_out):
            need(remote_path.is_absolute() and ".." not in remote_path.parts, "absolute remote path required")
        need(args.runner_args, "native runner arguments required")
        agent = agent_identity()
        remote_args = ["remote", "--self-sha256", wrapper["sha256"], "--nonce", nonce,
                       "--runner", str(args.runner), "--runner-sha256", args.runner_sha256,
                       "--out", str(args.remote_out), "--", *args.runner_args]
        remote_command = shlex.join(["/usr/bin/python3", "-I", "-S", "-c", BOOTSTRAP,
                                     str(args.remote_script), wrapper["sha256"], *remote_args])
        argv = ["/usr/bin/ssh", "-A", "-T", "-oBatchMode=yes", "-oStrictHostKeyChecking=yes",
                "-oControlMaster=no", "-oControlPath=none", "-oControlPersist=no", "-oForwardX11=no",
                "-oConnectTimeout=8", "-oConnectionAttempts=1", "-oServerAliveInterval=10", "-oServerAliveCountMax=3",
                "-oLocalCommand=none", "-oPermitLocalCommand=no", "-oIdentityAgent=" + agent["path"],
                "x230-ts", remote_command]
        report.update(wrapper=wrapper, runner_sha256=args.runner_sha256, remote_out=str(args.remote_out), agent=agent,
                      active_budget_seconds=MAIN_ACTIVE_SECONDS, remote_active_budget_seconds=REMOTE_ACTIVE_SECONDS,
                      heartbeat_seconds=HEARTBEAT_SECONDS, ssh_eof_cleanup_grace_seconds=SSH_EOF_GRACE,
                      phase="launch_intent", launch_attempts=1)
        save(args.out / "admission.json", report)
        save(path, report)
        with (args.out / "ssh.stdout").open("xb") as stdout, (args.out / "ssh.stderr").open("xb") as stderr:
            child = OwnedChild(argv, report["child"], cwd=args.out, stdin=subprocess.PIPE,
                               stdout=stdout, stderr=stderr, env=dict(os.environ))
            os.set_blocking(child.process.stdin.fileno(), False)
            report["phase"] = "running"
            save(path, report)
            sequence, next_heartbeat = 0, time.monotonic()
            with (args.out / "heartbeats.jsonl").open("xb") as journal:
                while True:
                    need(not STOP_SIGNALS, "signal revoked main lease")
                    now = time.monotonic()
                    need(now - started < MAIN_ACTIVE_SECONDS, "main absolute active deadline expired")
                    need(agent_identity() == agent, "main agent identity changed")
                    if child.reap():
                        break
                    if now >= next_heartbeat:
                        heartbeat = (json.dumps({"nonce": nonce, "sequence": sequence}, separators=(",", ":")) + "\n").encode()
                        need(os.write(child.process.stdin.fileno(), heartbeat) == len(heartbeat), "partial heartbeat write")
                        journal.write((json.dumps({"sequence": sequence, "sent_monotonic": now}) + "\n").encode())
                        journal.flush()
                        sequence += 1
                        next_heartbeat = now + HEARTBEAT_SECONDS
                    time.sleep(0.1)
                os.fsync(journal.fileno())
            need(report["child"]["returncode"] == 0, "SSH or remote lease failed")
            stdout.flush()
            stderr.flush()
            os.fsync(stdout.fileno())
            os.fsync(stderr.fileno())
        _, raw = file_receipt(args.out / "ssh.stdout", 1048576, contents=True)
        messages = [json.loads(line) for line in raw.splitlines() if line.strip()]
        need(len(messages) == 2 and messages[0].get("event") == "lease_admitted", "missing/ambiguous remote admission")
        completion = messages[-1]
        need(all(item.get("nonce") == nonce and item.get("out") == str(args.remote_out)
                 and item.get("runner_sha256") == args.runner_sha256 for item in messages)
             and completion.get("event") == "lease_completed" and completion.get("passed") is True
             and completion.get("original_child_reaped") is True
             and re.fullmatch(r"[0-9a-f]{64}", completion.get("report_sha256", "")) is not None,
             "remote completion is absent, failed or belongs to another lease")
        need(file_receipt(Path(__file__).absolute(), 1048576)["sha256"] == wrapper["sha256"], "main wrapper changed")
        report.update(passed=True, phase="complete", remote_completion=completion, heartbeats_sent=sequence)
    except BaseException as error:
        report.update(passed=False, phase="failed", error=type(error).__name__ + ": " + str(error))
    finally:
        if child is not None:
            try:
                # Closing this stream revokes the original remote lease. Allow
                # its EOF/heartbeat detection plus owned-runner cleanup before
                # terminating this original SSH client if the channel remains.
                if child.process.stdin is not None and not child.process.stdin.closed:
                    child.process.stdin.close()
                if not child.reap():
                    report["phase"] = "revoking"
                    save(path, report)
                    if not child.wait_for(SSH_EOF_GRACE):
                        child.terminate(FORCED_REAP_GRACE)
            except BaseException as error:
                report.update(passed=False, cleanup_error=type(error).__name__ + ": " + str(error))
            child.close()
        report.update(finished_utc=utc(), elapsed_seconds=time.monotonic() - started,
                      stop_signals=list(STOP_SIGNALS), phase="complete" if report["passed"] else "failed")
        for name in ("ssh.stdout", "ssh.stderr", "heartbeats.jsonl"):
            if (args.out / name).exists():
                try:
                    report[name.replace(".", "_")] = file_receipt(args.out / name, sync=True)
                except Exception as error:
                    report.update(passed=False, evidence_error=str(error))
        report["phase"] = "complete" if report["passed"] else "failed"
        save(path, report)
        emit({"report": str(path), "passed": report["passed"], "nonce": nonce, "error": report.get("error")})
    return 0 if report["passed"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="role", required=True)
    main_parser = subparsers.add_parser("main", help="hold one existing-agent SSH lease from main")
    remote_parser = subparsers.add_parser("remote", help="internal SSH entry point; do not run detached")
    for command in (main_parser, remote_parser):
        command.add_argument("--runner", type=Path, required=True)
        command.add_argument("--runner-sha256", required=True)
        command.add_argument("--out", type=Path, required=True)
        command.add_argument("runner_args", nargs=argparse.REMAINDER)
    main_parser.add_argument("--remote-script", type=Path, required=True)
    main_parser.add_argument("--remote-out", type=Path, required=True)
    remote_parser.add_argument("--self-sha256", required=True)
    remote_parser.add_argument("--nonce", required=True)
    args = parser.parse_args()
    if args.runner_args[:1] == ["--"]:
        args.runner_args = args.runner_args[1:]
    for signum in (signal.SIGHUP, signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda received, _frame: STOP_SIGNALS.append({"signal": signal.Signals(received).name, "monotonic": time.monotonic()}))
    return main_side(args) if args.role == "main" else remote(args)


if __name__ == "__main__":
    raise SystemExit(main())

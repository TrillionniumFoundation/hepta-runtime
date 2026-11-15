# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Execute the complete cancellation helper with isolated kernel boundaries.

Private directories, metadata validation, atomic writes and fsync are real.
Only /proc, pidfd, signals, ps, waiting, time and stdout effects are substituted.
No real process is selected or signalled by this fixture.
"""

import builtins
import errno
import io
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
from types import SimpleNamespace


PID = 424242
BOOT = "fixture-original-boot"
TICKS = "777"
POLLIN, POLLOUT, POLLERR, POLLHUP, POLLNVAL = 1, 4, 8, 16, 32


class Boundary:
    def __init__(self, job, options):
        self.job, self.options = job, options
        self.platform = options.get("platform", "linux")
        self.now_ns = 0
        self.monotonic_calls = 0
        self.events, self.signals, self.polls, self.sleeps, self.outputs = [], [], [], [], []
        self.steps = list(options.get("poll_steps", []))
        self.fd, self.fd_open, self.fd_closes = None, False, 0
        self.terminal_published = False

    def event(self, kind, **fields):
        self.events.append(dict(kind=kind, at_ns=self.now_ns, **fields))

    def write(self, name, raw):
        temporary = self.job / (name + ".fixture-next")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, self.job / name)
        fd = os.open(self.job, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def metadata(self, mode="valid"):
        raw = b'{"exit_code":0}' if mode == "valid" else b"{corrupt-terminal"
        self.write("exit.json", raw)
        self.terminal_published = True
        self.event("replace_exit", mode=mode)

    def monotonic(self):
        self.monotonic_calls += 1
        assert self.monotonic_calls <= 1000, "fixture detected an unbounded no-wait loop"
        return self.now_ns / 1_000_000_000

    def advance(self, milliseconds):
        self.now_ns += round(milliseconds * 1_000_000)
        after = self.options.get("exit_after_ms")
        if after is not None and self.now_ns >= round(after * 1_000_000) and not self.terminal_published:
            self.metadata()

    def sleep(self, seconds):
        assert len(self.sleeps) < 64, "fixture detected an unbounded sleep loop"
        self.sleeps.append(seconds)
        self.event("sleep", seconds=seconds)
        self.advance(seconds * 1000)

    def open(self, path, flags, mode=0o777, *, dir_fd=None):
        if os.fspath(path) == "exit.json":
            self.event("read_exit")
        return os.open(path, flags, mode, dir_fd=dir_fd)

    def pidfd_open(self, pid, flags):
        assert self.platform == "linux" and pid == PID and flags == 0
        self.event("pidfd_open", pid=pid)
        if self.options.get("setup_error") == "open":
            raise OSError(errno.ESRCH, "fixture pidfd_open failed")
        # This owned harmless descriptor models custody; it is never a real pidfd.
        self.fd = os.open(os.devnull, os.O_RDONLY | os.O_CLOEXEC)
        self.fd_open = True
        return self.fd

    def close(self, fd):
        if fd == self.fd:
            assert self.fd_open, "original descriptor closed more than once"
            self.fd_open = False
            self.fd_closes += 1
            self.event("close_pidfd")
        os.close(fd)

    def send(self, kind, target, signum, *unused):
        assert signum == signal.SIGTERM
        if kind == "pidfd":
            assert self.platform == "linux" and target == self.fd and self.fd_open
        else:
            assert self.platform != "linux" and target == PID, "unexpected PID fallback"
        self.signals.append(kind)
        self.event("signal", mechanism=kind)
        if self.options.get("signal_error"):
            raise OSError(errno.ESRCH, "fixture signal outcome unavailable")

    def poll_factory(self):
        self.event("poll_factory")
        if self.options.get("setup_error") == "poll":
            raise OSError(errno.ENOMEM, "fixture poll construction failed")
        return self

    def register(self, fd, mask):
        assert fd == self.fd and self.fd_open and mask == POLLIN
        self.event("poll_register")
        if self.options.get("setup_error") == "register":
            raise OSError(errno.EBADF, "fixture poll registration failed")

    def poll(self, milliseconds):
        assert type(milliseconds) is int and 0 < milliseconds <= 100
        assert len(self.polls) < 64, "fixture detected an unbounded poll loop"
        row = {"at_ns": self.now_ns, "timeout_ms": milliseconds}
        self.polls.append(row)
        self.event("poll", timeout_ms=milliseconds)
        step = self.steps.pop(0) if self.steps else {}
        self.advance(step.get("elapsed_ms", milliseconds))
        if "replace_exit" in step:
            self.metadata(step["replace_exit"])
        if step.get("error") == "eintr":
            raise InterruptedError(errno.EINTR, "fixture signal interrupted wait")
        if step.get("error") == "badfd":
            raise OSError(errno.EBADF, "fixture poll syscall failed")
        if "mask" not in step:
            return []
        fd = self.fd + 1 if step.get("foreign_fd") else self.fd
        events = [(fd, step["mask"])]
        if step.get("duplicate_event"):
            events.append((fd, POLLHUP))
        return events

    def capture(self, *values, sep=" ", end="\n", **unused):
        self.event("ack_write")
        if self.options.get("lost_ack"):
            raise BrokenPipeError(errno.EPIPE, "fixture ACK receiver disappeared")
        self.outputs.append(sep.join(str(value) for value in values) + end)

    def namespace(self, query):
        boundary = self

        class ProcessPath(type(Path())):
            def read_text(self, *args, **kwargs):
                if str(self) == f"/proc/{PID}/stat":
                    boundary.event("identity_read")
                    return f"{PID} (fixture) " + " ".join(["S"] + ["0"] * 18 + [TICKS])
                if str(self) == "/proc/sys/kernel/random/boot_id":
                    return BOOT
                return super().read_text(*args, **kwargs)

            def stat(self, *args, **kwargs):
                if str(self) == f"/proc/{PID}":
                    return SimpleNamespace(st_uid=os.geteuid())
                return super().stat(*args, **kwargs)

        def ps(argv, **kwargs):
            assert self.platform != "linux" and argv[:3] == ["ps", "-p", str(PID)]
            return "fixture-original-start" if argv[-1] == "lstart=" else str(os.geteuid())

        fake_os = SimpleNamespace(**vars(os))
        fake_os.open, fake_os.close = self.open, self.close
        fake_os.pidfd_open = self.pidfd_open
        fake_os.kill = lambda *args: self.send("posix", *args)
        fake_signal = SimpleNamespace(SIGTERM=signal.SIGTERM,
                                      pidfd_send_signal=lambda *args: self.send("pidfd", *args))
        if self.platform != "linux" or self.options.get("setup_error") == "missing_pidfd":
            del fake_os.pidfd_open
            del fake_signal.pidfd_send_signal
        modules = {
            "os": fake_os,
            "pathlib": SimpleNamespace(Path=ProcessPath),
            "signal": fake_signal,
            "subprocess": SimpleNamespace(check_output=ps),
            "sys": SimpleNamespace(platform=self.platform, stdin=io.StringIO(json.dumps(query))),
            "time": SimpleNamespace(monotonic=self.monotonic, sleep=self.sleep,
                                    time=lambda: 1_000_000 + self.now_ns / 1_000_000_000),
        }

        def imports(name, *args, **kwargs):
            if name == "select":
                self.event("import_select")
                if self.platform != "linux":
                    raise ImportError("select is deliberately unavailable for the legacy fixture")
                return SimpleNamespace(poll=self.poll_factory, POLLIN=POLLIN, POLLOUT=POLLOUT,
                                       POLLERR=POLLERR, POLLHUP=POLLHUP, POLLNVAL=POLLNVAL)
            if name in modules:
                return modules[name]
            assert name in {"io", "json", "math", "stat"}, "unexpected helper system import: " + name
            return builtins.__import__(name, *args, **kwargs)

        return {"__builtins__": {**vars(builtins), "__import__": imports, "print": self.capture}}


def exercise(helper, options):
    with tempfile.TemporaryDirectory(prefix="hepta-cancel-wait-") as temporary:
        state = Path(temporary).resolve() / "state"
        jobs, job = state / "jobs", state / "jobs" / "fixture"
        for directory in (state, jobs, job):
            directory.mkdir(mode=0o700)
        boundary = Boundary(job, options)
        query = {"job_id": "wait-fixture", "job_dir": str(job), "unit": "fixture-unit",
                 "request_digest": "a" * 64, "grace_seconds": options.get("grace", 1)}
        request = {**query, "launch_nonce": "b" * 32}
        identity = {"kind": "proc_start_ticks", "value": BOOT + ":" + TICKS}
        if boundary.platform != "linux":
            identity = {"kind": "ps_lstart", "value": "fixture-original-start"}
        for name, value in {
            "request.json": request,
            "launch.json": {"backend": "detached"},
            "started.json": {"job_id": query["job_id"], "launch_nonce": request["launch_nonce"],
                             "supervisor_pid": PID, "supervisor_uid": os.geteuid(),
                             "supervisor_identity": identity},
        }.items():
            boundary.write(name, json.dumps(value).encode())
        if options.get("already_exited"):
            boundary.metadata()
        namespace = boundary.namespace(query)
        cwd = os.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        error = None
        try:
            exec(compile(helper, "<complete-bound-cancel-helper>", "exec"), namespace)
        except BaseException as failure:
            if not (isinstance(failure, SystemExit) and failure.code in (None, 0)):
                error = {"type": type(failure).__name__, "message": str(failure),
                         "errno": getattr(failure, "errno", None)}
        finally:
            os.fchdir(cwd)
            os.close(cwd)
            leaked = boundary.fd_open
            if leaked:
                os.close(boundary.fd)
            for fd in namespace.get("_hepta_directory_pins", []):
                os.close(fd)
        cancel = job / "cancel-request.json"
        return {"error": error, "stdout": "".join(boundary.outputs), "signals": boundary.signals,
                "events": boundary.events, "polls": boundary.polls, "sleeps": boundary.sleeps,
                "elapsed_ns": boundary.now_ns, "pidfd_closes": boundary.fd_closes,
                "pidfd_leaked": leaked, "cancel_receipt": json.loads(cancel.read_text()) if cancel.exists() else None,
                "exit_exists": (job / "exit.json").exists()}


if __name__ == "__main__":
    payload = json.load(sys.stdin)
    print(json.dumps(exercise(payload["helper"], payload["options"]), sort_keys=True))

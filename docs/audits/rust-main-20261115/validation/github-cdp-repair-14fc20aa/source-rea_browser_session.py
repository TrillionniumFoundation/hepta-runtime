#!/usr/bin/env python3
"""Own and reap the Linux-only CDP reference's temporary process trees."""

import argparse
import ctypes
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time


class Interrupted(Exception):
    def __init__(self, signum):
        self.signum = signum


class OwnedProcesses:
    def __init__(self):
        self.owner = os.getpid()
        self.processes = []
        self.report = {"owner_pid": self.owner, "owned_sessions": [],
                       "term_used": False, "escalated_to_kill": False,
                       "reaped_pids": [], "remaining_live_children": []}
        if os.readlink("/proc/self") != str(self.owner):
            raise RuntimeError("procfs does not use this owner's PID namespace")
        if self.children():
            raise RuntimeError("CDP owner must start without existing children")
        # Reparent double-forked/session-escaping Chrome helpers to this owner.
        libc = ctypes.CDLL(None, use_errno=True)
        libc.prctl.argtypes = [ctypes.c_int] + [ctypes.c_ulong] * 4
        libc.prctl.restype = ctypes.c_int
        if libc.prctl(36, 1, 0, 0, 0):  # PR_SET_CHILD_SUBREAPER
            raise OSError(ctypes.get_errno(), "PR_SET_CHILD_SUBREAPER failed")
        signal.signal(signal.SIGCHLD, signal.SIG_DFL)

    def children(self):
        path = Path(f"/proc/self/task/{self.owner}/children")
        try:
            candidates = path.read_text().split()
            direct_list = True
        except FileNotFoundError:
            # Some Linux sandboxes omit task/children. Read only stat metadata
            # and retain only our own children; never inspect argv or env.
            candidates = [item.name for item in Path("/proc").iterdir() if item.name.isdecimal()]
            direct_list = False
        result = []
        for value in candidates:
            pid = int(value)
            try:
                fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
            except FileNotFoundError:
                continue
            if int(fields[1]) != self.owner:
                if direct_list:
                    raise RuntimeError("Child ownership changed before cleanup")
                continue
            result.append((pid, fields[0]))
        return sorted(result)

    def start(self, command, log=None):
        process = subprocess.Popen(
            command, start_new_session=True, stdin=subprocess.DEVNULL,
            stdout=log, stderr=subprocess.STDOUT if log is not None else None,
        )
        self.processes.append(process)
        if os.getpgid(process.pid) != process.pid or os.getsid(process.pid) != process.pid:
            raise RuntimeError("Temporary service did not acquire its own session")
        self.report["owned_sessions"].append(
            {"pid": process.pid, "pgid": process.pid, "sid": process.pid})
        return process

    def group_signal(self, signum):
        for process in self.processes:
            # Never poll()/wait() these leaders before the final reap. Their
            # unreaped PIDs pin the group identities even after early exit.
            try:
                os.killpg(process.pid, signum)
            except ProcessLookupError:
                pass

    @staticmethod
    def live_children(children):
        # A thread-group leader may show Z after pthread_exit while its other
        # threads still write. Only an exit waitable without reaping is dead.
        return [pid for pid, _state in children
                if os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None]

    def await_quiet(self, signum, seconds):
        deadline = time.monotonic() + seconds
        signaled = set()
        while True:
            children = self.children()
            live = self.live_children(children)
            self.report["remaining_live_children"] = live
            if not live:
                # Reparenting can add an orphan while the first snapshot is
                # read. Require a stable, wholly dead set before final reap.
                again = self.children()
                if again == children:
                    return True
            # Only this dedicated subreaper's unreaped children are eligible.
            # This also covers adopted descendants that created new sessions.
            for pid in live:
                if pid not in signaled:
                    os.kill(pid, signum)
                    signaled.add(pid)
            if time.monotonic() >= deadline:
                self.report["remaining_live_children"] = live
                return False
            time.sleep(0.02)

    def close(self, term_seconds, kill_seconds):
        self.report["term_used"] = bool(self.processes or self.children())
        self.group_signal(signal.SIGTERM)
        if not self.await_quiet(signal.SIGTERM, term_seconds):
            self.report["escalated_to_kill"] = True
            self.group_signal(signal.SIGKILL)
            if not self.await_quiet(signal.SIGKILL, kill_seconds):
                raise RuntimeError("Owned descendants survived SIGKILL; profile retained")
        # No signals follow this point: reaping may release the pinned IDs.
        deadline = time.monotonic() + kill_seconds
        while True:
            try:
                pid, status = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                break
            if pid:
                self.report["reaped_pids"].append(pid)
                for process in self.processes:
                    if process.pid == pid:
                        process.returncode = os.waitstatus_to_exitcode(status)
            elif time.monotonic() >= deadline:
                raise RuntimeError("Owned descendants could not be reaped; profile retained")
            else:
                time.sleep(0.02)
        self.report["remaining_live_children"] = []


def run_session(profile, evidence, chrome_command, http_command, probe_command,
                term_seconds=3.0, kill_seconds=3.0):
    owner = OwnedProcesses()
    original_status = 1
    profile_created = False
    lifecycle_error = None
    cleanup_error = None
    closing = False

    def interrupted(signum, _frame):
        if not closing:
            raise Interrupted(signum)

    old_handlers = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        profile.mkdir(mode=0o700)
        profile_created = True
        with (evidence / "http-server.log").open("w") as http_log, \
                (evidence / "chrome.log").open("w") as chrome_log:
            owner.start(http_command, http_log)
            chrome = owner.start(chrome_command, chrome_log)
            probe = owner.start(probe_command + [str(chrome.pid)])
            # Observe the probe result without releasing its PID/group anchor.
            result = os.waitid(os.P_PID, probe.pid, os.WEXITED | os.WNOWAIT)
            original_status = result.si_status if result.si_code == os.CLD_EXITED else 128 + result.si_status
    except Interrupted as error:
        original_status = 128 + error.signum
    except Exception as error:
        lifecycle_error = str(error)
        print(f"CDP lifecycle failed: {error}", file=sys.stderr)
    finally:
        closing = True
        try:
            owner.close(term_seconds, kill_seconds)
            if profile_created:
                # All descendants are dead and reaped before the one removal.
                shutil.rmtree(profile)
        except Exception as error:
            cleanup_error = str(error)
            print(f"CDP cleanup failed: {error}", file=sys.stderr)
            try:
                owner.report["remaining_live_children"] = owner.live_children(owner.children())
            except Exception as inspection_error:
                owner.report["remaining_live_children"] = None
                owner.report["remaining_children_inspection_error"] = str(inspection_error)
        report = {**owner.report, "probe_exit_status": original_status,
                  "lifecycle_error": lifecycle_error,
                  "cleanup_exit_status": 1 if cleanup_error else 0,
                  "final_exit_status": original_status or (1 if cleanup_error or lifecycle_error else 0),
                  "cleanup_error": cleanup_error, "profile_removed": profile_created and not profile.exists()}
        try:
            (evidence / "process-cleanup.json").write_text(json.dumps(report, indent=2) + "\n")
        except Exception as error:
            cleanup_error = cleanup_error or str(error)
            print(f"CDP cleanup evidence failed: {error}", file=sys.stderr)
        for sig, handler in old_handlers.items():
            signal.signal(sig, handler)
    return original_status if original_status else (1 if cleanup_error or lifecycle_error else 0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("probe", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    probe = args.probe[1:] if args.probe[:1] == ["--"] else args.probe
    if not probe:
        parser.error("A probe command is required")
    chrome = ["google-chrome", "--headless=new", "--no-sandbox", "--disable-gpu",
              "--disable-dev-shm-usage", "--disable-background-networking", "--no-first-run",
              "--no-default-browser-check", "--disable-extensions", "--remote-debugging-address=127.0.0.1",
              "--remote-debugging-port=0", "--remote-allow-origins=*", f"--user-data-dir={args.profile}",
              "about:blank"]
    http = [sys.executable, "-m", "http.server", str(args.port), "--bind", "127.0.0.1",
            "--directory", str(args.evidence / "html")]
    return run_session(args.profile, args.evidence, chrome, http, probe)


if __name__ == "__main__":
    raise SystemExit(main())

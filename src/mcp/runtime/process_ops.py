# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Operator-account process inspection/signalling. Not a privilege boundary."""
import json
import os
import pathlib
import signal
import subprocess
import sys
import time


def identity(pid):
    if sys.platform == "linux":
        stat = pathlib.Path(f"/proc/{pid}/stat").read_text()
        ticks = stat.rsplit(") ", 1)[1].split()[19]
        boot = pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        return f"linux:{boot}:{ticks}"
    value = subprocess.check_output(
        ["ps", "-p", str(pid), "-o", "lstart="], text=True, timeout=3
    ).strip()
    if not value:
        raise ProcessLookupError(pid)
    return "ps:" + value


def list_processes(q):
    after = int(q.get("after_pid", 0))
    limit = max(1, min(128, int(q.get("limit", 64))))
    records = []
    if sys.platform == "linux":
        for pid in sorted(int(p.name) for p in pathlib.Path("/proc").iterdir() if p.name.isdigit()):
            if pid <= after:
                continue
            try:
                start = identity(pid)
                folder = pathlib.Path(f"/proc/{pid}")
                record = {"pid": pid, "uid": folder.stat().st_uid,
                          "name": (folder / "comm").read_text().strip()[:256],
                          "identity": start}
                if identity(pid) != start:
                    continue
                records.append(record)
            except (OSError, ValueError, IndexError):
                continue
            if len(records) > limit:
                break
    else:
        output = subprocess.check_output(
            ["ps", "-axo", "pid=,uid=,comm="], text=True, timeout=5)
        rows = []
        for line in output.splitlines():
            fields = line.strip().split(None, 2)
            if len(fields) == 3 and int(fields[0]) > after:
                rows.append((int(fields[0]), int(fields[1]), fields[2]))
        for pid, uid, name in sorted(rows):
            try:
                records.append({"pid": pid, "uid": uid, "name": name[:256], "identity": identity(pid)})
            except (OSError, subprocess.SubprocessError):
                continue
            if len(records) > limit:
                break
    more = len(records) > limit
    records = records[:limit]
    return {"processes": records, "has_more": more,
            "next_after_pid": records[-1]["pid"] if records else after,
            "snapshot_atomic": False, "sampled_at_unix_ms": int(time.time() * 1000)}


def send_signal(q):
    pid, number = int(q["pid"]), int(q["signal"])
    if not 0 < pid <= 2147483647 or number not in ({0} | set(signal.valid_signals())):
        raise ValueError("single positive PID and supported signal required")
    fd = None
    try:
        atomic = sys.platform == "linux" and hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal")
        if atomic:
            fd = os.pidfd_open(pid, 0)
        actual = identity(pid)
        expected = q.get("expected_identity")
        if expected is not None and expected != actual:
            raise ValueError("process identity changed; no signal sent")
        if atomic:
            signal.pidfd_send_signal(fd, number, None, 0)
        else:
            # POSIX lacks a cross-platform pidfd equivalent. This is best effort.
            if identity(pid) != actual:
                raise ValueError("process identity changed; no signal sent")
            os.kill(pid, number)
        return {"pid": pid, "signal": number, "identity": actual,
                "result": "probe_succeeded" if number == 0 else "signal_sent",
                "atomic_identity": atomic, "effective_uid": os.geteuid(),
                "termination_confirmed": False}
    finally:
        if fd is not None:
            os.close(fd)


def main():
    q = json.load(sys.stdin)
    if q["op"] == "list":
        result = list_processes(q)
    elif q["op"] == "signal":
        result = send_signal(q)
    else:
        raise ValueError("unknown process operation")
    print(json.dumps(result, ensure_ascii=True))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(1)

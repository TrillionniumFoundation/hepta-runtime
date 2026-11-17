#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Retained-evidence reader guard; all native and process execution is rejected."""
from __future__ import annotations
from pathlib import Path
import ctypes
import gzip
import hashlib
import mmap
import os
import stat
import subprocess
import sys
import tarfile
from common import canonical, require

_ACTIVE = False
_ROOTS = ()


def _inside(path):
    if not isinstance(path, (str, bytes, os.PathLike)):
        return False
    try:
        p = Path(os.fsdecode(path)).absolute().resolve()
        return any(p == root or p.is_relative_to(root) for root in _ROOTS)
    except (OSError, ValueError):
        return False


def _audit(event, args):
    if not _ACTIVE:
        return
    if event == "open":
        path, mode, flags = args
        if (isinstance(mode, str) and any(c in mode for c in "wax+")) or flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND) or not _inside(path):
            raise PermissionError("reader denied file access")
    elif event in {"os.remove", "os.rmdir", "os.mkdir", "os.rename", "os.link", "os.symlink", "os.chmod", "os.chown", "os.utime", "os.truncate", "os.setxattr", "os.removexattr", "os.chdir", "os.fchdir"}:
        raise PermissionError("reader denied mutation")
    elif event.startswith(("subprocess.", "ctypes.", "mmap.", "socket.")) or event in {"os.system", "os.fork", "os.forkpty", "os.exec", "os.posix_spawn"}:
        raise PermissionError("reader denied execution/foreign capability")
    elif event in {"os.listdir", "os.scandir"} and not _inside(args[0]):
        raise PermissionError("reader denied foreign directory")


sys.addaudithook(_audit)


def snapshot(roots):
    result = []
    for number, root in enumerate(roots):
        for path in [root, *sorted(root.rglob("*"))]:
            before = path.lstat()
            require(stat.S_ISREG(before.st_mode) or stat.S_ISDIR(before.st_mode), "reader evidence contains non-ordinary entry")
            row = dict(root=number, path="." if path == root else path.relative_to(root).as_posix(),
                       dev=before.st_dev, inode=before.st_ino, mode=before.st_mode, uid=before.st_uid, gid=before.st_gid,
                       links=before.st_nlink, bytes=before.st_size, mtime_ns=before.st_mtime_ns, ctime_ns=before.st_ctime_ns)
            if stat.S_ISREG(before.st_mode):
                with path.open("rb") as stream:
                    row["sha256"] = hashlib.file_digest(stream, "sha256").hexdigest()
                after = path.stat()
                stable = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid,
                    s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
                require(stable(after) == stable(before), "reader snapshot changed during read")
            result.append(row)
    return result


def guarded(operation, *, roots):
    global _ACTIVE, _ROOTS
    require(not _ACTIVE, "reader guard is not reentrant")
    selected = tuple(sorted({Path(p).resolve(strict=True) for p in roots}))
    selected = tuple(p for p in selected if not any(p != q and p.is_relative_to(q) for q in selected))
    require(all(p.is_dir() for p in selected), "reader roots must be ordinary directories")
    _ROOTS = selected
    # Complete lazy standard-library initialization before activating the guard.
    gzip.decompress(gzip.compress(b""))
    before = snapshot(selected)
    probe_path = selected[0] / "readonly-probe-must-not-exist"
    canary = next(p for p in selected[0].rglob("*") if p.is_file())
    probes = []
    _ACTIVE = True
    try:
        actions = [
            ("write", lambda: probe_path.write_bytes(b"x")),
            ("os-open-write", lambda: os.open(probe_path, os.O_CREAT | os.O_WRONLY, 0o600)),
            ("mkdir", lambda: probe_path.mkdir()),
            ("rename", lambda: os.rename(canary, probe_path)),
            ("unlink", lambda: os.unlink(canary)),
            ("chmod", lambda: os.chmod(canary, canary.stat().st_mode & 0o777)),
            ("utime", lambda: os.utime(canary, None)),
            ("subprocess", lambda: subprocess.run(["/usr/bin/true"], check=True)),
            ("ctypes", lambda: ctypes.CDLL(None)),
            ("mmap", lambda: mmap.mmap(-1, 4096)),
            ("foreign-read", lambda: Path("/dev/null").read_bytes()),
        ]
        for name, action in actions:
            try:
                action()
            except PermissionError:
                probes.append(dict(name=name, rejected=True))
            else:
                raise ValueError("reader guard probe unexpectedly succeeded: " + name)
        evidence = operation()
        after = snapshot(selected)
        require(before == after, "reader changed evidence bytes or metadata")
    finally:
        _ACTIVE = False
        _ROOTS = ()
    return dict(status="READONLY_PASS", roots=[str(p) for p in selected], probes=probes,
                entries=len(before), before=before, after=after, evidence=evidence,
                native_executed=False, rust_executed=False, evidence_written=False)

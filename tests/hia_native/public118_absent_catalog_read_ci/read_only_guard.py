"""Read-only guard admitting only descriptors opened from the fixed owned files."""
from __future__ import annotations
import builtins
import ctypes
import fcntl
import hashlib
import json
import mmap
import os
from pathlib import Path
import stat
import subprocess
import sys
sys.dont_write_bytecode=True
def require(value,message):
    if not value:raise ValueError(message)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def read(path):
    path=Path(path);info=path.lstat()
    require(stat.S_ISREG(info.st_mode) and path.resolve()==path.absolute(),'regular non-aliased read')
    return path.read_bytes()
def snapshot(roots):
    result = {}
    for number, root in enumerate(roots):
        root = Path(root).absolute()
        for folder, dirs, names in os.walk(root, followlinks=False):
            for path in [Path(folder)] + [Path(folder) / name for name in names]:
                info = path.lstat()
                require(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode), "read-only snapshot rejects special files")
                key = str(number) + ":" + path.relative_to(root).as_posix()
                result[key] = {"mode": info.st_mode, "inode": info.st_ino, "device": info.st_dev,
                    "bytes": info.st_size, "mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns,
                    "sha256": sha(read(path)) if stat.S_ISREG(info.st_mode) else None}
    return result

def guarded(operation, *, roots, foreign_path):
    roots = [Path(root).absolute() for root in roots]
    before = snapshot(roots)
    allowed = {str(root / key.split(":", 1)[1]) for index, root in enumerate(roots)
               for key, row in before.items() if key.startswith(str(index) + ":") and row["sha256"] is not None}
    active = [False]
    denied = []
    descriptors = {}
    original_open, original_close = os.open, os.close

    def opened(path, flags, mode=0o777, *, dir_fd=None):
        fd = original_open(path, flags, mode, dir_fd=dir_fd)
        if active[0]:
            info = os.fstat(fd)
            descriptors[fd] = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_nlink)
        return fd

    def closed(fd):
        descriptors.pop(fd, None)
        return original_close(fd)

    def refuse(kind):
        denied.append(kind)
        raise PermissionError("owner-export read-only guard: " + kind)

    def audit(event, args):
        if not active[0]:
            return
        if event == "open":
            path, mode, flags = args
            if isinstance(mode, str) and any(value in mode for value in "wax+"):
                refuse("file-write")
            if type(flags) is int and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
                refuse("descriptor-write-open")
            if type(path) is int:
                if path not in descriptors:
                    refuse("foreign-file-descriptor")
                info = os.fstat(path)
                actual = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_nlink)
                if actual != descriptors[path] or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    refuse("foreign-file-descriptor")
                if fcntl.fcntl(path, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY:
                    refuse("descriptor-write-open")
            elif not isinstance(path, (str, bytes, os.PathLike)):
                refuse("foreign-file-descriptor")
            elif os.path.abspath(os.fsdecode(path)) not in allowed:
                refuse("foreign-read")
        if event in {"os.remove", "os.rmdir", "os.rename", "os.mkdir", "os.chmod", "os.chown", "os.utime",
                     "os.link", "os.symlink", "os.truncate", "os.setxattr", "os.removexattr"}:
            refuse("filesystem-mutation")
        if event in {"subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "os.fork", "os.forkpty"}:
            refuse("process-execution")
        if event.startswith("ctypes.") or event == "mmap.__new__":
            refuse("native-mapping")

    sys.addaudithook(audit)
    saved = {name: getattr(os, name) for name in ("write", "writev", "pwrite", "ftruncate") if hasattr(os, name)}

    def refuse_descriptor(*args, **kwargs):
        if active[0]:
            refuse("descriptor-write")
        raise RuntimeError("read-only descriptor wrapper used after guard lifetime")

    probes = []
    probe_file = roots[0] / "CAPTURE.json"
    attempts = [
        ("python-file-write", lambda: builtins.open(probe_file, "wb")),
        ("descriptor-open", lambda: os.open(probe_file, os.O_WRONLY)),
        ("foreign-read-descriptor", lambda: os.fdopen(1, "rb", closefd=False)),
        ("descriptor-write", lambda: os.write(1, b"")),
        ("metadata-mode", lambda: os.chmod(probe_file, 0o600)),
        ("metadata-time", lambda: os.utime(probe_file, None)),
        ("directory-create", lambda: os.mkdir(roots[0] / "forbidden-directory")),
        ("subprocess", lambda: subprocess.Popen(["/bin/true"])),
        ("shell", lambda: os.system("true")),
        ("native-dlopen", lambda: ctypes.CDLL(None)),
        ("native-mmap", lambda: mmap.mmap(-1, 4096)),
        ("producer-or-foreign-read", lambda: builtins.open(foreign_path, "rb")),
    ]
    try:
        for name in saved:
            setattr(os, name, refuse_descriptor)
        os.open, os.close = opened, closed
        active[0] = True
        for name, action in attempts:
            start = len(denied)
            try:
                action()
            except PermissionError as exc:
                require(len(denied) == start + 1, "probe was refused outside the read-only guard")
                probes.append({"name": name, "refusal": str(exc), "guard_event": denied[-1]})
            else:
                raise ValueError("read-only guard allowed " + name)
        prior = len(denied)
        result = operation()
        require(len(denied) == prior, "reader attempted a forbidden operation")
    finally:
        active[0] = False
        os.open, os.close = original_open, original_close
        for name, method in saved.items():
            setattr(os, name, method)
    after = snapshot(roots)
    require(before == after, "read-only reader changed complete bytes or filesystem metadata")
    return {"schema": "hepta.runtime.owner-export-readonly.v1", "pid": os.getpid(),
        "ppid": os.getppid(), "pgid": os.getpgrp(), "source_bound_guard": True,
        "native_or_rust_executions": 0, "reader_writes": 0, "probes": probes,
        "before": before, "after": after, "evidence": result}

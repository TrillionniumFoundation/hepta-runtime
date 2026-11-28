"""Fixed-reader guard, including owned read-only os.open -> fdopen custody."""
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
    # Descriptor-relative traversal keeps every byte read and every metadata
    # field while avoiding repeated pathlib resolution of each full ancestor.
    result = {}
    def metadata(info):
        return {"mode": info.st_mode, "inode": info.st_ino, "device": info.st_dev,
            "bytes": info.st_size, "mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns}
    def record(key, info, *, parent=None, name=None):
        require(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode),
                "read-only snapshot rejects special files")
        row = metadata(info)
        row["sha256"] = None
        if stat.S_ISREG(info.st_mode):
            descriptor = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent)
            try:
                opened = os.fstat(descriptor)
                require(metadata(opened) == metadata(info), "snapshot file changed before open")
                digest, count = hashlib.sha256(), 0
                while block := os.read(descriptor, 1 << 20):
                    digest.update(block)
                    count += len(block)
                require(count == info.st_size and metadata(os.fstat(descriptor)) == metadata(info),
                        "snapshot file changed during complete read")
                row["sha256"] = digest.hexdigest()
            finally:
                os.close(descriptor)
        result[key] = row
    for number, root in enumerate(roots):
        root = Path(root).absolute()
        require(root.resolve() == root and stat.S_ISDIR(root.lstat().st_mode),
                "read-only snapshot requires ordinary non-aliased roots")
        root_name = str(root)
        prefix = root_name.rstrip(os.sep) + os.sep
        for folder, dirs, names, parent in os.fwalk(root_name, follow_symlinks=False):
            relative = "." if folder == root_name else folder[len(prefix):]
            require(folder == root_name or folder.startswith(prefix), "snapshot traversal escaped root")
            key = str(number) + ":" + relative
            record(key, os.fstat(parent))
            for name in names + dirs:
                require(name not in (".", "..") and os.sep not in name, "snapshot entry is not a basename")
                suffix = name if relative == "." else relative + "/" + name
                record(str(number) + ":" + suffix,
                       os.stat(name, dir_fd=parent, follow_symlinks=False), parent=parent, name=name)
    return result

# Python audit hooks cannot be removed. Register one dispatcher and retain
# only guards that are currently active, instead of accumulating dead hooks.
_ACTIVE_AUDITS = []
_AUDIT_DISPATCH_INSTALLED = False

def _dispatch_audit(event, args):
    for handler in tuple(_ACTIVE_AUDITS):
        handler(event, args)

def guarded(operation, *, roots, foreign_path):
    global _AUDIT_DISPATCH_INSTALLED
    roots = [Path(root).absolute() for root in roots]
    before = snapshot(roots)
    allowed = {str(root / key.split(":", 1)[1]) for index, root in enumerate(roots)
               for key, row in before.items() if key.startswith(str(index) + ":") and row["sha256"] is not None}
    active = [False]
    denied = []
    owned_read_fds = {}
    original_open = os.open

    def tracked_open(*args, **kwargs):
        descriptor = original_open(*args, **kwargs)
        if active[0]:
            info = os.fstat(descriptor)
            owned_read_fds[descriptor] = (info.st_dev, info.st_ino)
        return descriptor

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
                # os.fdopen is used by the existing strict regular-file
                # reader. Only a descriptor opened through an admitted path
                # during this guard, still on that inode and read-only, may
                # be consumed. Pre-existing or replaced descriptors refuse.
                if path not in owned_read_fds:
                    refuse("foreign-file-descriptor")
                info = os.fstat(path)
                if ((info.st_dev, info.st_ino) != owned_read_fds[path]
                        or fcntl.fcntl(path, fcntl.F_GETFL) & os.O_ACCMODE):
                    refuse("foreign-file-descriptor")
            else:
                if not isinstance(path, (str, bytes, os.PathLike)):
                    refuse("foreign-file-descriptor")
                if os.path.abspath(os.fsdecode(path)) not in allowed:
                    refuse("foreign-read")
        if event in {"os.remove", "os.rmdir", "os.rename", "os.mkdir", "os.chmod", "os.chown", "os.utime",
                     "os.link", "os.symlink", "os.truncate", "os.setxattr", "os.removexattr"}:
            refuse("filesystem-mutation")
        if event in {"subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "os.fork", "os.forkpty"}:
            refuse("process-execution")
        if event.startswith("ctypes.") or event == "mmap.__new__":
            refuse("native-mapping")

    if not _AUDIT_DISPATCH_INSTALLED:
        sys.addaudithook(_dispatch_audit)
        _AUDIT_DISPATCH_INSTALLED = True
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
        ("descriptor-write", lambda: os.write(1, b"")),
        ("metadata-mode", lambda: os.chmod(probe_file, 0o600)),
        ("metadata-time", lambda: os.utime(probe_file, None)),
        ("directory-create", lambda: os.mkdir(roots[0] / "forbidden-directory")),
        ("subprocess", lambda: subprocess.Popen(["/bin/true"])),
        ("shell", lambda: os.system("true")),
        ("native-dlopen", lambda: ctypes.CDLL(None)),
        ("native-mmap", lambda: mmap.mmap(-1, 4096)),
        ("producer-or-foreign-read", lambda: builtins.open(foreign_path, "rb")),
        ("unadmitted-file-descriptor", lambda: builtins.open(0, "rb", closefd=False)),
    ]
    try:
        _ACTIVE_AUDITS.append(audit)
        for name in saved:
            setattr(os, name, refuse_descriptor)
        os.open = tracked_open
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
        try:
            if audit in _ACTIVE_AUDITS:
                _ACTIVE_AUDITS.remove(audit)
        finally:
            os.open = original_open
            for name, method in saved.items():
                setattr(os, name, method)
    after = snapshot(roots)
    require(before == after, "read-only reader changed complete bytes or filesystem metadata")
    return {"schema": "hepta.runtime.scope-span-readonly.v2", "pid": os.getpid(),
        "ppid": os.getppid(), "pgid": os.getpgrp(), "source_bound_guard": True,
        "native_or_rust_executions": 0, "reader_writes": 0, "probes": probes,
        "before": before, "after": after, "evidence": result}

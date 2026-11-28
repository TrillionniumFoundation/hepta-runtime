"""Fixed aggregate reader guard with explicit complete library/tool pins."""
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
import threading
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


def external_snapshot(paths):
    result={}
    for value in sorted(set(str(Path(p).absolute()) for p in paths)):
        path=Path(value)
        if not os.path.lexists(path):
            require(path.suffix==".pyc", "only absent Python bytecode lookups are declared")
            result[value]={"absent":True}
            continue
        logical=path.lstat()
        resolved=path.resolve(strict=True)
        actual=resolved.stat()
        require(stat.S_ISREG(actual.st_mode), "external library/tool must be a regular target")
        def meta(v):
            return {"mode":v.st_mode,"device":v.st_dev,"inode":v.st_ino,"bytes":v.st_size,
                    "mtime_ns":v.st_mtime_ns,"ctime_ns":v.st_ctime_ns,"nlink":v.st_nlink}
        with resolved.open("rb") as stream:
            digest=hashlib.file_digest(stream,"sha256").hexdigest()
        require(meta(path.lstat())==meta(logical) and meta(resolved.stat())==meta(actual),
                "external library/tool changed during complete read")
        result[value]={"absent":False,"logical":meta(logical),"resolved":str(resolved),
                       "target":meta(actual),"sha256":digest}
    return result


def _diagnostic_value(value):
    if value is None or type(value) in (bool, int, float, str):
        return value
    if type(value) is bytes:
        return {"type": "bytes", "hex": value.hex()}
    if type(value) in (tuple, list):
        return [_diagnostic_value(item) for item in value]
    if isinstance(value, Path):
        return {"type": "path", "value": str(value)}
    return {"type": type(value).__module__ + "." + type(value).__qualname__}

def _denial_trace(kind, phase):
    # Frame metadata and selected primitive arguments only. Do not use
    # traceback/linecache, which would read new source files while guarded.
    frames = []
    current = sys._getframe(1)
    try:
        while current is not None:
            code = current.f_code
            row = {"file": code.co_filename, "function": code.co_name,
                   "line": current.f_lineno}
            if code.co_filename == __file__:
                names = {
                    "audit": ("event", "args", "path", "mode", "flags", "raw", "resolved"),
                    "tracked_open": ("path", "flags", "mode", "dir_fd", "raw", "resolved"),
                    "admitted_fd": ("number", "directory"),
                }.get(code.co_name, ())
                row["arguments"] = {name: _diagnostic_value(current.f_locals[name])
                                    for name in names if name in current.f_locals}
            frames.append(row)
            current = current.f_back
    finally:
        del current
    return {"kind": kind, "phase": phase, "frames": frames}

def guarded(operation, *, roots, foreign_path, external_files=(), diagnostics=None):
    global _AUDIT_DISPATCH_INSTALLED
    require(diagnostics is None or type(diagnostics) is list, "owned diagnostic list required")
    roots = [Path(root).absolute() for root in roots]
    before = snapshot(roots)
    external_before = external_snapshot(external_files)
    owned_paths = {str(root / key.split(":", 1)[1]): row
                   for index, root in enumerate(roots) for key, row in before.items()
                   if key.startswith(str(index) + ":")}
    allowed = {path for path, row in owned_paths.items() if row["sha256"] is not None}
    directories = {path for path, row in owned_paths.items() if stat.S_ISDIR(row["mode"])}
    allowed.update(external_before)
    active = [False]
    denied = []
    diagnostic_phase = ["probes"]
    owned_read_fds = {}
    pending_open = threading.local()
    original_open = os.open

    def refuse(kind):
        denied.append(kind)
        if diagnostics is not None:
            diagnostics.append(_denial_trace(kind, diagnostic_phase[0]))
        raise PermissionError("history-aggregate read-only guard: " + kind)

    def admitted_fd(number, *, directory=False):
        if type(number) is not int or number not in owned_read_fds:
            refuse("foreign-file-descriptor")
        row = owned_read_fds[number]
        try:
            info = os.fstat(number)
            access = fcntl.fcntl(number, fcntl.F_GETFL) & os.O_ACCMODE
        except OSError:
            refuse("foreign-file-descriptor")
        if ((info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)) != row["identity"]
                or access or (directory and not stat.S_ISDIR(info.st_mode))):
            refuse("foreign-file-descriptor")
        return row

    def tracked_open(path, flags, mode=0o777, *, dir_fd=None):
        if not active[0]:
            return original_open(path, flags, mode, dir_fd=dir_fd)
        if not isinstance(path, (str, bytes, os.PathLike)):
            refuse("foreign-file-descriptor")
        raw = os.fsdecode(path)
        if dir_fd is not None and not os.path.isabs(raw):
            parent = admitted_fd(dir_fd, directory=True)
            if any(part in ("", ".", "..") for part in raw.split(os.sep)):
                refuse("noncanonical-descriptor-path")
            resolved = os.path.join(parent["path"], raw)
        else:
            resolved = os.path.abspath(raw)
        previous = getattr(pending_open, "stack", ())
        pending_open.stack = previous + ((raw, flags, resolved),)
        try:
            # Keep the reader's original descriptor-relative syscall. The
            # audit event has no dir_fd field, so the admitted parent is
            # carried only across this exact os.open invocation.
            descriptor = original_open(path, flags, mode, dir_fd=dir_fd)
        finally:
            pending_open.stack = previous
        try:
            info = os.fstat(descriptor)
            expected = owned_paths.get(resolved)
            if expected is None:
                external = external_before.get(resolved)
                expected = None if external is None or external["absent"] else external["target"]
            if (expected is None or
                    (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)) !=
                    (expected["device"], expected["inode"], stat.S_IFMT(expected["mode"]))):
                refuse("opened-path-identity")
            owned_read_fds[descriptor] = {
                "path": resolved,
                "identity": (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode))}
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

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
                # Only current, read-only descriptors obtained through an
                # admitted exact path may be consumed by os.fdopen.
                admitted_fd(path)
            else:
                if not isinstance(path, (str, bytes, os.PathLike)):
                    refuse("foreign-file-descriptor")
                raw = os.fsdecode(path)
                pending = getattr(pending_open, "stack", ())
                if (pending and pending[-1][0] == raw and type(flags) is int
                        and (pending[-1][1] | os.O_CLOEXEC) == (flags | os.O_CLOEXEC)):
                    resolved = pending[-1][2]
                else:
                    resolved = os.path.abspath(raw)
                if resolved in directories:
                    required = os.O_DIRECTORY | os.O_NOFOLLOW
                    if type(flags) is not int or flags & required != required:
                        refuse("unprotected-directory-open")
                elif resolved not in allowed:
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
        diagnostic_phase[0] = "reader"
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
    external_after = external_snapshot(external_files)
    require(external_before == external_after, "external library/tool bytes or metadata changed")
    require(before == after, "read-only reader changed complete bytes or filesystem metadata")
    return {"schema": "hepta.history.aggregate.readonly.v1", "pid": os.getpid(),
        "ppid": os.getppid(), "pgid": os.getpgrp(), "source_bound_guard": True,
        "native_or_rust_executions": 0, "reader_writes": 0, "probes": probes,
        "before": before, "after": after, "external_before": external_before,
        "external_after": external_after, "evidence": result}

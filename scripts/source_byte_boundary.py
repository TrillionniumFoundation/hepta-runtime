"""Bounded, no-follow source-byte intake for exact Git-index qualification.

Do not interpret a Git path string as a filesystem containment boundary: a
tracked regular file may sit below a replaced, untracked symlink directory.
For each Git index path, open one directory at a time from an already-open
worktree root, refuse symlinks at *every* component, and attest the bytes from
the resulting file descriptor. This is not a read-only worktree or OS sandbox.
"""
from __future__ import annotations

import os
from pathlib import Path
import stat

MAX_SOURCE_BYTES = 64 * 1024 * 1024


class UnsafeSourcePath(ValueError):
    """No trustworthy regular source blob was available for this index path."""


def read_indexed_file(worktree: Path, relative: bytes) -> tuple[bytes, int]:
    """Return bounded source bytes and mode from the same no-follow inode.

    Fail closed on unsupported hosts, path aliases, intermediate symlinks,
    FIFOs/devices, hard links or files changing during the read.
    """
    if os.name != "posix" or not all(
        hasattr(os, flag) for flag in ("O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK")
    ):
        raise UnsafeSourcePath("POSIX no-follow directory-descriptor APIs required")
    if not isinstance(relative, bytes):
        raise UnsafeSourcePath("Git index source pathname is not bytes")
    components = relative.split(b"/")
    if any(part in (b"", b".", b"..") for part in components):
        raise UnsafeSourcePath("noncanonical Git source path component")

    dir_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    file_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    dir_fd = None
    try:
        dir_fd = os.open(worktree, dir_flags)
        for component in components[:-1]:
            next_fd = os.open(component, dir_flags, dir_fd=dir_fd)
            os.close(dir_fd)
            dir_fd = next_fd
        file_fd = os.open(components[-1], file_flags, dir_fd=dir_fd)
        with os.fdopen(file_fd, "rb", buffering=0) as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise UnsafeSourcePath("Git source path is not a regular file")
            if before.st_nlink != 1:
                raise UnsafeSourcePath("Git source inode has unreviewed hard links")
            if before.st_size > MAX_SOURCE_BYTES:
                raise UnsafeSourcePath("Git source file exceeds byte cap")
            data = source.read(MAX_SOURCE_BYTES + 1)
            after = os.fstat(source.fileno())
            if len(data) > MAX_SOURCE_BYTES:
                raise UnsafeSourcePath("Git source file grew beyond byte cap")
            if (len(data) != after.st_size or before.st_size != after.st_size
                    or before.st_mtime_ns != after.st_mtime_ns
                    or before.st_ctime_ns != after.st_ctime_ns
                    or before.st_ino != after.st_ino or before.st_dev != after.st_dev):
                raise UnsafeSourcePath("Git source inode changed during byte intake")
            return data, after.st_mode
    except OSError as exc:
        raise UnsafeSourcePath("Git source no-follow descriptor admission failed") from exc
    finally:
        if dir_fd is not None:
            os.close(dir_fd)

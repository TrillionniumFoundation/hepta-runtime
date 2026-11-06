#!/usr/bin/env python3
"""Execute one exact diagnostic ELF. No child, retry, benchmark, or acceptance logic."""
import argparse
import hashlib
import os
import re
import stat
import sys

LIMIT = 256 * 1024 * 1024


def stamp(value):
    return (
        value.st_dev, value.st_ino, value.st_uid, value.st_gid, value.st_mode,
        value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--expected-elf-sha256", required=True)
    parser.add_argument("--mode", choices=("on", "off"), required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("runtime_arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    argv = args.runtime_arguments
    if argv and argv[0] == "--":
        argv = argv[1:]
    if sys.platform != "linux" or os.execve not in os.supports_fd:
        raise RuntimeError("Linux fd-exec support is required")
    if not argv or argv[0] != "mcp":
        raise RuntimeError("explicit original mcp arguments are required")
    if not os.path.isabs(args.binary) or not os.path.isabs(args.output):
        raise RuntimeError("binary and output must be absolute")
    if not re.fullmatch(r"[0-9a-f]{64}", args.expected_elf_sha256):
        raise RuntimeError("expected ELF SHA256 must be lowercase hex")
    descriptor = os.open(
        args.binary, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    )
    try:
        original = os.fstat(descriptor)
        if not stat.S_ISREG(original.st_mode) or not original.st_mode & 0o111:
            raise RuntimeError("binary must be a regular executable")
        if original.st_size < 4 or original.st_size > LIMIT:
            raise RuntimeError("binary size exceeds explicit bounds")
        digest = hashlib.sha256()
        total = 0
        first = True
        while True:
            data = os.read(descriptor, 65536)
            if not data:
                break
            if first and not data.startswith(b"\x7fELF"):
                raise RuntimeError("binary is not an ELF")
            first = False
            total += len(data)
            if total > LIMIT:
                raise RuntimeError("binary grew beyond the bound")
            digest.update(data)
        if total != original.st_size or digest.hexdigest() != args.expected_elf_sha256:
            raise RuntimeError("actual ELF bytes differ from the supplied exact identity")
        if stamp(os.fstat(descriptor)) != stamp(original):
            raise RuntimeError("ELF changed during verification")
        if stamp(os.stat(args.binary, follow_symlinks=False)) != stamp(original):
            raise RuntimeError("named ELF binding changed during verification")
        environment = os.environ.copy()
        environment["HEPTA_RUNTIME_PHASE_COST_MODE"] = args.mode
        environment["HEPTA_RUNTIME_PHASE_COST_OUTPUT"] = args.output
        environment["HEPTA_RUNTIME_PHASE_COST_ELF_SHA256"] = args.expected_elf_sha256
        # Same PID/session/stdio. This does not prove a Cargo feature or prevent
        # an authorized same-inode writer after this check; external custody
        # and original build/source/binary receipts remain necessary.
        os.execve(descriptor, [args.binary, *argv], environment)
    finally:
        os.close(descriptor)


if __name__ == "__main__":
    main()

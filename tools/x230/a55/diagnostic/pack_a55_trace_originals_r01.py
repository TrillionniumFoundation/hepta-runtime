#!/usr/bin/env python3
"""Preserve three completed diagnostic originals; no process or network operations."""
import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import stat

BASE = Path('/home/qian/hepta-runtime-optimization-20261023/a41-phase-timing-20261025-r01')
ROOT = BASE / 'a55-metadata-diagnostic-r01'
OUTPUT = BASE / 'a55-metadata-diagnostic-r01-originals.json.gz'
NAMES = ('report.json', 'metadata-trace.json', 'controller-0-B/stderr.log')
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024
PINS = {
    "controller-0-B/stderr.log": {
        "bytes": 770538,
        "path": "/home/qian/hepta-runtime-optimization-20261023/a41-phase-timing-20261025-r01/a55-metadata-diagnostic-r01/controller-0-B/stderr.log",
        "sha256": "1ccc5766467d3c3578dd9beaa1e628a5d0a301cbbe637587a0bc62a36a0e973a",
        "version": "2053:5574491:770538:1793045509841786407:1793045509841786407"
    },
    "metadata-trace.json": {
        "bytes": 2281630,
        "path": "/home/qian/hepta-runtime-optimization-20261023/a41-phase-timing-20261025-r01/a55-metadata-diagnostic-r01/metadata-trace.json",
        "sha256": "c87694a39753ac382cbbc8821929310069a235a832f236e698ee24f34a442a69",
        "version": "2053:7260143:2281630:1793045555314731098:1793045555314731098"
    },
    "report.json": {
        "bytes": 252970,
        "path": "/home/qian/hepta-runtime-optimization-20261023/a41-phase-timing-20261025-r01/a55-metadata-diagnostic-r01/report.json",
        "sha256": "f68d9e041dfedbbcee2428a2e91a9d8261e71da52c44e778c70c68671518c1c7",
        "version": "2053:7260144:252970:1793045555458730934:1793045555459730933"
    }
}


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def stamp(value):
    # atime may change during an authorized read and is not a mutation fence.
    return [value.st_dev, value.st_ino, value.st_uid, value.st_gid, value.st_mode,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns]


def version(value):
    return ':'.join(str(part) for part in
                    (value.st_dev, value.st_ino, value.st_size,
                     value.st_mtime_ns, value.st_ctime_ns))


def pins_ready():
    if not isinstance(PINS, dict) or set(PINS) != set(NAMES):
        return False
    total = 0
    for name in NAMES:
        row = PINS[name]
        if not isinstance(row, dict) or set(row) != {'path', 'bytes', 'sha256', 'version'}:
            return False
        if row['path'] != str(ROOT / name) or type(row['bytes']) is not int:
            return False
        if not 0 < row['bytes'] <= MAX_FILE_BYTES:
            return False
        digest, token = row['sha256'], row['version']
        if not isinstance(digest, str) or len(digest) != 64:
            return False
        if any(c not in '0123456789abcdef' for c in digest) or not isinstance(token, str):
            return False
        parts = token.split(':')
        if len(parts) != 5 or any(not p or not p.isascii() or not p.isdecimal() for p in parts):
            return False
        if int(parts[2]) != row['bytes']:
            return False
        total += row['bytes']
    return total <= MAX_TOTAL_BYTES


def directory_fence(fd, parent_fd, component, expected=None):
    held = os.fstat(fd)
    named = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
    need(stat.S_ISDIR(held.st_mode) and held.st_uid == os.getuid()
         and not held.st_mode & 0o077, 'diagnostic directory is not private and owned')
    current = stamp(held)
    need(current == stamp(named), 'diagnostic directory path binding changed')
    if expected is not None:
        need(current == expected, 'diagnostic directory changed through capture')
    return current


def read_fixed(directory_fd, component, name):
    need(name in NAMES and component == name.rsplit('/', 1)[-1], 'unplanned original')
    expected = PINS[name]
    fd = os.open(component, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                 dir_fd=directory_fd)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
             and before.st_nlink == 1 and not before.st_mode & 0o077,
             'diagnostic original is not a private single-link regular file')
        need(before.st_size == expected['bytes'] and version(before) == expected['version'],
             'original no longer matches the operator file_info version')
        need(stamp(before) == stamp(os.stat(component, dir_fd=directory_fd,
                                            follow_symlinks=False)), 'original initial name changed')
        raw = bytearray()
        while True:
            block = os.read(fd, min(65536, expected['bytes'] + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
            need(len(raw) <= expected['bytes'], 'diagnostic original grew beyond exact bound')
        raw = bytes(raw)
        need(len(raw) == expected['bytes'] and sha(raw) == expected['sha256'],
             'diagnostic original complete bytes differ')
        need(stamp(before) == stamp(os.fstat(fd))
             == stamp(os.stat(component, dir_fd=directory_fd, follow_symlinks=False)),
             'diagnostic original changed during complete read')
        return raw, {'path': expected['path'], 'bytes': len(raw), 'sha256': sha(raw),
                     'stat9': stamp(before), 'version': version(before)}
    finally:
        os.close(fd)


def create(base_fd, raw):
    fd = os.open(OUTPUT.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                 | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=base_fd)
    try:
        offset = 0
        while offset < len(raw):
            count = os.write(fd, raw[offset:])
            need(count > 0, 'zero-length output write')
            offset += count
        os.fsync(fd)
        current = os.fstat(fd)
        need(current.st_size == len(raw)
             and stamp(current) == stamp(os.stat(OUTPUT.name, dir_fd=base_fd,
                                                  follow_symlinks=False)),
             'transport output changed before receipt')
        receipt = {'path': str(OUTPUT), 'bytes': len(raw), 'sha256': sha(raw),
                   'stat9': stamp(current)}
    finally:
        os.close(fd)
    os.fsync(base_fd)
    return receipt


def main():
    need(pins_ready(), 'three actual original identities required before any file read or write')
    os.umask(0o077)
    need(BASE.resolve(strict=True) == BASE, 'output parent path contains a symlink')
    base_fd = os.open(BASE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    opened = []
    try:
        base_stat = os.fstat(base_fd)
        need(stat.S_ISDIR(base_stat.st_mode) and base_stat.st_uid == os.getuid(),
             'output parent is not an owned directory')
        need(stamp(base_stat) == stamp(BASE.lstat()), 'output parent binding changed')
        root_fd = os.open(ROOT.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                          | os.O_CLOEXEC, dir_fd=base_fd)
        opened.append(root_fd)
        root_stat = directory_fence(root_fd, base_fd, ROOT.name)
        controller_fd = os.open('controller-0-B', os.O_RDONLY | os.O_DIRECTORY
                                | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root_fd)
        opened.append(controller_fd)
        controller_stat = directory_fence(controller_fd, root_fd, 'controller-0-B')
        located = {name: (controller_fd if '/' in name else root_fd, name.rsplit('/', 1)[-1])
                   for name in NAMES}
        captured = {name: read_fixed(*located[name], name) for name in NAMES}
        for name in NAMES:
            again, receipt = read_fixed(*located[name], name)
            need(again == captured[name][0] and receipt == captured[name][1],
                 'diagnostic original differs on the second complete read')
        directory_fence(controller_fd, root_fd, 'controller-0-B', controller_stat)
        directory_fence(root_fd, base_fd, ROOT.name, root_stat)
        need(stamp(base_stat) == stamp(os.fstat(base_fd)) == stamp(BASE.lstat()),
             'output parent changed before publication')
        bundle = {'schema': 'hepta-a55-diagnostic-three-originals-transport/v1',
                  'root': str(ROOT), 'scope': 'three completed originals; transport only',
                  'semantic_trace_acceptance_evaluated': False,
                  'directory_stat9': {'root': root_stat, 'controller-0-B': controller_stat},
                  'files': {name: {**receipt, 'base64': base64.b64encode(raw).decode('ascii')}
                            for name, (raw, receipt) in captured.items()}}
        expanded = (json.dumps(bundle, sort_keys=True, separators=(',', ':')) + '\n').encode()
        packed = gzip.compress(expanded, mtime=0)
        output = create(base_fd, packed)
        print(json.dumps({'captured': True, 'files': len(captured), 'evidence': output,
                          'source_bytes': sum(len(raw) for raw, _ in captured.values()),
                          'expanded_bytes': len(expanded), 'expanded_sha256': sha(expanded),
                          'semantic_trace_acceptance_evaluated': False,
                          'business_launches': 0, 'child_executions': 0, 'network_operations': 0,
                          'signals': 0}, sort_keys=True), flush=True)
    finally:
        for fd in reversed(opened):
            os.close(fd)
        os.close(base_fd)


if __name__ == '__main__':
    main()

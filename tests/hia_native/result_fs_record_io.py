# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Compare actual native and original filesystem effects in owned directories."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import socket
import stat
import struct
import subprocess
import sys
import time
import traceback

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
ENCODE = lambda value: (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def setup(root, row):
    root.mkdir(mode=0o700)
    for name, spec in row['files'].items():
        assert '/' not in name and name not in ('.', '..')
        path = root / name;kind = spec['kind']
        if kind == 'hardlink':continue
        if kind == 'file':path.write_bytes(bytes.fromhex(spec['data']))
        elif kind == 'directory':path.mkdir()
        elif kind == 'fifo':os.mkfifo(path)
        elif kind == 'socket':
            previous = os.open('.', os.O_PATH | os.O_CLOEXEC)
            try:
                os.chdir(root)
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:server.bind('.socket-setup')
                os.rename('.socket-setup', name)
            finally:
                os.fchdir(previous);os.close(previous)
        elif kind == 'symlink':path.symlink_to(spec['target'])
        else:raise AssertionError(spec)
        if kind != 'symlink':path.chmod(spec['mode'])
    for name, spec in row['files'].items():
        if spec['kind'] == 'hardlink':os.link(root / spec['target'], root / name, follow_symlinks=False)
    root.chmod(row.get('directory_mode', 0o700))


def snapshot(root, prior=None):
    rows = {};identities = {}
    for name in sorted(os.listdir(root)):
        path = root / name;value = path.lstat();identity = (value.st_dev, value.st_ino)
        identities[name] = identity
        record = dict(mode=value.st_mode, uid=value.st_uid, gid=value.st_gid, links=value.st_nlink)
        if stat.S_ISREG(value.st_mode):
            record['bytes'] = value.st_size
            try:
                data = path.read_bytes();record['sha256'] = SHA(data);assert len(data) == value.st_size
            except PermissionError as error:record['content_read_errno'] = error.errno
        if stat.S_ISLNK(value.st_mode):record['target'] = os.readlink(path)
        if prior is not None:record['same_inode_as_before'] = identity == prior[name] if name in prior else None
        rows[name] = record
    for name, record in rows.items():record['aliases'] = sorted(n for n, identity in identities.items() if identity == identities[name])
    directory = root.stat()
    return dict(directory_mode=directory.st_mode, directory_uid=directory.st_uid, directory_gid=directory.st_gid,
        entries=rows), identities


def parse(raw):
    position = 0;rows = []
    while position < len(raw):
        assert position + 4 <= len(raw)
        code = struct.unpack_from('<I', raw, position)[0];position += 4
        size = code if code <= 256 << 10 else 0
        assert position + size <= len(raw)
        body = raw[position:position + size];position += size
        if size:
            assert size >= 48
            magic, diagnostic, errno, length, changed, reserved = struct.unpack_from('<8s5Q', body)
            assert magic == b'HRRFO001' and length == size - 48 and changed == reserved == 0
            rows.append(dict(code=code, diagnostic=diagnostic, errno=errno, result_bytes=length,
                output_sha256=SHA(body)))
        else:rows.append(dict(code=code, result_bytes=0))
    return rows


def run_one(executable, root, directory, row, wire):
    directory.mkdir(mode=0o700);setup(root, row)
    before, identities = snapshot(root)
    pins = []
    try:
        for name, identity in identities.items():
            fd = os.open(root / name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
            observed = os.fstat(fd);assert (observed.st_dev, observed.st_ino) == identity
            pins.append((name, fd, identity))
        started = time.monotonic()
        process = subprocess.Popen([str(executable), str(root)], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=dict(os.environ, PATH=''),
            umask=row.get('umask', 0o077))
        timed = False
        try:stdout, stderr = process.communicate(wire, timeout=15)
        except subprocess.TimeoutExpired:
            timed = True;process.kill();stdout, stderr = process.communicate()
        (directory / 'stdout.bin').write_bytes(stdout);(directory / 'stderr.bin').write_bytes(stderr)
        after, _ = snapshot(root, identities)
        for name, fd, identity in pins:
            observed = os.fstat(fd);assert (observed.st_dev, observed.st_ino) == identity
        receipt = dict(command=[str(executable), str(root)], pid=process.pid, exit_code=process.returncode,
            reaped=True, timed_out=timed, timeout_seconds=15, elapsed_seconds=time.monotonic() - started,
            stdin_bytes=len(wire), stdin_sha256=SHA(wire), stdout_bytes=len(stdout), stdout_sha256=SHA(stdout),
            stderr_bytes=len(stderr), stderr_sha256=SHA(stderr), umask=row.get('umask', 0o077),
            path_environment_empty=True, initial_inodes_held_through_after_snapshot=len(pins),
            identity_custody_verified=True)
        result = dict(process=receipt, before=before, after=after)
        (directory / 'observation.json').write_bytes(ENCODE(result))
        assert process.returncode == 0 and not timed and not stderr, receipt
        result['replies'] = parse(stdout)
        assert len(result['replies']) == len(row['operations'])
        return result, stdout
    finally:
        for _, fd, _ in pins:os.close(fd)

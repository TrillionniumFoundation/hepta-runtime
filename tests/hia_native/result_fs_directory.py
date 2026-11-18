# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Compare real original/native directory leases and descriptor-relative path effects."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import select
import socket
import stat
import struct
import subprocess
import sys
import time
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parent))
from result_directory_cases import cases, frame
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
ENCODE = lambda value: (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def parent(root, relative):
    parts = relative.split('/');assert all(part not in ('', '.', '..') for part in parts)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in parts[:-1]:
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd);fd = following
        return fd, parts[-1]
    except BaseException:
        os.close(fd);raise


def setup(root, row):
    root.mkdir(mode=0o700)
    for name, spec in sorted(row['nodes'].items(), key=lambda item: (item[0].count('/'), item[0])):
        fd, basename = parent(root, name)
        try:
            kind = spec['kind']
            if kind == 'directory':os.mkdir(basename, mode=0o700, dir_fd=fd)
            elif kind == 'file':
                handle = os.open(basename, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=fd)
                with os.fdopen(handle, 'wb') as stream:stream.write(bytes.fromhex(spec['data']))
            elif kind == 'fifo':os.mkfifo(basename, mode=0o600, dir_fd=fd)
            elif kind == 'symlink':os.symlink(spec['target'], basename, dir_fd=fd)
            elif kind == 'socket':
                previous = os.open('.', os.O_PATH | os.O_CLOEXEC)
                try:
                    os.fchdir(fd)
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:server.bind('.socket-setup')
                    os.rename('.socket-setup', basename)
                finally:os.fchdir(previous);os.close(previous)
            else:raise AssertionError(kind)
        finally:os.close(fd)
    for name, spec in sorted(row['nodes'].items(), key=lambda item: (-item[0].count('/'), item[0])):
        if spec['kind'] == 'symlink':continue
        fd, basename = parent(root, name)
        try:os.chmod(basename, spec['mode'], dir_fd=fd)
        finally:os.close(fd)


def snapshot(root):
    result = {}
    def walk(fd, prefix):
        for name in sorted(os.listdir(fd)):
            full = prefix + name;metadata = os.stat(name, dir_fd=fd, follow_symlinks=False)
            row = dict(mode=metadata.st_mode, uid=metadata.st_uid, gid=metadata.st_gid, links=metadata.st_nlink)
            result[full] = row
            if stat.S_ISLNK(metadata.st_mode):row['target'] = os.readlink(name, dir_fd=fd)
            elif stat.S_ISREG(metadata.st_mode):
                row['bytes'] = metadata.st_size
                try:
                    handle = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                    with os.fdopen(handle, 'rb') as stream:raw = stream.read()
                    assert len(raw) == metadata.st_size;row['sha256'] = SHA(raw)
                except PermissionError as error:row['content_read_errno'] = error.errno
            elif stat.S_ISDIR(metadata.st_mode):
                try:child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                except PermissionError as error:row['enumeration_errno'] = error.errno;continue
                try:walk(child, full + '/')
                finally:os.close(child)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:walk(fd, '')
    finally:os.close(fd)
    return result


def mutate(root, change):
    action = change['action']
    if action == 'rename':os.rename(root / change['source'], root / change['target'])
    elif action == 'mkdir':os.mkdir(root / change['path'], 0o700)
    elif action == 'rmdir':os.rmdir(root / change['path'])
    elif action == 'chmod':os.chmod(root / change['path'], change['mode'])
    else:raise AssertionError(action)


def read_exact(process, size):
    raw = bytearray();deadline = time.monotonic() + 10
    while len(raw) < size:
        remaining = deadline - time.monotonic();assert remaining > 0, 'owned response deadline'
        assert select.select([process.stdout], [], [], remaining)[0], 'owned response deadline'
        piece = os.read(process.stdout.fileno(), size - len(raw));assert piece, ('early EOF', process.poll())
        raw.extend(piece)
    return bytes(raw)


def held_descriptors(process, root):
    result = []
    assert process.poll() is None
    path = Path('/proc') / str(process.pid) / 'fd'
    for entry in path.iterdir():
        try:metadata = entry.stat()
        except FileNotFoundError:continue
        if not stat.S_ISDIR(metadata.st_mode):continue
        try:
            target = os.readlink(entry)
            assert target.startswith(str(root) + '/')
            target = target.replace(str(root), '@FIXTURE@')
        except OSError as error:
            assert error.errno == 36
            target = '@OWNED_DIRECTORY_PATH_EXCEEDS_PROC_LINK_LIMIT@'
        result.append(dict(fd=int(entry.name), device=metadata.st_dev, inode=metadata.st_ino,
            target=target, links=metadata.st_nlink))
    assert process.poll() is None
    return sorted(result, key=lambda row: row['fd'])


def run(executable, row, directory):
    directory.mkdir(mode=0o700);root = directory / 'fixture';setup(root, row)
    before = snapshot(root);started = time.monotonic();stdout = bytearray();stdin = bytearray()
    process = subprocess.Popen([str(executable)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=dict(os.environ, PATH=''), umask=row.get('umask', 0o077), bufsize=0)
    responses = [];observations = [];leases = {};normalized = bytearray();error = None;stderr = b''
    try:
        for step in row['actions']:
            if 'mutation' in step:
                mutate(root, step['mutation']);observations.append(dict(mutation=step['mutation'], filesystem=snapshot(root)))
                continue
            wire = frame(step['request'], root);stdin.extend(wire)
            process.stdin.write(wire);process.stdin.flush()
            header = read_exact(process, 4);code = struct.unpack('<I', header)[0]
            assert code == 64 or code == 0xffffffff
            body = read_exact(process, 64) if code == 64 else b''
            stdout.extend(header + body);changed = bytearray(body)
            held = held_descriptors(process, root)
            if body:
                magic, diagnostic, errno, lease, device, inode, zero, zero2 = struct.unpack('<8s7Q', body)
                assert magic == b'HRSDR001' and zero == zero2 == 0
                assert len(held) == (1 if lease else 0)
                if diagnostic == 0 and step['request']['op'] != 4:
                    assert lease != 0 and (device, inode) == (held[0]['device'], held[0]['inode'])
                    if lease in leases:assert (device, inode, held[0]['fd']) == leases[lease]
                    else:leases[lease] = (device, inode, held[0]['fd'])
                    struct.pack_into('<QQ', changed, 32, 0, 0)
                else:assert device == inode == 0
                responses.append(dict(code=code, diagnostic=diagnostic, errno=errno, lease=lease,
                    held_target=held[0]['target'] if held else None, held_links=held[0]['links'] if held else None))
            else:responses.append(dict(code=code))
            normalized.extend(header + changed)
            observations.append(dict(response=responses[-1], actual_descriptors=held,
                actual_output_hex=body.hex(), filesystem=snapshot(root)))
        process.stdin.close();process.wait(timeout=10)
        assert not process.stdout.read(), 'unexpected trailing stdout'
        stderr = process.stderr.read();assert process.returncode == 0 and not stderr
        after = snapshot(root)
    except BaseException as caught:
        error = repr(caught);raise
    finally:
        if process.poll() is None:process.kill();process.wait()
        if process.stdout and not process.stdout.closed:stdout.extend(process.stdout.read())
        if process.stderr and not process.stderr.closed:stderr += process.stderr.read()
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream and not stream.closed:stream.close()
        (directory / 'stdin.bin').write_bytes(stdin);(directory / 'stdout.bin').write_bytes(stdout)
        (directory / 'stderr.bin').write_bytes(stderr)
        record = dict(command=[str(executable)], pid=process.pid, exit_code=process.returncode, reaped=True,
            elapsed_seconds=time.monotonic() - started, path_environment_empty=True,
            stdin_bytes=len(stdin), stdin_sha256=SHA(stdin), stdout_bytes=len(stdout), stdout_sha256=SHA(stdout),
            stderr_bytes=len(stderr), stderr_sha256=SHA(stderr),
            error=error, observations=observations)
        (directory / 'process.json').write_bytes(ENCODE(record))
    result = dict(before=before, after=after, responses=responses,
        action_filesystems=[item['filesystem'] for item in observations],
        verified_lease_generations=len(leases), actual_lease_identities_and_descriptors_verified=True)
    (directory / 'comparison.json').write_bytes(ENCODE(result))
    return result, bytes(normalized)

# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Unprivileged, descriptor-relative file operations. No symlink following."""
import json, os, stat, sys, uuid
q = json.load(sys.stdin)
root, path, op = q['root'], q['path'], q['op']
relative = os.path.relpath(path, root)
parts = [] if relative == '.' else relative.split('/')
if any(p in ('', '.', '..') for p in parts):
    raise SystemExit('file path escapes its capability root')
flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
rootfd = os.open(root, flags)
fd = os.dup(rootfd)
result = None
try:
    if op == 'mkdir':
        walk = parts
    else:
        walk = parts[:-1]
    for part in walk:
        if op == 'mkdir':
            try: os.mkdir(part, 0o770, dir_fd=fd)
            except FileExistsError: pass
        child = os.open(part, flags, dir_fd=fd)
        os.close(fd)
        fd = child
    name = parts[-1] if parts else '.'
    if op == 'mkdir':
        result = {'ok': True}
    elif op in ('exists', 'metadata', 'canonicalize'):
        try:
            meta = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISLNK(meta.st_mode): raise ValueError('symlinks are not file capabilities')
            result = {'exists': True, 'path': path, 'size': meta.st_size,
                      'is_dir': stat.S_ISDIR(meta.st_mode), 'is_file': stat.S_ISREG(meta.st_mode),
                      'modified_secs': meta.st_mtime}
        except FileNotFoundError:
            if op != 'exists': raise
            result = {'exists': False}
    elif op == 'read':
        f = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(f, 'rb') as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode): raise ValueError('not a regular file')
            data = stream.read(1048577)
        if len(data) > 1048576: raise ValueError('file exceeds 1 MiB bounded file capability')
        result = {'hex': data.hex()}
    elif op == 'write':
        data = bytes.fromhex(q['hex'])
        if len(data) > 1048576 or not parts: raise ValueError('invalid bounded write')
        temp = '.hepta-write-' + uuid.uuid4().hex
        f = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o660, dir_fd=fd)
        try:
            with os.fdopen(f, 'wb') as stream:
                stream.write(data); stream.flush(); os.fsync(stream.fileno())
            os.replace(temp, name, src_dir_fd=fd, dst_dir_fd=fd)
            os.fsync(fd)
        finally:
            try: os.unlink(temp, dir_fd=fd)
            except FileNotFoundError: pass
        result = {'ok': True}
    elif op == 'remove':
        if not parts: raise ValueError('cannot remove capability root')
        os.unlink(name, dir_fd=fd)
        os.fsync(fd)
        result = {'ok': True}
    elif op == 'list':
        directory = os.open(name, flags, dir_fd=fd)
        try:
            entries = []
            with os.scandir(directory) as it:
                for entry in it:
                    if len(entries) >= 10000: raise ValueError('directory exceeds 10000 entries')
                    m = entry.stat(follow_symlinks=False)
                    entries.append({'name': entry.name, 'size': m.st_size,
                                    'is_dir': stat.S_ISDIR(m.st_mode), 'is_file': stat.S_ISREG(m.st_mode),
                                    'modified_secs': m.st_mtime})
            result = {'entries': sorted(entries, key=lambda e: e['name'])}
        finally: os.close(directory)
    else:
        raise ValueError('unknown file capability')
except FileNotFoundError:
    if op != 'exists': raise
    result = {'exists': False}
finally:
    os.close(fd)
    os.close(rootfd)
print(json.dumps(result, sort_keys=True))

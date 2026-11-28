"""Retain complete owned fixture bytes, then retire only that fixture tree."""
from __future__ import annotations
import gzip
import hashlib
import json
import os
from pathlib import Path
import stat

def snapshot(path):
    """Use directory descriptors so the real >PATH_MAX cwd domain survives."""
    records = []
    def walk(fd, prefix):
        for text in sorted(os.listdir(fd), key=os.fsencode):
            name = os.fsencode(text)
            relative = prefix + name
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            row = {'path_hex': relative.hex(), 'mode': stat.S_IMODE(info.st_mode)}
            if stat.S_ISLNK(info.st_mode):
                row.update(kind='symlink', target_hex=os.fsencode(os.readlink(name, dir_fd=fd)).hex())
            elif stat.S_ISREG(info.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    with os.fdopen(child, 'rb', closefd=False) as stream:
                        raw = stream.read()
                finally:
                    os.close(child)
                row.update(kind='file', bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), data_hex=raw.hex())
            elif stat.S_ISDIR(info.st_mode):
                row['kind'] = 'directory'
                original = row['mode']
                # Only the setup-owned empty mode-000 directory needs this.
                # Restore its exact permission bits before executing either owner.
                if original == 0:
                    os.chmod(name, 0o700, dir_fd=fd, follow_symlinks=False)
                try:
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    try:
                        walk(child, relative + b'/')
                    finally:
                        os.close(child)
                finally:
                    if original == 0:
                        os.chmod(name, original, dir_fd=fd, follow_symlinks=False)
            else:
                raise ValueError('unexpected special file in owned lock fixture')
            records.append(row)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        walk(fd, b'')
    finally:
        os.close(fd)
    return sorted(records, key=lambda row: bytes.fromhex(row['path_hex']))

def retire(path, record_path):
    """Write an exact durable manifest before deleting a qualified test fixture."""
    path, record_path = Path(path), Path(record_path)
    observed = snapshot(path)
    raw = (json.dumps({'schema': 'hepta.runtime.file-lock-fixture.v1', 'path': str(path),
        'entries': observed}, sort_keys=True, separators=(',', ':')) + '\n').encode()
    with gzip.open(record_path, 'xb') as stream:
        stream.write(raw)
    assert gzip.decompress(record_path.read_bytes()) == raw
    def clear(fd):
        for text in os.listdir(fd):
            name = os.fsencode(text)
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                if stat.S_IMODE(info.st_mode) == 0:
                    os.chmod(name, 0o700, dir_fd=fd, follow_symlinks=False)
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    clear(child)
                finally:
                    os.close(child)
                os.rmdir(name, dir_fd=fd)
            else:
                os.unlink(name, dir_fd=fd)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        clear(fd)
    finally:
        os.close(fd)
    path.rmdir()
    packed = record_path.read_bytes()
    return {'file': record_path.name, 'entries': len(observed), 'bytes': len(packed),
        'sha256': hashlib.sha256(packed).hexdigest(), 'raw_bytes': len(raw),
        'raw_sha256': hashlib.sha256(raw).hexdigest(), 'retired': not path.exists()}

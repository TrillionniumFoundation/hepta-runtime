#!/usr/bin/env python3
"""Reconstruct one fixed opaque native-custody archive into a fresh output.

Run from a checkout containing all three adjacent part files. This program only
copies bytes and verifies hashes; it never opens or executes archive members.
On failure any partial output is preserved for inspection.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat

MANIFEST_SHA256 = '1693d87ef1b24d77ca8cf35881a67967dc36f2052337999db610d709033d94e7'
NAMES = ('part-000.bin', 'part-001.bin', 'part-002.bin')
FIELDS = ('st_dev', 'st_ino', 'st_uid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')


def need(value, reason):
    if not value:
        raise RuntimeError(reason)


def stamp(value):
    return tuple(getattr(value, field) for field in FIELDS)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    directory = Path(__file__).resolve().parent
    output = args.output.absolute()
    need(output.parent.resolve(strict=True) == output.parent, 'direct output parent required')
    need(not os.path.lexists(output), 'output already exists; no overwrite is permitted')
    dfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    outfd = None
    try:
        rawfd = os.open('reconstruction-manifest.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dfd)
        try:
            before = os.fstat(rawfd)
            need(stat.S_ISREG(before.st_mode) and before.st_size < 16384, 'ordinary bounded manifest required')
            with os.fdopen(os.dup(rawfd), 'rb') as stream:
                raw = stream.read(16384)
            need(len(raw) == before.st_size and stamp(before) == stamp(os.fstat(rawfd))
                 == stamp(os.stat('reconstruction-manifest.json', dir_fd=dfd, follow_symlinks=False)), 'manifest changed')
        finally:
            os.close(rawfd)
        need(hashlib.sha256(raw).hexdigest() == MANIFEST_SHA256, 'fixed reconstruction manifest hash differs')
        manifest = json.loads(raw)
        need(tuple(row['name'] for row in manifest['parts']) == NAMES, 'fixed three-part order differs')
        expected = manifest['archive']
        whole = hashlib.sha256()
        whole_git = hashlib.sha1(b'blob ' + str(expected['bytes']).encode() + b'\0')
        outfd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        total = 0
        with os.fdopen(os.dup(outfd), 'wb') as target:
            for row in manifest['parts']:
                need(row['offset'] == total and 0 < row['bytes'] <= 6500000, 'part offset/size differs')
                fd = os.open(row['name'], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dfd)
                try:
                    before = os.fstat(fd)
                    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size == row['bytes'],
                         'ordinary exact-size part required')
                    digest = hashlib.sha256()
                    git = hashlib.sha1(b'blob ' + str(row['bytes']).encode() + b'\0')
                    count = 0
                    with os.fdopen(os.dup(fd), 'rb') as stream:
                        while True:
                            block = stream.read(1024 * 1024)
                            if not block:
                                break
                            count += len(block)
                            need(count <= row['bytes'], 'part grew while reading')
                            digest.update(block)
                            git.update(block)
                            whole.update(block)
                            whole_git.update(block)
                            target.write(block)
                    need(count == row['bytes'] and digest.hexdigest() == row['sha256']
                         and git.hexdigest() == row['expected_git_blob_sha1'], 'part content hash differs')
                    need(stamp(before) == stamp(os.fstat(fd))
                         == stamp(os.stat(row['name'], dir_fd=dfd, follow_symlinks=False)), 'part identity changed')
                    total += count
                finally:
                    os.close(fd)
            need(total == expected['bytes'] and whole.hexdigest() == expected['sha256']
                 and whole_git.hexdigest() == expected['expected_local_whole_git_blob_sha1'], 'whole archive identity differs')
            target.flush()
            os.fsync(target.fileno())
        need(os.fstat(outfd).st_size == total and stamp(os.fstat(outfd)) == stamp(output.lstat()),
             'fresh output identity differs')
    finally:
        if outfd is not None:
            os.close(outfd)
        os.close(dfd)
    print(json.dumps({'reconstructed': True, 'output': str(output), 'bytes': total,
                      'sha256': whole.hexdigest(), 'expected_local_whole_git_blob_sha1': whole_git.hexdigest(),
                      'archive_code_executed': False}, sort_keys=True))


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Create the new D1 preparation directory from one pinned local staged archive.

No filesystem extraction, overwrite, cache operation, qualifier, compiler or workload
is invoked. A failed partial installation remains intact and is not retried.
"""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import tarfile

ROOT = Path('/home/qian/hepta-runtime-phase-cost-20261106-d1')
ARCHIVE_BYTES = 334455
ARCHIVE_SHA256 = 'eb6485c00d81803c2379982374ca6fdf4bf1665d58e5d2f2969ea520f2550e41'
MANIFEST_SHA256 = 'd13dcedb008d909073a5d5f60215aacd75ea64b63069722207ed2242bb702ebc'
MAX_EXPANDED = 4 * 1024 * 1024


def identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def pinned_archive(path):
    assert path.is_absolute() and path.resolve() == path
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1
        assert before.st_uid == os.getuid() and before.st_size == ARCHIVE_BYTES
        chunks, total = [], 0
        while total <= ARCHIVE_BYTES:
            part = os.read(descriptor, min(65536, ARCHIVE_BYTES + 1 - total))
            if not part:
                break
            chunks.append(part)
            total += len(part)
        raw = b''.join(chunks)
        fields = ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink',
                  'st_size', 'st_mtime_ns', 'st_ctime_ns')
        stamp = lambda value: tuple(getattr(value, key) for key in fields)
        assert stamp(before) == stamp(os.fstat(descriptor)) == stamp(path.lstat())
    finally:
        os.close(descriptor)
    assert identity(raw) == {'bytes': ARCHIVE_BYTES, 'sha256': ARCHIVE_SHA256}
    return raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', required=True)
    args = parser.parse_args()
    assert not sys.flags.optimize
    assert sys.platform == 'linux' and os.getuid() == 1000
    assert ROOT.parent.resolve() == ROOT.parent and ROOT.parent.stat().st_uid == os.getuid()
    assert not os.path.lexists(ROOT), 'D1 root already exists; do not reuse or overwrite it'
    archive = Path(args.archive).absolute()
    raw = pinned_archive(archive)
    with gzip.GzipFile(fileobj=io.BytesIO(raw), mode='rb') as compressed:
        expanded = compressed.read(MAX_EXPANDED + 1)
    assert len(expanded) <= MAX_EXPANDED
    members, total = {}, 0
    with tarfile.open(fileobj=io.BytesIO(expanded), mode='r:') as tar:
        for row in tar:
            path = PurePosixPath(row.name)
            assert row.isfile() and not row.issym() and not row.islnk()
            assert not path.is_absolute() and '..' not in path.parts and str(path) == row.name
            assert row.name not in members and row.name and len(members) < 64
            assert 0 <= row.size <= 1024 * 1024 and row.mode == 0o600
            stream = tar.extractfile(row)
            content = stream.read(row.size + 1)
            assert len(content) == row.size
            total += len(content)
            assert total <= MAX_EXPANDED
            members[row.name] = content
    assert len(members) == 51 and total == 1320021
    manifest_raw = members['qualification-package-manifest.json']
    assert hashlib.sha256(manifest_raw).hexdigest() == MANIFEST_SHA256
    manifest = json.loads(manifest_raw)
    assert manifest['schema'] == 'hepta-d1-first-qualification-preparation-package/v1'
    assert manifest['sealed'] is True and manifest['host_root'] == str(ROOT)
    assert manifest['file_count_excluding_manifest'] == 50
    assert {row['path'] for row in manifest['files']} == set(members) - {'qualification-package-manifest.json'}
    assert len(manifest['files']) == 50
    for row in manifest['files']:
        assert identity(members[row['path']]) == {key: row[key] for key in ('bytes', 'sha256')}
    assert manifest['d1_qualification_result'] is None
    assert manifest['ordinary_supplemental_result'] is None and manifest['diagnostic_result'] is None
    assert manifest['performance_acceptance_claim'] is False
    # The archive is fully checked before the only root claim. All children
    # are regular create-only files below this newly private directory.
    ROOT.mkdir(mode=0o700)
    installed = {}
    for name, content in sorted(members.items()):
        path = ROOT / name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        assert path.read_bytes() == content
        installed[name] = identity(content)
    receipt = {'schema': 'hepta-d1-qualification-create-only-install/v1',
               'root': str(ROOT), 'archive': {'path': str(archive), **identity(raw)},
               'manifest': identity(manifest_raw), 'members': installed, 'member_count': len(installed),
               'source_package_unchanged': True, 'cache_moved_or_deleted': False,
               'qualifier_or_compiler_started': False, 'automatic_retries': 0,
               'original_archive_preserved': True}
    body = (json.dumps(receipt, indent=2, sort_keys=True) + '\n').encode()
    with (ROOT / 'installation-01.json').open('xb') as stream:
        stream.write(body)
        stream.flush()
        os.fsync(stream.fileno())
    descriptor = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    print(json.dumps({'installed': str(ROOT), 'member_count': len(installed),
                      'installation_receipt': identity(body), 'qualification_started': False}, sort_keys=True))


if __name__ == '__main__':
    main()

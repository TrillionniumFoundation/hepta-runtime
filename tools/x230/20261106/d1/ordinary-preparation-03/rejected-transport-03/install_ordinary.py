#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Install the pinned ordinary supplement create-only under the D1 root.

No compiler, qualifier, verifier or workload is started. The original source,
qualification, exact CI and its original foundation are not write destinations.
The new full-validation foundation and unchanged failed receipts have new paths.
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
ARCHIVE_BYTES = 32282
ARCHIVE_SHA256 = 'dae24aad7cec46bcfd428aa57fa9af3f6814d08724f8db1d50a9c72bbc2c7cca'
MANIFEST_SHA256 = 'd1449e44c0c200edfa7394aecf5fc7db7ae5b7fa07d2b22c3e6ef060a44c9d21'
MAX_EXPANDED = 1024 * 1024
TARGETS = {
    'ordinary-tools-02/launch_ordinary_02.py', 'ordinary-tools-02/qualify_ordinary_02.py',
    'ordinary-tools-02/verify_ordinary_02.py', 'ordinary-tools-02/package-manifest-02.json',
    'ordinary-prerequisites-02.json', 'ordinary-seal-request-02.json',
    'ordinary-seal-manifest-02.json', 'ordinary-launch-command-02.json',
    'ordinary-deployment-manifest-02.json',
    'full-prerequisites-03/d1_prerequisites.py',
    'ordinary-preflight-failure-01/native.json', 'ordinary-preflight-failure-01/read-000.json',
    'ordinary-preflight-failure-01/start.json',
}


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


def create(path, raw):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', required=True)
    args = parser.parse_args()
    assert not sys.flags.optimize
    assert sys.platform == 'linux' and os.getuid() == 1000
    assert ROOT.resolve(strict=True) == ROOT and ROOT.is_dir() and ROOT.stat().st_uid == os.getuid()
    assert not ROOT.stat().st_mode & 0o022
    for name in ('ordinary-tools-02', 'ordinary-installation-started-02.json',
                 'ordinary-installation-02.json', 'ordinary-plan-02.json', 'ordinary-02',
                 'ordinary-postflight-02.json', 'ordinary-verification-input-02.json',
                 'full-prerequisites-03', 'ordinary-preflight-failure-01'):
        assert not os.path.lexists(ROOT / name), 'original ordinary namespace is already occupied: ' + name
    assert all(not os.path.lexists(ROOT / name) for name in TARGETS)
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
            assert row.name in TARGETS and row.name not in members
            assert 0 <= row.size <= MAX_EXPANDED and row.mode == 0o600
            content = tar.extractfile(row).read(row.size + 1)
            assert len(content) == row.size
            total += len(content)
            assert total <= MAX_EXPANDED
            members[row.name] = content
    assert set(members) == TARGETS and len(members) == 13 and total == 121598
    manifest_raw = members['ordinary-deployment-manifest-02.json']
    assert hashlib.sha256(manifest_raw).hexdigest() == MANIFEST_SHA256
    manifest = json.loads(manifest_raw)
    assert manifest['schema'] == 'hepta-d1-ordinary-deployment/v3' and manifest['root'] == str(ROOT)
    assert manifest['file_count_excluding_manifest'] == len(manifest['files']) == 12
    assert {row['path'] for row in manifest['files']} == TARGETS - {'ordinary-deployment-manifest-02.json'}
    for row in manifest['files']:
        assert identity(members[row['path']]) == {key: row[key] for key in ('bytes', 'sha256')}
    assert manifest['ordinary_executed'] is False and manifest['compiler_started'] is False and manifest['performance_acceptance_claim'] is False
    claim = {'schema': 'hepta-d1-ordinary-installation-claim/v3', 'completed': False,
             'archive': {'path': str(archive), **identity(raw)}, 'manifest': identity(manifest_raw),
             'automatic_retries': 0}
    # Exclusive claim closes a duplicate install race before either directory
    # or any destination is created. Interrupted partial output is retained.
    create(ROOT / 'ordinary-installation-started-02.json', (json.dumps(claim, sort_keys=True) + '\n').encode())
    (ROOT / 'ordinary-tools-02').mkdir(mode=0o700)
    (ROOT / 'full-prerequisites-03').mkdir(mode=0o700)
    (ROOT / 'ordinary-preflight-failure-01').mkdir(mode=0o700)
    installed = {}
    for name, content in sorted(members.items()):
        path = ROOT / name
        create(path, content)
        assert path.read_bytes() == content
        installed[name] = identity(content)
    receipt = {'schema': 'hepta-d1-ordinary-create-only-install/v3', 'root': str(ROOT),
               'archive': {'path': str(archive), **identity(raw)}, 'manifest': identity(manifest_raw),
               'members': installed, 'member_count': len(installed),
               'source_qualification_or_ci_files_modified': False, 'cache_moved_or_deleted': False,
               'ordinary_or_compiler_started': False, 'automatic_retries': 0, 'original_archive_preserved': True}
    body = (json.dumps(receipt, indent=2, sort_keys=True) + '\n').encode()
    create(ROOT / 'ordinary-installation-02.json', body)
    for directory in (ROOT / 'ordinary-tools-02', ROOT / 'full-prerequisites-03',
                      ROOT / 'ordinary-preflight-failure-01', ROOT):
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    print(json.dumps({'installed_ordinary_tools': 4, 'original_ci_foundation_modified': False,
                      'installed_new_full_foundation': 1, 'preserved_original_failed_receipts': 3,
                      'installation_receipt': identity(body), 'ordinary_started': False}, sort_keys=True))


if __name__ == '__main__':
    main()

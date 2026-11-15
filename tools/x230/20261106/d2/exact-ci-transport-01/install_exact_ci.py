#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Install one pinned CI package create-only under the already qualified D2 root.

No compiler, qualifier, CI runner, cache operation or workload is started.
Original source and qualification artifacts are not deployment destinations.
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

ROOT = Path('/home/qian/hepta-runtime-validation-cost-20261106-d2')
ARCHIVE_BYTES = 36267
ARCHIVE_SHA256 = '20bcdac7c8bbec18fd45a5fa1412925c3819a77132aa333b0a4886e315c49b3f'
MANIFEST_SHA256 = '2aa7d73896263f9a3c2904209f178ca981e900771ba3fb0dfc4536fa6c02de95'
MAX_EXPANDED = 1024 * 1024
TARGETS = {
    'rust-ci-tools-01/materialize_rust_ci_plan_01.py', 'rust-ci-tools-01/run_rust_ci_01.py',
    'rust-ci-tools-01/launch_exact_rust_ci_01.py', 'rust-ci-tools-01/audit_nextest_0137.py',
    'rust-ci-tools-01/canonical-workflow.yml', 'rust-ci-tools-01/package-manifest-01.json',
    'full-prerequisites-01/d2_prerequisites.py', 'qualification-prerequisites-01.json',
    'rust-ci-actual-pins-01.json', 'rust-ci-seal-manifest-01.json',
    'rust-ci-launch-command-01.json', 'rust-ci-deployment-manifest-01.json',
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
    for name in ('rust-ci-tools-01', 'full-prerequisites-01', 'rust-ci-installation-started-01.json',
                 'rust-ci-installation-01.json', 'rust-ci-plan-01.json', 'rust-ci-01'):
        assert not os.path.lexists(ROOT / name), 'original CI namespace is already occupied: ' + name
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
    assert set(members) == TARGETS and len(members) == 12 and total == 143640
    manifest_raw = members['rust-ci-deployment-manifest-01.json']
    assert hashlib.sha256(manifest_raw).hexdigest() == MANIFEST_SHA256
    manifest = json.loads(manifest_raw)
    assert manifest['schema'] == 'hepta-d2-exact-ci-deployment/v1' and manifest['root'] == str(ROOT)
    assert manifest['file_count_excluding_manifest'] == len(manifest['files']) == 11
    assert {row['path'] for row in manifest['files']} == TARGETS - {'rust-ci-deployment-manifest-01.json'}
    for row in manifest['files']:
        assert identity(members[row['path']]) == {key: row[key] for key in ('bytes', 'sha256')}
    assert manifest['ci_executed'] is False and manifest['performance_acceptance_claim'] is False
    claim = {'schema': 'hepta-d2-exact-ci-installation-claim/v1', 'completed': False,
             'archive': {'path': str(archive), **identity(raw)}, 'manifest': identity(manifest_raw),
             'automatic_retries': 0}
    # Exclusive claim closes a duplicate install race before either directory
    # or any destination is created. Interrupted partial output is retained.
    create(ROOT / 'rust-ci-installation-started-01.json', (json.dumps(claim, sort_keys=True) + '\n').encode())
    (ROOT / 'rust-ci-tools-01').mkdir(mode=0o700)
    (ROOT / 'full-prerequisites-01').mkdir(mode=0o700)
    installed = {}
    for name, content in sorted(members.items()):
        path = ROOT / name
        create(path, content)
        assert path.read_bytes() == content
        installed[name] = identity(content)
    receipt = {'schema': 'hepta-d2-exact-ci-create-only-install/v1', 'root': str(ROOT),
               'archive': {'path': str(archive), **identity(raw)}, 'manifest': identity(manifest_raw),
               'members': installed, 'member_count': len(installed),
               'source_or_qualification_files_modified': False, 'cache_moved_or_deleted': False,
               'ci_or_compiler_started': False, 'automatic_retries': 0, 'original_archive_preserved': True}
    body = (json.dumps(receipt, indent=2, sort_keys=True) + '\n').encode()
    create(ROOT / 'rust-ci-installation-01.json', body)
    for directory in (ROOT / 'rust-ci-tools-01', ROOT / 'full-prerequisites-01', ROOT):
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    print(json.dumps({'installed_ci_tools': 6, 'installed_foundation': 1,
                      'installation_receipt': identity(body), 'ci_started': False}, sort_keys=True))


if __name__ == '__main__':
    main()

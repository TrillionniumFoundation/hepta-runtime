#!/usr/bin/env python3
"""Independently verify exact XZ/tar/member bytes without loading archive code."""
import argparse
import hashlib
import io
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile

NAME = 'native-operations-custody-01.tar.xz'


def identity(body):
    return {'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()}


def stable(path):
    if path.resolve(strict=True) != path:
        raise ValueError('indirect local input')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    fields = ('st_dev', 'st_ino', 'st_uid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= 64 * 1024**2
        body = stream.read(before.st_size + 1)
        after = os.fstat(stream.fileno())
    final = path.lstat()
    assert len(body) == before.st_size and all(getattr(before, k) == getattr(after, k) == getattr(final, k) for k in fields)
    return body, {k: getattr(before, k) for k in fields}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', required=True, type=Path)
    parser.add_argument('--compare-originals', action='store_true')
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    assert not os.path.lexists(args.out)
    archive, _ = stable(args.bundle / NAME)
    declared, _ = stable(args.bundle / 'manifest.json')
    manifest = json.loads(declared)
    assert manifest['schema'] == 'hepta-r26-original-native-custody-bundle/v1'
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=512 * 1024**2)
    expanded = decoder.decompress(archive, max_length=256 * 1024**2 + 1)
    assert len(expanded) <= 256 * 1024**2 and decoder.eof and not decoder.unused_data
    assert decoder.check == lzma.CHECK_SHA256
    rows = manifest['original_files'] + manifest['packaging_support_files']
    expected = {row['archive_path']: row for row in rows}
    assert len(expected) == len(rows)
    observed, bodies = [], {}
    with tarfile.open(fileobj=io.BytesIO(expanded), mode='r:') as tar:
        members = tar.getmembers()
        assert [row.name for row in members] == ['manifest.json'] + sorted(expected)
        for member in members:
            name = PurePosixPath(member.name)
            assert not name.is_absolute() and str(name) == member.name
            assert all(part not in ('', '.', '..') for part in name.parts)
            assert member.type == tarfile.REGTYPE and not member.linkname and not member.pax_headers
            assert member.uid == member.gid == member.mtime == 0
            assert member.mode == 0o644 and member.uname == member.gname == ''
            raw = tar.extractfile(member).read()
            assert len(raw) == member.size
            if member.name == 'manifest.json':
                assert raw == declared
            else:
                row = expected[member.name]
                assert identity(raw) == {k: row[k] for k in ('bytes', 'sha256')}
                if args.compare_originals:
                    original, descriptor = stable(Path(row['source_path']))
                    assert original == raw and descriptor == row['original_identity']
            bodies[member.name] = raw
            observed.append({'archive_path': member.name, **identity(raw)})
        assert len(expanded[tar.offset:]) >= 1024 and not any(expanded[tar.offset:])
    originals = manifest['original_files']
    assert len(originals) == manifest['original_file_count']
    assert sum(row['bytes'] for row in originals) == manifest['original_total_bytes']
    original401 = json.loads(bodies['payload/806ba5f52f94/r26-publication-draft-04-capture-02/tools/x230/20261105/r26/reviews/native-custody-required-04.json'])
    by_path = {row['source_path']: row for row in originals}
    assert len(original401['files']) == manifest['original401_file_count'] == 401
    assert all(row['local_path'] in by_path and all(row[k] == by_path[row['local_path']][k]
               for k in ('bytes', 'sha256')) for row in original401['files'])
    assert all(not any('r28' in part.lower() for part in Path(row['source_path']).parts) for row in originals)
    coverage_rows = [row for row in manifest['packaging_support_files'] if Path(row['source_path']).name.startswith('native-coverage-')]
    assert len(coverage_rows) == 1
    coverage = json.loads(bodies[coverage_rows[0]['archive_path']])
    snapshot_rows = [row for row in manifest['packaging_support_files'] if Path(row['source_path']).name.startswith('input-snapshot-')]
    assert len(snapshot_rows) == 1
    snapshot_raw = bodies[snapshot_rows[0]['archive_path']]
    snapshot = json.loads(snapshot_raw)
    assert snapshot['schema'] == 'hepta-r26-native-custody-input-snapshot/v1'
    assert snapshot['files'] == originals
    assert snapshot['duplicate_companion_bodies'] == manifest['duplicate_companion_bodies']
    assert snapshot['private07_pending_original_read_batches'] == []
    assert coverage['inventory'] == {'path': snapshot_rows[0]['source_path'], **identity(snapshot_raw)}
    if args.compare_originals:
        for relative, declared_paths in snapshot['directory_scope'].items():
            directory = Path('/workspace/scratch/806ba5f52f94') / relative
            assert directory.resolve(strict=True) == directory and directory.is_dir()
            current = []
            for path in sorted(directory.rglob('*')):
                mode = path.lstat().st_mode
                assert stat.S_ISDIR(mode) or stat.S_ISREG(mode)
                if stat.S_ISREG(mode):
                    current.append(str(path))
            assert current == declared_paths
    assert coverage['gaps'] == [] and coverage['job_count'] == len(coverage['jobs']) == 36
    assert coverage['private07_pending_original_read_batches'] == []
    assert sum(v['both_native_streams_lossless'] is True for v in coverage['jobs'].values()) == 35
    unknown = coverage['jobs']['1a1abaf7904-fc05-4fba']
    assert unknown['original_state'] is None and unknown['original_exit_code'] is None
    assert unknown['preserved_launch_unknown_exception'] is True
    assert all(v['original_start_request_binding_present'] is True for v in coverage['jobs'].values())
    assert all(manifest[k] is False for k in ('original_raw_files_reencoded', 'candidate_adopted',
        'all_optimization_blockers_closed', 'archive_code_executed', 'archive_extracted',
        'native_workload_or_SSH_replayed', 'server_binary_byte_fetch_verified'))
    assert manifest['ongoing_R28_excluded'] is True and manifest['R26_candidate_rejected'] is True
    for row in manifest['duplicate_companion_bodies']:
        assert any(all(row[k] == c[k] for k in ('bytes', 'sha256')) for c in manifest['companion_archives'])
    assert len(manifest['companion_archives']) == 7
    completed_proofs = {}
    for label, row in manifest['completed_proofs'].items():
        original = by_path[row['source_path']]
        body = bodies[original['archive_path']]
        assert identity(body) == {k: row[k] for k in ('bytes', 'sha256')}
        completed_proofs[label] = json.loads(body)
        assert completed_proofs[label]['passed'] is True
    companions = {row['repository_path']: row for row in manifest['companion_archives']}
    assert len(companions) == 7
    for row in completed_proofs['six_archive_git_create']['archives']:
        declared_companion = companions[row['repository_path']]
        assert all(declared_companion[k] == row[k] for k in ('bytes', 'sha256', 'git_blob_sha1'))
        assert declared_companion['source_path'] == row['local_path']
        assert declared_companion['server_binary_byte_fetch_verified'] is False
    private_git = completed_proofs['private07_git_create']
    private_companion = companions[private_git['archive']['repository_path']]
    assert all(private_companion[k] == private_git['archive'][k] for k in ('bytes', 'sha256'))
    assert private_companion['git_blob_sha1'] == private_git['git_blob_sha1']
    assert private_companion['original_create_timeout_preserved'] is True
    assert private_git['create_calls'] == 2 and private_git['same_content_reconciliation_calls'] == 1
    assert private_git['automatic_retries'] == 0 and private_git['server_binary_byte_fetch_verified'] is False
    report = {'schema': 'hepta-r26-native-custody-independent-verification/v1', 'passed': True,
        'archive': {'path': str(args.bundle / NAME), **identity(archive),
                    'git_blob_sha1': hashlib.sha1(b'blob ' + str(len(archive)).encode() + b'\0' + archive).hexdigest()},
        'manifest': identity(declared), 'members': observed, 'member_count': len(observed),
        'original_file_count': len(originals), 'all_original401_included': True,
        'xz_sha256_check_and_exact_compressed_end_verified': True,
        'ustar_metadata_all_member_bytes_and_zero_tail_verified': True,
        'original_source_bytes_and_descriptors_compared': args.compare_originals,
        'all_seven_companion_repository_paths_and_git_create_proofs_bound': True,
        'private07_original_create_timeout_and_authorized_reconciliation_preserved': True,
        'native_coverage': manifest['native_coverage'],
        'prior_R25_custody_body_duplicated': False, 'archive_code_executed': False,
        'archive_extracted': False, 'host_calls': 0, 'git_mutations': 0,
        'verifier': {'path': str(Path(__file__).resolve()), **identity(Path(__file__).read_bytes())}}
    with args.out.open('xb') as stream:
        stream.write((json.dumps(report, sort_keys=True, indent=2) + '\n').encode())
    print(json.dumps({k: v for k, v in report.items() if k != 'members'}, sort_keys=True))


if __name__ == '__main__':
    main()

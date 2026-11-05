#!/usr/bin/env python3
"""Build one deterministic archive from the completed fixed local custody inventory."""
import argparse
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import re
import stat
import tarfile

WORK = Path('/workspace/scratch/806ba5f52f94')
HERE = WORK / 'r25-lifecycle-audit/r26-native-custody-final-01'
NAME = 'native-operations-custody-01.tar.xz'
FIELDS = ('st_dev', 'st_ino', 'st_uid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
FIXED_PROOFS = {
    'r26_full_QA': ('benchmark-r26/verified-full-export-02/full-archive-verification-01.json',
                    '46475164121d2d832c658fc8c9a9b417bdc480295a527d989ec70dde7ef0bbfc'),
    'mac_full_QA': ('r25-integration-audit/r26-mac-companion-actual-capture-01/verified-01/independent-verification-01.json',
                    'd77ff03153267a2f1cf7504cc05f14b51897b5a2efe9708c6347d90887f3c380'),
    'formal_cross_package': ('r25-integration-audit/r26-cross-package-verification-01/formal-cross-package-proof-01.json',
                            'bd8652b68fdc5dca3b1bdf6ebcde776f36190dd901bfd4e825992a5d71e75c95'),
    'private_cross_package': ('r25-integration-audit/r26-private-cross-package-verification-01/private-cross-package-proof-01.json',
                             '0bafb73187e5ed01c2b86628874efc8781399fb0d980769c315a9b6d636a3bc8'),
    'six_archive_git_create': ('r25-integration-audit/r26-six-archive-blob-publication-01/publication-proof-01.json',
                              '66e5a7a9b3e2d4c6bfe31f4499134b2cc746f06a25cee7ebb0c237718e027f62'),
    'private07_git_create': ('r25-integration-audit/private07-blob-publication-01/publication-proof-01.json',
                            '2a30b79d0e5a9cb44a2b6b06028340ad8acaf1f5fa3557c8aac9bbdf9a3b5906'),
}
PRIVATE_QA = WORK / 'r25-capacity-audit/actual-private-export-07/full-verification-01.json'
PRIVATE_ARCHIVE = WORK / 'r25-capacity-audit/actual-private-export-07/assembled-01/private-diagnostic-full-07.tar.gz'
PRIVATE_SHA = '4292ad42e87728630f4a6d9a42a34a8447836f20b07ce095415f91c0f897d1bd'


def need(value, reason):
    if not value:
        raise ValueError(reason)


def digest(body):
    return {'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()}


def stamp(value):
    return {name: getattr(value, name) for name in FIELDS}


def frozen(path, expected=None):
    need(path.is_absolute() and path.resolve(strict=True) == path, 'direct original path required: ' + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= 32 * 1024**2,
             'unsafe original file: ' + str(path))
        body = stream.read(before.st_size + 1)
        need(len(body) == before.st_size and stamp(before) == stamp(os.fstat(stream.fileno())),
             'original descriptor changed: ' + str(path))
    need(stamp(before) == stamp(path.lstat()), 'original path changed: ' + str(path))
    record = {'source_path': str(path), **digest(body), 'original_identity': stamp(before)}
    if expected is not None:
        need(all(record[key] == expected[key] for key in ('source_path', 'bytes', 'sha256', 'original_identity')),
             'original differs from frozen inventory: ' + str(path))
    return body, record


def directory_scope(index):
    for relative, expected in index['directory_scope'].items():
        root = WORK / relative
        need(root.resolve(strict=True) == root and root.is_dir(), 'original evidence root changed')
        actual = []
        for path in sorted(root.rglob('*')):
            mode = path.lstat().st_mode
            need(stat.S_ISDIR(mode) or stat.S_ISREG(mode), 'unexpected file type in original evidence scope')
            if stat.S_ISREG(mode):
                actual.append(str(path))
        need(actual == expected, 'original evidence inventory changed: ' + relative)


def add(tar, name, body):
    member = tarfile.TarInfo(name)
    member.size, member.mode, member.uid, member.gid, member.mtime = len(body), 0o644, 0, 0, 0
    member.uname = member.gname = ''
    tar.addfile(member, io.BytesIO(body))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', required=True, type=Path)
    parser.add_argument('--coverage', required=True, type=Path)
    parser.add_argument('--private-qa-sha256', required=True)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    need(re.fullmatch(r'[0-9a-f]{64}', args.private_qa_sha256), 'actual complete private07 QA pin required')
    need(args.out.is_absolute() and args.out.parent.resolve(strict=True) == args.out.parent
         and args.out.parent == HERE and not os.path.lexists(args.out), 'fresh fixed local artifact output required')
    index_raw, index_identity = frozen(args.inventory)
    coverage_raw, coverage_identity = frozen(args.coverage)
    index, coverage = json.loads(index_raw), json.loads(coverage_raw)
    need(index['schema'] == 'hepta-r26-native-custody-input-snapshot/v1'
         and index['original401_count'] == 401 and index['all_original401_bytes_matched'] is True
         and index['ongoing_R28_excluded'] is True
         and index['private07_pending_original_read_batches'] == [], 'complete fixed original snapshot required')
    need(coverage['inventory'] == {'path': str(args.inventory), **digest(index_raw)}
         and coverage['gaps'] == [] and coverage['all_observed_native_operations_accounted_for'] is True
         and coverage['private07_pending_original_read_batches'] == []
         and coverage['job_count'] == len(coverage['jobs']) == 36, 'complete original native coverage required')
    unknown = coverage['jobs']['1a1abaf7904-fc05-4fba']
    need(unknown['preserved_launch_unknown_exception'] is True and unknown['original_state'] is None
         and unknown['original_exit_code'] is None and unknown['original_start_request_binding_present'] is True,
         'original unknown installation was promoted')
    need(sum(row['both_native_streams_lossless'] is True for row in coverage['jobs'].values()) == 35
         and all(row['original_start_request_binding_present'] is True for row in coverage['jobs'].values()),
         'original start/request or full native streams missing')
    directory_scope(index)
    members, original_records = {}, []
    seen_paths = set()
    for row in index['files']:
        path = Path(row['source_path'])
        need(path not in seen_paths and not any('r28' in part.lower() for part in path.parts),
             'duplicate path or ongoing R28 entered fixed scope')
        seen_paths.add(path)
        body, actual = frozen(path, row)
        need(row['archive_path'] == 'payload/' + path.relative_to('/workspace/scratch').as_posix(),
             'original archive name differs')
        need(not body.startswith(b'\x7fELF'), 'ELF bodies are outside native custody scope')
        members[row['archive_path']] = body
        original_records.append(row)
    old = json.loads(members['payload/806ba5f52f94/r26-publication-draft-04-capture-02/tools/x230/20261105/r26/reviews/native-custody-required-04.json'])
    by_path = {row['source_path']: row for row in original_records}
    need(all(row['local_path'] in by_path and all(row[key] == by_path[row['local_path']][key]
             for key in ('bytes', 'sha256')) for row in old['files']), 'one of the original401 bodies was omitted')
    proof_records, proof_values = {}, {}
    for label, (relative, expected_sha) in FIXED_PROOFS.items():
        body, record = frozen(WORK / relative)
        need(record['sha256'] == expected_sha, 'fixed completed proof differs: ' + label)
        need(record['source_path'] in by_path, 'completed proof must be in the payload: ' + label)
        value = json.loads(body)
        need(value['passed'] is True, 'completed companion proof failed: ' + label)
        proof_records[label], proof_values[label] = record, value
    private_raw, private_record = frozen(PRIVATE_QA)
    private = json.loads(private_raw)
    need(private_record['sha256'] == args.private_qa_sha256 and private_record['source_path'] in by_path,
         'actual full private07 QA not bound in original scope')
    need(private['schema'] == 'hepta-private07-independent-downloaded-archive-verification/v1'
         and private['passed'] is True and private['original_outcomes_preserved'] is True
         and private['original_unknown_installation_preserved'] is True
         and private['capacity_attribution_allowed'] is False
         and private['archive_code_executed'] is False and private['archives_extracted'] is False,
         'full private07 consumer or negative-outcome preservation missing')
    private_body, private_archive = frozen(PRIVATE_ARCHIVE)
    need(digest(private_body) == {'bytes': 7150445, 'sha256': PRIVATE_SHA}
         and all(private['archive'][key] == private_archive[key] for key in ('bytes', 'sha256')),
         'actual completed private07 archive differs')
    proof_records['private07_full_QA'] = private_record
    blobs = proof_values['six_archive_git_create']
    need(len(blobs['archives']) == 6 and blobs['server_binary_byte_fetch_verified'] is False
         and blobs['git_tree_commit_ref_or_PR_mutations'] == 0,
         'original Git create scope or absent binary readback claim changed')
    companion_archives = []
    for row in blobs['archives']:
        body, actual = frozen(Path(row['local_path']))
        git_sha = hashlib.sha1(b'blob ' + str(len(body)).encode() + b'\0' + body).hexdigest()
        need(all(actual[k] == row[k] for k in ('bytes', 'sha256'))
             and git_sha == row['expected_git_blob_sha1'] == row['git_blob_sha1']
             and row['server_binary_byte_fetch_verified'] is False,
             'separately published companion identity differs')
        companion_archives.append({'repository_path': row['repository_path'], **actual,
            'git_blob_sha1': git_sha, 'git_create_response_bound': True,
            'server_binary_byte_fetch_verified': False, 'body_duplicated_here': False})
    private_git = proof_values['private07_git_create']
    private_git_sha = hashlib.sha1(b'blob ' + str(len(private_body)).encode() + b'\0' + private_body).hexdigest()
    need(private_git['schema'] == 'hepta-private07-git-blob-publication-proof/v1'
         and all(private_git['archive'][k] == private_archive[k] for k in ('bytes', 'sha256'))
         and private_git['archive']['local_path'] == private_archive['source_path']
         and private_git['archive']['repository_path'] == 'tools/x230/20261105/r25/evidence/private-diagnostic-full-07.tar.gz'
         and private_git_sha == private_git['archive']['expected_git_blob_sha1'] == private_git['git_blob_sha1']
         and private_git['create_calls'] == 2 and private_git['same_content_reconciliation_calls'] == 1
         and private_git['automatic_retries'] == 0 and private_git['create_tool_argument_fields_equal'] is True
         and private_git['server_binary_byte_fetch_verified'] is False
         and private_git['git_tree_commit_ref_or_PR_mutations'] == 0,
         'private07 original timeout and authorized same-content reconciliation binding differs')
    companion_archives.append({'repository_path': private_git['archive']['repository_path'],
        **private_archive, 'git_blob_sha1': private_git_sha, 'git_create_response_bound': True,
        'original_create_timeout_preserved': True, 'authorized_same_content_reconciliation_calls': 1,
        'server_binary_byte_fetch_verified': False, 'body_duplicated_here': False})
    for omission in index['duplicate_companion_bodies']:
        body, actual = frozen(Path(omission['source_path']), omission)
        need(any(all(actual[k] == row[k] for k in ('bytes', 'sha256')) for row in companion_archives),
             'omitted assembled body is not one of the complete companions')
    previous = index['R25_transfer_custody_external_dependency']
    old_body, _ = frozen(WORK / 'r25-evidence/archive-transfer-custody-02/archive-transfer-custody-02.tar.xz')
    need(all(digest(old_body)[k] == previous[k] for k in ('bytes', 'sha256'))
         and hashlib.sha1(b'blob ' + str(len(old_body)).encode() + b'\0' + old_body).hexdigest() == previous['git_blob_sha1'],
         'previously closed R25 custody reference differs')
    support = []
    for path in (args.inventory, args.coverage, HERE / 'snapshot_inputs_02.py',
                 HERE / 'check_native_custody_01.py', Path(__file__).resolve(),
                 HERE / 'verify_custody_bundle_01.py', HERE / 'README.md'):
        body, record = frozen(path)
        record['archive_path'] = 'meta/' + path.name
        need(record['archive_path'] not in members, 'duplicate packaging support name')
        support.append(record)
        members[record['archive_path']] = body
    manifest = {'schema': 'hepta-r26-original-native-custody-bundle/v1',
        'repository_path': 'tools/x230/20261105/r26/evidence/' + NAME,
        'original401_file_count': 401, 'original_file_count': len(original_records),
        'original_total_bytes': sum(row['bytes'] for row in original_records),
        'original_files': original_records, 'packaging_support_files': support,
        'duplicate_companion_bodies': index['duplicate_companion_bodies'],
        'companion_archives': companion_archives, 'completed_proofs': proof_records,
        'prior_R25_custody_reused_without_body_duplication': previous,
        'native_coverage': {'original_operations': 36, 'strong_terminal_and_complete_dual_streams': 35,
                            'preserved_launch_unknown_operation': '1a1abaf7904-fc05-4fba',
                            'unknown_terminal_inferred': False, 'gaps': []},
        'all_original_raw_files_in_fixed_scope_preserved': True,
        'all_failures_timeouts_and_read_only_retries_in_scope_preserved': True,
        'original_raw_files_reencoded': False, 'ongoing_R28_excluded': True,
        'R26_candidate_rejected': True, 'candidate_adopted': False,
        'all_optimization_blockers_closed': False,
        'archive_code_executed': False, 'archive_extracted': False,
        'native_workload_or_SSH_replayed': False, 'host_calls': 0, 'git_mutations': 0,
        'server_binary_byte_fetch_verified': False,
        'tar_metadata': {'format': 'ustar', 'mode': 0o644, 'uid': 0, 'gid': 0, 'mtime': 0, 'uname': '', 'gname': ''},
        'compression': {'format': 'xz', 'preset': 6, 'check': 'sha256'}}
    encoded = (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode()
    for name in members:
        tarfile.TarInfo(name).tobuf(format=tarfile.USTAR_FORMAT)
    args.out.mkdir(mode=0o700)
    with (args.out / 'manifest.json').open('xb') as stream:
        stream.write(encoded)
    with (args.out / NAME).open('xb') as raw:
        with lzma.LZMAFile(raw, 'w', format=lzma.FORMAT_XZ, check=lzma.CHECK_SHA256, preset=6) as compressed:
            with tarfile.open(fileobj=compressed, mode='w|', format=tarfile.USTAR_FORMAT) as archive:
                add(archive, 'manifest.json', encoded)
                for name, body in sorted(members.items()):
                    add(archive, name, body)
    directory_scope(index)
    for row in original_records + support:
        frozen(Path(row['source_path']), row)
    frozen(args.inventory, index_identity)
    frozen(args.coverage, coverage_identity)
    archive_raw, archive_identity = frozen(args.out / NAME)
    receipt = {'schema': 'hepta-r26-native-custody-build/v1', 'built': True,
        'archive': archive_identity, 'manifest': digest(encoded), 'member_count': len(members) + 1,
        'original_file_count': len(original_records), 'packaging_support_files': len(support),
        'independent_verification_still_required': True, 'all_source_bytes_and_identities_unchanged': True,
        'host_calls': 0, 'git_mutations': 0, 'archive_code_executed': False}
    with (args.out / 'build-receipt.json').open('xb') as stream:
        stream.write((json.dumps(receipt, sort_keys=True, indent=2) + '\n').encode())
    print(json.dumps(receipt, sort_keys=True))


if __name__ == '__main__':
    main()

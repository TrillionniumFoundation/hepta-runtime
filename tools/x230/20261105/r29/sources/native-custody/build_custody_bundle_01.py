#!/usr/bin/env python3
"""Build the fixed R29 original-call bundle only after complete local proofs."""
import argparse
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import stat
import tarfile

WORK = Path('/workspace/scratch/806ba5f52f94')
HERE = WORK / 'r25-integration-audit/r29-native-custody-final-01'
NAME = 'native-operations-custody-01.tar.xz'
FIELDS = ('st_dev', 'st_ino', 'st_uid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')


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
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    need(args.out.is_absolute() and args.out.parent.resolve(strict=True) == args.out.parent
         and args.out.parent == HERE and not os.path.lexists(args.out), 'fresh fixed local artifact output required')
    index_raw, index_identity = frozen(args.inventory)
    coverage_raw, coverage_identity = frozen(args.coverage)
    index, coverage = json.loads(index_raw), json.loads(coverage_raw)
    need(index['schema'] == 'hepta-r29-native-custody-input-snapshot/v1'
         and index['all_three_companions_verified'] is True and index['candidate_adopted'] is False
         and index['original_lifecycle_rejection_preserved'] is True,
         'complete actual R29 snapshot required')
    need(coverage['schema'] == 'hepta-r29-original-native-custody-coverage/v1'
         and coverage['inventory'] == {'path': str(args.inventory), **digest(index_raw)}
         and coverage['gaps'] == [] and coverage['all_observed_native_operations_accounted_for'] is True
         and coverage['all_three_companions_verified'] is True
         and set(coverage['jobs']) == set(index['operation_jobs'])
         and coverage['job_count'] == len(index['operation_jobs'])
         and coverage['explicit_unknown_installation'] is None,
         'complete original native coverage required')
    need(all(row['both_native_streams_lossless'] is True and row['original_start_request_binding_present'] is True
             and row['preserved_launch_unknown_exception'] is False for row in coverage['jobs'].values()),
         'original request, strong terminal or full native streams missing')
    for job_id, declaration in index['operation_jobs'].items():
        observed = coverage['jobs'][job_id]
        need((observed['host'], observed['original_state'], observed['original_exit_code']) ==
             (declaration['host'], declaration['expected_state'], declaration['expected_exit_code']),
             'original native outcome changed')
    need(index['excluded_job'] == '1a1adac31be-fc05-5a9a' and index['excluded_job'] not in coverage['jobs'],
         'separate R30 operation entered R29 qualification/performance evidence')
    directory_scope(index)
    members, original_records, seen_paths = {}, [], set()
    for row in index['files']:
        path = Path(row['source_path'])
        need(path not in seen_paths and not path.is_relative_to(WORK / index['excluded_dependency_root']),
             'duplicate path or excluded dependency task entered fixed scope')
        seen_paths.add(path)
        body, _ = frozen(path, row)
        need(row['archive_path'] == 'payload/' + path.relative_to('/workspace/scratch').as_posix(),
             'original archive name differs')
        need(not body.startswith(b'\x7fELF'), 'ELF bodies are outside native custody scope')
        members[row['archive_path']] = body
        original_records.append(row)
    by_path = {row['source_path']: row for row in original_records}
    proof_records = index['completed_proofs']
    need(set(proof_records) == {'qualification_ci', 'performance', 'mac', 'cross_package'},
         'all actual companion and cross-package proofs are required')
    proof_values = {}
    for label, row in proof_records.items():
        body, _ = frozen(Path(row['source_path']), row)
        need(row['source_path'] in by_path and json.loads(body)['passed'] is True,
             'actual completed proof missing from original payload')
        proof_values[label] = json.loads(body)
    need(proof_values['qualification_ci']['original_negative_outcomes_preserved'] is True
         and proof_values['performance']['original_outcomes_preserved'] is True
         and proof_values['performance']['original_bindings']['campaigns']['observation01']['original_observation_gate_passed'] is True
         and proof_values['performance']['original_bindings']['campaigns']['lifecycle01']['original_normal_lifecycle_gate_passed'] is False
         and proof_values['performance']['original_bindings']['campaigns']['lifecycle01']['saturation_stage_entered'] is False
         and proof_values['mac']['original_negative_outcomes_preserved'] is True
         and proof_values['cross_package']['original_lifecycle_rejection_preserved'] is True
         and proof_values['cross_package']['Mac_wrapper_inner_text_bytes_compared_without_reencoding'] is True,
         'negative or unexecuted original outcomes were promoted')
    companions = index['companion_archives']
    need(set(companions) == {'qualification_ci', 'performance', 'mac'}, 'exact three companion archives required')
    for group, row in companions.items():
        body, _ = frozen(Path(row['source_path']), row)
        need(hashlib.sha1(b'blob ' + str(len(body)).encode() + b'\0' + body).hexdigest() == row['git_blob_sha1_local_only']
             and row['git_object_created_by_this_tool'] is False and row['body_duplicated_here'] is False,
             'companion content identity or publication scope changed')
        need(all(proof_values['cross_package']['archives'][group][k] == row[k] for k in ('bytes', 'sha256')),
             'actual cross-package archive binding differs')
    for omission in index['duplicate_companion_bodies']:
        _, actual = frozen(Path(omission['source_path']), omission)
        need(any(all(actual[k] == row[k] for k in ('source_path', 'bytes', 'sha256')) for row in companions.values()),
             'omitted body is not an exact separately verified companion')
    support = []
    for path in (args.inventory, args.coverage, HERE / 'snapshot_inputs_01.py',
                 HERE / 'check_native_custody_01.py', Path(__file__).resolve(),
                 HERE / 'verify_custody_bundle_01.py', HERE / 'README.md'):
        body, record = frozen(path)
        record['archive_path'] = 'meta/' + path.name
        need(record['archive_path'] not in members, 'duplicate packaging support name')
        support.append(record)
        members[record['archive_path']] = body
    native_summary = {'original_operations': len(coverage['jobs']),
        'strong_terminal_and_complete_dual_streams': len(coverage['jobs']),
        'original_failed_operations': sorted(job for job, row in coverage['jobs'].items()
                                             if row['original_exit_code'] != 0),
        'unknown_terminal_inferred': False, 'gaps': []}
    manifest = {'schema': 'hepta-r29-original-native-custody-bundle/v1',
        'repository_path': 'tools/x230/20261105/r29/evidence/' + NAME,
        'original_file_count': len(original_records), 'original_total_bytes': sum(row['bytes'] for row in original_records),
        'original_files': original_records, 'packaging_support_files': support,
        'duplicate_companion_bodies': index['duplicate_companion_bodies'],
        'companion_archives': companions, 'completed_proofs': proof_records,
        'native_coverage': native_summary,
        'prior_published_evidence_commit': index['prior_published_evidence_commit'],
        'accepted_src_tree': index['accepted_src_tree'],
        'excluded_dependency_task': {'job_id': index['excluded_job'], 'root': index['excluded_dependency_root']},
        'all_original_raw_files_in_fixed_scope_preserved': True,
        'all_failures_timeouts_and_read_only_retries_in_scope_preserved': True,
        'original_raw_files_reencoded': False, 'R29_candidate_rejected': True,
        'candidate_adopted': False, 'all_optimization_blockers_closed': False,
        'archive_code_executed': False, 'archive_extracted': False,
        'native_workload_or_SSH_replayed': False, 'host_calls': 0, 'git_mutations': 0,
        'git_objects_created_by_this_tool': False, 'server_binary_byte_fetch_verified': False,
        'own_pack_verify_and_future_publication_operations_kept_outside_bundle': True,
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
    receipt = {'schema': 'hepta-r29-native-custody-build/v1', 'built': True,
        'archive': archive_identity, 'manifest': digest(encoded), 'member_count': len(members) + 1,
        'original_file_count': len(original_records), 'packaging_support_files': len(support),
        'independent_verification_still_required': True, 'all_source_bytes_and_identities_unchanged': True,
        'host_calls': 0, 'git_mutations': 0, 'archive_code_executed': False}
    with (args.out / 'build-receipt.json').open('xb') as stream:
        stream.write((json.dumps(receipt, sort_keys=True, indent=2) + '\n').encode())
    print(json.dumps(receipt, sort_keys=True))


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Snapshot the fixed R28 custody scope after all three original archive QAs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat

WORK = Path('/workspace/scratch/806ba5f52f94')
HERE = WORK / 'r25-integration-audit/r28-native-custody-preparation-01'
SCOPE = HERE / 'scope-preparation-01.json'
SCOPE_SHA256 = '80e04bf6eb404281207f2b5e1a8ddb3c816dc0ad85c6e2c007569f57bf71875b'
GROUPS = ('qualification_ci', 'performance', 'mac')
ROOTS = {
    'qualification_ci': WORK / 'benchmark-r28/qualification-ci-export-operations-01',
    'performance': WORK / 'benchmark-r28/performance-export-operations-01',
    'mac': WORK / 'benchmark-r28/mac-companion-operations-01',
}
QA_SCHEMAS = {
    'qualification_ci': 'hepta-r28-qualification-ci-independent-verification/v1',
    'performance': 'hepta-r28-performance-independent-verification/v1',
    'mac': 'hepta-r28-mac-companion-independent-verification/v1',
}
EXPORTERS = {
    'qualification_ci': '0878941cf72bf093e09019e82766fa60674ec39447b5858121c91612b9e3dd19',
    'performance': '3aaa6744cf49649fe5a94d0e68489a6edfdee772c04aa8dda14141e3556701fb',
}
NAMES = {'qualification_ci': 'qualification-ci-01.tar.xz',
         'performance': 'performance-01.tar.xz', 'mac': 'formal-holders-01.tar.gz'}
CAPTURE_KEYS = {
    'qualification_ci': 'hepta-r28-qualification-ci-evidence-export-20261105-01',
    'performance': 'hepta-r28-performance-evidence-export-20261105-01',
    'mac': 'hepta-r28-mac-holder-evidence-export-20261105-01',
}
FIELDS = ('st_dev', 'st_ino', 'st_uid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')


def stamp(info):
    return {name: getattr(info, name) for name in FIELDS}


def frozen(path):
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError('direct absolute original path required: ' + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > 32 * 1024**2:
            raise ValueError('unsafe original file: ' + str(path))
        body = stream.read(before.st_size + 1)
        if len(body) != before.st_size or stamp(before) != stamp(os.fstat(stream.fileno())):
            raise ValueError('original changed during read: ' + str(path))
    if stamp(before) != stamp(path.lstat()):
        raise ValueError('original path replaced: ' + str(path))
    return body, {'source_path': str(path), 'bytes': len(body),
                  'sha256': hashlib.sha256(body).hexdigest(), 'original_identity': stamp(before)}


def need(value, reason):
    if not value:
        raise ValueError(reason)


def bound_record(row, root):
    need(isinstance(row, dict) and set(row) == {'local_path', 'bytes', 'sha256'}, 'actual file pin required')
    need(isinstance(row['local_path'], str) and type(row['bytes']) is int
         and isinstance(row['sha256'], str) and re.fullmatch(r'[0-9a-f]{64}', row['sha256']),
         'future or malformed file pin')
    path = Path(row['local_path'])
    need(path.is_relative_to(root), 'actual evidence file is outside its fixed original operation directory')
    body, actual = frozen(path)
    need(all(actual[k] == row[k] for k in ('bytes', 'sha256')), 'actual evidence bytes differ')
    return body, actual


def completed_companions(value, scope):
    need(value['schema'] == 'hepta-r28-completed-companion-bindings/v1'
         and set(value['companions']) == set(GROUPS), 'exact three completed companion bindings required')
    proofs, companions, operations = {}, {}, dict(scope['known_original_operations'])
    for group in GROUPS:
        row = value['companions'][group]
        qa_raw, qa_pin = bound_record(row['independent_verification'], ROOTS[group])
        archive_raw, archive_pin = bound_record(row['archive'], ROOTS[group])
        need(Path(archive_pin['source_path']).name == NAMES[group], 'fixed archive name differs')
        qa = json.loads(qa_raw)
        need(qa.get('schema') == QA_SCHEMAS[group] and qa.get('passed') is True,
             'original full consumer has not passed')
        if group == 'mac':
            need(set(qa['groups']) == {'formal'} and qa['original_negative_outcomes_preserved'] is True
                 and qa['capture_success_is_not_workload_success'] is True
                 and qa['archived_code_executed'] is False and qa['archives_extracted'] is False,
                 'Mac companion widened or lost original outcome semantics')
            declared, job_id = qa['groups']['formal']['archive'], qa['capture_job_id']
        else:
            need(qa['candidate_adopted'] is False and qa['archive_code_executed'] is False
                 and qa['archive_extracted'] is False and qa['exporter_sha256'] == EXPORTERS[group],
                 'full consumer source or preservation flags differ')
            declared, job_id = qa['archive'], qa['original_capture']['job_id']
            if group == 'qualification_ci':
                need(qa['original_negative_outcomes_preserved'] is True
                     and job_id == '1a1acd29fba-fc05-5724', 'qualification/CI original failed attempts lost')
            else:
                need(qa['original_observation_rejection_preserved'] is True
                     and qa['lifecycle_and_saturation_executed'] is False,
                     'actual rejection or unexecuted lifecycle changed')
        need(all(declared[k] == archive_pin[k] for k in ('bytes', 'sha256')),
             'downloaded companion differs from its full consumer proof')
        need(isinstance(job_id, str) and re.fullmatch(r'[0-9a-f]+-[0-9a-f]+-[0-9a-f]+', job_id),
             'actual capture job remains unbound')
        operation = {'job_id': job_id, 'host': 'main' if group == 'mac' else 'x230',
                     'idempotency_key': CAPTURE_KEYS[group], 'expected_state': 'succeeded',
                     'expected_exit_code': 0, 'original_start_paths': []}
        if job_id in operations:
            need(all(operations[job_id][k] == operation[k] for k in
                     ('job_id', 'host', 'idempotency_key', 'expected_state', 'expected_exit_code')),
                 'actual capture conflicts with saved operation')
        else:
            need(group in scope['late_capture_groups'], 'unexpected late native operation')
            operations[job_id] = operation
        proofs[group] = qa_pin
        companions[group] = {**archive_pin,
            'repository_path': scope['prospective_repository_prefix'] + NAMES[group],
            'full_consumer': qa_pin, 'native_capture_job_id': job_id,
            'git_blob_sha1_local_only': hashlib.sha1(b'blob ' + str(len(archive_raw)).encode() + b'\0' + archive_raw).hexdigest(),
            'git_object_created': False, 'body_duplicated_here': False}
    cross_raw, cross_pin = bound_record(value['cross_package_verification'], HERE)
    cross = json.loads(cross_raw)
    need(cross['schema'] == 'hepta-r28-three-companion-cross-verification/v1'
         and cross['passed'] is True and cross['candidate_adopted'] is False
         and cross['original_observation_rejection_preserved'] is True
         and cross['Mac_wrapper_inner_text_bytes_compared_without_reencoding'] is True
         and cross['archive_code_executed'] is False and set(cross['archives']) == set(GROUPS),
         'actual cross-package proof is absent or widened')
    for group in GROUPS:
        need(all(cross['archives'][group][k] == companions[group][k] for k in ('bytes', 'sha256'))
             and all(cross['independent_verifications'][group][k] == proofs[group][k] for k in ('bytes', 'sha256')),
             'cross-package proof refers to other actual archives or QAs')
    proofs['cross_package'] = cross_pin
    need(len(operations) == len(scope['known_original_operations']) + 2,
         'the fixed two remaining original captures are not independently bound')
    return proofs, companions, operations


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--completion', type=Path, required=True)
    parser.add_argument('--completion-sha256', required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    need(args.out.is_absolute() and args.out.parent == HERE and not os.path.lexists(args.out),
         'fresh fixed local snapshot required')
    scope_raw, scope_pin = frozen(SCOPE)
    need(scope_pin['sha256'] == SCOPE_SHA256, 'reviewed fixed scope changed')
    scope = json.loads(scope_raw)
    need(args.completion == HERE / 'completed-companions-01.json', 'fixed actual late-binding file required')
    completion_raw, completion_pin = frozen(args.completion)
    need(re.fullmatch(r'[0-9a-f]{64}', args.completion_sha256)
         and completion_pin['sha256'] == args.completion_sha256, 'actual late-binding identity differs')
    proofs, companions, operations = completed_companions(json.loads(completion_raw), scope)
    selected = {SCOPE: {'fixed_scope'}, args.completion: {'actual_companion_binding'}}
    directory_files = {}
    for relative in scope['roots']:
        directory = WORK / relative
        need(directory.resolve(strict=True) == directory and directory.is_dir(),
             'fixed original evidence directory missing: ' + relative)
        names = []
        for path in sorted(directory.rglob('*')):
            mode = path.lstat().st_mode
            if stat.S_ISDIR(mode):
                continue
            need(stat.S_ISREG(mode) and '__pycache__' not in path.parts,
                 'unexpected file type or generated cache in original scope')
            need(not path.is_relative_to(WORK / scope['fixed_excluded_root']), 'excluded dependency task entered scope')
            names.append(str(path))
            selected.setdefault(path, set()).add('original_evidence_tree:' + relative)
        directory_files[relative] = names
    for relative in scope['extra_files']:
        selected.setdefault(WORK / relative, set()).add('explicit_source_or_proof')
    for record in proofs.values():
        selected.setdefault(Path(record['source_path']), set()).add('actual_completed_QA')
    companion_paths = {row['source_path'] for row in companions.values()}
    records, omissions = [], []
    for path, roles in sorted(selected.items()):
        body, row = frozen(path)
        need(not body.startswith(b'\x7fELF'), 'ELF bodies do not belong in local native custody')
        row['roles'] = sorted(roles)
        if str(path) in companion_paths:
            row['reason'] = 'Exact separately verified companion archive body; original raw transport remains included'
            omissions.append(row)
        else:
            row['archive_path'] = 'payload/' + path.relative_to('/workspace/scratch').as_posix()
            records.append(row)
    result = {'schema': 'hepta-r28-native-custody-input-snapshot/v1',
        'scope': scope_pin, 'completion_binding': completion_pin,
        'files': records, 'directory_scope': directory_files, 'duplicate_companion_bodies': omissions,
        'operation_jobs': operations, 'excluded_job': scope['fixed_excluded_job'],
        'excluded_dependency_root': scope['fixed_excluded_root'],
        'completed_proofs': proofs, 'companion_archives': companions,
        'all_three_companions_verified': True, 'all_native_streams_complete_not_inferred': True,
        'prior_published_evidence_commit': scope['prior_published_commit'],
        'accepted_src_tree': scope['accepted_src_tree'], 'candidate_adopted': False,
        'original_observation_rejection_preserved': True, 'raw_bodies_modified': False,
        'host_calls': 0, 'git_mutations': 0}
    with args.out.open('xb') as stream:
        stream.write((json.dumps(result, sort_keys=True, indent=2) + '\n').encode())
    print(json.dumps({'snapshot': str(args.out), 'files': len(records),
                      'bytes': sum(r['bytes'] for r in records), 'native_operations': len(operations),
                      'final_custody_claimed': False}, sort_keys=True))


if __name__ == '__main__':
    main()

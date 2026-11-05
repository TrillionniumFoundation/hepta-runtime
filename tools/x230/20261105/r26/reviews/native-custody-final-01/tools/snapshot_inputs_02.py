#!/usr/bin/env python3
"""Snapshot only the fixed original R26 evidence scope; no host or Git calls."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat

WORK = Path('/workspace/scratch/806ba5f52f94')
OLD = WORK / 'r26-publication-draft-04-capture-02/tools/x230/20261105/r26/reviews/native-custody-required-04.json'
OLD_SHA = '5a2d4ff9ff6b20ba065cacbb0ecf382c36c6f27e5c480b5a2d9a33d6e020868f'
ROOTS = (
    'benchmark-r26/actual-full-export-02',
    'benchmark-r26/actual-full-export-operations-01',
    'benchmark-r26/actual-full-export-operations-02',
    'benchmark-r26/actual-export-staging-01',
    'benchmark-r26/actual-observation-receipts-01',
    'r25-capacity-audit/actual-private-export-staging-06',
    'r25-capacity-audit/actual-private-export-staging-07',
    'r25-capacity-audit/actual-private-export-operations-06',
    'r25-capacity-audit/actual-private-export-operations-07',
    'r25-capacity-audit/actual-private-export-failed-06',
    'r25-capacity-audit/actual-private-export-07',
    'r25-capacity-audit/mechanism-stage-03',
    'r25-capacity-audit/mechanism-stage-04',
    'r25-capacity-audit/mechanism-stage-05',
    'r25-capacity-audit/mechanism-monitor-stage-02',
    'r25-capacity-audit/mechanism-monitor-03/cost-delivery-02',
    'r25-capacity-audit/mechanism-phase-stage-03',
    'r25-capacity-audit/failed-build-03',
    'r25-capacity-audit/failed-build-04',
    'r25-capacity-audit/phase-failure-02-readback',
    'r25-capacity-audit/diagnostic-export-07',
    'r25-integration-audit/r26-mac-companion-staging-01',
    'r25-integration-audit/r26-mac-companion-fixed-staging-01',
    'r25-integration-audit/r26-mac-companion-actual-input-01',
    'r25-integration-audit/r26-mac-companion-actual-capture-01',
    'r25-integration-audit/r26-mac-companion-local-qa-01',
    'r25-integration-audit/r26-mac-companion-tools-01',
    'r25-integration-audit/r26-cross-package-verification-01',
    'r25-integration-audit/r26-private-cross-package-verification-01',
    'r25-integration-audit/r26-four-archive-transfer-01',
    'r25-capacity-audit/private07-transfer-plan-02',
    'r25-integration-audit/private07-archive-assembly-01',
    'r25-integration-audit/r26-six-archive-blob-publication-01',
    'r25-integration-audit/private07-blob-publication-01',
    'r25-integration-audit/private-diagnostic-export-actual-input-06-02',
    'r25-lifecycle-audit/r26-export-04',
)
EXTRA = (
    'r25-results/diagnostic-04-native-terminal.json',
    'benchmark-r26/verified-full-export-02/full-archive-verification-01.json',
    'r25-integration-audit/r26-companion-custody-01/audit_existing_native_logs_02.py',
    'r25-integration-audit/r26-companion-custody-01/existing-native-log-coverage-02.json',
    'r25-integration-audit/r26-companion-custody-01/existing-native-custody-index-03.json',
    'r25-integration-audit/native-custody-checker-review-01.json',
    'r25-evidence/archive-transfer-custody-02/publication-proof.json',
    'r25-evidence/archive-transfer-custody-02/independent-verification.json',
)
# The actual Mac and private output bodies are separate companion artifacts.
# Raw transfer envelopes, chunks and full consumer proofs remain in the scope.
COMPANIONS = {
    'r25-capacity-audit/actual-private-export-07/assembled-01/private-diagnostic-full-07.tar.gz',
    'r25-integration-audit/r26-mac-companion-actual-capture-01/verified-01/formal-holders-01.tar.gz',
    'r25-integration-audit/r26-mac-companion-actual-capture-01/verified-01/diagnostic-holders-01.tar.gz',
}
FIELDS = ('st_dev', 'st_ino', 'st_uid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')


def stamp(info):
    return {name: getattr(info, name) for name in FIELDS}


def frozen(path):
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError('direct absolute original path required: ' + str(path))
    if any('r28' in part.lower() for part in path.parts):
        raise ValueError('ongoing R28 is outside this custody snapshot')
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if os.path.lexists(args.out):
        raise ValueError('new local snapshot required')
    original_raw, old_identity = frozen(OLD)
    if hashlib.sha256(original_raw).hexdigest() != OLD_SHA:
        raise ValueError('original 401-file inventory changed')
    original = json.loads(original_raw)
    if len(original['files']) != 401:
        raise ValueError('original scope differs')
    selected, old_rows = {OLD: {'fixed_original401_index'}}, {}
    for row in original['files']:
        path = Path(row['local_path'])
        old_rows[path] = row
        selected.setdefault(path, set()).add('fixed_original401_payload')
    directory_files = {}
    for relative in ROOTS:
        directory = WORK / relative
        if directory.resolve(strict=True) != directory or not directory.is_dir():
            raise ValueError('fixed original evidence directory missing: ' + relative)
        names = []
        for path in sorted(directory.rglob('*')):
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                continue
            if not stat.S_ISREG(info.st_mode):
                raise ValueError('nonregular original evidence: ' + str(path))
            if '__pycache__' in path.parts:
                raise ValueError('unexpected generated Python cache in original scope')
            names.append(str(path))
            selected.setdefault(path, set()).add('original_evidence_tree:' + relative)
        directory_files[relative] = names
    for relative in EXTRA:
        selected.setdefault(WORK / relative, set()).add('explicit_source_or_proof')
    records, omissions = [], []
    for path, roles in sorted(selected.items()):
        _, row = frozen(path)
        if path in old_rows and any(row[k] != old_rows[path][k] for k in ('bytes', 'sha256')):
            raise ValueError('original401 body changed: ' + str(path))
        row['roles'] = sorted(roles)
        relative = path.relative_to('/workspace/scratch').as_posix()
        if path.is_relative_to(WORK) and str(path.relative_to(WORK)) in COMPANIONS:
            row['reason'] = 'exact assembled body is a separately verified companion; publication is recorded independently'
            omissions.append(row)
        else:
            row['archive_path'] = 'payload/' + relative
            records.append(row)
    expected_batches = {f'read-batch-{i:03d}.json' for i in range(38)}
    transfer = WORK / 'r25-capacity-audit/actual-private-export-07/transfer-operations'
    present_batches = {p.name for p in transfer.iterdir() if p.is_file()}
    result = {'schema': 'hepta-r26-native-custody-input-snapshot/v1',
        'original401': old_identity, 'original401_count': 401,
        'all_original401_bytes_matched': True, 'files': records,
        'directory_scope': directory_files, 'duplicate_companion_bodies': omissions,
        'private07_pending_original_read_batches': sorted(expected_batches - present_batches),
        'private07_expected_batch_count': 38, 'snapshot_only': True,
        'native_custody_complete_not_inferred': True, 'ongoing_R28_excluded': True,
        'R25_transfer_custody_external_dependency': {
            'repository_path': 'tools/x230/20261105/r25/evidence/archive-transfer-custody-02.tar.xz',
            'bytes': 6631284, 'sha256': 'cb5b1ad088ad300f61390dab27fc4abf285fee18414352ba93997403e4e6738e',
            'git_blob_sha1': 'effcf7defa03a9b3b7e5c494fecc5409279341b3',
            'body_duplicated_here': False},
        'raw_bodies_modified': False, 'host_calls': 0, 'git_mutations': 0}
    with args.out.open('xb') as stream:
        stream.write((json.dumps(result, sort_keys=True, indent=2) + '\n').encode())
    print(json.dumps({'snapshot': str(args.out), 'files': len(records),
                      'bytes': sum(r['bytes'] for r in records),
                      'pending_private_batches': len(result['private07_pending_original_read_batches']),
                      'final_custody_claimed': False}, sort_keys=True))


if __name__ == '__main__':
    main()

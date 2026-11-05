#!/usr/bin/env python3
"""Assemble the fixed private07 archive from original local read envelopes.

This entry does not download, execute archive code, or replace the reviewed
verify_private_diagnostic_07.py consumer. Its output contains exact archive and
embedded manifest bytes for that separate full audit. Failed read envelopes
belong in separate files; the 38 success envelopes use {request, result}.
"""
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import zlib

HERE = Path(__file__).resolve().parent
PLAN_SHA = 'cd7a6e287e21b29018a3d9c01b841679ad464a32b2e9c11d2839af35fb8796b1'
REMOTE = '/home/qian/hepta-runtime-optimization-20261105-r25/mechanism-evidence-export-07'
ARCHIVE_NAME = 'private-diagnostic-full-07.tar.gz'
FIELDS = ('st_dev', 'st_ino', 'st_uid', 'st_mode', 'st_nlink', 'st_size',
          'st_mtime_ns', 'st_ctime_ns')


def need(value, reason):
    if not value:
        raise RuntimeError(reason)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def stamp(value):
    return {key: getattr(value, key) for key in FIELDS}


def pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def load(raw):
    return json.loads(raw, object_pairs_hook=pairs)


def stable_read(path, maximum=1024 * 1024):
    path = Path(path).absolute()
    need(path.resolve(strict=True) == path, 'direct local input required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
             and before.st_nlink == 1 and 0 <= before.st_size <= maximum,
             'unsafe or oversized local input')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(maximum + 1)
        need(len(raw) == before.st_size
             and stamp(before) == stamp(os.fstat(fd)) == stamp(path.lstat()),
             'local original changed while reading')
    finally:
        os.close(fd)
    return {'local_path': str(path), 'bytes': len(raw), 'sha256': digest(raw),
            'descriptor_identity': stamp(before)}, raw


def bound_read(pin, inputs):
    identity, raw = stable_read(pin['local_path'])
    need((identity['bytes'], identity['sha256']) == (pin['bytes'], pin['sha256']),
         'bound input bytes differ')
    inputs.append(identity)
    return load(raw)


def recheck(inputs):
    for expected in inputs:
        identity, _ = stable_read(expected['local_path'])
        need(identity == expected, 'local original changed after validation')


def write_new(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                 | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(os.dup(fd), 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        before = stamp(os.fstat(fd))
        need(before == stamp(path.lstat()) and before['st_size'] == len(raw)
             and stat.S_IMODE(before['st_mode']) == 0o600, 'new output identity differs')
    finally:
        os.close(fd)
    identity, body = stable_read(path, max(len(raw), 1))
    need(identity['descriptor_identity'] == before and body == raw, 'new output readback differs')
    return identity


def embedded_manifest(raw, report_item):
    # A bounded single gzip member is verified here. All original-member and
    # preserved-outcome checks remain the separate reviewed consumer's job.
    size = report_item['archive_verification']['gzip_integrity']['expanded_bytes']
    need(type(size) is int and 0 < size <= 256 * 1024**2, 'unexpected expansion bound')
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    expanded = decoder.decompress(raw, size + 1)
    need(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
         and len(expanded) == size, 'gzip CRC, EOF or expansion identity differs')
    names = set()
    manifest = None
    with tarfile.open(fileobj=io.BytesIO(expanded), mode='r:') as archive:
        for member in archive:
            name = member.name
            safe = PurePosixPath(name)
            need(name and not safe.is_absolute() and str(safe) == name
                 and '..' not in safe.parts and '.' not in safe.parts
                 and '\\' not in name and '\x00' not in name
                 and name not in names and member.isreg(), 'unsafe or duplicate tar member')
            names.add(name)
            if name == '_export-manifest.json':
                expected = report_item['manifest']
                need(member.size == expected['bytes'] and member.size <= 16 * 1024**2,
                     'embedded original manifest size differs')
                stream = archive.extractfile(member)
                need(stream is not None, 'embedded manifest stream missing')
                manifest = stream.read(member.size + 1)
                need(len(manifest) == member.size and digest(manifest) == expected['sha256'],
                     'embedded original manifest bytes differ')
    need(manifest is not None and len(names) == report_item['included_files'] + 1,
         'embedded manifest or member count differs')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--read-dir', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    read_dir = args.read_dir.absolute()
    out = args.out.absolute()
    need(read_dir.resolve(strict=True) == read_dir and read_dir.is_dir(), 'direct read directory required')
    need(out.parent.resolve(strict=True) == out.parent and not os.path.lexists(out),
         'fresh direct output directory required')
    plan_identity, raw = stable_read(HERE / 'plan.json')
    need(plan_identity['sha256'] == PLAN_SHA, 'fixed original transfer plan differs')
    plan = load(raw)
    need(plan['schema'] == 'hepta-private07-fixed-archive-read-plan/v1'
         and plan['batch_count'] == 38 and plan['chunk_count'] == 149
         and len(plan['batches']) == 38, 'fixed batch scope differs')
    own_identity, _ = stable_read(Path(__file__).absolute())
    inputs = [plan_identity, own_identity]
    report = bound_read(plan['source_report'], inputs)
    terminal = bound_read(plan['source_native_terminal'], inputs)
    need(report['schema'] == 'hepta-r25-private-diagnostic-export/v3'
         and report['passed'] is True and report['export_completed'] is True
         and report['no_workload_executed'] is True and report['diagnostic_only'] is True
         and report['production_candidate'] is False and report['capacity_admission_made_here'] is False
         and terminal['job_id'] == plan['source_job_id'] == '1a1ac1a134e-fc05-5238'
         and terminal['state'] == 'succeeded' and type(terminal['exit_code']) is int and terminal['exit_code'] == 0
         and all(terminal[key] is True for key in
                 ('output_complete', 'output_durable', 'terminal_publication_confirmed'))
         and all(terminal[key] is False for key in ('automatic_retry', 'cancelled', 'timed_out')),
         'original export proof differs')
    consumer_pin = plan['required_final_consumer']
    need(consumer_pin['local_path'] == str(HERE.parent.parent / 'r25-capacity-audit/diagnostic-export-07/verify_private_diagnostic_07.py')
         and consumer_pin['bytes'] == 28186
         and consumer_pin['sha256'] == 'b074e409e80d035e47782b25d9b27164d91d0b24b9e0d1320a36266b9013ff30',
         'separate required full consumer differs')
    consumer_identity, _ = stable_read(consumer_pin['local_path'])
    need((consumer_identity['bytes'], consumer_identity['sha256']) == (consumer_pin['bytes'], consumer_pin['sha256']),
         'separate reviewed full consumer source changed')
    inputs.append(consumer_identity)
    manifest = bound_read(plan['source_original_transfer_manifest'], inputs)
    need(manifest['schema'] == 'hepta-r26-lossless-archive-chunks/v1'
         and manifest['encoding'] == 'base64' and manifest['maximum_decoded_chunk_bytes'] == 48000
         and manifest['maximum_text_file_bytes'] == 64000
         and manifest['archive'] == plan['archive'] == report['archive'] == report['transfer']['archive']
         and plan['embedded_original_manifest'] == report['manifest']
         and report['archive']['source_path'] == REMOTE + '/' + ARCHIVE_NAME
         and report['archive']['bytes'] == 7150445
         and report['archive']['sha256'] == '4292ad42e87728630f4a6d9a42a34a8447836f20b07ce095415f91c0f897d1bd'
         and plan['source_original_transfer_manifest']['sha256'] == report['transfer']['manifest']['sha256']
         and plan['source_original_transfer_manifest']['bytes'] == report['transfer']['manifest']['bytes']
         and len(manifest['chunks']) == report['transfer']['chunks'] == 149
         and report['archive_verification']['regular_members'] == report['included_files'] + 1 == 4136,
         'original transfer manifest/report differs')
    expected, offset = [], 0
    for number, chunk in enumerate(manifest['chunks']):
        need(chunk['path'] == f'{REMOTE}/{ARCHIVE_NAME}.chunks/chunk-{number:05d}.b64'
             and chunk['offset'] == offset and type(chunk['bytes']) is int
             and 0 < chunk['bytes'] <= 48000
             and chunk['base64_bytes'] == 4 * ((chunk['bytes'] + 2) // 3) <= 64000,
             'chunk sequence differs')
        expected.append({'chunk_index': number, **chunk})
        offset += chunk['bytes']
    need(len(expected) == 149 and offset == report['archive']['bytes'], 'fixed original chunk total differs')
    body = bytearray()
    read_proofs = []
    for number, batch in enumerate(plan['batches']):
        chunks = expected[number * 4:number * 4 + 4]
        need(batch['batch_index'] == number and batch['chunks'] == chunks, 'batch chunk binding differs')
        request = bound_read(batch['request'], inputs)
        need(request == {'host': 'x230', 'paths': [chunk['path'] for chunk in chunks],
                         'max_file_bytes': 65536, 'max_response_bytes': 262144},
             'exact original batch request differs')
        identity, raw = stable_read(read_dir / f'read-batch-{number:03d}.json')
        envelope = load(raw)
        need(type(envelope) is dict and set(envelope) == {'request', 'result'}
             and envelope['request'] == request, 'original request/result envelope differs')
        result = envelope['result']
        need(type(result) is dict and result.get('isError') is not True
             and type(result.get('content')) is list and len(result['content']) == 1
             and result['content'][0].get('type') == 'text'
             and type(result['content'][0].get('text')) is str, 'successful original text response required')
        dto = load(result['content'][0]['text'])
        need(type(dto) is dict and dto.get('atomic_snapshot') is False
             and dto.get('encoding') == 'utf-8' and dto.get('snapshot_scope') == 'independent_file'
             and dto.get('truncated') is False and type(dto.get('files')) is list
             and len(dto['files']) == len(chunks), 'complete original file response required')
        versions = []
        for current, chunk in zip(dto['files'], chunks, strict=True):
            need(type(current) is dict and set(current) == {'eof', 'path', 'sha256', 'size', 'text', 'version'}
                 and current['path'] == chunk['path'] and current['eof'] is True
                 and type(current['size']) is int and current['size'] == chunk['base64_bytes']
                 and current['sha256'] == chunk['base64_sha256'] and type(current['text']) is str,
                 'original file metadata differs')
            version = current['version']
            need(type(version) is str and re.fullmatch(r'[0-9]+:[0-9]+:[0-9]+:[0-9]+:[0-9]+', version),
                 'original file version is malformed')
            device, inode, size, mtime, ctime = map(int, version.split(':'))
            need(device > 0 and inode > 0 and size == current['size'] and mtime > 0 and ctime > 0,
                 'original file version and size disagree')
            encoded = current['text'].encode('ascii')
            need(len(encoded) == chunk['base64_bytes'] and digest(encoded) == chunk['base64_sha256'],
                 'encoded chunk bytes differ')
            decoded = base64.b64decode(encoded, validate=True)
            need(base64.b64encode(decoded) == encoded and len(decoded) == chunk['bytes']
                 and digest(decoded) == chunk['sha256'], 'decoded chunk bytes differ')
            need(len(body) == chunk['offset'], 'decoded chunk offset differs')
            body.extend(decoded)
            versions.append({'path': current['path'], 'version': version,
                             'bytes': current['size'], 'sha256': current['sha256']})
        inputs.append(identity)
        read_proofs.append({'batch_index': number, 'original_envelope': identity,
                            'original_file_versions': versions})
    whole = bytes(body)
    need(len(whole) == report['archive']['bytes'] and digest(whole) == report['archive']['sha256'],
         'whole original archive differs')
    manifest_raw = embedded_manifest(whole, report)
    recheck(inputs)
    out.mkdir(mode=0o700)
    # Partial output is retained if a write fails. Nothing is overwritten,
    # retried, extracted to paths, or executed.
    outputs = {'archive': write_new(out / ARCHIVE_NAME, whole),
               'manifest': write_new(out / 'manifest.json', manifest_raw)}
    recheck(inputs)
    receipt = {'schema': 'hepta-private07-original-read-envelope-assembly/v1',
               'assembled': True, 'outputs': outputs, 'original_read_batches': read_proofs,
               'original_bound_inputs': inputs, 'source_export_job_id': terminal['job_id'],
               'all_149_encoded_and_decoded_chunks_verified': True,
               'whole_archive_byte_identity_verified': True,
               'original_embedded_manifest_bytes_verified': True,
               'full_archive_consumer_executed': False, 'full_member_and_outcome_QA_passed': False,
               'required_next_consumer': consumer_pin,
               'candidate_adopted': False, 'capacity_attribution_authorized': False,
               'archive_code_executed': False, 'host_rpc_calls': 0,
               'raw_envelopes_modified': False, 'failed_read_envelopes_consumed': False}
    raw = (json.dumps(receipt, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
    identity = write_new(out / 'assembly-receipt-01.json', raw)
    fd = os.open(out, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    print(json.dumps({'assembled': True, 'receipt': identity, 'full_QA_still_required': True}, sort_keys=True))


if __name__ == '__main__':
    main()

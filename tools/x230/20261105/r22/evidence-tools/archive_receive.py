#!/usr/bin/env python3
"""Resume pinned read-only archive transfer; never overwrite source chunks."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re

ROOT = Path('/workspace/scratch/806ba5f52f94')
TRANSFER = ROOT / 'transfer'
IDENTITIES = TRANSFER / 'archive-identities.json'
LIMIT = 65535
NAMES = ('qualification', 'microbenchmark', 'campaign')
CHUNK_NAME = re.compile(r'archive-(qualification|microbenchmark|campaign)-(\d+)(?:-attempt-\d+)?\.json\Z')


def digest(data, algorithm='sha256'):
    return hashlib.new(algorithm, data).hexdigest()


def read_json(path):
    raw = path.read_bytes()
    return json.loads(raw), raw


def write_report(path, doc):
    # Reports are regenerated from the immutable raw responses; they are not evidence inputs.
    path.write_text(json.dumps(doc, sort_keys=True, indent=2) + '\n')


def identities():
    rows, raw = read_json(IDENTITIES)
    assert isinstance(rows, list) and len(rows) == len(NAMES)
    mapped = {r['name']: r for r in rows}
    assert set(mapped) == set(NAMES)
    for name, row in mapped.items():
        assert row['size'] > 0 and re.fullmatch('[0-9a-f]{64}', row['sha256'])
        assert isinstance(row['version'], str) and row['version']
        assert row['path'].endswith('/' + name + '-01.tar.gz')
    return mapped, digest(raw)


def verify_chunk(path, expected, offset):
    assert not path.is_symlink(), 'chunk file is a symlink'
    chunk, raw = read_json(path)
    assert isinstance(chunk, dict), 'not a chunk object'
    assert chunk['path'] == expected['path'], 'path mismatch'
    assert chunk['version'] == expected['version'], 'version mismatch'
    assert chunk['size'] == expected['size'], 'total size mismatch'
    assert type(chunk['offset']) is int and chunk['offset'] == offset, 'offset mismatch'
    assert 0 <= offset < expected['size'] and offset % LIMIT == 0, 'off-grid offset'
    end = min(offset + LIMIT, expected['size'])
    assert type(chunk['next_offset']) is int and chunk['next_offset'] == end, 'next offset mismatch'
    assert type(chunk['eof']) is bool and chunk['eof'] == (end == expected['size']), 'eof mismatch'
    data = base64.b64decode(chunk['data_base64'], validate=True)
    assert len(data) == end - offset, 'decoded length mismatch'
    assert base64.b64encode(data).decode('ascii') == chunk['data_base64'], 'noncanonical base64'
    assert digest(data) == chunk['chunk_sha256'], 'chunk SHA256 mismatch'
    return data, {
        'path': str(path), 'offset': offset, 'bytes': len(data),
        'chunk_sha256': digest(data), 'response_sha256': digest(raw),
        'response_bytes': len(raw),
        'source': 'initial-transfer' if path.parent == TRANSFER else 'resumed-transfer',
    }


def scan():
    ids, receipt_sha = identities()
    chosen = {name: {} for name in NAMES}
    invalid, duplicates = [], []
    files = list(TRANSFER.glob('archive-*.json'))
    for directory in sorted(TRANSFER.glob('archive-resume-*')):
        if directory.is_dir() and not directory.is_symlink():
            files.extend(directory.glob('archive-*.json'))
    for path in sorted(files):
        match = CHUNK_NAME.fullmatch(path.name)
        if not match:
            continue
        name, offset = match[1], int(match[2])
        try:
            data, record = verify_chunk(path, ids[name], offset)
            if offset in chosen[name]:
                existing = chosen[name][offset]
                assert existing['chunk_sha256'] == record['chunk_sha256'], 'conflicting valid duplicate'
                duplicates.append(record)
            else:
                chosen[name][offset] = record
        except (AssertionError, KeyError, TypeError, ValueError, OSError) as exc:
            invalid.append({'path': str(path), 'name': name, 'offset': offset,
                            'error': type(exc).__name__ + ': ' + str(exc),
                            'original_file_preserved': True})
    missing = []
    for name in NAMES:
        for offset in range(0, ids[name]['size'], LIMIT):
            if offset not in chosen[name]:
                missing.append({'name': name, 'offset': offset,
                                'limit': LIMIT, 'expected_version': ids[name]['version'],
                                'path': ids[name]['path']})
    report = {
        'schema': 'hepta-r22-archive-chunk-transfer/v1',
        'input_identity_path': str(IDENTITIES), 'input_identity_sha256': receipt_sha,
        'chunk_limit': LIMIT, 'expected_chunks': sum(len(range(0, r['size'], LIMIT)) for r in ids.values()),
        'valid_selected_chunks': sum(len(r) for r in chosen.values()),
        'complete': not missing,
        'selected': {name: [chosen[name][o] for o in sorted(chosen[name])] for name in NAMES},
        'invalid_response_events': invalid, 'duplicate_valid_responses': duplicates,
        'missing': missing,
        'workload_rerun': False,
    }
    write_report(TRANSFER / 'archive-chunk-progress.json', report)
    return ids, report


def assemble():
    ids, report = scan()
    assert report['complete'], 'missing validated chunks'
    out = ROOT / 'evidence'
    out.mkdir(exist_ok=True)
    artifacts = []
    for name in NAMES:
        expected = ids[name]
        body = bytearray()
        for record in report['selected'][name]:
            data, again = verify_chunk(Path(record['path']), expected, record['offset'])
            assert again == record, 'response changed after scan'
            body.extend(data)
        raw = bytes(body)
        assert len(raw) == expected['size'], 'archive size mismatch'
        assert digest(raw) == expected['sha256'], 'archive SHA256 mismatch'
        target = out / (name + '-01.tar.gz')
        if target.exists():
            assert target.read_bytes() == raw, 'existing assembled archive differs; refusing overwrite'
        else:
            with target.open('xb') as stream:
                stream.write(raw)
        assert digest(target.read_bytes()) == expected['sha256']
        git_sha1 = digest(b'blob ' + str(len(raw)).encode('ascii') + b'\0' + raw, 'sha1')
        artifacts.append({
            'name': name, 'local_path': str(target),
            'repository_path': 'tools/x230/20261105/r22/evidence/' + target.name,
            'bytes': len(raw), 'sha256': digest(raw), 'git_blob_sha1': git_sha1,
            'remote_source_path': expected['path'], 'remote_source_version': expected['version'],
            'chunk_count': len(report['selected'][name]), 'archive_bytes_verified': True,
        })
    result = {'schema': 'hepta-r22-archive-assembly/v1', 'passed': True,
              'input_identity_sha256': report['input_identity_sha256'],
              'archives': artifacts, 'workload_rerun': False}
    write_report(TRANSFER / 'archive-assembly-report.json', result)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=('scan', 'assemble'))
    args = parser.parse_args()
    if args.command == 'assemble':
        print(json.dumps(assemble(), sort_keys=True))
    else:
        _, report = scan()
        print(json.dumps({k: report[k] for k in ('complete', 'expected_chunks', 'valid_selected_chunks', 'invalid_response_events', 'missing')}, sort_keys=True))


if __name__ == '__main__':
    main()

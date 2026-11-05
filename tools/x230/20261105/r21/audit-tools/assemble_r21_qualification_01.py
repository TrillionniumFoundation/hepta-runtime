#!/usr/bin/env python3
"""Assemble only the 46 verified original R21 archive chunks; no remote access."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path

REMOTE = '/home/qian/hepta-runtime-optimization-20261105-r21/export-qualification-01/qualification.tar.gz'
SIZE = 1483427
EXPECTED_SHA = '2cacd53aa32fa1a81620284ca0f0c60a282b1e7bd3ba47b7401a65b8101bd667'
LIMIT = 32768


def need(value, reason):
    if not value:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--chunks-dir', type=Path, required=True)
    parser.add_argument('--expected-version', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    args = parser.parse_args()
    need(not os.path.lexists(args.output) and not os.path.lexists(args.receipt), 'new archive and receipt required')
    offsets = list(range(0, SIZE, LIMIT))
    need(len(offsets) == 46 and {p.name for p in args.chunks_dir.glob('*.bin')}
         == {'%08d.bin' % n for n in offsets}, 'missing/extra chunk bytes')
    need({p.name for p in args.chunks_dir.glob('*.verified.json')}
         == {'%08d.verified.json' % n for n in offsets}, 'missing/extra verified chunk receipts')
    pieces, entries, source_bytes = [], [], {}
    for offset in offsets:
        path = args.chunks_dir / ('%08d.bin' % offset)
        proof_path = args.chunks_dir / ('%08d.verified.json' % offset)
        proof_raw, raw = proof_path.read_bytes(), path.read_bytes()
        proof = json.loads(proof_raw)
        end = min(SIZE, offset + LIMIT)
        need(proof['schema'] == 'hepta-r21-qualification-download-chunk/v1' and proof['verified'] is True
             and proof['offset'] == offset and proof['next_offset'] == end and proof['bytes'] == len(raw) == end - offset
             and proof['version'] == args.expected_version and proof['sha256'] == sha(raw)
             and proof['eof'] is (end == SIZE) and Path(proof['local_path']) == path.absolute(), 'verified chunk differs')
        response_path = Path(proof['response_path'])
        need(response_path.parent == args.chunks_dir.absolute(), 'raw response outside chunk directory')
        response_raw = response_path.read_bytes()
        need(sha(response_raw) == proof['response_sha256'], 'raw response bytes changed')
        response = json.loads(response_raw)
        request, value = response['arguments'], response['result']
        need(request == proof['request'] and request == {'host': 'x230', 'path': REMOTE,
             'expected_version': args.expected_version, 'offset': offset, 'limit': LIMIT}, 'original request differs')
        need(value['path'] == REMOTE and value['version'] == args.expected_version and value['size'] == SIZE
             and value['offset'] == offset and value['next_offset'] == end and value['eof'] is (end == SIZE)
             and value['chunk_sha256'] == sha(raw) and base64.b64decode(value['data_base64'], validate=True) == raw
             and len(value['data_base64']) == 4 * ((len(raw) + 2) // 3), 'original response/payload differs')
        pieces.append(raw)
        entries.append(proof)
        source_bytes.update({path: raw, proof_path: proof_raw, response_path: response_raw})
    archive = b''.join(pieces)
    need(len(archive) == SIZE and sha(archive) == EXPECTED_SHA, 'complete archive identity differs')
    need(all(path.read_bytes() == raw for path, raw in source_bytes.items()), 'download evidence changed while assembling')
    with args.output.open('xb') as stream:
        stream.write(archive)
    need(args.output.read_bytes() == archive, 'saved archive differs')
    receipt = {'schema': 'hepta-r21-qualification-download/v1', 'passed': True,
        'archive': {'path': str(args.output.absolute()), 'bytes': SIZE, 'sha256': EXPECTED_SHA},
        'chunk_count': len(entries), 'chunks': entries, 'version': args.expected_version,
        'all_saved_responses_and_chunks_revalidated': True, 'remote_calls_by_this_tool': 0,
        'remote_inflight_status_evaluated_by_this_tool': False,
        'failure_responses_removed': False, 'automatic_retries': 0}
    with args.receipt.open('x') as stream:
        json.dump(receipt, stream, sort_keys=True, indent=2)
        stream.write('\n')
    print(json.dumps({'passed': True, 'chunk_count': 46, 'archive': receipt['archive'],
                      'receipt_sha256': sha(args.receipt.read_bytes())}, sort_keys=True))


if __name__ == '__main__':
    main()

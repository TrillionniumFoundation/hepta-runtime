#!/usr/bin/env python3
"""Validate one saved R21 binary_read response; this tool never contacts a host."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re

REMOTE = '/home/qian/hepta-runtime-optimization-20261105-r21/export-qualification-01/qualification.tar.gz'
SIZE = 1483427
LIMIT = 32768


def need(value, reason):
    if not value:
        raise ValueError(reason)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--response', type=Path, required=True)
    parser.add_argument('--expected-version', required=True)
    args = parser.parse_args()
    raw_response = args.response.read_bytes()
    response = json.loads(raw_response)
    value, request = response['result'], response['arguments']
    need(request['host'] == 'x230' and value['path'] == request['path'] == REMOTE, 'host/path differs')
    need(value['version'] == request['expected_version'] == args.expected_version
         and len(args.expected_version) > 0, 'observed immutable version differs')
    offset = request['offset']
    need(type(offset) is int and 0 <= offset < SIZE and offset % LIMIT == 0
         and request['limit'] == LIMIT and value['size'] == SIZE and value['offset'] == offset,
         'chunk request/size/offset differs')
    end = min(SIZE, offset + LIMIT)
    need(value['next_offset'] == end and value['eof'] is (end == SIZE), 'chunk boundary/eof differs')
    data = base64.b64decode(value['data_base64'], validate=True)
    need(len(data) == end - offset and len(value['data_base64']) == 4 * ((len(data) + 2) // 3),
         'base64 payload truncated or length differs')
    digest = hashlib.sha256(data).hexdigest()
    need(re.fullmatch('[0-9a-f]{64}', value['chunk_sha256']) and digest == value['chunk_sha256'],
         'chunk full-byte SHA differs')
    output = args.response.parent / ('%08d.bin' % offset)
    receipt_path = args.response.parent / ('%08d.verified.json' % offset)
    need(not output.exists() and not receipt_path.exists(), 'chunk or receipt already exists; preserve previous attempt')
    with output.open('xb') as stream:
        stream.write(data)
    need(output.read_bytes() == data, 'saved chunk differs')
    receipt = {'schema': 'hepta-r21-qualification-download-chunk/v1', 'verified': True,
        'offset': offset, 'next_offset': end, 'bytes': len(data), 'sha256': digest,
        'version': value['version'], 'eof': value['eof'], 'request': request,
        'response_path': str(args.response.absolute()), 'response_sha256': hashlib.sha256(raw_response).hexdigest(),
        'local_path': str(output.absolute()), 'remote_calls_by_this_tool': 0}
    with receipt_path.open('x') as stream:
        json.dump(receipt, stream, sort_keys=True, indent=2)
        stream.write('\n')
    print(json.dumps({k: receipt[k] for k in ('verified', 'offset', 'next_offset', 'bytes', 'sha256')}))


if __name__ == '__main__':
    main()

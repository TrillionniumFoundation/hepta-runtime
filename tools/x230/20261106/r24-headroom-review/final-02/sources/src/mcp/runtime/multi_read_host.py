# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Full-file strict UTF-8 batches; per-file identity checks, no cross-file snapshot.
The native binary helper supplies the same descriptor-relative walk and regular-file
opening used by binary_read. Never dispatch caller-selected binary operations.
"""
import hashlib
import json
import os
import sys

if 'parent' not in globals():
    from binary_file import parent, regular, version

def _batch_path(path):
    if (not isinstance(path, str) or len(path.encode('utf-8')) > 4096 or
            not path.startswith('/') or '\0' in path or
            any(part in ('', '.', '..') for part in path[1:].split('/'))):
        raise ValueError('bounded absolute non-aliased path required')

def _wire_size(result):
    text = json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(',', ':'))
    outer = {'content': [{'type': 'text', 'text': text}], 'isError': False}
    return len(json.dumps(outer, ensure_ascii=False, separators=(',', ':')).encode('utf-8'))

def multi_read(q):
    files = q['files']
    file_limit = q.get('max_file_bytes', 16384)
    response_limit = q.get('max_response_bytes', 65536)
    if (not isinstance(files, list) or not 1 <= len(files) <= 16 or
            type(file_limit) is not int or not 1 <= file_limit <= 65536 or
            type(response_limit) is not int or not 1024 <= response_limit <= 262144):
        raise ValueError('invalid bounded multi-file request')
    seen = set()
    # Validate every path before opening any source.
    for entry in files:
        _batch_path(entry['path'])
        _batch_path(entry['root']) if entry['root'] != '/' else None
        if entry['path'] in seen: raise ValueError('batch paths must be distinct')
        seen.add(entry['path'])
    result = {'files': [], 'atomic_snapshot': False, 'snapshot_scope': 'independent_file',
              'encoding': 'utf-8', 'truncated': False}
    for entry in files:
        fd, name = parent(entry['root'], entry['path'])
        try:
            f = regular(fd, name)
            try:
                before = os.fstat(f)
                if before.st_nlink != 1:
                    raise ValueError('hardlinked files are outside this read capability')
                if before.st_size > file_limit:
                    raise ValueError('file exceeds full-read byte ceiling; use binary_read')
                ver = version(before)
                # A single descriptor and bounded loop handle short reads without truncation.
                parts = []
                remaining = file_limit + 1
                while remaining:
                    part = os.read(f, remaining)
                    if not part: break
                    parts.append(part)
                    remaining -= len(part)
                data = b''.join(parts)
                after = os.fstat(f)
                if version(after) != ver or after.st_nlink != 1 or len(data) != before.st_size:
                    raise ValueError('file changed during full read')
                if len(data) > file_limit:
                    raise ValueError('file exceeds full-read byte ceiling; use binary_read')
                text = data.decode('utf-8', errors='strict')
                # Reopen the descriptor walk: replacement or a symlink inserted after
                # open cannot silently leave the returned path bound to a stale inode.
                confirm, confirm_name = parent(entry['root'], entry['path'])
                try:
                    check = regular(confirm, confirm_name)
                    try:
                        checked = os.fstat(check)
                        if version(checked) != ver or checked.st_nlink != 1:
                            raise ValueError('source path identity changed during read')
                    finally: os.close(check)
                finally: os.close(confirm)
                result['files'].append({'path': entry['path'], 'size': len(data),
                    'version': ver, 'sha256': hashlib.sha256(data).hexdigest(),
                    'text': text, 'eof': True})
                if _wire_size(result) > response_limit:
                    raise ValueError('multi-file response exceeds serialized MCP result byte budget')
            finally: os.close(f)
        finally: os.close(fd)
    return result

def run_multi_read():
    try:
        result = multi_read(json.load(sys.stdin))
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(',', ':')))
    except Exception as exc:
        # Neither partial content nor a traceback with source bytes crosses the boundary.
        print('multi-file read rejected: ' + type(exc).__name__ + ': ' + str(exc), file=sys.stderr)
        raise SystemExit(1)

if __name__ == '__main__':
    run_multi_read()

#!/usr/bin/env python3
"""Verify manifest bytes; never import or execute preserved source."""
import hashlib
import json
from pathlib import Path
import sys
if sys.flags.optimize:
    raise SystemExit('optimized Python is refused')
def require(condition, message):
    if not condition:
        raise ValueError(message)
root = Path(__file__).resolve().parent
manifest = json.loads((root / 'SOURCE_MANIFEST.json').read_text(encoding='utf-8'))
seen = set()
for row in manifest['candidates'] + manifest['notices']:
    path = root / row['relative_path']
    require(path.resolve().is_relative_to(root), 'projection path escaped root')
    raw = path.read_bytes()
    require(len(raw) == row['bytes'], row['relative_path'] + ': size')
    require(hashlib.sha256(raw).hexdigest() == row['sha256'], row['relative_path'] + ': SHA256')
    require(hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == row['git_blob_sha'], row['relative_path'] + ': Git blob')
    require(row['git_blob_sha'] not in seen, 'duplicate object')
    seen.add(row['git_blob_sha'])
require(len(manifest['candidates']) == manifest['candidate_count'], 'candidate count')
print(json.dumps({'candidate_count': len(manifest['candidates']), 'notice_count': len(manifest['notices']), 'all_bytes_match_manifest': True, 'archived_source_executed': False, 'research_or_runtime_qualification': False}))

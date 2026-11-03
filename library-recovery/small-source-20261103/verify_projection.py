#!/usr/bin/env python3
"""Verify archived bytes only; never import or execute the preserved sources."""
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parent
manifest = json.loads((root / 'SOURCE_MANIFEST.json').read_text(encoding='utf-8'))
seen = set()
for row in manifest['sources'] + manifest['notices']:
    path = root / row['relative_path']
    assert path.resolve().is_relative_to(root.resolve())
    data = path.read_bytes()
    assert len(data) == row['bytes'], row['relative_path']
    assert hashlib.sha256(data).hexdigest() == row['sha256'], row['relative_path']
    assert hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() == row['git_blob_sha'], row['relative_path']
    assert row['git_blob_sha'] not in seen, row['relative_path']
    seen.add(row['git_blob_sha'])
assert len(manifest['sources']) == manifest['source_count']
print(json.dumps({'source_count': len(manifest['sources']), 'notice_count': len(manifest['notices']), 'all_bytes_match_manifest': True, 'archived_source_executed': False, 'research_or_runtime_qualification': False}))

#!/usr/bin/env python3
"""Hash the preserved source without importing or executing it."""
import hashlib
import json
from pathlib import Path
import sys
if sys.flags.optimize: raise SystemExit('optimized verification refused')
root = Path(__file__).resolve().parent
manifest = json.loads((root / 'SOURCE_MANIFEST.json').read_bytes())
if len(manifest['objects']) != 1: raise ValueError('unexpected candidate count')
row = manifest['objects'][0]
if row['relative_path'] != 'objects/c09a1f00ef5b5ea14888b48f3aebd8834546d4dd.py': raise ValueError('unexpected source path')
raw = (root / row['relative_path']).read_bytes()
identity = {'git_blob_sha': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
            'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}
if identity != {k: row[k] for k in identity}: raise ValueError('preserved source differs')
print(json.dumps({'candidate_count': 1, 'bytes': len(raw), 'all_bytes_match_manifest': True,
                  'archived_source_executed': False, 'new_runtime_qualification': False}))

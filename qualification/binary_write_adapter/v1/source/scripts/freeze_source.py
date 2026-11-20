#!/usr/bin/env python3
"""Create an exact full source inventory; never overwrite a prior frozen source."""
from pathlib import Path
import hashlib
import json
import stat

root=Path(__file__).resolve().parents[1]
manifest=root/'SOURCE_MANIFEST.json'
if manifest.exists():raise ValueError('source is already frozen')
rows={}
for path in sorted(root.rglob('*')):
    if path.is_symlink():raise ValueError('source symlink')
    if path.is_file():
        raw=path.read_bytes()
        rows[path.relative_to(root).as_posix()]=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),mode=stat.S_IMODE(path.stat().st_mode))
data=dict(schema='hepta.runtime.binary-write-adapter.source.v1',files=rows,compiler_commit='d3e2c90173cf733e42b299d0c4274df4b593a12f',
          compiler_sha256='bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0',public_binary_write_registered=False,whole_runtime_replaced=False)
raw=(json.dumps(data,sort_keys=True,indent=2)+'\n').encode();manifest.write_bytes(raw)
print(json.dumps(dict(files=len(rows),manifest_sha256=hashlib.sha256(raw).hexdigest(),source_bytes=sum(row['bytes']for row in rows.values())),sort_keys=True))

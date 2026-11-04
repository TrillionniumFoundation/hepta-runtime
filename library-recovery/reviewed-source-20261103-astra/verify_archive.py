#!/usr/bin/env python3
from pathlib import Path
import hashlib,json,tarfile
p=Path(__file__).resolve().parent
m=json.loads((p/'SOURCE_MANIFEST.json').read_text());v=json.loads((p/'LOCAL_VERIFICATION.json').read_text())
def identity(b):return dict(size_bytes=len(b),sha256=hashlib.sha256(b).hexdigest(),git_blob_sha1=hashlib.sha1(f'blob {len(b)}\0'.encode()+b).hexdigest())
assert identity((p/v['source_archive']).read_bytes())==v['source_archive_hashes']
with tarfile.open(p/v['source_archive'],'r:gz') as t:
 assert len(t.getmembers())==len(m['objects'])
 for x in m['objects']:assert identity(t.extractfile(x['object_path']).read())=={k:x[k] for k in ('size_bytes','sha256','git_blob_sha1')}
print(json.dumps({'source_objects':len(m['objects']),'verified':True,'source_executed':False}))
